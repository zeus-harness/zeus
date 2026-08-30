import { fail, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import {
  forwardZeusAuthCookies,
  serverApiFetcher,
  serverApiUrl
} from '$lib/api/server';

type JsonRecord = Record<string, unknown>;

type TotpSetupResponse = {
  confirmed: boolean;
  secret: string | null;
  provisioning_uri: string | null;
  recovery_codes: string[];
};

type ApiEvent = {
  fetch: typeof fetch;
  request: Request;
  url: URL;
};

function formValue(formData: FormData, name: string, trim = true): string {
  const value = formData.get(name);
  if (typeof value !== 'string') return '';
  return trim ? value.trim() : value;
}

function actionError(status: number, message: string) {
  return fail(status, { type: 'error' as const, message });
}

function responseStatus(status: number): number {
  return status >= 400 && status <= 599 ? status : 502;
}

function nfcCodePointLength(value: string): number {
  return Array.from(value.normalize('NFC')).length;
}

function isJsonRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isTotpSetupResponse(value: unknown): value is TotpSetupResponse {
  return (
    isJsonRecord(value) &&
    typeof value.confirmed === 'boolean' &&
    (typeof value.secret === 'string' || value.secret === null) &&
    (typeof value.provisioning_uri === 'string' || value.provisioning_uri === null) &&
    Array.isArray(value.recovery_codes) &&
    value.recovery_codes.every((code) => typeof code === 'string')
  );
}

async function responseJson(response: Response): Promise<unknown> {
  try {
    return await response.clone().json();
  } catch {
    return null;
  }
}

function accountApi(
  event: ApiEvent,
  method: 'DELETE' | 'POST' | 'PUT',
  path: string,
  payload: JsonRecord
): Promise<Response> {
  const apiFetch = serverApiFetcher(event.fetch, event.request.headers.get('cookie'), event.url.origin);
  return apiFetch(serverApiUrl(env.ZEUS_API_URL, path), {
    method,
    headers: {
      accept: 'application/json',
      'content-type': 'application/json'
    },
    body: JSON.stringify(payload)
  });
}

function passwordErrorMessage(status: number): string {
  if (status === 401) return '当前密码不正确，或当前会话已过期。';
  if (status === 400 || status === 422) return '密码格式无效，请检查后重试。';
  if (status >= 500) return '密码服务暂时不可用，请稍后重试。';
  return '密码更新失败，请稍后重试。';
}

function totpErrorMessage(status: number, operation: 'enable' | 'disable'): string {
  if (status === 401) {
    return operation === 'disable'
      ? '密码或验证码不正确，或当前会话已过期。'
      : '当前会话已过期，请重新登录。';
  }
  if (status === 403) return '当前账号暂时不满足 TOTP 操作条件。';
  if (status === 409) {
    return operation === 'disable'
      ? '当前账号不允许关闭 TOTP。'
      : 'TOTP 设置状态已变化，请刷新页面后重试。';
  }
  if (status === 400 || status === 422) return 'TOTP 请求无效，请检查输入后重试。';
  if (status >= 500) return 'TOTP 服务暂时不可用，请稍后重试。';
  return operation === 'disable' ? 'TOTP 关闭失败，请稍后重试。' : 'TOTP 设置失败，请稍后重试。';
}

export const load: PageServerLoad = async ({ parent }) => {
  const auth = await parent();
  if (auth.status === 'unauthenticated') {
    redirect(303, '/login');
  }

  return {};
};

export const actions: Actions = {
  changePassword: async (event) => {
    const formData = await event.request.formData();
    const currentPassword = formValue(formData, 'current_password', false);
    const newPassword = formValue(formData, 'new_password', false);
    const confirmation = formData.get('new_password_confirmation');

    if (!newPassword) return actionError(400, '新密码不能为空。');
    if (typeof confirmation === 'string' && confirmation !== newPassword) {
      return actionError(400, '两次输入的新密码不一致。');
    }
    if (nfcCodePointLength(newPassword) < 15) {
      return actionError(400, '新密码至少需要 15 个 NFC Unicode 字符。');
    }

    let response: Response;
    try {
      response = await accountApi(event, 'PUT', '/api/v1/users/me/password', {
        current_password: currentPassword || null,
        new_password: newPassword
      });
    } catch {
      return actionError(503, '无法连接密码 API，请稍后重试。');
    }

    forwardZeusAuthCookies(response, event.cookies);
    if (!response.ok) {
      return actionError(responseStatus(response.status), passwordErrorMessage(response.status));
    }

    return { type: 'success' as const, message: '密码已更新，当前会话已安全续期。' };
  },

  startTotp: async (event) => {
    let response: Response;
    try {
      response = await accountApi(event, 'POST', '/api/v1/users/me/totp', { code: null });
    } catch {
      return actionError(503, '无法连接 TOTP API，请稍后重试。');
    }

    forwardZeusAuthCookies(response, event.cookies);
    if (!response.ok) {
      return actionError(responseStatus(response.status), totpErrorMessage(response.status, 'enable'));
    }

    const payload = await responseJson(response);
    if (!isTotpSetupResponse(payload)) {
      return actionError(502, 'TOTP API 返回了无法识别的响应。');
    }
    if (payload.confirmed) {
      return { type: 'success' as const, message: 'TOTP 已启用。' };
    }
    if (!payload.secret || !payload.provisioning_uri) {
      return actionError(502, 'TOTP API 未返回完整的设置资料。');
    }

    return {
      type: 'totp_setup' as const,
      secret: payload.secret,
      provisioning_uri: payload.provisioning_uri
    };
  },

  confirmTotp: async (event) => {
    const code = formValue(await event.request.formData(), 'code');
    if (!code) return actionError(400, 'TOTP 验证码不能为空。');

    let response: Response;
    try {
      response = await accountApi(event, 'POST', '/api/v1/users/me/totp', { code });
    } catch {
      return actionError(503, '无法连接 TOTP API，请稍后重试。');
    }

    forwardZeusAuthCookies(response, event.cookies);
    if (!response.ok) {
      return actionError(responseStatus(response.status), totpErrorMessage(response.status, 'enable'));
    }

    const payload = await responseJson(response);
    if (!isTotpSetupResponse(payload) || !payload.confirmed) {
      return actionError(502, 'TOTP API 未确认设置完成。');
    }

    return {
      type: 'totp_confirmed' as const,
      message: 'TOTP 已启用。请立即保存以下一次性恢复码。',
      recovery_codes: payload.recovery_codes
    };
  },

  disableTotp: async (event) => {
    const formData = await event.request.formData();
    const password = formValue(formData, 'password', false);
    const code = formValue(formData, 'code');
    if (!password) return actionError(400, '当前密码不能为空。');
    if (!code) return actionError(400, 'TOTP 验证码不能为空。');

    let response: Response;
    try {
      response = await accountApi(event, 'DELETE', '/api/v1/users/me/totp', {
        password,
        code
      });
    } catch {
      return actionError(503, '无法连接 TOTP API，请稍后重试。');
    }

    forwardZeusAuthCookies(response, event.cookies);
    if (!response.ok) {
      return actionError(responseStatus(response.status), totpErrorMessage(response.status, 'disable'));
    }

    return { type: 'success' as const, message: 'TOTP 已关闭。' };
  }
};
