import { fail, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import { forwardZeusAuthCookies, serverApiFetcher } from '$lib/api/server';
import { loadSetupStatus, submitSetup, type SetupRequest } from '$lib/api/setup';

type SafeSetupValues = Omit<SetupRequest, 'bootstrap_token' | 'password'>;

function formValue(formData: FormData, name: string, trim = true): string {
  const value = formData.get(name);
  if (typeof value !== 'string') {
    return '';
  }
  return trim ? value.trim() : value;
}

function safeValues(payload: SetupRequest): SafeSetupValues {
  const { bootstrap_token: _bootstrapToken, password: _password, ...values } = payload;
  return values;
}

function actionError(status: number, message: string, values: SafeSetupValues) {
  return fail(status, { type: 'error' as const, message, values });
}

function apiErrorMessage(status: number): string {
  if (status === 400 || status === 422) {
    return '初始设置数据无效，请检查所有字段后重试。';
  }
  if (status === 401 || status === 403) {
    return 'Bootstrap token 无效或未获准。';
  }
  if (status === 409) {
    return '初始设置已经完成，请前往登录入口。';
  }
  if (status >= 500) {
    return '初始设置 API 暂时不可用，请稍后重试。';
  }
  return `初始设置失败（HTTP ${status}）。`;
}

export const load: PageServerLoad = async ({ fetch, request }) => {
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), new URL(request.url).origin);
  return {
    setupStatus: await loadSetupStatus(apiFetch, env.ZEUS_API_URL)
  };
};

export const actions: Actions = {
  default: async (event) => {
    const formData = await event.request.formData();
    const payload: SetupRequest = {
      bootstrap_token: formValue(formData, 'bootstrap_token', false),
      email: formValue(formData, 'email').toLowerCase(),
      display_name: formValue(formData, 'display_name'),
      password: formValue(formData, 'password', false),
      organization_slug: formValue(formData, 'organization_slug'),
      organization_name: formValue(formData, 'organization_name'),
      workspace_slug: formValue(formData, 'workspace_slug'),
      workspace_name: formValue(formData, 'workspace_name')
    };
    const values = safeValues(payload);

    const requiredFields: Array<[keyof SetupRequest, string]> = [
      ['bootstrap_token', 'Bootstrap token'],
      ['email', 'Email'],
      ['display_name', 'Display name'],
      ['password', 'Password'],
      ['organization_slug', 'Organization slug'],
      ['organization_name', 'Organization name'],
      ['workspace_slug', 'Workspace slug'],
      ['workspace_name', 'Workspace name']
    ];
    const missingField = requiredFields.find(([name]) => payload[name].trim() === '');
    if (missingField) {
      return actionError(400, `${missingField[1]} 不能为空。`, values);
    }
    if (Array.from(payload.password.normalize('NFC')).length < 15) {
      return actionError(400, 'Password 至少需要 15 个字符。', values);
    }

    const apiFetch = serverApiFetcher(
      event.fetch,
      event.request.headers.get('cookie'),
      event.url.origin
    );
    let response: Response;
    try {
      response = await submitSetup(apiFetch, env.ZEUS_API_URL, payload);
    } catch {
      return actionError(502, '无法连接初始设置 API，请稍后重试。', values);
    }

    if (response.status !== 201) {
      const status = response.status >= 400 && response.status <= 599 ? response.status : 502;
      return actionError(status, apiErrorMessage(response.status), values);
    }

    forwardZeusAuthCookies(response, event.cookies);
    redirect(303, '/verify-email');
  }
};
