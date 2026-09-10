import { fail, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import { forwardZeusAuthCookies, serverApiFetcher, serverApiUrl } from '$lib/api/server';

export type OidcGrant = {
  client_id: string;
  client_public_id: string;
  client_name: string;
  organization_id: string;
  organization_name: string;
  scopes: string[];
  granted_at: string;
  last_used_at: string;
};

type JsonRecord = Record<string, unknown>;
type ActionEvent = Parameters<NonNullable<Actions['revoke']>>[0];

function isJsonRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function isOidcGrant(value: unknown): value is OidcGrant {
  return (
    isJsonRecord(value) &&
    typeof value.client_id === 'string' &&
    typeof value.client_public_id === 'string' &&
    typeof value.client_name === 'string' &&
    typeof value.organization_id === 'string' &&
    typeof value.organization_name === 'string' &&
    isStringArray(value.scopes) &&
    typeof value.granted_at === 'string' &&
    typeof value.last_used_at === 'string'
  );
}

function formValue(formData: FormData, name: string): string {
  const value = formData.get(name);
  return typeof value === 'string' ? value.trim() : '';
}

function actionError(status: number, message: string) {
  return fail(status, { type: 'error' as const, message });
}

function responseStatus(status: number): number {
  return status >= 400 && status <= 599 ? status : 502;
}

function loadErrorMessage(status: number): string {
  if (status >= 500) return '授权记录服务暂时不可用，请稍后重试。';
  return '无法读取 OIDC 授权记录，请稍后重试。';
}

function revokeErrorMessage(status: number): string {
  if (status === 403) return '当前账号无权撤销该 OIDC 授权。';
  if (status === 404) return '该 OIDC 授权不存在或已经撤销。';
  if (status >= 500) return '授权记录服务暂时不可用，请稍后重试。';
  return '无法撤销该 OIDC 授权，请稍后重试。';
}

export const load: PageServerLoad = async ({ fetch, parent, request, url }) => {
  const auth = await parent();
  if (auth.status === 'unauthenticated') redirect(303, '/login');
  if (auth.status !== 'ready') {
    return {
      grants: [],
      loadError: '无法确认当前登录状态，请稍后重试。',
      httpStatus: null
    };
  }

  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  let response: Response;
  try {
    response = await apiFetch(serverApiUrl(env.ZEUS_API_URL, '/api/v1/users/me/oidc-grants'), {
      headers: { accept: 'application/json' }
    });
  } catch {
    return {
      grants: [],
      loadError: '无法连接 OIDC 授权记录 API，请稍后重试。',
      httpStatus: null
    };
  }

  if (response.status === 401) redirect(303, '/login');
  if (!response.ok) {
    return {
      grants: [],
      loadError: loadErrorMessage(response.status),
      httpStatus: response.status
    };
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    return {
      grants: [],
      loadError: 'OIDC 授权记录 API 返回了无法识别的响应。',
      httpStatus: 502
    };
  }
  if (!Array.isArray(payload) || !payload.every(isOidcGrant)) {
    return {
      grants: [],
      loadError: 'OIDC 授权记录 API 返回了无法识别的响应。',
      httpStatus: 502
    };
  }

  return { grants: payload, loadError: null, httpStatus: null };
};

export const actions: Actions = {
  revoke: async (event) => {
    const clientId = formValue(await event.request.formData(), 'client_id');
    if (!clientId) return actionError(400, '缺少要撤销的 OIDC Client ID。');

    const apiFetch = serverApiFetcher(
      event.fetch,
      event.request.headers.get('cookie'),
      event.url.origin
    );
    let response: Response;
    try {
      response = await apiFetch(
        serverApiUrl(
          env.ZEUS_API_URL,
          `/api/v1/users/me/oidc-grants/${encodeURIComponent(clientId)}`
        ),
        {
          method: 'DELETE',
          headers: { accept: 'application/json' }
        }
      );
    } catch {
      return actionError(503, '无法连接 OIDC 授权撤销 API，请稍后重试。');
    }

    forwardZeusAuthCookies(response, event.cookies);
    if (response.status === 401) redirect(303, '/login');
    if (!response.ok) {
      return actionError(responseStatus(response.status), revokeErrorMessage(response.status));
    }

    return { type: 'success' as const, message: 'OIDC 授权已撤销。' };
  }
};
