import { fail, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import { forwardZeusAuthCookies, serverApiFetcher, serverApiUrl } from '$lib/api/server';
import { formValue, withReturnTo } from '$lib/server/auth';

type JsonRecord = Record<string, unknown>;

export type AuthorizationRequest = {
  request_id: string;
  organization_id: string;
  organization_name: string;
  client_id: string;
  client_public_id: string;
  client_name: string;
  scopes: string[];
};

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isJsonRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isAuthorizationRequest(value: unknown): value is AuthorizationRequest {
  return (
    isJsonRecord(value) &&
    typeof value.request_id === 'string' &&
    typeof value.organization_id === 'string' &&
    typeof value.organization_name === 'string' &&
    typeof value.client_id === 'string' &&
    typeof value.client_public_id === 'string' &&
    typeof value.client_name === 'string' &&
    Array.isArray(value.scopes) &&
    value.scopes.every((scope) => typeof scope === 'string')
  );
}

function consentPath(requestId: string): string {
  return `/oauth/consent?request=${encodeURIComponent(requestId)}`;
}

function actionError(status: number, message: string) {
  return fail(status, { type: 'error' as const, message });
}

async function responseJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function validRedirectUrl(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 8192) return false;
  try {
    const parsed = new URL(value);
    return (parsed.protocol === 'https:' || parsed.protocol === 'http:') && !parsed.username && !parsed.password;
  } catch {
    return false;
  }
}

export const load: PageServerLoad = async ({ fetch, parent, request, url }) => {
  const requestId = url.searchParams.get('request')?.trim() ?? '';
  const returnTo = consentPath(requestId);
  const auth = await parent();
  if (auth.status === 'unauthenticated') {
    redirect(303, withReturnTo('/login', returnTo));
  }
  if (auth.status !== 'ready') {
    return { authorizationRequest: null, loadError: '无法确认当前登录状态，请稍后重试。' };
  }
  if (!UUID_PATTERN.test(requestId)) {
    return { authorizationRequest: null, loadError: '授权请求地址无效。' };
  }

  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  let response: Response;
  try {
    response = await apiFetch(
      serverApiUrl(
        env.ZEUS_API_URL,
        `/api/v1/users/me/oidc-authorization-requests/${encodeURIComponent(requestId)}`
      ),
      { headers: { accept: 'application/json' } }
    );
  } catch {
    return { authorizationRequest: null, loadError: '无法连接授权 API，请稍后重试。' };
  }

  if (response.status === 401) redirect(303, withReturnTo('/login', returnTo));
  if (response.status === 404 || response.status === 410) {
    return { authorizationRequest: null, loadError: '该授权请求已过期、已处理或不属于当前会话。' };
  }
  if (!response.ok) {
    return { authorizationRequest: null, loadError: '授权服务暂时不可用，请稍后重试。' };
  }
  const payload = await responseJson(response);
  if (!isAuthorizationRequest(payload) || payload.request_id !== requestId) {
    return { authorizationRequest: null, loadError: '授权 API 返回了无法识别的响应。' };
  }
  return { authorizationRequest: payload, loadError: null };
};

async function decide(
  event: Parameters<NonNullable<Actions['approve']>>[0],
  approved: boolean
) {
  const requestId = formValue(await event.request.formData(), 'request_id');
  if (!UUID_PATTERN.test(requestId)) return actionError(400, '授权请求 ID 无效。');

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
        `/api/v1/users/me/oidc-authorization-requests/${encodeURIComponent(requestId)}`
      ),
      {
        method: 'POST',
        headers: { accept: 'application/json', 'content-type': 'application/json' },
        body: JSON.stringify({ approved })
      }
    );
  } catch {
    return actionError(503, '无法连接授权 API，请稍后重试。');
  }

  forwardZeusAuthCookies(response, event.cookies);
  if (response.status === 401) {
    redirect(303, withReturnTo('/login', consentPath(requestId)));
  }
  if (response.status === 404 || response.status === 410) {
    return actionError(404, '该授权请求已过期、已处理或不属于当前会话。');
  }
  if (!response.ok) return actionError(503, '授权服务暂时不可用，请稍后重试。');

  const payload = await responseJson(response);
  const redirectUrl = isJsonRecord(payload) ? payload.redirect_url : null;
  if (!validRedirectUrl(redirectUrl)) {
    return actionError(502, '授权 API 返回了无效的回调地址。');
  }
  redirect(303, redirectUrl);
}

export const actions: Actions = {
  approve: (event) => decide(event, true),
  deny: (event) => decide(event, false)
};
