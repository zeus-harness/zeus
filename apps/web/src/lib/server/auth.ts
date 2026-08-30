import type { Cookies } from '@sveltejs/kit';

import { serverApiFetcher, serverApiUrl } from '$lib/api/server';

export { forwardZeusAuthCookies } from '$lib/api/server';

export const GENERIC_IDENTITY_MESSAGE = '如果该请求符合条件，我们会发送下一步指引。请检查邮箱。';

export type AuthActionEvent = {
  fetch: typeof fetch;
  request: Request;
  url: URL;
  cookies: Cookies;
};

export function authApiFetcher(event: AuthActionEvent): typeof fetch {
  return serverApiFetcher(
    event.fetch,
    event.request.headers.get('cookie'),
    event.url.origin
  );
}

export function formValue(formData: FormData, name: string, trim = true): string {
  const value = formData.get(name);
  if (typeof value !== 'string') {
    return '';
  }
  return trim ? value.trim() : value;
}

export function urlToken(url: URL, name = 'token'): string | null {
  const token = url.searchParams.get(name)?.trim();
  return token || null;
}

export function postAuth(
  fetcher: typeof fetch,
  apiBaseUrl: string | undefined,
  path: string,
  payload?: Record<string, string>
): Promise<Response> {
  const headers = new Headers({ accept: 'application/json' });
  const init: RequestInit = { method: 'POST', headers };
  if (payload) {
    headers.set('content-type', 'application/json');
    init.body = JSON.stringify(payload);
  }
  return fetcher(serverApiUrl(apiBaseUrl, path), init);
}

export async function responseJson(response: Response): Promise<unknown> {
  try {
    return await response.clone().json();
  } catch {
    return null;
  }
}

export function responseOk(response: Response): boolean {
  return response.status >= 200 && response.status < 300;
}

export function isMfaRequired(payload: unknown): boolean {
  return (
    typeof payload === 'object' &&
    payload !== null &&
    !Array.isArray(payload) &&
    (payload as Record<string, unknown>).mfa_required === true
  );
}
