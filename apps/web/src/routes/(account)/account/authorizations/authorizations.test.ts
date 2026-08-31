import { describe, expect, it, vi } from 'vitest';

import { actions, load } from './+page.server';
import type { Actions } from './$types';

vi.mock('$env/dynamic/private', () => ({
  env: { ZEUS_API_URL: 'http://zeus-api:8080' }
}));

const CLIENT_ID = 'portal-client';
const ORGANIZATION_ID = '01900000-0000-7000-8000-000000000002';
const CLIENT_PUBLIC_ID = 'zoc_portal-client-public-id';

type ActionEvent = Parameters<NonNullable<Actions['revoke']>>[0];
type ActionHandler = (event: ActionEvent) => Promise<unknown>;

function handler(action: unknown): ActionHandler {
  return action as ActionHandler;
}

function jsonResponse(status: number, payload: unknown): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json' }
  });
}

function grant(overrides: Record<string, unknown> = {}) {
  return {
    client_id: CLIENT_ID,
    client_public_id: CLIENT_PUBLIC_ID,
    client_name: 'Customer portal',
    organization_id: ORGANIZATION_ID,
    organization_name: 'Acme Corporation',
    scopes: ['openid', 'profile'],
    granted_at: '2026-08-30T00:00:00Z',
    last_used_at: '2026-08-30T02:00:00Z',
    ...overrides
  };
}

function actionEvent(
  fields: Record<string, string>,
  response: Response
): { event: ActionEvent; fetcher: ReturnType<typeof vi.fn> } {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response);
  const event = {
    fetch: fetcher,
    request: new Request('http://web.test/account/authorizations', {
      method: 'POST',
      body: new URLSearchParams(fields),
      headers: { cookie: 'zeus_session=SESSION_FOR_TEST; zeus_csrf=CSRF_FOR_TEST' }
    }),
    url: new URL('http://web.test/account/authorizations'),
    cookies: { set: vi.fn() }
  } as unknown as ActionEvent;
  return { event, fetcher };
}

function loadEvent(fetcher: ReturnType<typeof vi.fn>, status: 'ready' | 'unavailable' = 'ready') {
  return {
    parent: async () => ({
      status,
      principal: status === 'ready' ? { organization_id: ORGANIZATION_ID } : null
    }),
    fetch: fetcher,
    request: new Request('http://web.test/account/authorizations', {
      headers: { cookie: 'zeus_session=SESSION_FOR_TEST; zeus_csrf=CSRF_FOR_TEST' }
    }),
    url: new URL('http://web.test/account/authorizations')
  } as unknown as Parameters<typeof load>[0];
}

describe('account OIDC authorizations page load', () => {
  it('loads grants with client, organization, scopes, and usage timestamps', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(200, [grant()]));

    const result = await load(loadEvent(fetcher));

    expect(result).toEqual({ grants: [grant()], loadError: null, httpStatus: null });
    expect(fetcher).toHaveBeenCalledWith(
      'http://zeus-api:8080/api/v1/users/me/oidc-grants',
      expect.any(Object)
    );
    expect(new Headers(fetcher.mock.calls[0]?.[1]?.headers).get('cookie')).toBe(
      'zeus_session=SESSION_FOR_TEST; zeus_csrf=CSRF_FOR_TEST'
    );
  });

  it('returns an actionable error for an API failure or malformed payload', async () => {
    const unavailable = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 503 }));
    await expect(load(loadEvent(unavailable))).resolves.toMatchObject({
      grants: [],
      loadError: '授权记录服务暂时不可用，请稍后重试。',
      httpStatus: 503
    });

    const malformed = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(200, { grants: [] }));
    await expect(load(loadEvent(malformed))).resolves.toMatchObject({
      grants: [],
      loadError: 'OIDC 授权记录 API 返回了无法识别的响应。',
      httpStatus: 502
    });
  });

  it('keeps the page load local when auth is unavailable and redirects logged-out users', async () => {
    const unavailable = vi.fn<typeof fetch>();
    await expect(load(loadEvent(unavailable, 'unavailable'))).resolves.toMatchObject({
      grants: [],
      loadError: '无法确认当前登录状态，请稍后重试。'
    });
    expect(unavailable).not.toHaveBeenCalled();

    await expect(
      load({
        parent: async () => ({ principal: null, status: 'unauthenticated' as const })
      } as unknown as Parameters<typeof load>[0])
    ).rejects.toMatchObject({ status: 303, location: '/login' });
  });
});

describe('account OIDC authorizations page actions', () => {
  it('revokes a grant with the session security headers', async () => {
    const { event, fetcher } = actionEvent(
      { client_id: CLIENT_ID },
      new Response(null, { status: 204 })
    );

    await expect(handler(actions.revoke)(event)).resolves.toEqual({
      type: 'success',
      message: 'OIDC 授权已撤销。'
    });

    const [url, init] = fetcher.mock.calls[0] ?? [];
    expect(url).toBe(`http://zeus-api:8080/api/v1/users/me/oidc-grants/${CLIENT_ID}`);
    expect(init?.method).toBe('DELETE');
    const headers = new Headers(init?.headers);
    expect(headers.get('cookie')).toBe('zeus_session=SESSION_FOR_TEST; zeus_csrf=CSRF_FOR_TEST');
    expect(headers.get('x-zeus-csrf')).toBe('CSRF_FOR_TEST');
    expect(headers.get('origin')).toBe('http://web.test');
  });

  it('validates a missing client ID and maps a missing grant to an action error', async () => {
    const missing = actionEvent({}, new Response(null, { status: 204 }));
    await expect(handler(actions.revoke)(missing.event)).resolves.toMatchObject({ status: 400 });
    expect(missing.fetcher).not.toHaveBeenCalled();

    const missingGrant = actionEvent(
      { client_id: CLIENT_ID },
      new Response(null, { status: 404 })
    );
    await expect(handler(actions.revoke)(missingGrant.event)).resolves.toMatchObject({ status: 404 });
  });
});
