import { describe, expect, it, vi } from 'vitest';

import { actions, load } from './+page.server';
import type { Actions } from './$types';

vi.mock('$env/dynamic/private', () => ({
  env: { ZEUS_API_URL: 'http://zeus-api:8080' }
}));

const REQUEST_ID = '01900000-0000-7000-8000-000000000044';

type ActionEvent = Parameters<NonNullable<Actions['approve']>>[0];
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

function authorizationRequest() {
  return {
    request_id: REQUEST_ID,
    organization_id: '01900000-0000-7000-8000-000000000002',
    organization_name: 'Acme Corporation',
    client_id: '01900000-0000-7000-8000-000000000022',
    client_public_id: 'zoc_portal-client-public-id',
    client_name: 'Customer portal',
    scopes: ['openid', 'profile']
  };
}

function loadEvent(fetcher: ReturnType<typeof vi.fn>, status = 'ready') {
  const url = new URL(`http://web.test/oauth/consent?request=${REQUEST_ID}`);
  return {
    parent: async () => ({ status, principal: status === 'ready' ? { user_id: 'user' } : null }),
    fetch: fetcher,
    request: new Request(url, {
      headers: { cookie: 'zeus_session=SESSION_FOR_TEST; zeus_csrf=CSRF_FOR_TEST' }
    }),
    url
  } as unknown as Parameters<typeof load>[0];
}

function actionEvent(response: Response): { event: ActionEvent; fetcher: ReturnType<typeof vi.fn> } {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response);
  const event = {
    fetch: fetcher,
    request: new Request(`http://web.test/oauth/consent?request=${REQUEST_ID}`, {
      method: 'POST',
      body: new URLSearchParams({ request_id: REQUEST_ID }),
      headers: { cookie: 'zeus_session=SESSION_FOR_TEST; zeus_csrf=CSRF_FOR_TEST' }
    }),
    url: new URL(`http://web.test/oauth/consent?request=${REQUEST_ID}`),
    cookies: { set: vi.fn() }
  } as unknown as ActionEvent;
  return { event, fetcher };
}

describe('OIDC consent page', () => {
  it('loads a session-bound authorization request', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(200, authorizationRequest()));

    await expect(load(loadEvent(fetcher))).resolves.toEqual({
      authorizationRequest: authorizationRequest(),
      loadError: null
    });
    expect(fetcher).toHaveBeenCalledWith(
      `http://zeus-api:8080/api/v1/users/me/oidc-authorization-requests/${REQUEST_ID}`,
      expect.any(Object)
    );
  });

  it('preserves the consent request when login is required', async () => {
    await expect(load(loadEvent(vi.fn<typeof fetch>(), 'unauthenticated'))).rejects.toMatchObject({
      status: 303,
      location: `/login?return_to=%2Foauth%2Fconsent%3Frequest%3D${REQUEST_ID}`
    });
  });

  it.each([
    ['approve', true],
    ['deny', false]
  ] as const)('submits the %s decision with CSRF headers and follows the registered redirect', async (action, approved) => {
    const redirectUrl = `https://client.example.test/callback?${approved ? 'code=CODE_FOR_TEST' : 'error=access_denied'}`;
    const { event, fetcher } = actionEvent(jsonResponse(200, { redirect_url: redirectUrl }));

    await expect(handler(actions[action])(event)).rejects.toMatchObject({
      status: 303,
      location: redirectUrl
    });
    const [url, init] = fetcher.mock.calls[0] ?? [];
    expect(url).toBe(
      `http://zeus-api:8080/api/v1/users/me/oidc-authorization-requests/${REQUEST_ID}`
    );
    expect(init?.method).toBe('POST');
    expect(JSON.parse(String(init?.body))).toEqual({ approved });
    const headers = new Headers(init?.headers);
    expect(headers.get('x-zeus-csrf')).toBe('CSRF_FOR_TEST');
    expect(headers.get('origin')).toBe('http://web.test');
  });
});
