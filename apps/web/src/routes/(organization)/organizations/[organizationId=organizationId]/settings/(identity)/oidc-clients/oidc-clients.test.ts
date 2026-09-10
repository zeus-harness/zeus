import { describe, expect, it, vi } from 'vitest';

import { actions, load } from './+page.server';
import type { Actions } from './$types';

vi.mock('$env/dynamic/private', () => ({
  env: { ZEUS_API_URL: 'http://zeus-api:8080' }
}));

const ORGANIZATION_ID = '01900000-0000-7000-8000-000000000002';
const CLIENT_RESOURCE_ID = '01900000-0000-7000-8000-000000000022';
const CLIENT_ID = 'zoc_portal-client-public-id';
const PAGE_PATH = `/organizations/${ORGANIZATION_ID}/settings/oidc-clients`;

type ActionEvent = Parameters<NonNullable<Actions['create']>>[0];
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

function client(overrides: Record<string, unknown> = {}) {
  return {
    id: CLIENT_RESOURCE_ID,
    client_id: CLIENT_ID,
    organization_id: ORGANIZATION_ID,
    name: 'Customer portal',
    client_type: 'confidential',
    redirect_uris: ['https://app.example.test/oidc/callback'],
    post_logout_redirect_uris: ['https://app.example.test/logout/callback'],
    trusted: true,
    allowed_scopes: ['openid', 'profile'],
    status: 'active',
    revision: 3,
    created_at: '2026-08-30T00:00:00Z',
    updated_at: '2026-08-30T00:00:00Z',
    ...overrides
  };
}

function principalResponse(): Response {
  return jsonResponse(200, { organization_id: ORGANIZATION_ID });
}

function actionEvent(
  fields: Record<string, string>,
  responses: Response[],
  pathname = PAGE_PATH
): { event: ActionEvent; fetcher: ReturnType<typeof vi.fn> } {
  const fetcher = vi.fn<typeof fetch>();
  for (const response of responses) fetcher.mockResolvedValueOnce(response);
  const event = {
    fetch: fetcher,
    request: new Request(`http://web.test${pathname}`, {
      method: 'POST',
      body: new URLSearchParams(fields),
      headers: { cookie: 'zeus_session=SESSION_FOR_TEST; zeus_csrf=CSRF_FOR_TEST' }
    }),
    url: new URL(`http://web.test${pathname}`),
    params: { organizationId: ORGANIZATION_ID },
    cookies: { set: vi.fn() }
  } as unknown as ActionEvent;
  return { event, fetcher };
}

function loadEvent(fetcher: ReturnType<typeof vi.fn>, organizationId: string | null = ORGANIZATION_ID) {
  return {
    parent: async () => ({
      status: 'ready' as const,
      principal: { organization_id: organizationId }
    }),
    fetch: fetcher,
    request: new Request(`http://web.test${PAGE_PATH}`, {
      headers: { cookie: 'zeus_session=SESSION_FOR_TEST; zeus_csrf=CSRF_FOR_TEST' }
    }),
    url: new URL(`http://web.test${PAGE_PATH}`),
    params: { organizationId: ORGANIZATION_ID }
  } as unknown as Parameters<typeof load>[0];
}

describe('admin OIDC clients page load', () => {
  it('loads clients for the active organization and forwards the session cookie', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(200, [client()]));

    const result = await load(loadEvent(fetcher));

    expect(result).toMatchObject({
      authStatus: 'ready',
      organizationId: ORGANIZATION_ID,
      clients: [client()],
      loadError: null,
      httpStatus: null
    });
    expect(fetcher).toHaveBeenCalledWith(
      `http://zeus-api:8080/api/v1/organizations/${ORGANIZATION_ID}/oidc-clients`,
      expect.any(Object)
    );
    expect(new Headers(fetcher.mock.calls[0]?.[1]?.headers).get('cookie')).toBe(
      'zeus_session=SESSION_FOR_TEST; zeus_csrf=CSRF_FOR_TEST'
    );
  });

  it('does not call the client API without an active organization', async () => {
    const fetcher = vi.fn<typeof fetch>();

    const result = await load(loadEvent(fetcher, null));

    expect(result).toMatchObject({
      authStatus: 'ready',
      organizationId: null,
      clients: [],
      loadError: null
    });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('returns a safe load error for an unavailable or malformed API response', async () => {
    const unavailable = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 503 }));
    await expect(load(loadEvent(unavailable))).resolves.toMatchObject({
      clients: [],
      loadError: 'OIDC Client 服务暂时不可用，请稍后重试。',
      httpStatus: 503
    });

    const malformed = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(200, { clients: [] }));
    await expect(load(loadEvent(malformed))).resolves.toMatchObject({
      clients: [],
      loadError: 'OIDC Client API 返回了无法识别的响应。',
      httpStatus: 502
    });
  });

  it('redirects unauthenticated visitors to login', async () => {
    await expect(
      load({
        parent: async () => ({ principal: null, status: 'unauthenticated' as const })
      } as unknown as Parameters<typeof load>[0])
    ).rejects.toMatchObject({ status: 303, location: '/login' });
  });
});

describe('admin OIDC clients page actions', () => {
  it('creates a client with all configured arrays and forwards CSRF and Origin', async () => {
    const created = { ...client(), client_secret: 'one-time-secret-for-test' };
    const { event, fetcher } = actionEvent(
      {
        name: ' Customer portal ',
        client_type: 'confidential',
        redirect_uris: 'https://app.example.test/oidc/callback\nhttps://app.example.test/alt',
        post_logout_redirect_uris: 'https://app.example.test/logout/callback',
        trusted: 'true',
        allowed_scopes: 'openid, profile\nemail'
      },
      [principalResponse(), jsonResponse(201, created)]
    );

    await expect(handler(actions.create)(event)).resolves.toEqual({
      type: 'created',
      message: 'OIDC Client 已创建。请立即保存本次显示的 Client Secret。',
      client: { id: CLIENT_RESOURCE_ID, client_id: CLIENT_ID, name: 'Customer portal' },
      client_secret: 'one-time-secret-for-test'
    });

    const [url, init] = fetcher.mock.calls[1] ?? [];
    expect(url).toBe(`http://zeus-api:8080/api/v1/organizations/${ORGANIZATION_ID}/oidc-clients`);
    expect(init?.method).toBe('POST');
    expect(JSON.parse(String(init?.body))).toEqual({
      name: 'Customer portal',
      client_type: 'confidential',
      redirect_uris: [
        'https://app.example.test/oidc/callback',
        'https://app.example.test/alt'
      ],
      post_logout_redirect_uris: ['https://app.example.test/logout/callback'],
      trusted: true,
      allowed_scopes: ['openid', 'profile', 'email']
    });
    const headers = new Headers(init?.headers);
    expect(headers.get('cookie')).toBe('zeus_session=SESSION_FOR_TEST; zeus_csrf=CSRF_FOR_TEST');
    expect(headers.get('x-zeus-csrf')).toBe('CSRF_FOR_TEST');
    expect(headers.get('origin')).toBe('http://web.test');
  });

  it('patches an existing client with its revision If-Match header', async () => {
    const { event, fetcher } = actionEvent(
      {
        client_id: CLIENT_RESOURCE_ID,
        revision: '3',
        name: 'Updated portal',
        redirect_uris: 'https://updated.example.test/callback',
        post_logout_redirect_uris: '',
        trusted: 'false',
        allowed_scopes: 'openid, email'
      },
      [principalResponse(), new Response(null, { status: 204 })]
    );

    await expect(handler(actions.update)(event)).resolves.toEqual({
      type: 'success',
      message: 'OIDC Client 已更新。'
    });

    const [url, init] = fetcher.mock.calls[1] ?? [];
    expect(url).toBe(
      `http://zeus-api:8080/api/v1/organizations/${ORGANIZATION_ID}/oidc-clients/${CLIENT_RESOURCE_ID}`
    );
    expect(init?.method).toBe('PATCH');
    expect(new Headers(init?.headers).get('if-match')).toBe('"revision-3"');
    expect(JSON.parse(String(init?.body))).toEqual({
      name: 'Updated portal',
      redirect_uris: ['https://updated.example.test/callback'],
      post_logout_redirect_uris: [],
      trusted: false,
      allowed_scopes: ['openid', 'email']
    });
  });

  it('deletes a client and maps API conflicts to an action error', async () => {
    const deleted = actionEvent(
      { client_id: CLIENT_RESOURCE_ID },
      [principalResponse(), new Response(null, { status: 204 })]
    );
    await expect(handler(actions.delete)(deleted.event)).resolves.toEqual({
      type: 'success',
      message: 'OIDC Client 已删除。'
    });
    expect(deleted.fetcher.mock.calls[1]?.[0]).toBe(
      `http://zeus-api:8080/api/v1/organizations/${ORGANIZATION_ID}/oidc-clients/${CLIENT_RESOURCE_ID}`
    );
    expect(deleted.fetcher.mock.calls[1]?.[1]?.method).toBe('DELETE');

    const conflict = actionEvent(
      { name: 'Portal', client_type: 'public' },
      [principalResponse(), new Response(null, { status: 409 })]
    );
    await expect(handler(actions.create)(conflict.event)).resolves.toMatchObject({ status: 409 });
  });

  it('rejects invalid form values and a creation response without a secret', async () => {
    const invalid = actionEvent(
      { name: 'Portal', client_type: 'native' },
      [principalResponse()]
    );
    await expect(handler(actions.create)(invalid.event)).resolves.toMatchObject({ status: 400 });
    expect(invalid.fetcher).toHaveBeenCalledTimes(1);

    const missingSecret = actionEvent(
      { name: 'Portal', client_type: 'public' },
      [principalResponse(), jsonResponse(201, client())]
    );
    await expect(handler(actions.create)(missingSecret.event)).resolves.toMatchObject({ status: 502 });
  });
});
