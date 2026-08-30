import { describe, expect, it, vi } from 'vitest';

import { actions, load } from './+page.server';
import type { Actions } from './$types';

vi.mock('$env/dynamic/private', () => ({
  env: { ZEUS_API_URL: 'http://zeus-api:8080' }
}));

const ORGANIZATION_ID = '01900000-0000-7000-8000-000000000002';
const PROVIDER_ID = '01900000-0000-7000-8000-000000000012';

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

function provider(overrides: Record<string, unknown> = {}) {
  return {
    id: PROVIDER_ID,
    organization_id: ORGANIZATION_ID,
    slug: 'okta',
    issuer_url: 'https://idp.example.test',
    client_id: 'client-id',
    scopes: ['openid', 'profile', 'email'],
    group_claim: null,
    jit_enabled: true,
    trusted_acr: ['urn:example:loa:2'],
    trusted_amr: ['pwd', 'mfa'],
    enabled: true,
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
  responses: Response[]
): { event: ActionEvent; fetcher: ReturnType<typeof vi.fn> } {
  const fetcher = vi.fn<typeof fetch>();
  for (const response of responses) fetcher.mockResolvedValueOnce(response);
  const event = {
    fetch: fetcher,
    request: new Request('http://web.test/admin/identity-providers', {
      method: 'POST',
      body: new URLSearchParams(fields),
      headers: { cookie: 'zeus_session=SESSION_FOR_TEST; zeus_csrf=CSRF_FOR_TEST' }
    }),
    url: new URL('http://web.test/admin/identity-providers'),
    cookies: { set: vi.fn() }
  } as unknown as ActionEvent;
  return { event, fetcher };
}

describe('admin identity provider page', () => {
  it('loads providers for the organization from the parent principal', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(200, [provider()]));
    const result = await load({
      parent: async () => ({
        status: 'ready' as const,
        principal: { organization_id: ORGANIZATION_ID }
      }),
      fetch: fetcher,
      request: new Request('http://web.test/admin/identity-providers'),
      url: new URL('http://web.test/admin/identity-providers')
    } as unknown as Parameters<typeof load>[0]);

    if (!result) throw new Error('expected the identity provider page load to return data');
    expect(result).toMatchObject({ organizationId: ORGANIZATION_ID, loadError: null });
    expect(result.providers).toHaveLength(1);
    expect(fetcher.mock.calls[0]?.[0]).toBe(
      `http://zeus-api:8080/api/v1/organizations/${ORGANIZATION_ID}/identity-providers`
    );
  });

  it('does not call the provider API without an active organization', async () => {
    const fetcher = vi.fn<typeof fetch>();
    const result = await load({
      parent: async () => ({
        status: 'ready' as const,
        principal: { organization_id: null }
      }),
      fetch: fetcher,
      request: new Request('http://web.test/admin/identity-providers'),
      url: new URL('http://web.test/admin/identity-providers')
    } as unknown as Parameters<typeof load>[0]);

    expect(result).toMatchObject({ organizationId: null, providers: [], loadError: null });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('redirects unauthenticated visitors to login', async () => {
    await expect(
      load({
        parent: async () => ({ principal: null, status: 'unauthenticated' as const })
      } as unknown as Parameters<typeof load>[0])
    ).rejects.toMatchObject({ status: 303, location: '/login' });
  });

  it('creates a provider with trusted authentication values and forwarded request headers', async () => {
    const { event, fetcher } = actionEvent(
      {
        slug: 'okta',
        issuer_url: 'https://idp.example.test/',
        client_id: 'client-id',
        client_secret: 'test-client-secret',
        jit_enabled: 'true',
        trusted_acr: 'urn:example:loa:2\nurn:example:loa:3',
        trusted_amr: 'pwd, mfa'
      },
      [principalResponse(), jsonResponse(201, provider())]
    );

    await expect(handler(actions.create)(event)).resolves.toEqual({
      type: 'success',
      message: '身份提供商已创建。'
    });

    const [url, init] = fetcher.mock.calls[1] ?? [];
    expect(url).toBe(
      `http://zeus-api:8080/api/v1/organizations/${ORGANIZATION_ID}/identity-providers`
    );
    expect(init?.method).toBe('POST');
    expect(JSON.parse(String(init?.body))).toEqual({
      slug: 'okta',
      issuer_url: 'https://idp.example.test/',
      client_id: 'client-id',
      client_secret: 'test-client-secret',
      jit_enabled: true,
      trusted_acr: ['urn:example:loa:2', 'urn:example:loa:3'],
      trusted_amr: ['pwd', 'mfa']
    });
    const headers = new Headers(init?.headers);
    expect(headers.get('cookie')).toBe('zeus_session=SESSION_FOR_TEST; zeus_csrf=CSRF_FOR_TEST');
    expect(headers.get('x-zeus-csrf')).toBe('CSRF_FOR_TEST');
    expect(headers.get('origin')).toBe('http://web.test');
  });

  it('patches a provider with its strong revision If-Match header', async () => {
    const { event, fetcher } = actionEvent(
      {
        provider_id: PROVIDER_ID,
        revision: '3',
        slug: 'okta-updated',
        issuer_url: 'https://idp.example.test',
        client_id: 'updated-client-id',
        client_secret: '',
        enabled: 'true',
        jit_enabled: 'false',
        trusted_acr: 'loa-2',
        trusted_amr: 'mfa'
      },
      [principalResponse(), jsonResponse(200, provider({ slug: 'okta-updated', revision: 4 }))]
    );

    await expect(handler(actions.update)(event)).resolves.toEqual({
      type: 'success',
      message: '身份提供商已更新。'
    });

    const [url, init] = fetcher.mock.calls[1] ?? [];
    expect(url).toBe(
      `http://zeus-api:8080/api/v1/organizations/${ORGANIZATION_ID}/identity-providers/${PROVIDER_ID}`
    );
    expect(init?.method).toBe('PATCH');
    expect(new Headers(init?.headers).get('if-match')).toBe('"revision-3"');
    expect(JSON.parse(String(init?.body))).toEqual({
      slug: 'okta-updated',
      issuer_url: 'https://idp.example.test',
      client_id: 'updated-client-id',
      enabled: true,
      jit_enabled: false,
      trusted_acr: ['loa-2'],
      trusted_amr: ['mfa']
    });
  });
});
