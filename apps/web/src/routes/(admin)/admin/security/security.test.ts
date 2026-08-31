import { describe, expect, it, vi } from 'vitest';

import { actions, load } from './+page.server';
import type { Actions } from './$types';

vi.mock('$env/dynamic/private', () => ({
  env: { ZEUS_API_URL: 'http://zeus-api:8080' }
}));

const ORGANIZATION_ID = '01900000-0000-7000-8000-000000000002';
const PROVIDER_ID = '01900000-0000-7000-8000-000000000012';

type ActionEvent = Parameters<NonNullable<Actions['update']>>[0];
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
    scopes: ['openid'],
    group_claim: null,
    jit_enabled: false,
    trusted_acr: [],
    trusted_amr: [],
    enabled: true,
    revision: 3,
    created_at: '2026-08-30T00:00:00Z',
    updated_at: '2026-08-30T00:00:00Z',
    ...overrides
  };
}

function policy(overrides: Record<string, unknown> = {}) {
  return {
    organization_id: ORGANIZATION_ID,
    mfa_required: false,
    federated_required: false,
    required_federated_provider_id: null,
    revision: 7,
    updated_by: null,
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
    request: new Request('http://web.test/admin/security', {
      method: 'POST',
      body: new URLSearchParams(fields),
      headers: { cookie: 'zeus_session=SESSION_FOR_TEST; zeus_csrf=CSRF_FOR_TEST' }
    }),
    url: new URL('http://web.test/admin/security'),
    cookies: { set: vi.fn() }
  } as unknown as ActionEvent;
  return { event, fetcher };
}

describe('admin organization security page', () => {
  it('reads identity policy and providers for the active organization', async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(200, [provider()]))
      .mockResolvedValueOnce(jsonResponse(200, policy()));
    const result = await load({
      parent: async () => ({
        status: 'ready' as const,
        principal: { organization_id: ORGANIZATION_ID }
      }),
      fetch: fetcher,
      request: new Request('http://web.test/admin/security'),
      url: new URL('http://web.test/admin/security')
    } as unknown as Parameters<typeof load>[0]);

    if (!result) throw new Error('expected the security page load to return data');
    expect(result.policy).toEqual(policy());
    expect(result.providers).toEqual([provider()]);
    expect(fetcher.mock.calls.map(([url]) => url)).toEqual([
      `http://zeus-api:8080/api/v1/organizations/${ORGANIZATION_ID}/identity-providers`,
      `http://zeus-api:8080/api/v1/organizations/${ORGANIZATION_ID}/identity-policy`
    ]);
  });

  it('updates MFA and federated requirements with the policy revision', async () => {
    const { event, fetcher } = actionEvent(
      {
        revision: '7',
        mfa_required: 'true',
        federated_required: 'true',
        required_federated_provider_id: PROVIDER_ID
      },
      [principalResponse(), jsonResponse(200, policy({ mfa_required: true, federated_required: true }))]
    );

    await expect(handler(actions.update)(event)).resolves.toEqual({
      type: 'success',
      message: '身份策略已更新。'
    });

    const [url, init] = fetcher.mock.calls[1] ?? [];
    expect(url).toBe(
      `http://zeus-api:8080/api/v1/organizations/${ORGANIZATION_ID}/identity-policy`
    );
    expect(init?.method).toBe('PUT');
    expect(new Headers(init?.headers).get('if-match')).toBe('"revision-7"');
    expect(JSON.parse(String(init?.body))).toEqual({
      mfa_required: true,
      federated_required: true,
      required_federated_provider_id: PROVIDER_ID
    });
    const headers = new Headers(init?.headers);
    expect(headers.get('cookie')).toBe('zeus_session=SESSION_FOR_TEST; zeus_csrf=CSRF_FOR_TEST');
    expect(headers.get('x-zeus-csrf')).toBe('CSRF_FOR_TEST');
    expect(headers.get('origin')).toBe('http://web.test');
  });

  it('clears the required provider when federated login is disabled', async () => {
    const { event, fetcher } = actionEvent(
      { revision: '8', mfa_required: 'false', federated_required: 'false' },
      [principalResponse(), jsonResponse(200, policy({ revision: 9 }))]
    );

    await expect(handler(actions.update)(event)).resolves.toMatchObject({ type: 'success' });
    expect(JSON.parse(String(fetcher.mock.calls[1]?.[1]?.body))).toEqual({
      mfa_required: false,
      federated_required: false,
      required_federated_provider_id: null
    });
  });

  it('does not load organization data without an active organization', async () => {
    const fetcher = vi.fn<typeof fetch>();
    const result = await load({
      parent: async () => ({
        status: 'ready' as const,
        principal: { organization_id: null }
      }),
      fetch: fetcher,
      request: new Request('http://web.test/admin/security'),
      url: new URL('http://web.test/admin/security')
    } as unknown as Parameters<typeof load>[0]);

    expect(result).toMatchObject({ organizationId: null, policy: null, providers: [] });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('redirects unauthenticated visitors to login', async () => {
    await expect(
      load({
        parent: async () => ({ principal: null, status: 'unauthenticated' as const })
      } as unknown as Parameters<typeof load>[0])
    ).rejects.toMatchObject({ status: 303, location: '/login' });
  });
});
