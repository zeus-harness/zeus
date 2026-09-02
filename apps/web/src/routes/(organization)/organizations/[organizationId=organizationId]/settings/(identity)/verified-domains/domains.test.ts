import { describe, expect, it, vi } from 'vitest';

import { actions, load } from './+page.server';
import type { Actions } from './$types';

vi.mock('$env/dynamic/private', () => ({
  env: { ZEUS_API_URL: 'http://zeus-api:8080' }
}));

const ORGANIZATION_ID = '01900000-0000-7000-8000-000000000002';
const DOMAIN_ID = '01900000-0000-7000-8000-000000000022';
const PAGE_PATH = `/organizations/${ORGANIZATION_ID}/settings/verified-domains`;

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

function domain(overrides: Record<string, unknown> = {}) {
  return {
    id: DOMAIN_ID,
    organization_id: ORGANIZATION_ID,
    domain: 'example.com',
    status: 'pending',
    verified_at: null,
    created_by: '01900000-0000-7000-8000-000000000001',
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

describe('admin organization domains page', () => {
  it('loads domains for the active organization', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(200, [domain()]));
    const result = await load({
      parent: async () => ({
        status: 'ready' as const,
        principal: { organization_id: ORGANIZATION_ID }
      }),
      fetch: fetcher,
      request: new Request(`http://web.test${PAGE_PATH}`),
      url: new URL(`http://web.test${PAGE_PATH}`),
      params: { organizationId: ORGANIZATION_ID }
    } as unknown as Parameters<typeof load>[0]);

    if (!result) throw new Error('expected the domains page load to return data');
    expect(result).toMatchObject({ organizationId: ORGANIZATION_ID, loadError: null });
    expect(result.domains).toEqual([domain()]);
    expect(fetcher.mock.calls[0]?.[0]).toBe(
      `http://zeus-api:8080/api/v1/organizations/${ORGANIZATION_ID}/domains`
    );
  });

  it('creates a domain and returns the DNS TXT challenge only in the action result', async () => {
    const created = {
      ...domain(),
      txt_record_name: '_zeus-verification.example.com',
      txt_record_value: 'zeus-domain-verification=test-challenge'
    };
    const { event, fetcher } = actionEvent(
      { domain: ' Example.com. ' },
      [principalResponse(), jsonResponse(201, created)]
    );

    await expect(handler(actions.create)(event)).resolves.toEqual({
      type: 'domain_created',
      message: '域名已创建，请按下方资料添加 DNS TXT 记录。',
      verification: {
        domain_id: DOMAIN_ID,
        domain: 'example.com',
        txt_record_name: '_zeus-verification.example.com',
        txt_record_value: 'zeus-domain-verification=test-challenge'
      }
    });

    const [url, init] = fetcher.mock.calls[1] ?? [];
    expect(url).toBe(`http://zeus-api:8080/api/v1/organizations/${ORGANIZATION_ID}/domains`);
    expect(init?.method).toBe('POST');
    expect(JSON.parse(String(init?.body))).toEqual({ domain: 'Example.com.' });
    const headers = new Headers(init?.headers);
    expect(headers.get('x-zeus-csrf')).toBe('CSRF_FOR_TEST');
    expect(headers.get('origin')).toBe('http://web.test');
  });

  it('verifies a pending domain and can revoke it with the matching organization path', async () => {
    const verify = actionEvent(
      { domain_id: DOMAIN_ID },
      [principalResponse(), new Response(null, { status: 200 })]
    );
    await expect(handler(actions.verify)(verify.event)).resolves.toEqual({
      type: 'success',
      message: '域名已验证。'
    });
    expect(verify.fetcher.mock.calls[1]?.[0]).toBe(
      `http://zeus-api:8080/api/v1/organizations/${ORGANIZATION_ID}/domains/${DOMAIN_ID}/verify`
    );
    expect(verify.fetcher.mock.calls[1]?.[1]?.method).toBe('POST');

    const revoke = actionEvent(
      { domain_id: DOMAIN_ID },
      [principalResponse(), new Response(null, { status: 204 })]
    );
    await expect(handler(actions.revoke)(revoke.event)).resolves.toEqual({
      type: 'success',
      message: '域名已撤销。'
    });
    expect(revoke.fetcher.mock.calls[1]?.[0]).toBe(
      `http://zeus-api:8080/api/v1/organizations/${ORGANIZATION_ID}/domains/${DOMAIN_ID}`
    );
    expect(revoke.fetcher.mock.calls[1]?.[1]?.method).toBe('DELETE');
  });

  it('redirects unauthenticated visitors to login', async () => {
    await expect(
      load({
        parent: async () => ({ principal: null, status: 'unauthenticated' as const })
      } as unknown as Parameters<typeof load>[0])
    ).rejects.toMatchObject({ status: 303, location: '/login' });
  });
});
