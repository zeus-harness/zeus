import { describe, expect, it, vi } from 'vitest';

import { actions, load } from './+page.server';
import type { Actions } from './$types';

vi.mock('$env/dynamic/private', () => ({
  env: { ZEUS_API_URL: 'http://zeus-api:8080' }
}));

type ActionEvent = Parameters<NonNullable<Actions['link']>>[0];
type ActionHandler = (event: ActionEvent) => Promise<unknown>;

function actionHandler(action: unknown): ActionHandler {
  return action as ActionHandler;
}

function actionEvent(
  fields: Record<string, string>,
  response: Response
): { event: ActionEvent; fetcher: ReturnType<typeof vi.fn> } {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response);
  const event = {
    fetch: fetcher,
    request: new Request('http://web.test/account/federation', {
      method: 'POST',
      body: new URLSearchParams(fields),
      headers: { cookie: 'zeus_session=SESSION_FOR_TEST; zeus_csrf=CSRF_FOR_TEST' }
    }),
    url: new URL('http://web.test/account/federation'),
    cookies: { set: vi.fn() }
  } as unknown as ActionEvent;
  return { event, fetcher };
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' }
  });
}

function readyLoadEvent(fetcher: ReturnType<typeof vi.fn>): Parameters<typeof load>[0] {
  return {
    fetch: fetcher,
    request: new Request('http://web.test/account/federation', {
      headers: { cookie: 'zeus_session=SESSION_FOR_TEST; zeus_csrf=CSRF_FOR_TEST' }
    }),
    url: new URL('http://web.test/account/federation'),
    parent: async () => ({ principal: { organization_id: null }, status: 'ready' as const })
  } as unknown as Parameters<typeof load>[0];
}

describe('account federation page load', () => {
  it('loads global identities, Organization bindings, and linkable providers together', async () => {
    const binding = {
      binding_id: '01900000-0000-7000-8000-000000000012',
      organization_id: '01900000-0000-7000-8000-000000000013',
      organization_name: 'Acme',
      provider_id: '01900000-0000-7000-8000-000000000014',
      provider_slug: 'entra-id',
      status: 'active',
      binding_source: 'explicit',
      linked_at: '2026-08-30T01:00:00Z',
      last_login_at: '2026-08-30T02:00:00Z'
    };
    const identity = {
      identity_id: '01900000-0000-7000-8000-000000000010',
      issuer: 'https://issuer.example.test',
      subject: 'subject-for-test',
      status: 'active',
      created_at: '2026-08-30T01:00:00Z',
      last_login_at: '2026-08-30T02:00:00Z',
      organization_bindings: [binding]
    };
    const provider = {
      provider_id: binding.provider_id,
      organization_id: binding.organization_id,
      organization_name: 'Acme',
      provider_slug: 'entra-id',
      issuer: 'https://issuer.example.test'
    };
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValue(jsonResponse(200, { identities: [identity], available_providers: [provider] }));

    await expect(load(readyLoadEvent(fetcher))).resolves.toEqual({
      identities: [identity],
      providers: [provider],
      loadError: null
    });
    expect(fetcher).toHaveBeenCalledOnce();
    expect(fetcher).toHaveBeenCalledWith(
      'http://zeus-api:8080/api/v1/users/me/external-identities',
      expect.any(Object)
    );
    expect(new Headers(fetcher.mock.calls[0]?.[1]?.headers).get('cookie')).toBe(
      'zeus_session=SESSION_FOR_TEST; zeus_csrf=CSRF_FOR_TEST'
    );
  });

  it('redirects unauthenticated visitors to login', async () => {
    const event = {
      parent: async () => ({ principal: null, status: 'unauthenticated' as const })
    } as unknown as Parameters<typeof load>[0];

    await expect(load(event)).rejects.toMatchObject({ status: 303, location: '/login' });
  });
});

describe('account federation actions', () => {
  it('starts an explicit link with a JSON provider request', async () => {
    const providerId = '01900000-0000-7000-8000-000000000020';
    const { event, fetcher } = actionEvent(
      { provider_id: providerId },
      jsonResponse(200, { authorization_url: 'https://issuer.example.test/authorize?state=test' })
    );

    await expect(actionHandler(actions.link)(event)).rejects.toMatchObject({
      status: 303,
      location: 'https://issuer.example.test/authorize?state=test'
    });
    const [url, init] = fetcher.mock.calls[0] ?? [];
    expect(url).toBe('http://zeus-api:8080/api/v1/users/me/external-identities/link-intents');
    expect(init?.method).toBe('POST');
    expect(init?.body).toBe(JSON.stringify({ provider_id: providerId }));
    expect(new Headers(init?.headers).get('x-zeus-csrf')).toBe('CSRF_FOR_TEST');
    expect(new Headers(init?.headers).get('origin')).toBe('http://web.test');
  });

  it('revokes one Organization binding without deleting the global identity', async () => {
    const identityId = '01900000-0000-7000-8000-000000000021';
    const bindingId = '01900000-0000-7000-8000-000000000022';
    const { event, fetcher } = actionEvent(
      { identity_id: identityId, binding_id: bindingId },
      new Response(null, { status: 204 })
    );

    await expect(actionHandler(actions.unlinkBinding)(event)).resolves.toEqual({
      type: 'success',
      message: 'Organization 信任绑定已解除。'
    });
    expect(fetcher).toHaveBeenCalledWith(
      `http://zeus-api:8080/api/v1/users/me/external-identities/${identityId}/organization-bindings/${bindingId}`,
      expect.objectContaining({ method: 'DELETE' })
    );
  });

  it('revokes a global identity through its separate endpoint', async () => {
    const identityId = '01900000-0000-7000-8000-000000000023';
    const { event, fetcher } = actionEvent(
      { identity_id: identityId },
      new Response(null, { status: 204 })
    );

    await expect(actionHandler(actions.revokeIdentity)(event)).resolves.toEqual({
      type: 'success',
      message: '全局外部身份已撤销。'
    });
    expect(fetcher).toHaveBeenCalledWith(
      `http://zeus-api:8080/api/v1/users/me/external-identities/${identityId}`,
      expect.objectContaining({ method: 'DELETE' })
    );
  });

  it('validates missing action identifiers before calling the API', async () => {
    const link = actionEvent({}, new Response(null, { status: 204 }));
    const unlink = actionEvent({}, new Response(null, { status: 204 }));
    const revoke = actionEvent({}, new Response(null, { status: 204 }));

    await expect(actionHandler(actions.link)(link.event)).resolves.toMatchObject({ status: 400 });
    await expect(actionHandler(actions.unlinkBinding)(unlink.event)).resolves.toMatchObject({ status: 400 });
    await expect(actionHandler(actions.revokeIdentity)(revoke.event)).resolves.toMatchObject({ status: 400 });
    expect(link.fetcher).not.toHaveBeenCalled();
    expect(unlink.fetcher).not.toHaveBeenCalled();
    expect(revoke.fetcher).not.toHaveBeenCalled();
  });
});
