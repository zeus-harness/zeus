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
  path: string,
  fields: Record<string, string>,
  response: Response
): { event: ActionEvent; fetcher: ReturnType<typeof vi.fn> } {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response);
  const event = {
    fetch: fetcher,
    request: new Request(`http://web.test${path}`, {
      method: 'POST',
      body: new URLSearchParams(fields),
      headers: { cookie: 'zeus_session=SESSION_FOR_TEST; zeus_csrf=CSRF_FOR_TEST' }
    }),
    url: new URL(`http://web.test${path}`),
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

function readyLoadEvent(
  fetcher: ReturnType<typeof vi.fn>
): Parameters<typeof load>[0] {
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
  it('loads linked identities and providers for the active organization', async () => {
    const identity = {
      identity_id: '01900000-0000-7000-8000-000000000010',
      provider_id: '01900000-0000-7000-8000-000000000011',
      organization_id: '01900000-0000-7000-8000-000000000012',
      organization_name: 'Acme',
      provider_slug: 'entra-id',
      issuer: 'https://issuer.example.test',
      subject: 'subject-for-test',
      linked_at: '2026-08-30T01:00:00Z',
      last_login_at: '2026-08-30T02:00:00Z'
    };
    const provider = {
      id: '01900000-0000-7000-8000-000000000011',
      organization_id: '01900000-0000-7000-8000-000000000012',
      slug: 'entra-id',
      issuer_url: 'https://issuer.example.test',
      enabled: true
    };
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(200, [identity]))
      .mockResolvedValueOnce(
        jsonResponse(200, [{ organization_id: provider.organization_id, identity_providers: [provider] }])
      );

    const result = await load(readyLoadEvent(fetcher));

    expect(result).toEqual({
      identities: [identity],
      identityLoadError: null,
      providers: [provider],
      providerLoadError: null
    });
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(fetcher).toHaveBeenNthCalledWith(
      1,
      'http://zeus-api:8080/api/v1/users/me/federated-identities',
      expect.any(Object)
    );
    expect(fetcher).toHaveBeenNthCalledWith(
      2,
      'http://zeus-api:8080/api/v1/users/me/organizations',
      expect.any(Object)
    );
    expect(new Headers(fetcher.mock.calls[0]?.[1]?.headers).get('cookie')).toBe(
      'zeus_session=SESSION_FOR_TEST; zeus_csrf=CSRF_FOR_TEST'
    );
  });

  it('loads linkable providers without requiring an active organization', async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(200, []))
      .mockResolvedValueOnce(jsonResponse(200, []));

    const result = await load(readyLoadEvent(fetcher));

    expect(result).toMatchObject({
      identities: [],
      identityLoadError: null,
      providers: [],
      providerLoadError: null
    });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it('redirects unauthenticated visitors to login', async () => {
    const event = {
      parent: async () => ({ principal: null, status: 'unauthenticated' as const })
    } as unknown as Parameters<typeof load>[0];

    await expect(load(event)).rejects.toMatchObject({ status: 303, location: '/login' });
  });
});

describe('account federation actions', () => {
  it('starts linking and redirects to the authorization URL', async () => {
    const { event, fetcher } = actionEvent(
      '/account/federation',
      { provider_id: '01900000-0000-7000-8000-000000000020' },
      jsonResponse(200, { authorization_url: 'https://issuer.example.test/authorize?state=test' })
    );

    await expect(actionHandler(actions.link)(event)).rejects.toMatchObject({
      status: 303,
      location: 'https://issuer.example.test/authorize?state=test'
    });
    const [url, init] = fetcher.mock.calls[0] ?? [];
    expect(url).toBe(
      'http://zeus-api:8080/api/v1/users/me/federated-identities/01900000-0000-7000-8000-000000000020/link-intents'
    );
    expect(init?.method).toBe('POST');
    expect(new Headers(init?.headers).get('x-zeus-csrf')).toBe('CSRF_FOR_TEST');
    expect(new Headers(init?.headers).get('origin')).toBe('http://web.test');
  });

  it('unlinks an identity and keeps the account page available', async () => {
    const { event, fetcher } = actionEvent(
      '/account/federation',
      { identity_id: '01900000-0000-7000-8000-000000000021' },
      new Response(null, { status: 204 })
    );

    await expect(actionHandler(actions.unlink)(event)).resolves.toEqual({
      type: 'success',
      message: '企业身份已解绑。'
    });
    expect(fetcher).toHaveBeenCalledWith(
      'http://zeus-api:8080/api/v1/users/me/federated-identities/01900000-0000-7000-8000-000000000021',
      expect.any(Object)
    );
    expect(fetcher.mock.calls[0]?.[1]?.method).toBe('DELETE');
  });

  it('validates missing action identifiers before calling the API', async () => {
    const link = actionEvent('/account/federation', {}, new Response(null, { status: 204 }));
    const unlink = actionEvent('/account/federation', {}, new Response(null, { status: 204 }));

    await expect(actionHandler(actions.link)(link.event)).resolves.toMatchObject({ status: 400 });
    await expect(actionHandler(actions.unlink)(unlink.event)).resolves.toMatchObject({ status: 400 });
    expect(link.fetcher).not.toHaveBeenCalled();
    expect(unlink.fetcher).not.toHaveBeenCalled();
  });
});
