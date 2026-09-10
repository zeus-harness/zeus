import { describe, expect, it, vi } from 'vitest';

import { actions } from './+page.server';

vi.mock('$env/dynamic/private', () => ({
  env: { ZEUS_API_URL: 'http://zeus-api:8080' }
}));

type SelectAction = (event: {
  cookies: { set: ReturnType<typeof vi.fn> };
  fetch: typeof fetch;
  request: Request;
  url: URL;
}) => Promise<unknown>;

const select = actions.select as unknown as SelectAction;

const principal = {
  principal_kind: 'user',
  principal_id: 'user-1',
  user_id: 'user-1',
  organization_id: null,
  workspace_id: null,
  organization_role: null,
  workspace_role: null,
  scopes: [],
  email: 'user@example.test',
  display_name: 'User',
  email_verified_at: '2026-09-01T00:00:00Z',
  platform_roles: [],
  auth_methods: ['password'],
  has_native_password: true,
  totp_enabled: false,
  mfa_required: false,
  authenticated_at: '2026-09-01T00:00:00Z',
  mfa_satisfied_at: null,
  idle_expires_at: '2026-09-01T02:00:00Z',
  absolute_expires_at: '2026-09-01T12:00:00Z',
  tenant_access_grant_id: null,
  tenant_access_expires_at: null
};

const organizations = [
  {
    organization_id: 'org-1',
    organization_slug: 'acme',
    organization_name: 'Acme',
    organization_status: 'active',
    organization_role: 'member',
    identity_settings_mode: 'self_service',
    support_access: false,
    can_manage_organization: false,
    can_manage_identity_settings: false,
    workspaces: [
      {
        id: 'workspace-1',
        slug: 'main',
        name: 'Main',
        status: 'active',
        role: 'builder',
        support_access: false
      }
    ]
  }
];

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' }
  });
}

function contextResponse(cookieCount = 2): Response {
  const headers = new Headers();
  if (cookieCount >= 1) headers.append('set-cookie', 'zeus_session=rotated; Path=/; HttpOnly');
  if (cookieCount >= 2) headers.append('set-cookie', 'zeus_csrf=rotated-csrf; Path=/');
  return new Response(JSON.stringify({ organization_id: 'org-1', workspace_id: 'workspace-1' }), {
    status: 200,
    headers
  });
}

function selectionEvent(fetcher: typeof fetch, returnTo = '/workspace-1/runs') {
  const url = new URL('http://web.test/workspaces?/select');
  const request = new Request(url, {
    method: 'POST',
    headers: { cookie: 'zeus_session=session; zeus_csrf=csrf' },
    body: new URLSearchParams({
      organization_id: 'org-1',
      workspace_id: 'workspace-1',
      return_to: returnTo
    })
  });
  return {
    cookies: { set: vi.fn() },
    fetch: fetcher,
    request,
    url
  };
}

function successfulFetcher(context = contextResponse()) {
  return vi.fn<typeof fetch>().mockImplementation(async (input) => {
    const url = String(input);
    if (url.endsWith('/api/v1/auth/me')) return json(principal);
    if (url.endsWith('/api/v1/users/me/organizations')) return json(organizations);
    if (url.endsWith('/api/v1/auth/context')) return context;
    return new Response(null, { status: 404 });
  });
}

describe('Workspace selection action', () => {
  it('rotates context with CSRF and redirects only inside the selected Workspace', async () => {
    const fetcher = successfulFetcher();
    const event = selectionEvent(fetcher);

    await expect(select(event)).rejects.toMatchObject({
      status: 303,
      location: '/workspace-1/runs'
    });
    const contextCall = fetcher.mock.calls.find(([input]) =>
      String(input).endsWith('/api/v1/auth/context')
    );
    expect(contextCall).toBeDefined();
    const headers = new Headers(contextCall?.[1]?.headers);
    expect(headers.get('origin')).toBe('http://web.test');
    expect(headers.get('x-zeus-csrf')).toBe('csrf');
    expect(JSON.parse(String(contextCall?.[1]?.body))).toEqual({
      organization_id: 'org-1',
      workspace_id: 'workspace-1'
    });
    expect(event.cookies.set).toHaveBeenCalledTimes(2);
  });

  it('rejects a Workspace that is absent from the current selector result', async () => {
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith('/api/v1/auth/me')) return json(principal);
      if (url.endsWith('/api/v1/users/me/organizations')) return json([]);
      return new Response(null, { status: 500 });
    });

    await expect(select(selectionEvent(fetcher))).rejects.toMatchObject({ status: 403 });
    expect(
      fetcher.mock.calls.some(([input]) => String(input).endsWith('/api/v1/auth/context'))
    ).toBe(false);
  });

  it('fails closed when the API omits one rotated Session credential', async () => {
    await expect(select(selectionEvent(successfulFetcher(contextResponse(1))))).rejects.toMatchObject({
      status: 502
    });
  });

  it('returns a stable unavailable state when the selector API cannot be reached', async () => {
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async (input) => {
      if (String(input).endsWith('/api/v1/auth/me')) return json(principal);
      throw new TypeError('network unavailable');
    });

    await expect(select(selectionEvent(fetcher))).rejects.toMatchObject({ status: 503 });
  });

  it('drops a return path that belongs to another Workspace', async () => {
    await expect(
      select(selectionEvent(successfulFetcher(), '/workspace-2/work-items'))
    ).rejects.toMatchObject({ status: 303, location: '/workspace-1' });
  });
});
