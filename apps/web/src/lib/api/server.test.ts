import { describe, expect, it, vi } from 'vitest';
import type { Cookies } from '@sveltejs/kit';

import { forwardZeusAuthCookies, loadCurrentPrincipal, serverApiFetcher } from './server';

describe('server API session forwarding', () => {
  it('forwards the browser session cookie to an internal API URL', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 204 }));
    const apiFetch = serverApiFetcher(fetcher, 'zeus_session=test-session');

    await apiFetch('http://zeus-api:8080/api/v1/auth/me', {
      headers: { accept: 'application/json' }
    });

    const init = fetcher.mock.calls[0]?.[1];
    const headers = new Headers(init?.headers);
    expect(headers.get('cookie')).toBe('zeus_session=test-session');
    expect(headers.get('accept')).toBe('application/json');
  });

  it('adds CSRF and browser Origin to unsafe API requests', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 204 }));
    const apiFetch = serverApiFetcher(
      fetcher,
      'zeus_session=test-session; zeus_csrf=test-csrf',
      'http://127.0.0.1:3000'
    );

    await apiFetch('http://zeus-api:8080/api/v1/work-items', { method: 'POST' });

    const headers = new Headers(fetcher.mock.calls[0]?.[1]?.headers);
    expect(headers.get('x-zeus-csrf')).toBe('test-csrf');
    expect(headers.get('origin')).toBe('http://127.0.0.1:3000');
  });

  it('forwards only Zeus authentication cookies from an upstream response', () => {
    const headers = new Headers();
    headers.append(
      'set-cookie',
      'zeus_session=session-token; Path=/; HttpOnly; SameSite=Lax; Max-Age=7200; Secure'
    );
    headers.append('set-cookie', 'zeus_csrf=csrf-token; Path=/; SameSite=Lax; Max-Age=7200');
    headers.append(
      'set-cookie',
      'zeus_tenant_access_grant=grant-id; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600'
    );
    headers.append('set-cookie', 'unrelated=value; Path=/');
    const set = vi.fn();

    expect(
      forwardZeusAuthCookies(new Response(null, { headers }), { set } as unknown as Cookies)
    ).toBe(3);
    expect(set).toHaveBeenNthCalledWith(1, 'zeus_session', 'session-token', {
      path: '/',
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: 7200
    });
    expect(set).toHaveBeenNthCalledWith(2, 'zeus_csrf', 'csrf-token', {
      path: '/',
      httpOnly: false,
      secure: false,
      sameSite: 'lax',
      maxAge: 7200
    });
    expect(set).toHaveBeenNthCalledWith(3, 'zeus_tenant_access_grant', 'grant-id', {
      path: '/',
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      maxAge: 3600
    });
  });

  it('loads the selected workspace from the authenticated principal', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          principal_kind: 'user',
          principal_id: '01900000-0000-7000-8000-000000000001',
          user_id: '01900000-0000-7000-8000-000000000001',
          organization_id: '01900000-0000-7000-8000-000000000002',
          workspace_id: '01900000-0000-7000-8000-000000000003',
          organization_role: 'member',
          workspace_role: 'builder',
          scopes: [],
          email: 'builder@example.test',
          display_name: 'Builder',
          email_verified_at: '2026-08-30T00:00:00Z',
          platform_roles: [],
          auth_methods: ['password'],
          authenticated_at: '2026-08-30T00:00:00Z',
          mfa_satisfied_at: null,
          idle_expires_at: '2026-08-30T02:00:00Z',
          absolute_expires_at: '2026-08-31T00:00:00Z'
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    );

    const result = await loadCurrentPrincipal(fetcher, 'http://zeus-api:8080/');

    expect(result.status).toBe('ready');
    expect(result.principal?.workspace_id).toBe('01900000-0000-7000-8000-000000000003');
    expect(fetcher).toHaveBeenCalledWith(
      'http://zeus-api:8080/api/v1/auth/me',
      expect.any(Object)
    );
  });

  it('preserves nullable tenant context and session metadata', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          principal_kind: 'user',
          principal_id: '01900000-0000-7000-8000-000000000004',
          user_id: '01900000-0000-7000-8000-000000000004',
          organization_id: null,
          workspace_id: null,
          organization_role: null,
          workspace_role: null,
          scopes: [],
          email: 'pending@example.test',
          display_name: 'Pending user',
          email_verified_at: null,
          platform_roles: ['platform_admin'],
          auth_methods: ['password'],
          authenticated_at: '2026-08-30T00:00:00Z',
          mfa_satisfied_at: null,
          idle_expires_at: '2026-08-30T02:00:00Z',
          absolute_expires_at: '2026-08-31T00:00:00Z'
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    );

    const result = await loadCurrentPrincipal(fetcher, undefined);

    expect(result).toMatchObject({
      status: 'ready',
      principal: {
        organization_id: null,
        workspace_id: null,
        email_verified_at: null,
        platform_roles: ['platform_admin'],
        auth_methods: ['password'],
        authenticated_at: '2026-08-30T00:00:00Z',
        mfa_satisfied_at: null,
        idle_expires_at: '2026-08-30T02:00:00Z',
        absolute_expires_at: '2026-08-31T00:00:00Z'
      }
    });
  });
});
