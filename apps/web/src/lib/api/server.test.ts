import { describe, expect, it, vi } from 'vitest';

import { loadCurrentPrincipal, serverApiFetcher } from './server';

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
          display_name: 'Builder'
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
});
