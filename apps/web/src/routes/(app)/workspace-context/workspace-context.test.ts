import { describe, expect, it, vi } from 'vitest';

import { POST } from './+server';

vi.mock('$env/dynamic/private', () => ({
  env: { ZEUS_API_URL: 'http://zeus-api:8080' }
}));

function requestEvent(fields: Record<string, string>, response: Response) {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response);
  const cookieSet = vi.fn();
  const url = new URL('http://web.test/workspace-context');
  const request = new Request(url, {
    method: 'POST',
    headers: { cookie: 'zeus_session=session-for-test; zeus_csrf=csrf-for-test' },
    body: new URLSearchParams(fields)
  });

  return {
    event: {
      cookies: { set: cookieSet },
      fetch: fetcher,
      request,
      url
    } as unknown as Parameters<typeof POST>[0],
    fetcher,
    cookieSet
  };
}

describe('workspace context endpoint', () => {
  it('forwards the selected context with browser write protection headers', async () => {
    const response = new Response(null, { status: 204 });
    response.headers.append(
      'set-cookie',
      'zeus_session=rotated-session; Path=/; HttpOnly; SameSite=Lax; Max-Age=60'
    );
    const { event, fetcher, cookieSet } = requestEvent(
      {
        organization_id: 'organization-1',
        workspace_id: 'workspace-1',
        return_to: '/runs?status=running'
      },
      response
    );

    await expect(POST(event)).rejects.toMatchObject({
      status: 303,
      location: '/runs?status=running'
    });

    expect(fetcher).toHaveBeenCalledWith(
      'http://zeus-api:8080/api/v1/auth/context',
      expect.objectContaining({ method: 'POST' })
    );
    const init = fetcher.mock.calls[0]?.[1];
    const headers = new Headers(init?.headers);
    expect(headers.get('origin')).toBe('http://web.test');
    expect(headers.get('x-zeus-csrf')).toBe('csrf-for-test');
    expect(JSON.parse(String(init?.body))).toEqual({
      organization_id: 'organization-1',
      workspace_id: 'workspace-1'
    });
    expect(cookieSet).toHaveBeenCalledWith(
      'zeus_session',
      'rotated-session',
      expect.objectContaining({ httpOnly: true, path: '/' })
    );
  });

  it('rejects an external return target', async () => {
    const { event } = requestEvent(
      {
        organization_id: 'organization-1',
        workspace_id: 'workspace-1',
        return_to: '//outside.example.test/path'
      },
      new Response(null, { status: 204 })
    );

    await expect(POST(event)).rejects.toMatchObject({ status: 303, location: '/' });
  });

  it('returns a stable gateway error when the API cannot be reached', async () => {
    const { event } = requestEvent(
      {
        organization_id: 'organization-1',
        workspace_id: 'workspace-1',
        return_to: '/'
      },
      new Response(null, { status: 204 })
    );
    event.fetch = vi.fn<typeof fetch>().mockRejectedValue(new Error('network unavailable'));

    await expect(POST(event)).rejects.toMatchObject({
      status: 502,
      body: { message: 'Workspace 切换服务暂时不可用。' }
    });
  });
});
