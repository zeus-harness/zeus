import { describe, expect, it, vi } from 'vitest';

import { loadSetupStatus, submitSetup, type SetupRequest } from './setup';

describe('setup API helpers', () => {
  it('loads setup-required and bootstrap-token status from the v1 endpoint', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({ setup_required: true, bootstrap_token_configured: true }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    );

    await expect(loadSetupStatus(fetcher, 'http://zeus-api:8080/')).resolves.toEqual({
      status: 'ready',
      data: { setup_required: true, bootstrap_token_configured: true }
    });
    expect(fetcher).toHaveBeenCalledWith(
      'http://zeus-api:8080/api/v1/setup/status',
      { headers: { accept: 'application/json' } }
    );
  });

  it('reports an unavailable setup status without trusting an invalid response', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(JSON.stringify({ setup_required: 'yes' }), { status: 200 })
    );

    await expect(loadSetupStatus(fetcher, undefined)).resolves.toMatchObject({
      status: 'unavailable',
      httpStatus: 200
    });
  });

  it('posts the complete setup payload as JSON', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 201 }));
    const payload: SetupRequest = {
      bootstrap_token: 'bootstrap-token',
      email: 'admin@example.test',
      display_name: 'Admin',
      password: 'a-password-longer-than-15',
      organization_slug: 'acme',
      organization_name: 'Acme',
      workspace_slug: 'default',
      workspace_name: 'Default'
    };

    await expect(submitSetup(fetcher, 'http://zeus-api:8080', payload)).resolves.toMatchObject({
      status: 201
    });

    const [url, init] = fetcher.mock.calls[0] ?? [];
    expect(url).toBe('http://zeus-api:8080/api/v1/setup');
    expect(init?.method).toBe('POST');
    expect(new Headers(init?.headers).get('content-type')).toBe('application/json');
    expect(JSON.parse(String(init?.body))).toEqual(payload);
  });
});
