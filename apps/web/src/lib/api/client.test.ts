import { describe, expect, it, vi } from 'vitest';

import { ZeusApiClient } from './client';

describe('ZeusApiClient', () => {
  it('loads API metadata from the v1 endpoint', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          product: 'Zeus',
          version: '0.1.0',
          api_version: 'v1',
          queue_backend: 'postgresql',
          worker_process: false,
          features: []
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    );
    const client = new ZeusApiClient('', fetcher);

    await expect(client.meta()).resolves.toMatchObject({ product: 'Zeus' });
    expect(fetcher).toHaveBeenCalledWith(
      '/api/v1/meta',
      expect.objectContaining({ headers: { accept: 'application/json' } })
    );
  });
});
