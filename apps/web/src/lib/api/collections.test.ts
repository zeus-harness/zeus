import { describe, expect, it, vi } from 'vitest';

import { getManagementResource, managementResources } from '../control-plane';
import {
  fetchWorkspaceCollection,
  normalizeCollectionRecords,
  type ApiFetcher
} from './collections';

describe('control-plane resources', () => {
  it('exposes navigation entries for every requested resource', () => {
    expect(managementResources.map((resource) => resource.slug)).toEqual([
      'agents',
      'workflows',
      'model-profiles',
      'connections',
      'capabilities',
      'schedules',
      'webhooks'
    ]);
  });

  it('normalizes common collection response envelopes', () => {
    expect(normalizeCollectionRecords({ items: [{ id: 'agent-1' }] })).toEqual([
      { id: 'agent-1' }
    ]);
    expect(normalizeCollectionRecords([{ id: 'workflow-1' }])).toEqual([
      { id: 'workflow-1' }
    ]);
    expect(normalizeCollectionRecords({ message: 'empty' })).toEqual([]);
  });
});

describe('fetchWorkspaceCollection', () => {
  it('does not call the API until a workspace is configured', async () => {
    const fetcher = vi.fn<ApiFetcher>();
    const result = await fetchWorkspaceCollection(fetcher, getManagementResource('agents')!, {});

    expect(result.status).toBe('not-configured');
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('loads a declared collection through the server fetcher', async () => {
    const fetcher = vi.fn<ApiFetcher>().mockResolvedValue(
      new Response(JSON.stringify({ data: [{ id: 'agent-1', name: 'Review agent' }] }), {
        status: 200,
        headers: { 'content-type': 'application/json' }
      })
    );
    const resource = getManagementResource('agents')!;

    await expect(
      fetchWorkspaceCollection(fetcher, resource, {
        apiBaseUrl: 'http://localhost:3000/',
        workspaceId: 'workspace-1'
      })
    ).resolves.toMatchObject({
      status: 'ready',
      records: [{ id: 'agent-1', name: 'Review agent' }]
    });
    expect(fetcher).toHaveBeenCalledWith(
      'http://localhost:3000/api/v1/workspaces/workspace-1/agents',
      expect.objectContaining({ headers: { accept: 'application/json' } })
    );
  });

  it('uses the implemented webhook endpoint path', async () => {
    const fetcher = vi.fn<ApiFetcher>().mockResolvedValue(
      new Response(JSON.stringify({ items: [] }), { status: 200 })
    );
    const result = await fetchWorkspaceCollection(fetcher, getManagementResource('webhooks')!, {
      workspaceId: 'workspace-1'
    });

    expect(result.status).toBe('ready');
    expect(fetcher).toHaveBeenCalledWith(
      '/api/v1/workspaces/workspace-1/webhook-endpoints',
      expect.any(Object)
    );
  });

  it('maps a reserved API response to the same explicit unavailable state', async () => {
    const fetcher = vi.fn<ApiFetcher>().mockResolvedValue(new Response(null, { status: 501 }));

    const result = await fetchWorkspaceCollection(fetcher, getManagementResource('agents')!, {
      workspaceId: 'workspace-1'
    });

    expect(result).toMatchObject({
      status: 'not-available',
      httpStatus: 501,
      records: []
    });
  });
});
