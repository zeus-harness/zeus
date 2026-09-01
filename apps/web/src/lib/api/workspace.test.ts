import { describe, expect, it, vi } from 'vitest';

import {
  loadWorkspaceData,
  type ApiFetcher as WorkspaceApiFetcher
} from './client';
import {
  createWorkItem,
  listWorkItems,
  updateWorkItem
} from './work-items';
import { listExperienceCandidates, listExperienceEntries, searchExperienceEntries } from './experiences';
import {
  cancelRun,
  decideApproval,
  getRunTrace,
  listApprovals,
  listRuns,
  retryRun,
  startWorkItemRun
} from './runs';
import { listUserOrganizations } from './identity';

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json' }
  });
}

describe('workspace API helpers', () => {
  it('does not call a business endpoint without an authenticated workspace', async () => {
    const fetcher = vi.fn<WorkspaceApiFetcher>();
    const loader = vi.fn(async () => ({ items: [] }));

    const result = await loadWorkspaceData(
      fetcher,
      { authStatus: 'ready', workspaceId: null },
      loader
    );

    expect(result).toMatchObject({ status: 'not-configured' });
    expect(loader).not.toHaveBeenCalled();
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('reports unauthenticated and API failure states explicitly', async () => {
    const fetcher = vi.fn<WorkspaceApiFetcher>();
    const loader = vi.fn(async () => ({ items: [] }));

    await expect(
      loadWorkspaceData(fetcher, { authStatus: 'unauthenticated', workspaceId: 'ws-1' }, loader)
    ).resolves.toMatchObject({ status: 'unauthenticated' });

    const failingFetcher = vi
      .fn<WorkspaceApiFetcher>()
      .mockResolvedValue(jsonResponse({ title: 'backend unavailable' }, 503));
    await expect(
      loadWorkspaceData(
        failingFetcher,
        { authStatus: 'ready', workspaceId: 'ws-1' },
        (apiFetch, workspaceId) => listWorkItems(apiFetch, { workspaceId })
      )
    ).resolves.toMatchObject({ status: 'error', httpStatus: 503 });
  });

  it('uses opaque pagination and workspace-scoped collection paths', async () => {
    const fetcher = vi.fn<WorkspaceApiFetcher>().mockResolvedValue(
      jsonResponse({ items: [], next_cursor: null })
    );

    await listWorkItems(fetcher, {
      apiBaseUrl: 'http://zeus-api:8080/',
      workspaceId: 'workspace/one',
      status: 'in_progress',
      cursor: 'opaque-cursor',
      limit: 25
    });

    expect(fetcher).toHaveBeenCalledWith(
      'http://zeus-api:8080/api/v1/workspaces/workspace%2Fone/work-items?status=in_progress&cursor=opaque-cursor&limit=25',
      expect.objectContaining({ headers: expect.any(Headers) })
    );
  });

  it('sends idempotency and revision headers for mutable WorkItems', async () => {
    const fetcher = vi
      .fn<WorkspaceApiFetcher>()
      .mockImplementation(async () => jsonResponse({ id: 'item-1' }));

    await createWorkItem(fetcher, { workspaceId: 'ws-1' }, { title: 'New item' }, 'request-1');
    const createInit = fetcher.mock.calls[0]?.[1];
    const createHeaders = new Headers(createInit?.headers);
    expect(createHeaders.get('idempotency-key')).toBe('request-1');
    expect(createHeaders.get('content-type')).toBe('application/json');

    await updateWorkItem(fetcher, { workspaceId: 'ws-1' }, 'item-1', 7, {
      status: 'in_progress'
    });
    const updateInit = fetcher.mock.calls[1]?.[1];
    expect(new Headers(updateInit?.headers).get('if-match')).toBe('"revision-7"');
  });

  it('targets trace, approval, experience list, and FTS search endpoints', async () => {
    const fetcher = vi.fn<WorkspaceApiFetcher>().mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith('/trace')) {
        return jsonResponse({ run: {}, run_events: [] });
      }
      if (url.includes('/experience-candidates')) {
        return jsonResponse({ items: [], next_cursor: null });
      }
      if (url.includes('/experience-entries/search')) {
        return jsonResponse([]);
      }
      return jsonResponse([]);
    });

    await getRunTrace(fetcher, { workspaceId: 'ws-1' }, 'run-1');
    await decideApproval(fetcher, { workspaceId: 'ws-1' }, 'approval-1', 'approve');
    await listExperienceCandidates(fetcher, { workspaceId: 'ws-1', status: 'pending' });
    await listExperienceEntries(fetcher, { workspaceId: 'ws-1', includeWithdrawn: true });
    await searchExperienceEntries(fetcher, { workspaceId: 'ws-1', q: 'incident response' });

    const urls = fetcher.mock.calls.map(([input]) => String(input));
    expect(urls).toContain('/api/v1/workspaces/ws-1/runs/run-1/trace');
    expect(urls).toContain('/api/v1/workspaces/ws-1/approvals/approval-1/approve');
    expect(urls).toContain('/api/v1/workspaces/ws-1/experience-candidates?status=pending');
    expect(urls).toContain('/api/v1/workspaces/ws-1/experience-entries?include_withdrawn=true');
    expect(urls).toContain(
      '/api/v1/workspaces/ws-1/experience-entries/search?q=incident+response&limit=20'
    );
  });

  it('starts a WorkItem Run atomically and filters execution collections', async () => {
    const fetcher = vi.fn<WorkspaceApiFetcher>().mockResolvedValue(
      jsonResponse({ session: { id: 'session-1' }, run: { id: 'run-1' } }, 201)
    );

    await startWorkItemRun(
      fetcher,
      { workspaceId: 'ws-1' },
      'work-item-1',
      { workflow_id: 'workflow-1', input: {}, message: 'Investigate' },
      'start-1'
    );
    const startInit = fetcher.mock.calls[0]?.[1];
    expect(new Headers(startInit?.headers).get('idempotency-key')).toBe('start-1');
    expect(fetcher.mock.calls[0]?.[0]).toBe(
      '/api/v1/workspaces/ws-1/work-items/work-item-1/runs'
    );

    fetcher.mockResolvedValueOnce(jsonResponse({ items: [], next_cursor: null }));
    await listRuns(fetcher, {
      workspaceId: 'ws-1',
      workItemId: 'work-item-1',
      status: 'running'
    });
    expect(fetcher.mock.calls[1]?.[0]).toBe(
      '/api/v1/workspaces/ws-1/runs?work_item_id=work-item-1&status=running'
    );

    fetcher.mockResolvedValueOnce(jsonResponse([]));
    await listApprovals(fetcher, {
      workspaceId: 'ws-1',
      workItemId: 'work-item-1',
      status: 'pending'
    });
    expect(fetcher.mock.calls[2]?.[0]).toBe(
      '/api/v1/workspaces/ws-1/approvals?status=pending&work_item_id=work-item-1'
    );
  });

  it('supports empty cancel responses and idempotent manual retries', async () => {
    const fetcher = vi
      .fn<WorkspaceApiFetcher>()
      .mockResolvedValueOnce(new Response(null, { status: 202 }))
      .mockResolvedValueOnce(jsonResponse({ id: 'retry-1' }, 201));

    await expect(cancelRun(fetcher, { workspaceId: 'ws-1' }, 'run-1', 'operator request')).resolves.toBeUndefined();
    await retryRun(fetcher, { workspaceId: 'ws-1' }, 'run-1', 'retry-request-1');

    expect(fetcher.mock.calls[0]?.[0]).toBe('/api/v1/workspaces/ws-1/runs/run-1/cancel');
    expect(new Headers(fetcher.mock.calls[1]?.[1]?.headers).get('idempotency-key')).toBe(
      'retry-request-1'
    );
  });

  it('normalizes user workspaces without exposing identity-provider payloads', async () => {
    const fetcher = vi.fn<WorkspaceApiFetcher>().mockResolvedValue(
      jsonResponse([
        {
          organization_id: 'org-1',
          organization_slug: 'acme',
          organization_name: 'Acme',
          organization_status: 'active',
          organization_role: 'owner',
          workspaces: [
            { id: 'ws-1', slug: 'platform', name: 'Platform', status: 'active', role: 'owner' },
            { id: 42, name: 'invalid' }
          ],
          identity_providers: [{ id: 'provider-secret-metadata' }]
        }
      ])
    );

    await expect(listUserOrganizations(fetcher)).resolves.toEqual([
      {
        organization_id: 'org-1',
        organization_slug: 'acme',
        organization_name: 'Acme',
        organization_status: 'active',
        organization_role: 'owner',
        workspaces: [
          { id: 'ws-1', slug: 'platform', name: 'Platform', status: 'active', role: 'owner' }
        ]
      }
    ]);
  });
});
