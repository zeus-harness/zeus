import { describe, expect, it, vi } from 'vitest';

import {
  createWorkItem,
  decideApproval,
  getRunTrace,
  listExperienceCandidates,
  listExperienceEntries,
  listWorkItems,
  loadWorkspaceData,
  searchExperienceEntries,
  updateWorkItem,
  type WorkspaceApiFetcher
} from './workspace';

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
});
