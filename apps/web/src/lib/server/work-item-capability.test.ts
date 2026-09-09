import { describe, expect, it } from 'vitest';
import { enableWorkItemRead, workItemReadDefinition } from './work-item-capability';

const workspaceId = '019f0000-0000-7000-8000-000000000001';
const organizationId = '019f0000-0000-7000-8000-000000000002';
const capabilityId = '019f0000-0000-7000-8000-000000000003';

function event(handle: (request: Request) => Promise<Response> | Response, selectedWorkspace = workspaceId) {
  const url = new URL(`http://web.test/${workspaceId}/settings/capabilities`);
  const form = new FormData();
  form.set('organization_id', capabilityId);
  form.set('approval_required', 'on');
  return {
    url, params: { workspaceId }, request: new Request(url, { method: 'POST', body: form }),
    fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      if (new URL(request.url).pathname === '/api/v1/auth/me') {
        return Response.json({ workspace_id: selectedWorkspace, organization_id: organizationId });
      }
      return handle(request);
    }) as typeof fetch
  };
}

describe('WorkItem capability setup', () => {
  it('uses the authenticated Organization and preserves Workspace approval and revision', async () => {
    const mutations: string[] = [];
    const input = event(async (request) => {
      const pathname = new URL(request.url).pathname;
      if (pathname === `/api/v1/organizations/${organizationId}/capability-definitions`) {
        expect(request.method).toBe('GET');
        return Response.json({ items: [{ ...workItemReadDefinition, id: capabilityId }] });
      }
      if (request.method === 'GET') {
        expect(pathname).toBe(`/api/v1/workspaces/${workspaceId}/capabilities`);
        return Response.json({ items: [{ capability_id: capabilityId, revision: 4 }] });
      }
      mutations.push(pathname);
      expect(request.method).toBe('PATCH');
      expect(request.headers.get('if-match')).toBe('"revision-4"');
      expect(await request.json()).toEqual({ enabled: true, approval_required: true });
      return Response.json({});
    });
    await expect(enableWorkItemRead(input, 'http://api.test')).rejects.toMatchObject({ status: 303 });
    expect(mutations).toEqual([`/api/v1/workspaces/${workspaceId}/capabilities/${capabilityId}`]);
  });

  it('cannot turn an Organization registration denial into a Workspace enable', async () => {
    const writes: string[] = [];
    const input = event((request) => {
      const pathname = new URL(request.url).pathname;
      expect(pathname).toBe(`/api/v1/organizations/${organizationId}/capability-definitions`);
      if (request.method === 'GET') return Response.json({ items: [] });
      writes.push(pathname);
      return Response.json({}, { status: 403 });
    });
    expect(await enableWorkItemRead(input, 'http://api.test')).toMatchObject({ status: 403 });
    expect(writes).toHaveLength(1);
  });

  it('rejects a stale Workspace before reading or registering any tool', async () => {
    let calls = 0;
    const input = event(() => { calls += 1; return Response.json({}); }, capabilityId);
    expect(await enableWorkItemRead(input, 'http://api.test')).toMatchObject({ status: 409 });
    expect(calls).toBe(0);
  });
});
