import { describe, expect, it } from 'vitest';
import { saveStudioResource } from './agent-studio';

const workspaceId = '019f0000-0000-7000-8000-000000000001';
const resourceId = '019f0000-0000-7000-8000-000000000002';
const versionId = '019f0000-0000-7000-8000-000000000003';

function event(resource: string, values: Record<string, string>, mutate: (request: Request) => Response, selectedWorkspace = workspaceId) {
  const form = new FormData();
  for (const [key, value] of Object.entries(values)) form.set(key, value);
  const url = new URL(`http://web.test/${workspaceId}/${resource}`);
  return {
    params: { workspaceId, resource }, url,
    request: new Request(url, { method: 'POST', body: form }),
    fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      if (new URL(request.url).pathname === '/api/v1/auth/me') {
        return Response.json({ workspace_id: selectedWorkspace });
      }
      return mutate(request);
    }) as typeof fetch
  };
}

describe('Agent Studio actions', () => {
  it('publishes only the chosen version with the displayed revision', async () => {
    let called = false;
    const input = event('agents', {
      intent: 'activate', resource_id: resourceId, version_id: versionId, revision: '7'
    }, (request) => {
      called = true;
      expect(new URL(request.url).pathname).toBe(`/api/v1/workspaces/${workspaceId}/agents/${resourceId}/active-version`);
      expect(request.method).toBe('POST');
      expect(request.headers.get('if-match')).toBe('"revision-7"');
      return Response.json({ id: resourceId });
    });
    await expect(saveStudioResource(input, 'http://api.test')).rejects.toMatchObject({ status: 303 });
    expect(called).toBe(true);
  });

  it('keeps a revision conflict visible instead of retrying publication', async () => {
    let calls = 0;
    const input = event('workflows', {
      intent: 'activate', resource_id: resourceId, version_id: versionId, revision: '7'
    }, () => { calls += 1; return Response.json({}, { status: 412 }); });
    expect(await saveStudioResource(input, 'http://api.test')).toMatchObject({ status: 412, data: { type: 'error' } });
    expect(calls).toBe(1);
  });

  it('never returns model credentials or an API error body in form feedback', async () => {
    const secret = crypto.randomUUID();
    const input = event('connections', { intent: 'create', name: 'Model', api_key: secret },
      () => Response.json({ detail: secret }, { status: 400 }));
    const result = await saveStudioResource(input, 'http://api.test');
    expect(result).toMatchObject({ status: 400 });
    expect(JSON.stringify(result).includes(secret)).toBe(false);
    expect(JSON.stringify(result).includes('api_key')).toBe(false);
  });

  it('rejects a stale Workspace context before any mutation', async () => {
    let called = false;
    const input = event('agents', { intent: 'create', name: 'Agent' },
      () => { called = true; return Response.json({}); }, resourceId);
    expect(await saveStudioResource(input, 'http://api.test')).toMatchObject({ status: 409 });
    expect(called).toBe(false);
  });

  it('rejects malformed resource IDs without making a mutation', async () => {
    let called = false;
    const input = event('agents', { intent: 'version', resource_id: '../connections', instructions: 'Test' },
      () => { called = true; return Response.json({}); });
    expect(await saveStudioResource(input, 'http://api.test')).toMatchObject({ status: 400 });
    expect(called).toBe(false);
  });
});
