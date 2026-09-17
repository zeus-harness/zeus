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
    params: { workspaceId: ['connections', 'model-profiles'].includes(resource) ? undefined : workspaceId, organizationId: ['connections', 'model-profiles'].includes(resource) ? workspaceId : undefined, resource }, url,
    request: new Request(url, { method: 'POST', body: form }),
    fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      if (new URL(request.url).pathname === '/api/v1/auth/me') {
        return Response.json({ workspace_id: selectedWorkspace, organization_id: selectedWorkspace });
      }
      return mutate(request);
    }) as typeof fetch
  };
}

describe('Agent Studio actions', () => {
  it('carries the requirements template into the draft without publishing or running', async () => {
    let writes = 0;
    const input = event('agents', { intent: 'create', name: '需求整理助手', template: 'requirements' }, () => {
      writes += 1;
      return Response.json({ id: resourceId });
    });
    await expect(saveStudioResource(input, 'http://api.test')).rejects.toMatchObject({
      status: 303, location: `/${workspaceId}/agents?selected=${resourceId}&template=requirements`
    });
    expect(writes).toBe(1);
  });
  it('preserves unedited model parameters and checks the displayed revision', async () => {
    let updated: Request | undefined;
    const input = event('model-profiles', {
      intent: 'update', resource_id: resourceId, revision: '7', name: 'Model', connection_id: versionId,
      base_url: 'https://model.example/v1', model: 'test-model', timeout_seconds: '45'
    }, (request) => {
      if (request.method === 'GET') return Response.json({ revision: 7, configuration: { temperature: 0.3, thinking: { type: 'disabled' } } });
      updated = request;
      return Response.json({ id: resourceId });
    });
    await expect(saveStudioResource(input, 'http://api.test')).rejects.toMatchObject({ status: 303 });
    expect(updated?.method).toBe('PATCH');
    expect(updated?.headers.get('if-match')).toBe('"revision-7"');
    expect(await updated?.json()).toMatchObject({ configuration: { temperature: 0.3, thinking: { type: 'disabled' }, timeout_seconds: 45 } });
  });

  it('rotates the configured secret name without returning it in feedback', async () => {
    const secret = crypto.randomUUID();
    let updated: Request | undefined;
    const input = event('connections', { intent: 'rotate', resource_id: resourceId, revision: '7', api_key: secret }, (request) => {
      if (request.method === 'GET') return Response.json({ revision: 7, configuration: { api_key_secret_name: 'provider_key' } });
      updated = request;
      return Response.json({ detail: secret }, { status: 412 });
    });
    const result = await saveStudioResource(input, 'http://api.test');
    expect(updated?.method).toBe('PUT');
    expect(updated?.url).toContain('/secrets/provider_key');
    expect(updated?.headers.get('if-match')).toBe('"revision-7"');
    expect(result).toMatchObject({ status: 412 });
    expect(JSON.stringify(result)).not.toContain(secret);
  });

  it('does not overwrite a newer model configuration', async () => {
    let writes = 0;
    const input = event('model-profiles', {
      intent: 'update', resource_id: resourceId, revision: '7', name: 'Model', connection_id: versionId,
      base_url: 'https://model.example/v1', model: 'test-model', timeout_seconds: '45'
    }, (request) => {
      if (request.method !== 'GET') writes += 1;
      return Response.json({ revision: 8, configuration: {} });
    });
    expect(await saveStudioResource(input, 'http://api.test')).toMatchObject({ status: 412 });
    expect(writes).toBe(0);
  });

  it('saves the selected organization model on the Agent version', async () => {
    let saved: Request | undefined;
    const input = event('agents', { intent: 'version', resource_id: resourceId, instructions: 'Summarize', model_profile_id: versionId }, (request) => {
      saved = request;
      return Response.json({ id: resourceId });
    });
    await expect(saveStudioResource(input, 'http://api.test')).rejects.toMatchObject({ status: 303 });
    expect(await saved?.json()).toMatchObject({ model_profile_id: versionId });
  });

  it('lets Workflow inherit its Agent model without a supplier or model override', async () => {
    let saved: Request | undefined;
    const input = event('workflows', { intent: 'version', resource_id: resourceId, agent_version_id: versionId,
      max_steps: '8', max_runtime_seconds: '120', token_budget: '4000' }, (request) => {
      saved = request;
      return Response.json({ id: resourceId });
    });
    await expect(saveStudioResource(input, 'http://api.test')).rejects.toMatchObject({ status: 303 });
    const body = await saved?.json();
    expect(body.agent_version_id).toBe(versionId);
    expect(body).not.toHaveProperty('model_profile_id');
    expect(body).not.toHaveProperty('connection_id');
  });

  it('explains a legacy Agent without a model and preserves entered values', async () => {
    const input = event('workflows', { intent: 'version', resource_id: resourceId, agent_version_id: versionId,
      max_steps: '8', max_runtime_seconds: '120', token_budget: '4000' }, () =>
      Response.json({ detail: 'select a model on the Agent version' }, { status: 422 }));
    const result = await saveStudioResource(input, 'http://api.test');
    expect(result).toMatchObject({ status: 422, data: { message: expect.stringContaining('旧版本尚未绑定模型'),
      values: { resource_id: resourceId, agent_version_id: versionId, max_steps: '8', token_budget: '4000' } } });
  });

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
