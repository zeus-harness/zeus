import { describe, expect, it } from 'vitest';
import { conversationAction, draftTitle } from './studio-conversation';

const workspace = '019f0000-0000-7000-8000-000000000001';
const item = '019f0000-0000-7000-8000-000000000002';
const run = '019f0000-0000-7000-8000-000000000003';
const key = '019f0000-0000-7000-8000-000000000004';
function event(values: Record<string, string>, handler: (request: Request) => Response | Promise<Response>, context = workspace) {
  const url = new URL(`http://web.test/${workspace}/studio`);
  return { params: { workspaceId: workspace }, url, request: new Request(url, { method: 'POST', body: new URLSearchParams(values) }),
    fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      if (request.url.endsWith('/auth/me')) return Response.json({ workspace_id: context });
      return handler(request);
    }) as typeof fetch };
}

describe('conversational operations', () => {
  it('keeps titles short without splitting unicode or dropping the original description', () => {
    expect(draftTitle('整理反馈。请分类并提出建议')).toBe('整理反馈');
    expect([...draftTitle('😀'.repeat(80))]).toHaveLength(49);
  });
  it('previews original text without writing resources or calling a model', async () => {
    const result = await conversationAction(event({ intent: 'draft', kind: 'work-item', message: '需求标题\n原始内容' }, () => { throw new Error('unexpected write'); }), 'http://api.test');
    expect(result).toMatchObject({ type: 'draft', values: { title: '需求标题', description: '需求标题\n原始内容' } });
  });
  it('creates only the confirmed WorkItem with a stable idempotency key', async () => {
    let writes = 0;
    await expect(conversationAction(event({ intent: 'create', kind: 'work-item', title: '已编辑标题', description: '已编辑描述', request_id: key }, async request => {
      writes++;
      expect(request.url).toContain(`/workspaces/${workspace}/work-items`);
      expect(request.headers.get('Idempotency-Key')).toBe(key);
      expect(await request.json()).toMatchObject({ title: '已编辑标题', description: '已编辑描述' });
      return Response.json({ id: item });
    }), 'http://api.test')).rejects.toMatchObject({ status: 303, location: `/${workspace}/studio?work_item=${item}` });
    expect(writes).toBe(1);
  });
  it('saves an unpublished workflow without creating versions or executions', async () => {
    let writes = 0;
    await expect(conversationAction(event({ intent: 'create', kind: 'workflow', title: '流程', description: '要求' }, request => {
      writes++;
      expect(new URL(request.url).pathname).toBe(`/api/v1/workspaces/${workspace}/workflows`);
      return Response.json({ id: item });
    }), 'http://api.test')).rejects.toMatchObject({ status: 303, location: `/${workspace}/studio?workflow=${item}` });
    expect(writes).toBe(1);
  });
  it('continues the authoritative session and version, ignoring client supplied replacements', async () => {
    await expect(conversationAction(event({ intent: 'send', work_item_id: item, run_id: run, message: '补充意见', request_id: key, workflow_id: key }, async request => {
      if (request.method === 'GET') return Response.json({ work_item_id: item, status: 'succeeded', session_id: 'server-session', workflow_version_id: 'server-version', input: { existing: true } });
      expect(await request.json()).toMatchObject({ session_id: 'server-session', workflow_version_id: 'server-version', input: { existing: true }, message: '补充意见' });
      expect(request.headers.get('Idempotency-Key')).toBe(key);
      return Response.json({ id: run });
    }), 'http://api.test')).rejects.toMatchObject({ status: 303 });
  });
  it.each([
    [{ work_item_id: key, status: 'succeeded' }, 400],
    [{ work_item_id: item, status: 'running' }, 409]
  ])('rejects mismatched or unfinished runs', async (previous, status) => {
    const result = await conversationAction(event({ intent: 'send', work_item_id: item, run_id: run, message: '继续', request_id: key }, request => {
      expect(request.method).toBe('GET');
      return Response.json(previous);
    }), 'http://api.test');
    expect(result).toMatchObject({ status });
  });
  it('stops writes after workspace context changes', async () => {
    const result = await conversationAction(event({ intent: 'create', kind: 'work-item', title: '标题' }, () => { throw new Error('unexpected write'); }, key), 'http://api.test');
    expect(result).toMatchObject({ status: 409 });
  });
  it('retains user input but does not expose upstream error details', async () => {
    const result = await conversationAction(event({ intent: 'create', kind: 'workflow', title: '保留的标题' }, () => Response.json({ detail: 'private upstream details' }, { status: 403 })), 'http://api.test');
    expect(result).toMatchObject({ status: 403, data: { values: { title: '保留的标题' } } });
    expect(JSON.stringify(result)).not.toContain('private upstream details');
  });
});

describe('discussion without execution privileges', () => {
  const workflow = '019f0000-0000-7000-8000-000000000005';
  const version = '019f0000-0000-7000-8000-000000000006';
  it('rejects a tool-enabled flow before creating a session or run', async () => {
    const result = await conversationAction(event({ intent: 'discuss', workflow_id: workflow, request_id: key, message: '先讨论' }, request => {
      expect(request.method).toBe('GET');
      return Response.json(request.url.endsWith('/versions') ? [{ id: version, capability_policy: { allowed: ['tool'] } }] : { active_version_id: version });
    }), 'http://api.test');
    expect(result).toMatchObject({ status: 400 });
  });
  it('creates a standalone session and a no-tool run, without creating a WorkItem', async () => {
    const writes: string[] = [];
    await expect(conversationAction(event({ intent: 'discuss', workflow_id: workflow, request_id: key, message: '先讨论目标' }, async request => {
      if (request.method === 'GET') return Response.json(request.url.endsWith('/versions') ? [{ id: version, capability_policy: { allowed: [] }, code_repository: null, execution_environment: null }] : { active_version_id: version });
      writes.push(new URL(request.url).pathname);
      const body = await request.json();
      expect(body.work_item_id).toBeNull();
      if (request.url.endsWith('/sessions')) return Response.json({ id: 'discussion-session' });
      expect(body.input).toEqual({ studio_resource_mode: 'preview' });
      expect(body).toMatchObject({ session_id: 'discussion-session', workflow_version_id: version, message: '先讨论目标' });
      return Response.json({ id: run });
    }), 'http://api.test')).rejects.toMatchObject({ location: `/${workspace}/studio?discuss=1&run=${run}` });
    expect(writes).toEqual([`/api/v1/workspaces/${workspace}/sessions`, `/api/v1/workspaces/${workspace}/runs`]);
  });
  it('rejects continuation after a flow changes its active version', async () => {
    const result = await conversationAction(event({ intent: 'discuss', run_id: run, workflow_id: workflow, request_id: key, message: '继续' }, request => {
      expect(request.method).toBe('GET');
      if (request.url.endsWith(`/runs/${run}`)) return Response.json({ work_item_id: null, status: 'succeeded', workflow_version_id: 'old-version' });
      return Response.json(request.url.endsWith('/versions') ? [{ id: version, capability_policy: { allowed: [] } }] : { active_version_id: version });
    }), 'http://api.test');
    expect(result).toMatchObject({ status: 400 });
  });
});

describe('plan provenance', () => {
  it('previews the server output instead of a substituted client message', async () => {
    const result = await conversationAction(event({ intent: 'draft', kind: 'work-item', run_id: run, message: '客户端替换' }, request => {
      expect(request.method).toBe('GET');
      return Response.json({ work_item_id: null, status: 'succeeded', output: { content: '说明\n## 正确标题\n目标和验收' } });
    }), 'http://api.test');
    expect(result).toMatchObject({ type: 'draft', values: { title: '正确标题', run_id: run, description: '说明\n## 正确标题\n目标和验收' } });
  });
  it('saves a verified discussion reference without starting execution', async () => {
    let writes = 0;
    await expect(conversationAction(event({ intent: 'create', kind: 'work-item', title: '计划', description: '目标', run_id: run, request_id: key }, async request => {
      if (request.method === 'GET') return Response.json({ status: 'succeeded', work_item_id: null });
      writes++;
      expect(await request.json()).toMatchObject({ source_kind: 'studio_discussion', external_reference: run });
      return Response.json({ id: item });
    }), 'http://api.test')).rejects.toMatchObject({ status: 303 });
    expect(writes).toBe(1);
  });
  it('refuses a work-item run as standalone discussion provenance', async () => {
    expect(await conversationAction(event({ intent: 'create', kind: 'work-item', title: '计划', description: '目标', run_id: run, request_id: key }, request => {
      expect(request.method).toBe('GET');
      return Response.json({ status: 'succeeded', work_item_id: item });
    }), 'http://api.test')).toMatchObject({ status: 400 });
  });
});

describe('resource preview authority', () => {
  const proposal = '019f0000-0000-7000-8000-000000000007';
  const events = [
    { event_type: 'tool_call', run_id: run, payload: { registry_key: 'zeus.studio-resource-create', tool_call_id: proposal } },
    { event_type: 'tool_result', run_id: run, payload: { synthetic: false, tool_call_id: proposal, result: { id: proposal, kind: 'work_item', title: '服务端草稿', description: '真实预览', status: 'proposed' } } }
  ];
  it('loads persisted proposal fields instead of trusting submitted preview text', async () => {
    const result = await conversationAction(event({ intent: 'draft', kind: 'workflow', message: '伪造', run_id: run, proposal_id: proposal }, request => {
      expect(request.method).toBe('GET');
      return Response.json(request.url.endsWith('/trace') ? { run: { status: 'succeeded', work_item_id: null }, session_events: events } : { status: 'succeeded', work_item_id: null, output: 'assistant text' });
    }), 'http://api.test');
    expect(result).toMatchObject({ type: 'draft', values: { title: '服务端草稿', description: '真实预览', kind: 'work-item', request_id: proposal } });
  });
  it('confirms edited content using the proposal id as stable creation key and preserves conversation', async () => {
    await expect(conversationAction(event({ intent: 'create', kind: 'work-item', title: '确认标题', description: '确认内容', run_id: run, proposal_id: proposal, request_id: key }, async request => {
      if (request.method === 'GET') return Response.json(request.url.endsWith('/trace') ? { run: { status: 'succeeded', work_item_id: null }, session_events: events } : { status: 'succeeded', work_item_id: null });
      expect(request.headers.get('Idempotency-Key')).toBe(proposal);
      expect(await request.json()).toMatchObject({ title: '确认标题', input: { studio_proposal_id: proposal }, external_reference: run });
      return Response.json({ id: item });
    }), 'http://api.test')).rejects.toMatchObject({ location: `/${workspace}/studio?discuss=1&run=${run}&work_item=${item}` });
  });
  it('rejects a forged proposal before writing', async () => {
    const result = await conversationAction(event({ intent: 'create', kind: 'work-item', title: '伪造', run_id: run, proposal_id: key }, request => {
      expect(request.method).toBe('GET');
      return Response.json(request.url.endsWith('/trace') ? { run: { status: 'succeeded', work_item_id: null }, session_events: events } : { status: 'succeeded', work_item_id: null });
    }), 'http://api.test');
    expect(result).toMatchObject({ status: 400 });
  });
});

it.each(['', 'yes'])('continues discussion of a saved item without starting its business workflow (direct-create=%s)', async allow => {
  const workflow = '019f0000-0000-7000-8000-000000000005';
  const version = '019f0000-0000-7000-8000-000000000006';
  const writes: string[] = [];
  await expect(conversationAction(event({ intent: 'discuss', work_item_id: item, run_id: run, workflow_id: workflow, message: '继续讨论，不执行', request_id: key, allow_create: allow }, async request => {
    if (request.method === 'GET') {
      if (request.url.endsWith(`/work-items/${item}`)) return Response.json({ id: item, title: '关联工作', description: '要求', status: 'open' });
      if (request.url.endsWith(`/runs/${run}`)) return Response.json({ work_item_id: null, status: 'succeeded', workflow_version_id: version, session_id: 'original-chat' });
      return Response.json(request.url.endsWith('/versions') ? [{ id: version, capability_policy: { allowed: [] } }] : { active_version_id: version });
    }
    writes.push(new URL(request.url).pathname);
    expect(await request.json()).toMatchObject({ session_id: 'original-chat', work_item_id: null, workflow_version_id: version, input: { studio_work_item_id: item, studio_resource_mode: allow === 'yes' ? 'create' : 'preview' } });
    return Response.json({ id: run });
  }), 'http://api.test')).rejects.toMatchObject({ location: `/${workspace}/studio?discuss=1&run=${run}&work_item=${item}` });
  expect(writes).toEqual([`/api/v1/workspaces/${workspace}/runs`]);
});
