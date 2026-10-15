import { expect, it } from 'vitest';
import { launchTask } from './task-launch';
const workspace = '019f0000-0000-7000-8000-000000000001';
const item = '019f0000-0000-7000-8000-000000000002';
const key = '019f0000-0000-7000-8000-000000000003';
function event(handler: (request: Request) => Promise<Response>, context = workspace) {
  const url = new URL(`http://web.test/${workspace}/new`);
  return { params: { workspaceId: workspace }, url, request: new Request(url, { method: 'POST', body: new URLSearchParams({ message: '验证模拟日志。确认测试通过', workflow_id: key, request_id: key }) }), fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init);
    return request.url.endsWith('/auth/me') ? Response.json({ workspace_id: context }) : handler(request);
  }) as typeof fetch };
}
it('reuses separate creation/attempt keys after an interrupted start response', async () => {
  const writes: string[] = [];
  const handler = async (request: Request) => {
    const body = await request.json();
    writes.push(request.headers.get('Idempotency-Key')!);
    if (request.url.endsWith('/work-items')) { expect(body.description).toBe('验证模拟日志。确认测试通过'); return Response.json({ id: item }); }
    expect(body.workflow_id).toBe(key);
    if (writes.length === 2) throw new Error('lost response');
    return Response.json({ run: { id: 'run' } });
  };
  expect(await launchTask(event(handler), 'http://api.test')).toMatchObject({ status: 502, data: { workItemId: item, values: { request_id: key } } });
  await expect(launchTask(event(handler), 'http://api.test')).rejects.toMatchObject({ status: 303, location: `/${workspace}/work-items/${item}` });
  expect(writes).toEqual([`task-${key}`, `task-run-${key}`, `task-${key}`, `task-run-${key}`]);
});
it('refuses a changed workspace before any business writes', async () => {
  expect(await launchTask(event(async () => { throw new Error('unexpected write'); }, 'another'), 'http://api.test')).toMatchObject({ status: 409 });
});
