import { expect, it } from 'vitest';
import { taskAttemptAction } from './task-attempt';
const workspace = '019f0000-0000-7000-8000-000000000001', run = '019f0000-0000-7000-8000-000000000002';
function event(workItemId: string, canDecide = true) {
  const url = new URL(`http://web.test/${workspace}/work-items/current`);
  const writes: Request[] = [];
  return { writes, params: { workspaceId: workspace, work_item_id: 'current' }, url, request: new Request(url, { method: 'POST', body: new URLSearchParams({ run_id: run, approval_id: 'approval', decision: 'approve' }) }), fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init);
    if (request.url.endsWith('/auth/me')) return Response.json({ workspace_id: workspace });
    if (request.url.endsWith('/trace')) return Response.json({ run: { id: run, work_item_id: workItemId }, approvals: [{ id: 'approval', run_id: run, can_decide: canDecide }] });
    writes.push(request); return Response.json({});
  }) as typeof fetch };
}
it('refuses approval/retry for another task before writing', async () => {
  for (const intent of ['decide', 'retry'] as const) {
    const request = event('other');
    expect(await taskAttemptAction(request, intent, 'http://api.test')).toMatchObject({ status: 403 });
    expect(request.writes).toHaveLength(0);
  }
});
it('uses the server approval authority rather than the submitted intent', async () => {
  const request = event('current', false);
  expect(await taskAttemptAction(request, 'decide', 'http://api.test')).toMatchObject({ status: 403 });
  expect(request.writes).toHaveLength(0);
});
it('returns to the task and reuses the existing per-run retry key', async () => {
  const request = event('current');
  await expect(taskAttemptAction(request, 'retry', 'http://api.test')).rejects.toMatchObject({ status: 303, location: `/${workspace}/work-items/current` });
  expect(request.writes[0].headers.get('Idempotency-Key')).toBe(`retry-${run}`);
});
