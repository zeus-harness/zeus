import { describe, expect, it, vi } from 'vitest';
import { actions } from './+page.server';
import type { Actions } from './$types';
vi.mock('$env/dynamic/private', () => ({ env: { ZEUS_API_URL: 'http://api.test' } }));
vi.mock('$lib/server/workspace-context', () => ({ requireWorkspaceAction: async (event: { fetch: typeof fetch }) => ({ apiFetch: event.fetch, workspaceId: 'workspace' }) }));
type Event = Parameters<NonNullable<Actions['edit']>>[0];
function event(status = 200) {
  const fetcher = vi.fn().mockResolvedValue(Response.json(status === 200 ? { id: 'item' } : { code: 'precondition_failed' }, { status }));
  return { fetcher, event: { params: { workspaceId: 'workspace', work_item_id: 'item' }, fetch: fetcher, request: new Request('http://web.test', { method: 'POST', body: new URLSearchParams({ title: '新标题', description: '新描述', priority: 'high', assignee_user_id: '', revision: '3' }) }) } as unknown as Event };
}
describe('work item editing', () => {
  it('sends visible revision and explicitly clears the assignee without changing status', async () => {
    const input = event();
    await expect(actions.edit!(input.event)).rejects.toMatchObject({ status: 303 });
    const [, init] = input.fetcher.mock.calls[0];
    expect(new Headers(init.headers).get('if-match')).toBe('"revision-3"');
    expect(JSON.parse(init.body)).toEqual({ title: '新标题', description: '新描述', priority: 'high', assignee_user_id: null, clear_assignee: true });
  });
  it('preserves input and stale revision on conflict', async () => {
    const input = event(412);
    expect(await actions.edit!(input.event)).toMatchObject({ status: 412, data: { editValues: { title: '新标题', revision: '3' } } });
  });
  it('reports forbidden without exposing backend details', async () => {
    const input = event(403);
    expect(await actions.edit!(input.event)).toMatchObject({ status: 403, data: { message: '当前会话无权编辑此工作项。' } });
  });
});
