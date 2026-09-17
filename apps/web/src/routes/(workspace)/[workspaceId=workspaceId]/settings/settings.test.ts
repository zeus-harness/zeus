import { describe, expect, it, vi } from 'vitest';
import { actions } from './+page.server';
import type { Actions } from './$types';

vi.mock('$env/dynamic/private', () => ({ env: { ZEUS_API_URL: 'http://api.test' } }));
type Event = Parameters<NonNullable<Actions['save']>>[0];
function fixture(status = 200, name = '新名称', revision = '3') {
  const fetcher = vi.fn().mockResolvedValue(new Response('{}', { status }));
  const event = {
    params: { workspaceId: 'workspace-test' }, fetch: fetcher,
    request: new Request('http://web.test/workspace-test/settings', {
      method: 'POST', headers: { cookie: 'zeus_csrf=TEST_CSRF' },
      body: new URLSearchParams({ name, revision, status: 'archived', workspace_id: 'another-workspace' })
    }), url: new URL('http://web.test/workspace-test/settings')
  } as unknown as Event;
  return { event, fetcher };
}
describe('Workspace settings', () => {
  it('saves only the name to the route workspace with revision and CSRF protection', async () => {
    const { event, fetcher } = fixture();
    expect(await actions.save!(event)).toMatchObject({ saved: true });
    const [url, init] = fetcher.mock.calls[0];
    expect(url).toBe('http://api.test/api/v1/workspaces/workspace-test');
    expect(init.method).toBe('PATCH');
    expect(JSON.parse(init.body)).toEqual({ name: '新名称' });
    expect(init.headers.get('if-match')).toBe('"revision-3"');
    expect(init.headers.get('x-zeus-csrf')).toBe('TEST_CSRF');
    expect(init.headers.get('origin')).toBe('http://web.test');
  });
  it.each([['', '3'], ['名'.repeat(54), '3'], ['Valid', 'bad']])('rejects invalid input', async (name, revision) => {
    const { event, fetcher } = fixture(200, name, revision);
    expect(await actions.save!(event)).toMatchObject({ status: 400 });
    expect(fetcher).not.toHaveBeenCalled();
  });
  it.each([403, 412])('preserves permission/conflict failures (%s) and user input', async status => {
    const { event } = fixture(status);
    expect(await actions.save!(event)).toMatchObject({ status, data: { saved: false, name: '新名称', revision: '3' } });
  });
});
