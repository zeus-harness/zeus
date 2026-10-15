import { describe, expect, it, vi } from 'vitest';
import { actions } from './+page.server';
import type { Actions } from './$types';
vi.mock('$env/dynamic/private', () => ({ env: { ZEUS_API_URL: 'http://api.test' } }));
vi.mock('$lib/server/workspace-context', () => ({ requireWorkspaceAction: async (event: { fetch: typeof fetch }) => ({ apiFetch: event.fetch, workspaceId: 'workspace' }) }));
type Event = Parameters<NonNullable<Actions['archive']>>[0];
const reviewId = '01900000-0000-7000-8000-000000000001';
function input(status = 201, overrides = {}) {
  const fetcher = vi.fn().mockResolvedValue(Response.json(status === 201 ? { id: 'archive' } : { detail: 'private internal error' }, { status }));
  const url = new URL('http://web.test/workspace/work-items/item');
  return { fetcher, event: { params: { workspaceId: 'workspace', work_item_id: 'item' }, url, fetch: fetcher, request: new Request(url, { method: 'POST', body: new URLSearchParams({ review_id: reviewId, revision: '3', resolution_summary: 'Synthetic logs and tests confirm resolution', verified: 'yes', actor_id: 'forged', run_id: 'forged', ...overrides }) }) } as unknown as Event };
}
describe('verified archival action', () => {
  it('binds current revision and review, with a stable key for duplicate or interrupted submissions', async () => {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const value = input();
      await expect(actions.archive!(value.event)).rejects.toMatchObject({ status: 303, location: '/workspace/work-items/item#closure' });
      const [url, init] = value.fetcher.mock.calls[0];
      expect(String(url)).toContain('/work-items/item/archive');
      expect(JSON.parse(init.body)).toEqual({ review_id: reviewId, resolution_summary: 'Synthetic logs and tests confirm resolution' });
      expect(new Headers(init.headers).get('if-match')).toBe('"revision-3"');
      expect(new Headers(init.headers).get('idempotency-key')).toBe(`archive-${reviewId}-3`);
    }
  });
  it.each([403, 409, 412, 502])('preserves the report on failure %i and hides internal details', async status => {
    const result = await actions.archive!(input(status).event);
    expect(result).toMatchObject({ status, data: { archiveValues: 'Synthetic logs and tests confirm resolution' } });
    expect(JSON.stringify(result)).not.toContain('private internal error');
  });
  it.each([{ verified: '' }, { resolution_summary: ' ' }, { revision: '0' }, { review_id: 'forged' }])('rejects invalid or unconfirmed input %o', async overrides => {
    const value = input(201, overrides);
    expect(await actions.archive!(value.event)).toMatchObject({ status: 400 });
    expect(value.fetcher).not.toHaveBeenCalled();
  });
});
