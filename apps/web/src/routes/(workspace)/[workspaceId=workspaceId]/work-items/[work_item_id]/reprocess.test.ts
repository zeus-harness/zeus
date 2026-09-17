import { describe, expect, it, vi } from 'vitest';
import { actions } from './+page.server';
import type { Actions } from './$types';
vi.mock('$env/dynamic/private', () => ({ env: { ZEUS_API_URL: 'http://api.test' } }));
vi.mock('$lib/server/workspace-context', () => ({ requireWorkspaceAction: async (event: { fetch: typeof fetch }) => ({ apiFetch: event.fetch, workspaceId: 'workspace' }) }));
type Event = Parameters<NonNullable<Actions['reprocess']>>[0];
const reviewId = '01900000-0000-7000-8000-000000000001';
function event(status = 201, revision = '3', review = reviewId) {
  const fetcher = vi.fn().mockResolvedValue(Response.json(status === 201 ? { run: { id: 'new-run' } } : { detail: 'internal detail' }, { status }));
  return { fetcher, event: { params: { workspaceId: 'workspace', work_item_id: 'item' }, fetch: fetcher, request: new Request('http://web.test', { method: 'POST', body: new URLSearchParams({ review_id: review, revision, reason: 'forged', workflow_id: 'forged' }) }) } as unknown as Event };
}
describe('reprocess a human change request', () => {
  it('sends only the review reference, revision and a stable idempotency key', async () => {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const input = event();
      await expect(actions.reprocess!(input.event)).rejects.toMatchObject({ status: 303, location: '/workspace/runs/new-run' });
      const [url, init] = input.fetcher.mock.calls[0];
      expect(String(url)).toContain(`/work-items/item/reviews/${reviewId}/runs`);
      expect(new Headers(init.headers).get('if-match')).toBe('"revision-3"');
      expect(new Headers(init.headers).get('idempotency-key')).toBe(`review-reprocess-${reviewId}-3`);
      expect(JSON.parse(init.body)).toEqual({});
    }
  });
  it.each([403, 409, 412, 422, 502])('preserves status %i without exposing server details', async status => {
    const result = await actions.reprocess!(event(status).event);
    expect(result).toMatchObject({ status, data: { type: 'error' } });
    expect(JSON.stringify(result)).not.toContain('internal detail');
  });
  it.each([['0', reviewId], ['1.2', reviewId], ['3', 'invalid']])('rejects invalid references before calling the API', async (revision, review) => {
    const input = event(201, revision, review);
    expect(await actions.reprocess!(input.event)).toMatchObject({ status: 400 });
    expect(input.fetcher).not.toHaveBeenCalled();
  });
});
