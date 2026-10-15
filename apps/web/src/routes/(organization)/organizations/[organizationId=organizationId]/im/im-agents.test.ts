import { describe, expect, it, vi } from 'vitest';
import { actions } from './+page.server';
import type { Actions } from './$types';
vi.mock('$env/dynamic/private', () => ({ env: { ZEUS_API_URL: 'http://api.test' } }));
type Event = Parameters<NonNullable<Actions['mutate']>>[0];
function invocation(overrides: Record<string, string> = {}, principal = {}) {
  const fetcher = vi.fn(async (url: RequestInfo | URL) => String(url).endsWith('/auth/me')
    ? Response.json({ organization_id: 'org', workspace_id: 'workspace', user_id: 'user', tenant_access_grant_id: null, ...principal })
    : Response.json({ id: 'run' }));
  const url = new URL('http://web.test/organizations/org/im');
  const request = new Request(url, { method: 'POST', body: new URLSearchParams({ operation: 'invoke_agent', conversation: 'conversation', agent_member_id: 'agent', source_message_id: 'message', share_result: 'yes', workspace_id: 'forged', content: 'forged', ...overrides }) });
  return { fetcher, event: { fetch: fetcher, request, url, params: { organizationId: 'org' } } as unknown as Event };
}
describe('conversation Agent invocation', () => {
  it('uses the current workspace and only sends source references with a stable idempotency key', async () => {
    const input = invocation();
    await expect(actions.mutate!(input.event)).rejects.toMatchObject({ status: 303, location: '/organizations/org/im?conversation=conversation' });
    const [url, init] = input.fetcher.mock.calls[1] as unknown as [string, RequestInit];
    expect(url).toBe('http://api.test/api/v1/workspaces/workspace/im/conversations/conversation/agent-calls');
    expect(JSON.parse(String(init.body))).toEqual({ agent_member_id: 'agent', source_message_id: 'message', create_work_item: false });
    expect(new Headers(init.headers).get('Idempotency-Key')).toBe('im:agent:message');
  });
  it('creates a persistent goal only when selected, using the same source deduplication key', async () => {
    const input = invocation({ create_work_item: 'yes' });
    await expect(actions.mutate!(input.event)).rejects.toMatchObject({ status: 303 });
    const [, init] = input.fetcher.mock.calls[1] as unknown as [string, RequestInit];
    expect(JSON.parse(String(init.body))).toEqual({ agent_member_id: 'agent', source_message_id: 'message', create_work_item: true });
    expect(new Headers(init.headers).get('Idempotency-Key')).toBe('im:agent:message');
  });
  it('requires explicit acknowledgement of result sharing', async () => {
    const input = invocation({ share_result: '' });
    expect(await actions.mutate!(input.event)).toMatchObject({ status: 400 });
    expect(input.fetcher).toHaveBeenCalledTimes(1);
  });
  it.each([{ workspace_id: null }, { tenant_access_grant_id: 'support' }, { organization_id: 'other' }])('rejects invalid context %o', async principal => {
    const input = invocation({}, principal);
    expect(await actions.mutate!(input.event)).toMatchObject({ status: 403 });
    expect(input.fetcher).toHaveBeenCalledTimes(1);
  });
});
