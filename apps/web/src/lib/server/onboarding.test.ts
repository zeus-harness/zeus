import { describe, expect, it, vi } from 'vitest';
import { loadOnboarding } from './onboarding';
import { loadMemberOptions } from './member-options';
import type { CurrentPrincipal } from '$lib/api/server';
const options = { apiBaseUrl: 'http://api.test', workspaceId: 'test-workspace' };
describe('first-use readiness', () => {
  it('requires a published non-archived version for Agent and Workflow readiness', async () => {
    const fetcher = vi.fn().mockImplementation((url: string) => Response.json({ items: url.includes('model-profiles') ? [{}] : [{ active_version_id: null }, { active_version_id: 'old', archived_at: '2026-01-01' }] }));
    expect(await loadOnboarding(fetcher, options)).toEqual({ model: 'configured', agent: 'missing', workflow: 'missing' });
  });
  it('does not report forbidden or incomplete pages as missing configuration', async () => {
    const fetcher = vi.fn().mockImplementation((url: string) => url.includes('agents') ? new Response(null, { status: 403 }) : Response.json({ items: [], next_cursor: 'more' }));
    expect(await loadOnboarding(fetcher, options)).toEqual({ model: 'unavailable', agent: 'unavailable', workflow: 'unavailable' });
  });
  it('does not request the owner member directory for a normal member', async () => {
    const fetcher = vi.fn();
    const result = await loadMemberOptions(fetcher, options, false, { user_id: 'self', display_name: '本人', email: 'self@example.test' } as CurrentPrincipal);
    expect(fetcher).not.toHaveBeenCalled();
    expect(result.members.map(member => member.user_id)).toEqual(['self']);
    expect(result.memberOptionsLimited).toBe(true);
  });
  it('filters inactive member options and signals a truncated directory', async () => {
    const fetcher = vi.fn().mockResolvedValue(Response.json([{ user_id: 'active', status: 'active' }, { user_id: 'inactive', status: 'suspended' }]));
    const result = await loadMemberOptions(fetcher, options, true, null);
    expect(result.members.map(member => member.user_id)).toEqual(['active']);
  });
});
