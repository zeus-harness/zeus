import { describe, expect, it } from 'vitest';
import { workItemScopeHref } from './work-item-filters';
describe('task scope switching', () => {
  const url = new URL('http://local/ws/work-items?view=created&q=客户&status=canceled&assignee_user_id=member&cursor=old&create=1');
  it('retains compatible filters and resets pagination and create mode', () => {
    const next = new URL(workItemScopeHref(url, ''), url);
    expect(Object.fromEntries(next.searchParams)).toEqual({ q: '客户', status: 'canceled', assignee_user_id: 'member' });
  });
  it('drops a conflicting assignee only in the unassigned scope', () => {
    const next = new URL(workItemScopeHref(url, 'unassigned'), url);
    expect(Object.fromEntries(next.searchParams)).toEqual({ q: '客户', status: 'canceled', view: 'unassigned' });
    expect(new URL(workItemScopeHref(url, 'created'), url).searchParams.get('assignee_user_id')).toBe('member');
  });
});
