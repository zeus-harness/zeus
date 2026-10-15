import { describe, expect, it } from 'vitest';
import { taskState } from './task-state';
const item = { archived_at: null, status: 'open' };
describe('business task progress', () => {
  it('does not call a successful attempt resolved before human acceptance and verification', () => {
    expect(taskState(item, { id: 'current', status: 'succeeded' }).label).toBe('待验收');
    expect(taskState(item, { id: 'current', status: 'succeeded' }, { run_id: 'old', decision: 'accepted' }).label).toBe('待验收');
    expect(taskState(item, { id: 'current', status: 'succeeded' }, { run_id: 'current', decision: 'accepted' }).label).toBe('待验证归档');
  });
  it('keeps a failed latest attempt actionable despite an earlier accepted result', () => {
    expect(taskState(item, { id: 'new', status: 'failed' }, { run_id: 'old', decision: 'accepted' }).label).toBe('需要处理');
  });
  it('invalidates presentation of acceptance after the goal changes', () => {
    expect(taskState({ ...item, revision: 4 }, { id: 'current', status: 'succeeded' }, { run_id: 'current', decision: 'accepted', work_item_revision: 1 }).label).toBe('待重新验收');
  });
  it('distinguishes persistent waiting, requested changes and verified archival', () => {
    expect(taskState(item, { id: 'a', status: 'waiting_approval' }).label).toBe('等待审批');
    expect(taskState(item, { id: 'a', status: 'succeeded' }, { run_id: 'a', decision: 'needs_changes' }).label).toBe('需要修改');
    expect(taskState({ ...item, archived_at: '2026-10-01T00:00:00Z' }).label).toBe('已归档');
  });
});
