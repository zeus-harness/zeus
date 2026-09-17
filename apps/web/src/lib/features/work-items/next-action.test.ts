import { describe, expect, it } from 'vitest';
import { workItemNextAction } from './next-action';
describe('task next action', () => {
  it('prioritizes a canceled task over missing configuration', () => {
    expect(workItemNextAction('canceled', undefined, false, true).href).toBe('#update-status');
    expect(workItemNextAction('canceled', undefined, false, false).action).toBe('');
  });
  it('prioritizes an existing run over configuration setup', () => {
    expect(workItemNextAction('open', 'waiting_approval', false, true).href).toBe('#execution');
    expect(workItemNextAction('open', 'succeeded', false, true).href).toBe('#acceptance');
  });
  it('guides new and failed tasks to the relevant next action', () => {
    expect(workItemNextAction('open', undefined, false, true).title).toBe('先准备可运行的流程');
    expect(workItemNextAction('open', 'failed', true, true).href).toBe('#execution');
  });
});
