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
  it('offers explicit completion only for accepted successful output', () => {
    expect(workItemNextAction('open', 'succeeded', true, true, 'accepted').title).toBe('最新结果已验收通过');
    expect(workItemNextAction('open', 'failed', true, true, 'accepted').title).toBe('上次运行失败');
    expect(workItemNextAction('completed', 'succeeded', true, true, 'accepted').title).toBe('工作已完成');
  });
  it('guides new and failed tasks to the relevant next action', () => {
    expect(workItemNextAction('open', undefined, false, true).title).toBe('先准备可运行的流程');
    expect(workItemNextAction('open', 'failed', true, true).href).toBe('#execution');
  });
});
