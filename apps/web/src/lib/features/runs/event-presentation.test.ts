import { describe, expect, it } from 'vitest';
import type { RunEvent } from '$lib/api/runs';
import { eventLabel } from './event-presentation';

const event = (event_type: string, payload: Record<string, unknown> = {}) => ({ event_type, payload } as RunEvent);
describe('execution labels', () => {
  it('does not present intermediate completions as Run completion', () => {
    expect(eventLabel(event('experience.selection_completed'))).toBe('经验选择完成');
    expect(eventLabel(event('model.completed'))).toBe('模型响应完成');
    expect(eventLabel(event('tool.result', { status: 'succeeded' }))).toBe('工具执行结果');
  });
  it('only labels the parent Run terminal event as completed', () => {
    expect(eventLabel(event('run.status_changed', { status: 'succeeded' }))).toBe('运行完成');
    expect(eventLabel(event('run.status_changed', { status: 'failed' }))).toBe('运行失败');
    expect(eventLabel(event('child.completed', { status: 'succeeded' }))).toBe('child.completed');
  });
});
