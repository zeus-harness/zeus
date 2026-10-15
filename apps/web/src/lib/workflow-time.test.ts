import { describe, expect, it } from 'vitest';
import { workflowTimeSummary } from './workflow-time';

describe('Workflow time policy', () => {
  it('distinguishes legacy wall time from active budgets', () => {
    expect(workflowTimeSummary({}, 900)).toContain('包含等待');
    expect(workflowTimeSummary({ runtime_clock: 'active', wait_timeout_seconds: 604800, business_timeout_seconds: 2592000 }, 900))
      .toBe('执行预算 900 秒 · 单次等待 7 天 · 总期限 30 天');
  });
});
