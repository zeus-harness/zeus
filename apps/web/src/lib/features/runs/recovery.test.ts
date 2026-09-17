import { expect, it } from 'vitest';
import { runRecovery } from './recovery';

it('explains timeout cost uncertainty and avoids changing a terminal run', () => {
  expect(runRecovery('failed', 'model_timeout')).toContain('部分用量');
  expect(runRecovery('failed', 'token_budget_exceeded')).toContain('新 Workflow');
  expect(runRecovery('canceled', null)).toContain('原运行记录保留');
  expect(runRecovery('failed', 'unknown')).toContain('是否已产生业务操作');
  expect(runRecovery('succeeded', null)).toBeNull();
});
