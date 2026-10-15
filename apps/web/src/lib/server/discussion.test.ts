import { expect, it } from 'vitest';
import { discussionSafe } from './discussion';
import type { WorkflowVersion } from '$lib/api/agent-studio';
it('requires an explicit empty tool allow-list and no code environment', () => {
  for (const value of [{}, { capability_policy: {} }, { capability_policy: { allowed: ['tool'] } }, { capability_policy: { allowed: [] }, code_repository: {} }, { capability_policy: { allowed: [] }, execution_environment: 'image' }]) expect(discussionSafe(value as WorkflowVersion)).toBe(false);
  expect(discussionSafe({ capability_policy: { allowed: [] }, code_repository: null, execution_environment: null } as WorkflowVersion)).toBe(true);
});
