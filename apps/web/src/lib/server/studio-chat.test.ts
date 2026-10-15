import { expect, it } from 'vitest';
import { isStudioChat, studioTool } from './studio-chat';
import { discussionSafe } from './discussion';
import type { WorkflowVersion } from '$lib/api/agent-studio';
it('accepts only the bounded chat tool with no repository or sandbox', () => {
  const policy = { studio_chat: true, allowed: [studioTool] };
  expect(isStudioChat({ capability_policy: policy } as WorkflowVersion)).toBe(true);
  for (const extra of [{ allow_all: true }, { allowed_capabilities: ['external-tool'] }, { allowed: [studioTool, 'external-tool'] }]) {
    expect(isStudioChat({ capability_policy: { ...policy, ...extra } } as WorkflowVersion)).toBe(false);
  }
  expect(isStudioChat({ capability_policy: policy, code_repository: {} } as WorkflowVersion)).toBe(false);
  expect(discussionSafe({ capability_policy: { allowed: [], allow_all: true } } as WorkflowVersion)).toBe(false);
});
