import type { SubmitFunction } from '@sveltejs/kit';

export const WORKSPACE_CONTEXT_CHANNEL = 'zeus-workspace-context';

export type WorkspaceContextMessage = {
  type: 'workspace-selected';
  workspaceId: string;
  occurredAt: string;
};

export function publishWorkspaceSelection(workspaceId: string): void {
  if (typeof BroadcastChannel === 'undefined') return;
  const channel = new BroadcastChannel(WORKSPACE_CONTEXT_CHANNEL);
  channel.postMessage({
    type: 'workspace-selected',
    workspaceId,
    occurredAt: new Date().toISOString()
  } satisfies WorkspaceContextMessage);
  channel.close();
}

export function enhanceWorkspaceSelection(workspaceId: string): SubmitFunction {
  return () => async ({ result, update }) => {
    if (result.type === 'redirect') publishWorkspaceSelection(workspaceId);
    await update({ reset: false });
  };
}
