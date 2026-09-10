import { fail, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import { loadWorkspaceData } from '$lib/api/client';
import { decideApproval, listApprovals } from '$lib/api/runs';
import { serverApiFetcher } from '$lib/api/server';
import { requireWorkspaceAction } from '$lib/server/workspace-context';

function actionError(status: number, message: string) {
  return fail(status, { type: 'error' as const, message });
}

async function actionWorkspace(event: Parameters<NonNullable<Actions['decide']>>[0]) {
  return requireWorkspaceAction(event, env.ZEUS_API_URL, event.params.workspaceId);
}

export const load: PageServerLoad = async ({ fetch, parent, params, request, url }) => {
  const { status: authStatus } = await parent();
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const status = url.searchParams.get('status') || undefined;
  const workItemId = url.searchParams.get('work_item_id') || undefined;
  const result = await loadWorkspaceData(
    apiFetch,
    { authStatus, workspaceId: params.workspaceId },
    (workspaceFetch, workspaceId) =>
      listApprovals(workspaceFetch, {
        apiBaseUrl: env.ZEUS_API_URL,
        workspaceId,
        status,
        workItemId
      })
  );

  return {
    result,
    filterStatus: status ?? 'pending',
    filterWorkItemId: workItemId ?? '',
    workspaceId: params.workspaceId
  };
};

export const actions: Actions = {
  decide: async (event) => {
    const context = await actionWorkspace(event);
    if (context.error) {
      return context.error;
    }

    const formData = await event.request.formData();
    const approvalId = String(formData.get('approval_id') ?? '').trim();
    const decision = String(formData.get('decision') ?? '').trim();
    const reason = String(formData.get('reason') ?? '').trim() || null;
    if (!approvalId) {
      return actionError(400, '审批 ID 不能为空。');
    }
    if (decision !== 'approve' && decision !== 'reject') {
      return actionError(400, '审批决定无效。');
    }

    try {
      await decideApproval(
        context.apiFetch,
        { apiBaseUrl: env.ZEUS_API_URL, workspaceId: context.workspaceId },
        approvalId,
        decision,
        reason
      );
    } catch (error) {
      return actionError(502, error instanceof Error ? error.message : '审批处理失败。');
    }
    const params = new URLSearchParams({
      status: event.url.searchParams.get('status') || 'pending'
    });
    const workItemId = event.url.searchParams.get('work_item_id');
    if (workItemId) params.set('work_item_id', workItemId);
    redirect(303, `/${event.params.workspaceId}/approvals?${params.toString()}`);
  }
};
