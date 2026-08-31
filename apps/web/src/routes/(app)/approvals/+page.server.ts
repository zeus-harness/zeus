import { fail, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import { loadWorkspaceData } from '$lib/api/client';
import { decideApproval, listApprovals } from '$lib/api/runs';
import { loadCurrentPrincipal, serverApiFetcher } from '$lib/api/server';

function actionError(status: number, message: string) {
  return fail(status, { type: 'error' as const, message });
}

async function actionWorkspace(event: Parameters<NonNullable<Actions['decide']>>[0]) {
  const apiFetch = serverApiFetcher(
    event.fetch,
    event.request.headers.get('cookie'),
    event.url.origin
  );
  const auth = await loadCurrentPrincipal(apiFetch, env.ZEUS_API_URL);
  if (auth.status === 'unauthenticated') {
    return { apiFetch, error: actionError(401, '当前会话未登录，请先登录 Zeus。') };
  }
  if (auth.status !== 'ready') {
    return { apiFetch, error: actionError(503, '无法确认当前登录状态，认证 API 暂不可用。') };
  }
  const workspaceId = auth.principal?.workspace_id;
  if (!workspaceId) {
    return { apiFetch, error: actionError(400, '当前会话未选择 Workspace，无法处理审批。') };
  }
  return { apiFetch, workspaceId };
}

export const load: PageServerLoad = async ({ fetch, parent, request, url }) => {
  const { principal, status: authStatus } = await parent();
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const status = url.searchParams.get('status') || undefined;
  const workItemId = url.searchParams.get('work_item_id') || undefined;
  const result = await loadWorkspaceData(
    apiFetch,
    { authStatus, workspaceId: principal?.workspace_id },
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
    workspaceId: principal?.workspace_id ?? null
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
    redirect(303, `/approvals?${params.toString()}`);
  }
};
