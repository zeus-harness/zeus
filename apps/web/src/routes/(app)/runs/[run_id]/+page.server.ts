import { fail, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import { loadWorkspaceData, ZeusApiError } from '$lib/api/client';
import {
  cancelRun,
  decideApproval,
  getRunTrace,
  listChildRuns,
  retryRun,
  runEventStreamUrl
} from '$lib/api/runs';
import { loadCurrentPrincipal, serverApiFetcher } from '$lib/api/server';

function actionError(status: number, message: string) {
  return fail(status, { type: 'error' as const, message });
}

function apiActionError(error: unknown, fallback: string) {
  const status = error instanceof ZeusApiError ? error.status : 502;
  return actionError(status >= 400 && status <= 599 ? status : 502, error instanceof Error ? error.message : fallback);
}

async function actionWorkspace(event: Parameters<NonNullable<Actions['cancel']>>[0]) {
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
    return { apiFetch, error: actionError(400, '当前会话未选择 Workspace，无法操作 Run。') };
  }
  return { apiFetch, workspaceId };
}

export const load: PageServerLoad = async ({ fetch, parent, request, params, url }) => {
  const { principal, status: authStatus } = await parent();
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const workspaceContext = {
    authStatus,
    workspaceId: principal?.workspace_id
  };
  const [trace, childRuns] = await Promise.all([
    loadWorkspaceData(apiFetch, workspaceContext, (workspaceFetch, workspaceId) =>
      getRunTrace(workspaceFetch, { apiBaseUrl: env.ZEUS_API_URL, workspaceId }, params.run_id)
    ),
    loadWorkspaceData(apiFetch, workspaceContext, (workspaceFetch, workspaceId) =>
      listChildRuns(workspaceFetch, { apiBaseUrl: env.ZEUS_API_URL, workspaceId }, params.run_id)
    )
  ]);

  return {
    trace,
    childRuns,
    runId: params.run_id,
    workspaceId: principal?.workspace_id ?? null,
    streamUrl: principal?.workspace_id
      ? runEventStreamUrl({ workspaceId: principal.workspace_id }, params.run_id)
      : null
  };
};

export const actions: Actions = {
  cancel: async (event) => {
    const context = await actionWorkspace(event);
    if (context.error) return context.error;
    const formData = await event.request.formData();
    const reason = String(formData.get('reason') ?? '').trim() || null;
    try {
      await cancelRun(
        context.apiFetch,
        { apiBaseUrl: env.ZEUS_API_URL, workspaceId: context.workspaceId },
        event.params.run_id,
        reason
      );
    } catch (error) {
      return apiActionError(error, 'Run 取消失败。');
    }
    redirect(303, `/runs/${event.params.run_id}`);
  },
  retry: async (event) => {
    const context = await actionWorkspace(event);
    if (context.error) return context.error;
    let retryRunId: string;
    try {
      const retry = await retryRun(
        context.apiFetch,
        { apiBaseUrl: env.ZEUS_API_URL, workspaceId: context.workspaceId },
        event.params.run_id,
        crypto.randomUUID()
      );
      retryRunId = retry.id;
    } catch (error) {
      return apiActionError(error, 'Run 重试失败。');
    }
    redirect(303, `/runs/${retryRunId}`);
  },
  decide: async (event) => {
    const context = await actionWorkspace(event);
    if (context.error) return context.error;
    const formData = await event.request.formData();
    const approvalId = String(formData.get('approval_id') ?? '').trim();
    const decision = String(formData.get('decision') ?? '').trim();
    const reason = String(formData.get('reason') ?? '').trim() || null;
    if (!approvalId) return actionError(400, '审批 ID 不能为空。');
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
      return apiActionError(error, '审批处理失败。');
    }
    redirect(303, `/runs/${event.params.run_id}`);
  }
};
