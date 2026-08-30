import { fail, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import { getWorkItem, loadWorkspaceData, updateWorkItem } from '$lib/api/workspace';
import { loadCurrentPrincipal, serverApiFetcher } from '$lib/api/server';

function actionError(status: number, message: string) {
  return fail(status, { type: 'error' as const, message });
}

async function actionWorkspace(event: Parameters<NonNullable<Actions['update']>>[0]) {
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
    return { apiFetch, error: actionError(400, '当前会话未选择 Workspace，无法更新 WorkItem。') };
  }
  return { apiFetch, workspaceId };
}

export const load: PageServerLoad = async ({ fetch, parent, request, params, url }) => {
  const { principal, status: authStatus } = await parent();
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const result = await loadWorkspaceData(
    apiFetch,
    { authStatus, workspaceId: principal?.workspace_id },
    (workspaceFetch, workspaceId) =>
      getWorkItem(workspaceFetch, { apiBaseUrl: env.ZEUS_API_URL, workspaceId }, params.work_item_id)
  );

  return {
    result,
    workItemId: params.work_item_id,
    workspaceId: principal?.workspace_id ?? null
  };
};

export const actions: Actions = {
  update: async (event) => {
    const context = await actionWorkspace(event);
    if (context.error) {
      return context.error;
    }

    const formData = await event.request.formData();
    const status = String(formData.get('status') ?? '').trim();
    const revision = Number.parseInt(String(formData.get('revision') ?? ''), 10);
    if (!status) {
      return actionError(400, '请选择要更新的状态。');
    }
    if (!Number.isSafeInteger(revision) || revision < 1) {
      return actionError(400, 'WorkItem revision 无效，请刷新后重试。');
    }

    try {
      await updateWorkItem(
        context.apiFetch,
        { apiBaseUrl: env.ZEUS_API_URL, workspaceId: context.workspaceId },
        event.params.work_item_id,
        revision,
        { status }
      );
    } catch (error) {
      return actionError(502, error instanceof Error ? error.message : 'WorkItem 更新失败。');
    }
    redirect(303, `/work-items/${event.params.work_item_id}`);
  }
};
