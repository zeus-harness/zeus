import { loadCapabilityCatalog } from '$lib/api/agent-studio';
import { getRunTrace } from '$lib/api/runs';
import { getWorkItem } from '$lib/api/work-items';
import { fail, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import { listWorkItems } from '$lib/api/work-items';
import { jsonRequest, requestWorkspaceJson } from '$lib/api/client';
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
  const { status: authStatus, activeOrganization } = await parent();
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

  const workItems = await loadWorkspaceData(apiFetch, { authStatus, workspaceId: params.workspaceId },
    workspaceFetch => listWorkItems(workspaceFetch, { apiBaseUrl: env.ZEUS_API_URL, workspaceId: params.workspaceId,
      limit: 50, q: url.searchParams.get('item_q') || undefined, cursor: url.searchParams.get('item_cursor') || undefined }));
  const options = { apiBaseUrl: env.ZEUS_API_URL, workspaceId: params.workspaceId };
  let catalog: Awaited<ReturnType<typeof loadCapabilityCatalog>>['items'] = [];
  try { catalog = (await loadCapabilityCatalog(apiFetch, env.ZEUS_API_URL, activeOrganization.organization_id)).items; } catch { /* Display-only enrichment. */ }
  const details: Record<string, { title: string; name: string; input: unknown; scope: string }> = {};
  // Bound enrichment per page; never let a failed detail request hide the approval queue.
  const rows = (result.data ?? []).slice(0, 20);
  for (let offset = 0; offset < rows.length; offset += 4) {
    await Promise.all(rows.slice(offset, offset + 4).map(async approval => {
      try {
        const trace = await getRunTrace(apiFetch, options, approval.run_id);
        const tool = trace.tool_calls.find(tool => tool.id === approval.tool_call_id);
        if (!tool) return;
        const definition = catalog.find(def => def.id === tool.capability_id);
        const item = trace.run.work_item_id ? await getWorkItem(apiFetch, options, trace.run.work_item_id) : null;
        details[approval.id] = { title: item?.title ?? '独立运行', name: definition?.display_name ?? '工具操作', input: tool.input,
          scope: definition?.executor_key === 'builtin.work_item_read' ? '只读取本次运行关联的工作项' : '按当前流程授权范围执行；请核对下方参数' };
      } catch { /* Existing detail link remains available, no permission bypass. */ }
    }));
  }
  return {
    details,
    workItems,
    itemQuery: url.searchParams.get('item_q') ?? '',
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
    if (decision !== 'approve' && decision !== 'reject' && decision !== 'revoke') {
      return actionError(400, '审批决定无效。');
    }

    try {
      if (decision === 'revoke') {
        await requestWorkspaceJson(context.apiFetch, { apiBaseUrl: env.ZEUS_API_URL, workspaceId: context.workspaceId }, `/approvals/${encodeURIComponent(approvalId)}/revoke`, jsonRequest('POST', { reason }));
      } else await decideApproval(
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
