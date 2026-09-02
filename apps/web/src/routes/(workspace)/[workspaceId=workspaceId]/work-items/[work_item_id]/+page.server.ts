import { fail, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import { loadWorkspaceData, ZeusApiError } from '$lib/api/client';
import { listWorkflows } from '$lib/api/control-plane';
import { listApprovals, listRuns, startWorkItemRun } from '$lib/api/runs';
import {
  getWorkItem,
  listWorkItemAttachments,
  listWorkItemExternalReferences,
  updateWorkItem
} from '$lib/api/work-items';
import { serverApiFetcher } from '$lib/api/server';
import { requireWorkspaceAction } from '$lib/server/workspace-context';

function actionError(status: number, message: string) {
  return fail(status, { type: 'error' as const, message });
}

async function actionWorkspace(event: Parameters<NonNullable<Actions['update']>>[0]) {
  return requireWorkspaceAction(event, env.ZEUS_API_URL, event.params.workspaceId);
}

function parseJsonObject(value: string): Record<string, unknown> {
  if (!value.trim()) return {};
  const parsed: unknown = JSON.parse(value);
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('Run input 必须是 JSON 对象。');
  }
  return parsed as Record<string, unknown>;
}

export const load: PageServerLoad = async ({ fetch, parent, request, params, url }) => {
  const { status: authStatus } = await parent();
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const workspaceContext = { authStatus, workspaceId: params.workspaceId };
  const [result, workflows, runs, approvals, attachments, externalReferences] = await Promise.all([
    loadWorkspaceData(apiFetch, workspaceContext, (workspaceFetch, workspaceId) =>
      getWorkItem(workspaceFetch, { apiBaseUrl: env.ZEUS_API_URL, workspaceId }, params.work_item_id)
    ),
    loadWorkspaceData(apiFetch, workspaceContext, (workspaceFetch, workspaceId) =>
      listWorkflows(workspaceFetch, { apiBaseUrl: env.ZEUS_API_URL, workspaceId, limit: 100 })
    ),
    loadWorkspaceData(apiFetch, workspaceContext, (workspaceFetch, workspaceId) =>
      listRuns(workspaceFetch, {
        apiBaseUrl: env.ZEUS_API_URL,
        workspaceId,
        workItemId: params.work_item_id,
        limit: 50
      })
    ),
    loadWorkspaceData(apiFetch, workspaceContext, (workspaceFetch, workspaceId) =>
      listApprovals(workspaceFetch, {
        apiBaseUrl: env.ZEUS_API_URL,
        workspaceId,
        workItemId: params.work_item_id,
        status: 'all'
      })
    ),
    loadWorkspaceData(apiFetch, workspaceContext, (workspaceFetch, workspaceId) =>
      listWorkItemAttachments(
        workspaceFetch,
        { apiBaseUrl: env.ZEUS_API_URL, workspaceId },
        params.work_item_id
      )
    ),
    loadWorkspaceData(apiFetch, workspaceContext, (workspaceFetch, workspaceId) =>
      listWorkItemExternalReferences(
        workspaceFetch,
        { apiBaseUrl: env.ZEUS_API_URL, workspaceId },
        params.work_item_id
      )
    )
  ]);

  return {
    result,
    workflows,
    runs,
    approvals,
    attachments,
    externalReferences,
    workItemId: params.work_item_id,
    workspaceId: params.workspaceId
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
      const status = error instanceof ZeusApiError && error.status === 412 ? 412 : 502;
      return actionError(status, error instanceof Error ? error.message : 'WorkItem 更新失败。');
    }
    redirect(303, `/${event.params.workspaceId}/work-items/${event.params.work_item_id}`);
  },
  start: async (event) => {
    const context = await actionWorkspace(event);
    if (context.error) return context.error;

    const formData = await event.request.formData();
    const workflowId = String(formData.get('workflow_id') ?? '').trim();
    const message = String(formData.get('message') ?? '').trim();
    if (!workflowId) return actionError(400, '请选择一个已有活动版本的 Workflow。');

    let input: Record<string, unknown>;
    try {
      input = parseJsonObject(String(formData.get('input') ?? ''));
    } catch (error) {
      return actionError(400, error instanceof Error ? error.message : 'Run input 无效。');
    }

    let runId: string;
    try {
      const started = await startWorkItemRun(
        context.apiFetch,
        { apiBaseUrl: env.ZEUS_API_URL, workspaceId: context.workspaceId },
        event.params.work_item_id,
        { workflow_id: workflowId, input, message: message || null },
        crypto.randomUUID()
      );
      runId = started.run.id;
    } catch (error) {
      const status = error instanceof ZeusApiError && error.status === 409 ? 409 : 502;
      return actionError(status, error instanceof Error ? error.message : 'Agent 启动失败。');
    }
    redirect(303, `/${event.params.workspaceId}/runs/${runId}`);
  }
};
