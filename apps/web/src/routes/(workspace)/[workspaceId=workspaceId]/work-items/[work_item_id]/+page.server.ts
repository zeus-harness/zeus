import { workItemListReturn } from '$lib/work-item-list-return';
import { fail, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import { loadWorkspaceData, ZeusApiError } from '$lib/api/client';
import { listWorkflows } from '$lib/api/control-plane';
import { listApprovals, listRuns, startWorkItemRun, reprocessWorkItemReview } from '$lib/api/runs';
import {
  getWorkItem,
  listWorkItemReviews,
  createWorkItemReview,
  listWorkItemAttachments,
  listWorkItemExternalReferences,
  updateWorkItem
} from '$lib/api/work-items';
import { serverApiFetcher } from '$lib/api/server';
import { loadMemberOptions } from '$lib/server/member-options';
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
  const { status: authStatus, principal, canManageWorkspace, activeWorkspace } = await parent();
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const workspaceContext = { authStatus, workspaceId: params.workspaceId };
  const [result, workflows, runs, approvals, attachments, externalReferences, reviews] = await Promise.all([
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
    ),
    loadWorkspaceData(apiFetch, workspaceContext, (workspaceFetch, workspaceId) =>
      listWorkItemReviews(workspaceFetch, { apiBaseUrl: env.ZEUS_API_URL, workspaceId }, params.work_item_id, url.searchParams.get('review_cursor') ?? undefined)
    )
  ]);

  const memberOptions = await loadMemberOptions(apiFetch, { apiBaseUrl: env.ZEUS_API_URL, workspaceId: params.workspaceId }, canManageWorkspace, principal);
  return {
    ...memberOptions,
    canEdit: canManageWorkspace || ['builder', 'operator'].includes(activeWorkspace.role),
    saved: url.searchParams.get('saved') === '1',
    result,
    reviews,
    reviewCursor: url.searchParams.get('review_cursor'),
    reviewed: url.searchParams.get('reviewed') === '1',
    workflows,
    runs,
    approvals,
    attachments,
    externalReferences,
    workItemId: params.work_item_id,
    workspaceId: params.workspaceId
  };
};

function detailReturn(event: Parameters<NonNullable<Actions['edit']>>[0], suffix = ''): string {
  const url = new URL(`/${event.params.workspaceId}/work-items/${event.params.work_item_id}${suffix}`, event.url.origin);
  const target = event.url.searchParams.get('list_return');
  if (target) url.searchParams.set('list_return', workItemListReturn(target, event.params.workspaceId));
  return url.pathname + url.search + url.hash;
}

export const actions: Actions = {
  reprocess: async (event) => {
    const context = await actionWorkspace(event);
    if (context.error) return context.error;
    const form = await event.request.formData();
    const reviewId = String(form.get('review_id') ?? '').trim();
    const revision = Number(form.get('revision'));
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(reviewId) || !Number.isSafeInteger(revision) || revision < 1) {
      return actionError(400, '修改意见或工作项版本无效，请刷新后重试。');
    }
    let runId: string;
    try {
      const started = await reprocessWorkItemReview(context.apiFetch,
        { apiBaseUrl: env.ZEUS_API_URL, workspaceId: context.workspaceId },
        event.params.work_item_id, reviewId, revision);
      runId = started.run.id;
    } catch (error) {
      const status = error instanceof ZeusApiError ? error.status : 502;
      return actionError(status, status === 412 ? '工作项已更新，请刷新并核对内容后重新处理。'
        : status === 403 ? '当前会话无权重新处理此工作项。'
        : status === 409 ? '修改意见或原流程不可用，请刷新后检查。'
        : status === 422 ? '原运行上下文过大或无效，无法重新处理。'
        : '未能重新处理，请稍后重试。');
    }
    redirect(303, `/${event.params.workspaceId}/runs/${runId}`);
  },
  edit: async (event) => {
    const context = await actionWorkspace(event);
    if (context.error) return context.error;
    const fields = await event.request.formData();
    const values = Object.fromEntries(['title', 'description', 'priority', 'assignee_user_id', 'revision'].map(key => [key, String(fields.get(key) ?? '').trim()]));
    const failure = (status: number, message: string) => fail(status, { type: 'error' as const, message, editValues: values });
    const revision = Number(values.revision);
    if (!values.title || [...values.title].length > 500 || [...values.description].length > 50000 || !['low', 'normal', 'high', 'urgent'].includes(values.priority)) return failure(400, '请填写有效标题、描述和优先级。');
    if (!Number.isSafeInteger(revision) || revision < 1) return failure(400, '版本无效，请刷新后重试。');
    try {
      await updateWorkItem(context.apiFetch, { apiBaseUrl: env.ZEUS_API_URL, workspaceId: context.workspaceId }, event.params.work_item_id, revision, {
        title: values.title, description: values.description, priority: values.priority,
        assignee_user_id: values.assignee_user_id || null, clear_assignee: !values.assignee_user_id
      });
    } catch (cause) {
      const status = cause instanceof ZeusApiError ? cause.status : 502;
      return failure(status, status === 412 ? '工作项已被修改。你的输入已保留，请刷新核对最新内容后再编辑。' : status === 403 ? '当前会话无权编辑此工作项。' : '未能保存，请检查输入或稍后重试。');
    }
    redirect(303, detailReturn(event, '?saved=1'));
  },
  review: async (event) => {
    const context = await actionWorkspace(event);
    if (context.error) return context.error;
    const form = await event.request.formData();
    const run_id = String(form.get('run_id') ?? '').trim();
    const decision = String(form.get('decision') ?? '');
    const reason = String(form.get('reason') ?? '').trim();
    const revision = Number(form.get('revision'));
    if (!run_id || !['accepted', 'needs_changes'].includes(decision) || !reason || [...reason].length > 4000 || !Number.isSafeInteger(revision) || revision < 1) {
      return actionError(400, '请选择有结果的运行、验收决定，并填写 1–4000 字的原因。');
    }
    try {
      await createWorkItemReview(context.apiFetch, { apiBaseUrl: env.ZEUS_API_URL, workspaceId: context.workspaceId }, event.params.work_item_id, revision, { run_id, decision, reason });
    } catch (error) {
      const status = error instanceof ZeusApiError ? error.status : 502;
      return actionError(status, status === 412 ? '工作项已更新，请刷新并重新核对结果后提交。' : '验收未保存，请确认运行已成功、属于当前工作项且你有操作权限。');
    }
    redirect(303, detailReturn(event, '?reviewed=1#acceptance'));
  },
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
    redirect(303, detailReturn(event));
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
