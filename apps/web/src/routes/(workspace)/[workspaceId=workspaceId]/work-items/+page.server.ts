import { fail, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import {
  createWorkItem,
  listWorkItems,
  type CreateWorkItemInput
} from '$lib/api/work-items';
import { loadWorkspaceData } from '$lib/api/client';
import { serverApiFetcher } from '$lib/api/server';
import { requireWorkspaceAction } from '$lib/server/workspace-context';

function formValue(formData: FormData, name: string): string {
  const value = formData.get(name);
  return typeof value === 'string' ? value.trim() : '';
}

function parseJsonObject(value: string): Record<string, unknown> {
  if (!value) {
    return {};
  }
  const parsed: unknown = JSON.parse(value);
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('JSON 输入必须是对象。');
  }
  return parsed as Record<string, unknown>;
}

function actionError(status: number, message: string) {
  return fail(status, { type: 'error' as const, message });
}

async function actionWorkspace(event: Parameters<NonNullable<Actions['create']>>[0]) {
  return requireWorkspaceAction(event, env.ZEUS_API_URL, event.params.workspaceId);
}

export const load: PageServerLoad = async ({ fetch, parent, params, request, url }) => {
  const { status: authStatus } = await parent();
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const status = url.searchParams.get('status') || undefined;
  const assigneeUserId = url.searchParams.get('assignee_user_id') || undefined;
  const cursor = url.searchParams.get('cursor') || undefined;
  const result = await loadWorkspaceData(
    apiFetch,
    { authStatus, workspaceId: params.workspaceId },
    (workspaceFetch, workspaceId) =>
      listWorkItems(workspaceFetch, {
        apiBaseUrl: env.ZEUS_API_URL,
        workspaceId,
        status,
        assigneeUserId,
        cursor,
        limit: 50
      })
  );

  return {
    result,
    filterStatus: status ?? '',
    filterAssigneeUserId: assigneeUserId ?? '',
    openCreate: url.searchParams.get('create') === '1',
    workspaceId: params.workspaceId
  };
};

export const actions: Actions = {
  create: async (event) => {
    const context = await actionWorkspace(event);
    if (context.error) {
      return context.error;
    }

    const formData = await event.request.formData();
    const title = formValue(formData, 'title');
    if (!title) {
      return actionError(400, 'WorkItem 标题不能为空。');
    }

    let input: Record<string, unknown>;
    try {
      input = parseJsonObject(formValue(formData, 'input'));
    } catch (error) {
      return actionError(400, error instanceof Error ? error.message : 'JSON 输入无效。');
    }

    const payload: CreateWorkItemInput = {
      title,
      description: formValue(formData, 'description'),
      priority: formValue(formData, 'priority') || 'normal',
      assignee_user_id: formValue(formData, 'assignee_user_id') || null,
      source_kind: formValue(formData, 'source_kind') || null,
      external_reference: formValue(formData, 'external_reference') || null,
      input
    };

    let workItemId: string;
    try {
      const item = await createWorkItem(
        context.apiFetch,
        { apiBaseUrl: env.ZEUS_API_URL, workspaceId: context.workspaceId },
        payload,
        crypto.randomUUID()
      );
      workItemId = item.id;
    } catch (error) {
      return actionError(502, error instanceof Error ? error.message : 'WorkItem 创建失败。');
    }

    redirect(303, `/${event.params.workspaceId}/work-items/${workItemId}`);
  }
};
