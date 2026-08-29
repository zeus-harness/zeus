import { fail, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import {
  createWorkItem,
  listWorkItems,
  loadWorkspaceData,
  type CreateWorkItemInput,
  type JsonValue
} from '$lib/api/workspace';
import { loadCurrentPrincipal, serverApiFetcher } from '$lib/api/server';

function formValue(formData: FormData, name: string): string {
  const value = formData.get(name);
  return typeof value === 'string' ? value.trim() : '';
}

function parseJsonObject(value: string): JsonValue {
  if (!value) {
    return {};
  }
  const parsed: unknown = JSON.parse(value);
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('JSON 输入必须是对象。');
  }
  return parsed as JsonValue;
}

function actionError(status: number, message: string) {
  return fail(status, { type: 'error' as const, message });
}

async function actionWorkspace(event: Parameters<NonNullable<Actions['create']>>[0]) {
  const apiFetch = serverApiFetcher(event.fetch, event.request.headers.get('cookie'));
  const auth = await loadCurrentPrincipal(apiFetch, env.ZEUS_API_URL);
  if (auth.status === 'unauthenticated') {
    return { apiFetch, error: actionError(401, '当前会话未登录，请先登录 Zeus。') };
  }
  if (auth.status !== 'ready') {
    return { apiFetch, error: actionError(503, '无法确认当前登录状态，认证 API 暂不可用。') };
  }
  const workspaceId = auth.principal?.workspace_id;
  if (!workspaceId) {
    return { apiFetch, error: actionError(400, '当前会话未选择 Workspace，无法创建 WorkItem。') };
  }
  return { apiFetch, workspaceId };
}

export const load: PageServerLoad = async ({ fetch, parent, request, url }) => {
  const { principal, status: authStatus } = await parent();
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'));
  const status = url.searchParams.get('status') || undefined;
  const cursor = url.searchParams.get('cursor') || undefined;
  const result = await loadWorkspaceData(
    apiFetch,
    { authStatus, workspaceId: principal?.workspace_id },
    (workspaceFetch, workspaceId) =>
      listWorkItems(workspaceFetch, {
        apiBaseUrl: env.ZEUS_API_URL,
        workspaceId,
        status,
        cursor,
        limit: 50
      })
  );

  return {
    result,
    filterStatus: status ?? '',
    workspaceId: principal?.workspace_id ?? null
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

    let input: JsonValue;
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

    try {
      const item = await createWorkItem(
        context.apiFetch,
        { apiBaseUrl: env.ZEUS_API_URL, workspaceId: context.workspaceId },
        payload,
        crypto.randomUUID()
      );
      redirect(303, `/work-items/${item.id}`);
    } catch (error) {
      return actionError(502, error instanceof Error ? error.message : 'WorkItem 创建失败。');
    }
  }
};
