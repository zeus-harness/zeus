import { fail, type ActionFailure, type RequestEvent } from '@sveltejs/kit';

import { loadCurrentPrincipal, serverApiFetcher } from '$lib/api/server';

type WorkspaceActionError = ActionFailure<{
  type: 'error';
  code: string;
  message: string;
}>;

type WorkspaceActionContext =
  | {
      apiFetch: typeof fetch;
      workspaceId: string;
      error?: never;
    }
  | {
      apiFetch: typeof fetch;
      workspaceId?: never;
      error: WorkspaceActionError;
    };

function actionError(status: number, code: string, message: string): WorkspaceActionError {
  return fail(status, { type: 'error', code, message });
}

export async function requireWorkspaceAction(
  event: Pick<RequestEvent, 'fetch' | 'request' | 'url'>,
  apiBaseUrl: string | undefined,
  expectedWorkspaceId: string | undefined
): Promise<WorkspaceActionContext> {
  const apiFetch = serverApiFetcher(
    event.fetch,
    event.request.headers.get('cookie'),
    event.url.origin
  );
  const auth = await loadCurrentPrincipal(apiFetch, apiBaseUrl);
  if (auth.status === 'unauthenticated') {
    return {
      apiFetch,
      error: actionError(401, 'authentication_required', '当前会话未登录，请先登录 Zeus。')
    };
  }
  if (auth.status !== 'ready') {
    return {
      apiFetch,
      error: actionError(503, 'identity_unavailable', '无法确认当前登录状态，认证 API 暂不可用。')
    };
  }
  if (
    !expectedWorkspaceId ||
    !auth.principal?.workspace_id ||
    auth.principal.workspace_id !== expectedWorkspaceId
  ) {
    return {
      apiFetch,
      error: actionError(
        409,
        'workspace_context_changed',
        'Workspace 上下文已在另一个页面切换。请重新选择后再提交。'
      )
    };
  }
  return { apiFetch, workspaceId: expectedWorkspaceId };
}
