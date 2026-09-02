import { fail, type ActionFailure, type RequestEvent } from '@sveltejs/kit';

import { loadCurrentPrincipal, serverApiFetcher } from '$lib/api/server';

type OrganizationActionError = ActionFailure<{
  type: 'error';
  code: string;
  message: string;
}>;

export async function requireOrganizationAction(
  event: Pick<RequestEvent, 'fetch' | 'request' | 'url'>,
  apiBaseUrl: string | undefined,
  expectedOrganizationId: string | undefined
): Promise<
  | {
      apiFetch: typeof fetch;
      organizationId: string;
      error?: never;
    }
  | {
      apiFetch: typeof fetch;
      organizationId?: never;
      error: OrganizationActionError;
    }
> {
  const apiFetch = serverApiFetcher(
    event.fetch,
    event.request.headers.get('cookie'),
    event.url.origin
  );
  const auth = await loadCurrentPrincipal(apiFetch, apiBaseUrl);
  if (auth.status === 'unauthenticated') {
    return {
      apiFetch,
      error: fail(401, {
        type: 'error',
        code: 'authentication_required',
        message: '当前会话未登录，请先登录 Zeus。'
      })
    };
  }
  if (auth.status !== 'ready') {
    return {
      apiFetch,
      error: fail(503, {
        type: 'error',
        code: 'identity_unavailable',
        message: '无法确认当前登录状态，认证 API 暂不可用。'
      })
    };
  }
  if (
    !expectedOrganizationId ||
    auth.principal?.organization_id !== expectedOrganizationId
  ) {
    return {
      apiFetch,
      error: fail(409, {
        type: 'error',
        code: 'organization_context_changed',
        message: 'Organization 上下文已变化，请重新选择后再提交。'
      })
    };
  }
  return { apiFetch, organizationId: expectedOrganizationId };
}
