import { error, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { RequestHandler } from './$types';

import { forwardZeusAuthCookies, serverApiFetcher } from '$lib/api/server';

function formValue(formData: FormData, name: string): string {
  const value = formData.get(name);
  return typeof value === 'string' ? value.trim() : '';
}

function safeReturnTo(value: string): string {
  return value.startsWith('/') && !value.startsWith('//') ? value : '/';
}

export const POST: RequestHandler = async ({ cookies, fetch, request, url }) => {
  const formData = await request.formData();
  const organizationId = formValue(formData, 'organization_id');
  const workspaceId = formValue(formData, 'workspace_id');
  if (!organizationId || !workspaceId) error(400, 'Organization 和 Workspace 不能为空。');

  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  let response: Response;
  try {
    response = await apiFetch(`${env.ZEUS_API_URL?.replace(/\/+$/, '') ?? ''}/api/v1/auth/context`, {
      method: 'POST',
      headers: { accept: 'application/json', 'content-type': 'application/json' },
      body: JSON.stringify({ organization_id: organizationId, workspace_id: workspaceId })
    });
  } catch {
    error(502, 'Workspace 切换服务暂时不可用。');
  }
  if (!response.ok) {
    let message = `Workspace 切换失败（HTTP ${response.status}）。`;
    try {
      const problem = (await response.json()) as { detail?: unknown; title?: unknown };
      if (typeof problem.detail === 'string') message = problem.detail;
      else if (typeof problem.title === 'string') message = problem.title;
    } catch {
      // Keep the stable fallback without exposing the response body.
    }
    error(response.status, message);
  }
  forwardZeusAuthCookies(response, cookies);

  redirect(303, safeReturnTo(formValue(formData, 'return_to')));
};
