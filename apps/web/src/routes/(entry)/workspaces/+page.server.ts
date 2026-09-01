import { error, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import { listUserOrganizations } from '$lib/api/identity';
import { forwardZeusAuthCookies, loadCurrentPrincipal, serverApiFetcher } from '$lib/api/server';
import { safeReturnToValue } from '$lib/server/auth';
import { flattenWorkspaceOptions } from '$lib/tenancy/navigation';

function formValue(formData: FormData, name: string): string {
  const value = formData.get(name);
  return typeof value === 'string' ? value.trim() : '';
}

function selectedTarget(candidate: string, workspaceId: string, origin: string): string {
  const fallback = `/${workspaceId}`;
  const safe = safeReturnToValue(candidate, origin, fallback);
  return safe === fallback || safe.startsWith(`${fallback}/`) || safe.startsWith(`${fallback}?`)
    ? safe
    : fallback;
}

export const load: PageServerLoad = async ({ parent, url }) => {
  const auth = await parent();
  if (auth.status === 'unauthenticated') redirect(303, `/login?return_to=${encodeURIComponent('/workspaces')}`);

  const workspaces = flattenWorkspaceOptions(auth.organizations);
  const onlyWorkspace = workspaces.length === 1 ? workspaces[0] : null;
  return {
    workspaces,
    autoSelect:
      url.searchParams.get('auto') === '1' &&
      onlyWorkspace?.status === 'active' &&
      auth.principal?.workspace_id !== onlyWorkspace.id
        ? onlyWorkspace.id
        : null,
    returnTo: url.searchParams.get('return_to') ?? '',
    isPlatformAdmin: auth.principal?.platform_roles.includes('platform_admin') ?? false
  };
};

export const actions: Actions = {
  select: async ({ cookies, fetch, request, url }) => {
    const formData = await request.formData();
    const organizationId = formValue(formData, 'organization_id');
    const workspaceId = formValue(formData, 'workspace_id');
    if (!organizationId || !workspaceId) error(400, 'Organization 和 Workspace 不能为空。');

    const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
    const auth = await loadCurrentPrincipal(apiFetch, env.ZEUS_API_URL);
    if (auth.status === 'unauthenticated') redirect(303, '/login');
    if (auth.status !== 'ready') error(503, 'Workspace 切换服务暂时不可用。');

    let organizations;
    try {
      organizations = await listUserOrganizations(apiFetch, env.ZEUS_API_URL);
    } catch {
      error(503, 'Workspace 列表暂时不可用。');
    }
    const allowed = organizations.some(
      (organization) =>
        organization.organization_id === organizationId &&
        organization.workspaces.some(
          (workspace) => workspace.id === workspaceId && workspace.status === 'active'
        )
    );
    if (!allowed) error(403, '当前身份不能选择该 Workspace。');

    let response: Response;
    try {
      response = await apiFetch(
        `${env.ZEUS_API_URL?.replace(/\/+$/, '') ?? ''}/api/v1/auth/context`,
        {
          method: 'POST',
          headers: { accept: 'application/json', 'content-type': 'application/json' },
          body: JSON.stringify({ organization_id: organizationId, workspace_id: workspaceId })
        }
      );
    } catch {
      error(503, 'Workspace 切换服务暂时不可用。');
    }
    if (response.status === 401) redirect(303, '/login');
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
    if (forwardZeusAuthCookies(response, cookies) < 2) {
      error(502, 'Workspace 切换响应缺少新的 Session 凭据。');
    }
    redirect(303, selectedTarget(formValue(formData, 'return_to'), workspaceId, url.origin));
  }
};
