import { error, redirect } from '@sveltejs/kit';
import type { LayoutServerLoad } from './$types';

import { mfaChallengeRedirect } from '$lib/server/auth';
import { findWorkspaceOption, flattenWorkspaceOptions } from '$lib/tenancy/navigation';

export const load: LayoutServerLoad = async ({ parent, params, url }) => {
  const auth = await parent();
  const returnTo = `${url.pathname}${url.search}`;
  if (auth.status === 'unauthenticated') {
    redirect(303, `/login?return_to=${encodeURIComponent(returnTo)}`);
  }
  if (auth.status !== 'ready' || !auth.principal) {
    error(503, '无法确认当前登录状态。');
  }

  const selected = findWorkspaceOption(
    flattenWorkspaceOptions(auth.organizations),
    params.workspaceId
  );
  if (!selected || selected.status !== 'active') {
    redirect(303, `/workspaces?return_to=${encodeURIComponent(returnTo)}`);
  }
  if (
    auth.principal.workspace_id !== params.workspaceId ||
    auth.principal.organization_id !== selected.organization.organization_id
  ) {
    redirect(303, `/workspaces?return_to=${encodeURIComponent(returnTo)}`);
  }
  const mfaRedirect = mfaChallengeRedirect(auth.principal, returnTo);
  if (mfaRedirect) redirect(303, mfaRedirect);

  return {
    activeOrganization: selected.organization,
    activeWorkspace: selected,
    workspaceBase: `/${params.workspaceId}`,
    canManageWorkspace:
      selected.role === 'owner' || selected.support_access,
    canManageOrganization:
      selected.organization.organization_role === 'owner' ||
      selected.organization.support_access,
    canManageIdentity: selected.organization.can_manage_identity_settings
  };
};
