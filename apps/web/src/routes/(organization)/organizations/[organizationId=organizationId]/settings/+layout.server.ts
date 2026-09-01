import { error, redirect } from '@sveltejs/kit';
import type { LayoutServerLoad } from './$types';

import { mfaChallengeRedirect } from '$lib/server/auth';
import { canSeeIdentitySettings, hasValidTenantAccessGrant } from '$lib/tenancy/navigation';

export const load: LayoutServerLoad = async ({ parent, params, url }) => {
  const auth = await parent();
  const returnTo = `${url.pathname}${url.search}`;
  if (auth.status === 'unauthenticated') {
    redirect(303, `/login?return_to=${encodeURIComponent(returnTo)}`);
  }
  if (auth.status !== 'ready' || !auth.principal) error(503, '无法确认当前登录状态。');

  const organization = auth.organizations.find(
    (candidate) => candidate.organization_id === params.organizationId
  );
  if (!organization) error(404, '找不到该 Organization。');
  if (auth.principal.organization_id !== params.organizationId) {
    redirect(303, `/workspaces?return_to=${encodeURIComponent(returnTo)}`);
  }

  const supportAccess = hasValidTenantAccessGrant(auth.principal, params.organizationId);
  if (organization.organization_role !== 'owner' && !supportAccess) {
    error(403, '只有 Organization Owner 可以进入 Organization 设置。');
  }
  const mfaRedirect = mfaChallengeRedirect(auth.principal, returnTo);
  if (mfaRedirect) redirect(303, mfaRedirect);
  return {
    activeOrganization: organization,
    supportAccess,
    canManageIdentity: canSeeIdentitySettings(auth.principal, organization)
  };
};
