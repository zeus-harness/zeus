import { error, redirect } from '@sveltejs/kit';
import { mfaChallengeRedirect } from '$lib/server/auth';
import type { LayoutServerLoad } from './$types';
export const load: LayoutServerLoad = async ({ parent, params, url }) => {
  const auth = await parent();
  const returnTo = `${url.pathname}${url.search}`;
  if (auth.status === 'unauthenticated') redirect(303, `/login?return_to=${encodeURIComponent(returnTo)}`);
  if (auth.status !== 'ready' || !auth.principal) error(503, '无法确认登录状态。');
  const organization = auth.organizations.find(item => item.organization_id === params.organizationId);
  if (!organization) error(404, '组织不可用。');
  if (auth.principal.organization_id !== params.organizationId) redirect(303, `/workspaces?return_to=${encodeURIComponent(returnTo)}`);
  if (auth.principal.tenant_access_grant_id) error(403, '平台支持身份不能读取成员聊天。');
  const mfa = mfaChallengeRedirect(auth.principal, returnTo);
  if (mfa) redirect(303, mfa);
  return { activeOrganization: organization };
};
