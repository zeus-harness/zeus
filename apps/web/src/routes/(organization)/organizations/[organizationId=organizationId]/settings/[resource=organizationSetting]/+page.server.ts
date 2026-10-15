import { manageInvitation } from '$lib/server/organization-invitations';
import { requestJson } from '$lib/api/client';
import { serverApiUrl } from '$lib/api/server';
import type { components } from '$lib/api/generated/schema';
import { testModel } from '$lib/server/model-test';
import { loadModelConnections } from '$lib/api/agent-studio';
import { saveStudioResource } from '$lib/server/agent-studio';
import { error } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import { fetchOrganizationCollection } from '$lib/api/collections';
import { serverApiFetcher } from '$lib/api/server';
import { organizationSettingResources } from '$lib/control-plane';

export const load: PageServerLoad = async ({ parent, fetch, params, request, url }) => {
  const resource = organizationSettingResources.find(
    (candidate) => candidate.slug === params.resource
  );
  if (!resource) error(404, '找不到 Organization 设置资源。');
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  if (resource.slug === 'connections' || resource.slug === 'model-profiles') {
    const models = await loadModelConnections(apiFetch, { apiBaseUrl: env.ZEUS_API_URL, organizationId: params.organizationId });
    return { resource, collection: null, models, organizationId: params.organizationId,
      selectedConnection: url.searchParams.get('connection') ?? '', saved: url.searchParams.has('saved') };
  }
  const auth = await parent();
  const canInvite = resource.slug === 'members' && auth.activeOrganization.organization_role === 'owner' && !auth.supportAccess;
  let invitations: components['schemas']['InvitationResponse'][] = [];
  let invitationError = '';
  if (canInvite) {
    try { invitations = await requestJson(apiFetch, serverApiUrl(env.ZEUS_API_URL, `/api/v1/organizations/${params.organizationId}/invitations`)); }
    catch { invitationError = '邀请列表暂时无法加载，请刷新后重试。'; }
  }
  const collection = await fetchOrganizationCollection(apiFetch, resource, {
    apiBaseUrl: env.ZEUS_API_URL,
    organizationId: params.organizationId
  });
  return { resource, collection, invitations, invitationError, canInvite, models: null, organizationId: params.organizationId, selectedConnection: '', saved: false };
};

export const actions: Actions = { invitation: (event) => manageInvitation(event, env.ZEUS_API_URL), testModel: (event) => testModel(event, env.ZEUS_API_URL), save: (event) => saveStudioResource(event, env.ZEUS_API_URL) };
