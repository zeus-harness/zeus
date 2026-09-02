import { error } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { PageServerLoad } from './$types';

import { fetchWorkspaceCollection } from '$lib/api/collections';
import { serverApiFetcher } from '$lib/api/server';
import { getManagementResource } from '$lib/control-plane';

export const load: PageServerLoad = async ({ fetch, parent, params, request, url }) => {
  const context = await parent();
  if (!context.canManageWorkspace && !['builder'].includes(context.activeWorkspace.role)) {
    error(403, '当前角色不能进入 Agent Studio。');
  }
  const resource = getManagementResource(params.resource);
  if (!resource) error(404, '找不到 Agent Studio 资源。');

  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const collection = await fetchWorkspaceCollection(apiFetch, resource, {
    apiBaseUrl: env.ZEUS_API_URL,
    workspaceId: params.workspaceId
  });
  return { resource, collection, workspaceId: params.workspaceId };
};
