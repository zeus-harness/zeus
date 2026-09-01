import { error } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { PageServerLoad } from './$types';

import { fetchWorkspaceCollection } from '$lib/api/collections';
import { serverApiFetcher } from '$lib/api/server';
import { getWorkspaceSettingResource } from '$lib/control-plane';

export const load: PageServerLoad = async ({ fetch, params, request, url }) => {
  const resource = getWorkspaceSettingResource(params.resource);
  if (!resource) error(404, '找不到 Workspace 设置资源。');
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const collection = await fetchWorkspaceCollection(apiFetch, resource, {
    apiBaseUrl: env.ZEUS_API_URL,
    workspaceId: params.workspaceId
  });
  return { resource, collection, workspaceId: params.workspaceId };
};
