import { error } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { PageServerLoad } from './$types';

import { getManagementResource } from '$lib/control-plane';
import { fetchWorkspaceCollection } from '$lib/api/collections';

import { serverApiFetcher } from '$lib/api/server';

export const load: PageServerLoad = async ({ params, fetch, parent, request }) => {
  const resource = getManagementResource(params.resource);

  if (!resource) {
    error(404, '找不到控制面资源');
  }

  const { principal } = await parent();
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'));
  const collection = await fetchWorkspaceCollection(apiFetch, resource, {
    apiBaseUrl: env.ZEUS_API_URL,
    workspaceId: principal?.workspace_id ?? undefined
  });

  return { resource, collection };
};
