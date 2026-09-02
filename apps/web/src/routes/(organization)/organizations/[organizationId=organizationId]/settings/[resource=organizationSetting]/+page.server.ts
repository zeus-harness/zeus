import { error } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { PageServerLoad } from './$types';

import { fetchOrganizationCollection } from '$lib/api/collections';
import { serverApiFetcher } from '$lib/api/server';
import { organizationSettingResources } from '$lib/control-plane';

export const load: PageServerLoad = async ({ fetch, params, request, url }) => {
  const resource = organizationSettingResources.find(
    (candidate) => candidate.slug === params.resource
  );
  if (!resource) error(404, '找不到 Organization 设置资源。');
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const collection = await fetchOrganizationCollection(apiFetch, resource, {
    apiBaseUrl: env.ZEUS_API_URL,
    organizationId: params.organizationId
  });
  return { resource, collection, organizationId: params.organizationId };
};
