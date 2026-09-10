import { env } from '$env/dynamic/private';
import type { PageServerLoad } from './$types';

import { listPlatformOrganizations } from '$lib/api/platform';
import { serverApiFetcher } from '$lib/api/server';

export const load: PageServerLoad = async ({ fetch, parent, request, url }) => {
  await parent();
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const organizations = await listPlatformOrganizations(apiFetch, env.ZEUS_API_URL);
  return {
    organizationCount: organizations.length,
    activeCount: organizations.filter((organization) => organization.status === 'active').length,
    suspendedCount: organizations.filter((organization) => organization.status === 'suspended').length,
    provisioningCount: organizations.filter((organization) => organization.status === 'provisioning').length
  };
};
