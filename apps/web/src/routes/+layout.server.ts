import { env } from '$env/dynamic/private';
import type { LayoutServerLoad } from './$types';

import { listUserOrganizations } from '$lib/api/identity';
import { loadCurrentPrincipal, serverApiFetcher } from '$lib/api/server';

export const load: LayoutServerLoad = async ({ fetch, request, url }) => {
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const auth = await loadCurrentPrincipal(apiFetch, env.ZEUS_API_URL);
  if (auth.status !== 'ready' || !auth.principal?.user_id) {
    return { ...auth, organizations: [] };
  }
  try {
    return {
      ...auth,
      organizations: await listUserOrganizations(apiFetch, env.ZEUS_API_URL)
    };
  } catch {
    return { ...auth, organizations: [] };
  }
};
