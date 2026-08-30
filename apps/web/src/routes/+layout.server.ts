import { env } from '$env/dynamic/private';
import type { LayoutServerLoad } from './$types';

import { loadCurrentPrincipal, serverApiFetcher } from '$lib/api/server';

export const load: LayoutServerLoad = async ({ fetch, request, url }) => {
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  return loadCurrentPrincipal(apiFetch, env.ZEUS_API_URL);
};
