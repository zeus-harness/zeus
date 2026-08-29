import { env } from '$env/dynamic/private';
import type { LayoutServerLoad } from './$types';

import { loadCurrentPrincipal, serverApiFetcher } from '$lib/api/server';

export const load: LayoutServerLoad = async ({ fetch, request }) => {
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'));
  return loadCurrentPrincipal(apiFetch, env.ZEUS_API_URL);
};
