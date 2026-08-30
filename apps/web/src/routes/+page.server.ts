import { redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { PageServerLoad } from './$types';

import { loadSetupStatus } from '$lib/api/setup';
import { serverApiFetcher } from '$lib/api/server';

export const load: PageServerLoad = async ({ fetch, parent, request, url }) => {
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const [auth, setupStatus] = await Promise.all([
    parent(),
    loadSetupStatus(apiFetch, env.ZEUS_API_URL)
  ]);

  if (setupStatus.status === 'ready' && setupStatus.data.setup_required) {
    redirect(303, '/setup');
  }
  if (auth.status === 'unauthenticated') {
    redirect(303, '/login');
  }

  return {};
};
