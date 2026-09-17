import { env } from '$env/dynamic/private';
import type { PageServerLoad } from './$types';
import { listPlatformUsers } from '$lib/api/platform';
import { serverApiFetcher } from '$lib/api/server';

export const load: PageServerLoad = async ({ fetch, request, url }) => {
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const cursor = url.searchParams.get('cursor');
  const email = url.searchParams.get('email')?.trim() ?? '';
  return { users: await listPlatformUsers(apiFetch, env.ZEUS_API_URL, cursor, email), cursor, email };
};
