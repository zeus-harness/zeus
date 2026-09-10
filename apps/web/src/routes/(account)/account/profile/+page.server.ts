import { redirect } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ parent }) => {
  const auth = await parent();
  if (auth.status === 'unauthenticated') {
    redirect(303, '/login');
  }

  return {};
};
