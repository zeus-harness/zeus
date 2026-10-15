import { error, redirect } from '@sveltejs/kit';
import { mfaChallengeRedirect } from '$lib/server/auth';
import type { PageServerLoad } from './$types';
export const load: PageServerLoad = async ({ parent }) => {
  const auth = await parent();
  if (auth.status === 'unauthenticated') redirect(303, '/login?return_to=%2Fmanagement');
  if (auth.status !== 'ready' || !auth.principal) error(503, '登录状态暂不可用。');
  const mfa = mfaChallengeRedirect(auth.principal, '/management');
  if (mfa) redirect(303, mfa);
  return {};
};
