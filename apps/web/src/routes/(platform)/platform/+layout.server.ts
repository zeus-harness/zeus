import { error, redirect } from '@sveltejs/kit';
import type { LayoutServerLoad } from './$types';

export const load: LayoutServerLoad = async ({ parent, url }) => {
  const auth = await parent();
  if (auth.status === 'unauthenticated') {
    redirect(303, `/login?return_to=${encodeURIComponent(`${url.pathname}${url.search}`)}`);
  }
  if (auth.status !== 'ready' || !auth.principal) error(503, '无法确认当前登录状态。');
  if (!auth.principal.platform_roles.includes('platform_admin')) {
    error(403, '只有 platform_admin 可以进入平台控制台。');
  }
  return {};
};
