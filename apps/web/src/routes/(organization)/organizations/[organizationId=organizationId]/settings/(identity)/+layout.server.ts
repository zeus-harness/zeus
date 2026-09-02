import { error } from '@sveltejs/kit';
import type { LayoutServerLoad } from './$types';

export const load: LayoutServerLoad = async ({ parent }) => {
  const context = await parent();
  if (!context.canManageIdentity) {
    error(403, '此 Organization 的身份设置由平台托管。');
  }
  return {};
};
