import { error } from '@sveltejs/kit';
import type { LayoutServerLoad } from './$types';

export const load: LayoutServerLoad = async ({ parent }) => {
  const context = await parent();
  if (!context.canManageWorkspace) {
    error(403, '只有 Workspace Owner 或有效平台支持会话可以进入 Workspace 设置。');
  }
  return {};
};
