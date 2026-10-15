import { env } from '$env/dynamic/private';
import { fail, redirect } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import { listWorkflows } from '$lib/api/control-plane';
import { serverApiFetcher } from '$lib/api/server';
import { requireWorkspaceAction } from '$lib/server/workspace-context';
import { prepareStudioChat } from '$lib/server/studio-chat';
import { studioId } from '$lib/server/agent-studio';
export const load: PageServerLoad = async ({ parent, fetch, request, url, params }) => {
  await parent();
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const workflows = await listWorkflows(apiFetch, { apiBaseUrl: env.ZEUS_API_URL, workspaceId: params.workspaceId, limit: 100 });
  return { workspaceId: params.workspaceId, workflows: workflows.items.filter(w => !w.archived_at && w.active_version_id), saved: url.searchParams.has('saved') };
};
export const actions: Actions = {
  prepare: async event => {
    const context = await requireWorkspaceAction(event, env.ZEUS_API_URL, event.params.workspaceId);
    if (context.error) return context.error;
    const fields = await event.request.formData();
    try { await prepareStudioChat(context.apiFetch, { apiBaseUrl: env.ZEUS_API_URL, workspaceId: context.workspaceId }, studioId(String(fields.get('workflow_id') ?? ''))); }
    catch { return fail(400, { message: '配置未完成。首次配置需要组织工具目录管理权限和工作空间所有者权限；请检查模型来源及工具是否被停用。已有资源保留。' }); }
    redirect(303, `/${context.workspaceId}/settings/studio?saved=1`);
  }
};
