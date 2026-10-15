import { error, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import { serverApiFetcher } from '$lib/api/server';
import { loadOnboarding } from '$lib/server/onboarding';
import { loadModelConnections } from '$lib/api/agent-studio';
import { taskReturnTo, withTaskReturn } from '$lib/task-return';
import type { PageServerLoad } from './$types';

// Re-evaluate after every visit; never write resources or switch context on GET.
export const load: PageServerLoad = async ({ parent, fetch, request, url, params }) => {
  const context = await parent();
  const base = `/${params.workspaceId}`;
  const returnTo = taskReturnTo(url.searchParams.get('return_to')) || `${base}/studio`;
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const readiness = await loadOnboarding(apiFetch, { apiBaseUrl: env.ZEUS_API_URL, workspaceId: params.workspaceId });
  if (Object.values(readiness).includes('unavailable')) error(503, '暂时无法确认执行配置，请稍后重试。');
  let target = returnTo;
  if (readiness.model === 'missing') {
    if (!context.canManageOrganization) error(403, '请联系组织所有者接入模型；原任务已保留。');
    const organizationId = context.activeOrganization.organization_id;
    const models = await loadModelConnections(apiFetch, { apiBaseUrl: env.ZEUS_API_URL, organizationId });
    target = `/organizations/${organizationId}/settings/${models.connections.length ? 'model-profiles' : 'connections'}`;
  } else if (readiness.agent === 'missing' || readiness.workflow === 'missing') {
    if (!context.canManageWorkspace && context.activeWorkspace.role !== 'builder') error(403, '请联系工作空间所有者或构建者发布流程；原任务已保留。');
    target = readiness.agent === 'missing' ? `${base}/agents?template=requirements` : `${base}/workflows`;
  }
  redirect(303, target === returnTo ? returnTo : withTaskReturn(target, returnTo));
};
