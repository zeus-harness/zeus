import { redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { PageServerLoad } from './$types';
import { loadOnboarding } from '$lib/server/onboarding';
import { loadSetupStatus } from '$lib/api/setup';
import { loadWorkspaceData } from '$lib/api/client';
import { listApprovals, listRuns } from '$lib/api/runs';
import { serverApiFetcher } from '$lib/api/server';
import { listWorkItems, listWorkItemReviews } from '$lib/api/work-items';
import { taskState } from '$lib/features/work-items/task-state';

export const load: PageServerLoad = async ({ fetch, parent, params, request, url }) => {
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const [auth, setupStatus] = await Promise.all([parent(), loadSetupStatus(apiFetch, env.ZEUS_API_URL)]);
  if (setupStatus.status === 'ready' && setupStatus.data.setup_required) redirect(303, '/setup');
  if (auth.status === 'unauthenticated') redirect(303, '/login');
  const context = { authStatus: auth.status, workspaceId: params.workspaceId };
  const options = { apiBaseUrl: env.ZEUS_API_URL, workspaceId: params.workspaceId };
  const [workItems, approvals, onboarding] = await Promise.all([
    loadWorkspaceData(apiFetch, context, workspaceFetch => listWorkItems(workspaceFetch, { ...options, limit: 20 })),
    loadWorkspaceData(apiFetch, context, workspaceFetch => listApprovals(workspaceFetch, { ...options, status: 'pending' })),
    loadOnboarding(apiFetch, options)
  ]);
  const tasks = await Promise.all((workItems.data?.items ?? []).map(async item => {
    const runs = await loadWorkspaceData(apiFetch, context, workspaceFetch => listRuns(workspaceFetch, { ...options, workItemId: item.id, limit: 1 }));
    const run = runs.data?.items[0];
    const reviews = run?.status === 'succeeded' ? await loadWorkspaceData(apiFetch, context, workspaceFetch => listWorkItemReviews(workspaceFetch, options, item.id)) : null;
    const review = reviews?.data?.items.find(value => value.run_id === run?.id);
    return { item, run, progress: runs.status === 'ready' ? taskState(item, run, review) : { label: '进度暂不可用', detail: '请进入任务核对。', stage: 0 } };
  }));
  return { tasks, workItems, approvals, onboarding, workspaceId: params.workspaceId };
};
