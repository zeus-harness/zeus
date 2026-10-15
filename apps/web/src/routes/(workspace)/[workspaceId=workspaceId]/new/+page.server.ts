import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';
import { loadWorkspaceData } from '$lib/api/client';
import { listWorkflows } from '$lib/api/control-plane';
import { serverApiFetcher } from '$lib/api/server';
import { launchTask } from '$lib/server/task-launch';

export const load: PageServerLoad = async ({ parent, fetch, request, params, url }) => {
  const auth = await parent();
  const workflows = await loadWorkspaceData(serverApiFetcher(fetch, request.headers.get('cookie'), url.origin), { authStatus: auth.status, workspaceId: params.workspaceId }, (apiFetch, workspaceId) => listWorkflows(apiFetch, { apiBaseUrl: env.ZEUS_API_URL, workspaceId, limit: 100 }));
  return { workflows, workspaceId: params.workspaceId, requestId: crypto.randomUUID(), canLaunch: auth.canManageWorkspace || ['builder', 'operator'].includes(auth.activeWorkspace.role) };
};
export const actions: Actions = { create: event => launchTask(event, env.ZEUS_API_URL) };
