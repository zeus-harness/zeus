import { redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { PageServerLoad } from './$types';

import { loadSetupStatus } from '$lib/api/setup';
import { loadWorkspaceData } from '$lib/api/client';
import { listApprovals, listRuns } from '$lib/api/runs';
import { serverApiFetcher } from '$lib/api/server';
import { listWorkItems } from '$lib/api/work-items';

export const load: PageServerLoad = async ({ fetch, parent, params, request, url }) => {
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const [auth, setupStatus] = await Promise.all([
    parent(),
    loadSetupStatus(apiFetch, env.ZEUS_API_URL)
  ]);

  if (setupStatus.status === 'ready' && setupStatus.data.setup_required) {
    redirect(303, '/setup');
  }
  if (auth.status === 'unauthenticated') {
    redirect(303, '/login');
  }

  const workspaceContext = { authStatus: auth.status, workspaceId: params.workspaceId };
  const requestOptions = {
    apiBaseUrl: env.ZEUS_API_URL,
    workspaceId: params.workspaceId
  };
  const [myWorkItems, blockedWorkItems, approvals, recentRuns] = await Promise.all([
    loadWorkspaceData(apiFetch, workspaceContext, (workspaceFetch, workspaceId) =>
      listWorkItems(workspaceFetch, {
        ...requestOptions,
        workspaceId,
        assigneeUserId: auth.principal?.user_id ?? undefined,
        limit: 20
      })
    ),
    loadWorkspaceData(apiFetch, workspaceContext, (workspaceFetch, workspaceId) =>
      listWorkItems(workspaceFetch, {
        ...requestOptions,
        workspaceId,
        status: 'blocked',
        limit: 10
      })
    ),
    loadWorkspaceData(apiFetch, workspaceContext, (workspaceFetch, workspaceId) =>
      listApprovals(workspaceFetch, { ...requestOptions, workspaceId, status: 'pending' })
    ),
    loadWorkspaceData(apiFetch, workspaceContext, (workspaceFetch, workspaceId) =>
      listRuns(workspaceFetch, { ...requestOptions, workspaceId, limit: 10 })
    )
  ]);

  return { myWorkItems, blockedWorkItems, approvals, recentRuns, workspaceId: params.workspaceId };
};
