import { env } from '$env/dynamic/private';
import type { PageServerLoad } from './$types';

import { getRunTrace, listChildRuns, loadWorkspaceData } from '$lib/api/workspace';
import { serverApiFetcher } from '$lib/api/server';

export const load: PageServerLoad = async ({ fetch, parent, request, params, url }) => {
  const { principal, status: authStatus } = await parent();
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const workspaceContext = {
    authStatus,
    workspaceId: principal?.workspace_id
  };
  const [trace, childRuns] = await Promise.all([
    loadWorkspaceData(apiFetch, workspaceContext, (workspaceFetch, workspaceId) =>
      getRunTrace(workspaceFetch, { apiBaseUrl: env.ZEUS_API_URL, workspaceId }, params.run_id)
    ),
    loadWorkspaceData(apiFetch, workspaceContext, (workspaceFetch, workspaceId) =>
      listChildRuns(workspaceFetch, { apiBaseUrl: env.ZEUS_API_URL, workspaceId }, params.run_id)
    )
  ]);

  return {
    trace,
    childRuns,
    runId: params.run_id,
    workspaceId: principal?.workspace_id ?? null
  };
};
