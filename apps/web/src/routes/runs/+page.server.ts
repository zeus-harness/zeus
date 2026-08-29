import { env } from '$env/dynamic/private';
import type { PageServerLoad } from './$types';

import { listRuns, loadWorkspaceData } from '$lib/api/workspace';
import { serverApiFetcher } from '$lib/api/server';

export const load: PageServerLoad = async ({ fetch, parent, request, url }) => {
  const { principal, status: authStatus } = await parent();
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'));
  const result = await loadWorkspaceData(
    apiFetch,
    { authStatus, workspaceId: principal?.workspace_id },
    (workspaceFetch, workspaceId) =>
      listRuns(workspaceFetch, {
        apiBaseUrl: env.ZEUS_API_URL,
        workspaceId,
        cursor: url.searchParams.get('cursor') || undefined,
        limit: 50
      })
  );

  return {
    result,
    workspaceId: principal?.workspace_id ?? null
  };
};
