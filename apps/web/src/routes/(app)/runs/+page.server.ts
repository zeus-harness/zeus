import { env } from '$env/dynamic/private';
import type { PageServerLoad } from './$types';

import { loadWorkspaceData } from '$lib/api/client';
import { listRuns } from '$lib/api/runs';
import { serverApiFetcher } from '$lib/api/server';

export const load: PageServerLoad = async ({ fetch, parent, request, url }) => {
  const { principal, status: authStatus } = await parent();
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const status = url.searchParams.get('status') || undefined;
  const workItemId = url.searchParams.get('work_item_id') || undefined;
  const cursor = url.searchParams.get('cursor') || undefined;
  const result = await loadWorkspaceData(
    apiFetch,
    { authStatus, workspaceId: principal?.workspace_id },
    (workspaceFetch, workspaceId) =>
      listRuns(workspaceFetch, {
        apiBaseUrl: env.ZEUS_API_URL,
        workspaceId,
        status,
        workItemId,
        cursor,
        limit: 50
      })
  );

  return {
    result,
    filterStatus: status ?? '',
    filterWorkItemId: workItemId ?? '',
    workspaceId: principal?.workspace_id ?? null
  };
};
