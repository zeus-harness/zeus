import { env } from '$env/dynamic/private';
import type { PageServerLoad } from './$types';

import { loadWorkspaceData } from '$lib/api/client';
import { listWorkItems } from '$lib/api/work-items';
import { listRuns } from '$lib/api/runs';
import { serverApiFetcher } from '$lib/api/server';

export const load: PageServerLoad = async ({ fetch, parent, params, request, url }) => {
  const { status: authStatus } = await parent();
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const status = url.searchParams.get('status') || undefined;
  const workItemId = url.searchParams.get('work_item_id') || undefined;
  const cursor = url.searchParams.get('cursor') || undefined;
  const result = await loadWorkspaceData(
    apiFetch,
    { authStatus, workspaceId: params.workspaceId },
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

  const workItems = await loadWorkspaceData(apiFetch, { authStatus, workspaceId: params.workspaceId },
    workspaceFetch => listWorkItems(workspaceFetch, { apiBaseUrl: env.ZEUS_API_URL, workspaceId: params.workspaceId, limit: 50, q: url.searchParams.get('item_q') || undefined, cursor: url.searchParams.get('item_cursor') || undefined }));
  return {
    itemQuery: url.searchParams.get('item_q') ?? '',
    workItems,
    result,
    filterStatus: status ?? '',
    filterWorkItemId: workItemId ?? '',
    workspaceId: params.workspaceId
  };
};
