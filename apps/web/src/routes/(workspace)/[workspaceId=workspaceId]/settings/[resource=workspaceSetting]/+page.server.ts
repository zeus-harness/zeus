import { error } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import { fetchWorkspaceCollection } from '$lib/api/collections';
import { serverApiFetcher } from '$lib/api/server';
import { getWorkspaceSettingResource } from '$lib/control-plane';
import { saveStudioResource } from '$lib/server/agent-studio';
import { enableWorkItemRead } from '$lib/server/work-item-capability';

export const load: PageServerLoad = async ({ fetch, params, parent, request, url }) => {
  const resource = getWorkspaceSettingResource(params.resource);
  if (!resource) error(404, '找不到 Workspace 设置资源。');
  await parent();
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const collection = await fetchWorkspaceCollection(apiFetch, resource, {
    apiBaseUrl: env.ZEUS_API_URL,
    workspaceId: params.workspaceId
  });
  return { resource, collection, models: null, workspaceId: params.workspaceId, selectedConnection: '', saved: false };
};

export const actions: Actions = {
  save: (event) => saveStudioResource(event, env.ZEUS_API_URL),
  enableWorkItemRead: (event) => {
    if (event.params.resource !== 'capabilities') error(400, '该操作仅用于 Workspace 工具配置。');
    return enableWorkItemRead(event, env.ZEUS_API_URL);
  }
};
