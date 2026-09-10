import { error } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import { fetchWorkspaceCollection } from '$lib/api/collections';
import { serverApiFetcher } from '$lib/api/server';
import { getWorkspaceSettingResource } from '$lib/control-plane';
import { loadModelConnections } from '$lib/api/agent-studio';
import { saveStudioResource } from '$lib/server/agent-studio';
import { enableWorkItemRead } from '$lib/server/work-item-capability';
import { ZeusApiError } from '$lib/api/client';

export const load: PageServerLoad = async ({ fetch, params, parent, request, url }) => {
  const resource = getWorkspaceSettingResource(params.resource);
  if (!resource) error(404, '找不到 Workspace 设置资源。');
  await parent();
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  if (resource.slug === 'connections' || resource.slug === 'model-profiles') {
    try {
      const models = await loadModelConnections(apiFetch, {
        apiBaseUrl: env.ZEUS_API_URL, workspaceId: params.workspaceId
      });
      return {
        resource, models, collection: null, workspaceId: params.workspaceId,
        selectedConnection: url.searchParams.get('connection') ?? '', saved: url.searchParams.has('saved')
      };
    } catch (cause) {
      error(cause instanceof ZeusApiError && cause.status >= 400 && cause.status < 500 ? cause.status : 502,
        '无法读取模型配置，请检查当前权限或稍后重试。');
    }
  }
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
