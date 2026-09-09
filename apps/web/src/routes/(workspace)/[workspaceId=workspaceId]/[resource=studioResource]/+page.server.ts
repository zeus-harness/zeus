import { error } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import { fetchWorkspaceCollection } from '$lib/api/collections';
import { serverApiFetcher } from '$lib/api/server';
import { getManagementResource } from '$lib/control-plane';
import { loadAgentStudio } from '$lib/api/agent-studio';
import { saveStudioResource, studioId } from '$lib/server/agent-studio';
import { ZeusApiError } from '$lib/api/client';

export const load: PageServerLoad = async ({ fetch, parent, params, request, url }) => {
  const context = await parent();
  if (!context.canManageWorkspace && !['builder'].includes(context.activeWorkspace.role)) {
    error(403, '当前角色不能进入 Agent Studio。');
  }
  const resource = getManagementResource(params.resource);
  if (!resource) error(404, '找不到 Agent Studio 资源。');

  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  if (resource.slug === 'agents' || resource.slug === 'workflows') {
    const selected = url.searchParams.get('selected');
    if (selected) {
      try { studioId(selected); } catch { error(400, '资源 ID 无效。'); }
    }
    try {
      const studio = await loadAgentStudio(apiFetch, {
        apiBaseUrl: env.ZEUS_API_URL, workspaceId: params.workspaceId
      }, resource.slug, selected, context.activeOrganization.organization_id);
      return { resource, studio, collection: null, workspaceId: params.workspaceId };
    } catch (cause) {
      error(cause instanceof ZeusApiError && cause.status >= 400 && cause.status < 500 ? cause.status : 502,
        '无法读取 Agent Studio 配置，请检查当前权限或稍后重试。');
    }
  }
  const collection = await fetchWorkspaceCollection(apiFetch, resource, {
    apiBaseUrl: env.ZEUS_API_URL,
    workspaceId: params.workspaceId
  });
  return { resource, collection, studio: null, workspaceId: params.workspaceId };
};

export const actions: Actions = { save: (event) => saveStudioResource(event, env.ZEUS_API_URL) };
