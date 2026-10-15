import { error, fail } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import { fetchWorkspaceCollection } from '$lib/api/collections';
import { serverApiFetcher } from '$lib/api/server';
import { getWorkspaceSettingResource } from '$lib/control-plane';
import { loadCapabilityCatalog } from '$lib/api/agent-studio';
import { requireWorkspaceAction } from '$lib/server/workspace-context';
import { jsonRequest, requestWorkspaceJson } from '$lib/api/client';
import type { WorkspaceCapability } from '$lib/api/agent-studio';
import { ZeusApiError } from '$lib/api/client';
import { saveStudioResource } from '$lib/server/agent-studio';
import { enableWorkItemRead, enableSandboxExec } from '$lib/server/work-item-capability';

export const load: PageServerLoad = async ({ fetch, params, parent, request, url }) => {
  const resource = getWorkspaceSettingResource(params.resource);
  if (!resource) error(404, '找不到 Workspace 设置资源。');
  const context = await parent();
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const collection = await fetchWorkspaceCollection(apiFetch, resource, {
    apiBaseUrl: env.ZEUS_API_URL,
    workspaceId: params.workspaceId
  });
  let catalog: Awaited<ReturnType<typeof loadCapabilityCatalog>>['items'] = [];
  if (resource.slug === 'capabilities') {
    try { catalog = (await loadCapabilityCatalog(apiFetch, env.ZEUS_API_URL, context.activeOrganization.organization_id)).items; }
    catch (cause) { if (!(cause instanceof ZeusApiError) || cause.status !== 403) throw cause; }
    collection.records = collection.records.map(record => {
      const definition = catalog.find(item => item.id === record.capability_id);
      return { ...record, display_name: definition?.display_name ?? '工具名称暂不可见',
        enabled: record.enabled === true ? '已启用' : '未启用',
        approval_required: record.approval_required === true ? '每次需要审批' : '按风险策略审批' };
    });
  }
  return { catalog, resource, collection, models: null, workspaceId: params.workspaceId, selectedConnection: '', saved: false };
};

export const actions: Actions = {
  authorization: async (event) => {
    if (event.params.resource !== 'capabilities') error(400, '该操作仅用于工具配置。');
    const context = await requireWorkspaceAction(event, env.ZEUS_API_URL, event.params.workspaceId);
    if (context.error) return context.error;
    const form = await event.request.formData();
    const id = String(form.get('capability_id') ?? '');
    const options = { apiBaseUrl: env.ZEUS_API_URL, workspaceId: context.workspaceId };
    try {
    const binding = await requestWorkspaceJson<WorkspaceCapability>(context.apiFetch, options, `/capabilities/${encodeURIComponent(id)}`);
    const policy = binding.policy && typeof binding.policy === 'object' && !Array.isArray(binding.policy) ? binding.policy : {};
    await requestWorkspaceJson(context.apiFetch, options, `/capabilities/${encodeURIComponent(id)}`,
      jsonRequest('PATCH', { policy: { ...policy, resource_authorization_required: form.get('resource_authorization_required') === 'on' } },
        { 'If-Match': `"revision-${String(form.get('revision'))}"` }));
    return { type: 'success' as const, message: '权限申请策略已保存。' };
    } catch (cause) {
      const status = cause instanceof ZeusApiError ? cause.status : 502;
      return fail(status, { type: 'error' as const, message: status === 412 ? '配置已更新，请刷新后重试。' : '授权策略保存失败，请检查当前权限。' });
    }
  },
  save: (event) => saveStudioResource(event, env.ZEUS_API_URL),
  enableSandboxExec: (event) => {
    if (event.params.resource !== 'capabilities') error(400, '该操作仅用于 Workspace 工具配置。');
    return enableSandboxExec(event, env.ZEUS_API_URL);
  },
  enableWorkItemRead: (event) => {
    if (event.params.resource !== 'capabilities') error(400, '该操作仅用于 Workspace 工具配置。');
    return enableWorkItemRead(event, env.ZEUS_API_URL);
  }
};
