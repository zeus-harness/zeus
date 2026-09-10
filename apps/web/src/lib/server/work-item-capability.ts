import { fail, redirect, type RequestEvent } from '@sveltejs/kit';
import { loadCapabilityCatalog, type CapabilityDefinition, type WorkspaceCapability } from '$lib/api/agent-studio';
import { jsonRequest, requestJson, requestWorkspaceJson, ZeusApiError } from '$lib/api/client';
import { loadCurrentPrincipal, serverApiUrl } from '$lib/api/server';
import type { components } from '$lib/api/generated/schema';
import { requireWorkspaceAction } from './workspace-context';

export const workItemReadDefinition = {
  registry_key: 'zeus.work-item-read', display_name: '读取当前工作项',
  description: 'Read the title, description and input of the WorkItem linked to this Run. No arguments are accepted.',
  input_schema: { type: 'object', properties: {}, additionalProperties: false },
  output_schema: { type: 'object', required: ['id', 'title', 'description', 'status', 'priority', 'input'] },
  idempotency_mode: 'supported', risk_level: 'low', executor_key: 'builtin.work_item_read'
} satisfies components['schemas']['CreateCapabilityDefinitionRequest'];

export async function enableWorkItemRead(
  event: Pick<RequestEvent, 'fetch' | 'request' | 'url'> & { params: { workspaceId?: string } },
  apiBaseUrl?: string
) {
  const context = await requireWorkspaceAction(event, apiBaseUrl, event.params.workspaceId);
  if (context.error) return context.error;
  const auth = await loadCurrentPrincipal(context.apiFetch, apiBaseUrl);
  const organizationId = auth.principal?.organization_id;
  if (!organizationId) return fail(403, { type: 'error' as const, message: '当前会话没有 Organization 上下文。' });
  const options = { apiBaseUrl, workspaceId: context.workspaceId };
  try {
    const catalog = await loadCapabilityCatalog(context.apiFetch, apiBaseUrl, organizationId);
    let definition = catalog.items.find((item) => item.registry_key === workItemReadDefinition.registry_key);
    if (!definition) {
      // Organization and Workspace permissions are independently enforced by their APIs.
      definition = await requestJson<CapabilityDefinition>(context.apiFetch,
        serverApiUrl(apiBaseUrl, `/api/v1/organizations/${organizationId}/capability-definitions`),
        jsonRequest('POST', workItemReadDefinition));
    }
    if (definition.archived_at || definition.executor_key !== workItemReadDefinition.executor_key) {
      return fail(409, { type: 'error' as const, message: '目录中的工具已归档或执行器不匹配，请联系 Organization Owner。' });
    }
    const capabilities = await requestWorkspaceJson<{ items: WorkspaceCapability[] }>(context.apiFetch, options, '/capabilities', undefined, { limit: 100 });
    const existing = capabilities.items.find((item) => item.capability_id === definition.id);
    const form = await event.request.formData();
    const approvalRequired = form.get('approval_required') === 'on';
    if (existing) {
      await requestWorkspaceJson(context.apiFetch, options, `/capabilities/${existing.capability_id}`,
        jsonRequest('PATCH', { enabled: true, approval_required: approvalRequired }, { 'if-match': `"revision-${existing.revision}"` }));
    } else {
      const payload: components['schemas']['CreateWorkspaceCapabilityRequest'] = {
        capability_id: definition.id, connection_id: null, enabled: true,
        approval_required: approvalRequired, timeout_seconds: 10, policy: {}
      };
      await requestWorkspaceJson(context.apiFetch, options, '/capabilities', jsonRequest('POST', payload));
    }
  } catch (error) {
    const status = error instanceof ZeusApiError && error.status >= 400 && error.status < 500 ? error.status : 502;
    return fail(status, { type: 'error' as const, message: status === 403
      ? '首次注册需要 Organization Owner 权限；启用工具需要 Workspace Owner 权限。'
      : '工具配置未完成。已注册的目录项会保留，可刷新后重试。' });
  }
  redirect(303, `/${context.workspaceId}/settings/capabilities?saved=1`);
}
