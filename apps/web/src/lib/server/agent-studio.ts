import { withTaskReturn } from '$lib/task-return';
import { fail, redirect, type RequestEvent } from '@sveltejs/kit';
import { jsonRequest, requestJson, ZeusApiError } from '$lib/api/client';
import type { components } from '$lib/api/generated/schema';
import { serverApiUrl } from '$lib/api/server';
import { requireOrganizationAction } from './organization-context';
import { requireWorkspaceAction } from './workspace-context';

type StudioEvent = Pick<RequestEvent, 'fetch' | 'request' | 'url'> & {
  params: { workspaceId?: string; organizationId?: string; resource?: string };
};

export type StudioFeedback = { type: 'error' | 'success'; message: string; values?: Record<string, string> };
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

export function studioId(value: string): string {
  if (!uuid.test(value)) throw new Error('请选择有效的资源。');
  return value;
}

function integer(value: string, min: number, max: number): number {
  const result = Number(value);
  if (!value || !Number.isSafeInteger(result) || result < min || result > max) {
    throw new Error(`数值必须是 ${min} 到 ${max} 之间的整数。`);
  }
  return result;
}

function requestStudioJson<T>(fetcher: typeof fetch, options: { apiBaseUrl?: string; workspaceId?: string; organizationId?: string }, pathname: string, init?: RequestInit): Promise<T> {
  const prefix = options.organizationId ? `/api/v1/organizations/${options.organizationId}` : `/api/v1/workspaces/${options.workspaceId}`;
  const resourcePath = options.organizationId ? pathname.replace(/^\/connections(?=\/|$)/u, '/model-providers') : pathname;
  return requestJson<T>(fetcher, serverApiUrl(options.apiBaseUrl, prefix + resourcePath), init);
}

export async function saveStudioResource(event: StudioEvent, apiBaseUrl?: string) {
  const context = event.params.organizationId
    ? await requireOrganizationAction(event, apiBaseUrl, event.params.organizationId)
    : await requireWorkspaceAction(event, apiBaseUrl, event.params.workspaceId);
  if (context.error) return context.error;
  const resource = event.params.resource;
  if (!['agents', 'workflows', 'connections', 'model-profiles'].includes(resource ?? '')) {
    return fail(400, { type: 'error' as const, message: '该资源不支持此操作。' });
  }
  const form = await event.request.formData();
  const text = (name: string) => typeof form.get(name) === 'string' ? String(form.get(name)).trim() : '';
  const values = Object.fromEntries(
    ['name', 'description', 'instructions', 'base_url', 'model', 'connection_id', 'agent_version_id', 'model_profile_id', 'max_steps', 'max_runtime_seconds', 'token_budget', 'resource_id']
      .map((name) => [name, text(name)])
  );
  values.capability_ids = form.getAll('capability_id').filter((value): value is string => typeof value === 'string').join(',');
  const organizationId = 'organizationId' in context ? context.organizationId : undefined;
  const workspaceId = 'workspaceId' in context ? context.workspaceId : undefined;
  if (['connections', 'model-profiles'].includes(resource ?? '') && !organizationId) return fail(403, { type: 'error' as const, message: '模型供应商和模型由 Organization Owner 统一管理。' });
  if (['agents', 'workflows'].includes(resource ?? '') && !workspaceId) return fail(403, { type: 'error' as const, message: '请选择 Workspace。' });
  const options = { apiBaseUrl, workspaceId, organizationId };
  let target = event.url.pathname;
  try {
    const intent = text('intent');
    if (resource === 'agents' || resource === 'workflows') {
      if (intent === 'create') {
        if (!values.name || values.name.length > 160) throw new Error('名称不能为空，最多 160 个字符。');
        const payload: components['schemas']['CreateAgentRequest'] = { name: values.name, description: values.description };
        const created = await requestStudioJson<{ id: string }>(context.apiFetch, options, `/${resource}`, jsonRequest('POST', payload));
        target += `?selected=${created.id}`;
        if (resource === 'agents' && text('template') === 'requirements') target += '&template=requirements';
      } else {
        const id = studioId(text('resource_id'));
        target += `?selected=${id}`;
        if (intent === 'version') {
          let payload: components['schemas']['CreateAgentVersionRequest'] | components['schemas']['CreateWorkflowVersionRequest'];
          if (resource === 'agents') {
            if (!values.instructions || values.instructions.length > 200_000) throw new Error('请填写 Agent 指令，最多 200000 个字符。');
            payload = { instructions: values.instructions, configuration: {}, model_profile_id: studioId(values.model_profile_id) };
          } else {
            const allowed = form.getAll('capability_id').map((value) => studioId(String(value)));
            payload = {
              agent_version_id: studioId(values.agent_version_id),
              capability_policy: { allowed },
              approval_policy: { require_high_risk: true, fail_on_denial: false },
              max_steps: integer(text('max_steps'), 1, 1024),
              max_runtime_seconds: integer(text('max_runtime_seconds'), 1, 86_400),
              token_budget: integer(text('token_budget'), 1, 10_000_000),
              retry_policy: { model_network_attempts: 2, capability_attempts: 0 },
              input_schema: {}, output_schema: {}
            };
          }
          await requestStudioJson(context.apiFetch, options, `/${resource}/${id}/versions`, jsonRequest('POST', payload));
        } else if (intent === 'activate') {
          const revision = integer(text('revision'), 1, Number.MAX_SAFE_INTEGER);
          await requestStudioJson(context.apiFetch, options, `/${resource}/${id}/active-version`,
            jsonRequest('POST', { version_id: studioId(text('version_id')) }, { 'if-match': `"revision-${revision}"` }));
        } else throw new Error('请选择创建版本或发布版本。');
      }
    } else if (resource === 'connections' && intent === 'create') {
      const secret = typeof form.get('api_key') === 'string' ? String(form.get('api_key')).trim() : '';
      if (!values.name || !secret) throw new Error('请填写连接名称和 API Key。');
      const payload: components['schemas']['CreateConnectionRequest'] = {
        name: values.name, provider_kind: 'openai_compatible',
        configuration: { api_key_secret_name: 'api_key' }, secrets: { api_key: secret }
      };
      const connection = await requestStudioJson<{ id: string }>(context.apiFetch, options, '/connections', jsonRequest('POST', payload));
      target = `/organizations/${organizationId}/settings/model-profiles?connection=${connection.id}`;
    } else if (resource === 'connections' && intent === 'rotate') {
      const id = studioId(text('resource_id'));
      const revision = integer(text('revision'), 1, Number.MAX_SAFE_INTEGER);
      const secret = text('api_key');
      if (!secret) throw new Error('请填写新的 API Key。');
      const connection = await requestStudioJson<components['schemas']['ConnectionResponse']>(
        context.apiFetch, options, `/connections/${id}`);
      if (connection.revision !== revision) return fail(412, { type: 'error' as const, message: '连接已被更新，请刷新后重新输入密钥。' });
      const configuration = connection.configuration;
      const secretName = configuration && typeof configuration === 'object' && !Array.isArray(configuration)
        && 'api_key_secret_name' in configuration && typeof configuration.api_key_secret_name === 'string' ? configuration.api_key_secret_name : 'api_key';
      await requestStudioJson(context.apiFetch, options, `/connections/${id}/secrets/${encodeURIComponent(secretName)}`,
        jsonRequest('PUT', { secret }, { 'if-match': `"revision-${revision}"` }));
      target += '?saved=1';
    } else if (resource === 'model-profiles' && (intent === 'create' || intent === 'update')) {
      const payload: components['schemas']['CreateModelProfileRequest'] = {
        name: values.name, connection_id: studioId(values.connection_id), provider_kind: 'openai_compatible',
        base_url: values.base_url, model: values.model,
        configuration: { timeout_seconds: integer(text('timeout_seconds'), 1, 300) }
      };
      if (!payload.name || !payload.model || !payload.base_url) throw new Error('请填写模型名称、地址和模型 ID。');
      if (intent === 'update') {
        const id = studioId(text('resource_id'));
        const revision = integer(text('revision'), 1, Number.MAX_SAFE_INTEGER);
        const current = await requestStudioJson<components['schemas']['ModelProfileResponse']>(context.apiFetch, options, `/model-profiles/${id}`);
        if (current.revision !== revision) return fail(412, { type: 'error' as const, message: '模型配置已被更新，请刷新后重新修改。' });
        const configuration = current.configuration;
        payload.configuration = {
          ...(configuration && typeof configuration === 'object' && !Array.isArray(configuration) ? configuration : {}),
          timeout_seconds: integer(text('timeout_seconds'), 1, 300)
        };
        await requestStudioJson(context.apiFetch, options, `/model-profiles/${id}`,
          jsonRequest('PATCH', payload, { 'if-match': `"revision-${revision}"` }));
      } else {
        await requestStudioJson(context.apiFetch, options, '/model-profiles', jsonRequest('POST', payload));
      }
      target += '?saved=1';
    } else throw new Error('不支持该操作。');
  } catch (error) {
    if (error instanceof ZeusApiError) {
      const workflowModelMissing = resource === 'workflows' && error.status === 422 && error.message === 'select a model on the Agent version';
      const message = workflowModelMissing ? '所选 Agent 的旧版本尚未绑定模型。请到 Agents 选择组织模型，保存并发布新版本后，再回到此处选择该 Agent。无需重新填写 API Key。'
        : error.status === 412 ? '配置已被其他人更新，请刷新后重新操作。'
        : error.status === 403 ? '当前角色没有执行此操作的权限。'
          : error.status === 400 || error.status === 422 ? '配置未通过 API 校验，请检查地址、模型和所选资源。'
            : '保存失败，请稍后重试。已有资源和版本仍然保留。';
      return fail(error.status >= 400 && error.status < 500 ? error.status : 502, { type: 'error' as const, message, values });
    }
    return fail(400, { type: 'error' as const, message: error instanceof Error ? error.message : '配置无效。', values });
  }
  redirect(303, withTaskReturn(target, text('return_to')));
}
