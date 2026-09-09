import { fail, redirect, type RequestEvent } from '@sveltejs/kit';
import { jsonRequest, requestWorkspaceJson, ZeusApiError } from '$lib/api/client';
import type { components } from '$lib/api/generated/schema';
import { requireWorkspaceAction } from './workspace-context';

type StudioEvent = Pick<RequestEvent, 'fetch' | 'request' | 'url'> & {
  params: { workspaceId?: string; resource?: string };
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

export async function saveStudioResource(event: StudioEvent, apiBaseUrl?: string) {
  const context = await requireWorkspaceAction(event, apiBaseUrl, event.params.workspaceId);
  if (context.error) return context.error;
  const resource = event.params.resource;
  if (!['agents', 'workflows', 'connections', 'model-profiles'].includes(resource ?? '')) {
    return fail(400, { type: 'error' as const, message: '该资源不支持此操作。' });
  }
  const form = await event.request.formData();
  const text = (name: string) => typeof form.get(name) === 'string' ? String(form.get(name)).trim() : '';
  const values = Object.fromEntries(
    ['name', 'description', 'instructions', 'base_url', 'model', 'connection_id', 'agent_version_id', 'model_profile_id']
      .map((name) => [name, text(name)])
  );
  const options = { apiBaseUrl, workspaceId: context.workspaceId };
  let target = event.url.pathname;
  try {
    const intent = text('intent');
    if (resource === 'agents' || resource === 'workflows') {
      if (intent === 'create') {
        if (!values.name || values.name.length > 160) throw new Error('名称不能为空，最多 160 个字符。');
        const payload: components['schemas']['CreateAgentRequest'] = { name: values.name, description: values.description };
        const created = await requestWorkspaceJson<{ id: string }>(context.apiFetch, options, `/${resource}`, jsonRequest('POST', payload));
        target += `?selected=${created.id}`;
      } else {
        const id = studioId(text('resource_id'));
        target += `?selected=${id}`;
        if (intent === 'version') {
          let payload: components['schemas']['CreateAgentVersionRequest'] | components['schemas']['CreateWorkflowVersionRequest'];
          if (resource === 'agents') {
            if (!values.instructions || values.instructions.length > 200_000) throw new Error('请填写 Agent 指令，最多 200000 个字符。');
            payload = { instructions: values.instructions, configuration: {} };
          } else {
            const allowed = form.getAll('capability_id').map((value) => studioId(String(value)));
            payload = {
              agent_version_id: studioId(values.agent_version_id),
              model_profile_id: studioId(values.model_profile_id),
              capability_policy: { allowed },
              approval_policy: { require_high_risk: true, fail_on_denial: false },
              max_steps: integer(text('max_steps'), 1, 1024),
              max_runtime_seconds: integer(text('max_runtime_seconds'), 1, 86_400),
              token_budget: integer(text('token_budget'), 1, 10_000_000),
              retry_policy: { model_network_attempts: 2, capability_attempts: 0 },
              input_schema: {}, output_schema: {}
            };
          }
          await requestWorkspaceJson(context.apiFetch, options, `/${resource}/${id}/versions`, jsonRequest('POST', payload));
        } else if (intent === 'activate') {
          const revision = integer(text('revision'), 1, Number.MAX_SAFE_INTEGER);
          await requestWorkspaceJson(context.apiFetch, options, `/${resource}/${id}/active-version`,
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
      const connection = await requestWorkspaceJson<{ id: string }>(context.apiFetch, options, '/connections', jsonRequest('POST', payload));
      target = `/${context.workspaceId}/settings/model-profiles?connection=${connection.id}`;
    } else if (resource === 'model-profiles' && intent === 'create') {
      const payload: components['schemas']['CreateModelProfileRequest'] = {
        name: values.name, connection_id: studioId(values.connection_id), provider_kind: 'openai_compatible',
        base_url: values.base_url, model: values.model,
        configuration: { timeout_seconds: integer(text('timeout_seconds'), 1, 300) }
      };
      if (!payload.name || !payload.model || !payload.base_url) throw new Error('请填写模型名称、地址和模型 ID。');
      await requestWorkspaceJson(context.apiFetch, options, '/model-profiles', jsonRequest('POST', payload));
      target += '?saved=1';
    } else throw new Error('不支持该操作。');
  } catch (error) {
    if (error instanceof ZeusApiError) {
      const message = error.status === 412 ? '配置已被其他人更新，请刷新后重新发布。'
        : error.status === 403 ? '当前角色没有执行此操作的权限。'
          : error.status === 400 || error.status === 422 ? '配置未通过 API 校验，请检查地址、模型和所选资源。'
            : '保存失败，请稍后重试。已有资源和版本仍然保留。';
      return fail(error.status >= 400 && error.status < 500 ? error.status : 502, { type: 'error' as const, message, values });
    }
    return fail(400, { type: 'error' as const, message: error instanceof Error ? error.message : '配置无效。', values });
  }
  redirect(303, target);
}
