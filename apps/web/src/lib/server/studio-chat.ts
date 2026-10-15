import type { WorkflowVersion, Agent, Workflow, CapabilityDefinition, WorkspaceCapability } from '$lib/api/agent-studio';
import { loadCapabilityCatalog } from '$lib/api/agent-studio';
import { jsonRequest, requestJson, requestWorkspaceJson, type ApiFetcher, type WorkspaceRequestOptions } from '$lib/api/client';
import { loadCurrentPrincipal, serverApiUrl } from '$lib/api/server';

export const studioTool = 'zeus.studio-resource-create';
export const studioInstructions = `你是 Zeus 的聊天助手。以自然、直接的聊天为主，回答闲聊、知识问答、分析和建议，不要把每句话都变成需求调研、计划或验收流程。只有当用户表达了需要持续跟进的具体工作，或者希望保存可复用的流程时，才调用资源创建工具。普通问答、假设示例、引用内容，以及用户明确说“只聊聊/不要创建”时，不创建资源。缺少决定资源内容的关键信息时只问一个必要问题。
工作项保存本次要处理的目标、必要背景和交付要求；流程保存可复用的方法说明。默认先提供待确认预览，由用户确认创建。用户明确说先确认、草稿或不要创建时，不能直接创建。只有用户启用本轮直接创建且表达了创建意图时才可直接创建。不要重复创建历史消息中已创建的资源；使用已有资源继续交流。工具只创建工作项或未发布流程，不会发布或执行；如用户要求实际执行，创建后说明下一步入口，敏感动作仍需审批。工具返回 proposed 只表示预览，不能声称已创建；open 表示待处理工作项，不能称为草稿；unpublished 表示未发布流程。只有工具返回实际创建状态才可以声称创建成功，并简短说明创建了什么。权限不足或失败时如实说明，不编造资源。不要在普通聊天中反复声明权限或强行列验收标准。`;

export function isStudioChat(version: WorkflowVersion): boolean {
  const policy = version.capability_policy as { studio_chat?: boolean; allowed?: unknown; allow_all?: unknown; allowed_capabilities?: unknown } | null;
  return policy?.studio_chat === true && policy.allow_all !== true && (!Array.isArray(policy.allowed_capabilities) || policy.allowed_capabilities.length === 0) && Array.isArray(policy.allowed) && policy.allowed.length === 1 && policy.allowed[0] === studioTool && !version.code_repository && !version.execution_environment;
}

export async function prepareStudioChat(fetcher: ApiFetcher, options: WorkspaceRequestOptions, sourceWorkflow: string) {
  const principal = await loadCurrentPrincipal(fetcher, options.apiBaseUrl);
  const org = principal.principal?.organization_id;
  if (!org) throw new Error('缺少组织上下文');
  const existingFlows = await requestWorkspaceJson<{ items: Workflow[] }>(fetcher, options, '/workflows', undefined, { limit: 100 });
  const configured = existingFlows.items.find(w => w.name === 'Agent Studio 聊天' && !w.archived_at && w.active_version_id);
  if (configured) return configured.id;
  const source = await requestWorkspaceJson<Workflow>(fetcher, options, `/workflows/${sourceWorkflow}`);
  const versions = await requestWorkspaceJson<WorkflowVersion[]>(fetcher, options, `/workflows/${sourceWorkflow}/versions`);
  const version = versions.find(v => v.id === source.active_version_id);
  if (!version || source.archived_at) throw new Error('请选择有效模型来源');
  const catalog = await loadCapabilityCatalog(fetcher, options.apiBaseUrl, org);
  let capability = catalog.items.find(c => c.registry_key === studioTool);
  if (!capability) capability = await requestJson<CapabilityDefinition>(fetcher, serverApiUrl(options.apiBaseUrl, `/api/v1/organizations/${org}/capability-definitions`), jsonRequest('POST', {
    registry_key: studioTool, display_name: '聊天中创建工作', executor_key: 'builtin.studio_resource_create',
    description: 'Create a WorkItem for concrete work, or an unpublished Workflow for a reusable process, only when the user wants that work recorded. Never use for casual chat or hypothetical examples. Does not publish or execute. Reuse existing resources from conversation history.',
    input_schema: { type: 'object', properties: { kind: { type: 'string', enum: ['work_item', 'workflow'] }, title: { type: 'string', minLength: 1, maxLength: 160 }, description: { type: 'string', minLength: 1, maxLength: 50000 } }, required: ['kind', 'title', 'description'], additionalProperties: false },
    output_schema: { type: 'object', required: ['id', 'kind', 'title', 'status'] }, idempotency_mode: 'supported', risk_level: 'low'
  }));
  if (capability.archived_at || capability.executor_key !== 'builtin.studio_resource_create') throw new Error('工具目录不匹配');
  const enabled = await requestWorkspaceJson<{ items: WorkspaceCapability[] }>(fetcher, options, '/capabilities', undefined, { limit: 100 });
  const existing = enabled.items.find(c => c.capability_id === capability.id);
  // Preserve an administrator's stricter approval choice on an existing binding.
  if (existing) {
    if (!existing.enabled) throw new Error('工具已被管理员停用，请先在权限设置中启用');
  } else await requestWorkspaceJson(fetcher, options, '/capabilities', jsonRequest('POST', { capability_id: capability.id, connection_id: null, enabled: true, approval_required: false, timeout_seconds: 10, policy: {} }));
  const agent = await requestWorkspaceJson<Agent>(fetcher, options, '/agents', jsonRequest('POST', { name: 'Zeus 聊天助手', description: '自然聊天，按需创建工作。' }));
  const av = await requestWorkspaceJson<{ id: string }>(fetcher, options, `/agents/${agent.id}/versions`, jsonRequest('POST', { model_profile_id: version.model_profile_id, configuration: {}, instructions: studioInstructions }));
  await requestWorkspaceJson(fetcher, options, `/agents/${agent.id}/active-version`, jsonRequest('POST', { version_id: av.id }, { 'If-Match': `"revision-${agent.revision}"` }));
  const workflow = await requestWorkspaceJson<Workflow>(fetcher, options, '/workflows', jsonRequest('POST', { name: 'Agent Studio 聊天', description: '聊天入口使用的受控流程。' }));
  const wv = await requestWorkspaceJson<{ id: string }>(fetcher, options, `/workflows/${workflow.id}/versions`, jsonRequest('POST', {
    agent_version_id: av.id, capability_policy: { studio_chat: true, allowed: [studioTool] }, approval_policy: { require_high_risk: true, fail_on_denial: false },
    experience_policy: { include_workspace: false, include_organization: false, max_entries: 0 }, input_schema: {}, output_schema: {}, max_steps: 8, max_runtime_seconds: 180, token_budget: 8192,
    retry_policy: { model_network_attempts: 2, capability_attempts: 1 }
  }));
  await requestWorkspaceJson(fetcher, options, `/workflows/${workflow.id}/active-version`, jsonRequest('POST', { version_id: wv.id }, { 'If-Match': `"revision-${workflow.revision}"` }));
  return workflow.id;
}
