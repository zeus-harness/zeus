import { isStudioChat } from './studio-chat';
import { jsonRequest, requestWorkspaceJson, type ApiFetcher, type WorkspaceRequestOptions } from '$lib/api/client';
import type { Agent, Workflow, WorkflowVersion } from '$lib/api/agent-studio';

export function discussionSafe(version: WorkflowVersion): boolean {
  const policy = version.capability_policy as { allowed?: unknown; allow_all?: unknown; allowed_capabilities?: unknown } | null;
  return policy?.allow_all !== true && (!Array.isArray(policy?.allowed_capabilities) || policy.allowed_capabilities.length === 0) && Array.isArray(policy?.allowed) && policy.allowed.length === 0 && !version.code_repository && !version.execution_environment;
}
export async function discussionVersion(fetcher: ApiFetcher, options: WorkspaceRequestOptions, workflowId: string) {
  const workflow = await requestWorkspaceJson<Workflow>(fetcher, options, `/workflows/${workflowId}`);
  const versions = await requestWorkspaceJson<WorkflowVersion[]>(fetcher, options, `/workflows/${workflowId}/versions`);
  const version = versions.find(v => v.id === workflow.active_version_id);
  if (workflow.archived_at || !version || (!discussionSafe(version) && !isStudioChat(version))) throw new Error('请选择已发布且没有工具、仓库和执行环境的讨论流程。');
  return version;
}

/** Explicit setup action. All writes retain normal Builder permissions and version checks. */
export async function prepareDiscussion(fetcher: ApiFetcher, options: WorkspaceRequestOptions, sourceWorkflow: string) {
  const source = await requestWorkspaceJson<Workflow>(fetcher, options, `/workflows/${sourceWorkflow}`);
  const versions = await requestWorkspaceJson<WorkflowVersion[]>(fetcher, options, `/workflows/${sourceWorkflow}/versions`);
  const version = versions.find(v => v.id === source.active_version_id);
  if (!version || source.archived_at) throw new Error('请先选择有效的已发布流程作为模型来源。');
  const agent = await requestWorkspaceJson<Agent>(fetcher, options, '/agents', jsonRequest('POST', { name: '需求讨论助手', description: '只讨论和澄清需求，不执行工具。' }));
  const av = await requestWorkspaceJson<{ id: string }>(fetcher, options, `/agents/${agent.id}/versions`, jsonRequest('POST', {
    model_profile_id: version.model_profile_id, configuration: {},
    instructions: '你是需求讨论助手。先回应用户的问题，再就必要的缺失信息提出最多三个澄清问题。信息充分时给出简短计划、范围和可检查的验收条件。清楚区分事实与建议。你没有工具权限，不得声称已创建工作项、发布流程或执行任何操作。用户确认后由界面的独立按钮创建草稿；不能把对话当成执行授权。'
  }));
  await requestWorkspaceJson(fetcher, options, `/agents/${agent.id}/active-version`, jsonRequest('POST', { version_id: av.id }, { 'If-Match': `"revision-${agent.revision}"` }));
  const workflow = await requestWorkspaceJson<Workflow>(fetcher, options, '/workflows', jsonRequest('POST', { name: '需求讨论（无工具）', description: '讨论和规划专用；不绑定仓库，不允许工具。' }));
  const wv = await requestWorkspaceJson<{ id: string }>(fetcher, options, `/workflows/${workflow.id}/versions`, jsonRequest('POST', {
    agent_version_id: av.id, capability_policy: { allowed: [] }, approval_policy: { require_high_risk: true, fail_on_denial: false },
    experience_policy: { include_workspace: false, include_organization: false, max_entries: 0 }, input_schema: {}, output_schema: {}, max_steps: 4, max_runtime_seconds: 120, token_budget: 8192,
    retry_policy: { model_network_attempts: 2, capability_attempts: 0 }
  }));
  await requestWorkspaceJson(fetcher, options, `/workflows/${workflow.id}/active-version`, jsonRequest('POST', { version_id: wv.id }, { 'If-Match': `"revision-${workflow.revision}"` }));
  return workflow.id;
}
