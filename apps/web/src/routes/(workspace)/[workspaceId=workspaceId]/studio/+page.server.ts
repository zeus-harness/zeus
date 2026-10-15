import { isStudioChat } from '$lib/server/studio-chat';
import { discussionSafe } from '$lib/server/discussion';
import { studioResources } from '$lib/studio-resources';
import type { WorkflowVersion } from '$lib/api/agent-studio';
import type { components } from '$lib/api/generated/schema';
import { error } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';
import { requestWorkspaceJson, ZeusApiError } from '$lib/api/client';
import { serverApiFetcher } from '$lib/api/server';
import { listWorkItems, getWorkItem, listWorkItemReviews } from '$lib/api/work-items';
import { listWorkflows, type Workflow } from '$lib/api/control-plane';
import { getRun, getRunTrace, listRuns, runEventStreamUrl } from '$lib/api/runs';
import { studioId } from '$lib/server/agent-studio';
import { studioDraftKey } from '$lib/studio-draft';
import { loadOnboarding } from '$lib/server/onboarding';
import { conversationAction } from '$lib/server/studio-conversation';

export const load: PageServerLoad = async ({ parent, fetch, request, url, params }) => {
  const context = await parent();
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const options = { apiBaseUrl: env.ZEUS_API_URL, workspaceId: params.workspaceId };
  const id = (key: string) => {
    const value = url.searchParams.get(key);
    if (!value) return null;
    try { return studioId(value); } catch { error(400, '资源地址无效。'); }
  };
  const itemId = id('work_item');
  const runId = id('run');
  const workflowId = id('workflow');
  try {
    const [items, workflows, item, runs, workflow, onboarding] = await Promise.all([
      listWorkItems(apiFetch, { ...options, limit: 20, cursor: url.searchParams.get('cursor') ?? undefined }),
      listWorkflows(apiFetch, { ...options, limit: 100 }),
      itemId ? getWorkItem(apiFetch, options, itemId) : null,
      itemId ? listRuns(apiFetch, { ...options, workItemId: itemId, limit: 20 }) : null,
      workflowId ? requestWorkspaceJson<Workflow>(apiFetch, options, `/workflows/${workflowId}`) : null,
      loadOnboarding(apiFetch, options)
    ]);
    const recentRuns = (await listRuns(apiFetch, { ...options, limit: 30 })).items.filter(run => !run.work_item_id);
    const uniqueRuns = recentRuns.filter((run, index) => recentRuns.findIndex(other => other.session_id === run.session_id) === index).slice(0, 10);
    const recentDiscussionRuns = await Promise.all(uniqueRuns.map(async run => {
      try {
        const session = await requestWorkspaceJson<components['schemas']['SessionResponse']>(apiFetch, options, `/sessions/${run.session_id}`);
        return { ...run, title: session.title || '未命名讨论' };
      } catch { return { ...run, title: '讨论主题暂不可读取' }; }
    }));
    const discussionWorkflows: Workflow[] = [];
    const chatWorkflows: Workflow[] = [];
    for (const w of workflows.items.filter(w => !w.archived_at && w.active_version_id)) {
      const versions = await requestWorkspaceJson<WorkflowVersion[]>(apiFetch, options, `/workflows/${w.id}/versions`);
      if (versions.some(v => v.id === w.active_version_id && isStudioChat(v))) chatWorkflows.push(w);
      if (versions.some(v => v.id === w.active_version_id && (discussionSafe(v) || isStudioChat(v)))) discussionWorkflows.push(w);
    }
    let sourceRun: Awaited<ReturnType<typeof getRun>> | null = null;
    if (item?.source_kind === 'studio_discussion' && item.external_reference) {
      try { sourceRun = await getRun(apiFetch, options, studioId(item.external_reference)); } catch { /* A stale source must not block the saved work item. */ }
    }
    let trace = runId ? await getRunTrace(apiFetch, options, runId) : sourceRun ? await getRunTrace(apiFetch, options, recentDiscussionRuns.find(run => run.session_id === sourceRun.session_id)?.id ?? sourceRun.id) : null;
    const executionId = id('execution_run') ?? runs?.items[0]?.id;
    let executionTrace = executionId ? await getRunTrace(apiFetch, options, executionId) : null;
    if (trace?.run.work_item_id) { if (!url.searchParams.has('execution_run')) executionTrace = trace; trace = sourceRun ? await getRunTrace(apiFetch, options, recentDiscussionRuns.find(run => run.session_id === sourceRun.session_id)?.id ?? sourceRun.id) : null; }
    if (executionTrace && (!item || executionTrace.run.work_item_id !== item.id)) error(400, '执行与工作项不匹配。');
    if (trace?.run.work_item_id) error(400, '请选择聊天会话。');
    if (trace && item && sourceRun?.session_id !== trace.run.session_id && (trace.run.input as Record<string, unknown> | null)?.studio_work_item_id !== item.id) error(400, '聊天与工作项不匹配。');
    const discussion = true;
    const after = Number(url.searchParams.get('after') ?? '0');
    if (!Number.isSafeInteger(after) || after < 0) error(400, '消息位置无效。');
    const sessionEvents = trace ? await requestWorkspaceJson<components['schemas']['SessionEventResponse'][]>(apiFetch, options, `/sessions/${trace.run.session_id}/events`, undefined, { after, limit: 100 }) : [];
    const createdResources = studioResources(sessionEvents);
    const reviews = itemId ? await listWorkItemReviews(apiFetch, options, itemId).catch(() => null) : null;
    return {
      createdResources, executionTrace,
      executionStreamUrl: executionTrace ? runEventStreamUrl({ workspaceId: params.workspaceId }, executionTrace.run.id) : null,
      review: reviews?.items.find(review => review.run_id === trace?.run.id) ?? null,
      executionWorkflows: workflows.items.filter(w => !w.archived_at && w.active_version_id && !discussionWorkflows.some(d => d.id === w.id)),
      discussion, discussionWorkflows, recentDiscussionRuns, chatWorkflows,
      onboarding,
      draftScope: studioDraftKey(context.principal?.user_id ?? 'anonymous', params.workspaceId, `${itemId ?? workflowId ?? 'new'}:${trace?.run.id ?? ''}`),
      sessionEvents, nextEvent: sessionEvents.length === 100 ? sessionEvents.at(-1)?.sequence : null,
      workspaceId: params.workspaceId, items, item, runs, workflow, trace,
      workflows: workflows.items.filter(w => !w.archived_at && w.active_version_id),
      canConfigureChat: context.canManageWorkspace,
      canBuild: context.canManageWorkspace || context.activeWorkspace.role === 'builder',
      canOperate: context.canManageWorkspace || ['builder', 'operator'].includes(context.activeWorkspace.role),
      streamUrl: trace ? runEventStreamUrl({ workspaceId: params.workspaceId }, trace.run.id) : null,
      requestId: crypto.randomUUID()
    };
  } catch (cause) {
    if (cause instanceof ZeusApiError) error(cause.status >= 400 && cause.status < 500 ? cause.status : 502, '无法读取会话资源，请检查权限或稍后重试。');
    throw cause;
  }
};
export const actions: Actions = { interact: event => conversationAction(event, env.ZEUS_API_URL) };
