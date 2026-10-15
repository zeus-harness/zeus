import { discussionContextMarker } from '$lib/studio-message';
import { planDraft } from '$lib/plan-draft';
import { studioResources } from '$lib/studio-resources';
import { getWorkItem } from '$lib/api/work-items';
import { isStudioChat } from './studio-chat';
import { discussionSafe, discussionVersion, prepareDiscussion } from './discussion';
import { fail, redirect, type RequestEvent } from '@sveltejs/kit';
import { jsonRequest, requestWorkspaceJson, ZeusApiError } from '$lib/api/client';
import { createWorkItem } from '$lib/api/work-items';
import { getRun, getRunTrace, startWorkItemRun, TERMINAL_RUN_STATES, type Run } from '$lib/api/runs';
import { studioId } from './agent-studio';
import { requireWorkspaceAction } from './workspace-context';

export function draftTitle(message: string): string {
  const first = message.trim().split(/[\n。！？!?]/u)[0];
  const points = [...first];
  return points.slice(0, 48).join('') + (points.length > 48 ? '…' : '');
}

type Event = Pick<RequestEvent, 'fetch' | 'request' | 'url'> & { params: { workspaceId?: string } };

/** Chat is an interaction surface. Writes still use the existing domain APIs. */
export async function conversationAction(event: Event, apiBaseUrl?: string) {
  const context = await requireWorkspaceAction(event, apiBaseUrl, event.params.workspaceId);
  if (context.error) return context.error;
  const fields = await event.request.formData();
  const text = (key: string) => String(fields.get(key) ?? '').trim();
  const values = Object.fromEntries(['intent', 'kind', 'message', 'title', 'description', 'work_item_id', 'workflow_id', 'run_id', 'request_id', 'proposal_id', 'allow_create', 'conversation_run_id'].map(key => [key, text(key)]));
  const failure = (status: number, message: string) => fail(status, { type: 'error' as const, message, values });
  const options = { apiBaseUrl, workspaceId: context.workspaceId };
  let target = `/${context.workspaceId}/studio`;
  async function proposalForRun(runId: string, proposalId: string) {
    const trace = await getRunTrace(context.apiFetch, options, studioId(runId));
    if (trace.run.work_item_id || trace.run.status !== 'succeeded') throw new Error('Proposal source unavailable');
    const proposal = studioResources(trace.session_events).find(resource => resource.id === proposalId && resource.status === 'proposed' && resource.runId === runId);
    if (!proposal) throw new Error('Proposal unavailable');
    return proposal;
  }
  try {
    if (values.intent === 'prepare-discussion') {
      const id = await prepareDiscussion(context.apiFetch, options, studioId(values.workflow_id));
      target += `?discuss=1&discussion_workflow=${id}`;
    } else if (values.intent === 'discuss') {
      const requestId = studioId(values.request_id);
      if (!values.message || [...values.message].length > 50000) return failure(400, '请输入 1–50000 字的消息。');
      const relatedItem = values.work_item_id ? await getWorkItem(context.apiFetch, options, studioId(values.work_item_id)) : null;
      const discussionMessage = relatedItem ? `${values.message}${discussionContextMarker}${JSON.stringify({ title: relatedItem.title, description: relatedItem.description, status: relatedItem.status })}` : values.message;
      if ([...discussionMessage].length > 50000) return failure(400, '消息与关联工作项内容过长，请缩短本轮消息后重试。');
      let sessionId: string;
      let versionId: string;
      if (values.run_id) {
        const previous = await getRun(context.apiFetch, options, studioId(values.run_id));
        if (previous.work_item_id || !TERMINAL_RUN_STATES.has(previous.status)) return failure(409, '请等待讨论结束，并使用独立讨论会话。');
        const version = await discussionVersion(context.apiFetch, options, studioId(values.workflow_id));
        if (version.id !== previous.workflow_version_id || (!discussionSafe(version) && !isStudioChat(version))) return failure(400, '讨论流程版本已变化，请开启新讨论；不会自动切换执行权限。');
        sessionId = previous.session_id; versionId = previous.workflow_version_id;
      } else {
        const version = await discussionVersion(context.apiFetch, options, studioId(values.workflow_id));
        const session = await requestWorkspaceJson<{ id: string }>(context.apiFetch, options, '/sessions', jsonRequest('POST', { title: draftTitle(values.message), work_item_id: null }));
        sessionId = session.id; versionId = version.id;
      }
      const run = await requestWorkspaceJson<Run>(context.apiFetch, options, '/runs', jsonRequest('POST', {
        session_id: sessionId, workflow_version_id: versionId, work_item_id: null,
        input: { studio_resource_mode: values.allow_create === 'yes' ? 'create' : 'preview', ...(values.work_item_id ? { studio_work_item_id: studioId(values.work_item_id) } : {}) },
        message: discussionMessage
      }, { 'Idempotency-Key': requestId }));
      target += `?discuss=1&run=${run.id}${values.work_item_id ? `&work_item=${studioId(values.work_item_id)}` : ''}`;
    } else if (values.intent === 'draft') {
      if (!['work-item', 'workflow'].includes(values.kind) || !values.message || [...values.message].length > 50000) return failure(400, '请选择操作，并输入 1–50000 字的需求。');
      if (values.run_id) {
        const source = await getRun(context.apiFetch, options, studioId(values.run_id));
        if (source.work_item_id || source.status !== 'succeeded') return failure(400, '请选择已完成的独立讨论结果。');
        const output = source.output;
        values.message = typeof output === 'string' ? output : output && typeof output === 'object' && 'content' in output && typeof output.content === 'string' ? output.content : '';
        if (!values.message && !values.proposal_id) return failure(400, '讨论结果没有可转换的文本。');
      }
      let proposal;
      if (values.proposal_id && values.run_id) {
        proposal = await proposalForRun(values.run_id, values.proposal_id);
        values.kind = proposal.kind === 'work_item' ? 'work-item' : 'workflow';
      }
      const draftValues: Record<string, string> = {
        ...values,
        ...((values.run_id) ? planDraft(values.message) : { title: draftTitle(values.message), description: values.message }),
        ...(proposal ? { title: proposal.title, description: proposal.description } : {}),
        request_id: proposal?.id ?? crypto.randomUUID()
      };
      return { type: 'draft' as const, values: draftValues };
    } else if (values.intent === 'create') {
      if (!['work-item', 'workflow'].includes(values.kind) || !values.title || [...values.title].length > (values.kind === 'workflow' ? 160 : 500) || [...values.description].length > 50000) return failure(400, '请检查名称和描述长度。');
      if (values.run_id) {
        const source = await getRun(context.apiFetch, options, studioId(values.run_id));
        if (source.work_item_id || source.status !== 'succeeded') return failure(400, '来源讨论不可用，请重新预览。');
      }
      if (values.proposal_id) {
        const proposal = await proposalForRun(values.run_id, studioId(values.proposal_id));
        if (values.kind !== (proposal.kind === 'work_item' ? 'work-item' : 'workflow')) return failure(400, '草稿类型已变化，请重新预览。');
        values.request_id = proposal.id;
      }
      if (values.kind === 'work-item') {
        const item = await createWorkItem(context.apiFetch, options, {
          title: values.title, description: values.description, priority: 'normal', input: values.proposal_id ? { studio_proposal_id: values.proposal_id } : {},
          assignee_user_id: null, source_kind: values.run_id ? 'studio_discussion' : null, external_reference: values.run_id || null
        }, studioId(values.request_id));
        target += values.run_id ? `?discuss=1&run=${values.run_id}&work_item=${item.id}` : `?work_item=${item.id}`;
      } else {
        // The API enforces builder/owner permission; this creates an unpublished resource only.
        const workflow = await requestWorkspaceJson<{ id: string }>(context.apiFetch, options, '/workflows',
          jsonRequest('POST', { name: values.title, description: values.description }));
        target += `?workflow=${workflow.id}${values.run_id ? `&discuss=1&run=${values.run_id}` : ''}`;
      }
    } else if (values.intent === 'send') {
      const workItemId = studioId(values.work_item_id);
      const key = studioId(values.request_id);
      if (!values.message || [...values.message].length > 50000) return failure(400, '请输入 1–50000 字的消息。');
      let run: Run;
      if (values.run_id) {
        const previous = await getRun(context.apiFetch, options, studioId(values.run_id));
        if (previous.work_item_id !== workItemId) return failure(400, '所选运行不属于当前工作项。');
        if (!TERMINAL_RUN_STATES.has(previous.status)) return failure(409, '请等待当前运行结束后继续发送。');
        run = await requestWorkspaceJson<Run>(context.apiFetch, options, '/runs', jsonRequest('POST', {
          session_id: previous.session_id, workflow_version_id: previous.workflow_version_id,
          work_item_id: workItemId, input: previous.input, message: values.message
        }, { 'Idempotency-Key': key }));
      } else {
        const started = await startWorkItemRun(context.apiFetch, options, workItemId,
          { workflow_id: studioId(values.workflow_id), input: {}, message: values.message }, key);
        run = started.run;
      }
      target += `?work_item=${workItemId}&execution_run=${run.id}${values.conversation_run_id ? `&run=${studioId(values.conversation_run_id)}&discuss=1` : ''}`;
    } else return failure(400, '请选择有效操作。');
  } catch (cause) {
    if (cause instanceof ZeusApiError) {
      const status = cause.status >= 400 && cause.status < 500 ? cause.status : 502;
      return failure(status, status === 403 ? '当前角色没有执行此操作的权限。' : status === 409 ? '当前资源状态不允许操作，请刷新后检查。' : '操作未完成。请检查所选资源或稍后重试，输入已保留。');
    }
    return failure(400, '输入无效，请检查所选资源。');
  }
  redirect(303, target);
}
