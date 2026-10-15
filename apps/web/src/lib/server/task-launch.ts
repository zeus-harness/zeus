import { fail, redirect, type RequestEvent } from '@sveltejs/kit';
import { createWorkItem } from '$lib/api/work-items';
import { startWorkItemRun } from '$lib/api/runs';
import { ZeusApiError } from '$lib/api/client';
import { draftTitle } from './studio-conversation';
import { requireWorkspaceAction } from './workspace-context';

type Event = Pick<RequestEvent, 'fetch' | 'request' | 'url'> & { params: { workspaceId?: string } };
export async function launchTask(event: Event, apiBaseUrl?: string) {
  const context = await requireWorkspaceAction(event, apiBaseUrl, event.params.workspaceId);
  if (context.error) return context.error;
  const fields = await event.request.formData();
  const values = Object.fromEntries(['message', 'workflow_id', 'request_id'].map(key => [key, String(fields.get(key) ?? '').trim()]));
  const failure = (status: number, message: string, workItemId?: string) => fail(status, { type: 'error' as const, message, values, workItemId });
  if (!values.message || [...values.message].length > 50000 || !/^[0-9a-f-]{36}$/i.test(values.request_id) || !/^[0-9a-f-]{36}$/i.test(values.workflow_id)) return failure(400, '请描述任务目标，并选择已有的执行方式。');
  const options = { apiBaseUrl, workspaceId: context.workspaceId };
  let workItemId: string | undefined;
  try {
    // Both writes have stable, separate keys. A lost response can be retried without a second goal/attempt.
    const item = await createWorkItem(context.apiFetch, options, { title: draftTitle(values.message), description: values.message, priority: 'normal', input: {} }, `task-${values.request_id}`);
    workItemId = item.id;
    await startWorkItemRun(context.apiFetch, options, item.id, { workflow_id: values.workflow_id, input: {}, message: values.message }, `task-run-${values.request_id}`);
  } catch (cause) {
    const status = cause instanceof ZeusApiError ? cause.status : 502;
    return failure(status, workItemId ? '任务已保存，启动尚未确认。可打开任务核对，或保持原内容重试。' : '发起尚未确认，输入已保留。请保持原内容重试，避免重复创建任务。', workItemId);
  }
  redirect(303, `/${context.workspaceId}/work-items/${workItemId}`);
}
