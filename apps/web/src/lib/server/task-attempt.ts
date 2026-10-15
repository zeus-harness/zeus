import { fail, redirect, type RequestEvent } from '@sveltejs/kit';
import { decideApproval, getRunTrace, retryRun } from '$lib/api/runs';
import { ZeusApiError } from '$lib/api/client';
import { requireWorkspaceAction } from './workspace-context';
type Event = Pick<RequestEvent, 'fetch' | 'request' | 'url'> & { params: { workspaceId?: string; work_item_id?: string } };
export async function taskAttemptAction(event: Event, intent: 'decide' | 'retry', apiBaseUrl?: string) {
  const context = await requireWorkspaceAction(event, apiBaseUrl, event.params.workspaceId);
  if (context.error) return context.error;
  const fields = await event.request.formData();
  const runId = String(fields.get('run_id') ?? '');
  const approvalId = String(fields.get('approval_id') ?? '');
  const decision = String(fields.get('decision') ?? '');
  const reason = String(fields.get('reason') ?? '').trim() || null;
  const failure = (status: number, message: string) => fail(status, { type: 'error' as const, message });
  if (!/^[0-9a-f-]{36}$/i.test(runId) || (reason && [...reason].length > 4000)) return failure(400, '请求内容无效，请刷新任务后重试。');
  const options = { apiBaseUrl, workspaceId: context.workspaceId };
  try {
    const trace = await getRunTrace(context.apiFetch, options, runId);
    if (trace.run.work_item_id !== event.params.work_item_id) return failure(403, '操作不属于当前任务。');
    if (intent === 'decide') {
      const approval = trace.approvals.find(value => value.id === approvalId && value.run_id === runId);
      if (!approval?.can_decide) return failure(403, '当前身份无权决定这项审批。');
      if (decision !== 'approve' && decision !== 'reject') return failure(400, '请选择有效的审批决定。');
      await decideApproval(context.apiFetch, options, approvalId, decision, reason);
    } else {
      await retryRun(context.apiFetch, options, runId, `retry-${runId}`);
    }
  } catch (cause) {
    return failure(cause instanceof ZeusApiError ? cause.status : 502, '操作尚未确认，请刷新核对最新状态。原执行记录保留。');
  }
  redirect(303, `/${context.workspaceId}/work-items/${event.params.work_item_id}`);
}
