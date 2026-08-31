import type { components } from './generated/schema';
import {
  jsonRequest,
  requestWorkspaceJson,
  workspaceUrl,
  type ApiFetcher,
  type WorkspaceRequestOptions
} from './client';

export type Session = components['schemas']['SessionResponse'];
export type Run = components['schemas']['RunResponse'];
export type RunPage = components['schemas']['RunPageResponse'];
export type RunEvent = components['schemas']['RunEventResponse'];
export type RunTrace = components['schemas']['RunTraceResponse'];
export type ChildRun = components['schemas']['ChildRunResponse'];
export type Approval = components['schemas']['ApprovalResponse'];
export type StartWorkItemRunInput = components['schemas']['StartWorkItemRunRequest'];
export type WorkItemRunStart = components['schemas']['WorkItemRunStartResponse'];

export const TERMINAL_RUN_STATES = new Set(['succeeded', 'failed', 'canceled']);

export function listRuns(
  fetcher: ApiFetcher,
  options: WorkspaceRequestOptions & {
    workItemId?: string;
    status?: string;
    cursor?: string;
    limit?: number;
  }
): Promise<RunPage> {
  return requestWorkspaceJson<RunPage>(fetcher, options, '/runs', undefined, {
    work_item_id: options.workItemId,
    status: options.status,
    cursor: options.cursor,
    limit: options.limit
  });
}

export function startWorkItemRun(
  fetcher: ApiFetcher,
  options: WorkspaceRequestOptions,
  workItemId: string,
  input: StartWorkItemRunInput,
  idempotencyKey: string
): Promise<WorkItemRunStart> {
  return requestWorkspaceJson<WorkItemRunStart>(
    fetcher,
    options,
    `/work-items/${encodeURIComponent(workItemId)}/runs`,
    jsonRequest('POST', input, { 'Idempotency-Key': idempotencyKey })
  );
}

export function getRun(
  fetcher: ApiFetcher,
  options: WorkspaceRequestOptions,
  runId: string
): Promise<Run> {
  return requestWorkspaceJson<Run>(fetcher, options, `/runs/${encodeURIComponent(runId)}`);
}

export function getRunTrace(
  fetcher: ApiFetcher,
  options: WorkspaceRequestOptions,
  runId: string
): Promise<RunTrace> {
  return requestWorkspaceJson<RunTrace>(
    fetcher,
    options,
    `/runs/${encodeURIComponent(runId)}/trace`
  );
}

export function listRunEvents(
  fetcher: ApiFetcher,
  options: WorkspaceRequestOptions,
  runId: string,
  after = 0
): Promise<RunEvent[]> {
  return requestWorkspaceJson<RunEvent[]>(
    fetcher,
    options,
    `/runs/${encodeURIComponent(runId)}/events`,
    undefined,
    { after }
  );
}

export function runEventStreamUrl(options: WorkspaceRequestOptions, runId: string): string {
  return workspaceUrl(options, `/runs/${encodeURIComponent(runId)}/events/stream`);
}

export function listChildRuns(
  fetcher: ApiFetcher,
  options: WorkspaceRequestOptions,
  runId: string
): Promise<ChildRun[]> {
  return requestWorkspaceJson<ChildRun[]>(
    fetcher,
    options,
    `/runs/${encodeURIComponent(runId)}/children`
  );
}

export function listApprovals(
  fetcher: ApiFetcher,
  options: WorkspaceRequestOptions & { status?: string; workItemId?: string }
): Promise<Approval[]> {
  return requestWorkspaceJson<Approval[]>(fetcher, options, '/approvals', undefined, {
    status: options.status ?? 'pending',
    work_item_id: options.workItemId
  });
}

export function decideApproval(
  fetcher: ApiFetcher,
  options: WorkspaceRequestOptions,
  approvalId: string,
  decision: 'approve' | 'reject',
  reason?: string | null
): Promise<void> {
  return requestWorkspaceJson<void>(
    fetcher,
    options,
    `/approvals/${encodeURIComponent(approvalId)}/${decision}`,
    jsonRequest('POST', { reason: reason?.trim() || null })
  );
}

export function cancelRun(
  fetcher: ApiFetcher,
  options: WorkspaceRequestOptions,
  runId: string,
  reason?: string | null
): Promise<void> {
  return requestWorkspaceJson<void>(
    fetcher,
    options,
    `/runs/${encodeURIComponent(runId)}/cancel`,
    jsonRequest('POST', { reason: reason?.trim() || null })
  );
}

export function retryRun(
  fetcher: ApiFetcher,
  options: WorkspaceRequestOptions,
  runId: string,
  idempotencyKey: string
): Promise<Run> {
  return requestWorkspaceJson<Run>(
    fetcher,
    options,
    `/runs/${encodeURIComponent(runId)}/retry`,
    jsonRequest('POST', {}, { 'Idempotency-Key': idempotencyKey })
  );
}
