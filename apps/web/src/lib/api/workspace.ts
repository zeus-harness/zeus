import type { PrincipalResult } from './server';
import { serverApiUrl } from './server';

export type WorkspaceApiFetcher = (
  input: RequestInfo | URL,
  init?: RequestInit
) => Promise<Response>;

export type WorkspaceStatus =
  | 'ready'
  | 'not-configured'
  | 'unauthenticated'
  | 'unauthorized'
  | 'not-available'
  | 'error';

export type WorkspaceResource<T> = {
  status: WorkspaceStatus;
  data?: T;
  message: string;
  httpStatus?: number;
};

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

export type WorkItem = {
  id: string;
  organization_id: string;
  workspace_id: string;
  title: string;
  description: string;
  status: string;
  priority: string;
  assignee_user_id: string | null;
  source_kind: string | null;
  external_reference: string | null;
  input: JsonValue;
  output: JsonValue | null;
  revision: number;
  created_by: string | null;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
};

export type WorkItemPage = {
  items: WorkItem[];
  next_cursor: string | null;
};

export type CreateWorkItemInput = {
  title: string;
  description?: string;
  priority?: string;
  assignee_user_id?: string | null;
  source_kind?: string | null;
  external_reference?: string | null;
  input?: JsonValue;
};

export type UpdateWorkItemInput = {
  title?: string;
  description?: string;
  status?: string;
  priority?: string;
  assignee_user_id?: string | null;
  clear_assignee?: boolean;
  input?: JsonValue;
  output?: JsonValue;
};

export type Run = {
  id: string;
  organization_id: string;
  workspace_id: string;
  workflow_version_id: string;
  work_item_id: string | null;
  session_id: string;
  parent_run_id: string | null;
  retry_of_run_id: string | null;
  status: string;
  input: JsonValue;
  output: JsonValue | null;
  error_code: string | null;
  error_detail: string | null;
  attempt_count: number;
  cancel_requested_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
  updated_at: string;
};

export type RunPage = {
  items: Run[];
  next_cursor: string | null;
};

export type RunEvent = {
  id: string;
  run_id: string;
  session_event_id: string | null;
  sequence: number;
  schema_version: number;
  event_type: string;
  payload: JsonValue;
  occurred_at: string;
};

export type SessionEvent = {
  id: string;
  session_id: string;
  run_id: string | null;
  sequence: number;
  schema_version: number;
  event_type: string;
  actor_kind: string;
  actor_id: string | null;
  payload: JsonValue;
  occurred_at: string;
};

export type TraceToolCall = {
  id: string;
  capability_id: string;
  call_key: string;
  status: string;
  input: JsonValue;
  result: JsonValue | null;
  error_code: string | null;
  child_run_id: string | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
};

export type Approval = {
  id: string;
  run_id: string;
  tool_call_id: string;
  status: string;
  requested_at: string;
  expires_at: string | null;
  decided_at: string | null;
  decided_by: string | null;
  reason: string | null;
};

export type RunUsageEntry = {
  id: string;
  run_id: string;
  provider_request_id: string;
  prompt_tokens: number;
  completion_tokens: number;
  cache_tokens: number;
  occurred_at: string;
};

export type RunUsageSummary = {
  prompt_tokens: number;
  completion_tokens: number;
  cache_tokens: number;
  entries: RunUsageEntry[];
};

export type TraceRunLink = {
  relation: string;
  run_id: string;
  status: string;
  output: JsonValue | null;
  error_code: string | null;
  created_at: string;
};

export type ChildRun = {
  id: string;
  workflow_version_id: string;
  session_id: string;
  status: string;
  depth: number;
  token_budget: number;
  max_runtime_seconds: number;
  output: JsonValue | null;
  error_code: string | null;
  error_detail: string | null;
  created_at: string;
  finished_at: string | null;
};

export type ExperienceInjection = {
  id: string;
  experience_entry_id: string;
  experience_version: number;
  rank: number;
  query_sha256: string;
  injected_at: string;
};

export type RunTrace = {
  run: Run;
  run_events: RunEvent[];
  session_events: SessionEvent[];
  tool_calls: TraceToolCall[];
  approvals: Approval[];
  usage: RunUsageSummary;
  linked_runs: TraceRunLink[];
  experience_injections: ExperienceInjection[];
};

export type ExperienceEvidenceRef = {
  event_kind: string;
  event_id: string;
};

export type ExperienceCandidate = {
  id: string;
  organization_id: string;
  workspace_id: string;
  source_run_id: string;
  proposed_scope: string;
  title: string;
  content: string;
  tags: string[];
  evidence: JsonValue;
  status: string;
  reviewed_by: string | null;
  reviewed_at: string | null;
  review_reason: string | null;
  created_at: string;
};

export type ExperienceCandidatePage = {
  items: ExperienceCandidate[];
  next_cursor: string | null;
};

export type CreateExperienceCandidateInput = {
  source_run_id: string;
  proposed_scope: string;
  title: string;
  content: string;
  tags: string[];
  evidence: ExperienceEvidenceRef[];
};

export type ExperienceEntry = {
  id: string;
  organization_id: string;
  workspace_id: string | null;
  candidate_id: string;
  source_run_id: string;
  scope: string;
  version_number: number;
  title: string;
  content: string;
  tags: string[];
  evidence: JsonValue;
  published_by: string;
  published_at: string;
  withdrawn_at: string | null;
  withdrawal_reason: string | null;
};

export type ExperienceEntryPage = {
  items: ExperienceEntry[];
  next_cursor: string | null;
};

export type ExperienceSearchResult = {
  id: string;
  scope: string;
  version_number: number;
  title: string;
  content: string;
  tags: string[];
  rank: number;
  published_at: string;
};

export class ZeusApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly payload?: unknown
  ) {
    super(message);
    this.name = 'ZeusApiError';
  }
}

type WorkspaceRequestOptions = {
  apiBaseUrl?: string;
  workspaceId: string;
};

type QueryValue = string | number | boolean | null | undefined;

function workspaceUrl(
  options: WorkspaceRequestOptions,
  path: string,
  query: Record<string, QueryValue> = {}
): string {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  const url = serverApiUrl(
    options.apiBaseUrl,
    `/api/v1/workspaces/${encodeURIComponent(options.workspaceId)}${normalizedPath}`
  );
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== null && value !== '') {
      params.set(key, String(value));
    }
  }
  const queryString = params.toString();
  return queryString ? `${url}?${queryString}` : url;
}

function requestHeaders(init: RequestInit): Headers {
  const headers = new Headers(init.headers);
  headers.set('accept', 'application/json');
  if (init.body !== undefined && !headers.has('content-type')) {
    headers.set('content-type', 'application/json');
  }
  return headers;
}

function apiProblemMessage(status: number, payload: unknown): string {
  if (typeof payload === 'object' && payload !== null && !Array.isArray(payload)) {
    const detail = (payload as Record<string, unknown>).detail;
    const title = (payload as Record<string, unknown>).title;
    if (typeof detail === 'string' && detail.trim()) {
      return detail;
    }
    if (typeof title === 'string' && title.trim()) {
      return title;
    }
  }
  return `API 请求失败（HTTP ${status}）。`;
}

async function responsePayload(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return undefined;
  }
}

export async function requestJson<T>(
  fetcher: WorkspaceApiFetcher,
  input: RequestInfo | URL,
  init: RequestInit = {}
): Promise<T> {
  const response = await fetcher(input, { ...init, headers: requestHeaders(init) });
  if (!response.ok) {
    const payload = await responsePayload(response);
    throw new ZeusApiError(apiProblemMessage(response.status, payload), response.status, payload);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  try {
    return (await response.json()) as T;
  } catch {
    throw new ZeusApiError('API 返回了无法解析的 JSON。', response.status);
  }
}

async function requestWorkspaceJson<T>(
  fetcher: WorkspaceApiFetcher,
  options: WorkspaceRequestOptions,
  path: string,
  init: RequestInit = {},
  query: Record<string, QueryValue> = {}
): Promise<T> {
  return requestJson<T>(fetcher, workspaceUrl(options, path, query), init);
}

function jsonRequest(method: string, body: unknown, headers: HeadersInit = {}): RequestInit {
  return {
    method,
    headers,
    body: JSON.stringify(body)
  };
}

export async function loadWorkspaceData<T>(
  fetcher: WorkspaceApiFetcher,
  options: {
    authStatus: PrincipalResult['status'];
    workspaceId?: string | null;
  },
  loader: (fetcher: WorkspaceApiFetcher, workspaceId: string) => Promise<T>
): Promise<WorkspaceResource<T>> {
  if (options.authStatus === 'unauthenticated') {
    return {
      status: 'unauthenticated',
      message: '当前会话未登录，请先登录 Zeus。'
    };
  }
  if (options.authStatus !== 'ready') {
    return {
      status: 'error',
      message: '无法确认当前登录状态，认证 API 暂不可用。'
    };
  }
  const workspaceId = options.workspaceId?.trim();
  if (!workspaceId) {
    return {
      status: 'not-configured',
      message: '当前会话未选择 Workspace，无法加载业务数据。'
    };
  }

  try {
    return {
      status: 'ready',
      data: await loader(fetcher, workspaceId),
      message: 'API 已连接。'
    };
  } catch (error) {
    if (error instanceof ZeusApiError) {
      if (error.status === 401) {
        return {
          status: 'unauthenticated',
          message: '登录状态已失效，请重新登录。',
          httpStatus: error.status
        };
      }
      if (error.status === 403) {
        return {
          status: 'unauthorized',
          message: '当前身份没有访问此 Workspace 的权限。',
          httpStatus: error.status
        };
      }
      if (error.status === 404 || error.status === 501) {
        return {
          status: 'not-available',
          message: '列表 API 尚未实现或当前部署未提供此端点。',
          httpStatus: error.status
        };
      }
      return {
        status: 'error',
        message: error.message,
        httpStatus: error.status
      };
    }
    return {
      status: 'error',
      message: '无法连接到 Zeus API，请检查服务端 API 配置。'
    };
  }
}

export function listWorkItems(
  fetcher: WorkspaceApiFetcher,
  options: WorkspaceRequestOptions & { status?: string; cursor?: string; limit?: number }
): Promise<WorkItemPage> {
  return requestWorkspaceJson<WorkItemPage>(fetcher, options, '/work-items', undefined, {
    status: options.status,
    cursor: options.cursor,
    limit: options.limit
  });
}

export function createWorkItem(
  fetcher: WorkspaceApiFetcher,
  options: WorkspaceRequestOptions,
  input: CreateWorkItemInput,
  idempotencyKey: string
): Promise<WorkItem> {
  return requestWorkspaceJson<WorkItem>(
    fetcher,
    options,
    '/work-items',
    jsonRequest('POST', input, { 'Idempotency-Key': idempotencyKey })
  );
}

export function getWorkItem(
  fetcher: WorkspaceApiFetcher,
  options: WorkspaceRequestOptions,
  workItemId: string
): Promise<WorkItem> {
  return requestWorkspaceJson<WorkItem>(
    fetcher,
    options,
    `/work-items/${encodeURIComponent(workItemId)}`
  );
}

export function updateWorkItem(
  fetcher: WorkspaceApiFetcher,
  options: WorkspaceRequestOptions,
  workItemId: string,
  revision: number,
  input: UpdateWorkItemInput
): Promise<WorkItem> {
  return requestWorkspaceJson<WorkItem>(
    fetcher,
    options,
    `/work-items/${encodeURIComponent(workItemId)}`,
    jsonRequest('PATCH', input, { 'If-Match': `"revision-${revision}"` })
  );
}

export function listRuns(
  fetcher: WorkspaceApiFetcher,
  options: WorkspaceRequestOptions & { cursor?: string; limit?: number }
): Promise<RunPage> {
  return requestWorkspaceJson<RunPage>(fetcher, options, '/runs', undefined, {
    cursor: options.cursor,
    limit: options.limit
  });
}

export function getRun(
  fetcher: WorkspaceApiFetcher,
  options: WorkspaceRequestOptions,
  runId: string
): Promise<Run> {
  return requestWorkspaceJson<Run>(fetcher, options, `/runs/${encodeURIComponent(runId)}`);
}

export function getRunTrace(
  fetcher: WorkspaceApiFetcher,
  options: WorkspaceRequestOptions,
  runId: string
): Promise<RunTrace> {
  return requestWorkspaceJson<RunTrace>(
    fetcher,
    options,
    `/runs/${encodeURIComponent(runId)}/trace`
  );
}

export function listChildRuns(
  fetcher: WorkspaceApiFetcher,
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
  fetcher: WorkspaceApiFetcher,
  options: WorkspaceRequestOptions & { status?: string }
): Promise<Approval[]> {
  return requestWorkspaceJson<Approval[]>(fetcher, options, '/approvals', undefined, {
    status: options.status ?? 'pending'
  });
}

export function decideApproval(
  fetcher: WorkspaceApiFetcher,
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

export function listExperienceCandidates(
  fetcher: WorkspaceApiFetcher,
  options: WorkspaceRequestOptions & { status?: string; cursor?: string; limit?: number }
): Promise<ExperienceCandidatePage> {
  return requestWorkspaceJson<ExperienceCandidatePage>(
    fetcher,
    options,
    '/experience-candidates',
    undefined,
    {
      status: options.status,
      cursor: options.cursor,
      limit: options.limit
    }
  );
}

export function createExperienceCandidate(
  fetcher: WorkspaceApiFetcher,
  options: WorkspaceRequestOptions,
  input: CreateExperienceCandidateInput
): Promise<ExperienceCandidate> {
  return requestWorkspaceJson<ExperienceCandidate>(
    fetcher,
    options,
    '/experience-candidates',
    jsonRequest('POST', input)
  );
}

export function reviewExperienceCandidate(
  fetcher: WorkspaceApiFetcher,
  options: WorkspaceRequestOptions,
  candidateId: string,
  decision: 'approved' | 'rejected',
  reason?: string | null
): Promise<ExperienceCandidate> {
  return requestWorkspaceJson<ExperienceCandidate>(
    fetcher,
    options,
    `/experience-candidates/${encodeURIComponent(candidateId)}/review`,
    jsonRequest('POST', { decision, reason: reason?.trim() || null })
  );
}

export function publishExperienceCandidate(
  fetcher: WorkspaceApiFetcher,
  options: WorkspaceRequestOptions,
  candidateId: string
): Promise<ExperienceEntry> {
  return requestWorkspaceJson<ExperienceEntry>(
    fetcher,
    options,
    `/experience-candidates/${encodeURIComponent(candidateId)}/publish`,
    jsonRequest('POST', {})
  );
}

export function listExperienceEntries(
  fetcher: WorkspaceApiFetcher,
  options: WorkspaceRequestOptions & {
    scope?: string;
    includeWithdrawn?: boolean;
    cursor?: string;
    limit?: number;
  }
): Promise<ExperienceEntryPage> {
  return requestWorkspaceJson<ExperienceEntryPage>(
    fetcher,
    options,
    '/experience-entries',
    undefined,
    {
      scope: options.scope,
      include_withdrawn: options.includeWithdrawn,
      cursor: options.cursor,
      limit: options.limit
    }
  );
}

export function getExperienceEntry(
  fetcher: WorkspaceApiFetcher,
  options: WorkspaceRequestOptions,
  entryId: string
): Promise<ExperienceEntry> {
  return requestWorkspaceJson<ExperienceEntry>(
    fetcher,
    options,
    `/experience-entries/${encodeURIComponent(entryId)}`
  );
}

export function withdrawExperienceEntry(
  fetcher: WorkspaceApiFetcher,
  options: WorkspaceRequestOptions,
  entryId: string,
  reason: string
): Promise<void> {
  return requestWorkspaceJson<void>(
    fetcher,
    options,
    `/experience-entries/${encodeURIComponent(entryId)}/withdraw`,
    jsonRequest('POST', { reason })
  );
}

export function searchExperienceEntries(
  fetcher: WorkspaceApiFetcher,
  options: WorkspaceRequestOptions & { q: string; scope?: string; tags?: string; limit?: number }
): Promise<ExperienceSearchResult[]> {
  return requestWorkspaceJson<ExperienceSearchResult[]>(
    fetcher,
    options,
    '/experience-entries/search',
    undefined,
    {
      q: options.q,
      scope: options.scope,
      tags: options.tags,
      limit: options.limit ?? 20
    }
  );
}
