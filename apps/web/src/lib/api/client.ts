import type { PrincipalResult } from './server';
import { serverApiUrl } from './server';
import type { paths } from './generated/schema';

export type ApiFetcher = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

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

export type WorkspaceRequestOptions = {
  apiBaseUrl?: string;
  workspaceId: string;
};

export type QueryValue = string | number | boolean | null | undefined;

export type ApiMeta =
  paths['/api/v1/meta']['get']['responses'][200]['content']['application/json'];

export class ZeusApiClient {
  constructor(
    private readonly baseUrl = '',
    private readonly fetcher: typeof fetch = fetch
  ) {}

  async meta(signal?: AbortSignal): Promise<ApiMeta> {
    const response = await this.fetcher(`${this.baseUrl}/api/v1/meta`, {
      headers: { accept: 'application/json' },
      signal
    });
    if (!response.ok) {
      throw new Error(`Zeus API returned ${response.status}`);
    }
    return response.json() as Promise<ApiMeta>;
  }
}

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

export function workspaceUrl(
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

function problemMessage(status: number, payload: unknown): string {
  if (typeof payload === 'object' && payload !== null && !Array.isArray(payload)) {
    const detail = (payload as Record<string, unknown>).detail;
    const title = (payload as Record<string, unknown>).title;
    if (typeof detail === 'string' && detail.trim()) return detail;
    if (typeof title === 'string' && title.trim()) return title;
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
  fetcher: ApiFetcher,
  input: RequestInfo | URL,
  init: RequestInit = {}
): Promise<T> {
  const response = await fetcher(input, { ...init, headers: requestHeaders(init) });
  if (!response.ok) {
    const payload = await responsePayload(response);
    throw new ZeusApiError(problemMessage(response.status, payload), response.status, payload);
  }
  if (response.status === 204) return undefined as T;
  try {
    const body = await response.text();
    if (!body.trim()) return undefined as T;
    return JSON.parse(body) as T;
  } catch {
    throw new ZeusApiError('API 返回了无法解析的 JSON。', response.status);
  }
}

export function requestWorkspaceJson<T>(
  fetcher: ApiFetcher,
  options: WorkspaceRequestOptions,
  path: string,
  init: RequestInit = {},
  query: Record<string, QueryValue> = {}
): Promise<T> {
  return requestJson<T>(fetcher, workspaceUrl(options, path, query), init);
}

export function jsonRequest(method: string, body: unknown, headers: HeadersInit = {}): RequestInit {
  return { method, headers, body: JSON.stringify(body) };
}

export async function loadWorkspaceData<T>(
  fetcher: ApiFetcher,
  options: { authStatus: PrincipalResult['status']; workspaceId?: string | null },
  loader: (fetcher: ApiFetcher, workspaceId: string) => Promise<T>
): Promise<WorkspaceResource<T>> {
  if (options.authStatus === 'unauthenticated') {
    return { status: 'unauthenticated', message: '当前会话未登录，请先登录 Zeus。' };
  }
  if (options.authStatus !== 'ready') {
    return { status: 'error', message: '无法确认当前登录状态，认证 API 暂不可用。' };
  }
  const workspaceId = options.workspaceId?.trim();
  if (!workspaceId) {
    return { status: 'not-configured', message: '当前会话未选择 Workspace，无法加载业务数据。' };
  }

  try {
    return { status: 'ready', data: await loader(fetcher, workspaceId), message: 'API 已连接。' };
  } catch (error) {
    if (error instanceof ZeusApiError) {
      if (error.status === 401) {
        return { status: 'unauthenticated', message: '登录状态已失效，请重新登录。', httpStatus: 401 };
      }
      if (error.status === 403) {
        return { status: 'unauthorized', message: '当前身份没有访问此 Workspace 的权限。', httpStatus: 403 };
      }
      if (error.status === 404 || error.status === 501) {
        return {
          status: 'not-available',
          message: '当前部署未提供此端点。',
          httpStatus: error.status
        };
      }
      return { status: 'error', message: error.message, httpStatus: error.status };
    }
    return { status: 'error', message: '无法连接到 Zeus API，请检查服务端 API 配置。' };
  }
}
