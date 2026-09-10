import type { ManagementResource } from '../control-plane';

export type ApiRecord = Record<string, unknown>;

export type CollectionStatus =
  | 'not-configured'
  | 'not-available'
  | 'unauthorized'
  | 'error'
  | 'ready';

export type CollectionResult = {
  status: CollectionStatus;
  records: ApiRecord[];
  message?: string;
  httpStatus?: number;
};

export type ApiFetcher = (
  input: RequestInfo | URL,
  init?: RequestInit
) => Promise<Response>;

const collectionKeys = ['items', 'data', 'results', 'records'] as const;

function isRecord(value: unknown): value is ApiRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function normalizeCollectionRecords(payload: unknown): ApiRecord[] {
  if (Array.isArray(payload)) {
    return payload.filter(isRecord);
  }

  if (!isRecord(payload)) {
    return [];
  }

  for (const key of collectionKeys) {
    const value = payload[key];
    if (Array.isArray(value)) {
      return value.filter(isRecord);
    }
  }

  return [];
}

function collectionUrl(apiBaseUrl: string | undefined, resource: ManagementResource, workspaceId: string) {
  const base = apiBaseUrl?.trim().replace(/\/+$/, '') ?? '';
  return `${base}/api/v1/workspaces/${encodeURIComponent(workspaceId)}/${resource.endpoint}`;
}

function organizationCollectionUrl(
  apiBaseUrl: string | undefined,
  resource: ManagementResource,
  organizationId: string
) {
  const base = apiBaseUrl?.trim().replace(/\/+$/, '') ?? '';
  return `${base}/api/v1/organizations/${encodeURIComponent(organizationId)}/${resource.endpoint}`;
}

export async function fetchWorkspaceCollection(
  fetcher: ApiFetcher,
  resource: ManagementResource,
  options: { apiBaseUrl?: string; workspaceId?: string }
): Promise<CollectionResult> {
  const workspaceId = options.workspaceId?.trim();

  if (!workspaceId) {
    return {
      status: 'not-configured',
      records: [],
      message: '当前会话尚未选择 Workspace，暂不请求业务 API。'
    };
  }

  try {
    const response = await fetcher(collectionUrl(options.apiBaseUrl, resource, workspaceId), {
      headers: { accept: 'application/json' }
    });

    if (response.status === 401 || response.status === 403) {
      return {
        status: 'unauthorized',
        records: [],
        httpStatus: response.status,
        message: '当前身份没有访问此 Workspace 的权限。'
      };
    }

    if (response.status === 404 || response.status === 501) {
      return {
        status: 'not-available',
        records: [],
        httpStatus: response.status,
        message: '列表 API 尚未实现或当前部署未提供此端点。'
      };
    }

    if (!response.ok) {
      return {
        status: 'error',
        records: [],
        httpStatus: response.status,
        message: `API 请求失败（HTTP ${response.status}）。`
      };
    }

    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      return {
        status: 'error',
        records: [],
        httpStatus: response.status,
        message: 'API 返回了无法解析的 JSON。'
      };
    }

    return { status: 'ready', records: normalizeCollectionRecords(payload) };
  } catch {
    return {
      status: 'error',
      records: [],
      message: '无法连接到 Zeus API，请检查服务端 API 配置。'
    };
  }
}

export async function fetchOrganizationCollection(
  fetcher: ApiFetcher,
  resource: ManagementResource,
  options: { apiBaseUrl?: string; organizationId: string }
): Promise<CollectionResult> {
  try {
    const response = await fetcher(
      organizationCollectionUrl(options.apiBaseUrl, resource, options.organizationId),
      { headers: { accept: 'application/json' } }
    );
    if (response.status === 401 || response.status === 403) {
      return {
        status: 'unauthorized',
        records: [],
        httpStatus: response.status,
        message: '当前身份没有访问此 Organization 设置的权限。'
      };
    }
    if (response.status === 404 || response.status === 501) {
      return {
        status: 'not-available',
        records: [],
        httpStatus: response.status,
        message: '当前部署未提供此 Organization 设置端点。'
      };
    }
    if (!response.ok) {
      return {
        status: 'error',
        records: [],
        httpStatus: response.status,
        message: `API 请求失败（HTTP ${response.status}）。`
      };
    }
    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      return {
        status: 'error',
        records: [],
        httpStatus: response.status,
        message: 'API 返回了无法解析的 JSON。'
      };
    }
    return { status: 'ready', records: normalizeCollectionRecords(payload) };
  } catch {
    return {
      status: 'error',
      records: [],
      message: '无法连接到 Zeus API，请检查服务端 API 配置。'
    };
  }
}
