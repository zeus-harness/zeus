import { serverApiUrl } from './server';

export type SetupStatus = {
  setup_required: boolean;
  bootstrap_token_configured: boolean;
};

export type SetupStatusResult =
  | { status: 'ready'; data: SetupStatus }
  | {
      status: 'unavailable';
      data: null;
      httpStatus: number | null;
      message: string;
    };

export type SetupRequest = {
  bootstrap_token: string;
  email: string;
  display_name: string;
  password: string;
  organization_slug: string;
  organization_name: string;
  workspace_slug: string;
  workspace_name: string;
};

function isSetupStatus(value: unknown): value is SetupStatus {
  if (typeof value !== 'object' || value === null) {
    return false;
  }

  const status = value as Record<string, unknown>;
  return (
    typeof status.setup_required === 'boolean' &&
    typeof status.bootstrap_token_configured === 'boolean'
  );
}

export async function loadSetupStatus(
  fetcher: typeof fetch,
  apiBaseUrl: string | undefined
): Promise<SetupStatusResult> {
  try {
    const response = await fetcher(serverApiUrl(apiBaseUrl, '/api/v1/setup/status'), {
      headers: { accept: 'application/json' }
    });

    if (!response.ok) {
      return {
        status: 'unavailable',
        data: null,
        httpStatus: response.status,
        message: `无法读取初始设置状态（HTTP ${response.status}）。`
      };
    }

    const payload: unknown = await response.json();
    if (!isSetupStatus(payload)) {
      return {
        status: 'unavailable',
        data: null,
        httpStatus: response.status,
        message: '初始设置状态响应格式无效。'
      };
    }

    return { status: 'ready', data: payload };
  } catch {
    return {
      status: 'unavailable',
      data: null,
      httpStatus: null,
      message: '无法连接初始设置 API。'
    };
  }
}

export function submitSetup(
  fetcher: typeof fetch,
  apiBaseUrl: string | undefined,
  payload: SetupRequest
): Promise<Response> {
  return fetcher(serverApiUrl(apiBaseUrl, '/api/v1/setup'), {
    method: 'POST',
    headers: {
      accept: 'application/json',
      'content-type': 'application/json'
    },
    body: JSON.stringify(payload)
  });
}
