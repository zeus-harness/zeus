import { fail, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import {
  forwardZeusAuthCookies,
  loadCurrentPrincipal,
  serverApiFetcher,
  serverApiUrl
} from '$lib/api/server';

export type OidcClientType = 'public' | 'confidential';

export type OrganizationOidcClient = {
  id: string;
  client_id: string;
  organization_id: string;
  name: string;
  client_type: OidcClientType;
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  trusted: boolean;
  allowed_scopes: string[];
  status: string;
  revision: number;
  created_at: string;
  updated_at: string;
};

type CreatedOrganizationOidcClient = OrganizationOidcClient & {
  client_secret: string | null;
};

type JsonRecord = Record<string, unknown>;
type ActionEvent = Parameters<NonNullable<Actions['create']>>[0];

function isJsonRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function isOidcClientType(value: unknown): value is OidcClientType {
  return value === 'public' || value === 'confidential';
}

function isOrganizationOidcClient(value: unknown): value is OrganizationOidcClient {
  return (
    isJsonRecord(value) &&
    typeof value.id === 'string' &&
    typeof value.client_id === 'string' &&
    typeof value.organization_id === 'string' &&
    typeof value.name === 'string' &&
    isOidcClientType(value.client_type) &&
    isStringArray(value.redirect_uris) &&
    isStringArray(value.post_logout_redirect_uris) &&
    typeof value.trusted === 'boolean' &&
    isStringArray(value.allowed_scopes) &&
    typeof value.status === 'string' &&
    typeof value.revision === 'number' &&
    typeof value.created_at === 'string' &&
    typeof value.updated_at === 'string'
  );
}

function isCreatedOrganizationOidcClient(
  value: unknown
): value is CreatedOrganizationOidcClient {
  if (!isOrganizationOidcClient(value)) return false;
  const secret = (value as JsonRecord).client_secret;
  if (secret !== null && (typeof secret !== 'string' || secret.length === 0)) return false;
  return value.client_type !== 'confidential' || typeof secret === 'string';
}

function formValue(formData: FormData, name: string): string {
  const value = formData.get(name);
  return typeof value === 'string' ? value.trim() : '';
}

function listValue(formData: FormData, name: string): string[] {
  return formValue(formData, name)
    .split(/[\n,]/)
    .map((value) => value.trim())
    .filter(Boolean);
}

function actionError(status: number, message: string) {
  return fail(status, { type: 'error' as const, message });
}

function responseStatus(status: number): number {
  return status >= 400 && status <= 599 ? status : 502;
}

function clientErrorMessage(
  status: number,
  operation: 'create' | 'update' | 'delete'
): string {
  if (status === 403) return '当前账号无权管理此组织的 OIDC Client。';
  if (status === 404) return operation === 'create' ? '当前组织不存在。' : '该 OIDC Client 不存在或已经删除。';
  if (status === 409) return 'OIDC Client 配置已冲突，请刷新页面后重试。';
  if (status === 412) return 'OIDC Client 配置已被其他管理员修改，请刷新页面后重试。';
  if (status === 428) return '缺少 OIDC Client 版本条件，请刷新页面后重试。';
  if (status === 400 || status === 422) return 'OIDC Client 配置无效，请检查输入后重试。';
  if (status >= 500) return 'OIDC Client 服务暂时不可用，请稍后重试。';
  if (operation === 'create') return 'OIDC Client 创建失败，请稍后重试。';
  if (operation === 'update') return 'OIDC Client 更新失败，请稍后重试。';
  return 'OIDC Client 删除失败，请稍后重试。';
}

function loadErrorMessage(status: number): string {
  if (status === 403) return '当前账号无权读取此组织的 OIDC Client。';
  if (status >= 500) return 'OIDC Client 服务暂时不可用，请稍后重试。';
  return '无法读取组织 OIDC Client，请稍后重试。';
}

async function loadClients(
  apiFetch: typeof fetch,
  organizationId: string
): Promise<{ clients: OrganizationOidcClient[]; loadError: string | null; httpStatus: number | null }> {
  let response: Response;
  try {
    response = await apiFetch(
      serverApiUrl(
        env.ZEUS_API_URL,
        `/api/v1/organizations/${encodeURIComponent(organizationId)}/oidc-clients`
      ),
      { headers: { accept: 'application/json' } }
    );
  } catch {
    return { clients: [], loadError: '无法连接 OIDC Client API，请稍后重试。', httpStatus: null };
  }

  if (response.status === 401) redirect(303, '/login');
  if (!response.ok) {
    return {
      clients: [],
      loadError: loadErrorMessage(response.status),
      httpStatus: response.status
    };
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    return {
      clients: [],
      loadError: 'OIDC Client API 返回了无法识别的响应。',
      httpStatus: 502
    };
  }

  if (!Array.isArray(payload) || !payload.every(isOrganizationOidcClient)) {
    return {
      clients: [],
      loadError: 'OIDC Client API 返回了无法识别的响应。',
      httpStatus: 502
    };
  }

  return { clients: payload, loadError: null, httpStatus: null };
}

async function organizationActionContext(event: ActionEvent) {
  const apiFetch = serverApiFetcher(
    event.fetch,
    event.request.headers.get('cookie'),
    event.url.origin
  );
  const auth = await loadCurrentPrincipal(apiFetch, env.ZEUS_API_URL);
  if (auth.status === 'unauthenticated') redirect(303, '/login');
  if (auth.status !== 'ready') {
    return { apiFetch, error: actionError(503, '无法确认当前登录状态，认证 API 暂不可用。') };
  }
  const organizationId = auth.principal?.organization_id;
  if (!organizationId) {
    return { apiFetch, error: actionError(400, '当前会话没有活动组织，无法管理 OIDC Client。') };
  }
  return { apiFetch, organizationId };
}

function revisionValue(formData: FormData): number | null {
  const value = Number(formValue(formData, 'revision'));
  return Number.isSafeInteger(value) && value > 0 ? value : null;
}

async function responseJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

export const load: PageServerLoad = async ({ parent, fetch, request, url }) => {
  const auth = await parent();
  if (auth.status === 'unauthenticated') redirect(303, '/login');

  const organizationId = auth.principal?.organization_id ?? null;
  if (auth.status !== 'ready') {
    return {
      authStatus: auth.status,
      organizationId,
      clients: [],
      loadError: '无法确认当前登录状态，请稍后重试。',
      httpStatus: null
    };
  }
  if (!organizationId) {
    return {
      authStatus: auth.status,
      organizationId,
      clients: [],
      loadError: null,
      httpStatus: null
    };
  }

  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  return {
    authStatus: auth.status,
    organizationId,
    ...(await loadClients(apiFetch, organizationId))
  };
};

export const actions: Actions = {
  create: async (event) => {
    const context = await organizationActionContext(event);
    if ('error' in context) return context.error;

    const formData = await event.request.formData();
    const name = formValue(formData, 'name');
    const clientType = formValue(formData, 'client_type');
    if (!name) return actionError(400, 'OIDC Client 名称不能为空。');
    if (!isOidcClientType(clientType)) {
      return actionError(400, 'OIDC Client 类型必须是 public 或 confidential。');
    }

    let response: Response;
    try {
      response = await context.apiFetch(
        serverApiUrl(
          env.ZEUS_API_URL,
          `/api/v1/organizations/${encodeURIComponent(context.organizationId)}/oidc-clients`
        ),
        {
          method: 'POST',
          headers: {
            accept: 'application/json',
            'content-type': 'application/json'
          },
          body: JSON.stringify({
            name,
            client_type: clientType,
            redirect_uris: listValue(formData, 'redirect_uris'),
            post_logout_redirect_uris: listValue(formData, 'post_logout_redirect_uris'),
            trusted: formData.get('trusted') === 'true',
            allowed_scopes: listValue(formData, 'allowed_scopes')
          })
        }
      );
    } catch {
      return actionError(503, '无法连接 OIDC Client API，请稍后重试。');
    }

    forwardZeusAuthCookies(response, event.cookies);
    if (response.status === 401) redirect(303, '/login');
    if (!response.ok) {
      return actionError(responseStatus(response.status), clientErrorMessage(response.status, 'create'));
    }

    const payload = await responseJson(response);
    if (!isCreatedOrganizationOidcClient(payload)) {
      return actionError(502, 'OIDC Client API 未返回一次性的 Client Secret。');
    }

    return {
      type: 'created' as const,
      message:
        payload.client_secret === null
          ? 'OIDC Client 已创建。Public Client 不生成 Client Secret。'
          : 'OIDC Client 已创建。请立即保存本次显示的 Client Secret。',
      client: {
        id: payload.id,
        client_id: payload.client_id,
        name: payload.name
      },
      client_secret: payload.client_secret
    };
  },

  update: async (event) => {
    const context = await organizationActionContext(event);
    if ('error' in context) return context.error;

    const formData = await event.request.formData();
    const clientId = formValue(formData, 'client_id');
    const revision = revisionValue(formData);
    const name = formValue(formData, 'name');
    if (!clientId) return actionError(400, '缺少 OIDC Client ID。');
    if (!revision) return actionError(400, '缺少有效的 OIDC Client revision。');
    if (!name) return actionError(400, 'OIDC Client 名称不能为空。');

    let response: Response;
    try {
      response = await context.apiFetch(
        serverApiUrl(
          env.ZEUS_API_URL,
          `/api/v1/organizations/${encodeURIComponent(context.organizationId)}/oidc-clients/${encodeURIComponent(clientId)}`
        ),
        {
          method: 'PATCH',
          headers: {
            accept: 'application/json',
            'content-type': 'application/json',
            'if-match': `"revision-${revision}"`
          },
          body: JSON.stringify({
            name,
            redirect_uris: listValue(formData, 'redirect_uris'),
            post_logout_redirect_uris: listValue(formData, 'post_logout_redirect_uris'),
            trusted: formData.get('trusted') === 'true',
            allowed_scopes: listValue(formData, 'allowed_scopes')
          })
        }
      );
    } catch {
      return actionError(503, '无法连接 OIDC Client API，请稍后重试。');
    }

    forwardZeusAuthCookies(response, event.cookies);
    if (response.status === 401) redirect(303, '/login');
    if (!response.ok) {
      return actionError(responseStatus(response.status), clientErrorMessage(response.status, 'update'));
    }

    return { type: 'success' as const, message: 'OIDC Client 已更新。' };
  },

  delete: async (event) => {
    const context = await organizationActionContext(event);
    if ('error' in context) return context.error;

    const clientId = formValue(await event.request.formData(), 'client_id');
    if (!clientId) return actionError(400, '缺少要删除的 OIDC Client ID。');

    let response: Response;
    try {
      response = await context.apiFetch(
        serverApiUrl(
          env.ZEUS_API_URL,
          `/api/v1/organizations/${encodeURIComponent(context.organizationId)}/oidc-clients/${encodeURIComponent(clientId)}`
        ),
        {
          method: 'DELETE',
          headers: { accept: 'application/json' }
        }
      );
    } catch {
      return actionError(503, '无法连接 OIDC Client API，请稍后重试。');
    }

    forwardZeusAuthCookies(response, event.cookies);
    if (response.status === 401) redirect(303, '/login');
    if (!response.ok) {
      return actionError(responseStatus(response.status), clientErrorMessage(response.status, 'delete'));
    }

    return { type: 'success' as const, message: 'OIDC Client 已删除。' };
  }
};
