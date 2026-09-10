import { fail, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import {
  forwardZeusAuthCookies,
  loadCurrentPrincipal,
  serverApiFetcher,
  serverApiUrl
} from '$lib/api/server';

export type OrganizationDomain = {
  id: string;
  organization_id: string;
  domain: string;
  status: string;
  verified_at: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
};

type CreatedOrganizationDomain = OrganizationDomain & {
  txt_record_name: string;
  txt_record_value: string;
};

type JsonRecord = Record<string, unknown>;
type ActionEvent = Parameters<NonNullable<Actions['create']>>[0];

function isJsonRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isOrganizationDomain(value: unknown): value is OrganizationDomain {
  return (
    isJsonRecord(value) &&
    typeof value.id === 'string' &&
    typeof value.organization_id === 'string' &&
    typeof value.domain === 'string' &&
    typeof value.status === 'string' &&
    (typeof value.verified_at === 'string' || value.verified_at === null) &&
    typeof value.created_by === 'string' &&
    typeof value.created_at === 'string' &&
    typeof value.updated_at === 'string'
  );
}

function isCreatedOrganizationDomain(value: unknown): value is CreatedOrganizationDomain {
  if (!isOrganizationDomain(value)) return false;
  const record = value as JsonRecord;
  return typeof record.txt_record_name === 'string' && typeof record.txt_record_value === 'string';
}

function formValue(formData: FormData, name: string): string {
  const value = formData.get(name);
  return typeof value === 'string' ? value.trim() : '';
}

function actionError(status: number, message: string) {
  return fail(status, { type: 'error' as const, message });
}

function responseStatus(status: number): number {
  return status >= 400 && status <= 599 ? status : 502;
}

function domainErrorMessage(status: number, operation: 'create' | 'verify' | 'revoke'): string {
  if (status === 403) return '当前账号无权管理此组织的域名。';
  if (status === 404) return operation === 'revoke' ? '该域名不存在或已经撤销。' : '该域名不存在或状态已变化。';
  if (status === 409) return '域名状态已被其他管理员修改，请刷新页面。';
  if (status === 400 || status === 422) {
    return operation === 'verify'
      ? '未找到预期的 DNS TXT 记录，请确认记录已生效后重试。'
      : '域名无效，请检查输入后重试。';
  }
  if (status >= 500) return '域名服务暂时不可用，请稍后重试。';
  if (operation === 'create') return '域名创建失败，请稍后重试。';
  if (operation === 'verify') return '域名验证失败，请稍后重试。';
  return '域名撤销失败，请稍后重试。';
}

function loadErrorMessage(status: number): string {
  if (status === 403) return '当前账号无权读取此组织的域名。';
  if (status >= 500) return '域名服务暂时不可用，请稍后重试。';
  return '无法读取组织域名，请稍后重试。';
}

async function loadDomains(
  apiFetch: typeof fetch,
  organizationId: string
): Promise<{ domains: OrganizationDomain[]; loadError: string | null; httpStatus: number | null }> {
  let response: Response;
  try {
    response = await apiFetch(
      serverApiUrl(
        env.ZEUS_API_URL,
        `/api/v1/organizations/${encodeURIComponent(organizationId)}/domains`
      ),
      { headers: { accept: 'application/json' } }
    );
  } catch {
    return { domains: [], loadError: '无法连接域名 API，请稍后重试。', httpStatus: null };
  }

  if (response.status === 401) redirect(303, '/login');
  if (!response.ok) {
    return {
      domains: [],
      loadError: loadErrorMessage(response.status),
      httpStatus: response.status
    };
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    return {
      domains: [],
      loadError: '域名 API 返回了无法识别的响应。',
      httpStatus: 502
    };
  }

  if (!Array.isArray(payload) || !payload.every(isOrganizationDomain)) {
    return {
      domains: [],
      loadError: '域名 API 返回了无法识别的响应。',
      httpStatus: 502
    };
  }

  return { domains: payload, loadError: null, httpStatus: null };
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
  const organizationId = event.params.organizationId;
  if (!organizationId || auth.principal?.organization_id !== organizationId) {
    return { apiFetch, error: actionError(409, 'Organization 上下文已变化，请刷新后重试。') };
  }
  return { apiFetch, organizationId };
}

async function responseJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

export const load: PageServerLoad = async ({ parent, fetch, params, request, url }) => {
  const auth = await parent();
  if (auth.status === 'unauthenticated') redirect(303, '/login');

  const organizationId = params.organizationId;
  if (auth.status !== 'ready') {
    return {
      authStatus: auth.status,
      organizationId,
      domains: [],
      loadError: '无法确认当前登录状态，请稍后重试。',
      httpStatus: null
    };
  }
  if (!organizationId || auth.principal?.organization_id !== organizationId) {
    return {
      authStatus: auth.status,
      organizationId: null,
      domains: [],
      loadError: null,
      httpStatus: null
    };
  }

  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  return {
    authStatus: auth.status,
    organizationId,
    ...(await loadDomains(apiFetch, organizationId))
  };
};

export const actions: Actions = {
  create: async (event) => {
    const context = await organizationActionContext(event);
    if ('error' in context) return context.error;

    const domain = formValue(await event.request.formData(), 'domain');
    if (!domain) return actionError(400, '域名不能为空。');

    let response: Response;
    try {
      response = await context.apiFetch(
        serverApiUrl(
          env.ZEUS_API_URL,
          `/api/v1/organizations/${encodeURIComponent(context.organizationId)}/domains`
        ),
        {
          method: 'POST',
          headers: {
            accept: 'application/json',
            'content-type': 'application/json'
          },
          body: JSON.stringify({ domain })
        }
      );
    } catch {
      return actionError(503, '无法连接域名 API，请稍后重试。');
    }

    forwardZeusAuthCookies(response, event.cookies);
    if (response.status === 401) redirect(303, '/login');
    if (!response.ok) {
      return actionError(responseStatus(response.status), domainErrorMessage(response.status, 'create'));
    }

    const payload = await responseJson(response);
    if (!isCreatedOrganizationDomain(payload)) {
      return actionError(502, '域名 API 未返回完整的 DNS TXT 验证资料。');
    }

    return {
      type: 'domain_created' as const,
      message: '域名已创建，请按下方资料添加 DNS TXT 记录。',
      verification: {
        domain_id: payload.id,
        domain: payload.domain,
        txt_record_name: payload.txt_record_name,
        txt_record_value: payload.txt_record_value
      }
    };
  },

  verify: async (event) => {
    const context = await organizationActionContext(event);
    if ('error' in context) return context.error;

    const domainId = formValue(await event.request.formData(), 'domain_id');
    if (!domainId) return actionError(400, '缺少域名 ID。');

    let response: Response;
    try {
      response = await context.apiFetch(
        serverApiUrl(
          env.ZEUS_API_URL,
          `/api/v1/organizations/${encodeURIComponent(context.organizationId)}/domains/${encodeURIComponent(domainId)}/verify`
        ),
        {
          method: 'POST',
          headers: { accept: 'application/json' }
        }
      );
    } catch {
      return actionError(503, '无法连接域名验证 API，请稍后重试。');
    }

    forwardZeusAuthCookies(response, event.cookies);
    if (response.status === 401) redirect(303, '/login');
    if (!response.ok) {
      return actionError(responseStatus(response.status), domainErrorMessage(response.status, 'verify'));
    }

    return { type: 'success' as const, message: '域名已验证。' };
  },

  revoke: async (event) => {
    const context = await organizationActionContext(event);
    if ('error' in context) return context.error;

    const domainId = formValue(await event.request.formData(), 'domain_id');
    if (!domainId) return actionError(400, '缺少域名 ID。');

    let response: Response;
    try {
      response = await context.apiFetch(
        serverApiUrl(
          env.ZEUS_API_URL,
          `/api/v1/organizations/${encodeURIComponent(context.organizationId)}/domains/${encodeURIComponent(domainId)}`
        ),
        {
          method: 'DELETE',
          headers: { accept: 'application/json' }
        }
      );
    } catch {
      return actionError(503, '无法连接域名撤销 API，请稍后重试。');
    }

    forwardZeusAuthCookies(response, event.cookies);
    if (response.status === 401) redirect(303, '/login');
    if (!response.ok) {
      return actionError(responseStatus(response.status), domainErrorMessage(response.status, 'revoke'));
    }

    return { type: 'success' as const, message: '域名已撤销。' };
  }
};
