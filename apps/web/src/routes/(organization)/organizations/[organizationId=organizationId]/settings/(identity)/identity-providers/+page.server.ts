import { fail, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import {
  forwardZeusAuthCookies,
  loadCurrentPrincipal,
  serverApiFetcher,
  serverApiUrl
} from '$lib/api/server';

export type IdentityProvider = {
  id: string;
  organization_id: string;
  slug: string;
  issuer_url: string;
  client_id: string;
  scopes: string[];
  group_claim: string | null;
  jit_enabled: boolean;
  trusted_acr: string[];
  trusted_amr: string[];
  enabled: boolean;
  revision: number;
  created_at: string;
  updated_at: string;
};

type JsonRecord = Record<string, unknown>;
type ActionEvent = Parameters<NonNullable<Actions['create']>>[0];

function isJsonRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function isIdentityProvider(value: unknown): value is IdentityProvider {
  return (
    isJsonRecord(value) &&
    typeof value.id === 'string' &&
    typeof value.organization_id === 'string' &&
    typeof value.slug === 'string' &&
    typeof value.issuer_url === 'string' &&
    typeof value.client_id === 'string' &&
    isStringArray(value.scopes) &&
    (typeof value.group_claim === 'string' || value.group_claim === null) &&
    typeof value.jit_enabled === 'boolean' &&
    isStringArray(value.trusted_acr) &&
    isStringArray(value.trusted_amr) &&
    typeof value.enabled === 'boolean' &&
    typeof value.revision === 'number' &&
    typeof value.created_at === 'string' &&
    typeof value.updated_at === 'string'
  );
}

function formValue(formData: FormData, name: string, trim = true): string {
  const value = formData.get(name);
  if (typeof value !== 'string') return '';
  return trim ? value.trim() : value;
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

function providerErrorMessage(status: number, operation: 'create' | 'update'): string {
  if (status === 403) return '当前账号无权管理此组织的身份提供商。';
  if (status === 409) return '身份提供商配置已冲突，请检查 slug 或刷新页面。';
  if (status === 412) return '身份提供商配置已被其他管理员修改，请刷新页面后重试。';
  if (status === 428) return '缺少身份提供商版本条件，请刷新页面后重试。';
  if (status === 400 || status === 422) return '身份提供商配置无效，请检查输入后重试。';
  if (status >= 500) return '身份提供商服务暂时不可用，请稍后重试。';
  return operation === 'create' ? '身份提供商创建失败，请稍后重试。' : '身份提供商更新失败，请稍后重试。';
}

function loadErrorMessage(status: number): string {
  if (status === 403) return '当前账号无权读取此组织的身份提供商。';
  if (status >= 500) return '身份提供商服务暂时不可用，请稍后重试。';
  return '无法读取身份提供商，请稍后重试。';
}

async function loadProviders(
  apiFetch: typeof fetch,
  organizationId: string
): Promise<{ providers: IdentityProvider[]; loadError: string | null; httpStatus: number | null }> {
  let response: Response;
  try {
    response = await apiFetch(
      serverApiUrl(
        env.ZEUS_API_URL,
        `/api/v1/organizations/${encodeURIComponent(organizationId)}/identity-providers`
      ),
      { headers: { accept: 'application/json' } }
    );
  } catch {
    return {
      providers: [],
      loadError: '无法连接身份提供商 API，请稍后重试。',
      httpStatus: null
    };
  }

  if (response.status === 401) redirect(303, '/login');
  if (!response.ok) {
    return {
      providers: [],
      loadError: loadErrorMessage(response.status),
      httpStatus: response.status
    };
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    return {
      providers: [],
      loadError: '身份提供商 API 返回了无法识别的响应。',
      httpStatus: 502
    };
  }

  if (!Array.isArray(payload) || !payload.every(isIdentityProvider)) {
    return {
      providers: [],
      loadError: '身份提供商 API 返回了无法识别的响应。',
      httpStatus: 502
    };
  }

  return { providers: payload, loadError: null, httpStatus: null };
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

function revisionValue(formData: FormData): number | null {
  const value = Number(formValue(formData, 'revision'));
  return Number.isSafeInteger(value) && value > 0 ? value : null;
}

export const load: PageServerLoad = async ({ parent, fetch, params, request, url }) => {
  const auth = await parent();
  if (auth.status === 'unauthenticated') redirect(303, '/login');

  const organizationId = params.organizationId;
  if (auth.status !== 'ready') {
    return {
      authStatus: auth.status,
      organizationId,
      providers: [],
      loadError: '无法确认当前登录状态，请稍后重试。',
      httpStatus: null
    };
  }
  if (!organizationId || auth.principal?.organization_id !== organizationId) {
    return {
      authStatus: auth.status,
      organizationId: null,
      providers: [],
      loadError: null,
      httpStatus: null
    };
  }

  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  return {
    authStatus: auth.status,
    organizationId,
    ...(await loadProviders(apiFetch, organizationId))
  };
};

export const actions: Actions = {
  create: async (event) => {
    const context = await organizationActionContext(event);
    if ('error' in context) return context.error;

    const formData = await event.request.formData();
    const slug = formValue(formData, 'slug');
    const issuerUrl = formValue(formData, 'issuer_url');
    const clientId = formValue(formData, 'client_id');
    const clientSecret = formValue(formData, 'client_secret', false);
    if (!slug) return actionError(400, '身份提供商 slug 不能为空。');
    if (!issuerUrl) return actionError(400, 'Issuer URL 不能为空。');
    if (!clientId) return actionError(400, 'Client ID 不能为空。');
    if (!clientSecret) return actionError(400, 'Client secret 不能为空。');

    let response: Response;
    try {
      response = await context.apiFetch(
        serverApiUrl(
          env.ZEUS_API_URL,
          `/api/v1/organizations/${encodeURIComponent(context.organizationId)}/identity-providers`
        ),
        {
          method: 'POST',
          headers: {
            accept: 'application/json',
            'content-type': 'application/json'
          },
          body: JSON.stringify({
            slug,
            issuer_url: issuerUrl,
            client_id: clientId,
            client_secret: clientSecret,
            jit_enabled: formData.get('jit_enabled') === 'true',
            trusted_acr: listValue(formData, 'trusted_acr'),
            trusted_amr: listValue(formData, 'trusted_amr')
          })
        }
      );
    } catch {
      return actionError(503, '无法连接身份提供商 API，请稍后重试。');
    }

    forwardZeusAuthCookies(response, event.cookies);
    if (response.status === 401) redirect(303, '/login');
    if (!response.ok) {
      return actionError(responseStatus(response.status), providerErrorMessage(response.status, 'create'));
    }

    return { type: 'success' as const, message: '身份提供商已创建。' };
  },

  update: async (event) => {
    const context = await organizationActionContext(event);
    if ('error' in context) return context.error;

    const formData = await event.request.formData();
    const providerId = formValue(formData, 'provider_id');
    const revision = revisionValue(formData);
    const slug = formValue(formData, 'slug');
    const issuerUrl = formValue(formData, 'issuer_url');
    const clientId = formValue(formData, 'client_id');
    const clientSecret = formValue(formData, 'client_secret', false);
    if (!providerId) return actionError(400, '缺少身份提供商 ID。');
    if (!revision) return actionError(400, '缺少有效的身份提供商 revision。');
    if (!slug) return actionError(400, '身份提供商 slug 不能为空。');
    if (!issuerUrl) return actionError(400, 'Issuer URL 不能为空。');
    if (!clientId) return actionError(400, 'Client ID 不能为空。');

    const payload: JsonRecord = {
      slug,
      issuer_url: issuerUrl,
      client_id: clientId,
      enabled: formData.get('enabled') === 'true',
      jit_enabled: formData.get('jit_enabled') === 'true',
      trusted_acr: listValue(formData, 'trusted_acr'),
      trusted_amr: listValue(formData, 'trusted_amr')
    };
    if (clientSecret) payload.client_secret = clientSecret;

    let response: Response;
    try {
      response = await context.apiFetch(
        serverApiUrl(
          env.ZEUS_API_URL,
          `/api/v1/organizations/${encodeURIComponent(context.organizationId)}/identity-providers/${encodeURIComponent(providerId)}`
        ),
        {
          method: 'PATCH',
          headers: {
            accept: 'application/json',
            'content-type': 'application/json',
            'if-match': `"revision-${revision}"`
          },
          body: JSON.stringify(payload)
        }
      );
    } catch {
      return actionError(503, '无法连接身份提供商 API，请稍后重试。');
    }

    forwardZeusAuthCookies(response, event.cookies);
    if (response.status === 401) redirect(303, '/login');
    if (!response.ok) {
      return actionError(responseStatus(response.status), providerErrorMessage(response.status, 'update'));
    }

    return { type: 'success' as const, message: '身份提供商已更新。' };
  }
};
