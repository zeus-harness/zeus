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

export type IdentityPolicy = {
  organization_id: string;
  mfa_required: boolean;
  federated_required: boolean;
  required_federated_provider_id: string | null;
  revision: number;
  updated_by: string | null;
  updated_at: string;
};

type JsonRecord = Record<string, unknown>;
type ActionEvent = Parameters<NonNullable<Actions['update']>>[0];

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

function isIdentityPolicy(value: unknown): value is IdentityPolicy {
  return (
    isJsonRecord(value) &&
    typeof value.organization_id === 'string' &&
    typeof value.mfa_required === 'boolean' &&
    typeof value.federated_required === 'boolean' &&
    (typeof value.required_federated_provider_id === 'string' ||
      value.required_federated_provider_id === null) &&
    typeof value.revision === 'number' &&
    (typeof value.updated_by === 'string' || value.updated_by === null) &&
    typeof value.updated_at === 'string'
  );
}

function actionError(status: number, message: string) {
  return fail(status, { type: 'error' as const, message });
}

function formValue(formData: FormData, name: string): string {
  const value = formData.get(name);
  return typeof value === 'string' ? value.trim() : '';
}

function responseStatus(status: number): number {
  return status >= 400 && status <= 599 ? status : 502;
}

function policyErrorMessage(status: number): string {
  if (status === 403) return '当前账号无权管理此组织的身份策略。';
  if (status === 409) return '身份策略状态已被其他管理员修改，请刷新页面。';
  if (status === 412) return '身份策略已被其他管理员修改，请刷新页面后重试。';
  if (status === 428) return '缺少身份策略版本条件，请刷新页面后重试。';
  if (status === 400 || status === 422) return '身份策略无效，请确认联合身份和必选提供商设置。';
  if (status >= 500) return '身份策略服务暂时不可用，请稍后重试。';
  return '身份策略更新失败，请稍后重试。';
}

function loadErrorMessage(status: number, resource: 'provider' | 'policy'): string {
  if (status === 403) return resource === 'provider' ? '当前账号无权读取身份提供商。' : '当前账号无权读取身份策略。';
  if (status >= 500) return resource === 'provider' ? '身份提供商服务暂时不可用。' : '身份策略服务暂时不可用。';
  return resource === 'provider' ? '无法读取身份提供商，请稍后重试。' : '无法读取身份策略，请稍后重试。';
}

async function readJson<T>(
  apiFetch: typeof fetch,
  path: string,
  resource: 'provider' | 'policy',
  guard: (value: unknown) => value is T
): Promise<{ value: T | null; error: string | null; httpStatus: number | null }> {
  let response: Response;
  try {
    response = await apiFetch(serverApiUrl(env.ZEUS_API_URL, path), {
      headers: { accept: 'application/json' }
    });
  } catch {
    return {
      value: null,
      error: resource === 'provider' ? '无法连接身份提供商 API，请稍后重试。' : '无法连接身份策略 API，请稍后重试。',
      httpStatus: null
    };
  }

  if (response.status === 401) redirect(303, '/login');
  if (!response.ok) {
    return { value: null, error: loadErrorMessage(response.status, resource), httpStatus: response.status };
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    return {
      value: null,
      error: resource === 'provider' ? '身份提供商 API 返回了无法识别的响应。' : '身份策略 API 返回了无法识别的响应。',
      httpStatus: 502
    };
  }

  if (!guard(payload)) {
    return {
      value: null,
      error: resource === 'provider' ? '身份提供商 API 返回了无法识别的响应。' : '身份策略 API 返回了无法识别的响应。',
      httpStatus: 502
    };
  }

  return { value: payload, error: null, httpStatus: null };
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
    return { apiFetch, error: actionError(400, '当前会话没有活动组织，无法修改身份策略。') };
  }
  return { apiFetch, organizationId };
}

function revisionValue(formData: FormData): number | null {
  const value = Number(formValue(formData, 'revision'));
  return Number.isSafeInteger(value) && value > 0 ? value : null;
}

export const load: PageServerLoad = async ({ parent, fetch, request, url }) => {
  const auth = await parent();
  if (auth.status === 'unauthenticated') redirect(303, '/login');

  const organizationId = auth.principal?.organization_id ?? null;
  if (auth.status !== 'ready') {
    return {
      authStatus: auth.status,
      organizationId,
      providers: [],
      providersLoadError: '无法确认当前登录状态，请稍后重试。',
      providersHttpStatus: null,
      policy: null,
      policyLoadError: '无法确认当前登录状态，请稍后重试。',
      policyHttpStatus: null
    };
  }
  if (!organizationId) {
    return {
      authStatus: auth.status,
      organizationId,
      providers: [],
      providersLoadError: null,
      providersHttpStatus: null,
      policy: null,
      policyLoadError: null,
      policyHttpStatus: null
    };
  }

  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const providerPath = `/api/v1/organizations/${encodeURIComponent(organizationId)}/identity-providers`;
  const policyPath = `/api/v1/organizations/${encodeURIComponent(organizationId)}/identity-policy`;
  const [providers, policy] = await Promise.all([
    readJson<IdentityProvider[]>(apiFetch, providerPath, 'provider', (value): value is IdentityProvider[] =>
      Array.isArray(value) && value.every(isIdentityProvider)
    ),
    readJson<IdentityPolicy>(apiFetch, policyPath, 'policy', isIdentityPolicy)
  ]);

  return {
    authStatus: auth.status,
    organizationId,
    providers: providers.value ?? [],
    providersLoadError: providers.error,
    providersHttpStatus: providers.httpStatus,
    policy: policy.value,
    policyLoadError: policy.error,
    policyHttpStatus: policy.httpStatus
  };
};

export const actions: Actions = {
  update: async (event) => {
    const context = await organizationActionContext(event);
    if ('error' in context) return context.error;

    const formData = await event.request.formData();
    const revision = revisionValue(formData);
    if (!revision) return actionError(400, '缺少有效的身份策略 revision。');

    const mfaRequired = formData.get('mfa_required') === 'true';
    const federatedRequired = formData.get('federated_required') === 'true';
    const requiredProviderId = formValue(formData, 'required_federated_provider_id');
    if (federatedRequired && !requiredProviderId) {
      return actionError(400, '启用强制联合身份时必须选择一个身份提供商。');
    }

    let response: Response;
    try {
      response = await context.apiFetch(
        serverApiUrl(
          env.ZEUS_API_URL,
          `/api/v1/organizations/${encodeURIComponent(context.organizationId)}/identity-policy`
        ),
        {
          method: 'PUT',
          headers: {
            accept: 'application/json',
            'content-type': 'application/json',
            'if-match': `"revision-${revision}"`
          },
          body: JSON.stringify({
            mfa_required: mfaRequired,
            federated_required: federatedRequired,
            required_federated_provider_id: federatedRequired ? requiredProviderId : null
          })
        }
      );
    } catch {
      return actionError(503, '无法连接身份策略 API，请稍后重试。');
    }

    forwardZeusAuthCookies(response, event.cookies);
    if (response.status === 401) redirect(303, '/login');
    if (!response.ok) {
      return actionError(responseStatus(response.status), policyErrorMessage(response.status));
    }

    return { type: 'success' as const, message: '身份策略已更新。' };
  }
};
