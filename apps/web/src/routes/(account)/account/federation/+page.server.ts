import { fail, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import {
  forwardZeusAuthCookies,
  serverApiFetcher,
  serverApiUrl
} from '$lib/api/server';
import type { components } from '$lib/api/generated/schema';

export type OrganizationFederatedBinding =
  components['schemas']['OrganizationFederatedBindingResponse'];
export type ExternalIdentity = components['schemas']['ExternalIdentityResponse'];
export type AvailableFederatedProvider =
  components['schemas']['AvailableFederatedProviderResponse'];
type ExternalIdentityOverview = components['schemas']['ExternalIdentityOverviewResponse'];

type JsonRecord = Record<string, unknown>;

function isJsonRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isOrganizationBinding(value: unknown): value is OrganizationFederatedBinding {
  return (
    isJsonRecord(value) &&
    typeof value.binding_id === 'string' &&
    typeof value.organization_id === 'string' &&
    typeof value.organization_name === 'string' &&
    typeof value.provider_id === 'string' &&
    typeof value.provider_slug === 'string' &&
    typeof value.status === 'string' &&
    typeof value.binding_source === 'string' &&
    typeof value.linked_at === 'string' &&
    typeof value.last_login_at === 'string'
  );
}

function isExternalIdentity(value: unknown): value is ExternalIdentity {
  return (
    isJsonRecord(value) &&
    typeof value.identity_id === 'string' &&
    typeof value.issuer === 'string' &&
    typeof value.subject === 'string' &&
    typeof value.status === 'string' &&
    typeof value.created_at === 'string' &&
    typeof value.last_login_at === 'string' &&
    Array.isArray(value.organization_bindings) &&
    value.organization_bindings.every(isOrganizationBinding)
  );
}

function isAvailableProvider(value: unknown): value is AvailableFederatedProvider {
  return (
    isJsonRecord(value) &&
    typeof value.provider_id === 'string' &&
    typeof value.organization_id === 'string' &&
    typeof value.organization_name === 'string' &&
    typeof value.provider_slug === 'string' &&
    typeof value.issuer === 'string'
  );
}

function isExternalIdentityOverview(value: unknown): value is ExternalIdentityOverview {
  return (
    isJsonRecord(value) &&
    Array.isArray(value.identities) &&
    value.identities.every(isExternalIdentity) &&
    Array.isArray(value.available_providers) &&
    value.available_providers.every(isAvailableProvider)
  );
}

function responseStatus(status: number): number {
  return status >= 400 && status <= 599 ? status : 502;
}

function formValue(formData: FormData, name: string): string {
  const value = formData.get(name);
  return typeof value === 'string' ? value.trim() : '';
}

function actionError(status: number, message: string) {
  return fail(status, { type: 'error' as const, message });
}

function isLinkIntentResponse(value: unknown): value is { authorization_url: string } {
  return isJsonRecord(value) && typeof value.authorization_url === 'string';
}

async function responseJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function linkErrorMessage(status: number): string {
  if (status === 403) return '当前账号无法绑定该企业身份。';
  if (status === 404) return '企业身份提供商不存在或已停用。';
  if (status === 409) return '该外部身份已经绑定到其他 Zeus 账号。';
  if (status >= 500) return '企业身份绑定服务暂时不可用，请稍后重试。';
  return '无法发起企业身份绑定，请稍后重试。';
}

function unlinkErrorMessage(status: number): string {
  if (status === 404) return '该 Organization 信任绑定不存在或已经解除。';
  if (status >= 500) return '企业身份解绑服务暂时不可用，请稍后重试。';
  return '无法解除该 Organization 信任绑定，请稍后重试。';
}

function revokeErrorMessage(status: number): string {
  if (status === 404) return '该外部身份不存在或已经撤销。';
  if (status === 409) return '请先解除全部 Organization 绑定，并保留另一种登录方式。';
  if (status >= 500) return '外部身份撤销服务暂时不可用，请稍后重试。';
  return '无法撤销该外部身份，请稍后重试。';
}

export const load: PageServerLoad = async ({ fetch, parent, request, url }) => {
  const auth = await parent();
  if (auth.status === 'unauthenticated') {
    redirect(303, '/login');
  }
  if (auth.status !== 'ready') {
    return {
      identities: [],
      providers: [],
      loadError: '无法确认当前登录状态，请稍后重试。'
    };
  }

  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  let response: Response;
  try {
    response = await apiFetch(
      serverApiUrl(env.ZEUS_API_URL, '/api/v1/users/me/external-identities'),
      { headers: { accept: 'application/json' } }
    );
  } catch {
    return { identities: [], providers: [], loadError: '无法连接外部身份 API，请稍后重试。' };
  }
  if (response.status === 401) {
    redirect(303, '/login');
  }
  if (!response.ok) {
    return {
      identities: [],
      providers: [],
      loadError:
        response.status >= 500
          ? '外部身份服务暂时不可用，请稍后重试。'
          : '无法读取外部身份，请稍后重试。'
    };
  }
  const payload = await responseJson(response);
  if (!isExternalIdentityOverview(payload)) {
    return {
      identities: [],
      providers: [],
      loadError: '外部身份 API 返回了无法识别的响应。'
    };
  }
  return {
    identities: payload.identities,
    providers: payload.available_providers,
    loadError: null
  };
};

export const actions: Actions = {
  link: async (event) => {
    const providerId = formValue(await event.request.formData(), 'provider_id');
    if (!providerId) return actionError(400, '缺少要绑定的企业身份提供商。');

    const apiFetch = serverApiFetcher(
      event.fetch,
      event.request.headers.get('cookie'),
      event.url.origin
    );
    let response: Response;
    try {
      response = await apiFetch(
        serverApiUrl(env.ZEUS_API_URL, '/api/v1/users/me/external-identities/link-intents'),
        {
          method: 'POST',
          headers: { accept: 'application/json', 'content-type': 'application/json' },
          body: JSON.stringify({ provider_id: providerId })
        }
      );
    } catch {
      return actionError(503, '无法连接企业身份绑定 API，请稍后重试。');
    }

    forwardZeusAuthCookies(response, event.cookies);
    if (response.status === 401) redirect(303, '/login');
    if (!response.ok) {
      return actionError(responseStatus(response.status), linkErrorMessage(response.status));
    }
    const payload = await responseJson(response);
    if (!isLinkIntentResponse(payload)) {
      return actionError(502, '企业身份绑定 API 返回了无法识别的响应。');
    }

    let authorizationUrl: URL;
    try {
      authorizationUrl = new URL(payload.authorization_url);
    } catch {
      return actionError(502, '企业身份绑定 API 返回了无效的授权地址。');
    }
    if (authorizationUrl.protocol !== 'http:' && authorizationUrl.protocol !== 'https:') {
      return actionError(502, '企业身份绑定 API 返回了无效的授权地址。');
    }
    redirect(303, authorizationUrl.toString());
  },

  unlinkBinding: async (event) => {
    const formData = await event.request.formData();
    const identityId = formValue(formData, 'identity_id');
    const bindingId = formValue(formData, 'binding_id');
    if (!identityId || !bindingId) {
      return actionError(400, '缺少要解除的 Organization 信任绑定。');
    }

    const apiFetch = serverApiFetcher(
      event.fetch,
      event.request.headers.get('cookie'),
      event.url.origin
    );
    let response: Response;
    try {
      response = await apiFetch(
        serverApiUrl(
          env.ZEUS_API_URL,
          `/api/v1/users/me/external-identities/${encodeURIComponent(identityId)}/organization-bindings/${encodeURIComponent(bindingId)}`
        ),
        { method: 'DELETE', headers: { accept: 'application/json' } }
      );
    } catch {
      return actionError(503, '无法连接企业身份解绑 API，请稍后重试。');
    }

    forwardZeusAuthCookies(response, event.cookies);
    if (response.status === 401) redirect(303, '/login');
    if (!response.ok) {
      return actionError(responseStatus(response.status), unlinkErrorMessage(response.status));
    }
    return { type: 'success' as const, message: 'Organization 信任绑定已解除。' };
  },

  revokeIdentity: async (event) => {
    const identityId = formValue(await event.request.formData(), 'identity_id');
    if (!identityId) return actionError(400, '缺少要撤销的外部身份。');

    const apiFetch = serverApiFetcher(
      event.fetch,
      event.request.headers.get('cookie'),
      event.url.origin
    );
    let response: Response;
    try {
      response = await apiFetch(
        serverApiUrl(
          env.ZEUS_API_URL,
          `/api/v1/users/me/external-identities/${encodeURIComponent(identityId)}`
        ),
        { method: 'DELETE', headers: { accept: 'application/json' } }
      );
    } catch {
      return actionError(503, '无法连接外部身份撤销 API，请稍后重试。');
    }

    forwardZeusAuthCookies(response, event.cookies);
    if (response.status === 401) redirect(303, '/login');
    if (!response.ok) {
      return actionError(responseStatus(response.status), revokeErrorMessage(response.status));
    }
    return { type: 'success' as const, message: '全局外部身份已撤销。' };
  }
};
