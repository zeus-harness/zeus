import { fail, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import {
  forwardZeusAuthCookies,
  serverApiFetcher,
  serverApiUrl
} from '$lib/api/server';

export type FederatedIdentity = {
  identity_id: string;
  provider_id: string;
  organization_id: string;
  organization_name: string;
  provider_slug: string;
  issuer: string;
  subject: string;
  linked_at: string;
  last_login_at: string;
};

export type FederatedIdentityProvider = {
  id: string;
  organization_id: string;
  slug: string;
  issuer_url: string;
  enabled: boolean;
};

type UserOrganization = {
  organization_id: string;
  identity_providers: FederatedIdentityProvider[];
};

type JsonRecord = Record<string, unknown>;

type CollectionResult<T> = {
  data: T[];
  error: string | null;
};

function isJsonRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isFederatedIdentity(value: unknown): value is FederatedIdentity {
  return (
    isJsonRecord(value) &&
    typeof value.identity_id === 'string' &&
    typeof value.provider_id === 'string' &&
    typeof value.organization_id === 'string' &&
    typeof value.organization_name === 'string' &&
    typeof value.provider_slug === 'string' &&
    typeof value.issuer === 'string' &&
    typeof value.subject === 'string' &&
    typeof value.linked_at === 'string' &&
    typeof value.last_login_at === 'string'
  );
}

function isFederatedIdentityProvider(value: unknown): value is FederatedIdentityProvider {
  return (
    isJsonRecord(value) &&
    typeof value.id === 'string' &&
    typeof value.organization_id === 'string' &&
    typeof value.slug === 'string' &&
    typeof value.issuer_url === 'string' &&
    typeof value.enabled === 'boolean'
  );
}

function isUserOrganization(value: unknown): value is UserOrganization {
  return (
    isJsonRecord(value) &&
    typeof value.organization_id === 'string' &&
    Array.isArray(value.identity_providers) &&
    value.identity_providers.every(isFederatedIdentityProvider)
  );
}

function responseStatus(status: number): number {
  return status >= 400 && status <= 599 ? status : 502;
}

function collectionError(status: number, resource: string): string {
  if (status === 403) return `当前账号无权读取${resource}。`;
  if (status >= 500) return `${resource}服务暂时不可用，请稍后重试。`;
  return `无法读取${resource}，请稍后重试。`;
}

async function loadCollection<T>(
  apiFetch: typeof fetch,
  path: string,
  resource: string,
  isItem: (value: unknown) => value is T
): Promise<CollectionResult<T>> {
  let response: Response;
  try {
    response = await apiFetch(serverApiUrl(env.ZEUS_API_URL, path), {
      headers: { accept: 'application/json' }
    });
  } catch {
    return { data: [], error: `无法连接${resource} API，请稍后重试。` };
  }

  if (response.status === 401) {
    redirect(303, '/login');
  }
  if (!response.ok) {
    return { data: [], error: collectionError(response.status, resource) };
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    return { data: [], error: `${resource} API 返回了无法识别的响应。` };
  }
  if (!Array.isArray(payload) || !payload.every(isItem)) {
    return { data: [], error: `${resource} API 返回了无法识别的响应。` };
  }

  return { data: payload, error: null };
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
  if (status === 409) return '该企业身份已经绑定到其他账号。';
  if (status >= 500) return '企业身份绑定服务暂时不可用，请稍后重试。';
  return '无法发起企业身份绑定，请稍后重试。';
}

function unlinkErrorMessage(status: number): string {
  if (status === 404) return '该企业身份不存在或已经解绑。';
  if (status === 409) return '至少需要保留一种登录方式。';
  if (status >= 500) return '企业身份解绑服务暂时不可用，请稍后重试。';
  return '无法解绑该企业身份，请稍后重试。';
}

export const load: PageServerLoad = async ({ fetch, parent, request, url }) => {
  const auth = await parent();
  if (auth.status === 'unauthenticated') {
    redirect(303, '/login');
  }

  if (auth.status !== 'ready') {
    return {
      identities: [],
      identityLoadError: '无法确认当前登录状态，请稍后重试。',
      providers: [],
      providerLoadError: null
    };
  }

  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const identitiesPromise = loadCollection(
    apiFetch,
    '/api/v1/users/me/federated-identities',
    '已绑定企业身份',
    isFederatedIdentity
  );
  const organizationsPromise = loadCollection(
    apiFetch,
    '/api/v1/users/me/organizations',
    '企业登录配置',
    isUserOrganization
  );
  const [identities, organizations] = await Promise.all([
    identitiesPromise,
    organizationsPromise
  ]);

  return {
    identities: identities.data,
    identityLoadError: identities.error,
    providers: organizations.data.flatMap((organization) => organization.identity_providers),
    providerLoadError: organizations.error
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
        serverApiUrl(
          env.ZEUS_API_URL,
          `/api/v1/users/me/federated-identities/${encodeURIComponent(providerId)}/link-intents`
        ),
        {
          method: 'POST',
          headers: { accept: 'application/json' }
        }
      );
    } catch {
      return actionError(503, '无法连接企业身份绑定 API，请稍后重试。');
    }

    forwardZeusAuthCookies(response, event.cookies);
    if (response.status === 401) {
      redirect(303, '/login');
    }
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

  unlink: async (event) => {
    const identityId = formValue(await event.request.formData(), 'identity_id');
    if (!identityId) return actionError(400, '缺少要解绑的企业身份。');

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
          `/api/v1/users/me/federated-identities/${encodeURIComponent(identityId)}`
        ),
        {
          method: 'DELETE',
          headers: { accept: 'application/json' }
        }
      );
    } catch {
      return actionError(503, '无法连接企业身份解绑 API，请稍后重试。');
    }

    forwardZeusAuthCookies(response, event.cookies);
    if (response.status === 401) {
      redirect(303, '/login');
    }
    if (!response.ok) {
      return actionError(responseStatus(response.status), unlinkErrorMessage(response.status));
    }

    return { type: 'success' as const, message: '企业身份已解绑。' };
  }
};
