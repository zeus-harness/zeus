import { fail, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions } from './$types';

import {
  authApiFetcher,
  formValue,
  forwardZeusAuthCookies,
  isMfaRequired,
  postAuth,
  responseJson,
  responseOk,
  safeReturnTo,
  withReturnTo
} from '$lib/server/auth';

function actionError(status: number, message: string, email: string) {
  return fail(status, { type: 'error' as const, message, values: { email } });
}

function loginError(status: number): string {
  if (status === 429) return '登录尝试次数过多，请稍后再试。';
  if (status >= 500) return '登录服务暂时不可用，请稍后重试。';
  return '邮箱或密码不正确。';
}

const SLUG_PATTERN = /^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])$/;

type FederatedLoginValues = {
  organization_slug: string;
  provider_slug: string;
};

function isStrictSlug(value: string): boolean {
  return SLUG_PATTERN.test(value);
}

function federatedActionError(status: number, message: string, values: FederatedLoginValues) {
  return fail(status, { type: 'error' as const, message, values });
}

function isTotpSetupRequired(payload: unknown): boolean {
  return (
    typeof payload === 'object' &&
    payload !== null &&
    !Array.isArray(payload) &&
    (payload as Record<string, unknown>).totp_setup_required === true
  );
}

export const actions: Actions = {
  default: async (event) => {
    const returnTo = safeReturnTo(event.url);
    const formData = await event.request.formData();
    const email = formValue(formData, 'email').toLowerCase();
    const password = formValue(formData, 'password', false);

    if (!email) return actionError(400, 'Email 不能为空。', email);
    if (!password) return actionError(400, 'Password 不能为空。', email);

    let response: Response;
    try {
      response = await postAuth(authApiFetcher(event), env.ZEUS_API_URL, '/api/v1/auth/login', {
        email,
        password
      });
    } catch {
      return actionError(503, '无法连接登录 API，请稍后重试。', email);
    }

    const payload = await responseJson(response);
    forwardZeusAuthCookies(response, event.cookies);
    if (!responseOk(response)) {
      const status = response.status >= 400 && response.status <= 599 ? response.status : 502;
      return actionError(status, loginError(response.status), email);
    }

    if (isTotpSetupRequired(payload)) {
      redirect(303, withReturnTo('/account/security?setup_totp=1', returnTo));
    }
    if (isMfaRequired(payload)) {
      redirect(303, withReturnTo('/mfa', returnTo));
    }
    redirect(303, returnTo);
  },

  federated: async (event) => {
    const returnTo = safeReturnTo(event.url);
    const formData = await event.request.formData();
    const values: FederatedLoginValues = {
      organization_slug: formValue(formData, 'organization_slug'),
      provider_slug: formValue(formData, 'provider_slug')
    };

    if (!values.organization_slug) {
      return federatedActionError(400, 'Organization slug 不能为空。', values);
    }
    if (!values.provider_slug) {
      return federatedActionError(400, 'Provider slug 不能为空。', values);
    }
    if (!isStrictSlug(values.organization_slug) || !isStrictSlug(values.provider_slug)) {
      return federatedActionError(400, 'Organization slug 或 Provider slug 格式无效。', values);
    }

    const loginUrl = new URL(
      `/auth/federated/${encodeURIComponent(values.organization_slug)}/${encodeURIComponent(values.provider_slug)}`,
      event.url.origin
    );
    loginUrl.searchParams.set('return_to', returnTo);
    redirect(303, `${loginUrl.pathname}${loginUrl.search}`);
  }
};
