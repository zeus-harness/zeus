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
  responseOk
} from '$lib/server/auth';

function actionError(status: number, message: string, email: string) {
  return fail(status, { type: 'error' as const, message, values: { email } });
}

function loginError(status: number): string {
  if (status === 429) return '登录尝试次数过多，请稍后再试。';
  if (status >= 500) return '登录服务暂时不可用，请稍后重试。';
  return '邮箱或密码不正确。';
}

export const actions: Actions = {
  default: async (event) => {
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

    if (isMfaRequired(payload)) {
      redirect(303, '/mfa');
    }
    redirect(303, '/');
  }
};
