import { fail, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import {
  authApiFetcher,
  formValue,
  forwardZeusAuthCookies,
  postAuth,
  responseOk,
  safeReturnTo
} from '$lib/server/auth';

function actionError(status: number, message: string) {
  return fail(status, { type: 'error' as const, message });
}

export const actions: Actions = {
  default: async (event) => {
    const returnTo = safeReturnTo(event.url);
    const formData = await event.request.formData();
    const code = formValue(formData, 'code');
    if (!code) return actionError(400, '验证码不能为空。');

    let response: Response;
    try {
      response = await postAuth(authApiFetcher(event), env.ZEUS_API_URL, '/api/v1/auth/mfa/verify', {
        code
      });
    } catch {
      return actionError(503, '无法提交 MFA 验证请求，请稍后重试。');
    }

    forwardZeusAuthCookies(response, event.cookies);
    if (!responseOk(response)) {
      return actionError(
        response.status >= 500 ? 503 : response.status === 401 ? 401 : 400,
        response.status >= 500
          ? 'MFA 服务暂时不可用，请稍后重试。'
          : response.status === 401
            ? '验证码无效或登录已过期，请检查后重试。'
            : '验证码无效，请检查后重试。'
      );
    }
    redirect(303, returnTo);
  }
};

export const load: PageServerLoad = ({ url }) => ({
  return_to: safeReturnTo(url)
});
