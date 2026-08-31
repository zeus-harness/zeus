import { fail, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import {
  authApiFetcher,
  formValue,
  forwardZeusAuthCookies,
  GENERIC_IDENTITY_MESSAGE,
  postAuth,
  responseOk,
  urlToken
} from '$lib/server/auth';

function actionError(status: number, message: string, email = '') {
  return fail(status, { type: 'error' as const, message, values: { email } });
}

export const load: PageServerLoad = ({ url }) => ({
  tokenPresent: Boolean(urlToken(url))
});

export const actions: Actions = {
  confirm: async (event) => {
    const token = urlToken(event.url);
    if (!token) return actionError(400, '验证链接缺少 token，请从邮件中的完整链接打开。');

    let response: Response;
    try {
      response = await postAuth(
        authApiFetcher(event),
        env.ZEUS_API_URL,
        '/api/v1/auth/email-verifications/confirm',
        { token }
      );
    } catch {
      return actionError(503, '无法提交邮箱验证请求，请稍后重试。');
    }

    forwardZeusAuthCookies(response, event.cookies);
    if (!responseOk(response)) {
      return actionError(
        response.status >= 500 ? 503 : 400,
        response.status >= 500
          ? '邮箱验证服务暂时不可用，请稍后重试。'
          : '验证链接无效或已过期，请重新申请验证邮件。'
      );
    }
    redirect(303, '/login?verified=1');
  },

  resend: async (event) => {
    const formData = await event.request.formData();
    const email = formValue(formData, 'email').toLowerCase();
    if (!email) return actionError(400, 'Email 不能为空。', email);

    let response: Response;
    try {
      response = await postAuth(
        authApiFetcher(event),
        env.ZEUS_API_URL,
        '/api/v1/auth/email-verifications',
        { email }
      );
    } catch {
      return actionError(503, '无法提交请求，请稍后重试。', email);
    }

    forwardZeusAuthCookies(response, event.cookies);
    if (response.status >= 500) {
      return actionError(503, '验证邮件服务暂时不可用，请稍后重试。', email);
    }
    return { type: 'success' as const, message: GENERIC_IDENTITY_MESSAGE, values: { email } };
  }
};
