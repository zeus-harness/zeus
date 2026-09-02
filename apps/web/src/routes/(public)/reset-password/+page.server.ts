import { fail, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import {
  authApiFetcher,
  formValue,
  forwardZeusAuthCookies,
  postAuth,
  responseOk,
  urlToken
} from '$lib/server/auth';

function actionError(status: number, message: string) {
  return fail(status, { type: 'error' as const, message });
}

export const load: PageServerLoad = ({ url }) => ({
  tokenPresent: Boolean(urlToken(url))
});

export const actions: Actions = {
  default: async (event) => {
    const token = urlToken(event.url);
    if (!token) return actionError(400, '重置链接缺少 token，请从邮件中的完整链接打开。');

    const formData = await event.request.formData();
    const password = formValue(formData, 'password', false);
    const passwordConfirmation = formValue(formData, 'password_confirmation', false);
    if (Array.from(password.normalize('NFC')).length < 15) {
      return actionError(400, 'Password 至少需要 15 个字符。');
    }
    if (password !== passwordConfirmation) {
      return actionError(400, '两次输入的 Password 不一致。');
    }

    let response: Response;
    try {
      response = await postAuth(
        authApiFetcher(event),
        env.ZEUS_API_URL,
        '/api/v1/auth/password-resets/confirm',
        { token, password }
      );
    } catch {
      return actionError(503, '无法提交密码重置请求，请稍后重试。');
    }

    forwardZeusAuthCookies(response, event.cookies);
    if (!responseOk(response)) {
      return actionError(
        response.status >= 500 ? 503 : 400,
        response.status >= 500
          ? '密码重置服务暂时不可用，请稍后重试。'
          : '重置链接无效或已过期，或密码不符合要求。'
      );
    }
    redirect(303, '/login?reset=1');
  }
};
