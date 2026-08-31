import { fail } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions } from './$types';

import {
  authApiFetcher,
  formValue,
  forwardZeusAuthCookies,
  GENERIC_IDENTITY_MESSAGE,
  postAuth
} from '$lib/server/auth';

function actionError(status: number, message: string, email: string) {
  return fail(status, { type: 'error' as const, message, values: { email } });
}

export const actions: Actions = {
  default: async (event) => {
    const formData = await event.request.formData();
    const email = formValue(formData, 'email').toLowerCase();
    if (!email) return actionError(400, 'Email 不能为空。', email);

    let response: Response;
    try {
      response = await postAuth(
        authApiFetcher(event),
        env.ZEUS_API_URL,
        '/api/v1/auth/password-resets',
        { email }
      );
    } catch {
      return actionError(503, '无法提交请求，请稍后重试。', email);
    }

    forwardZeusAuthCookies(response, event.cookies);
    if (response.status >= 500) {
      return actionError(503, '找回密码服务暂时不可用，请稍后重试。', email);
    }
    return { type: 'success' as const, message: GENERIC_IDENTITY_MESSAGE, values: { email } };
  }
};
