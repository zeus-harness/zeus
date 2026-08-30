import { fail } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import {
  authApiFetcher,
  formValue,
  forwardZeusAuthCookies,
  GENERIC_IDENTITY_MESSAGE,
  postAuth,
  urlToken
} from '$lib/server/auth';

type RegistrationValues = {
  email: string;
  display_name: string;
};

function actionError(status: number, message: string, values: RegistrationValues) {
  return fail(status, { type: 'error' as const, message, values });
}

export const load: PageServerLoad = ({ url }) => ({
  invitationPresent: Boolean(
    urlToken(url, 'invitation_token') ?? urlToken(url, 'invite_token') ?? urlToken(url, 'token')
  )
});

export const actions: Actions = {
  default: async (event) => {
    const formData = await event.request.formData();
    const values: RegistrationValues = {
      email: formValue(formData, 'email').toLowerCase(),
      display_name: formValue(formData, 'display_name')
    };
    const password = formValue(formData, 'password', false);
    const invitationToken =
      urlToken(event.url, 'invitation_token') ??
      urlToken(event.url, 'invite_token') ??
      urlToken(event.url, 'token');

    if (!values.email) return actionError(400, 'Email 不能为空。', values);
    if (!values.display_name) return actionError(400, 'Display name 不能为空。', values);
    if (Array.from(password.normalize('NFC')).length < 15) {
      return actionError(400, 'Password 至少需要 15 个字符。', values);
    }

    const payload: Record<string, string> = {
      email: values.email,
      display_name: values.display_name,
      password
    };
    if (invitationToken) payload.invitation_token = invitationToken;

    let response: Response;
    try {
      response = await postAuth(
        authApiFetcher(event),
        env.ZEUS_API_URL,
        '/api/v1/auth/register',
        payload
      );
    } catch {
      return actionError(503, '无法提交注册请求，请稍后重试。', values);
    }

    forwardZeusAuthCookies(response, event.cookies);
    if (response.status >= 500) {
      return actionError(503, '注册服务暂时不可用，请稍后重试。', values);
    }

    return { type: 'success' as const, message: GENERIC_IDENTITY_MESSAGE, values };
  }
};
