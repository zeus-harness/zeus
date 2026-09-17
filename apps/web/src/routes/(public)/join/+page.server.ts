import { fail, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';
import { authApiFetcher, forwardZeusAuthCookies, postAuth, urlToken, withReturnTo } from '$lib/server/auth';

export const load: PageServerLoad = async ({ parent, url }) => {
  const auth = await parent();
  const token = urlToken(url);
  return {
    tokenPresent: Boolean(token),
    signedIn: auth.status === 'ready' && Boolean(auth.principal?.user_id),
    loginHref: withReturnTo('/login', `${url.pathname}${url.search}`),
    registerHref: token ? `/register?invitation_token=${encodeURIComponent(token)}` : '/register'
  };
};

export const actions: Actions = {
  default: async (event) => {
    const token = urlToken(event.url);
    if (!token) return fail(400, { message: '邀请链接不完整，请从邀请邮件重新打开。' });
    let response: Response;
    try {
      response = await postAuth(authApiFetcher(event), env.ZEUS_API_URL,
        `/api/v1/invitations/${encodeURIComponent(token)}/accept`, {});
    } catch {
      return fail(503, { message: '暂时无法处理邀请，请稍后重试。' });
    }
    forwardZeusAuthCookies(response, event.cookies);
    if (!response.ok) return fail(response.status >= 500 ? 503 : 400, {
      message: '无法加入组织。请使用受邀邮箱对应的已验证账号登录，并确认邀请尚未过期或使用。'
    });
    redirect(303, '/');
  }
};
