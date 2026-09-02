import { error, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { RequestHandler } from './$types';

import { revokePlatformTenantAccessGrantResponse } from '$lib/api/platform';
import { forwardZeusAuthCookies, serverApiFetcher } from '$lib/api/server';

export const POST: RequestHandler = async ({ cookies, fetch, request, url }) => {
  const formData = await request.formData();
  const grantId = String(formData.get('grant_id') ?? '').trim();
  if (!grantId) error(400, 'Grant ID 不能为空。');
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  let response: Response;
  try {
    response = await revokePlatformTenantAccessGrantResponse(apiFetch, grantId, env.ZEUS_API_URL);
  } catch {
    error(502, '租户访问服务暂时不可用。');
  }
  if (!response.ok) error(response.status, '租户访问退出失败。');
  forwardZeusAuthCookies(response, cookies);
  redirect(303, '/platform/organizations');
};
