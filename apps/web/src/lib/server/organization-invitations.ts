import { fail, redirect, type RequestEvent } from '@sveltejs/kit';
import { requestJson, jsonRequest, ZeusApiError } from '$lib/api/client';
import { loadCurrentPrincipal, serverApiFetcher, serverApiUrl } from '$lib/api/server';

export async function manageInvitation(event: RequestEvent, apiBaseUrl?: string) {
  const apiFetch = serverApiFetcher(event.fetch, event.request.headers.get('cookie'), event.url.origin);
  const auth = await loadCurrentPrincipal(apiFetch, apiBaseUrl);
  if (auth.status === 'unauthenticated') redirect(303, '/login');
  if (event.params.resource !== 'members' || auth.status !== 'ready' || !auth.principal ||
      auth.principal?.organization_id !== event.params.organizationId ||
      auth.principal.organization_role !== 'owner' || auth.principal.tenant_access_grant_id) {
    return fail(403, { type: 'error' as const, message: '只有当前组织的 Owner 可以管理邀请。' });
  }
  const form = await event.request.formData();
  const operation = String(form.get('operation') ?? '');
  const base = serverApiUrl(apiBaseUrl, `/api/v1/organizations/${event.params.organizationId}/invitations`);
  try {
    if (operation === 'create') {
      const email = String(form.get('email') ?? '').trim();
      const role = String(form.get('organization_role') ?? 'member');
      if (!email || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !['member', 'auditor', 'owner'].includes(role)) {
        return fail(400, { type: 'error' as const, message: '请填写有效邮箱并选择组织角色。' });
      }
      await requestJson(apiFetch, base, jsonRequest('POST', { email, organization_role: role, workspaces: [] }));
    } else if (operation === 'resend' || operation === 'revoke') {
      const id = String(form.get('invitation_id') ?? '');
      if (!/^[0-9a-f]{8}-[0-9a-f-]{27}$/i.test(id)) return fail(400, { type: 'error' as const, message: '邀请标识无效。' });
      await requestJson(apiFetch, `${base}/${id}${operation === 'resend' ? '/resend' : ''}`, { method: operation === 'resend' ? 'POST' : 'DELETE' });
    } else return fail(400, { type: 'error' as const, message: '邀请操作无效。' });
  } catch (cause) {
    const status = cause instanceof ZeusApiError ? cause.status : 502;
    return fail(status, { type: 'error' as const, message: status === 409 ? '该邮箱已有待处理邀请，请刷新后重发。' : status === 404 ? '邀请已处理或不存在，请刷新页面。' : status === 403 ? '当前账号无权管理此组织的邀请。' : '邀请操作未完成，请稍后重试。' });
  }
  return { type: 'success' as const, message: operation === 'revoke' ? '邀请已撤销，原链接已失效。' : '邀请邮件已加入发送队列，请查看邀请状态。' };
}
