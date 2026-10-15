import { env } from '$env/dynamic/private';
import { error, fail, redirect } from '@sveltejs/kit';
import { randomUUID } from 'node:crypto';
import { requestJson, jsonRequest, ZeusApiError } from '$lib/api/client';
import { serverApiFetcher, serverApiUrl, loadCurrentPrincipal } from '$lib/api/server';
import type { components } from '$lib/api/generated/schema';
import type { PageServerLoad, Actions } from './$types';
type Schema = components['schemas'];
export const load: PageServerLoad = async ({ parent, fetch, request, url, params }) => {
  const auth = await parent();
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const base = serverApiUrl(env.ZEUS_API_URL, `/api/v1/organizations/${params.organizationId}/im`);
  const selected = url.searchParams.get('conversation') ?? '';
  const query = url.searchParams.get('q') ?? '';
  const cursor = url.searchParams.get('cursor') ?? '';
  try {
    const workspaceId = auth.principal?.workspace_id ?? null;
    const canOperate = ['owner', 'builder', 'operator'].includes(auth.principal?.workspace_role ?? '');
    const [conversations, people, detail, messages, workflows] = await Promise.all([
      requestJson<Schema['ImConversations']>(apiFetch, `${base}/conversations?limit=50&cursor=${encodeURIComponent(url.searchParams.get('list_cursor') ?? '')}`.replace(/&cursor=$/, '')),
      requestJson<Schema['ImPeople']>(apiFetch, `${base}/people?q=${encodeURIComponent(query)}${url.searchParams.get('people_cursor') ? `&cursor=${encodeURIComponent(url.searchParams.get('people_cursor')!)}` : ''}`),
      selected ? requestJson<Schema['ImDetail']>(apiFetch, `${base}/conversations/${encodeURIComponent(selected)}`) : null,
      selected ? requestJson<Schema['ImMessages']>(apiFetch, `${base}/conversations/${encodeURIComponent(selected)}/messages?limit=50${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`) : null,
      workspaceId && canOperate ? requestJson<Schema['WorkflowPageResponse']>(apiFetch, serverApiUrl(env.ZEUS_API_URL, `/api/v1/workspaces/${workspaceId}/workflows?limit=100`)) : null
    ]);
    return { workspaceId, canOperate, workflows: workflows?.items.filter(item => item.active_version_id && !item.archived_at) ?? [], conversations, people, detail, messages, selected, query, cursor, userId: auth.principal!.user_id, organizationId: params.organizationId, requestId: randomUUID() };
  } catch (cause) { error(cause instanceof ZeusApiError ? cause.status : 502, '会话不可访问或同步服务暂不可用。'); }
};
export const actions: Actions = {
  mutate: async (event) => {
    const apiFetch = serverApiFetcher(event.fetch, event.request.headers.get('cookie'), event.url.origin);
    const auth = await loadCurrentPrincipal(apiFetch, env.ZEUS_API_URL);
    if (auth.status !== 'ready' || auth.principal?.organization_id !== event.params.organizationId || auth.principal.tenant_access_grant_id) return fail(403, { message: '组织上下文已改变，请刷新页面。' });
    const form = await event.request.formData();
    const op = String(form.get('operation') ?? '');
    const id = String(form.get('conversation') ?? '');
    const base = serverApiUrl(env.ZEUS_API_URL, `/api/v1/organizations/${event.params.organizationId}/im`);
    let destination: string | null = null;
    try {
      if (op === 'create') {
        const result = await requestJson<Schema['ImId']>(apiFetch, `${base}/conversations`, jsonRequest('POST', { kind: form.get('kind'), title: form.get('kind') === 'direct' ? '私聊' : form.get('title'), participants: form.getAll('participants'), request_id: form.get('request_id') }));
        destination = result.id;
      } else if (op === 'send') {
        await requestJson(apiFetch, `${base}/conversations/${encodeURIComponent(id)}/messages`, jsonRequest('POST', { content: form.get('content'), request_id: form.get('request_id'), reply_to: form.get('reply_to') || null, mentions: form.getAll('mentions').filter(Boolean) }));
      } else if (op === 'add_agent' || op === 'invoke_agent') {
        const workspace = auth.principal.workspace_id;
        if (!workspace) return fail(403, { message: '请先选择有执行权限的 Workspace。聊天成员身份不会授予执行权限。' });
        const endpoint = serverApiUrl(env.ZEUS_API_URL, `/api/v1/workspaces/${workspace}/im/conversations/${encodeURIComponent(id)}`);
        if (op === 'add_agent') {
          await requestJson(apiFetch, `${endpoint}/agents`, jsonRequest('POST', { workflow_version_id: form.get('workflow_version_id') }));
        } else {
          if (form.get('share_result') !== 'yes') return fail(400, { message: '请确认将所选消息交给 Agent，并将回复分享到当前会话。' });
          await requestJson(apiFetch, `${endpoint}/agent-calls`, jsonRequest('POST', { agent_member_id: form.get('agent_member_id'), source_message_id: form.get('source_message_id'), create_work_item: form.get('create_work_item') === 'yes' }, { 'Idempotency-Key': `im:${form.get('agent_member_id')}:${form.get('source_message_id')}` }));
        }
        destination = id;
      } else if (op === 'remove_agent') {
        await requestJson(apiFetch, `${base}/conversations/${encodeURIComponent(id)}/agents/${encodeURIComponent(String(form.get('agent_member_id') ?? ''))}`, jsonRequest('DELETE', {}));
        destination = id;
      } else if (['rename', 'add', 'leave', 'read'].includes(op)) {
        await requestJson(apiFetch, `${base}/conversations/${encodeURIComponent(id)}`, jsonRequest('PATCH', { operation: op, value: form.get('value') || null, target: form.get('target') || null }));
        if (op === 'leave') destination = '';
      } else return fail(400, { message: '操作无效。' });
    } catch (cause) { return fail(cause instanceof ZeusApiError ? cause.status : 502, { message: '操作未完成。请检查成员、输入和权限后重试；未发送的消息会保留。' }); }
    if (destination !== null) redirect(303, `${event.url.pathname}${destination ? `?conversation=${destination}` : ''}`);
    return { ok: true };
  }
};
