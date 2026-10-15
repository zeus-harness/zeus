<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { enhance } from '$app/forms';
  import { invalidateAll, beforeNavigate, afterNavigate } from '$app/navigation';
  import { Button } from '@zeus/ui/components/ui/button';
  import { Input } from '@zeus/ui/components/ui/input';
  import { Textarea } from '@zeus/ui/components/ui/textarea';
  import { displayTimestamp } from '$lib/display-timestamp';
  import ConversationAgents from '$lib/features/im/ConversationAgents.svelte';
  import type { PageProps } from './$types';
  let { data, form }: PageProps = $props();
  let content = $state('');
  let conversationKind = $state('direct');
  let selectedPeople = $state<string[]>([]);
  let canCreate = $derived(conversationKind === 'direct' ? selectedPeople.length === 1 : selectedPeople.length >= 1 && selectedPeople.length < 50);
  let requestId = $state(untrack(() => data.requestId));
  let pending = $state(false);
  let reply = $state('');
  let mention = $state('');
  let agentSource = $state('');
  let selectedAgentMessage = $derived(data.messages?.items.find(message => message.id === agentSource));
  let callableAgents = $derived(data.detail?.agents.filter(agent => agent.workspace_id === data.workspaceId && selectedAgentMessage && selectedAgentMessage.sequence >= agent.joined_sequence) ?? []);
  const callLabels: Record<string, string> = { queued: '排队中', running: '正在处理', waiting_approval: '等待审批', waiting_input: '等待补充信息', succeeded: '已完成', failed: '失败', canceled: '已取消' };
  let syncing = $state(false);
  let offline = $state(false);
  let acknowledged = '';
  let previousConversation = untrack(() => data.selected);
  afterNavigate(() => { if (previousConversation !== data.selected) { content = ''; reply = ''; mention = ''; agentSource = ''; requestId = crypto.randomUUID(); previousConversation = data.selected; } });
  let base = $derived(`/organizations/${data.organizationId}/im`);
  let owner = $derived(data.detail?.members.some(member => member.id === data.userId && member.role === 'owner'));
  beforeNavigate(({ cancel }) => { if (content.trim() && !pending && !window.confirm('当前消息尚未发送，离开会丢失草稿。仍要离开吗？')) cancel(); });
  async function synchronize() {
    if (document.hidden || syncing || pending) return;
    syncing = true;
    try {
      await invalidateAll();
      const last = data.messages?.items.at(-1);
      const key = `${data.selected}:${last?.sequence}`;
      if (!document.hidden && last && !data.cursor && acknowledged !== key) {
        const body = new FormData();
        body.set('operation', 'read'); body.set('conversation', data.selected); body.set('value', String(last.sequence));
        const response = await fetch(`${base}?/mutate`, { method: 'POST', body, headers: { 'x-sveltekit-action': 'true' } });
        if (response.ok) acknowledged = key;
      }
      offline = false;
    } catch { offline = true; } finally { syncing = false; }
  }
  onMount(() => {
    void synchronize();
    const timer = setInterval(() => { void synchronize(); }, 3000);
    const visible = () => { if (!document.hidden) void synchronize(); };
    document.addEventListener('visibilitychange', visible);
    return () => { clearInterval(timer); document.removeEventListener('visibilitychange', visible); };
  });
  const send: import('@sveltejs/kit').SubmitFunction = () => {
    pending = true;
    return async ({ result, update }) => {
      if (result.type === 'success') { content = ''; reply = ''; mention = ''; requestId = crypto.randomUUID(); }
      pending = false;
      await update({ reset: false });
    };
  };
</script>
<svelte:head><title>团队消息 · Zeus</title></svelte:head>
<main class="p-4 lg:p-6">
  <header class="mb-5 flex flex-wrap items-center justify-between gap-3">
    <div><h1 class="text-2xl font-semibold">团队消息</h1><p class="mt-1 text-sm text-muted-foreground">{data.activeOrganization.organization_name} · 组织内沟通</p></div>
    <span role="status" class="text-xs text-muted-foreground">{offline ? '同步中断，正在重试' : '消息已保存 · 自动同步'}</span>
  </header>
  {#if form && 'message' in form}<p role="alert" class="mb-4 text-sm text-destructive">{form.message}</p>{/if}
  <div class="grid gap-4 lg:grid-cols-[15rem_minmax(0,1fr)]">
    <aside class="rounded-xl border p-4">
      <h2 class="font-medium">会话</h2>
      <nav class="my-4 space-y-2" aria-label="IM 会话列表">
        {#each data.conversations.items as conversation (conversation.id)}
          <a href="{base}?conversation={conversation.id}" class="block rounded-lg p-2 text-sm hover:bg-muted" class:bg-muted={conversation.id === data.selected} aria-current={conversation.id === data.selected ? 'page' : undefined}>
            <span class="block break-words">{conversation.title}</span><span class="text-xs text-muted-foreground">{conversation.kind === 'group' ? '群聊' : '私聊'}{conversation.unread ? ` · ${conversation.unread} 条未读` : ''}</span>
          </a>
        {:else}<p class="text-sm text-muted-foreground">还没有会话，从组织通讯录开始。</p>{/each}
      </nav>
      {#if data.conversations.next_cursor}<a class="text-sm underline" href="{base}?list_cursor={encodeURIComponent(data.conversations.next_cursor)}">更多会话</a>{/if}
      <details class="mt-4"><summary class="cursor-pointer text-sm">新建私聊或群聊</summary>
        <form method="GET" class="my-3 flex gap-2"><Input name="q" aria-label="查找组织成员" placeholder="成员姓名前缀" value={data.query} /><Button type="submit" variant="outline" size="sm">查找</Button></form>
        <form method="POST" action="?/mutate" class="space-y-3">
          <input type="hidden" name="operation" value="create" /><input type="hidden" name="request_id" value={data.requestId} />
          <label class="block text-sm">类型<select name="kind" bind:value={conversationKind} class="mt-1 w-full rounded border p-2"><option value="direct">私聊（选择一人）</option><option value="group">群聊</option></select></label>
          {#if conversationKind === 'group'}<label class="block text-sm">群聊名称<Input name="title" required maxlength={160} placeholder="例如：项目讨论" /></label>{/if}
          <fieldset class="max-h-56 space-y-2 overflow-auto"><legend class="mb-2 text-sm">组织成员</legend>
            {#each data.people.items.filter(person => person.id !== data.userId) as person (person.id)}<label class="flex items-center gap-2 text-sm"><input type="checkbox" name="participants" bind:group={selectedPeople} value={person.id} />{person.display_name}</label>{:else}<p class="text-sm text-muted-foreground">{data.query ? '没有找到匹配的成员，请换个姓名搜索。' : '还没有可以聊天的其他成员。'}</p>{/each}
          </fieldset>
          <p class="text-xs text-muted-foreground">仅限本组织，最多 50 人。跨组织邀请暂未开放。</p>
          {#if !data.people.items.some(person => person.id !== data.userId)}
            {#if data.activeOrganization.organization_role === 'owner'}<a class="block text-sm underline" href={`/organizations/${data.organizationId}/settings/members`}>邀请同事加入组织</a>{:else}<p class="text-sm">请联系组织管理员邀请同事加入。</p>{/if}
          {/if}
          <Button type="submit" disabled={!canCreate}>{conversationKind === 'direct' ? '开始私聊' : '创建群聊'}</Button>
        </form>
        {#if data.people.next_cursor}<a class="mt-2 block text-sm underline" href="{base}?q={encodeURIComponent(data.query)}&people_cursor={encodeURIComponent(data.people.next_cursor)}">下一页成员</a>{/if}
      </details>
    </aside>
    <section class="min-w-0 rounded-xl border" aria-label="聊天区">
      {#if data.detail}
        <header class="border-b p-4"><h2 class="font-semibold">{data.detail.conversation.title}</h2><p class="text-xs text-muted-foreground">组织内{data.detail.conversation.kind === 'group' ? '群聊' : '私聊'} · {data.detail.members.length} 人 · {data.detail.agents.length} 个 Agent</p></header>
        <div class="max-h-[60vh] min-h-64 space-y-4 overflow-y-auto p-4" aria-live="polite" aria-label="聊天消息">
          {#if data.messages?.next_cursor}<a class="block text-sm underline" href="{base}?conversation={data.selected}&cursor={encodeURIComponent(data.messages.next_cursor)}">更早的消息</a>{/if}
          {#if data.cursor}<a class="block text-sm underline" href="{base}?conversation={data.selected}">返回最新消息</a>{/if}
          {#each data.messages?.items ?? [] as message (message.id)}
            <article class="rounded-lg bg-muted/60 p-3" class:ml-8={message.sender_id === data.userId}>
              <p class="text-xs text-muted-foreground">{message.sender_name}{message.sender_agent_id ? ' · Agent' : ''} · {message.organization_name} · {displayTimestamp(message.created_at)}</p>
              {#if message.reply_to}<p class="mt-1 border-l-2 pl-2 text-xs text-muted-foreground">回复：{data.messages?.items.find(item => item.id === message.reply_to)?.content.slice(0, 100) ?? '较早的消息'}</p>{/if}
              {#if message.mentions.length}<p class="mt-1 text-xs">{message.mentions.map(id => `@${data.detail?.members.find(member => member.id === id)?.display_name ?? '成员'}`).join(' ')}</p>{/if}
              <p class="mt-2 whitespace-pre-wrap break-words text-sm">{message.content}</p>
              <button class="mt-2 text-xs underline" onclick={() => { reply = message.id; }}>回复</button>
              {#if message.sender_id && data.canOperate && data.detail.agents.some(agent => agent.workspace_id === data.workspaceId && message.sequence >= agent.joined_sequence)}<button class="ml-3 mt-2 text-xs underline" onclick={() => { agentSource = message.id; }}>交给 Agent</button>{/if}
            </article>
          {:else}<p class="py-12 text-center text-sm text-muted-foreground">发送第一条消息，开始沟通。</p>{/each}
        </div>
        {#if data.detail.calls.length}
          <details class="border-t p-4"><summary class="cursor-pointer text-sm">Agent 调用与审批（最近 {data.detail.calls.length} 次）</summary>
            <ul class="mt-3 space-y-2 text-sm">{#each data.detail.calls as call (call.run_id)}<li>
              {data.detail.agents.find(agent => agent.id === call.agent_member_id)?.display_name ?? '已移出的 Agent'} · {callLabels[call.status] ?? call.status}
              <a class="ml-2 underline" href={`/${call.workspace_id}/runs/${call.run_id}`}>{call.status === 'waiting_approval' ? '查看并处理审批' : '运行详情'}</a>
              {#if call.work_item_id}<a class="ml-2 underline" href={`/${call.workspace_id}/work-items/${call.work_item_id}`}>跟踪工作项与验收</a>{/if}
            </li>{/each}</ul>
            <p class="mt-2 text-xs text-muted-foreground">审批仍由有权限的本人完成；@ 或聊天中的“同意”不会授予权限。</p>
          </details>
        {/if}
        {#if selectedAgentMessage}
          <form method="POST" action="?/mutate" class="space-y-3 border-t bg-muted/30 p-4">
            <input type="hidden" name="operation" value="invoke_agent" /><input type="hidden" name="conversation" value={data.selected} /><input type="hidden" name="source_message_id" value={selectedAgentMessage.id} />
            <p class="text-sm font-medium">将所选消息交给 Agent</p>
            <blockquote class="max-h-32 overflow-auto border-l-2 pl-3 text-sm whitespace-pre-wrap">{selectedAgentMessage.content}</blockquote>
            <label class="block text-sm">选择 Agent <select name="agent_member_id" required class="ml-2 rounded border bg-background p-2">{#each callableAgents as agent (agent.id)}<option value={agent.id}>{agent.display_name}</option>{/each}</select></label>
            <label class="flex items-start gap-2 text-sm"><input type="checkbox" name="share_result" value="yes" required />以我的 Workspace 权限执行，并将回复分享给有权查看原消息的会话成员。</label>
            <label class="flex items-start gap-2 text-sm"><input type="checkbox" name="create_work_item" value="yes" checked />创建持久工作项，跟踪重试、人工验收和归档。</label>
            <p class="text-xs text-muted-foreground">工作项目标来自上方原消息；Agent 创建其他资源仍使用草稿。同一消息重复调用同一个 Agent 不会重复执行。</p>
            <div class="flex gap-2"><Button type="submit" disabled={!callableAgents.length}>调用 Agent</Button><Button type="button" variant="outline" onclick={() => { agentSource = ''; }}>取消</Button></div>
          </form>
        {/if}
        <form method="POST" action="?/mutate" use:enhance={send} class="space-y-3 border-t p-4">
          <input type="hidden" name="operation" value="send" /><input type="hidden" name="conversation" value={data.selected} /><input type="hidden" name="request_id" value={requestId} /><input type="hidden" name="reply_to" value={reply} />
          {#if reply}<p class="text-xs">正在回复消息 <button type="button" class="underline" onclick={() => { reply = ''; }}>取消回复</button></p>{/if}
          <label class="block text-sm">提及成员<select name="mentions" bind:value={mention} class="ml-2 rounded border p-1"><option value="">不提及</option>{#each data.detail.members.filter(member => member.id !== data.userId) as member (member.id)}<option value={member.id}>@{member.display_name}</option>{/each}</select></label>
          <Textarea name="content" aria-label="消息内容" bind:value={content} required maxlength={10000} rows={3} placeholder="发送消息…" disabled={pending} />
          <div class="flex items-center justify-between gap-2"><span class="text-xs text-muted-foreground">{pending ? '发送中…' : '失败可直接重试，不会重复发送'}</span><Button type="submit" disabled={pending || !content.trim()}>发送</Button></div>
        </form>
      {:else}<div class="p-10"><h2 class="font-medium">选择一个会话</h2><p class="mt-2 text-sm text-muted-foreground">从左侧选择会话，或新建会话与同事讨论。聊天只对会话成员可见。</p></div>{/if}
    </section>
    {#if data.detail}<details class="rounded-xl border p-4 lg:col-start-2"><summary class="cursor-pointer text-sm font-medium">会话设置与成员</summary><div class="mt-4">
      <h2 class="font-medium">会话成员与范围</h2>
      {#if data.detail}
        <ul class="my-4 space-y-2 text-sm">{#each data.detail.members as member (member.id)}<li>{member.display_name}{member.role === 'owner' ? ' · 会话负责人' : ''}</li>{/each}</ul>
        <p class="text-xs text-muted-foreground">{data.activeOrganization.organization_name} · 新加入的成员仅能看到加入后的消息。</p>
        {#if data.detail.conversation.kind === 'group'}
          <ConversationAgents conversation={data.selected} agents={data.detail.agents} workflows={data.workflows} workspaceId={data.workspaceId} owner={!!owner} canOperate={data.canOperate} />
          {#if owner}
            <form method="POST" action="?/mutate" class="mt-4 space-y-2"><input type="hidden" name="operation" value="rename" /><input type="hidden" name="conversation" value={data.selected} /><Input name="value" aria-label="群聊名称" required maxlength={160} value={data.detail.conversation.title} /><Button type="submit" variant="outline" size="sm">修改名称</Button></form>
            <form method="POST" action="?/mutate" class="mt-4 space-y-2"><input type="hidden" name="operation" value="add" /><input type="hidden" name="conversation" value={data.selected} /><label class="text-sm">添加组织成员<select name="target" required class="mt-1 w-full rounded border p-2"><option value="">选择成员</option>{#each data.people.items.filter(person => !data.detail?.members.some(member => member.id === person.id)) as person (person.id)}<option value={person.id}>{person.display_name}</option>{/each}</select></label><Button type="submit" variant="outline" size="sm">添加（不共享历史）</Button></form>
          {/if}
          <form method="POST" action="?/mutate" class="mt-4"><input type="hidden" name="operation" value="leave" /><input type="hidden" name="conversation" value={data.selected} /><Button type="submit" variant="outline" size="sm">退出群聊</Button></form>
        {/if}
      {:else}<p class="mt-3 text-sm text-muted-foreground">私聊和群聊仅对会话成员可见，组织管理员不会自动获得读取权限。</p>{/if}
    </div></details>{/if}
  </div>
</main>
