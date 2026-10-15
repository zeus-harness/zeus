<script lang="ts">
  import { approvalKindLabel, approvalAuthorityLabel } from '$lib/approval-policy';
  import { discussionSource } from '$lib/plan-draft';
  import { displayTimestamp } from '$lib/display-timestamp';
  import ResultContent from '$lib/features/results/ResultContent.svelte';
  import { reprocessingMessageSummary, discussionMessageSummary } from '$lib/studio-message';
  import { enhance } from '$app/forms';
  import { onMount } from 'svelte';
  import { beforeNavigate, invalidateAll } from '$app/navigation';
  import { page } from '$app/state';
  import { Button } from '@zeus/ui/components/ui/button';
  import { Input } from '@zeus/ui/components/ui/input';
  import { Textarea } from '@zeus/ui/components/ui/textarea';
  import RunTimeline from '$lib/features/runs/RunTimeline.svelte';
  import { TERMINAL_RUN_STATES } from '$lib/api/runs';
  import type { PageProps } from '../../../routes/(workspace)/[workspaceId=workspaceId]/studio/$types';
  import { withTaskReturn } from '$lib/task-return';
  import { draftFields, encodeStudioDraft, decodeStudioDraft } from '$lib/studio-draft';

  let { data, form }: Pick<PageProps, 'data' | 'form'> = $props();
  let pending = $state(false);
  let base = $derived(`/${data.workspaceId}`);
  let localValues = $state<Record<string, string> | null>(null);
  let restored = $state(false);
  let storageFailed = $state(false);
  let dirty = $state(false);
  let values = $derived(localValues ?? (form && 'values' in form ? form.values : null));
  let returnTo = $derived(`${base}/studio${data.item ? `?work_item=${data.item.id}${data.trace ? `&run=${data.trace.run.id}` : ''}` : data.workflow ? `?workflow=${data.workflow.id}` : ''}`);
  const configure = (href: string) => withTaskReturn(href, returnTo);
  function remember(values: Record<string, string>) {
    localValues = values;
    dirty = !!(values.message || values.title || values.description);
    try { sessionStorage.setItem(data.draftScope, encodeStudioDraft(values)); storageFailed = false; }
    catch { storageFailed = true; }
  }
  function capture(event: Event) {
    if (event.currentTarget instanceof HTMLFormElement) remember(draftFields(new FormData(event.currentTarget)));
  }
  function clearDraft() {
    try { sessionStorage.removeItem(data.draftScope); } catch { /* Leave protection covers unavailable storage. */ }
    localValues = null; form = null; dirty = false; restored = false;
  }
  const submit: import('@sveltejs/kit').SubmitFunction = ({ formData }) => {
    pending = true;
    remember(draftFields(formData));
    return async ({ result, update }) => {
      try {
        if (result.type === 'redirect') clearDraft();
        if (result.type === 'success' && result.data && 'values' in result.data) {
          const next = result.data.values as Record<string, string>;
          remember({ ...next, intent: result.data.type === 'draft' ? 'create' : next.intent });
        }
        await update({ reset: false });
      } finally { pending = false; }
    };
  };
  onMount(() => {
    if (form) return;
    try {
      const saved = decodeStudioDraft(sessionStorage.getItem(data.draftScope));
      if (saved) { localValues = saved; restored = true; dirty = true; }
    } catch { storageFailed = true; }
  });
  beforeNavigate(({ cancel }) => {
    if (dirty && storageFailed && !pending && !window.confirm('草稿未能自动保存，离开会丢失输入。仍要离开吗？')) cancel();
  });
  function protectUnload(event: BeforeUnloadEvent) {
    if (dirty && storageFailed && !pending) { event.preventDefault(); event.returnValue = ''; }
  }
  let draft = $derived(values && (form?.type === 'draft' || values.intent === 'create') ? values : null);
  let busy = $derived(!!data.trace && !TERMINAL_RUN_STATES.has(data.trace.run.status));
  let messages = $derived(data.sessionEvents.filter(event => ['user_message', 'assistant_message', 'follow_up_message'].includes(event.event_type)) ?? []);
  function content(payload: unknown): string {
    if (typeof payload === 'string') return payload;
    if (payload && typeof payload === 'object' && 'content' in payload && typeof payload.content === 'string') return payload.content;
    return '';
  }
  let discussionMode = $derived(data.discussion || (!data.item && !data.workflow));
  let output = $derived(content(data.trace?.run.output));
  const statusLabels: Record<string, string> = { queued: '排队中', running: '正在处理', waiting_approval: '等待审批', waiting_child: '等待子任务', succeeded: '已完成', failed: '执行失败', canceled: '已取消' };
</script>

<svelte:window onbeforeunload={protectUnload} />

<svelte:head><title>助手讨论 · Zeus</title></svelte:head>

<div class="flex min-h-[calc(100dvh-9rem)] flex-col overflow-hidden rounded-xl border border-border bg-background lg:flex-row">
  <aside class="border-b border-border bg-muted/30 p-4 lg:w-60 lg:shrink-0 lg:border-r lg:border-b-0">
    <a href="{base}/studio" class="block rounded-lg border border-border bg-background px-3 py-2 text-center text-sm font-medium">＋ 新建对话</a>
    {#if data.item}<details class="mt-5">
      <summary class="cursor-pointer text-xs font-medium text-muted-foreground">最近工作项</summary>
      <nav class="mt-3 max-h-56 space-y-1 overflow-auto lg:max-h-[60dvh]" aria-label="最近工作项">
        {#each data.items.items as item (item.id)}
          <a href="{base}/studio?work_item={item.id}" aria-current={data.item?.id === item.id ? 'page' : undefined} class="block truncate rounded-md px-3 py-2 text-sm hover:bg-muted {data.item?.id === item.id ? 'bg-muted font-medium' : ''}" title={item.title}>{item.title}</a>
        {:else}<p class="px-3 py-2 text-sm text-muted-foreground">还没有工作项。从右侧描述需求开始。</p>{/each}
      </nav>
      {#if data.items.next_cursor}<a class="mt-3 block text-sm underline" href="{base}/studio?cursor={encodeURIComponent(data.items.next_cursor)}">更早的工作项</a>{/if}
    </details>{/if}
    {#if data.recentDiscussionRuns.length}<details class="mt-4 text-sm"><summary class="cursor-pointer">最近聊天</summary><nav aria-label="最近聊天" class="mt-2 space-y-2">{#each data.recentDiscussionRuns as run (run.id)}<a class="block underline" href="{base}/studio?discuss=1&run={run.id}">{run.title}<span class="block text-xs text-muted-foreground">{statusLabels[run.status] ?? run.status} · {displayTimestamp(run.created_at)}</span></a>{/each}</nav></details>{/if}

  </aside>

  <section class="flex min-w-0 flex-1 flex-col" aria-label="会话工作区">
    <header class="flex flex-wrap items-center justify-between gap-3 border-b border-border px-6 py-4">
      <div><h1 class="font-semibold">助手讨论</h1><p class="mt-1 text-xs text-muted-foreground">理清思路，再交给 Agent 执行</p></div>
      {#if data.canConfigureChat}<a class="text-sm underline" href="{base}/settings/studio">聊天设置</a>{/if}
      {#if data.item}<a class="text-sm underline" href="{base}/work-items/{data.item.id}">查看工作项</a>{/if}
    </header>
    <div class="mx-auto w-full max-w-3xl flex-1 space-y-6 px-5 py-5 sm:px-8">
      {#if dirty}<p role="status" class="text-xs text-muted-foreground">{storageFailed ? '无法自动保存草稿，请勿关闭此页面。' : restored ? '已恢复本标签页的草稿。草稿保留 24 小时，尚未提交。' : '草稿已暂存于本标签页，保留 24 小时。'}{#if !draft}<button type="button" class="ml-3 underline" onclick={clearDraft}>清除草稿</button>{/if}</p>{/if}
      {#if !data.trace && !discussionMode}
        <section aria-label="执行准备情况" class="rounded-lg border border-border p-4 text-sm">
          <p class="font-medium">{data.workflows.length ? '已有已发布流程，可选择后执行' : '当前还不能执行，可以先整理需求'}</p>
          <p class="mt-2 text-muted-foreground">模型：{data.onboarding.model === 'configured' ? '已配置' : data.onboarding.model === 'missing' ? '待配置' : '暂无法确认'} · 智能体：{data.onboarding.agent === 'configured' ? '已发布' : data.onboarding.agent === 'missing' ? '待发布' : '暂无法确认'} · 流程：{data.onboarding.workflow === 'configured' ? '已发布' : data.onboarding.workflow === 'missing' ? '待发布' : '暂无法确认'}</p>
          <p class="mt-2 text-xs text-muted-foreground">配置存在不代表模型连接或实际执行已经验证。</p>
          {#if data.canBuild && !data.workflows.length}<a class="mt-3 inline-block underline" href={configure(`${base}/prepare`)}>按需求整理模板准备执行环境</a>{:else if !data.workflows.length}<p class="mt-2">请联系组织所有者配置模型、工作空间构建者发布流程。</p>{/if}
        </section>
      {/if}
      {#if !data.item && !data.workflow && !draft && !data.trace}
        <div class="py-4 text-center"><h2 class="text-2xl font-semibold">想聊点什么？</h2><p class="mt-3 text-sm leading-6 text-muted-foreground">问个问题、聊个想法，或者一起做点事。</p></div>
      {/if}
      {#if form?.type === 'error'}<p role="alert" class="rounded-lg border border-destructive/40 p-4 text-sm text-destructive">{form.message}</p>{/if}
      {#if draft}
        <div class="ml-8 whitespace-pre-wrap break-words rounded-2xl bg-muted p-4 text-sm">{draft.message}</div>
        <div class="space-y-3"><p class="text-sm font-medium">操作引导</p><p class="text-sm text-muted-foreground">已整理标题与计划内容，请核对目标和验收条件后保存。这一步仅编辑预览，确认后才创建资源。</p>
          <form method="POST" action="?/interact" class="space-y-4 rounded-xl border border-border p-5" oninput={capture} onchange={capture} use:enhance={submit}>
            <input type="hidden" name="proposal_id" value={draft.proposal_id ?? ''} /><input type="hidden" name="run_id" value={draft.run_id ?? ''} /><input type="hidden" name="intent" value="create" /><input type="hidden" name="kind" value={draft.kind} /><input type="hidden" name="message" value={draft.message} /><input type="hidden" name="request_id" value={draft.request_id} />
            <p class="text-xs text-muted-foreground">{draft.kind === 'workflow' ? '流程草稿' : '工作项草稿'} · 尚未保存</p>{#if draft.kind === 'workflow'}<p class="text-sm">这里只保存流程说明。还需配置 Agent、工具权限和执行限制，发布版本后才能复用执行。</p>{/if}
            <label class="block space-y-2 text-sm"><span>标题</span><Input name="title" value={draft.title} required maxlength={draft.kind === 'workflow' ? 160 : 500} /></label>
            <label class="block space-y-2 text-sm"><span>描述与验收要求</span><Textarea name="description" value={draft.description} rows={5} maxlength={50000} /></label>
            <Button type="submit" disabled={pending}>{pending ? '正在保存…' : '确认保存'}</Button>
            <button type="button" onclick={clearDraft} class="ml-3 text-sm text-muted-foreground underline">放弃草稿</button>
          </form>
        </div>
      {/if}
      {#if data.workflow}
        <div class="rounded-xl border border-border p-5"><p class="text-xs text-muted-foreground">流程已保存 · 尚未发布</p><h2 class="mt-2 font-medium">{data.workflow.name}</h2><p class="mt-3 whitespace-pre-wrap text-sm">{data.workflow.description}</p><p class="mt-4 text-sm text-muted-foreground">下一步选择 Agent、工具权限和执行限制，保存版本并发布后即可运行。</p><a class="mt-3 inline-block text-sm underline" href={configure(`${base}/workflows?selected=${data.workflow.id}`)}>配置并发布流程</a></div>
      {/if}
      {#if data.item || (data.discussion && data.trace)}
        {#if data.item}<article class="rounded-xl border border-border p-5"><p class="text-xs text-muted-foreground">关联任务 · {data.executionTrace ? (statusLabels[data.executionTrace.run.status] ?? data.executionTrace.run.status) : '待开始'}</p><h2 class="mt-2 font-medium">{data.item.title}</h2><details class="mt-3 text-sm"><summary class="cursor-pointer">查看目标与计划</summary><ResultContent text={data.item.description ?? ''} actions={false} /></details>{#if discussionSource(data.workspaceId, data.item)}<a class="text-sm underline" href={discussionSource(data.workspaceId, data.item)!}>查看来源讨论</a>{/if}</article>{/if}
        {#if data.item && data.runs && data.runs.items.length > 1}
          <details class="text-sm"><summary class="cursor-pointer text-muted-foreground">历史运行（最近 {data.runs.items.length} 次）</summary><div class="mt-3 flex flex-col gap-2">{#each data.runs.items as run (run.id)}<a href="{base}/studio?work_item={data.item.id}&run={run.id}" class="underline">{statusLabels[run.status] ?? run.status} · {new Date(run.created_at).toLocaleString('zh-CN')}</a>{/each}</div></details>
        {/if}
        {#each messages as message (message.id)}
          {#if content(message.payload)}{@const summary = message.event_type === 'user_message' ? (reprocessingMessageSummary(content(message.payload)) ?? discussionMessageSummary(content(message.payload))) : null}<article class="space-y-2 {message.event_type === 'assistant_message' ? '' : 'ml-8 rounded-2xl bg-muted p-4'}"><p class="text-xs text-muted-foreground">{message.event_type === 'assistant_message' ? 'Agent' : '用户'}</p><div>{#if message.event_type === 'assistant_message'}<ResultContent text={content(message.payload)} />{:else}<p class="whitespace-pre-wrap break-words text-sm leading-7">{summary ?? content(message.payload)}</p>{/if}</div>
            {#if summary}<details class="text-xs"><summary class="cursor-pointer">查看本次处理的原始上下文</summary><pre class="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-words">{content(message.payload)}</pre></details>{/if}</article>{/if}
        {/each}
        {#if data.nextEvent && data.trace}<a class="text-sm underline" href={`${base}/studio?${data.item ? `work_item=${data.item.id}` : 'discuss=1'}&run=${data.trace.run.id}&after=${data.nextEvent}`}>查看后续消息</a>{/if}
        {#if data.trace}
          <div class="space-y-4">
            <p role="status" class="text-sm font-medium">{statusLabels[data.trace.run.status] ?? data.trace.run.status}</p>
            {#if output && !messages.some(message => message.event_type === 'assistant_message' && content(message.payload) === output)}<ResultContent text={output} />{/if}
            {#if data.discussion && output && !busy && !data.chatWorkflows.some(w => w.active_version_id === data.trace?.run.workflow_version_id)}
              <form method="POST" action="?/interact" use:enhance={submit} class="rounded-lg border border-border p-4 space-y-3">
                <input type="hidden" name="intent" value="draft" /><input type="hidden" name="run_id" value={data.trace.run.id} /><input type="hidden" name="message" value={output} />
                <p class="text-sm">将这份建议整理为草稿，核对后才创建资源，不会启动执行。</p>
                <select name="kind" aria-label="计划保存为" class="border border-border rounded p-2"><option value="work-item">工作项草稿</option>{#if data.canBuild}<option value="workflow">流程草稿</option>{/if}</select>
                <Button type="submit" disabled={pending}>确认计划并预览草稿</Button>
              </form>
            {/if}
            {#each data.createdResources as resource (resource.id)}
              <article class="space-y-2 rounded-lg border border-border p-4" aria-label="聊天关联的工作">
                <p class="text-sm text-muted-foreground">{resource.status === 'proposed' && (data.item?.input as Record<string, unknown> | null)?.studio_proposal_id === resource.id ? '已确认并保存为当前工作项' : resource.status === 'proposed' ? '待确认预览 · 尚未创建' : resource.kind === 'work_item' ? '工作项已创建 · 待处理' : '流程已创建 · 尚未发布'}</p><h3 class="font-medium">{resource.title}</h3>
                {#if resource.status === 'proposed' && (data.item?.input as Record<string, unknown> | null)?.studio_proposal_id !== resource.id}
                  <p class="whitespace-pre-wrap text-sm">{resource.description}</p>
                  <form method="POST" action="?/interact" use:enhance={submit}>
                    <input type="hidden" name="intent" value="draft" /><input type="hidden" name="proposal_id" value={resource.id} /><input type="hidden" name="run_id" value={resource.runId} /><input type="hidden" name="kind" value={resource.kind === 'work_item' ? 'work-item' : 'workflow'} /><input type="hidden" name="message" value="预览资源" />
                    <Button type="submit" variant="outline" disabled={pending || busy}>编辑并确认创建</Button>
                  </form>
                {:else if resource.status !== 'proposed'}
                  <a class="text-sm underline" href={resource.kind === 'work_item' ? `${base}/studio?work_item=${resource.id}&discuss=1&run=${data.trace.run.id}` : `${base}/workflows?selected=${resource.id}`}>{resource.kind === 'work_item' ? '关联到当前对话' : '配置并发布流程'}</a>
                  {#if resource.kind === 'work_item'}<a class="ml-3 text-sm underline" href={`${base}/work-items/${resource.id}`}>查看工作项详情</a>{/if}
                {/if}
              </article>
            {/each}
            {#if data.trace.run.output && !output}<details><summary class="cursor-pointer text-sm">查看结构化结果</summary><pre class="mt-2 overflow-auto text-xs">{JSON.stringify(data.trace.run.output, null, 2)}</pre></details>{/if}
            {#each data.trace.approvals.filter(approval => approval.status === 'pending') as approval (approval.id)}
              <article class="rounded-xl border border-border p-4 text-sm">
                <p class="font-medium">{approvalKindLabel(approval.kind)}</p>
                <p class="mt-1 text-muted-foreground">{approvalAuthorityLabel(approval.kind)}</p>
                <p class="mt-1 text-muted-foreground">运行已挂起，等待处理后继续。</p>
                <a class="mt-2 inline-block underline" href="{base}/runs/{data.trace.run.id}#run-approvals">{approval.can_decide ? '查看并处理' : '查看审批进度'}</a>
              </article>
            {/each}
            {#key data.trace.run.id}<RunTimeline compact initialEvents={data.trace.run_events} initialStatus={data.trace.run.status} streamUrl={data.streamUrl} onSnapshotChange={() => { void invalidateAll(); }} />{/key}
            <div class="flex flex-wrap gap-4 text-sm"><a class="underline" href="{base}/runs/{data.trace.run.id}">运行详情与审批</a><button type="button" class="underline" onclick={() => invalidateAll()}>刷新结果</button></div>
          </div>
        {:else}<p class="text-sm text-muted-foreground">目标与讨论已保存。任务进度和审批可在任务详情查看。</p>{/if}
      {/if}
    </div>
    {#if data.item}
      <section class="mx-auto w-full max-w-3xl space-y-3 px-5 py-4" aria-label="关联工作的执行">
        {#if data.executionTrace}
          <p class="font-medium">工作执行：{statusLabels[data.executionTrace.run.status] ?? data.executionTrace.run.status}</p>
          <ResultContent text={content(data.executionTrace.run.output)} />
          {#key data.executionTrace.run.id}<RunTimeline compact initialEvents={data.executionTrace.run_events} initialStatus={data.executionTrace.run.status} streamUrl={data.executionStreamUrl} onSnapshotChange={() => { void invalidateAll(); }} />{/key}
          <a class="text-sm underline" href={`${base}/runs/${data.executionTrace.run.id}`}>查看执行与审批</a>
          {#if data.executionTrace.run.status === 'succeeded'}<a class="ml-3 text-sm underline" href={`${base}/work-items/${data.item.id}?review_run=${data.executionTrace.run.id}#acceptance`}>验收结果</a>{/if}
        {/if}
        <details class="rounded-lg border p-4"><summary class="cursor-pointer font-medium">开始执行工作项</summary>
          <form method="POST" action="?/interact" use:enhance={submit} class="mt-3 space-y-3">
            <input type="hidden" name="intent" value="send" /><input type="hidden" name="work_item_id" value={data.item.id} /><input type="hidden" name="request_id" value={data.requestId} /><input type="hidden" name="conversation_run_id" value={data.trace?.run.id ?? ''} />
            <p class="text-sm">仅执行「{data.item.title}」。此操作会启动所选流程，工具和资源访问继续受审批约束。</p>
            <label class="block text-sm">执行工作流<select name="workflow_id" required class="ml-2 max-w-full rounded border p-2"><option value="">请选择流程</option>{#each data.workflows as workflow (workflow.id)}<option value={workflow.id}>{workflow.name}</option>{/each}</select></label>
            <Textarea name="message" aria-label="执行要求" placeholder="说明这次需要执行的范围和预期结果" required maxlength={50000} />
            <Button type="submit" disabled={pending || !data.canOperate || !data.workflows.length || (!!data.executionTrace && !TERMINAL_RUN_STATES.has(data.executionTrace.run.status))}>开始执行</Button>
          </form>
        </details>
      </section>
    {/if}
    {#if !draft}
      <div class="sticky bottom-0 border-t border-border bg-background px-5 py-5 sm:px-8">
        {#key page.url.search}
          <form method="POST" action="?/interact" class="mx-auto max-w-3xl space-y-3" oninput={capture} onchange={capture} use:enhance={submit}>
            <input type="hidden" name="intent" value="discuss" /><input type="hidden" name="request_id" value={values?.request_id || data.requestId} />
            <input type="hidden" name="work_item_id" value={data.item?.id ?? ''} />
            <input type="hidden" name="run_id" value={data.trace?.run.id ?? ''} />
            <input type="hidden" name="workflow_id" value={data.trace ? data.discussionWorkflows.find(w => w.active_version_id === data.trace?.run.workflow_version_id)?.id ?? '' : data.chatWorkflows[0]?.id ?? ''} />
            {#if !data.trace && !data.chatWorkflows.length}<p class="text-sm">聊天助手尚未配置。{#if data.canConfigureChat}<a class="underline" href="{base}/settings/studio">前往聊天设置</a>{:else}请联系工作空间所有者。{/if}</p>{/if}
            <label class="block"><span class="sr-only">消息</span><Textarea name="message" value={values?.message ?? ''} placeholder="继续聊聊，或补充你的想法…" required maxlength={50000} rows={3} disabled={!data.canOperate || busy} /></label>
            <details class="text-sm"><summary class="cursor-pointer">创建偏好：默认先预览</summary><label class="mt-2 flex items-center gap-2"><input type="checkbox" name="allow_create" value="yes" />允许本轮直接创建工作项或未发布流程</label><p class="mt-1 text-muted-foreground">仅在本轮明确要求直接创建时勾选；不会自动开始执行。</p></details>
            <div class="flex items-center justify-between gap-4"><p class="text-sm text-muted-foreground">{!data.canOperate ? '当前角色只有查看权限。' : busy ? '正在回复…' : data.item ? '继续讨论不会启动工作流程。' : '需要保存的工作会先展示预览。'}</p><Button type="submit" disabled={pending || !data.canOperate || busy || (!data.trace && !data.chatWorkflows.length)}>{pending ? '发送中…' : '发送'}</Button></div>
          </form>
        {/key}
      </div>
    {/if}
  </section>
</div>
