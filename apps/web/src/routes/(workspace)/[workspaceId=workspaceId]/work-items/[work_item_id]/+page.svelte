<script lang="ts">
  import { beforeNavigate } from '$app/navigation';
  let draftDirty = $state(false);
  let submittingEdit = $state(false);
  let editorReset = $state(0);
  let discardFeedback = $state(false);
  function allowLeaving(): boolean {
    if (submittingEdit || !(draftDirty || editValues)) return true;
    if (!window.confirm('有未保存的修改，确定放弃并离开吗？')) return false;
    draftDirty = false;
    discardFeedback = true;
    return true;
  }
  beforeNavigate((navigation) => { if (!allowLeaving()) navigation.cancel(); });
  function markDraft(event: Event) {
    if ((event.target as HTMLInputElement).name) draftDirty = true;
  }
  function cancelEdit() {
    if (!allowLeaving()) return;
    draftDirty = false;
    discardFeedback = true;
    editorReset += 1;
    editOpen = false;
  }

  import { Input } from '@zeus/ui/components/ui/input';
  import MemberPicker from '$lib/features/work-items/MemberPicker.svelte';
  import type { MemberOption } from '$lib/server/member-options';
  import { statusLabel } from '$lib/features/status-labels';
  import { ArrowLeft, Bot, ExternalLink, FileText, Play, UserRound } from '@lucide/svelte';

  import * as Alert from '@zeus/ui/components/ui/alert';
  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';
  import { Label } from '@zeus/ui/components/ui/label';
  import { NativeSelect, NativeSelectOption } from '@zeus/ui/components/ui/native-select';
  import { Separator } from '@zeus/ui/components/ui/separator';
  import * as Table from '@zeus/ui/components/ui/table';
  import * as Tabs from '@zeus/ui/components/ui/tabs';
  import { Textarea } from '@zeus/ui/components/ui/textarea';

  import EmptyState from '$lib/components/layout/EmptyState.svelte';
  import WorkspaceStatus from '$lib/components/WorkspaceStatus.svelte';
  import type { Workflow } from '$lib/api/control-plane';
  import type { Run } from '$lib/api/runs';
  import type { ActionData, PageData } from './$types';

  let { data, form } = $props<{ data: PageData; form: ActionData }>();
  let editOpen = $state(false);
  let editValues = $derived(!discardFeedback && form && 'editValues' in form ? form.editValues : null);
  let item = $derived(data.result.data);
  let workspaceBase = $derived(`/${data.workspaceId}`);
  let workflows = $derived(data.workflows.data?.items ?? []);
  let activeWorkflows = $derived(
    workflows.filter((workflow: Workflow) => workflow.active_version_id)
  );
  let runs = $derived(data.runs.data?.items ?? []);
  let approvals = $derived(data.approvals.data ?? []);
  let attachments = $derived(data.attachments.data ?? []);
  let externalReferences = $derived(data.externalReferences.data ?? []);
  let latestResult = $derived(
    item?.output ??
      runs.find((run: Run) => run.status === 'succeeded' && run.output !== null)?.output ??
      null
  );

  let reviewableRuns = $derived(runs.filter((run: Run) => run.status === 'succeeded' && run.output !== null));
  let latestRun = $derived(runs[0]);
  let activeTab = $derived(item?.status === 'canceled' ? 'details' : latestRun && ['queued', 'running', 'waiting_approval', 'waiting_child'].includes(latestRun.status) ? 'activity' : latestResult !== null ? 'result' : 'details');
  let resultText = $derived(typeof latestResult === 'string' ? latestResult : latestResult && typeof latestResult === 'object' && 'content' in latestResult && typeof latestResult.content === 'string' ? latestResult.content : null);
  let reviewRecords = $derived(data.reviews.data?.items ?? []);
  const workItemLabels: Record<string, string> = { open: '待处理', in_progress: '处理中', blocked: '已阻塞', completed: '已完成', canceled: '已取消' };

  function dateLabel(value: string | null): string {
    return value
      ? new Intl.DateTimeFormat('zh-CN', {
          month: 'short',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit'
        }).format(new Date(value))
      : '—';
  }

  function formatJson(value: unknown): string {
    try {
      return JSON.stringify(value, null, 2) ?? '—';
    } catch {
      return '—';
    }
  }

  function statusVariant(status: string): 'default' | 'secondary' | 'destructive' | 'outline' {
    if (status === 'completed' || status === 'succeeded' || status === 'approved') return 'secondary';
    if (status === 'blocked' || status === 'failed' || status === 'canceled' || status === 'rejected') return 'destructive';
    if (status === 'in_progress' || status === 'running' || status === 'pending') return 'default';
    return 'outline';
  }
</script>

<svelte:window onbeforeunload={(event) => { if (!submittingEdit && (draftDirty || editValues)) { event.preventDefault(); event.returnValue = ''; } }} />
<svelte:head><title>Zeus · {item?.title ?? '工作项详情'}</title></svelte:head>

<main class="px-5 py-7 lg:px-8 lg:py-9">
  {#if data.result.status !== 'ready' || !item}
    <WorkspaceStatus status={data.result.status} message={data.result.message} httpStatus={data.result.httpStatus} title="工作项详情" />
  {:else}
    <a class="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground" href={`${workspaceBase}/work-items`}><ArrowLeft class="size-4" />返回工作项</a>
    <header class="mt-5 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
      <div class="min-w-0">
        <div class="flex flex-wrap items-center gap-2"><Badge variant={statusVariant(item.status)}>{workItemLabels[item.status] ?? item.status}</Badge><Badge variant="outline" class="capitalize">{statusLabel(item.priority)}</Badge></div>
        <h1 class="mt-3 text-2xl font-semibold tracking-tight sm:text-3xl">{item.title}</h1>
        <p class="mt-2 max-w-3xl whitespace-pre-wrap text-sm leading-6 text-muted-foreground">{item.description || '没有补充描述。'}</p>
      </div>
      <div class="flex items-center gap-2 text-sm text-muted-foreground"><UserRound class="size-4" />{data.members.find((member: MemberOption) => member.user_id === item.assignee_user_id)?.display_name || (item.assignee_user_id ? '已分配成员' : '未分配')}</div>
    </header>

    {#if form?.type === 'error'}
      <Alert.Root variant="destructive" class="mt-6"><Alert.Title>操作未完成</Alert.Title><Alert.Description>{form.message}</Alert.Description></Alert.Root>
    {/if}

    {#if data.saved}<p role="status" class="mt-4 text-sm">工作项已保存。</p>{/if}
    {#if data.canEdit}
      <div class="mt-4"><Button variant="outline" onclick={() => editOpen = !editOpen}>{editOpen ? '收起编辑' : '编辑工作项'}</Button></div>
      {#key `${item.id}:${item.revision}:${editorReset}`}
        <form hidden={!editOpen && !editValues} oninput={markDraft} onchange={markDraft} onsubmit={() => submittingEdit = true} method="POST" action="?/edit" class="mt-4 max-w-3xl space-y-4 rounded-lg border border-border p-5" aria-label="编辑工作项">
          <input type="hidden" name="revision" value={editValues?.revision ?? item.revision} />
          <div class="space-y-2"><Label for="edit-title">标题</Label><Input id="edit-title" name="title" required maxlength={500} value={editValues?.title ?? item.title} /></div>
          <div class="space-y-2"><Label for="edit-description">描述</Label><Textarea id="edit-description" name="description" rows={6} maxlength={50000} value={editValues?.description ?? item.description} /></div>
          <div class="space-y-2"><Label for="edit-priority">优先级</Label><NativeSelect id="edit-priority" name="priority" value={editValues?.priority ?? item.priority}>{#each ['low','normal','high','urgent'] as priority (priority)}<NativeSelectOption value={priority}>{statusLabel(priority)}</NativeSelectOption>{/each}</NativeSelect></div>
          <div class="space-y-2"><Label for="edit-assignee">负责人</Label><MemberPicker id="edit-assignee" members={data.members} limited={data.memberOptionsLimited} value={editValues?.assignee_user_id ?? item.assignee_user_id ?? ''} /></div>
          <div class="flex gap-2"><Button type="submit">保存任务信息</Button><Button type="button" variant="outline" onclick={cancelEdit}>取消编辑</Button></div>
        </form>
      {/key}
    {/if}
    {#if item.status === 'canceled'}<p class="mt-4 rounded-lg border border-border p-4 text-sm">此任务已取消。需要继续处理时，<a href="#update-status" class="underline">前往更新状态，恢复为待处理</a>。</p>{/if}
    <section aria-label="业务进度" class="mt-6 grid gap-3 sm:grid-cols-3">
      <div class="rounded-lg border border-border p-4"><p class="text-xs text-muted-foreground">工作项</p><p class="mt-2 font-medium">{workItemLabels[item.status] ?? item.status}</p><p class="mt-1 text-xs text-muted-foreground">业务状态由负责人更新</p></div>
      <div class="rounded-lg border border-border p-4"><p class="text-xs text-muted-foreground">最近运行</p><p class="mt-2 font-medium">{latestRun ? statusLabel(latestRun.status) : '尚未启动'}</p>{#if latestRun}<a class="mt-1 inline-block text-sm underline" href={`${workspaceBase}/runs/${latestRun.id}`}>查看执行过程</a>{/if}</div>
      <div class="rounded-lg border border-border p-4"><p class="text-xs text-muted-foreground">结果验收</p><p class="mt-2 font-medium">人工核对后记录决定</p><a class="mt-1 inline-block text-sm underline" href="#acceptance" onclick={() => activeTab = 'result'}>查看结果与验收</a></div>
    </section>
    <div class="mt-7 grid gap-6 xl:grid-cols-[minmax(0,1fr)_22rem]">
      <Tabs.Root bind:value={activeTab} class="min-w-0">
        <Tabs.List>
          <Tabs.Trigger value="activity">运行</Tabs.Trigger>
          <Tabs.Trigger value="details">详情</Tabs.Trigger>
          <Tabs.Trigger value="resources">资源</Tabs.Trigger>
          <Tabs.Trigger value="result">结果</Tabs.Trigger>
        </Tabs.List>

        <Tabs.Content value="activity" class="mt-4 space-y-5">
          <Card.Root>
            <Card.Header class="flex-row items-start justify-between gap-4"><div><Card.Title>关联运行</Card.Title><Card.Description>每次手工重试都会创建新 Run。</Card.Description></div><Badge variant="outline">{runs.length}</Badge></Card.Header>
            <Card.Content>
              {#if runs.length > 0}
                <div class="overflow-x-auto">
                  <Table.Root>
                    <Table.Header><Table.Row><Table.Head>运行</Table.Head><Table.Head>状态</Table.Head><Table.Head>尝试</Table.Head><Table.Head>开始</Table.Head><Table.Head>结束</Table.Head></Table.Row></Table.Header>
                    <Table.Body>
                      {#each runs as run (run.id)}
                        <Table.Row>
                          <Table.Cell><a class="font-medium hover:underline" href={`${workspaceBase}/runs/${run.id}`}>查看时间线</a><p class="mt-1 font-mono text-[0.6875rem] text-muted-foreground">{run.id}</p></Table.Cell>
                          <Table.Cell><Badge variant={statusVariant(run.status)}>{statusLabel(run.status)}</Badge></Table.Cell>
                          <Table.Cell>{run.attempt_count}</Table.Cell>
                          <Table.Cell class="whitespace-nowrap text-xs text-muted-foreground">{dateLabel(run.started_at ?? run.created_at)}</Table.Cell>
                          <Table.Cell class="whitespace-nowrap text-xs text-muted-foreground">{dateLabel(run.finished_at)}</Table.Cell>
                        </Table.Row>
                      {/each}
                    </Table.Body>
                  </Table.Root>
                </div>
              {:else}
                <EmptyState title="还没有运行" description="从右侧选择一个已有活动版本的 Workflow 启动 Agent。" />
              {/if}
            </Card.Content>
          </Card.Root>

          {#if approvals.length > 0}
            <Card.Root>
              <Card.Header><Card.Title>审批记录</Card.Title><Card.Description>待审批项应尽快处理，避免 Run 长时间占用上下文。</Card.Description></Card.Header>
              <Card.Content class="space-y-2">
                {#each approvals as approval (approval.id)}
                  <a class="flex items-center justify-between gap-4 rounded-lg border border-border p-3 hover:bg-accent" href={`${workspaceBase}/runs/${approval.run_id}`}>
                    <span><span class="block text-sm font-medium">工具调用审批</span><span class="block font-mono text-xs text-muted-foreground">{approval.tool_call_id}</span></span>
                    <Badge variant={statusVariant(approval.status)}>{approval.status}</Badge>
                  </a>
                {/each}
              </Card.Content>
            </Card.Root>
          {/if}
        </Tabs.Content>

        <Tabs.Content value="details" class="mt-4">
          <Card.Root><Card.Header><Card.Title>任务上下文</Card.Title><Card.Description>协作者可读信息保持在前，内部 ID 放到末尾。</Card.Description></Card.Header><Card.Content class="space-y-5">
            <dl class="grid gap-5 sm:grid-cols-2">
              <div><dt class="text-xs font-medium text-muted-foreground">负责人</dt><dd class="mt-1 break-all text-sm">{data.members.find((member: MemberOption) => member.user_id === item.assignee_user_id)?.display_name || (item.assignee_user_id ? '已分配成员' : '未分配')}</dd></div>
              <div><dt class="text-xs font-medium text-muted-foreground">来源</dt><dd class="mt-1 text-sm">{item.source_kind ?? '手工创建'}</dd></div>
              <div><dt class="text-xs font-medium text-muted-foreground">创建时间</dt><dd class="mt-1 text-sm">{dateLabel(item.created_at)}</dd></div>
              <div><dt class="text-xs font-medium text-muted-foreground">更新时间</dt><dd class="mt-1 text-sm">{dateLabel(item.updated_at)}</dd></div>
            </dl>
            <Separator />
            <details><summary class="cursor-pointer text-sm font-medium">查看 Input JSON</summary><pre class="mt-3 max-h-80 overflow-auto rounded-lg bg-muted p-4 font-mono text-xs leading-5">{formatJson(item.input)}</pre></details>
            <p class="font-mono text-[0.6875rem] text-muted-foreground">WorkItem {item.id} · revision {item.revision}</p>
          </Card.Content></Card.Root>
        </Tabs.Content>

        <Tabs.Content value="resources" class="mt-4 grid gap-5 md:grid-cols-2">
          <Card.Root><Card.Header><Card.Title class="flex items-center gap-2"><FileText class="size-4" />附件</Card.Title></Card.Header><Card.Content class="space-y-2">
            {#each attachments as attachment (attachment.id)}
              <div class="rounded-lg border border-border p-3"><p class="text-sm font-medium">{attachment.file_name}</p><p class="mt-1 text-xs text-muted-foreground">{attachment.content_type} · {attachment.size_bytes} bytes</p></div>
            {:else}<p class="text-sm text-muted-foreground">没有附件。</p>{/each}
          </Card.Content></Card.Root>
          <Card.Root><Card.Header><Card.Title class="flex items-center gap-2"><ExternalLink class="size-4" />外部引用</Card.Title></Card.Header><Card.Content class="space-y-2">
            {#each externalReferences as reference (reference.id)}
              <div class="rounded-lg border border-border p-3"><p class="text-sm font-medium">{reference.source_kind}</p><p class="mt-1 break-all text-xs text-muted-foreground">{reference.external_reference}</p></div>
            {:else}<p class="text-sm text-muted-foreground">没有外部引用。</p>{/each}
          </Card.Content></Card.Root>
        </Tabs.Content>

        <Tabs.Content value="result" class="mt-4">
          <Card.Root><Card.Header><Card.Title>最终结果</Card.Title><Card.Description>查看已保存的工作项结果，或最近一次成功运行的回答。运行成功不等于业务验收通过。</Card.Description></Card.Header><Card.Content>
            {#if latestResult !== null}
              {#if resultText !== null}<div class="whitespace-pre-wrap break-words text-sm leading-7">{resultText}</div>{/if}
              <details open={resultText === null} class="mt-4"><summary class="cursor-pointer text-sm text-muted-foreground">查看原始结果</summary><pre class="mt-3 max-h-[32rem] overflow-auto rounded-lg bg-muted p-4 font-mono text-xs leading-5">{formatJson(latestResult)}</pre></details>
              <p class="mt-3 text-xs text-muted-foreground">结果可能来自较早的成功运行；验收时请核对所选 Run，不代表最近运行已成功。</p>
            {:else}<EmptyState title="还没有结果" description="Agent 完成一次关联运行后，结果会显示在这里。" />{/if}
          </Card.Content></Card.Root>
        </Tabs.Content>
      </Tabs.Root>

      <aside class="space-y-5">
        <Card.Root>
          <Card.Header><Card.Title class="flex items-center gap-2"><Bot class="size-4" />启动 Agent</Card.Title><Card.Description>选择已发布流程处理这项工作。完成后查看结果，并在下方进行人工验收。</Card.Description></Card.Header>
          <Card.Content>
            {#if data.workflows.status !== 'ready'}
              <p class="text-sm text-destructive">{data.workflows.message}</p>
            {:else if activeWorkflows.length === 0}
              <EmptyState title="没有可运行的流程" description="请工作空间 Owner 或 Builder 配置 Agent，并发布流程版本。">
                {#snippet action()}<Button href={`${workspaceBase}/workflows?return_to=${encodeURIComponent(`${workspaceBase}/work-items/${data.workItemId}`)}`} variant="outline" size="sm">配置流程</Button>{/snippet}
              </EmptyState>
            {:else}
              <form method="POST" action="?/start" class="space-y-4">
                <div class="space-y-2"><Label for="workflow_id">流程</Label><NativeSelect id="workflow_id" name="workflow_id" required class="w-full"><NativeSelectOption value="" disabled selected>选择已发布流程</NativeSelectOption>{#each activeWorkflows as workflow (workflow.id)}<NativeSelectOption value={workflow.id}>{workflow.name}</NativeSelectOption>{/each}</NativeSelect></div>
                <div class="space-y-2"><Label for="message">给 Agent 的消息</Label><Textarea id="message" name="message" rows={4} placeholder="说明这次运行要完成的动作" /></div>
                <details class="space-y-3"><summary class="cursor-pointer text-sm">高级运行输入</summary><div class="space-y-2"><Label for="input">结构化输入（JSON）</Label><Textarea id="input" name="input" rows={5} class="font-mono text-xs" value={formatJson(item.input)} /></div></details>
                <Button type="submit" class="w-full"><Play class="size-4" />启动运行</Button>
              </form>
            {/if}
          </Card.Content>
        </Card.Root>

        <Card.Root>
          <Card.Header><Card.Title><span id="update-status" class="scroll-mt-20">更新状态</span></Card.Title><Card.Description>多人协作时会检查版本，避免覆盖他人的更新。</Card.Description></Card.Header>
          <Card.Content><form method="POST" action="?/update" class="space-y-4"><input type="hidden" name="revision" value={item.revision} /><div class="space-y-2"><Label for="status">状态</Label><NativeSelect id="status" name="status" value={item.status} class="w-full"><NativeSelectOption value="open">待处理</NativeSelectOption><NativeSelectOption value="in_progress">处理中</NativeSelectOption><NativeSelectOption value="blocked">已阻塞</NativeSelectOption><NativeSelectOption value="completed">已完成</NativeSelectOption><NativeSelectOption value="canceled">已取消</NativeSelectOption></NativeSelect></div><Button type="submit" variant="outline" class="w-full">保存状态</Button></form></Card.Content>
        </Card.Root>
      </aside>
    </div>
    <section id="acceptance" aria-label="人工验收" class="mt-6 scroll-mt-6">
      <Card.Root>
        <Card.Header><Card.Title>人工验收</Card.Title><Card.Description>核对指定运行的结果，记录接受或修改意见。工具审批仅授权执行，不代表业务验收。</Card.Description></Card.Header>
        <Card.Content class="space-y-5">
          {#if data.reviewed}<p role="status" class="text-sm">验收已保存。工作项状态保持不变，需要时请单独更新。</p>{/if}
          {#if data.reviews.status !== 'ready'}<p role="alert" class="text-sm text-destructive">验收记录暂时无法读取，请刷新后重试。</p>{/if}
          {#if reviewableRuns.length > 0}
            <form method="POST" action="?/review" class="space-y-4">
              <input type="hidden" name="revision" value={item.revision} />
              <div class="grid gap-4 md:grid-cols-2">
                <div class="space-y-2"><Label for="review-run">验收的运行</Label><NativeSelect id="review-run" name="run_id" required><NativeSelectOption value="" disabled selected>选择已成功的运行</NativeSelectOption>{#each reviewableRuns as run (run.id)}<NativeSelectOption value={run.id}>{dateLabel(run.created_at)} · {run.id}</NativeSelectOption>{/each}</NativeSelect></div>
                <div class="space-y-2"><Label for="review-decision">验收决定</Label><NativeSelect id="review-decision" name="decision" required><NativeSelectOption value="" disabled selected>请选择</NativeSelectOption><NativeSelectOption value="accepted">接受结果</NativeSelectOption><NativeSelectOption value="needs_changes">需要修改</NativeSelectOption></NativeSelect></div>
              </div>
              <div class="flex flex-wrap gap-3 text-sm">{#each reviewableRuns as run (run.id)}<a class="underline" href={`${workspaceBase}/runs/${run.id}`}>核对运行 {dateLabel(run.created_at)}</a>{/each}</div>
              <Label for="review-reason">验收原因</Label><Textarea id="review-reason" name="reason" required maxlength={4000} rows={3} placeholder="说明已核对的事实、缺失信息或需要修改的内容。" />
              <Button type="submit">保存验收记录</Button>
            </form>
          {:else}<p class="text-sm text-muted-foreground">当前加载的运行中没有可验收结果。请先完成一次成功运行。</p>{/if}
          <div class="space-y-3">
            {#each reviewRecords as review (review.id)}
              <article class="rounded-lg border border-border p-4">
                <div class="flex flex-wrap items-center justify-between gap-2"><Badge variant={review.decision === 'accepted' ? 'secondary' : 'outline'}>{review.decision === 'accepted' ? '接受结果' : '需要修改'}</Badge><time class="text-xs text-muted-foreground" datetime={review.created_at}>{dateLabel(review.created_at)}</time></div>
                <p class="mt-3 whitespace-pre-wrap break-words text-sm">{review.reason}</p>
                <a class="mt-3 inline-block text-sm underline" href={`${workspaceBase}/runs/${review.run_id}`}>查看本次验收的运行</a>
                {#if review.decision === 'needs_changes' && data.canEdit}
                  <form method="POST" action="?/reprocess" class="mt-3 space-y-2">
                    <input type="hidden" name="review_id" value={review.id} />
                    <input type="hidden" name="revision" value={item.revision} />
                    <p class="text-xs text-muted-foreground">使用当前工作项内容和原流程版本，结合这条意见与原结果创建新运行，可能产生模型费用。</p>
                    <Button type="submit" variant="outline">按此意见重新处理</Button>
                  </form>
                {/if}
                <details class="mt-2 text-xs text-muted-foreground"><summary class="cursor-pointer">验收依据</summary><p class="mt-2 break-all">操作者：{review.reviewed_by}<br />Workflow 版本：{review.workflow_version_id}<br />工作项 revision：{review.work_item_revision}</p></details>
              </article>
            {:else}<p class="text-sm text-muted-foreground">尚无人工验收记录。</p>{/each}
            <div class="flex gap-3 text-sm">{#if data.reviewCursor}<a class="underline" href="?view=result#acceptance">最新验收</a>{/if}{#if data.reviews.data?.next_cursor}<a class="underline" href={`?review_cursor=${encodeURIComponent(data.reviews.data.next_cursor)}#acceptance`}>更早的验收</a>{/if}</div>
          </div>
        </Card.Content>
      </Card.Root>
    </section>
  {/if}
</main>
