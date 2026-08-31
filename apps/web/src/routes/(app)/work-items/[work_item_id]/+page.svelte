<script lang="ts">
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
  let item = $derived(data.result.data);
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

<svelte:head><title>Zeus · {item?.title ?? '工作项详情'}</title></svelte:head>

<main class="px-5 py-7 lg:px-8 lg:py-9">
  {#if data.result.status !== 'ready' || !item}
    <WorkspaceStatus status={data.result.status} message={data.result.message} httpStatus={data.result.httpStatus} title="工作项详情" />
  {:else}
    <a class="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground" href="/work-items"><ArrowLeft class="size-4" />返回工作项</a>
    <header class="mt-5 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
      <div class="min-w-0">
        <div class="flex flex-wrap items-center gap-2"><Badge variant={statusVariant(item.status)}>{item.status}</Badge><Badge variant="outline" class="capitalize">{item.priority}</Badge></div>
        <h1 class="mt-3 text-2xl font-semibold tracking-tight sm:text-3xl">{item.title}</h1>
        <p class="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">{item.description || '没有补充描述。'}</p>
      </div>
      <div class="flex items-center gap-2 text-sm text-muted-foreground"><UserRound class="size-4" />{item.assignee_user_id ?? '未分配'}</div>
    </header>

    {#if form?.type === 'error'}
      <Alert.Root variant="destructive" class="mt-6"><Alert.Title>操作未完成</Alert.Title><Alert.Description>{form.message}</Alert.Description></Alert.Root>
    {/if}

    <div class="mt-7 grid gap-6 xl:grid-cols-[minmax(0,1fr)_22rem]">
      <Tabs.Root value="activity" class="min-w-0">
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
                          <Table.Cell><a class="font-medium hover:underline" href={`/runs/${run.id}`}>查看时间线</a><p class="mt-1 font-mono text-[0.6875rem] text-muted-foreground">{run.id}</p></Table.Cell>
                          <Table.Cell><Badge variant={statusVariant(run.status)}>{run.status}</Badge></Table.Cell>
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
                  <a class="flex items-center justify-between gap-4 rounded-lg border border-border p-3 hover:bg-accent" href={`/runs/${approval.run_id}`}>
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
              <div><dt class="text-xs font-medium text-muted-foreground">负责人</dt><dd class="mt-1 break-all text-sm">{item.assignee_user_id ?? '未分配'}</dd></div>
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
          <Card.Root><Card.Header><Card.Title>最终结果</Card.Title><Card.Description>优先显示 WorkItem output，否则显示最近成功 Run 的 output。</Card.Description></Card.Header><Card.Content>
            {#if latestResult}<pre class="max-h-[32rem] overflow-auto rounded-lg bg-muted p-4 font-mono text-xs leading-5">{formatJson(latestResult)}</pre>{:else}<EmptyState title="还没有结果" description="Agent 完成一次关联运行后，结果会显示在这里。" />{/if}
          </Card.Content></Card.Root>
        </Tabs.Content>
      </Tabs.Root>

      <aside class="space-y-5">
        <Card.Root>
          <Card.Header><Card.Title class="flex items-center gap-2"><Bot class="size-4" />启动 Agent</Card.Title><Card.Description>创建关联 Session 和 Run。请求使用幂等键。</Card.Description></Card.Header>
          <Card.Content>
            {#if data.workflows.status !== 'ready'}
              <p class="text-sm text-destructive">{data.workflows.message}</p>
            {:else if activeWorkflows.length === 0}
              <EmptyState title="没有可运行的 Workflow" description="先在 Agent 构建区创建版本并激活。">
                {#snippet action()}<Button href="/admin/workflows" variant="outline" size="sm">打开 Workflows</Button>{/snippet}
              </EmptyState>
            {:else}
              <form method="POST" action="?/start" class="space-y-4">
                <div class="space-y-2"><Label for="workflow_id">Workflow</Label><NativeSelect id="workflow_id" name="workflow_id" required class="w-full"><NativeSelectOption value="" disabled selected>选择 Workflow</NativeSelectOption>{#each activeWorkflows as workflow (workflow.id)}<NativeSelectOption value={workflow.id}>{workflow.name}</NativeSelectOption>{/each}</NativeSelect></div>
                <div class="space-y-2"><Label for="message">给 Agent 的消息</Label><Textarea id="message" name="message" rows={4} placeholder="说明这次运行要完成的动作" /></div>
                <div class="space-y-2"><Label for="input">Run input JSON</Label><Textarea id="input" name="input" rows={5} class="font-mono text-xs" value={formatJson(item.input)} /></div>
                <Button type="submit" class="w-full"><Play class="size-4" />启动运行</Button>
              </form>
            {/if}
          </Card.Content>
        </Card.Root>

        <Card.Root>
          <Card.Header><Card.Title>更新状态</Card.Title><Card.Description>使用 revision 防止覆盖协作者更新。</Card.Description></Card.Header>
          <Card.Content><form method="POST" action="?/update" class="space-y-4"><input type="hidden" name="revision" value={item.revision} /><div class="space-y-2"><Label for="status">状态</Label><NativeSelect id="status" name="status" value={item.status} class="w-full"><NativeSelectOption value="open">Open</NativeSelectOption><NativeSelectOption value="in_progress">In progress</NativeSelectOption><NativeSelectOption value="blocked">Blocked</NativeSelectOption><NativeSelectOption value="completed">Completed</NativeSelectOption><NativeSelectOption value="canceled">Canceled</NativeSelectOption></NativeSelect></div><Button type="submit" variant="outline" class="w-full">保存状态</Button></form></Card.Content>
        </Card.Root>
      </aside>
    </div>
  {/if}
</main>
