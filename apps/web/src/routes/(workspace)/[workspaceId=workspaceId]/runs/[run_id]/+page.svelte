<script lang="ts">
  import { invalidateAll } from '$app/navigation';
  import { onDestroy } from 'svelte';
  import { ArrowLeft, RotateCcw, Square } from '@lucide/svelte';

  import * as Alert from '@zeus/ui/components/ui/alert';
  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';
  import { Input } from '@zeus/ui/components/ui/input';
  import { Separator } from '@zeus/ui/components/ui/separator';
  import * as Table from '@zeus/ui/components/ui/table';

  import EmptyState from '$lib/components/layout/EmptyState.svelte';
  import RunTimeline from '$lib/features/runs/RunTimeline.svelte';
  import WorkspaceStatus from '$lib/components/WorkspaceStatus.svelte';
  import type { Approval } from '$lib/api/runs';

  import type { ActionData, PageData } from './$types';

  let { data, form } = $props<{ data: PageData; form: ActionData }>();
  let trace = $derived(data.trace.data);
  let workspaceBase = $derived(`/${data.workspaceId}`);
  let childRuns = $derived(data.childRuns.data ?? []);
  let pendingApprovals = $derived(
    trace?.approvals.filter((approval: Approval) => approval.status === 'pending') ?? []
  );
  let canCancel = $derived(
    trace ? ['queued', 'running', 'waiting_approval', 'waiting_child'].includes(trace.run.status) : false
  );
  let canRetry = $derived(trace ? ['failed', 'canceled'].includes(trace.run.status) : false);
  let snapshotRefreshTimer: ReturnType<typeof setTimeout> | null = null;

  function scheduleSnapshotRefresh(): void {
    if (snapshotRefreshTimer !== null) clearTimeout(snapshotRefreshTimer);
    snapshotRefreshTimer = setTimeout(() => {
      snapshotRefreshTimer = null;
      void invalidateAll();
    }, 100);
  }

  onDestroy(() => {
    if (snapshotRefreshTimer !== null) clearTimeout(snapshotRefreshTimer);
  });

  function dateLabel(value: string | null): string {
    return value ? value.replace('T', ' ').replace(/\.\d+Z$/, ' UTC').replace('Z', ' UTC') : '—';
  }

  function formatJson(value: unknown): string {
    try {
      return JSON.stringify(value, null, 2) ?? '—';
    } catch {
      return '—';
    }
  }

  function statusVariant(status: string): 'default' | 'secondary' | 'destructive' | 'outline' {
    if (status === 'succeeded' || status === 'approved' || status === 'completed') return 'secondary';
    if (status === 'failed' || status === 'rejected' || status === 'canceled' || status === 'denied') {
      return 'destructive';
    }
    if (status === 'running' || status === 'queued' || status === 'pending') return 'default';
    return 'outline';
  }
</script>

<svelte:head>
  <title>Zeus · Run Trace</title>
</svelte:head>

<main class="mx-auto max-w-[1480px] px-5 py-8 lg:px-8 lg:py-10">
  {#if data.trace.status !== 'ready' || !trace}
    <WorkspaceStatus
      status={data.trace.status}
      message={data.trace.message}
      httpStatus={data.trace.httpStatus}
      title="Run Trace"
    />
  {:else}
    <a class="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground" href={`${workspaceBase}/runs`}><ArrowLeft class="size-4" />返回运行</a>
    <div class="mt-5 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
      <div class="min-w-0">
        <div class="flex flex-wrap items-center gap-2">
          <Badge variant={statusVariant(trace.run.status)}>{trace.run.status}</Badge>
          <span class="text-xs text-muted-foreground">attempt {trace.run.attempt_count}</span>
        </div>
        <h1 class="mt-3 text-2xl font-semibold tracking-tight sm:text-3xl">Agent 运行</h1>
        {#if trace.run.work_item_id}
          <a class="mt-2 inline-flex text-sm text-primary hover:underline" href={`${workspaceBase}/work-items/${trace.run.work_item_id}`}>返回关联 WorkItem</a>
        {:else}
          <p class="mt-2 text-sm text-muted-foreground">该 Run 没有关联 WorkItem。</p>
        {/if}
        <details class="mt-3 text-xs text-muted-foreground">
          <summary class="cursor-pointer">内部标识</summary>
          <p class="mt-2 break-all font-mono">Run {trace.run.id}</p>
          <p class="mt-1 break-all font-mono">Session {trace.run.session_id}</p>
        </details>
      </div>
      <div class="flex flex-col gap-2 sm:min-w-64">
        {#if canCancel}
          <form method="POST" action="?/cancel" class="flex gap-2">
            <Input name="reason" aria-label="取消原因" placeholder="取消原因（可选）" />
            <Button type="submit" variant="destructive"><Square class="size-4" />取消</Button>
          </form>
        {:else if canRetry}
          <form method="POST" action="?/retry">
            <Button type="submit" variant="outline" class="w-full"><RotateCcw class="size-4" />创建重试 Run</Button>
          </form>
        {/if}
      </div>
    </div>

    {#if form?.type === 'error'}
      <Alert.Root variant="destructive" class="mt-6" role="alert">
        <Alert.Title>操作未完成</Alert.Title>
        <Alert.Description>{form.message}</Alert.Description>
      </Alert.Root>
    {/if}

    <section class="mt-8 grid gap-4 sm:grid-cols-2 xl:grid-cols-5" aria-label="Run 摘要">
      <Card.Root size="sm">
        <Card.Header><Card.Description>状态</Card.Description><Card.Title>{trace.run.status}</Card.Title></Card.Header>
      </Card.Root>
      <Card.Root size="sm">
        <Card.Header><Card.Description>Attempts</Card.Description><Card.Title>{trace.run.attempt_count}</Card.Title></Card.Header>
      </Card.Root>
      <Card.Root size="sm">
        <Card.Header><Card.Description>Run events</Card.Description><Card.Title>{trace.run_events.length}</Card.Title></Card.Header>
      </Card.Root>
      <Card.Root size="sm">
        <Card.Header><Card.Description>Tool calls</Card.Description><Card.Title>{trace.tool_calls.length}</Card.Title></Card.Header>
      </Card.Root>
      <Card.Root size="sm">
        <Card.Header><Card.Description>Child runs</Card.Description><Card.Title>{childRuns.length}</Card.Title></Card.Header>
      </Card.Root>
    </section>

    {#if trace.run.error_code || trace.run.error_detail}
      <section class="mt-6 rounded-xl border border-destructive/40 bg-destructive/10 p-4" aria-label="Run error">
        <p class="text-sm font-semibold text-destructive">Run error {trace.run.error_code ?? ''}</p>
        {#if trace.run.error_detail}
          <p class="mt-2 text-sm leading-6 text-destructive/90">{trace.run.error_detail}</p>
        {/if}
      </section>
    {/if}

    {#if trace.run.output !== null && trace.run.output !== undefined}
      <Card.Root class="mt-6">
        <Card.Header>
          <Card.Title>运行结果</Card.Title>
          <Card.Description>这是该 Run 已持久化的最终输出。</Card.Description>
        </Card.Header>
        <Card.Content>
          <pre class="max-h-[32rem] overflow-auto rounded-lg bg-muted p-4 font-mono text-xs leading-5">{formatJson(trace.run.output)}</pre>
        </Card.Content>
      </Card.Root>
    {:else if ['succeeded', 'failed', 'canceled'].includes(trace.run.status)}
      <div class="mt-6"><EmptyState title="Run 已结束，但没有输出" description="检查错误信息和事件时间线，确认终态原因。" /></div>
    {/if}

    <div class="mt-8 grid gap-6 xl:grid-cols-2">
      <Card.Root>
        <Card.Header>
          <Card.Title>运行时间线</Card.Title>
          <Card.Description>先显示持久快照，再通过 SSE 追加事件。</Card.Description>
        </Card.Header>
        <Card.Content class="space-y-6">
          <RunTimeline
            initialEvents={trace.run_events}
            initialStatus={trace.run.status}
            streamUrl={data.streamUrl}
            onSnapshotChange={scheduleSnapshotRefresh}
          />
          <Separator />
          <div>
            <details>
              <summary class="cursor-pointer text-sm font-medium">查看模型上下文事件（{trace.session_events.length}）</summary>
              {#if trace.session_events.length > 0}
                <div class="mt-3 space-y-2">
                  {#each trace.session_events as event (event.id)}
                    <details class="rounded-lg border border-border p-3">
                      <summary class="flex cursor-pointer list-none items-center justify-between gap-3 text-sm">
                        <span><span class="font-mono text-xs text-muted-foreground">#{event.sequence}</span> {event.event_type}</span>
                        <span class="text-xs text-muted-foreground">{dateLabel(event.occurred_at)}</span>
                      </summary>
                      <p class="mt-2 text-xs text-muted-foreground">actor: {event.actor_kind} {event.actor_id ?? ''}</p>
                      <pre class="mt-3 max-h-56 overflow-auto rounded bg-muted p-3 font-mono text-xs leading-5">{formatJson(event.payload)}</pre>
                    </details>
                  {/each}
                </div>
              {:else}
                <p class="mt-3 text-sm text-muted-foreground">暂无 Session events。</p>
              {/if}
            </details>
          </div>
        </Card.Content>
      </Card.Root>

      <Card.Root>
        <Card.Header>
          <Card.Title>Tool calls</Card.Title>
          <Card.Description>工具输入、结果、错误和关联的 Child Run。</Card.Description>
        </Card.Header>
        <Card.Content>
          {#if trace.tool_calls.length > 0}
            <div class="space-y-3">
              {#each trace.tool_calls as call (call.id)}
                <details class="rounded-lg border border-border p-3">
                  <summary class="flex cursor-pointer list-none items-center justify-between gap-3">
                    <span class="min-w-0 truncate text-sm font-medium">{call.call_key}</span>
                    <Badge variant={statusVariant(call.status)}>{call.status}</Badge>
                  </summary>
                  <div class="mt-3 space-y-3 text-xs">
                    <p class="font-mono text-muted-foreground">Capability {call.capability_id}</p>
                    {#if call.child_run_id}
                      <a class="font-mono text-primary hover:underline" href={`${workspaceBase}/runs/${call.child_run_id}`}>Child Run {call.child_run_id}</a>
                    {/if}
                    <div>
                      <p class="font-semibold">Input</p>
                      <pre class="mt-1 max-h-40 overflow-auto rounded bg-muted p-2 font-mono leading-5">{formatJson(call.input)}</pre>
                    </div>
                    {#if call.result !== null}
                      <div>
                        <p class="font-semibold">Result</p>
                        <pre class="mt-1 max-h-40 overflow-auto rounded bg-muted p-2 font-mono leading-5">{formatJson(call.result)}</pre>
                      </div>
                    {/if}
                    {#if call.error_code}
                      <p class="text-destructive">{call.error_code}</p>
                    {/if}
                  </div>
                </details>
              {/each}
            </div>
          {:else}
            <p class="text-sm text-muted-foreground">暂无 Tool calls。</p>
          {/if}
        </Card.Content>
      </Card.Root>

      <Card.Root>
        <Card.Header>
          <Card.Title>审批</Card.Title>
          <Card.Description>{pendingApprovals.length} 条等待处理。HTTP 结果决定最终状态。</Card.Description>
        </Card.Header>
        <Card.Content>
          {#if trace.approvals.length > 0}
            <div class="space-y-3">
              {#each trace.approvals as approval (approval.id)}
                <div class="rounded-lg border border-border p-4">
                  <div class="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <p class="text-sm font-medium">工具调用审批</p>
                      <p class="mt-1 font-mono text-xs text-muted-foreground">{approval.tool_call_id}</p>
                      <p class="mt-1 text-xs text-muted-foreground">请求于 {dateLabel(approval.requested_at)}</p>
                    </div>
                    <Badge variant={statusVariant(approval.status)}>{approval.status}</Badge>
                  </div>
                  {#if approval.reason}<p class="mt-3 text-sm text-muted-foreground">{approval.reason}</p>{/if}
                  {#if approval.status === 'pending'}
                    <div class="mt-4 grid gap-2 sm:grid-cols-2">
                      <form method="POST" action="?/decide" class="space-y-2">
                        <input type="hidden" name="approval_id" value={approval.id} />
                        <input type="hidden" name="decision" value="approve" />
                        <Input name="reason" aria-label="批准理由" placeholder="批准理由（可选）" />
                        <Button type="submit" class="min-h-11 w-full">批准</Button>
                      </form>
                      <form method="POST" action="?/decide" class="space-y-2">
                        <input type="hidden" name="approval_id" value={approval.id} />
                        <input type="hidden" name="decision" value="reject" />
                        <Input name="reason" aria-label="拒绝理由" placeholder="拒绝理由（可选）" />
                        <Button type="submit" variant="destructive" class="min-h-11 w-full">拒绝</Button>
                      </form>
                    </div>
                  {/if}
                </div>
              {/each}
            </div>
          {:else}
            <EmptyState title="没有审批请求" description="该 Run 尚未触发需要人工决定的 Capability。" />
          {/if}
        </Card.Content>
      </Card.Root>

      <Card.Root>
        <Card.Header>
          <Card.Title>Usage</Card.Title>
          <Card.Description>模型 token 使用摘要和每次 provider request。</Card.Description>
        </Card.Header>
        <Card.Content class="space-y-4">
          <div class="grid grid-cols-3 gap-3">
            <div class="rounded-lg bg-muted p-3"><p class="text-xs text-muted-foreground">Prompt</p><p class="mt-1 text-lg font-semibold">{trace.usage.prompt_tokens}</p></div>
            <div class="rounded-lg bg-muted p-3"><p class="text-xs text-muted-foreground">Completion</p><p class="mt-1 text-lg font-semibold">{trace.usage.completion_tokens}</p></div>
            <div class="rounded-lg bg-muted p-3"><p class="text-xs text-muted-foreground">Cache</p><p class="mt-1 text-lg font-semibold">{trace.usage.cache_tokens}</p></div>
          </div>
          {#if trace.usage.entries.length > 0}
            <Table.Root>
              <Table.Header><Table.Row><Table.Head>Provider request</Table.Head><Table.Head>Prompt</Table.Head><Table.Head>Completion</Table.Head><Table.Head>Cache</Table.Head></Table.Row></Table.Header>
              <Table.Body>
                {#each trace.usage.entries as entry (entry.id)}
                  <Table.Row>
                    <Table.Cell class="max-w-48 truncate font-mono text-xs" title={entry.provider_request_id}>{entry.provider_request_id}</Table.Cell>
                    <Table.Cell>{entry.prompt_tokens}</Table.Cell><Table.Cell>{entry.completion_tokens}</Table.Cell><Table.Cell>{entry.cache_tokens}</Table.Cell>
                  </Table.Row>
                {/each}
              </Table.Body>
            </Table.Root>
          {:else}
            <p class="text-sm text-muted-foreground">暂无 Usage entries。</p>
          {/if}
        </Card.Content>
      </Card.Root>

      <Card.Root>
        <Card.Header>
          <Card.Title>Linked runs</Card.Title>
          <Card.Description>父子关系及其他 Run link。</Card.Description>
        </Card.Header>
        <Card.Content>
          {#if trace.linked_runs.length > 0}
            <div class="space-y-2">
              {#each trace.linked_runs as linked (linked.run_id)}
                <a class="flex items-center justify-between gap-3 rounded-lg border border-border p-3 hover:bg-muted" href={`${workspaceBase}/runs/${linked.run_id}`}>
                  <span><span class="font-mono text-xs">{linked.run_id}</span><span class="ml-2 text-xs text-muted-foreground">{linked.relation}</span></span>
                  <Badge variant={statusVariant(linked.status)}>{linked.status}</Badge>
                </a>
              {/each}
            </div>
          {:else}
            <p class="text-sm text-muted-foreground">暂无 Linked runs。</p>
          {/if}
        </Card.Content>
      </Card.Root>

      <Card.Root>
        <Card.Header>
          <Card.Title>Experience injections</Card.Title>
          <Card.Description>该 Run 实际注入上下文的经验条目。</Card.Description>
        </Card.Header>
        <Card.Content>
          {#if trace.experience_injections.length > 0}
            <Table.Root>
              <Table.Header><Table.Row><Table.Head>Entry</Table.Head><Table.Head>Version</Table.Head><Table.Head>Rank</Table.Head><Table.Head>Injected</Table.Head></Table.Row></Table.Header>
              <Table.Body>
                {#each trace.experience_injections as injection (injection.id)}
                  <Table.Row>
                    <Table.Cell><a class="font-mono text-xs hover:underline" href={`${workspaceBase}/experience?entry=${injection.experience_entry_id}`}>{injection.experience_entry_id}</a></Table.Cell>
                    <Table.Cell>{injection.experience_version}</Table.Cell>
                    <Table.Cell>{injection.rank.toFixed(4)}</Table.Cell>
                    <Table.Cell class="text-xs text-muted-foreground">{dateLabel(injection.injected_at)}</Table.Cell>
                  </Table.Row>
                {/each}
              </Table.Body>
            </Table.Root>
          {:else}
            <p class="text-sm text-muted-foreground">暂无 Experience injections。</p>
          {/if}
        </Card.Content>
      </Card.Root>
    </div>

    <section class="mt-6" aria-label="Child Runs">
      {#if data.childRuns.status !== 'ready'}
        <WorkspaceStatus
          status={data.childRuns.status}
          message={data.childRuns.message}
          httpStatus={data.childRuns.httpStatus}
          title="Child Runs"
        />
      {:else}
        <Card.Root>
          <Card.Header>
            <Card.Title>Child Runs</Card.Title>
            <Card.Description>通过 `builtin.child_run` 创建并关联到当前 Run 的子运行。</Card.Description>
          </Card.Header>
          <Card.Content>
            {#if childRuns.length > 0}
              <Table.Root>
                <Table.Header><Table.Row><Table.Head>Run</Table.Head><Table.Head>状态</Table.Head><Table.Head>Depth</Table.Head><Table.Head>Token budget</Table.Head><Table.Head>Created</Table.Head><Table.Head>Finished</Table.Head></Table.Row></Table.Header>
                <Table.Body>
                  {#each childRuns as child (child.id)}
                    <Table.Row>
                      <Table.Cell><a class="font-mono text-xs hover:underline" href={`${workspaceBase}/runs/${child.id}`}>{child.id}</a></Table.Cell>
                      <Table.Cell><Badge variant={statusVariant(child.status)}>{child.status}</Badge></Table.Cell>
                      <Table.Cell>{child.depth}</Table.Cell>
                      <Table.Cell>{child.token_budget}</Table.Cell>
                      <Table.Cell class="text-xs text-muted-foreground">{dateLabel(child.created_at)}</Table.Cell>
                      <Table.Cell class="text-xs text-muted-foreground">{dateLabel(child.finished_at)}</Table.Cell>
                    </Table.Row>
                  {/each}
                </Table.Body>
              </Table.Root>
            {:else}
              <p class="text-sm text-muted-foreground">当前 Run 没有 Child Runs。</p>
            {/if}
          </Card.Content>
        </Card.Root>
      {/if}
    </section>
  {/if}
</main>
