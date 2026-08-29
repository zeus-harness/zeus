<script lang="ts">
  import { Badge } from '@zeus/ui/components/ui/badge';
  import * as Card from '@zeus/ui/components/ui/card';
  import { Separator } from '@zeus/ui/components/ui/separator';
  import * as Table from '@zeus/ui/components/ui/table';

  import WorkspaceStatus from '$lib/components/WorkspaceStatus.svelte';

  import type { PageData } from './$types';

  let { data } = $props<{ data: PageData }>();
  let trace = $derived(data.trace.data);
  let childRuns = $derived(data.childRuns.data ?? []);

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
    <div class="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
      <div>
        <a class="text-sm text-muted-foreground hover:underline" href="/runs">← 返回 Runs</a>
        <p class="mt-4 text-sm font-medium text-muted-foreground">Durable execution trace</p>
        <h1 class="mt-2 break-all text-3xl font-semibold tracking-tight">{trace.run.id}</h1>
        <p class="mt-2 font-mono text-xs text-muted-foreground">Session {trace.run.session_id}</p>
      </div>
      <Badge variant={statusVariant(trace.run.status)}>{trace.run.status}</Badge>
    </div>

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

    <div class="mt-8 grid gap-6 xl:grid-cols-2">
      <Card.Root>
        <Card.Header>
          <Card.Title>Events</Card.Title>
          <Card.Description>Run events and session events are the durable trace.</Card.Description>
        </Card.Header>
        <Card.Content class="space-y-6">
          <div>
            <div class="mb-3 flex items-baseline justify-between gap-3">
              <h2 class="text-sm font-semibold">Run events <span class="text-muted-foreground">({trace.run_events.length})</span></h2>
            </div>
            {#if trace.run_events.length > 0}
              <div class="space-y-2">
                {#each trace.run_events as event (event.id)}
                  <details class="rounded-lg border border-border p-3">
                    <summary class="flex cursor-pointer list-none items-center justify-between gap-3 text-sm">
                      <span><span class="font-mono text-xs text-muted-foreground">#{event.sequence}</span> {event.event_type}</span>
                      <span class="text-xs text-muted-foreground">{dateLabel(event.occurred_at)}</span>
                    </summary>
                    <pre class="mt-3 max-h-56 overflow-auto rounded bg-muted p-3 font-mono text-xs leading-5">{formatJson(event.payload)}</pre>
                  </details>
                {/each}
              </div>
            {:else}
              <p class="text-sm text-muted-foreground">暂无 Run events。</p>
            {/if}
          </div>
          <Separator />
          <div>
            <h2 class="mb-3 text-sm font-semibold">Session events <span class="text-muted-foreground">({trace.session_events.length})</span></h2>
            {#if trace.session_events.length > 0}
              <div class="space-y-2">
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
              <p class="text-sm text-muted-foreground">暂无 Session events。</p>
            {/if}
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
                      <a class="font-mono text-primary hover:underline" href={`/runs/${call.child_run_id}`}>Child Run {call.child_run_id}</a>
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
          <Card.Title>Approvals</Card.Title>
          <Card.Description>该 Run 关联的审批记录。</Card.Description>
        </Card.Header>
        <Card.Content>
          {#if trace.approvals.length > 0}
            <Table.Root>
              <Table.Header><Table.Row><Table.Head>Approval</Table.Head><Table.Head>状态</Table.Head><Table.Head>Requested</Table.Head><Table.Head>Decision</Table.Head></Table.Row></Table.Header>
              <Table.Body>
                {#each trace.approvals as approval (approval.id)}
                  <Table.Row>
                    <Table.Cell class="font-mono text-xs">{approval.id}</Table.Cell>
                    <Table.Cell><Badge variant={statusVariant(approval.status)}>{approval.status}</Badge></Table.Cell>
                    <Table.Cell class="text-xs text-muted-foreground">{dateLabel(approval.requested_at)}</Table.Cell>
                    <Table.Cell class="text-xs text-muted-foreground">{dateLabel(approval.decided_at)}</Table.Cell>
                  </Table.Row>
                {/each}
              </Table.Body>
            </Table.Root>
          {:else}
            <p class="text-sm text-muted-foreground">暂无 Approvals。</p>
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
                <a class="flex items-center justify-between gap-3 rounded-lg border border-border p-3 hover:bg-muted" href={`/runs/${linked.run_id}`}>
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
                    <Table.Cell><a class="font-mono text-xs hover:underline" href={`/experience?entry=${injection.experience_entry_id}`}>{injection.experience_entry_id}</a></Table.Cell>
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
                      <Table.Cell><a class="font-mono text-xs hover:underline" href={`/runs/${child.id}`}>{child.id}</a></Table.Cell>
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
