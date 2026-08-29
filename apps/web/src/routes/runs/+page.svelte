<script lang="ts">
  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';
  import * as Table from '@zeus/ui/components/ui/table';

  import WorkspaceStatus from '$lib/components/WorkspaceStatus.svelte';

  import type { PageData } from './$types';

  let { data } = $props<{ data: PageData }>();
  let runs = $derived(data.result.data?.items ?? []);

  function dateLabel(value: string | null): string {
    return value ? value.replace('T', ' ').replace(/\.\d+Z$/, ' UTC').replace('Z', ' UTC') : '—';
  }

  function statusVariant(status: string): 'default' | 'secondary' | 'destructive' | 'outline' {
    if (status === 'succeeded') return 'secondary';
    if (status === 'failed' || status === 'canceled') return 'destructive';
    if (status === 'running' || status === 'queued') return 'default';
    return 'outline';
  }
</script>

<svelte:head>
  <title>Zeus · Runs</title>
</svelte:head>

<main class="mx-auto max-w-[1480px] px-5 py-8 lg:px-8 lg:py-10">
  <div class="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
    <div>
      <p class="text-sm font-medium text-muted-foreground">Durable execution</p>
      <h1 class="mt-2 text-3xl font-semibold tracking-tight">Runs</h1>
      <p class="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
        从当前 Workspace 读取运行队列。打开任意 Run 可查看 append-only events、工具调用、审批、usage 和经验注入。
      </p>
    </div>
    {#if data.result.status === 'ready'}
      <Badge variant="secondary">{runs.length} runs</Badge>
    {/if}
  </div>

  {#if data.result.status !== 'ready'}
    <div class="mt-8">
      <WorkspaceStatus status={data.result.status} message={data.result.message} httpStatus={data.result.httpStatus} />
    </div>
  {:else}
    <Card.Root class="mt-8">
      <Card.Header>
        <Card.Title>运行记录</Card.Title>
        <Card.Description>选择一条 Run 进入 Trace 详情。</Card.Description>
      </Card.Header>
      <Card.Content>
        {#if runs.length > 0}
          <Table.Root>
            <Table.Header>
              <Table.Row>
                <Table.Head>Run</Table.Head>
                <Table.Head>状态</Table.Head>
                <Table.Head>WorkItem</Table.Head>
                <Table.Head>创建时间</Table.Head>
                <Table.Head>更新时间</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {#each runs as run (run.id)}
                <Table.Row>
                  <Table.Cell>
                    <a class="font-mono text-xs font-medium hover:underline" href={`/runs/${run.id}`}>{run.id}</a>
                    <p class="mt-1 text-xs text-muted-foreground">attempt {run.attempt_count}</p>
                  </Table.Cell>
                  <Table.Cell><Badge variant={statusVariant(run.status)}>{run.status}</Badge></Table.Cell>
                  <Table.Cell>
                    {#if run.work_item_id}
                      <a class="font-mono text-xs hover:underline" href={`/work-items/${run.work_item_id}`}>{run.work_item_id}</a>
                    {:else}
                      <span class="text-muted-foreground">—</span>
                    {/if}
                  </Table.Cell>
                  <Table.Cell class="text-muted-foreground">{dateLabel(run.created_at)}</Table.Cell>
                  <Table.Cell class="text-muted-foreground">{dateLabel(run.updated_at)}</Table.Cell>
                </Table.Row>
              {/each}
            </Table.Body>
          </Table.Root>
        {:else}
          <div class="rounded-lg border border-dashed border-border px-5 py-12 text-center">
            <h2 class="font-medium">当前没有 Run</h2>
            <p class="mt-2 text-sm text-muted-foreground">API 已连接，但当前 Workspace 没有返回运行记录。</p>
          </div>
        {/if}
        {#if data.result.data?.next_cursor}
          <div class="mt-4 flex justify-end">
            <Button href={`?cursor=${encodeURIComponent(data.result.data.next_cursor)}`} variant="outline" size="sm">下一页</Button>
          </div>
        {/if}
      </Card.Content>
    </Card.Root>
  {/if}
</main>
