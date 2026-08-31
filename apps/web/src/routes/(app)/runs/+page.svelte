<script lang="ts">
  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';
  import { Input } from '@zeus/ui/components/ui/input';
  import { Label } from '@zeus/ui/components/ui/label';
  import { NativeSelect, NativeSelectOption } from '@zeus/ui/components/ui/native-select';
  import * as Table from '@zeus/ui/components/ui/table';

  import EmptyState from '$lib/components/layout/EmptyState.svelte';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
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

  function nextHref(cursor: string): string {
    const params = new URLSearchParams({ cursor });
    if (data.filterStatus) params.set('status', data.filterStatus);
    if (data.filterWorkItemId) params.set('work_item_id', data.filterWorkItemId);
    return `?${params.toString()}`;
  }
</script>

<svelte:head>
  <title>Zeus · Runs</title>
</svelte:head>

<main class="mx-auto max-w-[1480px] px-5 py-8 lg:px-8 lg:py-10">
  <PageHeader eyebrow="Durable execution" title="运行" description="观察 Agent 状态、工具调用、审批和最终结果。">
    {#snippet actions()}
    {#if data.result.status === 'ready'}
        <Badge variant="secondary">{runs.length} 条</Badge>
    {/if}
    {/snippet}
  </PageHeader>

  {#if data.result.status !== 'ready'}
    <div class="mt-8">
      <WorkspaceStatus status={data.result.status} message={data.result.message} httpStatus={data.result.httpStatus} />
    </div>
  {:else}
    <Card.Root class="mt-8">
      <Card.Header class="gap-4 border-b border-border">
        <form method="GET" class="grid gap-3 sm:grid-cols-[12rem_minmax(16rem,1fr)_auto] sm:items-end">
          <div class="space-y-2">
            <Label for="run-status">状态</Label>
            <NativeSelect id="run-status" name="status" value={data.filterStatus} class="w-full">
              <NativeSelectOption value="">全部状态</NativeSelectOption>
              <NativeSelectOption value="queued">Queued</NativeSelectOption>
              <NativeSelectOption value="running">Running</NativeSelectOption>
              <NativeSelectOption value="waiting_approval">Waiting approval</NativeSelectOption>
              <NativeSelectOption value="waiting_child">Waiting child</NativeSelectOption>
              <NativeSelectOption value="succeeded">Succeeded</NativeSelectOption>
              <NativeSelectOption value="failed">Failed</NativeSelectOption>
              <NativeSelectOption value="canceled">Canceled</NativeSelectOption>
            </NativeSelect>
          </div>
          <div class="space-y-2"><Label for="work-item-filter">WorkItem ID</Label><Input id="work-item-filter" name="work_item_id" value={data.filterWorkItemId} placeholder="留空查看全部运行" /></div>
          <Button type="submit" variant="outline">筛选</Button>
        </form>
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
          <EmptyState title="没有符合条件的运行" description="从 WorkItem 详情启动 Agent，或调整筛选条件。" />
        {/if}
        {#if data.result.data?.next_cursor}
          <div class="mt-4 flex justify-end">
            <Button href={nextHref(data.result.data.next_cursor)} variant="outline" size="sm">下一页</Button>
          </div>
        {/if}
      </Card.Content>
    </Card.Root>
  {/if}
</main>
