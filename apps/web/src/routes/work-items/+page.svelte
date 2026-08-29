<script lang="ts">
  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';
  import { Separator } from '@zeus/ui/components/ui/separator';
  import * as Table from '@zeus/ui/components/ui/table';

  import WorkspaceStatus from '$lib/components/WorkspaceStatus.svelte';

  import type { ActionData, PageData } from './$types';

  let { data, form } = $props<{ data: PageData; form: ActionData }>();
  let items = $derived(data.result.data?.items ?? []);
  let hasWorkspaceData = $derived(data.result.status === 'ready');

  function dateLabel(value: string): string {
    return value.replace('T', ' ').replace(/\.\d+Z$/, ' UTC').replace('Z', ' UTC');
  }

  function statusVariant(status: string): 'default' | 'secondary' | 'destructive' | 'outline' {
    if (status === 'completed') return 'secondary';
    if (status === 'blocked' || status === 'canceled') return 'destructive';
    if (status === 'in_progress') return 'default';
    return 'outline';
  }

  function nextHref(cursor: string): string {
    const params = new URLSearchParams({ cursor });
    if (data.filterStatus) params.set('status', data.filterStatus);
    return `?${params.toString()}`;
  }
</script>

<svelte:head>
  <title>Zeus · WorkItems</title>
</svelte:head>

<main class="mx-auto max-w-[1480px] px-5 py-8 lg:px-8 lg:py-10">
  <div class="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
    <div>
      <p class="text-sm font-medium text-muted-foreground">Workspace work queue</p>
      <h1 class="mt-2 text-3xl font-semibold tracking-tight">WorkItems</h1>
      <p class="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
        从当前 Workspace 读取工作项，创建后可在详情页通过并发安全的 revision 更新状态。
      </p>
    </div>
    {#if hasWorkspaceData}
      <Badge variant="secondary">{items.length} items</Badge>
    {/if}
  </div>

  {#if form?.type === 'error'}
    <div class="mt-6 rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive" role="alert">
      {form.message}
    </div>
  {/if}

  {#if !hasWorkspaceData}
    <div class="mt-8">
      <WorkspaceStatus
        status={data.result.status}
        message={data.result.message}
        httpStatus={data.result.httpStatus}
      />
    </div>
  {:else}
    <div class="mt-8 grid gap-6 xl:grid-cols-[minmax(0,1fr)_22rem]">
      <Card.Root>
        <Card.Header class="flex-row items-start justify-between gap-4">
          <div>
            <Card.Title>工作项列表</Card.Title>
            <Card.Description>只显示 API 返回的真实记录。</Card.Description>
          </div>
          <form method="GET" class="flex items-center gap-2">
            <label class="sr-only" for="status-filter">按状态筛选</label>
            <select
              id="status-filter"
              name="status"
              value={data.filterStatus}
              class="h-9 rounded-md border border-input bg-background px-2 text-sm"
            >
              <option value="">全部状态</option>
              <option value="open">Open</option>
              <option value="in_progress">In progress</option>
              <option value="blocked">Blocked</option>
              <option value="completed">Completed</option>
              <option value="canceled">Canceled</option>
            </select>
            <Button type="submit" variant="outline" size="sm">筛选</Button>
          </form>
        </Card.Header>
        <Card.Content>
          {#if items.length > 0}
            <Table.Root>
              <Table.Header>
                <Table.Row>
                  <Table.Head>标题</Table.Head>
                  <Table.Head>状态</Table.Head>
                  <Table.Head>优先级</Table.Head>
                  <Table.Head>更新时间</Table.Head>
                </Table.Row>
              </Table.Header>
              <Table.Body>
                {#each items as item (item.id)}
                  <Table.Row>
                    <Table.Cell>
                      <a class="font-medium hover:underline" href={`/work-items/${item.id}`}>{item.title}</a>
                      {#if item.description}
                        <p class="mt-1 max-w-md truncate text-xs text-muted-foreground">{item.description}</p>
                      {/if}
                    </Table.Cell>
                    <Table.Cell><Badge variant={statusVariant(item.status)}>{item.status}</Badge></Table.Cell>
                    <Table.Cell class="text-muted-foreground">{item.priority}</Table.Cell>
                    <Table.Cell class="text-muted-foreground">{dateLabel(item.updated_at)}</Table.Cell>
                  </Table.Row>
                {/each}
              </Table.Body>
            </Table.Root>
          {:else}
            <div class="rounded-lg border border-dashed border-border px-5 py-12 text-center">
              <h2 class="font-medium">当前没有 WorkItem</h2>
              <p class="mt-2 text-sm text-muted-foreground">API 已连接，可以从右侧创建第一条工作项。</p>
            </div>
          {/if}
          {#if data.result.data?.next_cursor}
            <div class="mt-4 flex justify-end">
              <Button href={nextHref(data.result.data.next_cursor)} variant="outline" size="sm">下一页</Button>
            </div>
          {/if}
        </Card.Content>
      </Card.Root>

      <Card.Root id="new">
        <Card.Header>
          <Card.Title>新建 WorkItem</Card.Title>
          <Card.Description>创建请求会自动附带 Idempotency-Key。</Card.Description>
        </Card.Header>
        <Card.Content>
          <form method="POST" action="?/create" class="space-y-4">
            <div>
              <label class="text-sm font-medium" for="title">标题</label>
              <input id="title" name="title" required class="mt-2 h-10 w-full rounded-md border border-input bg-background px-3 text-sm" />
            </div>
            <div>
              <label class="text-sm font-medium" for="description">描述</label>
              <textarea id="description" name="description" rows="3" class="mt-2 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"></textarea>
            </div>
            <div class="grid gap-3 sm:grid-cols-2 xl:grid-cols-1">
              <div>
                <label class="text-sm font-medium" for="priority">优先级</label>
                <select id="priority" name="priority" value="normal" class="mt-2 h-10 w-full rounded-md border border-input bg-background px-3 text-sm">
                  <option value="low">Low</option>
                  <option value="normal">Normal</option>
                  <option value="high">High</option>
                  <option value="urgent">Urgent</option>
                </select>
              </div>
              <div>
                <label class="text-sm font-medium" for="assignee_user_id">Assignee user ID</label>
                <input id="assignee_user_id" name="assignee_user_id" placeholder="可选 UUID" class="mt-2 h-10 w-full rounded-md border border-input bg-background px-3 text-sm" />
              </div>
            </div>
            <Separator />
            <div>
              <label class="text-sm font-medium" for="source_kind">来源类型</label>
              <input id="source_kind" name="source_kind" placeholder="可选" class="mt-2 h-10 w-full rounded-md border border-input bg-background px-3 text-sm" />
            </div>
            <div>
              <label class="text-sm font-medium" for="external_reference">外部引用</label>
              <input id="external_reference" name="external_reference" placeholder="可选" class="mt-2 h-10 w-full rounded-md border border-input bg-background px-3 text-sm" />
            </div>
            <div>
              <label class="text-sm font-medium" for="input">Input JSON</label>
              <textarea id="input" name="input" rows="4" class="mt-2 w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-xs">&#123;&#125;</textarea>
            </div>
            <Button type="submit" class="w-full">创建 WorkItem</Button>
          </form>
        </Card.Content>
      </Card.Root>
    </div>
  {/if}
</main>
