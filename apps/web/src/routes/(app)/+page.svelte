<script lang="ts">
  import { ArrowRight, CircleAlert, Clock3, ListChecks, PlayCircle } from '@lucide/svelte';

  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';
  import * as Table from '@zeus/ui/components/ui/table';

  import EmptyState from '$lib/components/layout/EmptyState.svelte';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import WorkspaceStatus from '$lib/components/WorkspaceStatus.svelte';
  import type { WorkItem } from '$lib/api/work-items';
  import type { PageData } from './$types';

  let { data } = $props<{ data: PageData }>();
  let myOpenItems = $derived(
    (data.myWorkItems.data?.items ?? []).filter(
      (item: WorkItem) => item.status !== 'completed' && item.status !== 'canceled'
    )
  );
  let blockedItems = $derived(data.blockedWorkItems.data?.items ?? []);
  let pendingApprovals = $derived(data.approvals.data ?? []);
  let recentRuns = $derived(data.recentRuns.data?.items ?? []);
  let workspaceReady = $derived(data.myWorkItems.status === 'ready');

  function dateLabel(value: string): string {
    return new Intl.DateTimeFormat('zh-CN', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    }).format(new Date(value));
  }

  function statusVariant(status: string): 'default' | 'secondary' | 'destructive' | 'outline' {
    if (status === 'succeeded' || status === 'completed') return 'secondary';
    if (status === 'failed' || status === 'blocked' || status === 'canceled') return 'destructive';
    if (status === 'running' || status === 'in_progress') return 'default';
    return 'outline';
  }
</script>

<svelte:head><title>Zeus · Workspace 工作台</title></svelte:head>

<main class="px-5 py-7 lg:px-8 lg:py-9">
  <PageHeader
    eyebrow="Workspace"
    title="工作台"
    description="把待办、阻塞、审批和最近运行放在同一条工作线上。"
  >
    {#snippet actions()}
      <Button href="/work-items?create=1">新建工作项</Button>
    {/snippet}
  </PageHeader>

  {#if !workspaceReady}
    <div class="mt-7">
      <WorkspaceStatus
        status={data.myWorkItems.status}
        message={data.myWorkItems.message}
        httpStatus={data.myWorkItems.httpStatus}
      />
    </div>
  {:else}
    <section class="mt-7 grid gap-4 sm:grid-cols-2 xl:grid-cols-4" aria-label="Workspace 摘要">
      <Card.Root size="sm">
        <Card.Header>
          <Card.Description class="flex items-center gap-2"><ListChecks class="size-4" />我的开放工作项</Card.Description>
          <Card.Title class="text-3xl">{myOpenItems.length}</Card.Title>
        </Card.Header>
      </Card.Root>
      <Card.Root size="sm">
        <Card.Header>
          <Card.Description class="flex items-center gap-2"><CircleAlert class="size-4" />阻塞项</Card.Description>
          <Card.Title class="text-3xl">{blockedItems.length}</Card.Title>
        </Card.Header>
      </Card.Root>
      <Card.Root size="sm">
        <Card.Header>
          <Card.Description class="flex items-center gap-2"><Clock3 class="size-4" />待审批</Card.Description>
          <Card.Title class="text-3xl">{pendingApprovals.length}</Card.Title>
        </Card.Header>
      </Card.Root>
      <Card.Root size="sm">
        <Card.Header>
          <Card.Description class="flex items-center gap-2"><PlayCircle class="size-4" />最近运行</Card.Description>
          <Card.Title class="text-3xl">{recentRuns.length}</Card.Title>
        </Card.Header>
      </Card.Root>
    </section>

    <div class="mt-6 grid gap-6 xl:grid-cols-[minmax(0,1.15fr)_minmax(22rem,0.85fr)]">
      <Card.Root>
        <Card.Header class="flex-row items-start justify-between gap-4">
          <div>
            <Card.Title>我的开放工作项</Card.Title>
            <Card.Description>按更新时间排列。进入详情后可启动 Agent。</Card.Description>
          </div>
          <Button href="/work-items" variant="ghost" size="sm">查看全部 <ArrowRight class="size-4" /></Button>
        </Card.Header>
        <Card.Content>
          {#if myOpenItems.length > 0}
            <Table.Root>
              <Table.Header><Table.Row><Table.Head>工作项</Table.Head><Table.Head>状态</Table.Head><Table.Head>优先级</Table.Head><Table.Head>更新</Table.Head></Table.Row></Table.Header>
              <Table.Body>
                {#each myOpenItems.slice(0, 8) as item (item.id)}
                  <Table.Row>
                    <Table.Cell><a class="font-medium hover:underline" href={`/work-items/${item.id}`}>{item.title}</a></Table.Cell>
                    <Table.Cell><Badge variant={statusVariant(item.status)}>{item.status}</Badge></Table.Cell>
                    <Table.Cell class="capitalize text-muted-foreground">{item.priority}</Table.Cell>
                    <Table.Cell class="whitespace-nowrap text-xs text-muted-foreground">{dateLabel(item.updated_at)}</Table.Cell>
                  </Table.Row>
                {/each}
              </Table.Body>
            </Table.Root>
          {:else}
            <EmptyState title="没有分配给你的开放工作项" description="新建工作项，或让团队成员把工作分配给你。">
              {#snippet action()}<Button href="/work-items?create=1" variant="outline">新建工作项</Button>{/snippet}
            </EmptyState>
          {/if}
        </Card.Content>
      </Card.Root>

      <div class="space-y-6">
        <Card.Root>
          <Card.Header class="flex-row items-start justify-between gap-4">
            <div><Card.Title>等待你审批</Card.Title><Card.Description>只显示 pending 状态。</Card.Description></div>
            <Button href="/approvals" variant="ghost" size="sm">打开审批</Button>
          </Card.Header>
          <Card.Content class="space-y-3">
            {#each pendingApprovals.slice(0, 4) as approval (approval.id)}
              <a class="flex items-center justify-between gap-3 rounded-lg border border-border p-3 hover:bg-accent" href={`/runs/${approval.run_id}`}>
                <span class="min-w-0"><span class="block text-sm font-medium">工具调用待确认</span><span class="block truncate font-mono text-xs text-muted-foreground">{approval.tool_call_id}</span></span>
                <Badge variant="outline">pending</Badge>
              </a>
            {:else}
              <p class="text-sm text-muted-foreground">当前没有待审批调用。</p>
            {/each}
          </Card.Content>
        </Card.Root>

        <Card.Root>
          <Card.Header><Card.Title>最近运行</Card.Title><Card.Description>点击查看完整时间线和结果。</Card.Description></Card.Header>
          <Card.Content class="space-y-2">
            {#each recentRuns.slice(0, 5) as run (run.id)}
              <a class="flex items-center justify-between gap-3 rounded-lg px-3 py-2 hover:bg-accent" href={`/runs/${run.id}`}>
                <span class="min-w-0"><span class="block truncate text-sm font-medium">{run.work_item_id ? 'WorkItem Run' : 'Run'}</span><span class="block truncate text-xs text-muted-foreground">{dateLabel(run.created_at)}</span></span>
                <Badge variant={statusVariant(run.status)}>{run.status}</Badge>
              </a>
            {:else}
              <p class="text-sm text-muted-foreground">当前 Workspace 还没有运行。</p>
            {/each}
          </Card.Content>
        </Card.Root>
      </div>
    </div>
  {/if}
</main>
