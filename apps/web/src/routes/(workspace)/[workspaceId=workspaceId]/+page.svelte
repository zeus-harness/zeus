<script lang="ts">
  import { statusLabel } from '$lib/features/status-labels';
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
  let workspaceBase = $derived(`/${data.workspaceId}`);


  let setupSteps = $derived([
            { title: '1. 配置模型', state: data.onboarding.model, owner: '组织 Owner', href: data.canManageOrganization ? `/organizations/${data.activeOrganization.organization_id}/settings/model-profiles` : null, action: '配置组织模型' },
            { title: '2. 发布 Agent', state: data.onboarding.agent, owner: '工作空间 Owner / Builder', href: data.canManageWorkspace || data.activeWorkspace.role === 'builder' ? `${workspaceBase}/agents?template=requirements` : null, action: '使用需求整理模板' },
            { title: '3. 发布流程', state: data.onboarding.workflow, owner: '工作空间 Owner / Builder', href: data.canManageWorkspace || data.activeWorkspace.role === 'builder' ? `${workspaceBase}/workflows` : null, action: '配置执行流程' }
          ]);
  let nextSetupStep = $derived(setupSteps.find(step => step.state !== 'configured'));

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
      <Button href={`${workspaceBase}/work-items?create=1`}>新建工作项</Button>
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
    <nav class="mt-5 flex flex-wrap gap-3" aria-label="找回工作项"><Button href={`${workspaceBase}/work-items?view=created`} variant="outline">我创建的工作项</Button><Button href={`${workspaceBase}/work-items?view=unassigned`} variant="outline">未分配工作项</Button><Button href={`${workspaceBase}/work-items`} variant="ghost">全部工作项</Button></nav>
    <section class="mt-5 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-background p-4" aria-label="下一步配置">
      <div><p class="font-medium">{nextSetupStep ? `下一步：${nextSetupStep.title}` : '可以开始处理工作项'}</p><p class="mt-1 text-xs text-muted-foreground">{nextSetupStep?.state === 'unavailable' ? '暂时无法确认配置，请进入页面检查或联系管理员。' : nextSetupStep ? `负责角色：${nextSetupStep.owner}` : '运行完成后，在工作项中人工验收结果。'}</p></div>
      {#if nextSetupStep?.href}<Button href={nextSetupStep.href} variant="outline">{nextSetupStep.action}</Button>{:else if nextSetupStep}<p class="text-sm">请联系{nextSetupStep.owner}继续。</p>{/if}
    </section>
    <details class="mt-5 rounded-lg border border-border bg-background p-4">
      <summary class="cursor-pointer text-sm font-medium">查看完整配置步骤与负责角色</summary>
      <Card.Root class="mt-4 border-0 shadow-none">
      <Card.Header><Card.Title>完成第一项任务</Card.Title><Card.Description>按顺序准备模型与流程，再从工作项运行并验收结果。已配置不代表已通过真实模型调用验证。</Card.Description></Card.Header>
      <Card.Content>
        <ol class="grid gap-4 md:grid-cols-2 xl:grid-cols-4" aria-label="首次使用步骤">
          {#each setupSteps as step (step.title)}
            <li class="space-y-3 rounded-lg border border-border p-4">
              <p class="font-medium">{step.title}</p>
              <Badge variant={step.state === 'configured' ? 'secondary' : 'outline'}>{step.state === 'configured' ? '已配置' : step.state === 'missing' ? '待完成' : '暂时无法确认'}</Badge>
              <p class="text-xs text-muted-foreground">负责角色：{step.owner}</p>
              {#if step.href}<a class="block text-sm underline" href={step.href}>{step.action}</a>{:else}<p class="text-sm">请联系{step.owner}完成此步骤。</p>{/if}
            </li>
          {/each}
          <li class="space-y-3 rounded-lg border border-border p-4"><p class="font-medium">4. 运行并验收</p><p class="text-sm text-muted-foreground">填写真实需求，选择已发布流程；运行成功后在工作项结果中接受或提出修改意见。</p><Button href={`${workspaceBase}/work-items?create=1&template=requirements`} variant="outline">创建示例工作项</Button></li>
        </ol>
      </Card.Content>
    </Card.Root>
    </details>
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
          <Button href={`${workspaceBase}/work-items`} variant="ghost" size="sm">查看全部 <ArrowRight class="size-4" /></Button>
        </Card.Header>
        <Card.Content>
          {#if myOpenItems.length > 0}
            <Table.Root>
              <Table.Header><Table.Row><Table.Head>工作项</Table.Head><Table.Head>状态</Table.Head><Table.Head>优先级</Table.Head><Table.Head>更新</Table.Head></Table.Row></Table.Header>
              <Table.Body>
                {#each myOpenItems.slice(0, 8) as item (item.id)}
                  <Table.Row>
                    <Table.Cell><a class="font-medium hover:underline" href={`${workspaceBase}/work-items/${item.id}`}>{item.title}</a></Table.Cell>
                    <Table.Cell><Badge variant={statusVariant(item.status)}>{statusLabel(item.status)}</Badge></Table.Cell>
                    <Table.Cell class="capitalize text-muted-foreground">{statusLabel(item.priority)}</Table.Cell>
                    <Table.Cell class="whitespace-nowrap text-xs text-muted-foreground">{dateLabel(item.updated_at)}</Table.Cell>
                  </Table.Row>
                {/each}
              </Table.Body>
            </Table.Root>
          {:else}
            <EmptyState title="没有分配给你的开放工作项" description="新建工作项，或让团队成员把工作分配给你。">
              {#snippet action()}<Button href={`${workspaceBase}/work-items?create=1`} variant="outline">新建工作项</Button>{/snippet}
            </EmptyState>
          {/if}
        </Card.Content>
      </Card.Root>

      <div class="space-y-6">
        <Card.Root>
          <Card.Header class="flex-row items-start justify-between gap-4">
            <div><Card.Title>等待你审批</Card.Title><Card.Description>需要你确认后才能继续的工具调用。</Card.Description></div>
            <Button href={`${workspaceBase}/approvals`} variant="ghost" size="sm">打开审批</Button>
          </Card.Header>
          <Card.Content class="space-y-3">
            {#each pendingApprovals.slice(0, 4) as approval (approval.id)}
              <a class="flex items-center justify-between gap-3 rounded-lg border border-border p-3 hover:bg-accent" href={`${workspaceBase}/runs/${approval.run_id}`}>
                <span class="min-w-0"><span class="block text-sm font-medium">工具调用待确认</span><span class="block truncate font-mono text-xs text-muted-foreground">{approval.tool_call_id}</span></span>
                <Badge variant="outline">待审批</Badge>
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
              <a class="flex items-center justify-between gap-3 rounded-lg px-3 py-2 hover:bg-accent" href={`${workspaceBase}/runs/${run.id}`}>
                <span class="min-w-0"><span class="block truncate text-sm font-medium">{run.work_item_id ? 'WorkItem Run' : 'Run'}</span><span class="block truncate text-xs text-muted-foreground">{dateLabel(run.created_at)}</span></span>
                <Badge variant={statusVariant(run.status)}>{statusLabel(run.status)}</Badge>
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
