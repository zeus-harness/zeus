<script lang="ts">
  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';

  import WorkspaceStatus from '$lib/components/WorkspaceStatus.svelte';
  import type { WorkspaceStatus as WorkspaceApiStatus } from '$lib/api/workspace';

  import type { PageData } from './$types';

  let { data } = $props<{ data: PageData }>();

  let workspaceStatus: WorkspaceApiStatus = $derived(
    data.status === 'unauthenticated'
      ? 'unauthenticated'
      : data.status === 'ready' && data.principal?.workspace_id
        ? 'ready'
        : data.status === 'ready'
          ? 'not-configured'
          : 'error'
  );

  let workspaceMessage = $derived(
    workspaceStatus === 'ready'
      ? '当前页面会从 Zeus API 读取 Workspace 数据，所有操作都通过服务端会话完成。'
      : workspaceStatus === 'unauthenticated'
        ? '请先登录，再选择一个 Workspace 后使用业务页面。'
        : workspaceStatus === 'not-configured'
          ? '当前会话还没有选择 Workspace，业务页面不会发起跨租户请求。'
          : '无法确认当前登录状态，暂时不能加载 Workspace 数据。'
  );

  const destinations = [
    {
      href: '/work-items',
      label: 'WorkItems',
      description: '创建、跟踪并更新团队工作的状态。'
    },
    {
      href: '/runs',
      label: 'Runs',
      description: '查看运行记录，并进入单次 Run 的完整 Trace。'
    },
    {
      href: '/approvals',
      label: 'Approvals',
      description: '处理需要人工确认的工具调用。'
    },
    {
      href: '/experience',
      label: 'Experience',
      description: '审阅候选经验，发布、搜索和撤回团队经验。'
    }
  ] as const;
</script>

<svelte:head>
  <title>Zeus · Team Harness</title>
</svelte:head>

<main class="mx-auto min-h-[calc(100vh-4rem)] max-w-[1480px] px-5 py-8 lg:px-8 lg:py-12">
  <div class="flex flex-col gap-3">
    <div class="flex flex-wrap items-center gap-2">
      <Badge variant="secondary">Team Harness</Badge>
      {#if data.principal?.organization_id}
        <span class="font-mono text-xs text-muted-foreground">Organization {data.principal.organization_id}</span>
      {/if}
    </div>
    <h1 class="text-3xl font-semibold tracking-tight sm:text-4xl">工作区运行控制台</h1>
    <p class="max-w-2xl text-sm leading-6 text-muted-foreground">
      WorkItems、Runs、审批和团队经验都来自当前 Workspace 的真实 API 数据。每个页面都会明确展示登录、Workspace 或 API 状态。
    </p>
  </div>

  <section class="mt-8" aria-label="Workspace 状态">
    {#if workspaceStatus === 'ready'}
      <div class="rounded-xl border border-border bg-card p-5 shadow-xs">
        <div class="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p class="text-xs font-semibold uppercase tracking-[0.12em] text-muted-foreground">当前上下文</p>
            <h2 class="mt-2 text-lg font-semibold">{data.principal?.display_name ?? '已登录用户'}</h2>
            <p class="mt-1 text-sm text-muted-foreground">Workspace {data.principal?.workspace_id}</p>
          </div>
          <Badge variant="outline">API connected</Badge>
        </div>
        <p class="mt-4 text-sm leading-6 text-muted-foreground">{workspaceMessage}</p>
      </div>
    {:else}
      <WorkspaceStatus status={workspaceStatus} message={workspaceMessage} />
    {/if}
  </section>

  <section class="mt-8 grid gap-4 md:grid-cols-2" aria-label="业务页面">
    {#each destinations as destination (destination.href)}
      <Card.Root>
        <Card.Header>
          <Card.Title>{destination.label}</Card.Title>
          <Card.Description>{destination.description}</Card.Description>
        </Card.Header>
        <Card.Footer>
          <Button href={destination.href} variant="outline" size="sm">打开 {destination.label}</Button>
        </Card.Footer>
      </Card.Root>
    {/each}
  </section>
</main>
