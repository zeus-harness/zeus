<script lang="ts">
  import type { MemberOption } from '$lib/server/member-options';
  import { statusLabel } from '$lib/features/status-labels';
  import { Filter, Plus } from '@lucide/svelte';

  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';
  import { Input } from '@zeus/ui/components/ui/input';
  import { Label } from '@zeus/ui/components/ui/label';
  import { NativeSelect, NativeSelectOption } from '@zeus/ui/components/ui/native-select';
  import * as Sheet from '@zeus/ui/components/ui/sheet';
  import * as Table from '@zeus/ui/components/ui/table';
  import { Textarea } from '@zeus/ui/components/ui/textarea';

  import MemberPicker from '$lib/features/work-items/MemberPicker.svelte';
  import EmptyState from '$lib/components/layout/EmptyState.svelte';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import WorkspaceStatus from '$lib/components/WorkspaceStatus.svelte';
  import type { ActionData, PageData } from './$types';

  let { data, form } = $props<{ data: PageData; form: ActionData }>();
  let items = $derived(data.result.data?.items ?? []);
  let workspaceBase = $derived(`/${data.workspaceId}`);
  let hasWorkspaceData = $derived(data.result.status === 'ready');
  let createOpenOverride = $state<boolean | undefined>();
  let createOpen = $derived(
    createOpenOverride ?? (data.openCreate || form?.type === 'error')
  );

  function dateLabel(value: string): string {
    return new Intl.DateTimeFormat('zh-CN', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    }).format(new Date(value));
  }

  function statusVariant(status: string): 'default' | 'secondary' | 'destructive' | 'outline' {
    if (status === 'completed') return 'secondary';
    if (status === 'blocked' || status === 'canceled') return 'destructive';
    if (status === 'in_progress') return 'default';
    return 'outline';
  }

  function nextHref(cursor: string): string {
    const params = new URLSearchParams({ cursor });
    if (data.search) params.set('q', data.search);
    if (data.view) params.set('view', data.view);
    if (data.filterStatus) params.set('status', data.filterStatus);
    if (data.filterAssigneeUserId) params.set('assignee_user_id', data.filterAssigneeUserId);
    return `?${params.toString()}`;
  }
</script>

<svelte:head><title>Zeus · 工作项</title></svelte:head>

<main class="px-5 py-7 lg:px-8 lg:py-9">
  <PageHeader
    eyebrow="Workspace queue"
    title="工作项"
    description="从任务进入 Agent。状态、负责人和下一动作保持在主视图。"
  >
    {#snippet actions()}
      <Button onclick={() => (createOpenOverride = true)}><Plus class="size-4" />新建工作项</Button>
    {/snippet}
  </PageHeader>

  {#if form?.type === 'error'}
    <div class="mt-5 rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive" role="alert">{form.message}</div>
  {/if}

  {#if !hasWorkspaceData}
    <div class="mt-7"><WorkspaceStatus status={data.result.status} message={data.result.message} httpStatus={data.result.httpStatus} /></div>
  {:else}
    <nav class="mt-5 flex flex-wrap gap-3" aria-label="工作项范围"><Button href={`${workspaceBase}/work-items`} variant={!data.view ? 'secondary' : 'ghost'}>全部工作项</Button><Button href="?view=created" variant={data.view === 'created' ? 'secondary' : 'ghost'}>我创建的</Button><Button href="?view=unassigned" variant={data.view === 'unassigned' ? 'secondary' : 'ghost'}>未分配</Button></nav>
    <Card.Root class="mt-7">
      <Card.Header class="gap-4 border-b border-border">
        <form method="GET" class="grid gap-3 sm:grid-cols-2 xl:grid-cols-[minmax(12rem,1fr)_10rem_minmax(14rem,1fr)_auto] sm:items-end">
          <input type="hidden" name="view" value={data.view} />
          <div class="space-y-2"><Label for="task-search">任务标题</Label><Input id="task-search" name="q" type="search" maxlength={200} placeholder="输入标题关键词" value={data.search} /></div>
          <div class="space-y-2">
            <Label for="status-filter">状态</Label>
            <NativeSelect id="status-filter" name="status" value={data.filterStatus} class="w-full">
              <NativeSelectOption value="">全部状态</NativeSelectOption>
              <NativeSelectOption value="open">待处理</NativeSelectOption>
              <NativeSelectOption value="in_progress">处理中</NativeSelectOption>
              <NativeSelectOption value="blocked">已阻塞</NativeSelectOption>
              <NativeSelectOption value="completed">已完成</NativeSelectOption>
              <NativeSelectOption value="canceled">已取消</NativeSelectOption>
            </NativeSelect>
          </div>
          <div class="space-y-2">
            <Label for="assignee-filter">负责人</Label>
            <MemberPicker id="assignee-filter" members={data.members} limited={data.memberOptionsLimited} value={data.filterAssigneeUserId} emptyLabel="全部负责人" />
          </div>
          <Button type="submit" variant="outline"><Filter class="size-4" />筛选</Button>
        </form>
      </Card.Header>
      <Card.Content class="pt-0">
        {#if items.length > 0}
          <ul class="divide-y divide-border sm:hidden" aria-label="工作项列表">
            {#each items as item (item.id)}
              <li class="space-y-2 py-4">
                <a class="block break-words font-medium underline-offset-4 hover:underline" href={`${workspaceBase}/work-items/${item.id}`}>{item.title}</a>
                <div class="flex flex-wrap items-center gap-2 text-sm"><Badge variant={statusVariant(item.status)}>{statusLabel(item.status)}</Badge><span>{statusLabel(item.priority)}</span><span>{data.members.find((member: MemberOption) => member.user_id === item.assignee_user_id)?.display_name || (item.assignee_user_id ? '已分配成员' : '未分配')}</span></div>
                <p class="text-xs text-muted-foreground">更新于 {dateLabel(item.updated_at)}</p>
              </li>
            {/each}
          </ul>
          <div class="hidden overflow-x-auto sm:block">
            <Table.Root>
              <Table.Header>
                <Table.Row><Table.Head>工作项</Table.Head><Table.Head>负责人</Table.Head><Table.Head>状态</Table.Head><Table.Head>优先级</Table.Head><Table.Head>更新时间</Table.Head></Table.Row>
              </Table.Header>
              <Table.Body>
                {#each items as item (item.id)}
                  <Table.Row>
                    <Table.Cell class="min-w-72">
                  <a class="font-medium hover:underline" href={`${workspaceBase}/work-items/${item.id}`}>{item.title}</a>
                      {#if item.description}<p class="mt-1 max-w-xl truncate text-xs text-muted-foreground">{item.description}</p>{/if}
                    </Table.Cell>
                    <Table.Cell class="max-w-40 truncate text-xs text-muted-foreground">{data.members.find((member: MemberOption) => member.user_id === item.assignee_user_id)?.display_name || (item.assignee_user_id ? '已分配成员' : '未分配')}</Table.Cell>
                    <Table.Cell><Badge variant={statusVariant(item.status)}>{statusLabel(item.status)}</Badge></Table.Cell>
                    <Table.Cell class="capitalize text-muted-foreground">{statusLabel(item.priority)}</Table.Cell>
                    <Table.Cell class="whitespace-nowrap text-xs text-muted-foreground">{dateLabel(item.updated_at)}</Table.Cell>
                  </Table.Row>
                {/each}
              </Table.Body>
            </Table.Root>
          </div>
        {:else}
          <div class="py-6">
            <EmptyState title="没有符合条件的工作项" description="调整筛选条件，或创建一条新的团队工作项。">
              {#snippet action()}<Button onclick={() => (createOpenOverride = true)} variant="outline">新建工作项</Button>{#if data.filterStatus || data.filterAssigneeUserId || data.search}<Button href={`${workspaceBase}/work-items`} variant="ghost">清除筛选</Button>{/if}{/snippet}
            </EmptyState>
          </div>
        {/if}
        {#if data.result.data?.next_cursor}
          <div class="flex justify-end border-t border-border pt-4"><Button href={nextHref(data.result.data.next_cursor)} variant="outline" size="sm">下一页</Button></div>
        {/if}
      </Card.Content>
    </Card.Root>
  {/if}
</main>

<Sheet.Root open={createOpen} onOpenChange={(open) => (createOpenOverride = open)}>
  <Sheet.Content class="overflow-y-auto sm:max-w-xl">
    <Sheet.Header>
      <Sheet.Title>新建工作项</Sheet.Title>
      <Sheet.Description>创建成功后进入详情页，再选择 Workflow 启动 Agent。</Sheet.Description>
    </Sheet.Header>
    <form method="POST" action="?/create" class="space-y-5 px-4 pb-6">
      <div class="space-y-2"><Label for="title">标题</Label><Input id="title" name="title" required maxlength={500} value={data.requirementsTemplate ? '需求整理示例' : ''} /></div>
      <div class="space-y-2"><Label for="description">描述</Label><Textarea id="description" name="description" rows={5} maxlength={50000} value={data.requirementsTemplate ? '请整理以下需求中的已知事实、缺失信息和建议，结果由我确认。\n\n业务目标：\n使用者：\n当前问题：\n验收标准：' : ''} /></div>
      <div class="grid gap-4 sm:grid-cols-2">
        <div class="space-y-2">
          <Label for="priority">优先级</Label>
          <NativeSelect id="priority" name="priority" value="normal" class="w-full">
            <NativeSelectOption value="low">低</NativeSelectOption>
            <NativeSelectOption value="normal">普通</NativeSelectOption>
            <NativeSelectOption value="high">高</NativeSelectOption>
            <NativeSelectOption value="urgent">紧急</NativeSelectOption>
          </NativeSelect>
        </div>
        <div class="space-y-2"><Label for="assignee_user_id">负责人</Label><MemberPicker id="assignee_user_id" members={data.members} limited={data.memberOptionsLimited} /></div>
      </div>
      {#if data.memberOptionsLimited}<p class="text-xs text-muted-foreground">成员选项受当前权限或列表范围限制。找不到成员时请联系工作空间 Owner。</p>{/if}
      <details class="space-y-4 rounded-lg border border-border p-4">
        <summary class="cursor-pointer text-sm font-medium">高级设置（外部来源与结构化输入）</summary>
      <div class="grid gap-4 sm:grid-cols-2">
        <div class="space-y-2"><Label for="source_kind">来源类型</Label><Input id="source_kind" name="source_kind" placeholder="jira" /></div>
        <div class="space-y-2"><Label for="external_reference">外部引用</Label><Input id="external_reference" name="external_reference" placeholder="PROJ-42" /></div>
      </div>
      <p class="text-xs text-muted-foreground">来源类型与外部引用需要同时填写，手动创建可全部留空。</p>
      <div class="space-y-2"><Label for="input">结构化输入（JSON）</Label><Textarea id="input" name="input" rows={6} class="font-mono text-xs" value={'{}'} /></div>
      </details>
      <Sheet.Footer><Button type="submit" class="w-full sm:w-auto">创建并打开</Button></Sheet.Footer>
    </form>
  </Sheet.Content>
</Sheet.Root>
