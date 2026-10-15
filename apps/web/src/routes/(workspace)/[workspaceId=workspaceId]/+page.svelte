<script lang="ts">
  import { ArrowRight, CheckSquare, Clock3, Plus, Sparkles } from '@lucide/svelte';
  import { Badge } from '@zeus/ui/components/ui/badge';
  import * as Card from '@zeus/ui/components/ui/card';
  import WorkspaceStatus from '$lib/components/WorkspaceStatus.svelte';
  import { displayTimestamp } from '$lib/display-timestamp';
  import type { TaskSummary } from '$lib/features/work-items/task-state';
  import type { Approval } from '$lib/api/runs';
  import type { PageData } from './$types';
  let { data } = $props<{ data: PageData }>();
  let base = $derived(`/${data.workspaceId}`);
  let tasks = $derived(data.tasks as TaskSummary[]);
  let pending = $derived((data.approvals.data as Approval[] ?? []).filter(value => value.can_decide));
  let active = $derived(tasks.filter(value => !value.item.archived_at && value.item.status !== 'canceled'));
  let completed = $derived(tasks.filter(value => value.item.archived_at));
</script>
<svelte:head><title>工作台 · Zeus</title></svelte:head>
<main class="mx-auto max-w-6xl space-y-7 px-5 py-8 lg:px-10 lg:py-10">
  <header><p class="text-sm text-muted-foreground">{data.activeWorkspace.name}</p><h1 class="mt-2 text-3xl font-semibold tracking-tight">工作台</h1><p class="mt-2 text-sm text-muted-foreground">需要你决定的事，正在推进的任务，以及已验证的结果。</p></header>
  <a href={`${base}/new`} class="flex items-center justify-between gap-4 rounded-xl border bg-card p-5 shadow-sm transition-colors hover:bg-accent sm:p-6"><span class="flex items-center gap-4"><span class="grid size-11 shrink-0 place-items-center rounded-xl bg-primary/10 text-primary"><Sparkles class="size-5" /></span><span><span class="block font-semibold">发起任务</span><span class="mt-1 block text-sm text-muted-foreground">描述目标，让 Zeus 帮你推进</span></span></span><Plus class="size-5 shrink-0" /></a>
  {#if data.workItems.status !== 'ready'}<WorkspaceStatus status={data.workItems.status} message={data.workItems.message} httpStatus={data.workItems.httpStatus} />{:else}
    {#if data.onboarding.workflow !== 'configured'}<p class="rounded-lg border bg-background p-4 text-sm">执行方式尚未就绪，请联系负责人完成配置。{#if data.canManageWorkspace || data.activeWorkspace.role === 'builder'}<a href="/management" class="ml-2 underline">打开设置中心</a>{/if}</p>{/if}
    <section aria-label="待我审批" class="space-y-3"><div class="flex items-center justify-between"><h2 class="flex items-center gap-2 text-base font-semibold"><CheckSquare class="size-4" />待我审批 <span class="text-muted-foreground">{pending.length}</span></h2><a href={`${base}/approvals`} class="text-sm text-muted-foreground hover:underline">全部审批</a></div>
      {#if data.approvals.status !== 'ready'}<p role="alert" class="text-sm text-destructive">审批暂不可用，请刷新后重试。</p>{:else if pending.length === 0}<p class="rounded-xl border bg-card px-5 py-4 text-sm text-muted-foreground">暂无需要你处理的审批，Agent 遇到需要授权的操作会在这里等你。</p>{:else}<div class="grid gap-3 sm:grid-cols-2">{#each pending as approval (approval.id)}{@const task = tasks.find(value => value.run?.id === approval.run_id)}<a href={task ? `${base}/work-items/${task.item.id}#task-approvals` : `${base}/runs/${approval.run_id}#run-approvals`} class="flex items-center justify-between gap-4 rounded-xl border bg-card p-5 hover:bg-accent"><span><span class="block font-medium">{task?.item.title ?? '工具操作待审批'}</span><span class="mt-1 block text-xs text-muted-foreground">Agent 已暂停，等待你核对操作内容</span></span><ArrowRight class="size-4 shrink-0" /></a>{/each}</div>{/if}
    </section>
    <section aria-label="进行中的任务" class="space-y-3"><div class="flex items-center justify-between"><h2 class="flex items-center gap-2 text-base font-semibold"><Clock3 class="size-4" />正在推进</h2><a href={`${base}/work-items`} class="text-sm text-muted-foreground hover:underline">全部任务</a></div>
      <Card.Root><Card.Content class="p-0">{#each active as task (task.item.id)}<a href={`${base}/work-items/${task.item.id}`} class="flex flex-col gap-3 border-b p-5 last:border-0 hover:bg-accent sm:flex-row sm:items-center sm:justify-between"><span class="min-w-0"><span class="block break-words font-medium">{task.item.title}</span><span class="mt-1 block text-sm text-muted-foreground">{task.progress.detail}</span></span><Badge variant={task.progress.label === '需要处理' ? 'destructive' : 'outline'} class="w-fit shrink-0">{task.progress.label}</Badge></a>{:else}<div class="p-7 text-center"><p class="font-medium">还没有正在推进的任务</p><p class="mt-2 text-sm text-muted-foreground">从上方发起任务，或到全部任务中找回团队的工作。</p></div>{/each}</Card.Content></Card.Root>
    </section>
    <section aria-label="已验证的结果" class="space-y-3"><h2 class="text-base font-semibold">已验证 · 已归档</h2>{#if completed.length}<div class="grid gap-3 sm:grid-cols-2">{#each completed.slice(0,4) as task (task.item.id)}<a href={`${base}/work-items/${task.item.id}#closure`} class="rounded-xl border bg-card p-5 hover:bg-accent"><p class="font-medium">{task.item.title}</p><p class="mt-2 text-xs text-muted-foreground">{displayTimestamp(task.item.archived_at)} · 查看验证报告</p></a>{/each}</div>{:else}<p class="text-sm text-muted-foreground">任务完成并经负责人验证后，结果会留在这里。</p>{/if}</section>
    <p class="text-xs text-muted-foreground">展示最近更新的 20 项任务。<a href={`${base}/work-items`} class="underline">查找更早的任务</a></p>
  {/if}
</main>
