<script lang="ts">
  import { enhance } from '$app/forms';
  import { ArrowLeft, ArrowUp, Bot, ShieldCheck } from '@lucide/svelte';
  import { Button } from '@zeus/ui/components/ui/button';
  import { Label } from '@zeus/ui/components/ui/label';
  import { Textarea } from '@zeus/ui/components/ui/textarea';
  import { NativeSelect, NativeSelectOption } from '@zeus/ui/components/ui/native-select';
  import type { Workflow } from '$lib/api/control-plane';
  import type { ActionData, PageData } from './$types';
  let { data, form } = $props<{ data: PageData; form: ActionData }>();
  let message = $derived(form && 'values' in form ? form.values.message : '');
  let workflowId = $derived(form && 'values' in form ? form.values.workflow_id : (data.workflows.data?.items as Workflow[] | undefined)?.find(item => item.active_version_id)?.id ?? '');
  let workflows = $derived((data.workflows.data?.items as Workflow[] | undefined)?.filter(item => item.active_version_id) ?? []);
  let requestId = $derived(form && 'values' in form ? form.values.request_id : data.requestId);
  let submitting = $state(false);
  let interrupted = $state(false);
  let locked = $state(false);
</script>
<svelte:head><title>发起任务 · Zeus</title></svelte:head>
<main class="mx-auto max-w-3xl px-5 py-8 lg:py-14">
  <a href={`/${data.workspaceId}`} class="inline-flex items-center gap-2 text-sm text-muted-foreground"><ArrowLeft class="size-4" />返回工作台</a>
  <header class="mb-8 mt-12"><span class="mb-4 grid size-12 place-items-center rounded-xl bg-primary/10 text-primary"><Bot class="size-6" /></span><h1 class="text-3xl font-semibold tracking-tight">交给 Zeus 一件事</h1><p class="mt-3 text-muted-foreground">描述目标、相关背景和你希望看到的结果。</p></header>
  <form method="POST" action="?/create" class="space-y-5 rounded-xl border bg-card p-5 shadow-sm sm:p-7" use:enhance={({ cancel }) => {
    if (submitting) { cancel(); return; }
    submitting = true; interrupted = false; locked = true;
    return async ({ result, update }) => {
      try { if (result.type === 'error') interrupted = true; else { if (result.type === 'failure' && result.status === 400) locked = false; await update({ reset: false }); } }
      finally { submitting = false; }
    };
  }}>
    <input type="hidden" name="request_id" value={requestId} />
    <Label for="task-goal">任务目标</Label>
    <Textarea id="task-goal" name="message" required maxlength={50000} rows={7} bind:value={message} readonly={locked} class="resize-y border-0 bg-transparent text-base leading-7 shadow-none focus-visible:ring-0" placeholder="例如：分析测试日志中的失败原因，提出修复方案。修改前请先让我审批，修复后提供测试证据。" />
    <details class="rounded-lg bg-muted/50 p-3"><summary class="cursor-pointer text-sm text-muted-foreground">执行方式 · {workflows.find(item => item.id === workflowId)?.name ?? '尚未配置'}</summary><div class="mt-3 space-y-2"><Label for="task-workflow">执行方式</Label><NativeSelect id="task-workflow" name="workflow_id" bind:value={workflowId} disabled={locked} required><NativeSelectOption value="" disabled>选择已发布的流程</NativeSelectOption>{#each workflows as workflow (workflow.id)}<NativeSelectOption value={workflow.id}>{workflow.name}</NativeSelectOption>{/each}</NativeSelect>{#if locked}<input type="hidden" name="workflow_id" value={workflowId} />{/if}<p class="text-xs text-muted-foreground">使用该流程已发布的 Agent、组织模型和审批策略。</p></div></details>
    {#if workflows.length === 0}<p role="alert" class="text-sm text-muted-foreground">{data.workflows.status === 'ready' ? '还没有可执行的流程，请联系工作空间负责人完成配置。' : '暂时无法读取执行方式，请刷新后重试。'}</p>{/if}
    {#if form?.type === 'error'}<p role="alert" class="text-sm text-destructive">{form.message}</p>{#if 'workItemId' in form && form.workItemId}<a class="inline-block text-sm underline" href={`/${data.workspaceId}/work-items/${form.workItemId}`}>打开已保存的任务</a>{/if}{/if}
    {#if interrupted}<p role="alert" class="text-sm text-destructive">连接中断，发起尚未确认。原内容已保留，可重试同一次请求。</p>{/if}
    <div class="flex flex-col gap-4 border-t pt-5 sm:flex-row sm:items-center sm:justify-between"><p class="flex items-center gap-2 text-xs text-muted-foreground"><ShieldCheck class="size-4 shrink-0" />需要授权的操作会暂停，等待人工审批。</p><Button type="submit" disabled={!data.canLaunch || workflows.length === 0 || submitting} class="min-h-11 gap-2">{submitting ? '正在发起…' : locked ? '重试发起' : '发起任务'}<ArrowUp class="size-4" /></Button></div>
    {#if !data.canLaunch}<p class="text-sm text-muted-foreground">当前角色可以查看任务，由负责人或操作人员发起执行。</p>{/if}
  </form>
  <p class="mt-6 text-center text-sm text-muted-foreground">还需要先理清思路？<a class="underline underline-offset-4" href={`/${data.workspaceId}/studio`}>先与助手讨论</a></p>
</main>
