<script lang="ts">
  import { enhance } from '$app/forms';
  import type { SubmitFunction } from '@sveltejs/kit';
  import { invalidateAll } from '$app/navigation';
  import { onMount } from 'svelte';
  import { ArrowLeft, Check, ChevronRight, Clock3, ShieldCheck } from '@lucide/svelte';
  import { Button } from '@zeus/ui/components/ui/button';
  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Label } from '@zeus/ui/components/ui/label';
  import { Input } from '@zeus/ui/components/ui/input';
  import { Textarea } from '@zeus/ui/components/ui/textarea';
  import { NativeSelect, NativeSelectOption } from '@zeus/ui/components/ui/native-select';
  import ResultContent from '$lib/features/results/ResultContent.svelte';
  import WorkItemClosure from './WorkItemClosure.svelte';
  import { taskState, messageContent } from './task-state';
  import { runRecovery } from '$lib/features/runs/recovery';
  import { approvalKindLabel, approvalAuthorityLabel } from '$lib/approval-policy';
  import { displayTimestamp } from '$lib/display-timestamp';
  import { statusLabel } from '$lib/features/status-labels';
  import type { PageData, ActionData } from '../../../routes/(workspace)/[workspaceId=workspaceId]/work-items/[work_item_id]/$types';
  let { data, form, closureEligible }: { data: PageData; form: ActionData; closureEligible: boolean } = $props();
  let item = $derived(data.result.data!);
  let runs = $derived(data.runs.data?.items ?? []);
  let run = $derived(runs.find(value => value.parent_run_id === null));
  let trace = $derived(data.trace?.data);
  let review = $derived(data.reviews.data?.items.find(value => value.run_id === run?.id));
  let currentReview = $derived(review?.work_item_revision === item.revision - 1 ? review : undefined);
  let progress = $derived(taskState(item, run, review));
  let pending = $derived(trace?.approvals.filter(value => value.status === 'pending') ?? []);
  let messages = $derived(trace?.session_events.filter(value => ['user_message', 'follow_up_message', 'assistant_message'].includes(value.event_type)) ?? []);
  let workflows = $derived(data.workflows.data?.items.filter(value => value.active_version_id) ?? []);
  let workflowId = $derived(workflows.find(value => value.active_version_id === run?.workflow_version_id)?.id ?? workflows[0]?.id ?? '');
  let base = $derived(`/${data.workspaceId}`);
  let busy = $state(false);
  let interrupted = $state(false);
  let refreshError = $state(false);
  let recoveryConfirmed = $state(false);
  const submit: SubmitFunction = ({ cancel }) => {
    if (busy) { cancel(); return; }
    busy = true; interrupted = false;
    return async ({ result, update }) => {
      try { if (result.type === 'error') interrupted = true; else await update({ reset: false }); }
      finally { busy = false; }
    };
  };
  onMount(() => {
    let refreshing = false;
    const timer = setInterval(async () => {
      if (busy || refreshing || document.hidden || !run || ['succeeded', 'failed', 'canceled'].includes(run.status)) return;
      refreshing = true;
      try { await invalidateAll(); refreshError = false; } catch { refreshError = true; }
      finally { refreshing = false; }
    }, 3000);
    return () => clearInterval(timer);
  });
</script>
<a href={base} class="inline-flex items-center gap-2 text-sm text-muted-foreground hover:underline"><ArrowLeft class="size-4" />工作台</a>
<header class="mt-6 flex flex-wrap items-start justify-between gap-4"><div class="min-w-0"><div class="mb-3 flex items-center gap-3"><Badge variant={run?.status === 'failed' ? 'destructive' : 'secondary'}>{progress.label}</Badge><span class="text-xs text-muted-foreground">{displayTimestamp(item.updated_at)}</span></div><h1 class="break-words text-2xl font-semibold tracking-tight sm:text-3xl">{item.title}</h1></div><a href="?view=advanced" class="shrink-0 text-sm text-muted-foreground underline underline-offset-4">任务设置与完整记录</a></header>
<nav class="my-7 flex flex-wrap items-center gap-2 text-xs sm:gap-4 sm:text-sm" aria-label="任务进度">{#each ['目标已保存','Agent 处理','结果验收','验证归档'] as step,index (step)}<span class={progress.stage > index ? 'flex items-center gap-2 text-foreground' : progress.stage === index ? 'flex items-center gap-2 font-semibold text-primary' : 'flex items-center gap-2 text-muted-foreground'}><span class="grid size-6 place-items-center rounded-full border">{#if progress.stage > index}<Check class="size-3" />{:else}{index+1}{/if}</span>{step}</span>{#if index < 3}<ChevronRight class="size-3 text-muted-foreground" />{/if}{/each}</nav>
{#if form?.type === 'error'}<p role="alert" class="mb-5 rounded-lg border border-destructive/30 p-4 text-sm text-destructive">{form.message}</p>{/if}
{#if interrupted}<p role="alert" class="mb-5 text-sm text-destructive">连接中断，操作尚未确认。输入已保留，请刷新核对任务，再决定是否重试。</p>{/if}
{#if refreshError}<p role="alert" class="mb-5 text-sm text-destructive">进度连接中断，保留上次记录。<button type="button" class="underline" onclick={() => invalidateAll()}>重新连接</button></p>{/if}
<div class="grid items-start gap-6 xl:grid-cols-[minmax(0,1fr)_18rem]">
  <div class="min-w-0 space-y-6">
    <section class="rounded-xl border bg-card p-5 sm:p-6" aria-label="当前进度"><h2 class="flex items-center gap-2 font-semibold"><Clock3 class="size-4" />{progress.label}</h2><p class="mt-2 text-sm leading-6 text-muted-foreground">{progress.detail}</p>
      {#if run && ['failed','canceled'].includes(run.status) && !item.archived_at}<p class="mt-3 text-sm">{runRecovery(run.status,run.error_code ?? null)}</p>{#if data.canEdit}<form method="POST" action="?/retry" class="mt-4 space-y-3" use:enhance={submit}><input type="hidden" name="run_id" value={run.id} /><label class="flex items-start gap-2 text-sm"><input type="checkbox" required bind:checked={recoveryConfirmed} />已核对执行记录与已有操作，确认可以再次尝试</label><Button type="submit" disabled={busy || !recoveryConfirmed}>重试任务</Button></form>{/if}{/if}
      {#if run && data.trace?.status !== 'ready'}<p role="alert" class="mt-3 text-sm text-destructive">执行详情暂不可用，请刷新核对审批与结果。</p>{/if}
    </section>
    {#if pending.length > 0}<section id="task-approvals" aria-label="任务审批" class="scroll-mt-24 space-y-4">{#each pending as approval (approval.id)}{@const tool = trace?.tool_calls.find(value => value.id === approval.tool_call_id)}<article class="rounded-xl border border-primary/20 bg-card p-5 sm:p-6"><h2 class="flex items-center gap-2 font-semibold"><ShieldCheck class="size-4" />需要授权 · {approvalKindLabel(approval.kind)}</h2><p class="mt-2 text-sm text-muted-foreground">{approvalAuthorityLabel(approval.kind)}</p><p class="mt-4 text-sm font-medium">本次待执行内容</p>{#if tool}<pre class="mt-2 max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-muted p-4 font-mono text-xs leading-6">{JSON.stringify(tool.input,null,2)}</pre>{:else}<p role="alert" class="mt-2 text-sm">操作内容暂不可用，不能提交决定，请刷新。</p>{/if}
        {#if approval.can_decide && tool}<form method="POST" action="?/decide" class="mt-5 space-y-3" use:enhance={submit}><input type="hidden" name="run_id" value={approval.run_id} /><input type="hidden" name="approval_id" value={approval.id} /><Label for={`reason-${approval.id}`}>审批说明</Label><Input id={`reason-${approval.id}`} name="reason" maxlength={4000} required={approval.kind === 'resource_access'} placeholder="说明批准或拒绝的原因" /><div class="flex gap-3"><Button type="submit" name="decision" value="approve" disabled={busy}>批准</Button><Button type="submit" name="decision" value="reject" variant="outline" disabled={busy}>拒绝</Button></div><p class="text-xs text-muted-foreground">决定绑定这次操作；批准后 Agent 会继续，拒绝后保留记录。</p></form>{:else if !approval.can_decide}<p class="mt-4 text-sm text-muted-foreground">等待具备审批权限的负责人处理。</p>{/if}
      </article>{/each}</section>{/if}
    {#if run?.status === 'succeeded' && run.output !== null}<section id="acceptance" aria-label="结果与验收" class="scroll-mt-24 rounded-xl border bg-card p-5 sm:p-6"><h2 class="mb-4 font-semibold">Agent 提交的结果</h2><ResultContent text={messageContent(run.output) || JSON.stringify(run.output,null,2)} />
      {#if review}<p class="mt-5 rounded-lg bg-muted/50 p-4 text-sm">{review.decision === 'accepted' ? '已接受结果' : '需要修改'} · {review.reason}</p>{/if}
      {#if !item.archived_at && data.canEdit}<details open={!currentReview} class="mt-5"><summary class="cursor-pointer text-sm font-medium">{currentReview ? '更新验收决定' : '核对结果并验收'}</summary><form method="POST" action="?/review" class="mt-6 space-y-4 border-t pt-5" use:enhance={submit}><input type="hidden" name="revision" value={item.revision} /><input type="hidden" name="run_id" value={run.id} /><Label for="task-review-decision">验收决定</Label><NativeSelect id="task-review-decision" name="decision" required><NativeSelectOption value="" disabled selected>核对结果后选择</NativeSelectOption><NativeSelectOption value="accepted">接受结果</NativeSelectOption><NativeSelectOption value="needs_changes">需要修改</NativeSelectOption></NativeSelect><Label for="task-review-reason">验收原因</Label><Textarea id="task-review-reason" name="reason" required maxlength={4000} rows={3} placeholder="说明核对的事实，或需要补充修改的内容。" /><label class="flex items-start gap-2 text-sm"><input type="checkbox" required />我已核对上方所选运行的结果</label><Button type="submit" disabled={busy}>保存验收记录</Button></form></details>{/if}
      {#if review?.decision === 'needs_changes' && data.canEdit && !item.archived_at}<form method="POST" action="?/reprocess" class="mt-4" use:enhance={submit}><input type="hidden" name="review_id" value={review.id} /><input type="hidden" name="revision" value={item.revision} /><Button type="submit" disabled={busy}>按意见继续处理</Button></form>{/if}
    </section>{/if}
    {#if item.archived_at || (currentReview?.decision === 'accepted' && run?.status === 'succeeded')}<WorkItemClosure {item} review={data.reviews.data?.items[0]} archive={data.archive.data ?? null} canArchive={data.canArchive} eligible={closureEligible} report={form && 'archiveValues' in form ? form.archiveValues : ''} />{/if}
    {#if !item.archived_at && (!run || ['failed','canceled'].includes(run.status)) && data.canEdit}<details open={!run} class="rounded-xl border bg-card p-5"><summary class="cursor-pointer font-medium">{run ? '调整执行方式后再次尝试' : '开始处理任务'}</summary><form method="POST" action="?/start" class="mt-4 space-y-4" use:enhance={submit}><input type="hidden" name="request_id" value={data.launchRequestId} /><Label for="continue-message">给 Agent 的消息</Label><Textarea id="continue-message" name="message" rows={3} placeholder="补充这次尝试的目标或注意事项" /><Label for="continue-workflow">执行方式</Label><NativeSelect id="continue-workflow" name="workflow_id" required bind:value={workflowId}>{#each workflows as workflow (workflow.id)}<NativeSelectOption value={workflow.id}>{workflow.name}</NativeSelectOption>{/each}</NativeSelect><Button type="submit" disabled={busy || !workflowId}>开始处理</Button></form></details>{/if}
    <details class="rounded-xl border bg-card p-5"><summary class="cursor-pointer font-medium">对话与执行记录</summary><div class="mt-5 space-y-4">{#each messages as message (message.id)}<article class={message.event_type === 'assistant_message' ? 'rounded-lg border p-4' : 'rounded-lg bg-muted/50 p-4'}><p class="mb-2 text-xs text-muted-foreground">{message.event_type === 'assistant_message' ? 'Agent' : '用户'} · {displayTimestamp(message.occurred_at)}</p><ResultContent text={messageContent(message.payload)} actions={false} /></article>{:else}<p class="text-sm text-muted-foreground">开始处理后，对话和执行过程会保存在这里。</p>{/each}{#each runs as attempt,index (attempt.id)}<a class="flex items-center justify-between gap-3 rounded-lg border p-3 text-sm hover:bg-accent" href={`${base}/runs/${attempt.id}`}><span>第 {runs.length-index} 次尝试 · {displayTimestamp(attempt.created_at)}</span><Badge variant="outline">{statusLabel(attempt.status)}</Badge></a>{/each}</div></details>
  </div>
  <aside class="space-y-5 xl:sticky xl:top-24"><section class="rounded-xl border bg-card p-5"><h2 class="text-sm font-semibold">任务目标</h2><div class="mt-3 text-sm leading-7"><ResultContent text={item.description || item.title} actions={false} /></div></section><p class="text-xs leading-6 text-muted-foreground">目标跨多次尝试保留。批准操作、接受结果和验证归档分别记录。</p><a href={`${base}/studio?work_item=${item.id}`} class="inline-block text-sm underline underline-offset-4">与助手讨论这项任务</a></aside>
</div>
