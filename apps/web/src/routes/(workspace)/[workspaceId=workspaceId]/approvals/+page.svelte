<script lang="ts">
  import { approvalKindLabel, approvalAuthorityLabel } from '$lib/approval-policy';
  import { displayTimestamp } from '$lib/display-timestamp';
  import type { WorkItem } from '$lib/api/work-items';
  import WorkItemSearch from '$lib/features/runs/WorkItemSearch.svelte';
  import { statusLabel } from '$lib/features/status-labels';
  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';
  import { Input } from '@zeus/ui/components/ui/input';
  import { Label } from '@zeus/ui/components/ui/label';
  import { NativeSelect, NativeSelectOption } from '@zeus/ui/components/ui/native-select';
  import * as Table from '@zeus/ui/components/ui/table';

  import WorkspaceStatus from '$lib/components/WorkspaceStatus.svelte';

  import type { ActionData, PageData } from './$types';

  let { data, form } = $props<{ data: PageData; form: ActionData }>();
  let approvals = $derived(data.result.data ?? []);
  let workspaceBase = $derived(`/${data.workspaceId}`);

  const dateLabel = displayTimestamp;

  function statusVariant(status: string): 'default' | 'secondary' | 'destructive' | 'outline' {
    if (status === 'approved') return 'secondary';
    if (status === 'rejected' || status === 'expired' || status === 'canceled') return 'destructive';
    return 'outline';
  }
</script>

<svelte:head>
  <title>Zeus · 审批</title>
</svelte:head>

<main class="mx-auto max-w-[1480px] px-5 py-8 lg:px-8 lg:py-10">
  <div class="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
    <div>
      <p class="text-sm font-medium text-muted-foreground">人工确认</p>
      <h1 class="mt-2 text-3xl font-semibold tracking-tight">审批</h1>
      <p class="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
        执行确认由发起人处理；受限工具的权限申请由 Workspace Owner 授权。两类决定独立记录，不代表业务结果验收。
      </p>
    </div>
    {#if data.result.status === 'ready'}
      <Badge variant="secondary">{approvals.length} 条</Badge>
    {/if}
  </div>

  {#if form?.type === 'error'}
    <div class="mt-6 rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive" role="alert">
      {form.message}
    </div>
  {/if}

  {#if data.result.status !== 'ready'}
    <div class="mt-8">
      <WorkspaceStatus status={data.result.status} message={data.result.message} httpStatus={data.result.httpStatus} />
    </div>
  {:else}
    <Card.Root class="mt-8">
      <Card.Header class="flex-row items-start justify-between gap-4">
        <div>
          <Card.Title>审批队列</Card.Title>
          <Card.Description>默认显示待审批操作，也可查看历史记录。</Card.Description>
        </div>
        <WorkItemSearch query={data.itemQuery} status={data.filterStatus} selected={data.filterWorkItemId} nextCursor={data.workItems.data?.next_cursor} />
        <form method="GET" class="grid gap-3 sm:grid-cols-[11rem_minmax(15rem,1fr)_auto] sm:items-end">
          <div class="space-y-2"><Label for="approval-status">审批状态</Label>
          <NativeSelect id="approval-status" name="status" value={data.filterStatus} class="w-full">
            <NativeSelectOption value="pending">待审批</NativeSelectOption>
            <NativeSelectOption value="all">全部</NativeSelectOption>
            <NativeSelectOption value="approved">已批准</NativeSelectOption>
            <NativeSelectOption value="rejected">已拒绝</NativeSelectOption>
            <NativeSelectOption value="expired">已过期</NativeSelectOption>
            <NativeSelectOption value="canceled">已取消</NativeSelectOption>
          </NativeSelect>
          </div>
          <div class="space-y-2"><Label for="approval-work-item">工作项</Label>
            <input type="hidden" name="item_q" value={data.itemQuery} />
            <NativeSelect id="approval-work-item" name="work_item_id" value={data.filterWorkItemId} class="w-full">
              <NativeSelectOption value="">全部工作项</NativeSelectOption>
              {#if data.filterWorkItemId && !data.workItems.data?.items.some((item: WorkItem) => item.id === data.filterWorkItemId)}<NativeSelectOption value={data.filterWorkItemId}>当前筛选的工作项</NativeSelectOption>{/if}
              {#each data.workItems.data?.items ?? [] as item (item.id)}<NativeSelectOption value={item.id}>{item.title}</NativeSelectOption>{/each}
            </NativeSelect>
          </div>
          <Button type="submit" variant="outline" size="sm">筛选</Button>
        </form>
      </Card.Header>
      <Card.Content>
        {#if approvals.length > 0}
          <Table.Root>
            <Table.Header>
              <Table.Row>
                <Table.Head>工作项与工具操作</Table.Head>
                <Table.Head>执行详情</Table.Head>
                <Table.Head>状态</Table.Head>
                <Table.Head>请求时间</Table.Head>
                <Table.Head class="text-right">操作</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {#each approvals as approval (approval.id)}
                <Table.Row>
                  <Table.Cell>
                    <p class="mb-1 font-medium">{approvalKindLabel(approval.kind)}</p>
                    <p class="mb-2 text-xs text-muted-foreground">{approvalAuthorityLabel(approval.kind)}</p>
                    {#if approval.authorized_until}<p class="text-xs">授权截至 {dateLabel(approval.authorized_until)}</p>{/if}
                    {#if approval.revoked_at}<p class="text-sm text-destructive">授权已撤销</p>{/if}
                    {#if data.details[approval.id]}<p class="font-medium">{data.details[approval.id].title}</p><p class="mt-1 text-sm">{data.details[approval.id].name === 'builtin.work_item_read' ? '读取当前工作项' : data.details[approval.id].name}</p><p class="mt-1 text-xs text-muted-foreground">{data.details[approval.id].scope}</p><details class="mt-2"><summary class="cursor-pointer text-sm">查看执行参数</summary><pre class="max-h-64 max-w-md overflow-auto whitespace-pre-wrap break-words text-xs">{JSON.stringify(data.details[approval.id].input, null, 2)}</pre></details>{:else}<p class="text-sm">请进入运行详情核对操作</p>{/if}
                    <details><summary class="cursor-pointer text-sm">审批标识</summary><span class="font-mono text-xs">{approval.id}</span></details>
                    {#if approval.reason}
                      <p class="mt-1 max-w-xs text-xs text-muted-foreground">{approval.reason}</p>
                    {/if}
                  </Table.Cell>
                  <Table.Cell>
                    <a class="font-mono text-xs hover:underline" href={`${workspaceBase}/runs/${approval.run_id}`}>查看待确认操作与运行详情</a>

                  </Table.Cell>
                  <Table.Cell><Badge variant={statusVariant(approval.status)}>{statusLabel(approval.status)}</Badge></Table.Cell>
                  <Table.Cell class="text-muted-foreground">{dateLabel(approval.requested_at)}</Table.Cell>
                  <Table.Cell class="text-right">
                    {#if approval.status === 'pending' && approval.can_decide}
                      <div class="flex min-w-56 flex-col items-end gap-2">
                        <form method="POST" action="?/decide" class="flex w-full gap-2">
                          <input type="hidden" name="approval_id" value={approval.id} />
                          <input type="hidden" name="decision" value="approve" />
                          <Input name="reason" aria-label="批准理由" placeholder={approval.kind === 'resource_access' ? '授权理由（必填）' : '可选理由'} required={approval.kind === 'resource_access'} class="min-w-0 flex-1" />
                          <Button type="submit" size="sm" disabled={!data.details[approval.id]}>批准</Button>
                        </form>
                        <form method="POST" action="?/decide" class="flex w-full gap-2">
                          <input type="hidden" name="approval_id" value={approval.id} />
                          <input type="hidden" name="decision" value="reject" />
                          <Input name="reason" aria-label="拒绝理由" placeholder="拒绝理由" required={approval.kind === 'resource_access'} class="min-w-0 flex-1" />
                          <Button type="submit" variant="destructive" size="sm">拒绝</Button>
                        </form>
                      </div>
                    {:else if approval.kind === 'resource_access' && approval.status === 'approved' && !approval.revoked_at && approval.can_decide}
                      <form method="POST" action="?/decide" class="space-y-2">
                        <input type="hidden" name="approval_id" value={approval.id} />
                        <input type="hidden" name="decision" value="revoke" />
                        <Input name="reason" aria-label="撤销理由" placeholder="撤销理由（必填）" required />
                        <Button type="submit" variant="outline" size="sm">撤销未执行授权</Button>
                      </form>
                    {:else}
                      <span class="text-xs text-muted-foreground">{approval.status === 'pending' ? '等待有权处理的人' : '已处理'}</span>
                    {/if}
                  </Table.Cell>
                </Table.Row>
              {/each}
            </Table.Body>
          </Table.Root>
        {:else}
          <div class="rounded-lg border border-dashed border-border px-5 py-12 text-center">
            <h2 class="font-medium">没有待处理审批</h2>
            <p class="mt-2 text-sm text-muted-foreground">当前条件下没有审批。任务需要你确认工具操作时，会显示在这里。</p>
          </div>
        {/if}
      </Card.Content>
    </Card.Root>
  {/if}
</main>
