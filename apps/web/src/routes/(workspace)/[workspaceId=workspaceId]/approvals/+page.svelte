<script lang="ts">
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

  function dateLabel(value: string | null): string {
    return value ? value.replace('T', ' ').replace(/\.\d+Z$/, ' UTC').replace('Z', ' UTC') : '—';
  }

  function statusVariant(status: string): 'default' | 'secondary' | 'destructive' | 'outline' {
    if (status === 'approved') return 'secondary';
    if (status === 'rejected' || status === 'expired' || status === 'canceled') return 'destructive';
    return 'outline';
  }
</script>

<svelte:head>
  <title>Zeus · Approvals</title>
</svelte:head>

<main class="mx-auto max-w-[1480px] px-5 py-8 lg:px-8 lg:py-10">
  <div class="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
    <div>
      <p class="text-sm font-medium text-muted-foreground">Human-in-the-loop controls</p>
      <h1 class="mt-2 text-3xl font-semibold tracking-tight">Approvals</h1>
      <p class="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
        处理当前 Workspace 中待确认的 Capability 工具调用。批准或拒绝会写回 Run 的持久事件。
      </p>
    </div>
    {#if data.result.status === 'ready'}
      <Badge variant="secondary">{approvals.length} approvals</Badge>
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
          <Card.Description>默认只显示 pending，也可以查看其他状态。</Card.Description>
        </div>
        <form method="GET" class="grid gap-3 sm:grid-cols-[11rem_minmax(15rem,1fr)_auto] sm:items-end">
          <div class="space-y-2"><Label for="approval-status">审批状态</Label>
          <NativeSelect id="approval-status" name="status" value={data.filterStatus} class="w-full">
            <NativeSelectOption value="pending">Pending</NativeSelectOption>
            <NativeSelectOption value="all">All</NativeSelectOption>
            <NativeSelectOption value="approved">Approved</NativeSelectOption>
            <NativeSelectOption value="rejected">Rejected</NativeSelectOption>
            <NativeSelectOption value="expired">Expired</NativeSelectOption>
            <NativeSelectOption value="canceled">Canceled</NativeSelectOption>
          </NativeSelect>
          </div>
          <div class="space-y-2"><Label for="approval-work-item">WorkItem ID</Label><Input id="approval-work-item" name="work_item_id" value={data.filterWorkItemId} placeholder="留空查看全部" /></div>
          <Button type="submit" variant="outline" size="sm">筛选</Button>
        </form>
      </Card.Header>
      <Card.Content>
        {#if approvals.length > 0}
          <Table.Root>
            <Table.Header>
              <Table.Row>
                <Table.Head>Approval</Table.Head>
                <Table.Head>Run / Tool call</Table.Head>
                <Table.Head>状态</Table.Head>
                <Table.Head>请求时间</Table.Head>
                <Table.Head class="text-right">操作</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {#each approvals as approval (approval.id)}
                <Table.Row>
                  <Table.Cell>
                    <span class="font-mono text-xs">{approval.id}</span>
                    {#if approval.reason}
                      <p class="mt-1 max-w-xs text-xs text-muted-foreground">{approval.reason}</p>
                    {/if}
                  </Table.Cell>
                  <Table.Cell>
                    <a class="font-mono text-xs hover:underline" href={`${workspaceBase}/runs/${approval.run_id}`}>{approval.run_id}</a>
                    <p class="mt-1 font-mono text-xs text-muted-foreground">tool {approval.tool_call_id}</p>
                  </Table.Cell>
                  <Table.Cell><Badge variant={statusVariant(approval.status)}>{approval.status}</Badge></Table.Cell>
                  <Table.Cell class="text-muted-foreground">{dateLabel(approval.requested_at)}</Table.Cell>
                  <Table.Cell class="text-right">
                    {#if approval.status === 'pending'}
                      <div class="flex min-w-56 flex-col items-end gap-2">
                        <form method="POST" action="?/decide" class="flex w-full gap-2">
                          <input type="hidden" name="approval_id" value={approval.id} />
                          <input type="hidden" name="decision" value="approve" />
                          <Input name="reason" aria-label="批准理由" placeholder="可选理由" class="min-w-0 flex-1" />
                          <Button type="submit" size="sm">批准</Button>
                        </form>
                        <form method="POST" action="?/decide" class="flex w-full gap-2">
                          <input type="hidden" name="approval_id" value={approval.id} />
                          <input type="hidden" name="decision" value="reject" />
                          <Input name="reason" aria-label="拒绝理由" placeholder="拒绝理由（可选）" class="min-w-0 flex-1" />
                          <Button type="submit" variant="destructive" size="sm">拒绝</Button>
                        </form>
                      </div>
                    {:else}
                      <span class="text-xs text-muted-foreground">已处理</span>
                    {/if}
                  </Table.Cell>
                </Table.Row>
              {/each}
            </Table.Body>
          </Table.Root>
        {:else}
          <div class="rounded-lg border border-dashed border-border px-5 py-12 text-center">
            <h2 class="font-medium">没有待处理审批</h2>
            <p class="mt-2 text-sm text-muted-foreground">API 已连接，当前筛选条件没有返回记录。</p>
          </div>
        {/if}
      </Card.Content>
    </Card.Root>
  {/if}
</main>
