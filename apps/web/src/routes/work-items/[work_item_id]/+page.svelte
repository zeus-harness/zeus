<script lang="ts">
  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';
  import { Separator } from '@zeus/ui/components/ui/separator';

  import WorkspaceStatus from '$lib/components/WorkspaceStatus.svelte';

  import type { ActionData, PageData } from './$types';

  let { data, form } = $props<{ data: PageData; form: ActionData }>();
  let item = $derived(data.result.data);

  function dateLabel(value: string | null): string {
    return value ? value.replace('T', ' ').replace(/\.\d+Z$/, ' UTC').replace('Z', ' UTC') : '—';
  }

  function formatJson(value: unknown): string {
    try {
      return JSON.stringify(value, null, 2) ?? '—';
    } catch {
      return '—';
    }
  }

  function statusVariant(status: string): 'default' | 'secondary' | 'destructive' | 'outline' {
    if (status === 'completed') return 'secondary';
    if (status === 'blocked' || status === 'canceled') return 'destructive';
    if (status === 'in_progress') return 'default';
    return 'outline';
  }
</script>

<svelte:head>
  <title>Zeus · WorkItem 详情</title>
</svelte:head>

<main class="mx-auto max-w-[1200px] px-5 py-8 lg:px-8 lg:py-10">
  {#if data.result.status !== 'ready' || !item}
    <WorkspaceStatus
      status={data.result.status}
      message={data.result.message}
      httpStatus={data.result.httpStatus}
      title="WorkItem 详情"
    />
  {:else}
    <div class="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
      <div>
        <a class="text-sm text-muted-foreground hover:underline" href="/work-items">← 返回 WorkItems</a>
        <h1 class="mt-3 text-3xl font-semibold tracking-tight">{item.title}</h1>
        <p class="mt-2 font-mono text-xs text-muted-foreground">{item.id}</p>
      </div>
      <Badge variant={statusVariant(item.status)}>{item.status}</Badge>
    </div>

    {#if form?.type === 'error'}
      <div class="mt-6 rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive" role="alert">
        {form.message}
      </div>
    {/if}

    <div class="mt-8 grid gap-6 lg:grid-cols-[minmax(0,1fr)_20rem]">
      <Card.Root>
        <Card.Header>
          <Card.Title>工作项详情</Card.Title>
          <Card.Description>{item.description || '没有描述。'}</Card.Description>
        </Card.Header>
        <Card.Content class="space-y-5">
          <div class="grid gap-4 sm:grid-cols-2">
            <div>
              <dt class="text-xs font-semibold uppercase tracking-wide text-muted-foreground">优先级</dt>
              <dd class="mt-1 text-sm">{item.priority}</dd>
            </div>
            <div>
              <dt class="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Revision</dt>
              <dd class="mt-1 font-mono text-sm">{item.revision}</dd>
            </div>
            <div>
              <dt class="text-xs font-semibold uppercase tracking-wide text-muted-foreground">创建时间</dt>
              <dd class="mt-1 text-sm text-muted-foreground">{dateLabel(item.created_at)}</dd>
            </div>
            <div>
              <dt class="text-xs font-semibold uppercase tracking-wide text-muted-foreground">更新时间</dt>
              <dd class="mt-1 text-sm text-muted-foreground">{dateLabel(item.updated_at)}</dd>
            </div>
            <div>
              <dt class="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Assignee</dt>
              <dd class="mt-1 break-all font-mono text-xs">{item.assignee_user_id ?? '—'}</dd>
            </div>
            <div>
              <dt class="text-xs font-semibold uppercase tracking-wide text-muted-foreground">外部引用</dt>
              <dd class="mt-1 break-all text-sm">{item.external_reference ?? '—'}</dd>
            </div>
          </div>
          <Separator />
          <div>
            <h2 class="text-sm font-semibold">Input</h2>
            <pre class="mt-2 max-h-72 overflow-auto rounded-lg bg-muted p-3 font-mono text-xs leading-5">{formatJson(item.input)}</pre>
          </div>
          {#if item.output}
            <div>
              <h2 class="text-sm font-semibold">Output</h2>
              <pre class="mt-2 max-h-72 overflow-auto rounded-lg bg-muted p-3 font-mono text-xs leading-5">{formatJson(item.output)}</pre>
            </div>
          {/if}
        </Card.Content>
      </Card.Root>

      <Card.Root>
        <Card.Header>
          <Card.Title>更新状态</Card.Title>
          <Card.Description>使用当前 revision，避免覆盖其他协作者的更新。</Card.Description>
        </Card.Header>
        <Card.Content>
          <form method="POST" action="?/update" class="space-y-4">
            <input type="hidden" name="revision" value={item.revision} />
            <div>
              <label class="text-sm font-medium" for="status">状态</label>
              <select id="status" name="status" value={item.status} class="mt-2 h-10 w-full rounded-md border border-input bg-background px-3 text-sm">
                <option value="open">Open</option>
                <option value="in_progress">In progress</option>
                <option value="blocked">Blocked</option>
                <option value="completed">Completed</option>
                <option value="canceled">Canceled</option>
              </select>
            </div>
            <Button type="submit" class="w-full">保存状态</Button>
          </form>
        </Card.Content>
      </Card.Root>
    </div>
  {/if}
</main>
