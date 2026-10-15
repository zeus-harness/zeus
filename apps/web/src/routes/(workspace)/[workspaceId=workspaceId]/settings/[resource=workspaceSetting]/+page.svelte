<script lang="ts">
  import ResourceCollection from '$lib/features/control-plane/ResourceCollection.svelte';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';
  import type { ActionData, PageData } from './$types';

  let { data, form }: { data: PageData; form: ActionData } = $props();
  function enabled(executor: string) {
    const definition = data.catalog.find(item => item.executor_key === executor);
    return data.collection.records.some(record => record.capability_id === definition?.id && record.enabled === '已启用');
  }
</script>

<svelte:head><title>Zeus · {data.resource.label}</title></svelte:head>

{#if data.collection}
{#if data.resource.slug === 'capabilities'}
  <section class="space-y-4 px-5 pt-7 lg:px-8">
    <Card.Root>
      <Card.Header><Card.Title>读取当前工作项</Card.Title><Card.Description>Agent 可读取当前运行关联工作项的标题、描述和输入。首次注册需要 Organization Owner，Workspace Owner 可启用已有工具。</Card.Description></Card.Header>
      <Card.Content>
        {#if form?.type === 'error'}<p role="alert" class="mb-4 text-sm text-destructive">{form.message}</p>{/if}
        <form method="POST" action="?/enableWorkItemRead" class="flex flex-wrap items-center gap-4">
          <label class="flex items-center gap-2 text-sm"><input type="checkbox" name="approval_required" checked />执行前需要审批</label>
          <Button type="submit">{enabled('builtin.work_item_read') ? '更新审批设置' : '启用工作项读取'}</Button>
          <Button href={`/${data.workspaceId}/workflows`} variant="outline">配置 Workflow 工具</Button>
        </form>
      </Card.Content>
    </Card.Root>
    <Card.Root>
      <Card.Header><Card.Title>Alpine 隔离脚本</Card.Title><Card.Description>在独立环境中使用 Git、Node、Python 和 Rust。每次脚本都需人工审批，默认断网；Workflow 必须绑定代码仓库和固定执行环境。</Card.Description></Card.Header>
      <Card.Content>
        <form method="POST" action="?/enableSandboxExec" class="flex flex-wrap items-center gap-4">
          <Button type="submit" disabled={enabled('builtin.sandbox_exec')}>{enabled('builtin.sandbox_exec') ? '隔离脚本已启用 · 每次需审批' : '启用隔离脚本'}</Button>
          <span class="text-sm text-muted-foreground">首次注册需要 Organization Owner，启用需要 Workspace Owner。</span>
        </form>
      </Card.Content>
    </Card.Root>
    <Card.Root>
      <Card.Header><Card.Title>受限工具授权</Card.Title><Card.Description>开启后，每次调用先申请 Workspace Owner 授权，再由运行发起人确认。授权只覆盖本次参数，最长 1 小时；禁用的工具仍不可使用。</Card.Description></Card.Header>
      <Card.Content class="space-y-4">
        {#if form?.type === 'success'}<p role="status">{form.message}</p>{/if}
        {#each data.collection.records as record (record.id)}
          <form method="POST" action="?/authorization" class="flex flex-wrap items-center gap-3">
            <input type="hidden" name="capability_id" value={String(record.capability_id)} />
            <input type="hidden" name="revision" value={String(record.revision)} />
            <label class="flex items-center gap-2 text-sm"><input type="checkbox" name="resource_authorization_required" checked={Boolean(record.policy && typeof record.policy === 'object' && 'resource_authorization_required' in record.policy && record.policy.resource_authorization_required)} />{String(record.display_name)}：需要资源授权</label>
            <Button type="submit" variant="outline" size="sm">保存授权策略</Button>
          </form>
        {/each}
      </Card.Content>
    </Card.Root>
  </section>
{/if}
<ResourceCollection
  resource={data.resource}
  collection={data.collection}
  backHref={`/${data.workspaceId}/settings`}
  refreshHref={`/${data.workspaceId}/settings/${data.resource.slug}`}
/>
{/if}
