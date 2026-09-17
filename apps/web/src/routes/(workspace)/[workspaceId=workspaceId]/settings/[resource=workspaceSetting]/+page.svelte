<script lang="ts">
  import ResourceCollection from '$lib/features/control-plane/ResourceCollection.svelte';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';
  import type { ActionData, PageData } from './$types';

  let { data, form }: { data: PageData; form: ActionData } = $props();
</script>

<svelte:head><title>Zeus · {data.resource.label}</title></svelte:head>

{#if data.collection}
{#if data.resource.slug === 'capabilities'}
  <section class="px-5 pt-7 lg:px-8">
    <Card.Root>
      <Card.Header><Card.Title>读取当前工作项</Card.Title><Card.Description>Agent 可读取当前运行关联工作项的标题、描述和输入。首次注册需要 Organization Owner，Workspace Owner 可启用已有工具。</Card.Description></Card.Header>
      <Card.Content>
        {#if form?.type === 'error'}<p role="alert" class="mb-4 text-sm text-destructive">{form.message}</p>{/if}
        <form method="POST" action="?/enableWorkItemRead" class="flex flex-wrap items-center gap-4">
          <label class="flex items-center gap-2 text-sm"><input type="checkbox" name="approval_required" checked />执行前需要审批</label>
          <Button type="submit">启用工作项读取</Button>
          <Button href={`/${data.workspaceId}/workflows`} variant="outline">配置 Workflow 工具</Button>
        </form>
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
