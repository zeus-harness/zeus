<script lang="ts">
  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';
  import { Input } from '@zeus/ui/components/ui/input';
  import { Label } from '@zeus/ui/components/ui/label';

  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import type { ActionData, PageData } from './$types';

  let { data, form }: { data: PageData; form: ActionData } = $props();
</script>

<svelte:head><title>Zeus · {data.organization.name}</title></svelte:head>

<main class="px-5 py-7 lg:px-8 lg:py-9">
  <PageHeader
    eyebrow="Organization"
    title={data.organization.name}
    description="Organization 元数据、成员、Workspace 生命周期和身份边界。"
  >
    {#snippet actions()}<Badge variant="outline">{data.organization.status}</Badge>{/snippet}
  </PageHeader>
  {#if form?.type === 'error'}<p class="mt-6 text-sm text-destructive" role="alert">{form.message}</p>{/if}
  <div class="mt-7 grid gap-6 xl:grid-cols-[minmax(0,1fr)_22rem]">
    <Card.Root>
      <Card.Header><Card.Title>基本信息</Card.Title><Card.Description>激活后的 slug 不在这里修改。</Card.Description></Card.Header>
      <Card.Content>
        <form method="POST" action="?/update" class="space-y-4">
          <input type="hidden" name="revision" value={data.organization.revision} />
          <div class="space-y-2"><Label for="organization-name">名称</Label><Input id="organization-name" name="name" value={data.organization.name} required /></div>
          <div class="space-y-2"><Label for="organization-slug">Slug</Label><Input id="organization-slug" value={data.organization.slug} disabled /></div>
          <Button type="submit">保存修改</Button>
        </form>
      </Card.Content>
    </Card.Root>
    <Card.Root>
      <Card.Header><Card.Title>状态</Card.Title><Card.Description>状态变更由平台控制台处理。</Card.Description></Card.Header>
      <Card.Content class="space-y-2 text-sm text-muted-foreground">
        <p>Revision {data.organization.revision}</p>
        <p>创建于 {data.organization.created_at}</p>
      </Card.Content>
    </Card.Root>
  </div>
</main>
