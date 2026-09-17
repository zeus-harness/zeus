<script lang="ts">
  import { ArrowRight } from '@lucide/svelte';

  import { Button } from '@zeus/ui/components/ui/button';
  import { Input } from '@zeus/ui/components/ui/input';
  import * as Card from '@zeus/ui/components/ui/card';

  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import type { ActionData, PageData } from './$types';

  let { data, form }: { data: PageData; form: ActionData } = $props();
</script>

<svelte:head><title>Zeus · Workspace 设置</title></svelte:head>

<main class="px-5 py-7 lg:px-8 lg:py-9">
  <PageHeader
    eyebrow="Workspace"
    title="设置"
    description="管理 Workspace 基础信息、成员、Capability Policy 和机器身份。"
  />
  <Card.Root class="mt-7">
    <Card.Header>
      <Card.Title>基础信息</Card.Title>
      <Card.Description>Workspace 名称用于导航和工作空间列表，修改后不影响现有资源链接。</Card.Description>
    </Card.Header>
    <Card.Content>
      <form method="POST" action="?/save" class="max-w-xl space-y-4">
        {#if form}
          <p role={form.saved ? 'status' : 'alert'} class={form.saved ? 'text-sm' : 'text-sm text-destructive'}>{form.message}</p>
        {/if}
        <input type="hidden" name="revision" value={form && !form.saved ? form.revision : data.workspace.revision} />
        <div>
          <label for="workspace-name" class="text-sm font-medium">Workspace 名称</label>
          <Input id="workspace-name" name="name" required maxlength={160} class="mt-2" value={form && !form.saved ? form.name : data.workspace.name} />
        </div>
        <div>
          <p class="text-sm font-medium">Workspace 标识（slug）</p>
          <p class="mt-2 text-sm text-muted-foreground">{data.workspace.slug}</p>
        </div>
        <Button type="submit">保存基础信息</Button>
      </form>
    </Card.Content>
  </Card.Root>
  <div class="mt-7 grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
    {#each data.resources as resource (resource.slug)}
      <a href={`/${data.workspaceId}/settings/${resource.slug}`} class="group">
        <Card.Root class="h-full transition-colors group-hover:border-foreground/30">
          <Card.Header>
            <Card.Title class="flex items-center justify-between gap-3">{resource.label}<ArrowRight class="size-4 text-muted-foreground" /></Card.Title>
            <Card.Description>{resource.description}</Card.Description>
          </Card.Header>
        </Card.Root>
      </a>
    {/each}
  </div>
</main>
