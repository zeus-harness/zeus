<script lang="ts">
  import { ArrowRight } from '@lucide/svelte';

  import * as Card from '@zeus/ui/components/ui/card';

  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import type { PageData } from './$types';

  let { data }: { data: PageData } = $props();
</script>

<svelte:head><title>Zeus · Workspace 设置</title></svelte:head>

<main class="px-5 py-7 lg:px-8 lg:py-9">
  <PageHeader
    eyebrow="Workspace"
    title="设置"
    description="成员、模型、连接、Capability Policy 和机器身份与 Agent 构建区分开管理。"
  />
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
