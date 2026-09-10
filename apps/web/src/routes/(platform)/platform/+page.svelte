<script lang="ts">
  import { Building2, CirclePause, Clock3, ShieldCheck } from '@lucide/svelte';

  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';

  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import type { PageData } from './$types';

  let { data }: { data: PageData } = $props();
</script>

<svelte:head><title>Zeus · 平台控制台</title></svelte:head>

<main class="px-5 py-7 lg:px-8 lg:py-9">
  <PageHeader eyebrow="Platform" title="平台控制台" description="管理 Organization 生命周期。租户数据访问需要单独创建限时支持会话。">
    {#snippet actions()}<Button href="/platform/organizations">管理 Organizations</Button>{/snippet}
  </PageHeader>
  <section class="mt-7 grid gap-4 sm:grid-cols-2 xl:grid-cols-4" aria-label="Organization 摘要">
    <Card.Root><Card.Header><Card.Description class="flex items-center gap-2"><Building2 class="size-4" />全部</Card.Description><Card.Title class="text-3xl">{data.organizationCount}</Card.Title></Card.Header></Card.Root>
    <Card.Root><Card.Header><Card.Description class="flex items-center gap-2"><ShieldCheck class="size-4" />Active</Card.Description><Card.Title class="text-3xl">{data.activeCount}</Card.Title></Card.Header></Card.Root>
    <Card.Root><Card.Header><Card.Description class="flex items-center gap-2"><Clock3 class="size-4" />Provisioning</Card.Description><Card.Title class="text-3xl">{data.provisioningCount}</Card.Title></Card.Header></Card.Root>
    <Card.Root><Card.Header><Card.Description class="flex items-center gap-2"><CirclePause class="size-4" />Suspended</Card.Description><Card.Title class="text-3xl">{data.suspendedCount}</Card.Title></Card.Header></Card.Root>
  </section>
</main>
