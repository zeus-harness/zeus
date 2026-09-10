<script lang="ts">
  import * as Card from '@zeus/ui/components/ui/card';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
</script>

<svelte:head><title>Zeus · 平台用户</title></svelte:head>

<main class="px-5 py-7 lg:px-8 lg:py-9">
  <PageHeader eyebrow="Platform" title="用户" description="平台账号停用与匿名化 API 尚未接入此页面。" />
  <Card.Root class="mt-7"><Card.Header><Card.Title>边界已保留</Card.Title><Card.Description>本页不读取租户成员表。用户生命周期会使用独立的平台 API。</Card.Description></Card.Header></Card.Root>
</main>
