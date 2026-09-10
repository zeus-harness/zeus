<script lang="ts">
  import * as Card from '@zeus/ui/components/ui/card';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
</script>

<svelte:head><title>Zeus · 平台安全事件</title></svelte:head>

<main class="px-5 py-7 lg:px-8 lg:py-9">
  <PageHeader eyebrow="Platform" title="安全事件" description="平台安全事件和租户 Audit 保持分离。" />
  <Card.Root class="mt-7"><Card.Header><Card.Title>查询 API 尚未接入</Card.Title><Card.Description>平台控制台不会借用 Organization Audit 接口拼接全局日志。</Card.Description></Card.Header></Card.Root>
</main>
