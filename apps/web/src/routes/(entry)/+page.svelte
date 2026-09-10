<script lang="ts">
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';
</script>

<svelte:head><title>Zeus · 服务暂不可用</title></svelte:head>

<main class="grid min-h-screen place-items-center bg-muted/20 p-6">
  <Card.Root class="w-full max-w-md">
    <Card.Header>
      <Card.Title>暂时无法确认登录状态</Card.Title>
      <Card.Description>Zeus API 当前不可用。恢复后可重新加载入口。</Card.Description>
    </Card.Header>
    <Card.Footer><Button href="/">重新加载</Button></Card.Footer>
  </Card.Root>
</main>
