<script lang="ts">
  import { Button } from '@zeus/ui/components/ui/button';
  import type { PageProps } from './$types';
  let { data, form }: PageProps = $props();
  let configured = $derived(data.workflows.find(w => w.name === 'Agent Studio 聊天'));
</script>
<svelte:head><title>聊天设置 · Zeus</title></svelte:head>
<main class="mx-auto max-w-3xl space-y-6 px-5 py-8">
  <a class="text-sm underline" href={`/${data.workspaceId}/settings`}>返回工作空间设置</a>
  <h1 class="text-2xl font-semibold">Agent Studio 聊天设置</h1>
  <p>管理聊天助手、模型来源和自动创建工作的权限。聊天页面只保留会话本身。</p>
  {#if form?.message}<p role="alert">{form.message}</p>{/if}
  {#if data.saved}<p role="status">聊天助手已配置。</p>{/if}
  {#if configured}
    <section class="space-y-3 rounded-lg border p-5"><h2 class="font-medium">聊天助手已就绪</h2><p>普通聊天直接回复；遇到明确的工作，会按当前用户权限创建工作项或未发布流程。不会自动发布或启动执行。</p><Button href={`/${data.workspaceId}/studio`}>开始聊天</Button></section>
  {:else}
    <form method="POST" action="?/prepare" class="space-y-4 rounded-lg border p-5">
      <p>沿用已有流程的组织模型，配置专用聊天助手及受控的资源创建工具。模型密钥不会复制到工作空间。</p>
      <label class="block space-y-2"><span>模型来源</span><select name="workflow_id" required class="block max-w-full rounded border p-2"><option value="" disabled selected>选择已发布流程的模型</option>{#each data.workflows as w (w.id)}<option value={w.id}>{w.name}</option>{/each}</select></label>
      <Button type="submit" disabled={!data.workflows.length}>配置聊天助手</Button>
    </form>
  {/if}
  <nav aria-label="聊天配置" class="flex flex-wrap gap-4 text-sm">
    <a class="underline" href={`/${data.workspaceId}/agents`}>助手指令与模型</a>
    <a class="underline" href={`/${data.workspaceId}/workflows${configured ? `?selected=${configured.id}` : ''}`}>聊天流程与执行限制</a>
    <a class="underline" href={`/${data.workspaceId}/settings/capabilities`}>自动创建权限与审批</a>
  </nav>
</main>
