<script lang="ts">
  import { onMount, type Snippet } from 'svelte';
  import { TriangleAlert } from '@lucide/svelte';

  import * as Alert from '@zeus/ui/components/ui/alert';
  import { Button } from '@zeus/ui/components/ui/button';

  import {
    WORKSPACE_CONTEXT_CHANNEL,
    type WorkspaceContextMessage
  } from './workspace-channel';

  let { children, workspaceId }: { children: Snippet; workspaceId: string } = $props();
  let stale = $state(false);

  onMount(() => {
    if (typeof BroadcastChannel === 'undefined') return;
    const channel = new BroadcastChannel(WORKSPACE_CONTEXT_CHANNEL);
    channel.onmessage = (event: MessageEvent<WorkspaceContextMessage>) => {
      if (event.data?.type === 'workspace-selected' && event.data.workspaceId !== workspaceId) {
        stale = true;
      }
    };
    return () => channel.close();
  });

  function blockStaleWrite(event: SubmitEvent): void {
    if (!stale) return;
    event.preventDefault();
    event.stopPropagation();
  }
</script>

<div onsubmitcapture={blockStaleWrite}>
  {#if stale}
    <div class="sticky top-16 z-30 border-b border-destructive/30 bg-background px-5 py-3 lg:px-8">
      <Alert.Root variant="destructive">
        <TriangleAlert class="size-4" />
        <Alert.Title>Workspace 已在另一个标签页切换</Alert.Title>
        <Alert.Description>
          此页面已停止提交写操作。重新选择 Workspace 后再继续。
        </Alert.Description>
        <Alert.Action>
          <Button href="/workspaces" variant="outline" size="sm">重新选择</Button>
        </Alert.Action>
      </Alert.Root>
    </div>
  {/if}
  <div class:pointer-events-none={stale} class:select-none={stale} aria-disabled={stale}>
    {@render children()}
  </div>
</div>
