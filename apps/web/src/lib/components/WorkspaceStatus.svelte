<script lang="ts">
  import { Badge } from '@zeus/ui/components/ui/badge';

  import type { WorkspaceStatus as ApiStatus } from '$lib/api/client';

  let {
    status,
    message,
    httpStatus,
    title = 'Workspace 状态'
  }: {
    status: ApiStatus;
    message: string;
    httpStatus?: number;
    title?: string;
  } = $props();

  function statusLabel(value: ApiStatus): string {
    switch (value) {
      case 'ready':
        return 'API connected';
      case 'not-configured':
        return 'Workspace required';
      case 'unauthenticated':
        return 'Sign-in required';
      case 'unauthorized':
        return 'Access denied';
      case 'not-available':
        return 'API unavailable';
      case 'error':
        return 'Request failed';
    }
  }
</script>

<section class="rounded-xl border border-border bg-card p-5 shadow-xs" role="status" aria-live="polite">
  <div class="flex flex-wrap items-start justify-between gap-3">
    <div>
      <p class="text-xs font-semibold uppercase tracking-[0.12em] text-muted-foreground">{title}</p>
      <h2 class="mt-2 text-base font-semibold">
        {#if status === 'unauthenticated'}
          需要登录
        {:else if status === 'not-configured'}
          需要 Workspace 上下文
        {:else if status === 'unauthorized'}
          无法访问此 Workspace
        {:else if status === 'not-available'}
          API 尚未提供
        {:else}
          暂时无法加载
        {/if}
      </h2>
    </div>
    <Badge variant={status === 'ready' ? 'secondary' : 'outline'}>{statusLabel(status)}</Badge>
  </div>
  <p class="mt-3 max-w-2xl text-sm leading-6 text-muted-foreground">{message}</p>
  {#if httpStatus}
    <p class="mt-2 font-mono text-xs text-muted-foreground">HTTP {httpStatus}</p>
  {/if}
</section>
