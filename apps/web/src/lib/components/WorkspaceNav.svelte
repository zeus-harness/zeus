<script lang="ts">
  import { page } from '$app/state';

  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import { Separator } from '@zeus/ui/components/ui/separator';

  import type { PrincipalResult } from '$lib/api/server';

  const navigation = [
    { href: '/', label: '概览' },
    { href: '/work-items', label: 'WorkItems' },
    { href: '/runs', label: 'Runs' },
    { href: '/approvals', label: 'Approvals' },
    { href: '/experience', label: 'Experience' }
  ] as const;

  let {
    authStatus,
    workspaceId,
    displayName
  }: {
    authStatus: PrincipalResult['status'];
    workspaceId?: string | null;
    displayName?: string | null;
  } = $props();

  let pathname = $derived(page.url.pathname);

  function isActive(href: string): boolean {
    return href === '/' ? pathname === '/' : pathname === href || pathname.startsWith(`${href}/`);
  }

  function shortId(value: string): string {
    return value.length > 18 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value;
  }
</script>

<header class="border-b border-border bg-card/90 backdrop-blur">
  <div class="mx-auto flex min-h-16 max-w-[1480px] flex-wrap items-center gap-3 px-5 py-3 lg:px-8">
    <a class="flex items-center gap-3 font-semibold tracking-tight" href="/" aria-label="返回 Zeus 概览">
      <span class="flex size-9 items-center justify-center rounded-xl bg-primary text-primary-foreground">Z</span>
      <span>Zeus</span>
    </a>
    <Separator orientation="vertical" class="hidden h-6 sm:block" />
    <nav class="order-3 flex w-full gap-1 overflow-x-auto sm:order-none sm:w-auto" aria-label="工作区导航">
      {#each navigation as item (item.href)}
        <a
          class={isActive(item.href)
            ? 'whitespace-nowrap rounded-lg bg-accent px-3 py-2 text-sm font-medium text-accent-foreground'
            : 'whitespace-nowrap rounded-lg px-3 py-2 text-sm text-muted-foreground hover:bg-accent hover:text-accent-foreground'}
          href={item.href}
          aria-current={isActive(item.href) ? 'page' : undefined}
        >
          {item.label}
        </a>
      {/each}
    </nav>
    <div class="ml-auto flex items-center gap-2">
      {#if authStatus === 'ready' && workspaceId}
        <Badge variant="outline" title={workspaceId}>Workspace {shortId(workspaceId)}</Badge>
        {#if displayName}
          <span class="hidden text-sm text-muted-foreground md:inline">{displayName}</span>
        {/if}
      {:else if authStatus === 'unauthenticated'}
        <Badge variant="outline">未登录</Badge>
      {:else if authStatus === 'unavailable'}
        <Badge variant="outline">API unavailable</Badge>
      {:else}
        <Badge variant="outline">Workspace 未配置</Badge>
      {/if}
      <Button href="/work-items#new" size="sm">新建 WorkItem</Button>
    </div>
  </div>
</header>
