<script lang="ts">
  import { page } from '$app/state';
  import type { Component, Snippet } from 'svelte';
  import {
    Activity,
    BookOpen,
    Bot,
    Building2,
    Check,
    CheckSquare,
    ChevronDown,
    ClipboardList,
    LayoutDashboard,
    Menu,
    Settings,
    UserRound
  } from '@lucide/svelte';

  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as DropdownMenu from '@zeus/ui/components/ui/dropdown-menu';
  import * as Sheet from '@zeus/ui/components/ui/sheet';
  import { Separator } from '@zeus/ui/components/ui/separator';

  import type { UserOrganization } from '$lib/api/identity';
  import type { CurrentPrincipal, PrincipalResult } from '$lib/api/server';

  type Area = 'app' | 'account' | 'admin';
  type NavigationItem = { href: string; label: string; icon: Component };

  const primaryNavigation: NavigationItem[] = [
    { href: '/', label: '工作台', icon: LayoutDashboard },
    { href: '/work-items', label: '工作项', icon: ClipboardList },
    { href: '/runs', label: '运行', icon: Activity },
    { href: '/approvals', label: '审批', icon: CheckSquare },
    { href: '/experience', label: '经验', icon: BookOpen }
  ];
  const secondaryNavigation: NavigationItem[] = [
    { href: '/admin/agents', label: 'Agent 构建', icon: Bot },
    { href: '/admin', label: 'Organization 管理', icon: Building2 },
    { href: '/account/profile', label: '账号设置', icon: Settings }
  ];

  let {
    children,
    authStatus,
    principal,
    organizations,
    area = 'app'
  }: {
    children: Snippet;
    authStatus: PrincipalResult['status'];
    principal: CurrentPrincipal | null;
    organizations: UserOrganization[];
    area?: Area;
  } = $props();

  let pathname = $derived(page.url.pathname);
  let returnTo = $derived(`${page.url.pathname}${page.url.search}`);
  let currentWorkspace = $derived(
    organizations
      .flatMap((organization) =>
        organization.workspaces.map((workspace) => ({ ...workspace, organization }))
      )
      .find((workspace) => workspace.id === principal?.workspace_id)
  );
  let workspaceLabel = $derived(
    currentWorkspace?.name ?? (principal?.workspace_id ? shortId(principal.workspace_id) : '选择 Workspace')
  );

  function isActive(href: string): boolean {
    return href === '/' ? pathname === '/' : pathname === href || pathname.startsWith(`${href}/`);
  }

  function shortId(value: string): string {
    return value.length > 18 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value;
  }
</script>

<div class="min-h-screen bg-muted/20 text-foreground">
  <header class="sticky top-0 z-40 border-b border-border bg-background/95 backdrop-blur">
    <div class="flex h-16 items-center gap-3 px-4 lg:px-6">
      <Sheet.Root>
        <Sheet.Trigger>
          {#snippet child({ props })}
            <Button {...props} variant="ghost" size="icon" class="lg:hidden" aria-label="打开主导航">
              <Menu class="size-5" />
            </Button>
          {/snippet}
        </Sheet.Trigger>
        <Sheet.Content side="left" class="w-[19rem] p-0">
          <Sheet.Header class="border-b border-border px-5 py-4 text-left">
            <Sheet.Title>Zeus</Sheet.Title>
            <Sheet.Description>企业 Harness 工作台</Sheet.Description>
          </Sheet.Header>
          <nav class="space-y-1 p-3" aria-label="移动端主导航">
            {#each primaryNavigation as item (item.href)}
              {@const Icon = item.icon}
              <a
                class={isActive(item.href)
                  ? 'flex items-center gap-3 rounded-lg bg-accent px-3 py-2.5 text-sm font-medium'
                  : 'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm text-muted-foreground hover:bg-accent hover:text-foreground'}
                href={item.href}
                aria-current={isActive(item.href) ? 'page' : undefined}
              >
                <Icon class="size-4" />
                {item.label}
              </a>
            {/each}
            <Separator class="my-3" />
            {#each secondaryNavigation as item (item.href)}
              {@const Icon = item.icon}
              <a class="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm text-muted-foreground hover:bg-accent hover:text-foreground" href={item.href}>
                <Icon class="size-4" />
                {item.label}
              </a>
            {/each}
          </nav>
        </Sheet.Content>
      </Sheet.Root>

      <a class="flex items-center gap-2.5 font-semibold tracking-tight" href="/" aria-label="返回 Zeus 工作台">
        <span class="grid size-8 place-items-center rounded-lg bg-foreground text-sm text-background">Z</span>
        <span>Zeus</span>
      </a>

      <Separator orientation="vertical" class="hidden h-5 sm:block" />

      <DropdownMenu.Root>
        <DropdownMenu.Trigger>
          {#snippet child({ props })}
            <Button {...props} variant="ghost" size="sm" class="max-w-[15rem] gap-2">
              <Building2 class="size-4 text-muted-foreground" />
              <span class="truncate">{workspaceLabel}</span>
              <ChevronDown class="size-3.5 text-muted-foreground" />
            </Button>
          {/snippet}
        </DropdownMenu.Trigger>
        <DropdownMenu.Content align="start" class="w-64">
          <DropdownMenu.Label>切换 Workspace</DropdownMenu.Label>
          {#if organizations.length > 0}
            {#each organizations as organization (organization.organization_id)}
              <DropdownMenu.Separator />
              <DropdownMenu.Label class="truncate text-xs text-muted-foreground">{organization.organization_name}</DropdownMenu.Label>
              {#each organization.workspaces as workspace (workspace.id)}
                <form method="POST" action="/workspace-context">
                  <input type="hidden" name="organization_id" value={organization.organization_id} />
                  <input type="hidden" name="workspace_id" value={workspace.id} />
                  <input type="hidden" name="return_to" value={returnTo} />
                  <DropdownMenu.Item disabled={workspace.id === principal?.workspace_id}>
                    {#snippet child({ props })}
                      <button {...props} type="submit" class="flex w-full items-center justify-between gap-3 text-left">
                        <span class="min-w-0"><span class="block truncate">{workspace.name}</span><span class="block truncate text-xs text-muted-foreground">{workspace.role}</span></span>
                        {#if workspace.id === principal?.workspace_id}<Check class="size-4 shrink-0" />{/if}
                      </button>
                    {/snippet}
                  </DropdownMenu.Item>
                </form>
              {/each}
            {/each}
          {:else}
            <DropdownMenu.Item disabled>当前会话还未选择 Workspace</DropdownMenu.Item>
          {/if}
          <DropdownMenu.Separator />
          <DropdownMenu.Item>
            {#snippet child({ props })}
              <a {...props} href="/account/profile">查看可用 Organization</a>
            {/snippet}
          </DropdownMenu.Item>
          <DropdownMenu.Item>
            {#snippet child({ props })}
              <a {...props} href="/admin">管理 Workspace</a>
            {/snippet}
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Root>

      <div class="ml-auto flex items-center gap-2">
        {#if authStatus === 'unavailable'}
          <Badge variant="destructive">API 断开</Badge>
        {:else if !principal?.workspace_id && authStatus === 'ready'}
          <Badge variant="outline">未选 Workspace</Badge>
        {/if}
        <Button href="/work-items?create=1" size="sm" class="hidden sm:inline-flex">新建工作项</Button>
        <DropdownMenu.Root>
          <DropdownMenu.Trigger>
            {#snippet child({ props })}
              <Button {...props} variant="outline" size="icon" aria-label="打开用户菜单">
                <UserRound class="size-4" />
              </Button>
            {/snippet}
          </DropdownMenu.Trigger>
          <DropdownMenu.Content align="end" class="w-56">
            <DropdownMenu.Label>
              <span class="block truncate">{principal?.display_name ?? 'Zeus 用户'}</span>
              {#if principal?.email}<span class="mt-1 block truncate text-xs font-normal text-muted-foreground">{principal.email}</span>{/if}
            </DropdownMenu.Label>
            <DropdownMenu.Separator />
            <DropdownMenu.Item>
              {#snippet child({ props })}
                <a {...props} href="/account/profile">账号设置</a>
              {/snippet}
            </DropdownMenu.Item>
            <DropdownMenu.Item>
              {#snippet child({ props })}
                <a {...props} href="/account/sessions">登录会话</a>
              {/snippet}
            </DropdownMenu.Item>
          </DropdownMenu.Content>
        </DropdownMenu.Root>
      </div>
    </div>
  </header>

  <div class="mx-auto grid min-h-[calc(100vh-4rem)] max-w-[1680px] lg:grid-cols-[14rem_minmax(0,1fr)]">
    <aside class="hidden border-r border-border bg-background lg:flex lg:flex-col">
      <nav class="space-y-1 p-3" aria-label="主导航">
        {#each primaryNavigation as item (item.href)}
          {@const Icon = item.icon}
          <a
            class={isActive(item.href)
              ? 'flex items-center gap-3 rounded-lg bg-accent px-3 py-2.5 text-sm font-medium text-accent-foreground'
              : 'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm text-muted-foreground hover:bg-accent hover:text-foreground'}
            href={item.href}
            aria-current={isActive(item.href) ? 'page' : undefined}
          >
            <Icon class="size-4" />
            {item.label}
          </a>
        {/each}
      </nav>
      <div class="mt-auto p-3">
        <Separator class="mb-3" />
        <p class="px-3 pb-2 text-[0.6875rem] font-semibold uppercase tracking-[0.12em] text-muted-foreground">管理</p>
        {#each secondaryNavigation as item (item.href)}
          {@const Icon = item.icon}
          <a
            class={isActive(item.href) || (area === 'account' && item.href === '/account/profile') || (area === 'admin' && item.href === '/admin')
              ? 'flex items-center gap-3 rounded-lg bg-accent px-3 py-2.5 text-sm font-medium'
              : 'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm text-muted-foreground hover:bg-accent hover:text-foreground'}
            href={item.href}
          >
            <Icon class="size-4" />
            {item.label}
          </a>
        {/each}
      </div>
    </aside>
    <div class="min-w-0">{@render children()}</div>
  </div>
</div>
