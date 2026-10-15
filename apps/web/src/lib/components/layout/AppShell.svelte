<script lang="ts">
  import { enhance } from '$app/forms';
  import { afterNavigate } from '$app/navigation';
  let navigationOpen = $state(false);
  afterNavigate(() => { navigationOpen = false; });
  import { page } from '$app/state';
  import type { Component, Snippet } from 'svelte';
  import {
    Activity,
    BookOpen,
    Building2,
    Check,
    CheckSquare,
    ChevronDown,
    ClipboardList,
    LayoutDashboard,
    Menu,
    MessagesSquare,
    Settings,
    ShieldCheck,
    UserRound,
    Wrench
  } from '@lucide/svelte';

  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as DropdownMenu from '@zeus/ui/components/ui/dropdown-menu';
  import * as Sheet from '@zeus/ui/components/ui/sheet';
  import { Separator } from '@zeus/ui/components/ui/separator';

  import type { UserOrganization, UserWorkspace } from '$lib/api/identity';
  import type { CurrentPrincipal, PrincipalResult } from '$lib/api/server';
  import { enhanceWorkspaceSelection } from '$lib/features/tenancy/workspace-channel';
  import {
    findWorkspaceOption,
    flattenWorkspaceOptions,
    hasValidTenantAccessGrant,
    isOrganizationOwner,
    isPlatformOwner,
    isWorkspaceOwner,
    workspacePath,
    workspaceRootPath
  } from '$lib/tenancy/navigation';

  type Area = 'workspace' | 'account' | 'organization' | 'platform';
  type NavigationItem = { href: string; label: string; icon: Component };

  let {
    children,
    authStatus,
    principal,
    organizations,
    activeOrganization = null,
    activeWorkspace = null,
    area = 'workspace'
  }: {
    children: Snippet;
    authStatus: PrincipalResult['status'];
    principal: CurrentPrincipal | null;
    organizations: UserOrganization[];
    activeOrganization?: UserOrganization | null;
    activeWorkspace?: UserWorkspace | null;
    area?: Area;
  } = $props();

  let pathname = $derived(page.url.pathname);
  let workspaceOptions = $derived(flattenWorkspaceOptions(organizations));
  let selectedWorkspaceOption = $derived(
    findWorkspaceOption(workspaceOptions, activeWorkspace?.id ?? principal?.workspace_id)
  );
  let currentOrganization = $derived(
    activeOrganization ??
      selectedWorkspaceOption?.organization ??
      organizations.find((organization) => organization.organization_id === principal?.organization_id) ??
      null
  );
  let currentWorkspace = $derived(
    activeWorkspace ??
      selectedWorkspaceOption ??
      null
  );
  let workspaceBase = $derived(currentWorkspace ? workspaceRootPath(currentWorkspace.id) : null);
  let canManageWorkspace = $derived(
    currentWorkspace?.support_access === true ||
      isWorkspaceOwner(principal, currentWorkspace?.id)
  );
  let canManageOrganization = $derived(
    (currentOrganization && hasValidTenantAccessGrant(principal, currentOrganization.organization_id)) ||
      isOrganizationOwner(principal, currentOrganization?.organization_id)
  );
  let platformOwner = $derived(isPlatformOwner(principal));
  let businessNavigation = $derived<NavigationItem[]>(workspaceBase ? [
    { href: `${workspaceBase}/work-items`, label: '任务', icon: ClipboardList },
    { href: `${workspaceBase}/workflows`, label: '工作流', icon: Activity },
    { href: `${workspaceBase}/runs`, label: '运行', icon: Activity },
    { href: `${workspaceBase}/approvals`, label: '审批', icon: CheckSquare },
    { href: `${workspaceBase}/experience`, label: '经验', icon: BookOpen },
    { href: `${workspaceBase}/schedules`, label: '定时任务', icon: Activity },
    { href: `${workspaceBase}/webhooks`, label: '触发器', icon: Activity }
  ] : []);
  let primaryNavigation = $derived<NavigationItem[]>([
    ...(workspaceBase ? [
      { href: workspaceBase, label: '工作台', icon: LayoutDashboard },
      { href: `${workspaceBase}/work-items`, label: '任务', icon: ClipboardList },
      { href: `${workspaceBase}/approvals`, label: '审批', icon: CheckSquare }
    ] : []),
    ...(currentOrganization ? [{ href: `/organizations/${currentOrganization.organization_id}/im`, label: '团队消息', icon: MessagesSquare }] : [])
  ]);
  let secondaryNavigation = $derived.by<NavigationItem[]>(() => {
    const items: NavigationItem[] = [{ href: '/management', label: '设置中心', icon: Settings }];
    if (!isActive('/management')) return items;
    if (workspaceBase && canManageWorkspace) {
      items.push({ href: `${workspaceBase}/settings`, label: '工作空间设置', icon: Wrench });
    }
    if (currentOrganization && canManageOrganization) {
      items.push({
        href: `/organizations/${currentOrganization.organization_id}/settings`,
        label: '组织设置',
        icon: Building2
      });
    }
    if (platformOwner) {
      items.push({ href: '/platform', label: '平台控制台', icon: ShieldCheck });
    }
    items.push({ href: '/account/profile', label: '账号设置', icon: Settings });
    return items;
  });
  let workspaceLabel = $derived(currentWorkspace?.name ?? '选择工作空间');

  function isActive(href: string): boolean {
    if (href === '/management') return pathname === href || pathname.startsWith('/account/') || pathname.startsWith('/platform') || /^\/organizations\/[^/]+\/settings/.test(pathname) || (!!workspaceBase && (pathname.startsWith(`${workspaceBase}/settings`) || pathname === `${workspaceBase}/agents`));
    if (workspaceBase && href === workspaceBase) return pathname === href;
    return pathname === href || pathname.startsWith(`${href}/`);
  }

  function workspaceTarget(workspaceId: string): string {
    if (!workspaceBase || !pathname.startsWith(workspaceBase)) return workspaceRootPath(workspaceId);
    const suffix = pathname.slice(workspaceBase.length);
    return workspacePath(workspaceId, `${suffix}${page.url.search}`);
  }

  function accessExpiry(value: string | null | undefined): string {
    if (!value) return '即将到期';
    const minutes = Math.max(0, Math.ceil((new Date(value).getTime() - Date.now()) / 60_000));
    return `${minutes} 分钟后到期`;
  }
</script>

<div class="min-h-screen bg-muted/20 text-foreground">
  <header class="sticky top-0 z-40 border-b border-border bg-background/95 backdrop-blur">
    <div class="flex h-16 items-center gap-3 px-4 lg:px-6">
      <Sheet.Root bind:open={navigationOpen}>
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
            <Sheet.Description>{currentOrganization?.organization_name ?? '企业 Harness 工作台'}</Sheet.Description>
          </Sheet.Header>
          <nav class="space-y-1 p-3" aria-label="移动端主导航">
            {#each primaryNavigation as item (item.href)}
              {@const Icon = item.icon}
              <a
                class={isActive(item.href) ? 'flex items-center gap-3 rounded-lg bg-accent px-3 py-2.5 text-sm font-medium' : 'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm text-muted-foreground hover:bg-accent hover:text-foreground'}
                href={item.href}
                aria-current={isActive(item.href) ? 'page' : undefined}
              ><Icon class="size-4" />{item.label}</a>
            {/each}
            {#if workspaceBase}<details class="p-3 text-sm"><summary class="cursor-pointer">高级工具</summary><a class="block py-2" href={`${workspaceBase}/studio`}>助手讨论</a>{#each businessNavigation.filter(item => !item.href.endsWith('/work-items') && !item.href.endsWith('/approvals')) as item (item.href)}<a class="block py-2" href={item.href}>{item.label}</a>{/each}</details>{/if}
            {#if primaryNavigation.length > 0}<Separator class="my-3" />{/if}
            {#each secondaryNavigation as item (item.href)}
              {@const Icon = item.icon}
              <a
                class={isActive(item.href) ? 'flex items-center gap-3 rounded-lg bg-accent px-3 py-2.5 text-sm font-medium' : 'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm text-muted-foreground hover:bg-accent hover:text-foreground'}
                href={item.href}
              ><Icon class="size-4" />{item.label}</a>
            {/each}
          </nav>
        </Sheet.Content>
      </Sheet.Root>

      <a class="flex shrink-0 items-center gap-2.5 font-semibold tracking-tight" href="/" aria-label="返回 Zeus 入口">
        <span class="grid size-8 place-items-center rounded-lg bg-foreground text-sm text-background">Z</span>
        <span>Zeus</span>
      </a>
      <Separator orientation="vertical" class="hidden h-5 sm:block" />

      <DropdownMenu.Root>
        <DropdownMenu.Trigger>
          {#snippet child({ props })}
            <Button {...props} variant="ghost" size="sm" class="min-w-0 max-w-[18rem] shrink gap-2">
              <Building2 class="size-4 shrink-0 text-muted-foreground" />
              <span class="min-w-0 text-left">
                <span class="block truncate">{workspaceLabel}</span>
                {#if currentOrganization}<span class="block truncate text-[0.625rem] font-normal text-muted-foreground">{currentOrganization.organization_name}</span>{/if}
              </span>
              <ChevronDown class="size-3.5 shrink-0 text-muted-foreground" />
            </Button>
          {/snippet}
        </DropdownMenu.Trigger>
        <DropdownMenu.Content align="start" class="w-72">
          <DropdownMenu.Label>切换 Workspace</DropdownMenu.Label>
          {#each organizations as organization (organization.organization_id)}
            {#if organization.workspaces.length > 0}
              <DropdownMenu.Separator />
              <DropdownMenu.Label class="truncate text-xs text-muted-foreground">{organization.organization_name}</DropdownMenu.Label>
              {#each organization.workspaces as workspace (workspace.id)}
                <form method="POST" action="/workspaces?/select" use:enhance={enhanceWorkspaceSelection(workspace.id)}>
                  <input type="hidden" name="organization_id" value={organization.organization_id} />
                  <input type="hidden" name="workspace_id" value={workspace.id} />
                  <input type="hidden" name="return_to" value={workspaceTarget(workspace.id)} />
                  <DropdownMenu.Item disabled={workspace.id === principal?.workspace_id || workspace.status !== 'active'}>
                    {#snippet child({ props })}
                      <button {...props} type="submit" class="flex w-full items-center justify-between gap-3 text-left">
                        <span class="min-w-0"><span class="block truncate">{workspace.name}</span><span class="block truncate text-xs text-muted-foreground">{workspace.role}</span></span>
                        {#if workspace.id === principal?.workspace_id}<Check class="size-4 shrink-0" />{/if}
                      </button>
                    {/snippet}
                  </DropdownMenu.Item>
                </form>
              {/each}
            {/if}
          {/each}
          {#if organizations.every((organization) => organization.workspaces.length === 0)}
            <DropdownMenu.Item disabled>没有可用 Workspace</DropdownMenu.Item>
          {/if}
          <DropdownMenu.Separator />
          <DropdownMenu.Item>{#snippet child({ props })}<a {...props} href="/workspaces">查看全部 Workspace</a>{/snippet}</DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Root>

      <div class="ml-auto flex shrink-0 items-center gap-2">
        {#if authStatus === 'unavailable'}<Badge variant="destructive">API 断开</Badge>{/if}
        {#if workspaceBase && pathname !== workspaceBase && pathname !== `${workspaceBase}/new`}<Button href={`${workspaceBase}/new`} size="sm" class="hidden min-h-10 rounded-md px-4 sm:inline-flex">发起任务</Button>{/if}
        <DropdownMenu.Root>
          <DropdownMenu.Trigger>
            {#snippet child({ props })}<Button {...props} variant="outline" size="icon" aria-label="打开用户菜单"><UserRound class="size-4" /></Button>{/snippet}
          </DropdownMenu.Trigger>
          <DropdownMenu.Content align="end" class="w-56">
            <DropdownMenu.Label>
              <span class="block truncate">{principal?.display_name ?? 'Zeus 用户'}</span>
              {#if principal?.email}<span class="mt-1 block truncate text-xs font-normal text-muted-foreground">{principal.email}</span>{/if}
            </DropdownMenu.Label>
            <DropdownMenu.Separator />
            <DropdownMenu.Item>{#snippet child({ props })}<a {...props} href="/account/profile">账号设置</a>{/snippet}</DropdownMenu.Item>
            <DropdownMenu.Item>{#snippet child({ props })}<a {...props} href="/account/sessions">登录会话</a>{/snippet}</DropdownMenu.Item>
          </DropdownMenu.Content>
        </DropdownMenu.Root>
      </div>
    </div>
    {#if principal?.tenant_access_grant_id}
      <div class="flex flex-col gap-2 border-t border-amber-500/30 bg-amber-50 px-4 py-2 text-sm text-amber-950 dark:bg-amber-950/30 dark:text-amber-100 sm:flex-row sm:items-center sm:justify-between lg:px-6">
        <span>平台支持会话 · {currentOrganization?.organization_name ?? 'Organization'} · {accessExpiry(principal.tenant_access_expires_at)}</span>
        <form method="POST" action="/platform/tenant-access">
          <input type="hidden" name="grant_id" value={principal.tenant_access_grant_id} />
          <Button type="submit" variant="outline" size="xs">退出租户访问</Button>
        </form>
      </div>
    {/if}
    <nav class="flex gap-2 overflow-x-auto border-t px-3 py-2 lg:hidden" aria-label="模块切换">{#each primaryNavigation as item (item.href)}<a href={item.href} aria-current={isActive(item.href) ? 'page' : undefined} class="shrink-0 rounded px-3 py-2 text-sm" class:bg-muted={isActive(item.href)}>{item.label}</a>{/each}</nav>
  </header>

  <div class="mx-auto grid min-h-[calc(100vh-4rem)] max-w-[1680px] lg:grid-cols-[15rem_minmax(0,1fr)]">
    <aside class="hidden border-r border-border bg-background lg:flex lg:flex-col">
      {#if primaryNavigation.length > 0}
        <nav class="space-y-1 p-3" aria-label="主导航">
          {#each primaryNavigation as item (item.href)}
            {@const Icon = item.icon}
            <a
              class={isActive(item.href) ? 'flex items-center gap-3 rounded-lg bg-accent px-3 py-2.5 text-sm font-medium' : 'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm text-muted-foreground hover:bg-accent hover:text-foreground'}
              href={item.href}
              aria-current={isActive(item.href) ? 'page' : undefined}
            ><Icon class="size-4" />{item.label}</a>
          {/each}
        </nav>
      {/if}
      {#if workspaceBase}
        <details class="mx-3 mt-3 rounded-lg p-3 text-sm text-muted-foreground">
          <summary class="cursor-pointer">高级工具</summary>
          <nav aria-label="高级工具" class="mt-2 space-y-1">
            <a class="block rounded-lg px-3 py-2 hover:bg-accent" href={`${workspaceBase}/studio`}>助手讨论</a>
            {#each businessNavigation.filter(item => !item.href.endsWith('/work-items') && !item.href.endsWith('/approvals')) as item (item.href)}<a class="block rounded-lg px-3 py-2 hover:bg-accent" href={item.href}>{item.label}</a>{/each}
          </nav>
        </details>
      {/if}
      {#if secondaryNavigation.length > 0}
      <div class="mt-auto p-3">
        <Separator class="mb-3" />
        <p class="px-3 pb-2 text-[0.6875rem] font-semibold uppercase tracking-[0.12em] text-muted-foreground">设置</p>
        {#each secondaryNavigation as item (item.href)}
          {@const Icon = item.icon}
          <a
            class={isActive(item.href) || (area === 'account' && item.href === '/account/profile') ? 'flex items-center gap-3 rounded-lg bg-accent px-3 py-2.5 text-sm font-medium' : 'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm text-muted-foreground hover:bg-accent hover:text-foreground'}
            href={item.href}
          ><Icon class="size-4" />{item.label}</a>
        {/each}
      </div>
      {/if}
    </aside>
    <div class="min-w-0">{@render children()}</div>
  </div>
</div>
