<script lang="ts">
  import AppShell from '$lib/components/layout/AppShell.svelte';
  import { Button } from '@zeus/ui/components/ui/button';
  import type { PageData } from './$types';
  let { data }: { data: PageData } = $props();
  let organization = $derived(data.organizations.find(item => item.organization_id === data.principal?.organization_id));
  let workspace = $derived(organization?.workspaces.find(item => item.id === data.principal?.workspace_id));
</script>
<svelte:head><title>管理控制台 · Zeus</title></svelte:head>
<AppShell authStatus={data.status} principal={data.principal} organizations={data.organizations}>
  <main class="space-y-6 p-6 lg:p-8"><header><h1 class="text-2xl font-semibold">设置中心</h1><p class="mt-2 text-sm text-muted-foreground">管理控制台 · 按组织、工作空间和平台分别配置与治理。</p></header>
    <div class="grid gap-4 md:grid-cols-2">
      <section class="rounded-xl border p-5"><h2 class="font-medium">个人账号</h2><p class="my-3 text-sm text-muted-foreground">个人资料、MFA 和登录会话。</p><Button href="/account/profile" variant="outline">账号设置</Button></section>
      {#if workspace?.role === 'owner'}<section class="rounded-xl border p-5"><h2 class="font-medium">工作空间与聊天配置</h2><p class="my-3 text-sm text-muted-foreground">成员、工具授权、聊天助手和服务账号。</p><Button href={`/${workspace.id}/settings`} variant="outline">工作空间设置</Button><Button href={`/${workspace.id}/settings/studio`} variant="outline" class="ml-2">聊天助手设置</Button></section>{/if}
      {#if workspace && ['owner', 'builder'].includes(workspace.role)}<section class="rounded-xl border p-5"><h2 class="font-medium">Agent 配置</h2><p class="my-3 text-sm text-muted-foreground">管理 Agent 指令、版本和发布。</p><Button href={`/${workspace.id}/agents`} variant="outline">配置 Agent</Button></section>{/if}
      {#if organization?.organization_role === 'owner'}<section class="rounded-xl border p-5"><h2 class="font-medium">组织管理</h2><p class="my-3 text-sm text-muted-foreground">组织成员、模型供应商与组织安全。</p><Button href={`/organizations/${organization.organization_id}/settings`} variant="outline">组织设置</Button></section>{/if}
      {#if data.principal?.platform_roles.includes('platform_owner')}<section class="rounded-xl border p-5"><h2 class="font-medium">平台治理</h2><p class="my-3 text-sm text-muted-foreground">平台用户、租户与审计。平台角色不会自动授予成员聊天访问权。</p><Button href="/platform" variant="outline">平台控制台</Button></section>{/if}
    </div>
  </main>
</AppShell>
