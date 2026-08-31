<script lang="ts">
  import type { Snippet } from 'svelte';

  import AppShell from '$lib/components/layout/AppShell.svelte';
  import SectionNav from '$lib/components/layout/SectionNav.svelte';
  import type { LayoutData } from './$types';

  const accountNavigation = [
    { href: '/account/profile', label: '个人资料' },
    { href: '/account/security', label: '安全设置' },
    { href: '/account/federation', label: '联合身份' },
    { href: '/account/sessions', label: '登录会话' },
    { href: '/account/authorizations', label: '应用授权' }
  ] as const;

  let { children, data }: { children: Snippet; data: LayoutData } = $props();
</script>

<AppShell authStatus={data.status} principal={data.principal} organizations={data.organizations} area="account">
  <SectionNav label="账号导航" items={accountNavigation} />
  {@render children()}
</AppShell>
