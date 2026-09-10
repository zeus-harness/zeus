<script lang="ts">
  import type { Snippet } from 'svelte';

  import AppShell from '$lib/components/layout/AppShell.svelte';
  import SectionNav from '$lib/components/layout/SectionNav.svelte';
  import type { LayoutData } from './$types';

  const navigation = [
    { href: '/platform', label: '总览' },
    { href: '/platform/organizations', label: 'Organizations' },
    { href: '/platform/users', label: '用户' },
    { href: '/platform/logs', label: '安全事件' }
  ] as const;

  let { children, data }: { children: Snippet; data: LayoutData } = $props();
</script>

<AppShell authStatus={data.status} principal={data.principal} organizations={data.organizations} area="platform">
  <SectionNav label="平台控制台导航" items={navigation} />
  {@render children()}
</AppShell>
