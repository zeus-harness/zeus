<script lang="ts">
  import type { Snippet } from 'svelte';

  import SectionNav from '$lib/components/layout/SectionNav.svelte';
  import { managementResources } from '$lib/control-plane';

  const identityNavigation = [
    { href: '/admin/identity-providers', label: '身份提供商' },
    { href: '/admin/domains', label: '域名' },
    { href: '/admin/security', label: '身份策略' },
    { href: '/admin/oidc-clients', label: 'OIDC Client' }
  ] as const;
  const adminNavigation = [
    { href: '/admin', label: '总览' },
    ...managementResources.map((resource) => ({
      href: `/admin/${resource.slug}`,
      label: resource.label,
      description: resource.description
    })),
    ...identityNavigation
  ];

  let { children }: { children: Snippet } = $props();
</script>

<svelte:head>
  <title>Zeus · Control plane</title>
</svelte:head>

<SectionNav label="控制面导航" items={adminNavigation} />
{@render children()}
