<script lang="ts">
  import type { Snippet } from 'svelte';

  import AppShell from '$lib/components/layout/AppShell.svelte';
  import SectionNav from '$lib/components/layout/SectionNav.svelte';
  import type { LayoutData } from './$types';

  let { children, data }: { children: Snippet; data: LayoutData } = $props();
  let base = $derived(`/organizations/${data.activeOrganization.organization_id}/settings`);
  let navigation = $derived([
    { href: base, label: '概览' },
    { href: `${base}/members`, label: '成员' },
    { href: `${base}/workspaces`, label: 'Workspaces' },
    { href: `${base}/capabilities`, label: 'Capability Catalog' },
    ...(data.canManageIdentity
      ? [
          { href: `${base}/identity-providers`, label: '身份提供商' },
          { href: `${base}/verified-domains`, label: '已验证域名' },
          { href: `${base}/security`, label: '身份安全' },
          { href: `${base}/oidc-clients`, label: 'OIDC Clients' }
        ]
      : [])
  ]);
</script>

<AppShell
  authStatus={data.status}
  principal={data.principal}
  organizations={data.organizations}
  activeOrganization={data.activeOrganization}
  area="organization"
>
  <SectionNav label="Organization 设置导航" items={navigation} />
  {@render children()}
</AppShell>
