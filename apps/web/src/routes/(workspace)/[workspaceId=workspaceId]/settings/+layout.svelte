<script lang="ts">
  import type { Snippet } from 'svelte';

  import SectionNav from '$lib/components/layout/SectionNav.svelte';
  import { workspaceSettingResources } from '$lib/control-plane';
  import type { LayoutData } from './$types';

  let { children, data }: { children: Snippet; data: LayoutData } = $props();
  let base = $derived(`/${data.activeWorkspace.id}/settings`);
  let navigation = $derived([
    { href: base, label: '概览' },
    ...workspaceSettingResources.map((resource) => ({
      href: `${base}/${resource.slug}`,
      label: resource.label,
      description: resource.description
    }))
  ]);
</script>

<SectionNav label="Workspace 设置导航" items={navigation} />
{@render children()}
