<script lang="ts">
  import type { Snippet } from 'svelte';

  import AppShell from '$lib/components/layout/AppShell.svelte';
  import WorkspaceContextBoundary from '$lib/features/tenancy/WorkspaceContextBoundary.svelte';
  import type { LayoutData } from './$types';

  let { children, data }: { children: Snippet; data: LayoutData } = $props();
</script>

<AppShell
  authStatus={data.status}
  principal={data.principal}
  organizations={data.organizations}
  activeOrganization={data.activeOrganization}
  activeWorkspace={data.activeWorkspace}
  area="workspace"
>
  <WorkspaceContextBoundary workspaceId={data.activeWorkspace.id}>
    {@render children()}
  </WorkspaceContextBoundary>
</AppShell>
