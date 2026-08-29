<script lang="ts">
  import { page } from '$app/state';
  import type { Snippet } from 'svelte';

  import '../app.css';

  import type { LayoutData } from './$types';

  import WorkspaceNav from '$lib/components/WorkspaceNav.svelte';

  let { children, data }: { children: Snippet; data: LayoutData } = $props();
  let isAdmin = $derived(page.url.pathname.startsWith('/admin'));
</script>

<svelte:head>
  <title>Zeus</title>
  <meta
    name="description"
    content="Zeus enterprise Harness Agent control plane"
  />
</svelte:head>

{#if !isAdmin}
  <WorkspaceNav
    authStatus={data.status}
    workspaceId={data.principal?.workspace_id}
    displayName={data.principal?.display_name}
  />
{/if}

{@render children()}
