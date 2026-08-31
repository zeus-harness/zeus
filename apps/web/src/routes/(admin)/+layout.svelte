<script lang="ts">
  import type { Snippet } from 'svelte';

  import AppShell from '$lib/components/layout/AppShell.svelte';
  import type { LayoutData } from './$types';

  let { children, data }: { children: Snippet; data: LayoutData } = $props();
</script>

<AppShell authStatus={data.status} principal={data.principal} organizations={data.organizations} area="admin">
  {@render children()}
</AppShell>
