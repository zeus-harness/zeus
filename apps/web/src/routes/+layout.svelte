<script lang="ts">
  import UpdateNotice from '$lib/components/UpdateNotice.svelte';
  import type { Snippet } from 'svelte';

  import '../app.css';

  let { children }: { children: Snippet } = $props();
</script>

<svelte:head>
  <title>Zeus</title>
  <meta name="description" content="Zeus enterprise Harness Agent control plane" />
</svelte:head>

<UpdateNotice />
{@render children()}
