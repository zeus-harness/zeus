<script lang="ts">
  import StudioConversation from '$lib/features/studio/StudioConversation.svelte';
  import type { PageProps } from './$types';
  let { data, form }: PageProps = $props();
</script>

{#key data.draftScope}
  <StudioConversation {data} {form} />
{/key}
