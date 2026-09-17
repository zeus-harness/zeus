<script lang="ts">
  import ModelConnections from '$lib/features/control-plane/ModelConnections.svelte';
  import ResourceCollection from '$lib/features/control-plane/ResourceCollection.svelte';
  import type { ActionData, PageData } from './$types';

  let { data, form }: { data: PageData; form: ActionData } = $props();
</script>

<svelte:head><title>Zeus · {data.resource.label}</title></svelte:head>

{#if data.models && (data.resource.slug === 'connections' || data.resource.slug === 'model-profiles')}
  <ModelConnections models={data.models} resource={data.resource.slug} organizationId={data.organizationId} selectedConnection={data.selectedConnection} saved={data.saved} {form} />
{:else if data.collection}
<ResourceCollection
  resource={data.resource}
  collection={data.collection}
  backHref={`/organizations/${data.organizationId}/settings`}
  refreshHref={`/organizations/${data.organizationId}/settings/${data.resource.slug}`}
/>

{/if}
