<script lang="ts">
  import ResourceCollection from '$lib/features/control-plane/ResourceCollection.svelte';
  import type { PageData } from './$types';

  let { data }: { data: PageData } = $props();
</script>

<svelte:head><title>Zeus · {data.resource.label}</title></svelte:head>

<ResourceCollection
  resource={data.resource}
  collection={data.collection}
  backHref={`/organizations/${data.organizationId}/settings`}
  refreshHref={`/organizations/${data.organizationId}/settings/${data.resource.slug}`}
/>
