<script lang="ts">
  import ResourceCollection from '$lib/features/control-plane/ResourceCollection.svelte';
  import SectionNav from '$lib/components/layout/SectionNav.svelte';
  import { agentStudioResources } from '$lib/control-plane';
  import type { PageData } from './$types';

  let { data }: { data: PageData } = $props();
  let navigation = $derived(
    agentStudioResources.map((resource) => ({
      href: `/${data.workspaceId}/${resource.slug}`,
      label: resource.label,
      description: resource.description
    }))
  );
</script>

<svelte:head><title>Zeus · {data.resource.label}</title></svelte:head>

<SectionNav label="Agent Studio 导航" items={navigation} />
<ResourceCollection
  resource={data.resource}
  collection={data.collection}
  backHref={`/${data.workspaceId}`}
  refreshHref={`/${data.workspaceId}/${data.resource.slug}`}
/>
