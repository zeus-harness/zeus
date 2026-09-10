<script lang="ts">
  import ResourceCollection from '$lib/features/control-plane/ResourceCollection.svelte';
  import AgentStudio from '$lib/features/control-plane/AgentStudio.svelte';
  import SectionNav from '$lib/components/layout/SectionNav.svelte';
  import { agentStudioResources } from '$lib/control-plane';
  import type { ActionData, PageData } from './$types';

  let { data, form }: { data: PageData; form: ActionData } = $props();
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
{#if data.studio && (data.resource.slug === 'agents' || data.resource.slug === 'workflows')}
  <AgentStudio studio={data.studio} resource={data.resource.slug} workspaceId={data.workspaceId} {form} />
{:else if data.collection}
<ResourceCollection
  resource={data.resource}
  collection={data.collection}
  backHref={`/${data.workspaceId}`}
  refreshHref={`/${data.workspaceId}/${data.resource.slug}`}
/>
{/if}
