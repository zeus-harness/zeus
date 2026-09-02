<script lang="ts">
  import { ArrowLeft, RefreshCcw } from '@lucide/svelte';

  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';
  import * as Table from '@zeus/ui/components/ui/table';

  import type { CollectionResult } from '$lib/api/collections';
  import type { ManagementResource } from '$lib/control-plane';
  import EmptyState from '$lib/components/layout/EmptyState.svelte';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';

  let {
    resource,
    collection,
    backHref,
    refreshHref
  }: {
    resource: ManagementResource;
    collection: CollectionResult;
    backHref: string;
    refreshHref: string;
  } = $props();

  function formatValue(value: unknown): string {
    if (value === null || value === undefined || value === '') return '—';
    if (Array.isArray(value)) return value.join(', ') || '—';
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
      return String(value);
    }
    try {
      return JSON.stringify(value) ?? '—';
    } catch {
      return '—';
    }
  }

  function recordKey(record: Record<string, unknown>, index: number): string {
    const identity = record.id ?? record.uuid ?? record.key;
    return `${resource.slug}:${typeof identity === 'string' || typeof identity === 'number' ? identity : index}`;
  }
</script>

<main class="px-5 py-7 lg:px-8 lg:py-9">
  <a class="mb-5 inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground" href={backHref}>
    <ArrowLeft class="size-4" />返回
  </a>
  <PageHeader eyebrow="Control plane" title={resource.label} description={resource.description}>
    {#snippet actions()}
      <Badge variant={collection.status === 'ready' ? 'secondary' : 'outline'}>{collection.status}</Badge>
      <Button href={refreshHref} variant="outline" size="sm"><RefreshCcw class="size-4" />刷新</Button>
    {/snippet}
  </PageHeader>

  {#if collection.status === 'ready' && collection.records.length > 0}
    <Card.Root class="mt-7">
      <Card.Header><Card.Title>当前记录</Card.Title><Card.Description>{collection.records.length} records</Card.Description></Card.Header>
      <Card.Content class="overflow-x-auto">
        <Table.Root class="min-w-[42rem]">
          <Table.Header><Table.Row>{#each resource.columns as column (column.key)}<Table.Head>{column.label}</Table.Head>{/each}</Table.Row></Table.Header>
          <Table.Body>
            {#each collection.records as record, index (recordKey(record, index))}
              <Table.Row>{#each resource.columns as column (column.key)}<Table.Cell class="max-w-80 truncate">{formatValue(record[column.key])}</Table.Cell>{/each}</Table.Row>
            {/each}
          </Table.Body>
        </Table.Root>
      </Card.Content>
    </Card.Root>
  {:else}
    <Card.Root class="mt-7">
      <Card.Content class="py-10">
        <EmptyState
          title={collection.status === 'ready' ? `暂无 ${resource.label}` : '暂时无法加载'}
          description={collection.status === 'ready' ? '当前 Workspace 还没有记录。' : collection.message ?? '请求失败。'}
        />
      </Card.Content>
    </Card.Root>
  {/if}
</main>
