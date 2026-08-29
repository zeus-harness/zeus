<script lang="ts">
  import type { PageData } from './$types';

  let { data } = $props<{ data: PageData }>();

  function formatValue(value: unknown): string {
    if (value === null || value === undefined || value === '') {
      return '—';
    }

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
    return `${data.resource.slug}:${typeof identity === 'string' || typeof identity === 'number' ? identity : index}`;
  }

  function statusLabel(status: PageData['collection']['status']): string {
    switch (status) {
      case 'ready':
        return 'API connected';
      case 'not-configured':
        return 'Configuration needed';
      case 'not-available':
        return 'API unavailable';
      case 'unauthorized':
        return 'Access denied';
      case 'error':
        return 'Request failed';
    }
  }
</script>

<svelte:head>
  <title>Zeus · {data.resource.label}</title>
</svelte:head>

<div class="resource-heading">
  <div>
    <a class="breadcrumb" href="/admin">控制面资源</a>
    <h1>{data.resource.label}</h1>
    <p>{data.resource.description}</p>
  </div>
  <div class="heading-actions">
    <span class={data.collection.status === 'ready' ? 'status-badge is-ready' : 'status-badge'}>
      {statusLabel(data.collection.status)}
    </span>
    <a class="refresh-link" href={`/admin/${data.resource.slug}`}>刷新</a>
  </div>
</div>

<div class="endpoint-line">
  <span>Server load endpoint</span>
  <code>/api/v1/workspaces/&lt;workspace_id&gt;/{data.resource.endpoint}</code>
</div>

{#if data.collection.status === 'ready' && data.collection.records.length > 0}
  <section class="table-section" aria-label={`${data.resource.label} 列表`}>
    <div class="table-meta">
      <h2>列表</h2>
      <span>{data.collection.records.length} records</span>
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            {#each data.resource.columns as column (column.key)}
              <th scope="col">{column.label}</th>
            {/each}
          </tr>
        </thead>
        <tbody>
          {#each data.collection.records as record, index (recordKey(record, index))}
            <tr>
              {#each data.resource.columns as column (column.key)}
                <td>{formatValue(record[column.key])}</td>
              {/each}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </section>
{:else}
  <section class="empty-state" aria-live="polite">
    <div class="empty-mark" aria-hidden="true">—</div>
    {#if data.collection.status === 'ready'}
      <h2>暂无 {data.resource.label}</h2>
      <p>API 已连接，但当前 Workspace 尚未返回任何记录。</p>
    {:else if data.collection.status === 'not-configured'}
      <h2>需要 Workspace 上下文</h2>
      <p>{data.collection.message}</p>
      <code>ZEUS_WORKSPACE_ID</code>
    {:else if data.collection.status === 'not-available'}
      <h2>列表 API 尚未提供</h2>
      <p>{data.collection.message}</p>
      {#if data.collection.httpStatus}
        <span class="http-status">HTTP {data.collection.httpStatus}</span>
      {/if}
    {:else if data.collection.status === 'unauthorized'}
      <h2>无法访问此 Workspace</h2>
      <p>{data.collection.message}</p>
    {:else}
      <h2>暂时无法加载</h2>
      <p>{data.collection.message}</p>
    {/if}
  </section>
{/if}

<style>
  .resource-heading {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 2rem;
    padding-bottom: 1.5rem;
    border-bottom: 1px solid var(--border);
  }

  .breadcrumb {
    display: inline-block;
    margin-bottom: 0.85rem;
    color: var(--muted-foreground);
    font-size: 0.75rem;
    font-weight: 600;
    text-decoration: none;
  }

  .breadcrumb:hover {
    color: var(--foreground);
  }

  h1,
  h2,
  p {
    margin-top: 0;
  }

  h1 {
    margin-bottom: 0.5rem;
    font-size: clamp(1.6rem, 3vw, 2rem);
    letter-spacing: -0.03em;
    line-height: 1.1;
  }

  .resource-heading p {
    margin-bottom: 0;
    color: var(--muted-foreground);
    font-size: 0.875rem;
    line-height: 1.55;
  }

  .heading-actions {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }

  .status-badge {
    display: inline-flex;
    align-items: center;
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 0.35rem 0.65rem;
    color: var(--muted-foreground);
    font-size: 0.6875rem;
    font-weight: 650;
    white-space: nowrap;
  }

  .status-badge.is-ready {
    border-color: color-mix(in oklab, var(--primary) 28%, var(--border));
    color: var(--foreground);
  }

  .refresh-link {
    color: var(--muted-foreground);
    font-size: 0.8125rem;
    font-weight: 600;
    text-decoration: none;
  }

  .refresh-link:hover {
    color: var(--foreground);
  }

  .endpoint-line {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-top: 1.25rem;
    color: var(--muted-foreground);
    font-size: 0.75rem;
  }

  .endpoint-line code {
    border-radius: 0.35rem;
    background: var(--muted);
    padding: 0.25rem 0.45rem;
    color: var(--foreground);
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.75rem;
  }

  .table-section {
    margin-top: 2rem;
  }

  .table-meta {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 1rem;
    margin-bottom: 0.75rem;
  }

  .table-meta h2 {
    margin-bottom: 0;
    font-size: 1rem;
  }

  .table-meta span {
    color: var(--muted-foreground);
    font-size: 0.6875rem;
    font-weight: 650;
  }

  .table-wrap {
    overflow-x: auto;
    border-top: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
  }

  table {
    width: 100%;
    min-width: 42rem;
    border-collapse: collapse;
    text-align: left;
  }

  th,
  td {
    padding: 0.85rem 0.75rem;
    border-bottom: 1px solid var(--border);
    font-size: 0.8125rem;
    white-space: nowrap;
  }

  th {
    color: var(--muted-foreground);
    font-size: 0.6875rem;
    font-weight: 700;
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }

  td {
    color: var(--foreground);
  }

  tbody tr:last-child td {
    border-bottom: 0;
  }

  .empty-state {
    display: flex;
    min-height: 18rem;
    align-items: center;
    flex-direction: column;
    justify-content: center;
    margin-top: 2rem;
    border-top: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
    padding: 2rem;
    text-align: center;
  }

  .empty-mark {
    display: grid;
    width: 2.5rem;
    height: 2.5rem;
    place-items: center;
    border: 1px solid var(--border);
    border-radius: 0.75rem;
    color: var(--muted-foreground);
    font-size: 1.25rem;
  }

  .empty-state h2 {
    margin: 1rem 0 0.5rem;
    font-size: 1rem;
  }

  .empty-state p {
    max-width: 32rem;
    margin-bottom: 0;
    color: var(--muted-foreground);
    font-size: 0.8125rem;
    line-height: 1.6;
  }

  .empty-state code,
  .http-status {
    margin-top: 0.75rem;
    color: var(--muted-foreground);
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.75rem;
  }

  .empty-state code {
    border-radius: 0.35rem;
    background: var(--muted);
    padding: 0.3rem 0.45rem;
  }

  @media (max-width: 640px) {
    .resource-heading {
      display: block;
    }

    .heading-actions {
      margin-top: 1rem;
    }
  }
</style>
