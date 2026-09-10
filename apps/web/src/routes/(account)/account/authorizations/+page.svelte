<script lang="ts">
  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';
  import * as Table from '@zeus/ui/components/ui/table';

  import type { ActionData, PageData } from './$types';

  let { data, form } = $props<{ data: PageData; form: ActionData }>();

  function dateLabel(value: string | null | undefined): string {
    return value ? value.replace('T', ' ').replace(/\.\d+Z$/, ' UTC').replace('Z', ' UTC') : '未使用';
  }

  function shortId(value: string): string {
    return value.length > 18 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value;
  }
</script>

<svelte:head>
  <title>Zeus · Authorizations</title>
</svelte:head>

<main class="mx-auto max-w-[1100px] px-5 py-8 lg:px-8 lg:py-10">
  <div class="page-heading">
    <div>
      <p class="section-label">Account</p>
      <h1>OIDC Authorizations</h1>
      <p class="lede">查看第三方应用代表你访问组织资源的授权，并随时撤销不再需要的授权。</p>
    </div>
    <Badge variant="secondary">Personal access</Badge>
  </div>

  {#if form?.type === 'error'}
    <div class="notice notice-error" role="alert">{form.message}</div>
  {:else if form?.type === 'success'}
    <div class="notice" role="status" aria-live="polite">{form.message}</div>
  {/if}

  {#if data.loadError}
    <section class="state-card notice-error" role="alert">
      <h2>无法读取授权记录</h2>
      <p>{data.loadError}{#if data.httpStatus}（HTTP {data.httpStatus}）{/if}</p>
    </section>
  {:else if data.grants.length === 0}
    <Card.Root class="mt-6">
      <Card.Content>
        <div class="empty-state">
          <h2>还没有 OIDC 授权</h2>
          <p>当第三方应用请求并获得授权后，授权记录会显示在这里。</p>
        </div>
      </Card.Content>
    </Card.Root>
  {:else}
    <Card.Root class="mt-6">
      <Card.Header>
        <Card.Title>已授权的应用</Card.Title>
        <Card.Description>时间均以 UTC 显示。撤销后，该 Client 需要重新获得授权才能访问。</Card.Description>
      </Card.Header>
      <Card.Content>
        <div class="table-wrap">
          <Table.Root>
            <Table.Header>
              <Table.Row>
                <Table.Head>Client</Table.Head>
                <Table.Head>Organization</Table.Head>
                <Table.Head>Scope</Table.Head>
                <Table.Head>授权时间</Table.Head>
                <Table.Head>最后使用时间</Table.Head>
                <Table.Head class="text-right">操作</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {#each data.grants as grant (grant.client_id)}
                <Table.Row>
                  <Table.Cell>
                    <span class="primary-cell">{grant.client_name}</span>
                    <span class="secondary-cell">{grant.client_public_id}</span>
                  </Table.Cell>
                  <Table.Cell>
                    <span class="primary-cell">{grant.organization_name}</span>
                    <span class="secondary-cell">Organization {shortId(grant.organization_id)}</span>
                  </Table.Cell>
                  <Table.Cell class="scope-cell">{grant.scopes.join(' ') || '—'}</Table.Cell>
                  <Table.Cell class="muted-cell">{dateLabel(grant.granted_at)}</Table.Cell>
                  <Table.Cell class="muted-cell">{dateLabel(grant.last_used_at)}</Table.Cell>
                  <Table.Cell class="actions-cell">
                    <form method="POST" action="?/revoke">
                      <input type="hidden" name="client_id" value={grant.client_id} />
                      <Button type="submit" variant="destructive" size="sm">撤销</Button>
                    </form>
                  </Table.Cell>
                </Table.Row>
              {/each}
            </Table.Body>
          </Table.Root>
        </div>
      </Card.Content>
    </Card.Root>
  {/if}
</main>

<style>
  .page-heading {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 2rem;
    padding-bottom: 1.5rem;
    border-bottom: 1px solid var(--border);
  }

  .section-label {
    margin: 0 0 0.75rem;
    color: var(--muted-foreground);
    font-size: 0.75rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
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

  .lede {
    max-width: 42rem;
    margin-bottom: 0;
    color: var(--muted-foreground);
    font-size: 0.875rem;
    line-height: 1.6;
  }

  .notice,
  .state-card {
    margin-top: 1.25rem;
    border: 1px solid var(--border);
    border-radius: 0.75rem;
    padding: 0.85rem 1rem;
    background: color-mix(in oklab, var(--card) 75%, transparent);
    font-size: 0.8125rem;
  }

  .notice-error {
    border-color: color-mix(in oklab, var(--destructive) 45%, var(--border));
    background: color-mix(in oklab, var(--destructive) 10%, transparent);
    color: var(--destructive);
  }

  .state-card h2 {
    margin-bottom: 0.4rem;
    font-size: 1rem;
  }

  .state-card p {
    margin-bottom: 0;
    line-height: 1.6;
  }

  .table-wrap {
    overflow-x: auto;
  }

  .primary-cell,
  .secondary-cell {
    display: block;
  }

  .primary-cell {
    font-weight: 650;
  }

  .secondary-cell {
    margin-top: 0.25rem;
    overflow-wrap: anywhere;
    color: var(--muted-foreground);
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.6875rem;
  }

  :global([data-slot='table-cell'].scope-cell) {
    min-width: 12rem;
    color: var(--foreground);
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.75rem;
    line-height: 1.5;
    white-space: normal;
  }

  :global([data-slot='table-cell'].muted-cell) {
    min-width: 9rem;
    color: var(--muted-foreground);
    font-size: 0.75rem;
    white-space: nowrap;
  }

  :global([data-slot='table-cell'].actions-cell) {
    white-space: nowrap;
  }

  .empty-state {
    padding: 2rem 1rem;
    text-align: center;
  }

  .empty-state h2 {
    margin-bottom: 0.4rem;
    font-size: 1rem;
  }

  .empty-state p {
    margin-bottom: 0;
    color: var(--muted-foreground);
    font-size: 0.8125rem;
    line-height: 1.6;
  }

  @media (max-width: 640px) {
    .page-heading {
      display: block;
    }

    .page-heading > :global([data-slot='badge']) {
      display: inline-flex;
      margin-top: 1rem;
    }
  }
</style>
