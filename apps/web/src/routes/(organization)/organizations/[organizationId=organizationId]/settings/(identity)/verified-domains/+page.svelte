<script lang="ts">
  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';
  import { Input } from '@zeus/ui/components/ui/input';
  import * as Table from '@zeus/ui/components/ui/table';

  import type { ActionData, PageData } from './$types';

  let { data, form } = $props<{ data: PageData; form: ActionData }>();

  function statusVariant(status: string): 'default' | 'secondary' | 'destructive' | 'outline' {
    if (status === 'verified') return 'secondary';
    if (status === 'revoked') return 'destructive';
    if (status === 'pending') return 'default';
    return 'outline';
  }

  function dateLabel(value: string | null): string {
    return value ? value.replace('T', ' ').replace(/\.\d+Z$/, ' UTC').replace('Z', ' UTC') : '—';
  }
</script>

<svelte:head>
  <title>Zeus · Domains</title>
</svelte:head>

<div class="page-heading">
  <div>
    <p class="section-label">Organization identity</p>
    <h1>Verified Domains</h1>
    <p class="lede">验证组织拥有的邮箱域名，为联合身份的即时入组提供可信边界。</p>
  </div>
  <Badge variant={data.organizationId ? 'secondary' : 'outline'}>
    {data.organizationId ? 'Organization context ready' : 'No active organization'}
  </Badge>
</div>

{#if form?.type === 'error'}
  <div class="notice notice-error" role="alert">{form.message}</div>
{:else if form?.type === 'success'}
  <div class="notice" role="status" aria-live="polite">{form.message}</div>
{/if}

{#if form?.type === 'domain_created'}
  <section class="verification-notice" aria-labelledby="verification-heading">
    <div>
      <h2 id="verification-heading">DNS TXT 验证资料</h2>
      <p>{form.message}</p>
      <p class="one-time-note">TXT 值只在本次创建响应中显示；离开或刷新页面后不会从 API 再次读取。</p>
    </div>
    <dl class="record-list">
      <div>
        <dt>名称</dt>
        <dd><code>{form.verification.txt_record_name}</code></dd>
      </div>
      <div>
        <dt>值</dt>
        <dd><code>{form.verification.txt_record_value}</code></dd>
      </div>
    </dl>
  </section>
{/if}

{#if data.authStatus !== 'ready'}
  <section class="empty-state" role="status" aria-live="polite">
    <h2>暂时无法确认登录状态</h2>
    <p>{data.loadError ?? '认证 API 暂时不可用，请稍后重试。'}</p>
  </section>
{:else if !data.organizationId}
  <section class="empty-state" role="status" aria-live="polite">
    <h2>没有活动组织</h2>
    <p>当前会话没有活动组织，选择组织后才能管理已验证域名。</p>
  </section>
{:else}
  <div class="content-grid">
    <Card.Root>
      <Card.Header>
        <Card.Title>添加域名</Card.Title>
        <Card.Description>创建后请将一次性 TXT 记录添加到 DNS，再执行验证。</Card.Description>
      </Card.Header>
      <Card.Content>
        <form method="POST" action="?/create" class="form-stack">
          <div class="field">
            <label for="domain">域名</label>
            <Input
              id="domain"
              name="domain"
              required
              autocomplete="off"
              placeholder="example.com"
            />
            <p class="field-help">只填写域名，不要包含协议、路径或邮箱地址。</p>
          </div>
          <Button type="submit" class="w-full">创建验证挑战</Button>
        </form>
      </Card.Content>
    </Card.Root>

    <Card.Root>
      <Card.Header>
        <Card.Title>组织域名</Card.Title>
        <Card.Description>撤销会使域名失去已验证状态，但不会删除审计记录。</Card.Description>
      </Card.Header>
      <Card.Content>
        {#if data.loadError}
          <div class="notice notice-error" role="alert">
            {data.loadError}{#if data.httpStatus}（HTTP {data.httpStatus}）{/if}
          </div>
        {:else if data.domains.length === 0}
          <div class="empty-inline">
            <h2>还没有组织域名</h2>
            <p>添加一个域名后，在这里完成 DNS 验证。</p>
          </div>
        {:else}
          <Table.Root>
            <Table.Header>
              <Table.Row>
                <Table.Head>域名</Table.Head>
                <Table.Head>状态</Table.Head>
                <Table.Head>验证时间</Table.Head>
                <Table.Head>更新时间</Table.Head>
                <Table.Head class="text-right">操作</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {#each data.domains as domain (domain.id)}
                <Table.Row>
                  <Table.Cell>
                    <span class="domain-name">{domain.domain}</span>
                    <span class="domain-id">{domain.id}</span>
                  </Table.Cell>
                  <Table.Cell><Badge variant={statusVariant(domain.status)}>{domain.status}</Badge></Table.Cell>
                  <Table.Cell class="muted-cell">{dateLabel(domain.verified_at)}</Table.Cell>
                  <Table.Cell class="muted-cell">{dateLabel(domain.updated_at)}</Table.Cell>
                  <Table.Cell class="actions-cell">
                    {#if domain.status === 'pending'}
                      <form method="POST" action="?/verify">
                        <input type="hidden" name="domain_id" value={domain.id} />
                        <Button type="submit" size="sm">验证</Button>
                      </form>
                    {/if}
                    {#if domain.status !== 'revoked'}
                      <form method="POST" action="?/revoke">
                        <input type="hidden" name="domain_id" value={domain.id} />
                        <Button type="submit" variant="destructive" size="sm">撤销</Button>
                      </form>
                    {/if}
                    {#if domain.status === 'revoked'}<span class="muted-cell">已撤销</span>{/if}
                  </Table.Cell>
                </Table.Row>
              {/each}
            </Table.Body>
          </Table.Root>
        {/if}
      </Card.Content>
    </Card.Root>
  </div>
{/if}

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
  .verification-notice {
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

  .verification-notice {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(18rem, 1fr);
    gap: 1.25rem;
    border-color: color-mix(in oklab, var(--primary) 35%, var(--border));
  }

  .verification-notice h2 {
    margin-bottom: 0.4rem;
    font-size: 0.9375rem;
  }

  .verification-notice p {
    margin-bottom: 0;
    color: var(--muted-foreground);
    line-height: 1.5;
  }

  .one-time-note {
    margin-top: 0.5rem;
    font-size: 0.75rem;
  }

  .record-list {
    display: grid;
    gap: 0.75rem;
    margin: 0;
  }

  .record-list dt {
    color: var(--muted-foreground);
    font-size: 0.6875rem;
    font-weight: 700;
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }

  .record-list dd {
    margin: 0.3rem 0 0;
  }

  code {
    display: block;
    overflow-wrap: anywhere;
    border-radius: 0.4rem;
    background: var(--muted);
    padding: 0.45rem 0.55rem;
    color: var(--foreground);
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.75rem;
    line-height: 1.45;
  }

  .content-grid {
    display: grid;
    grid-template-columns: minmax(18rem, 22rem) minmax(0, 1fr);
    gap: 1.5rem;
    margin-top: 1.5rem;
  }

  .form-stack {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
  }

  .field label {
    color: var(--foreground);
    font-size: 0.8125rem;
    font-weight: 600;
  }

  .field-help {
    margin-bottom: 0;
    color: var(--muted-foreground);
    font-size: 0.75rem;
    line-height: 1.45;
  }

  .domain-name,
  .domain-id {
    display: block;
  }

  .domain-name {
    font-weight: 650;
  }

  .domain-id {
    margin-top: 0.25rem;
    color: var(--muted-foreground);
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.6875rem;
  }

  .muted-cell {
    color: var(--muted-foreground);
    font-size: 0.75rem;
  }

  :global([data-slot='table-cell'].actions-cell) {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
    white-space: nowrap;
  }

  .empty-state {
    display: flex;
    min-height: 18rem;
    align-items: center;
    flex-direction: column;
    justify-content: center;
    margin-top: 1.5rem;
    border-top: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
    padding: 2rem;
    text-align: center;
  }

  .empty-state h2,
  .empty-inline h2 {
    margin-bottom: 0.4rem;
    font-size: 1rem;
  }

  .empty-state p,
  .empty-inline p {
    margin-bottom: 0;
    color: var(--muted-foreground);
    font-size: 0.8125rem;
    line-height: 1.6;
  }

  .empty-inline {
    border: 1px dashed var(--border);
    border-radius: 0.65rem;
    padding: 2rem 1rem;
    text-align: center;
  }

  @media (max-width: 900px) {
    .content-grid {
      grid-template-columns: 1fr;
    }

    .verification-notice {
      grid-template-columns: 1fr;
    }
  }

  @media (max-width: 640px) {
    .page-heading {
      display: block;
    }

    .page-heading > :global([data-slot='badge']) {
      margin-top: 1rem;
    }

    :global([data-slot='table-cell'].actions-cell) {
      align-items: flex-end;
      flex-direction: column;
    }
  }
</style>
