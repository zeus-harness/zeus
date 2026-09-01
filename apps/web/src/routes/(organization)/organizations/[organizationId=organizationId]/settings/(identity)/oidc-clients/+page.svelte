<script lang="ts">
  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';
  import { Input } from '@zeus/ui/components/ui/input';
  import { NativeSelect, NativeSelectOption } from '@zeus/ui/components/ui/native-select';
  import { Textarea } from '@zeus/ui/components/ui/textarea';

  import type { ActionData, PageData } from './$types';

  let { data, form } = $props<{ data: PageData; form: ActionData }>();

  function dateLabel(value: string | null | undefined): string {
    return value ? value.replace('T', ' ').replace(/\.\d+Z$/, ' UTC').replace('Z', ' UTC') : '未提供';
  }

  function shortId(value: string): string {
    return value.length > 18 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value;
  }

  function listLabel(values: string[]): string {
    return values.length > 0 ? values.join('\n') : '—';
  }
</script>

<svelte:head>
  <title>Zeus · OIDC Clients</title>
</svelte:head>

<div class="page-heading">
  <div>
    <p class="section-label">Organization identity</p>
    <h1>OIDC Clients</h1>
    <p class="lede">管理允许外部应用访问组织身份的 OIDC Client、回调地址和授权范围。</p>
  </div>
  <Badge variant={data.organizationId ? 'secondary' : 'outline'}>
    {data.organizationId ? `Organization ${shortId(data.organizationId)}` : 'No active organization'}
  </Badge>
</div>

{#if form?.type === 'error'}
  <div class="notice notice-error" role="alert">{form.message}</div>
{:else if form?.type === 'success'}
  <div class="notice" role="status" aria-live="polite">{form.message}</div>
{/if}

{#if form?.type === 'created' && form.client_secret}
  <section class="secret-notice" aria-labelledby="secret-heading">
    <div>
      <h2 id="secret-heading">Client Secret（仅显示一次）</h2>
      <p>
        {form.client.name} 已创建，Client ID 为 <code>{form.client.client_id}</code>。
      </p>
      <p class="one-time-note">
        请立即将 Secret 保存到安全的密钥管理器。离开或刷新页面后无法再次获取；此页面不会将它保存到 localStorage。
      </p>
    </div>
    <code class="secret-value">{form.client_secret}</code>
  </section>
{:else if form?.type === 'created'}
  <div class="notice" role="status" aria-live="polite">{form.message}</div>
{/if}

{#if data.authStatus !== 'ready'}
  <section class="empty-state" role="status" aria-live="polite">
    <h2>暂时无法确认登录状态</h2>
    <p>{data.loadError ?? '认证 API 暂时不可用，请稍后重试。'}</p>
  </section>
{:else if !data.organizationId}
  <section class="empty-state" role="status" aria-live="polite">
    <h2>没有活动组织</h2>
    <p>当前会话没有活动组织，选择组织后才能管理 OIDC Client。</p>
  </section>
{:else}
  <div class="content-grid">
    <Card.Root>
      <Card.Header>
        <Card.Title>创建 OIDC Client</Card.Title>
        <Card.Description>Client Secret 只会在创建成功的响应中显示一次。</Card.Description>
      </Card.Header>
      <Card.Content>
        <form method="POST" action="?/create" class="form-stack">
          <div class="field">
            <label for="client-name">名称</label>
            <Input id="client-name" name="name" required autocomplete="off" placeholder="Customer portal" />
          </div>

          <div class="field">
            <label for="client-type">Client 类型</label>
            <NativeSelect id="client-type" name="client_type" value="public" class="w-full">
              <NativeSelectOption value="public">public</NativeSelectOption>
              <NativeSelectOption value="confidential">confidential</NativeSelectOption>
            </NativeSelect>
            <p class="field-help">confidential Client 适合能够安全保存 Secret 的服务端应用。</p>
          </div>

          <div class="field">
            <label for="client-redirect-uris">Redirect URIs</label>
            <Textarea
              id="client-redirect-uris"
              name="redirect_uris"
              rows={4}
              required
              placeholder="https://app.example.com/oidc/callback&#10;每行一个，也可用逗号分隔"
            />
          </div>

          <div class="field">
            <label for="client-post-logout-redirect-uris">Post-logout Redirect URIs</label>
            <Textarea
              id="client-post-logout-redirect-uris"
              name="post_logout_redirect_uris"
              rows={3}
              placeholder="https://app.example.com/logout/callback&#10;可选，每行一个"
            />
          </div>

          <div class="field">
            <label for="client-allowed-scopes">Allowed scopes</label>
            <Textarea
              id="client-allowed-scopes"
              name="allowed_scopes"
              rows={3}
              required
              placeholder="openid profile email&#10;可用逗号或换行分隔"
            />
          </div>

          <label class="checkbox-field">
            <input type="checkbox" name="trusted" value="true" />
            <span>
              <strong>Trusted Client</strong>
              <small>信任此应用可请求组织允许的 scopes。</small>
            </span>
          </label>

          <Button type="submit" class="w-full">创建 Client</Button>
        </form>
      </Card.Content>
    </Card.Root>

    <Card.Root>
      <Card.Header>
        <Card.Title>组织 OIDC Clients</Card.Title>
        <Card.Description>更新使用列表中的 revision 做并发保护；删除后不能恢复。</Card.Description>
      </Card.Header>
      <Card.Content>
        {#if data.loadError}
          <div class="notice notice-error" role="alert">
            {data.loadError}{#if data.httpStatus}（HTTP {data.httpStatus}）{/if}
          </div>
        {:else if data.clients.length === 0}
          <div class="empty-inline">
            <h2>还没有 OIDC Client</h2>
            <p>使用左侧表单创建第一个组织 Client。</p>
          </div>
        {:else}
          <div class="client-list">
            {#each data.clients as client (client.id)}
              <article class="client-card">
                <div class="client-summary">
                  <div class="client-title">
                    <h2>{client.name}</h2>
                    <Badge variant={client.client_type === 'confidential' ? 'secondary' : 'outline'}>
                      {client.client_type}
                    </Badge>
                    {#if client.trusted}<Badge variant="secondary">trusted</Badge>{/if}
                    <Badge variant={client.status === 'active' ? 'secondary' : 'destructive'}>
                      {client.status === 'active' ? 'active' : client.status}
                    </Badge>
                  </div>
                  <p class="client-id">Client ID · {client.client_id}</p>
                  <dl class="client-meta">
                    <div>
                      <dt>Allowed scopes</dt>
                      <dd class="multiline-value">{listLabel(client.allowed_scopes)}</dd>
                    </div>
                    <div>
                      <dt>Redirect URIs</dt>
                      <dd class="multiline-value">{listLabel(client.redirect_uris)}</dd>
                    </div>
                    <div>
                      <dt>Revision / 更新时间</dt>
                      <dd>{client.revision} · {dateLabel(client.updated_at)}</dd>
                    </div>
                  </dl>
                </div>

                {#if client.status === 'active'}
                <details class="edit-details">
                  <summary>编辑配置</summary>
                  <form method="POST" action="?/update" class="form-stack compact-form">
                    <input type="hidden" name="client_id" value={client.id} />
                    <input type="hidden" name="revision" value={client.revision} />

                    <div class="field">
                      <label for={`edit-client-name-${client.client_id}`}>名称</label>
                      <Input
                        id={`edit-client-name-${client.client_id}`}
                        name="name"
                        required
                        autocomplete="off"
                        value={client.name}
                      />
                    </div>

                    <p class="read-only-field">
                      <span>Client 类型</span>
                      <strong>{client.client_type}</strong>
                      <small>Client 类型创建后保持不变。</small>
                    </p>

                    <div class="field">
                      <label for={`edit-client-redirect-uris-${client.client_id}`}>Redirect URIs</label>
                      <Textarea
                        id={`edit-client-redirect-uris-${client.client_id}`}
                        name="redirect_uris"
                        rows={3}
                        required
                        value={client.redirect_uris.join('\n')}
                      />
                    </div>

                    <div class="field">
                      <label for={`edit-client-post-logout-redirect-uris-${client.client_id}`}>Post-logout Redirect URIs</label>
                      <Textarea
                        id={`edit-client-post-logout-redirect-uris-${client.client_id}`}
                        name="post_logout_redirect_uris"
                        rows={2}
                        value={client.post_logout_redirect_uris.join('\n')}
                      />
                    </div>

                    <div class="field">
                      <label for={`edit-client-allowed-scopes-${client.client_id}`}>Allowed scopes</label>
                      <Textarea
                        id={`edit-client-allowed-scopes-${client.client_id}`}
                        name="allowed_scopes"
                        rows={2}
                        required
                        value={client.allowed_scopes.join('\n')}
                      />
                    </div>

                    <label class="checkbox-field">
                      <input type="checkbox" name="trusted" value="true" checked={client.trusted} />
                      <span>Trusted Client</span>
                    </label>

                    <div class="form-actions">
                      <Button type="submit" size="sm">保存更改</Button>
                    </div>
                  </form>
                  <form method="POST" action="?/delete" class="delete-form">
                    <input type="hidden" name="client_id" value={client.id} />
                    <Button type="submit" variant="destructive" size="sm">删除 Client</Button>
                  </form>
                </details>
                {:else}
                  <p class="revoked-note">此 Client 已撤销，不能继续编辑或删除。</p>
                {/if}
              </article>
            {/each}
          </div>
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
  .secret-notice {
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

  .secret-notice {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(15rem, 0.8fr);
    gap: 1.25rem;
    border-color: color-mix(in oklab, var(--primary) 35%, var(--border));
  }

  .secret-notice h2 {
    margin-bottom: 0.4rem;
    font-size: 0.9375rem;
  }

  .secret-notice p {
    margin-bottom: 0;
    color: var(--muted-foreground);
    line-height: 1.5;
  }

  .secret-notice code {
    background: var(--muted);
    color: var(--foreground);
  }

  .one-time-note {
    margin-top: 0.5rem !important;
    font-size: 0.75rem;
  }

  code {
    overflow-wrap: anywhere;
    border-radius: 0.35rem;
    padding: 0.12rem 0.35rem;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.9em;
  }

  .secret-value {
    align-self: center;
    overflow-wrap: anywhere;
    border-radius: 0.5rem;
    padding: 0.7rem 0.8rem !important;
    font-size: 0.8rem;
    line-height: 1.5;
    user-select: text;
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

  .compact-form {
    margin-top: 1rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border);
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
  }

  .field label,
  .checkbox-field {
    color: var(--foreground);
    font-size: 0.8125rem;
    font-weight: 600;
  }

  .field-help,
  .read-only-field small {
    margin: 0;
    color: var(--muted-foreground);
    font-size: 0.75rem;
    line-height: 1.45;
  }

  .checkbox-field {
    display: flex;
    align-items: flex-start;
    gap: 0.6rem;
    font-weight: 500;
  }

  .checkbox-field input {
    width: 1rem;
    height: 1rem;
    margin-top: 0.1rem;
    accent-color: var(--primary);
  }

  .checkbox-field span {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
  }

  .checkbox-field small {
    color: var(--muted-foreground);
    font-size: 0.75rem;
    line-height: 1.45;
  }

  .client-list {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .client-card {
    border: 1px solid var(--border);
    border-radius: 0.75rem;
    padding: 1rem;
  }

  .client-title {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.5rem;
  }

  .client-title h2 {
    margin-bottom: 0;
    font-size: 0.9375rem;
  }

  .client-id {
    margin: 0.55rem 0 0;
    overflow-wrap: anywhere;
    color: var(--muted-foreground);
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.75rem;
    line-height: 1.5;
  }

  .client-meta {
    display: grid;
    gap: 0.85rem;
    margin: 1rem 0 0;
  }

  .client-meta dt,
  .read-only-field span {
    color: var(--muted-foreground);
    font-size: 0.6875rem;
    font-weight: 700;
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }

  .client-meta dd {
    margin: 0.25rem 0 0;
    overflow-wrap: anywhere;
    color: var(--foreground);
    font-size: 0.75rem;
  }

  .multiline-value {
    white-space: pre-wrap;
  }

  .edit-details {
    margin-top: 1rem;
    border-top: 1px solid var(--border);
    padding-top: 0.85rem;
  }

  .edit-details summary {
    cursor: pointer;
    color: var(--muted-foreground);
    font-size: 0.75rem;
    font-weight: 650;
  }

  .read-only-field {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    margin: 0;
    font-size: 0.8125rem;
  }

  .read-only-field strong {
    font-weight: 550;
  }

  .form-actions,
  .delete-form {
    display: flex;
    justify-content: flex-end;
  }

  .delete-form {
    margin-top: 0.75rem;
    padding-top: 0.75rem;
    border-top: 1px solid var(--border);
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
  }

  @media (max-width: 640px) {
    .page-heading,
    .secret-notice {
      display: block;
    }

    .page-heading > :global([data-slot='badge']),
    .secret-value {
      display: inline-block;
      margin-top: 1rem;
    }
  }
</style>
