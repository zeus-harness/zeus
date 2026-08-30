<script lang="ts">
  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';

  import type { ActionData, PageData } from './$types';

  let { data, form } = $props<{ data: PageData; form: ActionData }>();

  function statusVariant(enabled: boolean): 'secondary' | 'outline' {
    return enabled ? 'secondary' : 'outline';
  }

  function dateLabel(value: string): string {
    return value.replace('T', ' ').replace(/\.\d+Z$/, ' UTC').replace('Z', ' UTC');
  }

  function shortId(value: string): string {
    return value.length > 18 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value;
  }
</script>

<svelte:head>
  <title>Zeus · Identity Providers</title>
</svelte:head>

<div class="page-heading">
  <div>
    <p class="section-label">Organization identity</p>
    <h1>Identity Providers</h1>
    <p class="lede">配置当前组织的企业登录提供商，并控制新用户的即时入组与可信认证上下文。</p>
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

{#if data.authStatus !== 'ready'}
  <section class="empty-state" role="status" aria-live="polite">
    <h2>暂时无法确认登录状态</h2>
    <p>{data.loadError ?? '认证 API 暂时不可用，请稍后重试。'}</p>
  </section>
{:else if !data.organizationId}
  <section class="empty-state" role="status" aria-live="polite">
    <h2>没有活动组织</h2>
    <p>当前会话没有活动组织，选择组织后才能管理身份提供商。</p>
  </section>
{:else}
  <div class="content-grid">
    <Card.Root>
      <Card.Header>
        <Card.Title>创建身份提供商</Card.Title>
        <Card.Description>Client secret 只会提交给服务端，不会在列表或响应中回显。</Card.Description>
      </Card.Header>
      <Card.Content>
        <form method="POST" action="?/create" class="form-stack">
          <div class="field">
            <label for="provider-slug">Slug</label>
            <input id="provider-slug" name="slug" required autocomplete="off" placeholder="okta" />
          </div>
          <div class="field">
            <label for="provider-issuer-url">Issuer URL</label>
            <input
              id="provider-issuer-url"
              name="issuer_url"
              required
              type="url"
              autocomplete="url"
              placeholder="https://idp.example.com"
            />
          </div>
          <div class="field">
            <label for="provider-client-id">Client ID</label>
            <input id="provider-client-id" name="client_id" required autocomplete="off" />
          </div>
          <div class="field">
            <label for="provider-client-secret">Client secret</label>
            <input
              id="provider-client-secret"
              name="client_secret"
              required
              type="password"
              autocomplete="new-password"
            />
          </div>
          <label class="checkbox-field">
            <input type="checkbox" name="jit_enabled" value="true" />
            <span>
              <strong>启用即时入组（JIT）</strong>
              <small>允许满足组织域名条件的新联邦身份自动加入。</small>
            </span>
          </label>
          <div class="field">
            <label for="provider-trusted-acr">Trusted ACR</label>
            <textarea
              id="provider-trusted-acr"
              name="trusted_acr"
              rows="3"
              placeholder="urn:example:loa:2，可用逗号或换行分隔"
            ></textarea>
          </div>
          <div class="field">
            <label for="provider-trusted-amr">Trusted AMR</label>
            <textarea
              id="provider-trusted-amr"
              name="trusted_amr"
              rows="3"
              placeholder="pwd, mfa，可用逗号或换行分隔"
            ></textarea>
          </div>
          <Button type="submit" class="w-full">创建提供商</Button>
        </form>
      </Card.Content>
    </Card.Root>

    <Card.Root>
      <Card.Header>
        <Card.Title>已配置的提供商</Card.Title>
        <Card.Description>更新使用列表中的 revision 做并发保护；停用不会删除配置。</Card.Description>
      </Card.Header>
      <Card.Content>
        {#if data.loadError}
          <div class="notice notice-error" role="alert">
            {data.loadError}{#if data.httpStatus}（HTTP {data.httpStatus}）{/if}
          </div>
        {:else if data.providers.length === 0}
          <div class="empty-inline">
            <h2>还没有身份提供商</h2>
            <p>使用左侧表单创建第一个企业登录提供商。</p>
          </div>
        {:else}
          <div class="provider-list">
            {#each data.providers as provider (provider.id)}
              <article class="provider-card">
                <div class="provider-summary">
                  <div class="provider-title">
                    <h2>{provider.slug}</h2>
                    <Badge variant={statusVariant(provider.enabled)}>
                      {provider.enabled ? '已启用' : '已停用'}
                    </Badge>
                    {#if provider.jit_enabled}<Badge variant="outline">JIT</Badge>{/if}
                  </div>
                  <p class="issuer">{provider.issuer_url}</p>
                  <dl class="provider-meta">
                    <div>
                      <dt>Client ID</dt>
                      <dd>{provider.client_id}</dd>
                    </div>
                    <div>
                      <dt>Revision</dt>
                      <dd>{provider.revision}</dd>
                    </div>
                    <div>
                      <dt>更新时间</dt>
                      <dd>{dateLabel(provider.updated_at)}</dd>
                    </div>
                  </dl>
                </div>

                <details class="edit-details">
                  <summary>编辑配置</summary>
                  <form method="POST" action="?/update" class="form-stack compact-form">
                    <input type="hidden" name="provider_id" value={provider.id} />
                    <input type="hidden" name="revision" value={provider.revision} />
                    <div class="field">
                      <label for={`provider-slug-${provider.id}`}>Slug</label>
                      <input id={`provider-slug-${provider.id}`} name="slug" required value={provider.slug} />
                    </div>
                    <div class="field">
                      <label for={`provider-issuer-${provider.id}`}>Issuer URL</label>
                      <input
                        id={`provider-issuer-${provider.id}`}
                        name="issuer_url"
                        required
                        type="url"
                        value={provider.issuer_url}
                      />
                    </div>
                    <div class="field">
                      <label for={`provider-client-${provider.id}`}>Client ID</label>
                      <input id={`provider-client-${provider.id}`} name="client_id" required value={provider.client_id} />
                    </div>
                    <div class="field">
                      <label for={`provider-secret-${provider.id}`}>新 Client secret（可选）</label>
                      <input
                        id={`provider-secret-${provider.id}`}
                        name="client_secret"
                        type="password"
                        autocomplete="new-password"
                        placeholder="留空以保留原 secret"
                      />
                    </div>
                    <label class="checkbox-field">
                      <input type="checkbox" name="enabled" value="true" checked={provider.enabled} />
                      <span>启用此提供商</span>
                    </label>
                    <label class="checkbox-field">
                      <input type="checkbox" name="jit_enabled" value="true" checked={provider.jit_enabled} />
                      <span>启用即时入组（JIT）</span>
                    </label>
                    <div class="field">
                      <label for={`provider-acr-${provider.id}`}>Trusted ACR</label>
                      <textarea id={`provider-acr-${provider.id}`} name="trusted_acr" rows="2">{provider.trusted_acr.join(', ')}</textarea>
                    </div>
                    <div class="field">
                      <label for={`provider-amr-${provider.id}`}>Trusted AMR</label>
                      <textarea id={`provider-amr-${provider.id}`} name="trusted_amr" rows="2">{provider.trusted_amr.join(', ')}</textarea>
                    </div>
                    <Button type="submit" size="sm">保存更改</Button>
                  </form>
                </details>
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

  .notice {
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

  .field input,
  .field textarea {
    width: 100%;
    border: 1px solid var(--input);
    border-radius: 0.5rem;
    background: var(--background);
    padding: 0.6rem 0.7rem;
    color: var(--foreground);
    font: inherit;
    font-size: 0.8125rem;
    outline: none;
  }

  .field textarea {
    min-height: 4rem;
    resize: vertical;
    line-height: 1.5;
  }

  .field input:focus,
  .field textarea:focus {
    border-color: var(--ring);
    box-shadow: 0 0 0 3px color-mix(in oklab, var(--ring) 18%, transparent);
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
    font-weight: 400;
    line-height: 1.45;
  }

  .provider-list {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .provider-card {
    border: 1px solid var(--border);
    border-radius: 0.75rem;
    padding: 1rem;
  }

  .provider-title {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.5rem;
  }

  .provider-title h2 {
    margin-bottom: 0;
    font-size: 0.9375rem;
  }

  .issuer {
    margin: 0.55rem 0 0;
    overflow-wrap: anywhere;
    color: var(--muted-foreground);
    font-size: 0.8125rem;
    line-height: 1.5;
  }

  .provider-meta {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 0.75rem;
    margin: 1rem 0 0;
  }

  .provider-meta dt {
    color: var(--muted-foreground);
    font-size: 0.6875rem;
    font-weight: 700;
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }

  .provider-meta dd {
    margin: 0.25rem 0 0;
    overflow-wrap: anywhere;
    color: var(--foreground);
    font-size: 0.75rem;
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
    .page-heading {
      display: block;
    }

    .page-heading > :global([data-slot='badge']) {
      margin-top: 1rem;
    }

    .provider-meta {
      grid-template-columns: 1fr;
    }
  }
</style>
