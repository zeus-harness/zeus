<script lang="ts">
  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';
  import { NativeSelect, NativeSelectOption } from '@zeus/ui/components/ui/native-select';
  import { Separator } from '@zeus/ui/components/ui/separator';

  import type { ActionData, PageData } from './$types';

  let { data, form } = $props<{ data: PageData; form: ActionData }>();
  let enabledProviders = $derived(
    data.providers.filter((provider: { enabled: boolean }) => provider.enabled)
  );

  function dateLabel(value: string): string {
    return value.replace('T', ' ').replace(/\.\d+Z$/, ' UTC').replace('Z', ' UTC');
  }
</script>

<svelte:head>
  <title>Zeus · Security</title>
</svelte:head>

<div class="page-heading">
  <div>
    <p class="section-label">Organization identity</p>
    <h1>Security</h1>
    <p class="lede">设置当前组织的多因素认证与联合身份要求，保存时会校验策略 revision。</p>
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

{#if data.authStatus !== 'ready'}
  <section class="empty-state" role="status" aria-live="polite">
    <h2>暂时无法确认登录状态</h2>
    <p>{data.policyLoadError ?? '认证 API 暂时不可用，请稍后重试。'}</p>
  </section>
{:else if !data.organizationId}
  <section class="empty-state" role="status" aria-live="polite">
    <h2>没有活动组织</h2>
    <p>当前会话没有活动组织，选择组织后才能管理安全策略。</p>
  </section>
{:else if data.policyLoadError}
  <section class="empty-state notice-error" role="alert">
    <h2>无法读取身份策略</h2>
    <p>{data.policyLoadError}{#if data.policyHttpStatus}（HTTP {data.policyHttpStatus}）{/if}</p>
  </section>
{:else if !data.policy}
  <section class="empty-state" role="status" aria-live="polite">
    <h2>身份策略不可用</h2>
    <p>当前组织没有返回可编辑的身份策略，请稍后重试。</p>
  </section>
{:else}
  <div class="content-grid">
    <Card.Root>
      <Card.Header>
        <Card.Title>组织身份策略</Card.Title>
        <Card.Description>这些要求会影响当前组织成员的登录方式。</Card.Description>
      </Card.Header>
      <Card.Content>
        <form method="POST" action="?/update" class="form-stack">
          <input type="hidden" name="revision" value={data.policy.revision} />

          <label class="policy-option">
            <input
              type="checkbox"
              name="mfa_required"
              value="true"
              checked={data.policy.mfa_required}
            />
            <span>
              <strong>要求多因素认证（MFA）</strong>
              <small>组织成员必须完成 MFA 才能满足登录要求。</small>
            </span>
          </label>

          <Separator />

          <label class="policy-option">
            <input
              type="checkbox"
              name="federated_required"
              value="true"
              checked={data.policy.federated_required}
            />
            <span>
              <strong>要求联合身份登录</strong>
              <small>启用后必须从下方选择一个身份提供商。</small>
            </span>
          </label>

          <div class="field">
            <label for="required-federated-provider">必选身份提供商</label>
            <NativeSelect
              id="required-federated-provider"
              name="required_federated_provider_id"
              value={data.policy.required_federated_provider_id ?? ''}
              required={data.policy.federated_required}
              class="w-full"
            >
              <NativeSelectOption value="">不指定</NativeSelectOption>
              {#each data.providers as provider (provider.id)}
                <NativeSelectOption value={provider.id} disabled={!provider.enabled}>
                  {provider.slug}{provider.enabled ? '' : '（已停用）'}
                </NativeSelectOption>
              {/each}
            </NativeSelect>
            {#if data.providersLoadError}
              <p class="field-help notice-error" role="alert">
                {data.providersLoadError}{#if data.providersHttpStatus}（HTTP {data.providersHttpStatus}）{/if}
              </p>
            {:else if enabledProviders.length === 0}
              <p class="field-help">当前没有已启用的身份提供商；先创建并启用一个提供商。</p>
            {:else}
              <p class="field-help">只有已启用的身份提供商可以作为组织的必选提供商。</p>
            {/if}
          </div>

          <div class="revision-note">
            <span>当前 Revision</span>
            <strong>{data.policy.revision}</strong>
            <small>如果保存前策略发生变化，请刷新页面后重试。</small>
          </div>

          <Button type="submit" class="w-full">保存安全策略</Button>
        </form>
      </Card.Content>
    </Card.Root>

    <Card.Root>
      <Card.Header>
        <Card.Title>可用身份提供商</Card.Title>
        <Card.Description>停用的提供商不能被设为必选提供商。</Card.Description>
      </Card.Header>
      <Card.Content>
        {#if data.providersLoadError}
          <div class="notice notice-error" role="alert">{data.providersLoadError}</div>
        {:else if data.providers.length === 0}
          <div class="empty-inline">
            <h2>还没有身份提供商</h2>
            <p>先到 Identity Providers 页面创建一个企业登录提供商。</p>
          </div>
        {:else}
          <div class="provider-list">
            {#each data.providers as provider (provider.id)}
              <div class="provider-row">
                <div>
                  <strong>{provider.slug}</strong>
                  <p>{provider.issuer_url}</p>
                </div>
                <Badge variant={provider.enabled ? 'secondary' : 'outline'}>
                  {provider.enabled ? '已启用' : '已停用'}
                </Badge>
              </div>
            {/each}
          </div>
          <p class="updated-note">策略更新时间：{dateLabel(data.policy.updated_at)}</p>
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
    grid-template-columns: minmax(18rem, 1.1fr) minmax(18rem, 0.9fr);
    gap: 1.5rem;
    margin-top: 1.5rem;
  }

  .form-stack {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .policy-option {
    display: flex;
    align-items: flex-start;
    gap: 0.65rem;
    color: var(--foreground);
    font-size: 0.8125rem;
  }

  .policy-option input {
    width: 1rem;
    height: 1rem;
    margin-top: 0.1rem;
    accent-color: var(--primary);
  }

  .policy-option span {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
  }

  .policy-option small {
    color: var(--muted-foreground);
    font-size: 0.75rem;
    line-height: 1.45;
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
  }

  .field > label {
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

  .field-help.notice-error {
    border-radius: 0.4rem;
    padding: 0.45rem 0.55rem;
  }

  .revision-note {
    display: grid;
    grid-template-columns: auto auto;
    gap: 0.2rem 0.5rem;
    border-radius: 0.6rem;
    background: var(--muted);
    padding: 0.7rem 0.8rem;
    color: var(--muted-foreground);
    font-size: 0.75rem;
  }

  .revision-note strong {
    color: var(--foreground);
  }

  .revision-note small {
    grid-column: 1 / -1;
    line-height: 1.45;
  }

  .provider-list {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .provider-row {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 0.75rem;
    border-bottom: 1px solid var(--border);
    padding-bottom: 0.75rem;
  }

  .provider-row:last-child {
    border-bottom: 0;
    padding-bottom: 0;
  }

  .provider-row strong {
    font-size: 0.8125rem;
  }

  .provider-row p {
    max-width: 28rem;
    margin: 0.25rem 0 0;
    overflow-wrap: anywhere;
    color: var(--muted-foreground);
    font-size: 0.75rem;
    line-height: 1.45;
  }

  .updated-note {
    margin: 1rem 0 0;
    color: var(--muted-foreground);
    font-size: 0.75rem;
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
    max-width: 36rem;
    margin-bottom: 0;
    color: var(--muted-foreground);
    font-size: 0.8125rem;
    line-height: 1.6;
  }

  .empty-state.notice-error p {
    color: var(--destructive);
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
  }
</style>
