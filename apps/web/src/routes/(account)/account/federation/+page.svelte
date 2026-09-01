<script lang="ts">
  import { page } from '$app/state';

  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';

  import type { ActionData, PageData } from './$types';

  let { data, form } = $props<{ data: PageData; form: ActionData }>();
  let linkedNotice = $derived(
    page.url.searchParams.has('linked') ? '外部身份和 Organization 信任已建立。' : null
  );

  function dateLabel(value: string | null | undefined): string {
    return value
      ? value.replace('T', ' ').replace(/\.\d+Z$/, ' UTC').replace('Z', ' UTC')
      : '未提供';
  }

  function shortId(value: string): string {
    return value.length > 18 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value;
  }

  function activeBindingCount(bindings: PageData['identities'][number]['organization_bindings']) {
    return bindings.filter((binding) => binding.status === 'active').length;
  }
</script>

<svelte:head>
  <title>Zeus · 外部身份</title>
</svelte:head>

<main class="mx-auto max-w-[1100px] px-5 py-8 lg:px-8 lg:py-10">
  <div>
    <p class="text-sm font-medium text-muted-foreground">Account</p>
    <h1 class="mt-2 text-3xl font-semibold tracking-tight">外部身份</h1>
    <p class="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
      一个外部账号只绑定一个 Zeus 用户。每个 Organization 单独保存对该身份的信任。
    </p>
  </div>

  <div class="mt-8 space-y-6">
    {#if linkedNotice}
      <div class="rounded-xl border border-border bg-muted/40 p-4 text-sm" role="status" aria-live="polite">
        {linkedNotice}
      </div>
    {/if}

    {#if form?.type === 'error'}
      <div class="rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive" role="alert">
        {form.message}
      </div>
    {:else if form?.type === 'success'}
      <div class="rounded-xl border border-border bg-muted/40 p-4 text-sm" role="status" aria-live="polite">
        {form.message}
      </div>
    {/if}

    {#if data.loadError}
      <div class="rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive" role="alert">
        {data.loadError}
      </div>
    {/if}

    <Card.Root>
      <Card.Header>
        <Card.Title>已连接的外部账号</Card.Title>
        <Card.Description>先解除所有 Organization 信任，才能撤销全局外部身份。</Card.Description>
      </Card.Header>
      <Card.Content>
        {#if data.identities.length === 0}
          <div class="py-6 text-center">
            <h2 class="font-medium">还没有连接外部身份</h2>
            <p class="mt-2 text-sm text-muted-foreground">从下面的企业登录配置中选择一个 Provider。</p>
          </div>
        {:else}
          <div class="space-y-5">
            {#each data.identities as identity (identity.identity_id)}
              <section class="rounded-xl border border-border p-4">
                <div class="flex flex-wrap items-start justify-between gap-4">
                  <div class="min-w-0">
                    <div class="flex flex-wrap items-center gap-2">
                      <h2 class="break-all font-medium">{identity.issuer}</h2>
                      <Badge variant={identity.status === 'active' ? 'secondary' : 'outline'}>
                        {identity.status === 'active' ? '可用' : '已撤销'}
                      </Badge>
                    </div>
                    <p class="mt-2 text-sm text-muted-foreground">Subject {shortId(identity.subject)}</p>
                    <p class="mt-1 text-xs text-muted-foreground">最近登录 {dateLabel(identity.last_login_at)}</p>
                  </div>
                  <form method="POST" action="?/revokeIdentity">
                    <input type="hidden" name="identity_id" value={identity.identity_id} />
                    <Button
                      type="submit"
                      variant="destructive"
                      size="sm"
                      disabled={identity.status !== 'active' || activeBindingCount(identity.organization_bindings) > 0}
                    >
                      撤销外部身份
                    </Button>
                  </form>
                </div>

                <div class="mt-4 border-t border-border pt-4">
                  <h3 class="text-sm font-medium">Organization 信任</h3>
                  {#if identity.organization_bindings.length === 0}
                    <p class="mt-2 text-sm text-muted-foreground">当前没有 Organization 信任此身份。</p>
                  {:else}
                    <div class="mt-3 divide-y divide-border">
                      {#each identity.organization_bindings as binding (binding.binding_id)}
                        <div class="flex flex-wrap items-center justify-between gap-3 py-3 first:pt-0 last:pb-0">
                          <div>
                            <div class="flex flex-wrap items-center gap-2">
                              <span class="text-sm font-medium">{binding.organization_name}</span>
                              <Badge variant="outline">{binding.provider_slug}</Badge>
                              <Badge variant={binding.status === 'active' ? 'secondary' : 'outline'}>
                                {binding.status === 'active' ? '已信任' : '已解除'}
                              </Badge>
                            </div>
                            <p class="mt-1 text-xs text-muted-foreground">
                              最近登录 {dateLabel(binding.last_login_at)} · 来源 {binding.binding_source}
                            </p>
                          </div>
                          {#if binding.status === 'active'}
                            <form method="POST" action="?/unlinkBinding">
                              <input type="hidden" name="identity_id" value={identity.identity_id} />
                              <input type="hidden" name="binding_id" value={binding.binding_id} />
                              <Button type="submit" variant="outline" size="sm">解除信任</Button>
                            </form>
                          {/if}
                        </div>
                      {/each}
                    </div>
                  {/if}
                </div>
              </section>
            {/each}
          </div>
        {/if}
      </Card.Content>
    </Card.Root>

    <Card.Root>
      <Card.Header>
        <Card.Title>连接企业身份</Card.Title>
        <Card.Description>这里只列出你已加入的 Organization 所启用的 Provider。</Card.Description>
      </Card.Header>
      <Card.Content>
        {#if data.providers.length === 0}
          <div class="py-6 text-center">
            <h2 class="font-medium">没有可用的企业登录配置</h2>
            <p class="mt-2 text-sm text-muted-foreground">请联系 Organization Owner 配置身份提供商。</p>
          </div>
        {:else}
          <div class="space-y-3">
            {#each data.providers as provider (provider.provider_id)}
              <div class="flex flex-wrap items-center justify-between gap-4 rounded-lg border border-border p-4">
                <div class="min-w-0">
                  <div class="flex flex-wrap items-center gap-2">
                    <h2 class="font-medium">{provider.organization_name}</h2>
                    <Badge variant="secondary">{provider.provider_slug}</Badge>
                  </div>
                  <p class="mt-2 break-all text-sm text-muted-foreground">{provider.issuer}</p>
                </div>
                <form method="POST" action="?/link">
                  <input type="hidden" name="provider_id" value={provider.provider_id} />
                  <Button type="submit" size="sm">连接</Button>
                </form>
              </div>
            {/each}
          </div>
        {/if}
      </Card.Content>
    </Card.Root>
  </div>
</main>
