<script lang="ts">
  import { page } from '$app/state';

  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';

  import type { ActionData, PageData } from './$types';

  let { data, form } = $props<{ data: PageData; form: ActionData }>();
  let pathname = $derived(page.url.pathname);
  let linkedNotice = $derived(
    page.url.searchParams.has('linked') ? '企业身份已绑定。' : null
  );

  const accountNavigation = [
    { href: '/account/profile', label: '个人资料', description: '账号身份与会话状态' },
    { href: '/account/security', label: '安全设置', description: '密码与双因素认证' },
    { href: '/account/federation', label: '联合身份', description: '管理企业登录绑定' },
    { href: '/account/sessions', label: '登录会话', description: '查看并撤销活动会话' },
    { href: '/account/authorizations', label: '应用授权', description: '查看并撤销 OIDC 授权' }
  ] as const;

  function navigationClass(href: string): string {
    return pathname === href
      ? 'rounded-lg bg-accent px-3 py-2 text-sm font-medium text-accent-foreground'
      : 'rounded-lg px-3 py-2 text-sm text-muted-foreground hover:bg-accent hover:text-accent-foreground';
  }

  function dateLabel(value: string | null | undefined): string {
    return value ? value.replace('T', ' ').replace(/\.\d+Z$/, ' UTC').replace('Z', ' UTC') : '未提供';
  }

  function shortId(value: string): string {
    return value.length > 18 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value;
  }
</script>

<svelte:head>
  <title>Zeus · 联合身份</title>
</svelte:head>

<main class="mx-auto max-w-[1100px] px-5 py-8 lg:px-8 lg:py-10">
  <div>
    <p class="text-sm font-medium text-muted-foreground">Account</p>
    <h1 class="mt-2 text-3xl font-semibold tracking-tight">联合身份</h1>
    <p class="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
      管理已绑定的企业身份，并从你已加入的组织中选择企业登录方式。
    </p>
  </div>

  <div class="mt-8 grid gap-6 lg:grid-cols-[14rem_minmax(0,1fr)]">
    <aside>
      <nav class="flex flex-col gap-1" aria-label="账号导航">
        {#each accountNavigation as item (item.href)}
          <a
            class={navigationClass(item.href)}
            href={item.href}
            aria-current={pathname === item.href ? 'page' : undefined}
          >
            <span class="block">{item.label}</span>
            <span class="mt-1 block text-xs font-normal text-muted-foreground">{item.description}</span>
          </a>
        {/each}
      </nav>
    </aside>

    <div class="space-y-6">
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

      <Card.Root>
        <Card.Header>
          <Card.Title>已绑定的企业身份</Card.Title>
          <Card.Description>这些身份可以用于企业登录。解绑前请确认你仍保留其他登录方式。</Card.Description>
        </Card.Header>
        <Card.Content>
          {#if data.identityLoadError}
            <div class="rounded-lg border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive" role="alert">
              {data.identityLoadError}
            </div>
          {:else if data.identities.length === 0}
            <div class="py-6 text-center">
              <h2 class="font-medium">还没有绑定企业身份</h2>
              <p class="mt-2 text-sm text-muted-foreground">从下面的企业登录配置中选择一个提供商开始绑定。</p>
            </div>
          {:else}
            <div class="divide-y divide-border">
              {#each data.identities as identity (identity.identity_id)}
                <div class="flex flex-wrap items-start justify-between gap-4 py-4 first:pt-0 last:pb-0">
                  <div class="min-w-0">
                    <div class="flex flex-wrap items-center gap-2">
                      <h2 class="font-medium">{identity.organization_name}</h2>
                      <Badge variant="secondary">{identity.provider_slug}</Badge>
                    </div>
                    <dl class="mt-3 grid gap-x-6 gap-y-2 text-sm text-muted-foreground sm:grid-cols-2">
                      <div>
                        <dt class="text-xs uppercase tracking-wide">绑定时间</dt>
                        <dd class="mt-1">{dateLabel(identity.linked_at)}</dd>
                      </div>
                      <div>
                        <dt class="text-xs uppercase tracking-wide">最近登录</dt>
                        <dd class="mt-1">{dateLabel(identity.last_login_at)}</dd>
                      </div>
                    </dl>
                  </div>
                  <form method="POST" action="?/unlink">
                    <input type="hidden" name="identity_id" value={identity.identity_id} />
                    <Button type="submit" variant="destructive" size="sm">解绑</Button>
                  </form>
                </div>
              {/each}
            </div>
          {/if}
        </Card.Content>
      </Card.Root>

      <Card.Root>
        <Card.Header>
          <Card.Title>绑定企业身份</Card.Title>
          <Card.Description>绑定后会跳转到企业身份提供商完成授权。</Card.Description>
        </Card.Header>
        <Card.Content>
          {#if data.providerLoadError}
            <div class="rounded-lg border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive" role="alert">
              {data.providerLoadError}
            </div>
          {:else if data.providers.length === 0}
            <div class="py-6 text-center">
              <h2 class="font-medium">当前组织没有可用的企业登录配置</h2>
              <p class="mt-2 text-sm text-muted-foreground">请联系组织管理员配置身份提供商。</p>
            </div>
          {:else}
            <div class="space-y-3">
              {#each data.providers as provider (provider.id)}
                <div class="flex flex-wrap items-center justify-between gap-4 rounded-lg border border-border p-4">
                  <div class="min-w-0">
                    <div class="flex flex-wrap items-center gap-2">
                      <h2 class="font-medium">{provider.slug}</h2>
                      {#if provider.enabled}
                        <Badge variant="secondary">可用</Badge>
                      {:else}
                        <Badge variant="outline">已停用</Badge>
                      {/if}
                    </div>
                    <p class="mt-2 break-all text-sm text-muted-foreground">{provider.issuer_url}</p>
                    <p class="mt-1 text-xs text-muted-foreground">Organization {shortId(provider.organization_id)}</p>
                  </div>
                  <form method="POST" action="?/link">
                    <input type="hidden" name="provider_id" value={provider.id} />
                    <Button type="submit" size="sm" disabled={!provider.enabled}>绑定</Button>
                  </form>
                </div>
              {/each}
            </div>
          {/if}
        </Card.Content>
      </Card.Root>
    </div>
  </div>
</main>
