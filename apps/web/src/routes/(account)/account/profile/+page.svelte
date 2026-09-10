<script lang="ts">
  import { Badge } from '@zeus/ui/components/ui/badge';
  import * as Card from '@zeus/ui/components/ui/card';

  import type { PageData } from './$types';

  let { data } = $props<{ data: PageData }>();
  let principal = $derived(data.principal);

  function dateLabel(value: string | null | undefined): string {
    return value ? value.replace('T', ' ').replace(/\.\d+Z$/, ' UTC').replace('Z', ' UTC') : '未提供';
  }

  function methodLabel(method: string): string {
    if (method === 'password') return '密码';
    if (method === 'totp') return 'TOTP';
    if (method === 'recovery_code') return '恢复码';
    return method;
  }

</script>

<svelte:head>
  <title>Zeus · 个人资料</title>
</svelte:head>

<main class="mx-auto max-w-[1100px] px-5 py-8 lg:px-8 lg:py-10">
  <div>
    <p class="text-sm font-medium text-muted-foreground">Account</p>
    <h1 class="mt-2 text-3xl font-semibold tracking-tight">账号设置</h1>
    <p class="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
      管理你的 Zeus 身份、安全设置和活动登录会话。
    </p>
  </div>

  <div class="mt-8">
    {#if data.status !== 'ready' || !principal}
      <div class="rounded-xl border border-destructive/40 bg-destructive/10 p-5 text-sm text-destructive" role="alert">
        暂时无法读取当前账号信息，请稍后重试。
      </div>
    {:else}
      <div class="space-y-6">
        <Card.Root>
          <Card.Header>
            <Card.Title>个人资料</Card.Title>
            <Card.Description>这些信息来自当前登录身份。</Card.Description>
          </Card.Header>
          <Card.Content>
            <dl class="grid gap-x-6 gap-y-5 sm:grid-cols-2">
              <div>
                <dt class="text-xs font-medium uppercase tracking-wide text-muted-foreground">显示名称</dt>
                <dd class="mt-1 text-sm">{principal.display_name}</dd>
              </div>
              <div>
                <dt class="text-xs font-medium uppercase tracking-wide text-muted-foreground">Email</dt>
                <dd class="mt-1 break-all text-sm">{principal.email ?? '未提供'}</dd>
              </div>
              <div>
                <dt class="text-xs font-medium uppercase tracking-wide text-muted-foreground">邮箱状态</dt>
                <dd class="mt-1">
                  {#if principal.email_verified_at}
                    <div class="flex flex-wrap items-center gap-2">
                      <Badge variant="secondary">已验证</Badge>
                      <span class="text-xs text-muted-foreground">{dateLabel(principal.email_verified_at)}</span>
                    </div>
                  {:else}
                    <Badge variant="destructive">未验证</Badge>
                  {/if}
                </dd>
              </div>
              <div>
                <dt class="text-xs font-medium uppercase tracking-wide text-muted-foreground">平台角色</dt>
                <dd class="mt-1 flex flex-wrap gap-1">
                  {#if principal.platform_roles.length > 0}
                    {#each principal.platform_roles as role (role)}
                      <Badge variant="outline">{role}</Badge>
                    {/each}
                  {:else}
                    <span class="text-sm text-muted-foreground">无</span>
                  {/if}
                </dd>
              </div>
            </dl>
          </Card.Content>
        </Card.Root>

        <Card.Root>
          <Card.Header>
            <Card.Title>认证方式</Card.Title>
            <Card.Description>当前身份可用的登录与多因素认证方式。</Card.Description>
          </Card.Header>
          <Card.Content>
            {#if principal.auth_methods.length > 0}
              <div class="flex flex-wrap gap-2">
                {#each principal.auth_methods as method (method)}
                  <Badge variant="outline">{methodLabel(method)}</Badge>
                {/each}
              </div>
            {:else}
              <p class="text-sm text-muted-foreground">当前没有可显示的认证方式。</p>
            {/if}
          </Card.Content>
        </Card.Root>

        <Card.Root>
          <Card.Header>
            <Card.Title>当前会话</Card.Title>
            <Card.Description>时间均以 UTC 显示。</Card.Description>
          </Card.Header>
          <Card.Content>
            <dl class="grid gap-x-6 gap-y-5 sm:grid-cols-2">
              <div>
                <dt class="text-xs font-medium uppercase tracking-wide text-muted-foreground">MFA 验证时间</dt>
                <dd class="mt-1 text-sm">{dateLabel(principal.mfa_satisfied_at)}</dd>
              </div>
              <div>
                <dt class="text-xs font-medium uppercase tracking-wide text-muted-foreground">闲置过期时间</dt>
                <dd class="mt-1 text-sm">{dateLabel(principal.idle_expires_at)}</dd>
              </div>
              <div>
                <dt class="text-xs font-medium uppercase tracking-wide text-muted-foreground">绝对过期时间</dt>
                <dd class="mt-1 text-sm">{dateLabel(principal.absolute_expires_at)}</dd>
              </div>
            </dl>
          </Card.Content>
        </Card.Root>
      </div>
    {/if}
  </div>
</main>
