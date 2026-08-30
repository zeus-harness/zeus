<script lang="ts">
  import { page } from '$app/state';

  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';

  import type { ActionData, PageData } from './$types';

  let { data, form } = $props<{ data: PageData; form: ActionData }>();
  let pathname = $derived(page.url.pathname);

  const accountNavigation = [
    { href: '/account/profile', label: '个人资料', description: '账号身份与会话状态' },
    { href: '/account/security', label: '安全设置', description: '密码与双因素认证' },
    { href: '/account/federation', label: '联合身份', description: '管理企业登录绑定' },
    { href: '/account/sessions', label: '登录会话', description: '查看并撤销活动会话' }
  ] as const;

  function navigationClass(href: string): string {
    return pathname === href
      ? 'rounded-lg bg-accent px-3 py-2 text-sm font-medium text-accent-foreground'
      : 'rounded-lg px-3 py-2 text-sm text-muted-foreground hover:bg-accent hover:text-accent-foreground';
  }

  function dateLabel(value: string | null): string {
    return value ? value.replace('T', ' ').replace(/\.\d+Z$/, ' UTC').replace('Z', ' UTC') : '未完成';
  }

  function methodLabel(method: string): string {
    if (method === 'password') return '密码';
    if (method === 'totp') return 'TOTP';
    if (method === 'recovery_code') return '恢复码';
    return method;
  }

  function shortId(value: string): string {
    return value.length > 18 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value;
  }
</script>

<svelte:head>
  <title>Zeus · 登录会话</title>
</svelte:head>

<main class="mx-auto max-w-[1100px] px-5 py-8 lg:px-8 lg:py-10">
  <div>
    <p class="text-sm font-medium text-muted-foreground">Account</p>
    <h1 class="mt-2 text-3xl font-semibold tracking-tight">登录会话</h1>
    <p class="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
      查看当前账号的活动 Web 会话。撤销当前会话后，页面会返回登录入口。
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

    <div>
      {#if form?.type === 'error'}
        <div class="mb-6 rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive" role="alert">
          {form.message}
        </div>
      {:else if form?.type === 'success'}
        <div class="mb-6 rounded-xl border border-border bg-muted/40 p-4 text-sm" role="status" aria-live="polite">
          {form.message}
        </div>
      {/if}

      {#if data.loadError}
        <div class="rounded-xl border border-destructive/40 bg-destructive/10 p-5 text-sm text-destructive" role="alert">
          {data.loadError}
        </div>
      {:else if data.sessions.length === 0}
        <Card.Root>
          <Card.Content>
            <div class="py-8 text-center">
              <h2 class="font-medium">没有活动会话</h2>
              <p class="mt-2 text-sm text-muted-foreground">当前账号没有可显示的登录会话。</p>
            </div>
          </Card.Content>
        </Card.Root>
      {:else}
        <div class="space-y-4">
          {#each data.sessions as session (session.id)}
            <Card.Root>
              <Card.Header>
                <div class="flex flex-wrap items-start justify-between gap-3">
                  <div class="min-w-0">
                    <Card.Title>{session.current ? '当前会话' : '活动会话'}</Card.Title>
                    <Card.Description>
                      <span class="font-mono">{shortId(session.id)}</span>
                      {#if session.active_workspace_id}
                        <span> · Workspace {shortId(session.active_workspace_id)}</span>
                      {:else}
                        <span> · 未选择 Workspace</span>
                      {/if}
                    </Card.Description>
                  </div>
                  {#if session.current}
                    <Badge variant="secondary">Current</Badge>
                  {:else}
                    <Badge variant="outline">Active</Badge>
                  {/if}
                </div>
              </Card.Header>
              <Card.Content>
                <dl class="grid gap-x-6 gap-y-4 text-sm sm:grid-cols-2">
                  <div>
                    <dt class="text-xs font-medium uppercase tracking-wide text-muted-foreground">认证方式</dt>
                    <dd class="mt-2 flex flex-wrap gap-1">
                      {#each session.auth_methods as method (method)}
                        <Badge variant="outline">{methodLabel(method)}</Badge>
                      {/each}
                    </dd>
                  </div>
                  <div>
                    <dt class="text-xs font-medium uppercase tracking-wide text-muted-foreground">最后活动</dt>
                    <dd class="mt-1">{dateLabel(session.last_seen_at)}</dd>
                  </div>
                  <div>
                    <dt class="text-xs font-medium uppercase tracking-wide text-muted-foreground">认证时间</dt>
                    <dd class="mt-1">{dateLabel(session.authenticated_at)}</dd>
                  </div>
                  <div>
                    <dt class="text-xs font-medium uppercase tracking-wide text-muted-foreground">MFA 时间</dt>
                    <dd class="mt-1">{dateLabel(session.mfa_satisfied_at)}</dd>
                  </div>
                  <div>
                    <dt class="text-xs font-medium uppercase tracking-wide text-muted-foreground">闲置过期</dt>
                    <dd class="mt-1">{dateLabel(session.idle_expires_at)}</dd>
                  </div>
                  <div>
                    <dt class="text-xs font-medium uppercase tracking-wide text-muted-foreground">绝对过期</dt>
                    <dd class="mt-1">{dateLabel(session.absolute_expires_at)}</dd>
                  </div>
                </dl>
                <form method="POST" action="?/revoke" class="mt-5">
                  <input type="hidden" name="session_id" value={session.id} />
                  <input type="hidden" name="current" value={session.current ? 'true' : 'false'} />
                  <Button type="submit" variant="destructive" size="sm">
                    {session.current ? '撤销当前会话并退出' : '撤销会话'}
                  </Button>
                </form>
              </Card.Content>
            </Card.Root>
          {/each}
        </div>
      {/if}
    </div>
  </div>
</main>
