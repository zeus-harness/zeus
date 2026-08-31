<script lang="ts">
  import { page } from '$app/state';

  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';
  import { Input } from '@zeus/ui/components/ui/input';

  import type { ActionData } from './$types';

  let { form } = $props<{ form: ActionData }>();
  let federatedError = $derived(page.url.searchParams.get('error'));
  let notice = $derived(
    page.url.searchParams.has('verified')
      ? '邮箱已验证，请使用账号登录。'
      : page.url.searchParams.has('reset')
        ? '密码已重置，请使用新密码登录。'
        : federatedError === 'account_link_required'
          ? '该企业邮箱已经对应一个 Zeus 账号。请先用原生账号登录，再到“联合身份”页显式绑定。'
          : federatedError === 'federated_not_allowed'
            ? '当前企业身份不符合该组织的加入规则。请联系组织管理员确认邀请、域名或 Group Mapping。'
            : null
  );
  let email = $derived(form?.type === 'error' && 'email' in form.values ? form.values.email : '');
  let organizationSlug = $derived(
    form?.type === 'error' && 'organization_slug' in form.values ? form.values.organization_slug : ''
  );
  let providerSlug = $derived(
    form?.type === 'error' && 'provider_slug' in form.values ? form.values.provider_slug : ''
  );
</script>

<svelte:head>
  <title>Zeus · 登录</title>
</svelte:head>

<main class="mx-auto flex min-h-screen max-w-xl items-center px-5 py-10 lg:px-8">
  <section class="w-full">
    <p class="text-xs font-semibold uppercase tracking-[0.14em] text-muted-foreground">Zeus identity</p>
    <h1 class="mt-3 text-3xl font-semibold tracking-tight">登录</h1>
    <p class="mt-3 text-sm leading-6 text-muted-foreground">使用 Zeus 原生账号或企业身份继续工作。</p>

    {#if notice}
      <div class="mt-6 rounded-xl border border-border bg-muted/40 p-4 text-sm" role="status" aria-live="polite">
        {notice}
      </div>
    {/if}

    {#if form?.type === 'error'}
      <div class="mt-6 rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive" role="alert">
        {form.message}
      </div>
    {/if}

    <div class="mt-6 space-y-6">
      <Card.Root>
        <Card.Header>
          <Card.Title>Zeus 原生账号</Card.Title>
          <Card.Description>使用邮箱和密码登录你的 Zeus 账号。</Card.Description>
        </Card.Header>
        <Card.Content>
          <form method="POST" class="space-y-5">
            <div>
              <label class="text-sm font-medium" for="email">Email</label>
              <Input
                id="email"
                name="email"
                type="email"
                autocomplete="email"
                value={email}
                required
                class="mt-2"
              />
            </div>

            <div>
              <div class="flex items-center justify-between gap-3">
                <label class="text-sm font-medium" for="password">Password</label>
                <a class="text-xs text-muted-foreground hover:text-foreground hover:underline" href="/forgot-password">忘记密码？</a>
              </div>
              <Input
                id="password"
                name="password"
                type="password"
                autocomplete="current-password"
                required
                class="mt-2"
              />
            </div>

            <Button type="submit" class="w-full" size="lg">登录</Button>
          </form>
        </Card.Content>
        <Card.Footer class="justify-center">
          <p class="text-sm text-muted-foreground">
            还没有账号？ <a class="font-medium text-foreground hover:underline" href="/register">注册</a>
          </p>
        </Card.Footer>
      </Card.Root>

      <div class="flex items-center gap-3 text-xs uppercase tracking-[0.14em] text-muted-foreground" aria-hidden="true">
        <div class="h-px flex-1 bg-border"></div>
        <span>或</span>
        <div class="h-px flex-1 bg-border"></div>
      </div>

      <Card.Root>
        <Card.Header>
          <Card.Title>企业登录</Card.Title>
          <Card.Description>输入组织和身份提供商的 slug，前往企业单点登录。</Card.Description>
        </Card.Header>
        <Card.Content>
          <form method="POST" action="?/federated" class="space-y-5">
            <div>
              <label class="text-sm font-medium" for="organization_slug">Organization slug</label>
              <Input
                id="organization_slug"
                name="organization_slug"
                type="text"
                autocomplete="organization"
                minlength={3}
                maxlength={63}
                pattern={'[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])'}
                title="使用 3-63 个小写字母、数字或内部连字符"
                value={organizationSlug}
                required
                class="mt-2"
              />
            </div>

            <div>
              <label class="text-sm font-medium" for="provider_slug">Provider slug</label>
              <Input
                id="provider_slug"
                name="provider_slug"
                type="text"
                autocomplete="off"
                minlength={3}
                maxlength={63}
                pattern={'[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])'}
                title="使用 3-63 个小写字母、数字或内部连字符"
                value={providerSlug}
                required
                class="mt-2"
              />
              <p class="mt-2 text-xs leading-5 text-muted-foreground">slug 只能使用小写字母、数字和内部连字符。</p>
            </div>

            <Button type="submit" variant="outline" class="w-full" size="lg">使用企业身份登录</Button>
          </form>
        </Card.Content>
      </Card.Root>
    </div>
  </section>
</main>
