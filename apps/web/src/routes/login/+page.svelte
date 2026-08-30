<script lang="ts">
  import { page } from '$app/state';

  import type { ActionData } from './$types';

  let { form } = $props<{ form: ActionData }>();
  let notice = $derived(
    page.url.searchParams.has('verified')
      ? '邮箱已验证，请使用账号登录。'
      : page.url.searchParams.has('reset')
        ? '密码已重置，请使用新密码登录。'
        : null
  );
  let email = $derived(form?.type === 'error' ? form.values.email : '');
</script>

<svelte:head>
  <title>Zeus · 登录</title>
</svelte:head>

<main class="mx-auto flex min-h-screen max-w-xl items-center px-5 py-10 lg:px-8">
  <section class="w-full rounded-xl border border-border bg-card p-6 shadow-xs sm:p-8">
    <p class="text-xs font-semibold uppercase tracking-[0.14em] text-muted-foreground">Zeus identity</p>
    <h1 class="mt-3 text-3xl font-semibold tracking-tight">登录</h1>
    <p class="mt-3 text-sm leading-6 text-muted-foreground">使用你的 Zeus 原生账号继续工作。</p>

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

    <form method="POST" class="mt-6 space-y-5">
      <div>
        <label class="text-sm font-medium" for="email">Email</label>
        <input
          id="email"
          name="email"
          type="email"
          autocomplete="email"
          value={email}
          required
          class="mt-2 h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
        />
      </div>

      <div>
        <div class="flex items-center justify-between gap-3">
          <label class="text-sm font-medium" for="password">Password</label>
          <a class="text-xs text-muted-foreground hover:text-foreground hover:underline" href="/forgot-password">忘记密码？</a>
        </div>
        <input
          id="password"
          name="password"
          type="password"
          autocomplete="current-password"
          required
          class="mt-2 h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
        />
      </div>

      <button type="submit" class="w-full rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90">
        登录
      </button>
    </form>

    <p class="mt-6 text-center text-sm text-muted-foreground">
      还没有账号？ <a class="font-medium text-foreground hover:underline" href="/register">注册</a>
    </p>
  </section>
</main>
