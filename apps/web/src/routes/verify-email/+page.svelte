<script lang="ts">
  import { page } from '$app/state';

  import type { ActionData, PageData } from './$types';

  let { data, form } = $props<{ data: PageData; form: ActionData }>();
  let email = $derived(form?.values?.email ?? '');
  let confirmAction = $derived(
    `?/confirm&token=${encodeURIComponent(page.url.searchParams.get('token') ?? '')}`
  );
</script>

<svelte:head>
  <title>Zeus · 验证邮箱</title>
</svelte:head>

<main class="mx-auto flex min-h-screen max-w-xl items-center px-5 py-10 lg:px-8">
  <section class="w-full rounded-xl border border-border bg-card p-6 shadow-xs sm:p-8">
    <p class="text-xs font-semibold uppercase tracking-[0.14em] text-muted-foreground">Zeus identity</p>
    <h1 class="mt-3 text-3xl font-semibold tracking-tight">验证邮箱</h1>
    <p class="mt-3 text-sm leading-6 text-muted-foreground">
      请检查注册邮箱中的验证链接。验证成功后即可使用原生账号登录。
    </p>

    {#if form?.type === 'success'}
      <div class="mt-6 rounded-xl border border-border bg-muted/40 p-4 text-sm leading-6" role="status" aria-live="polite">
        {form.message}
      </div>
    {:else if form?.type === 'error'}
      <div class="mt-6 rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive" role="alert">
        {form.message}
      </div>
    {/if}

    {#if data.tokenPresent}
      <form method="POST" action={confirmAction} class="mt-6">
        <button type="submit" class="w-full rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90">
          确认邮箱
        </button>
      </form>
    {:else}
      <div class="mt-6 rounded-xl border border-border bg-muted/40 p-4 text-sm text-muted-foreground" role="status">
        当前地址没有验证 token。请从邮件中的完整链接打开此页面。
      </div>
    {/if}

    <form method="POST" action="?/resend" class="mt-6 space-y-3 border-t border-border pt-6">
      <div>
        <label class="text-sm font-medium" for="resend-email">Email</label>
        <input
          id="resend-email"
          name="email"
          type="email"
          autocomplete="email"
          value={email}
          required
          class="mt-2 h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
        />
      </div>
      <button type="submit" class="w-full rounded-md border border-border px-4 py-2 text-sm font-medium hover:bg-accent">
        重发验证邮件
      </button>
    </form>

    <p class="mt-6 text-center text-sm text-muted-foreground">
      <a class="font-medium text-foreground hover:underline" href="/login">返回登录</a>
    </p>
  </section>
</main>
