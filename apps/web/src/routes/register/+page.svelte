<script lang="ts">
  import type { ActionData, PageData } from './$types';

  let { data, form } = $props<{ data: PageData; form: ActionData }>();
  let values = $derived(form?.values);
</script>

<svelte:head>
  <title>Zeus · 注册</title>
</svelte:head>

<main class="mx-auto flex min-h-screen max-w-xl items-center px-5 py-10 lg:px-8">
  <section class="w-full rounded-xl border border-border bg-card p-6 shadow-xs sm:p-8">
    <p class="text-xs font-semibold uppercase tracking-[0.14em] text-muted-foreground">Zeus identity</p>
    <h1 class="mt-3 text-3xl font-semibold tracking-tight">注册</h1>
    <p class="mt-3 text-sm leading-6 text-muted-foreground">
      创建一个 Zeus 原生账号。注册后请检查邮箱完成验证。
    </p>

    {#if form?.type === 'success'}
      <div class="mt-6 rounded-xl border border-border bg-muted/40 p-4 text-sm leading-6" role="status" aria-live="polite">
        {form.message}
        <a class="mt-3 inline-block font-medium text-foreground hover:underline" href="/verify-email">前往邮箱验证</a>
      </div>
    {:else if form?.type === 'error'}
      <div class="mt-6 rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive" role="alert">
        {form.message}
      </div>
    {/if}

    {#if data.invitationPresent}
      <div class="mt-6 rounded-xl border border-border bg-muted/40 p-4 text-sm text-muted-foreground" role="status">
        已识别邀请链接，提交时会由服务端安全处理邀请信息。
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
          value={values?.email ?? ''}
          required
          class="mt-2 h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
        />
      </div>

      <div>
        <label class="text-sm font-medium" for="display_name">Display name</label>
        <input
          id="display_name"
          name="display_name"
          type="text"
          autocomplete="name"
          value={values?.display_name ?? ''}
          required
          class="mt-2 h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
        />
      </div>

      <div>
        <label class="text-sm font-medium" for="password">Password</label>
        <input
          id="password"
          name="password"
          type="password"
          autocomplete="new-password"
          minlength="15"
          required
          class="mt-2 h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
        />
        <p class="mt-2 text-xs leading-5 text-muted-foreground">至少 15 个字符。提交失败后不会回显密码。</p>
      </div>

      <button type="submit" class="w-full rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90">
        创建账号
      </button>
    </form>

    <p class="mt-6 text-center text-sm text-muted-foreground">
      已有账号？ <a class="font-medium text-foreground hover:underline" href="/login">返回登录</a>
    </p>
  </section>
</main>
