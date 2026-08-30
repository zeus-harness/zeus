<script lang="ts">
  import type { ActionData, PageData } from './$types';

  let { data, form } = $props<{ data: PageData; form: ActionData }>();
</script>

<svelte:head>
  <title>Zeus · 重置密码</title>
</svelte:head>

<main class="mx-auto flex min-h-screen max-w-xl items-center px-5 py-10 lg:px-8">
  <section class="w-full rounded-xl border border-border bg-card p-6 shadow-xs sm:p-8">
    <p class="text-xs font-semibold uppercase tracking-[0.14em] text-muted-foreground">Zeus identity</p>
    <h1 class="mt-3 text-3xl font-semibold tracking-tight">重置密码</h1>
    <p class="mt-3 text-sm leading-6 text-muted-foreground">设置一个新的 Zeus 登录密码。</p>

    {#if form?.type === 'error'}
      <div class="mt-6 rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive" role="alert">
        {form.message}
      </div>
    {/if}

    {#if data.tokenPresent}
      <form method="POST" class="mt-6 space-y-5">
        <div>
          <label class="text-sm font-medium" for="password">New password</label>
          <input
            id="password"
            name="password"
            type="password"
            autocomplete="new-password"
            minlength="15"
            required
            class="mt-2 h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
          />
        </div>

        <div>
          <label class="text-sm font-medium" for="password_confirmation">Confirm password</label>
          <input
            id="password_confirmation"
            name="password_confirmation"
            type="password"
            autocomplete="new-password"
            minlength="15"
            required
            class="mt-2 h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
          />
        </div>

        <button type="submit" class="w-full rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90">
          重置密码
        </button>
      </form>
    {:else}
      <div class="mt-6 rounded-xl border border-border bg-muted/40 p-4 text-sm text-muted-foreground" role="status">
        当前地址没有重置 token。请从邮件中的完整链接打开此页面。
      </div>
    {/if}

    <p class="mt-6 text-center text-sm text-muted-foreground">
      <a class="font-medium text-foreground hover:underline" href="/login">返回登录</a>
    </p>
  </section>
</main>
