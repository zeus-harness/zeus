<script lang="ts">
  import { Button } from '@zeus/ui/components/ui/button';
  import { Input } from '@zeus/ui/components/ui/input';

  import type { ActionData } from './$types';

  let { form } = $props<{ form: ActionData }>();
  let email = $derived(form?.values?.email ?? '');
</script>

<svelte:head>
  <title>Zeus · 找回密码</title>
</svelte:head>

<main class="mx-auto flex min-h-screen max-w-xl items-center px-5 py-10 lg:px-8">
  <section class="w-full rounded-xl border border-border bg-card p-6 shadow-xs sm:p-8">
    <p class="text-xs font-semibold uppercase tracking-[0.14em] text-muted-foreground">Zeus identity</p>
    <h1 class="mt-3 text-3xl font-semibold tracking-tight">找回密码</h1>
    <p class="mt-3 text-sm leading-6 text-muted-foreground">
      输入账号邮箱，我们会发送下一步指引。为保护账号安全，页面不会确认邮箱是否已注册。
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

    <form method="POST" class="mt-6 space-y-5">
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

      <Button type="submit" class="w-full" size="lg">
        发送找回指引
      </Button>
    </form>

    <p class="mt-6 text-center text-sm text-muted-foreground">
      <a class="font-medium text-foreground hover:underline" href="/login">返回登录</a>
    </p>
  </section>
</main>
