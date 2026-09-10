<script lang="ts">
  import { Button } from '@zeus/ui/components/ui/button';
  import { Input } from '@zeus/ui/components/ui/input';

  import type { ActionData, PageData } from './$types';

  let { data, form } = $props<{ data: PageData; form: ActionData }>();
</script>

<svelte:head>
  <title>Zeus · 多因素验证</title>
</svelte:head>

<main class="mx-auto flex min-h-screen max-w-xl items-center px-5 py-10 lg:px-8">
  <section class="w-full rounded-xl border border-border bg-card p-6 shadow-xs sm:p-8">
    <p class="text-xs font-semibold uppercase tracking-[0.14em] text-muted-foreground">Zeus identity</p>
    <h1 class="mt-3 text-3xl font-semibold tracking-tight">多因素验证</h1>
    <p class="mt-3 text-sm leading-6 text-muted-foreground">
      登录需要额外验证。请输入身份验证器中的验证码，也可以使用一个未使用的恢复码。
    </p>

    {#if form?.type === 'error'}
      <div class="mt-6 rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive" role="alert">
        {form.message}
      </div>
    {/if}

    <form method="POST" class="mt-6 space-y-5">
      <div>
        <label class="text-sm font-medium" for="code">验证码或恢复码</label>
        <Input
          id="code"
          name="code"
          type="text"
          inputmode="numeric"
          autocomplete="one-time-code"
          spellcheck="false"
          required
          class="mt-2 text-center font-mono tracking-[0.2em]"
        />
      </div>

      <Button type="submit" class="w-full" size="lg">
        完成验证
      </Button>
    </form>

    <p class="mt-6 text-center text-sm text-muted-foreground">
      <a class="font-medium text-foreground hover:underline" href={`/login?return_to=${encodeURIComponent(data.return_to)}`}>返回登录</a>
    </p>
  </section>
</main>
