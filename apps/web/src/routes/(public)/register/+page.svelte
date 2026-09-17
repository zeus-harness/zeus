<script lang="ts">
  import { Button } from '@zeus/ui/components/ui/button';
  import { Input } from '@zeus/ui/components/ui/input';

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
      自主注册会创建属于你的组织和默认工作空间，验证邮箱后即可使用；通过邀请注册则自动加入邀请指定的组织。
    </p>

    {#if form?.type === 'success'}
      <div class="mt-6 rounded-xl border border-border bg-muted/40 p-4 text-sm leading-6" role="status" aria-live="polite">
        {#if data.invitationPresent}
          邀请注册请求已提交。新账号注册成功后已加入受邀组织，可直接登录；已有账号请登录后接受邀请。
          <a class="mt-3 inline-block font-medium text-foreground hover:underline" href="/login">前往登录</a>
        {:else}
          {form.message}
          <p class="mt-2">请按邮件指引验证邮箱，随后登录你的组织；若已有账号，请直接登录。</p>
          <a class="mt-3 inline-block font-medium text-foreground hover:underline" href="/verify-email">前往邮箱验证</a>
        {/if}
      </div>
    {:else if form?.type === 'error'}
      <div class="mt-6 rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive" role="alert">
        {form.message}
      </div>
    {/if}

    {#if data.invitationPresent}
      <div class="mt-6 rounded-xl border border-border bg-muted/40 p-4 text-sm text-muted-foreground" role="status">
        已识别邀请链接，注册后自动加入受邀组织。
        {#if data.joinHref}<a class="ml-2 underline" href={data.joinHref}>已有账号？登录并接受邀请</a>{/if}
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
          value={values?.email ?? ''}
          required
          class="mt-2"
        />
      </div>

      <div>
        <label class="text-sm font-medium" for="display_name">Display name</label>
        <Input
          id="display_name"
          name="display_name"
          type="text"
          autocomplete="name"
          value={values?.display_name ?? ''}
          required
          class="mt-2"
        />
      </div>

      <div>
        <label class="text-sm font-medium" for="password">Password</label>
        <Input
          id="password"
          name="password"
          type="password"
          autocomplete="new-password"
          minlength={15}
          required
          class="mt-2"
        />
        <p class="mt-2 text-xs leading-5 text-muted-foreground">至少 15 个字符。提交失败后不会回显密码。</p>
      </div>

      <Button type="submit" class="w-full" size="lg">
        创建账号
      </Button>
    </form>

    <p class="mt-6 text-center text-sm text-muted-foreground">
      已有账号？ <a class="font-medium text-foreground hover:underline" href="/login">返回登录</a>
    </p>
  </section>
</main>
