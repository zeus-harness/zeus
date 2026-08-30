<script lang="ts">
  import type { ActionData, PageData } from './$types';

  let { data, form } = $props<{ data: PageData; form: ActionData }>();
  let values = $derived(form?.type === 'error' ? form.values : undefined);
</script>

<svelte:head>
  <title>Zeus · 初始设置</title>
</svelte:head>

<main class="mx-auto min-h-screen max-w-3xl px-5 py-10 lg:px-8 lg:py-16">
  <div class="mb-8">
    <p class="text-xs font-semibold uppercase tracking-[0.14em] text-muted-foreground">Zeus identity</p>
    <h1 class="mt-3 text-3xl font-semibold tracking-tight sm:text-4xl">完成初始设置</h1>
    <p class="mt-3 max-w-2xl text-sm leading-6 text-muted-foreground">
      创建第一个平台管理员、组织和 Workspace。完成后会建立当前 Session，并前往邮箱验证步骤。
    </p>
  </div>

  {#if form?.type === 'error'}
    <div class="mb-6 rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive" role="alert">
      {form.message}
    </div>
  {/if}

  {#if data.setupStatus.status === 'ready' && !data.setupStatus.data.setup_required}
    <section class="rounded-xl border border-border bg-card p-6 shadow-xs" role="status">
      <h2 class="text-lg font-semibold">初始设置已完成</h2>
      <p class="mt-2 text-sm leading-6 text-muted-foreground">
        这个 Zeus 实例已经完成初始化。请使用登录入口继续。
      </p>
      <a class="mt-5 inline-flex rounded-md border border-border px-4 py-2 text-sm font-medium hover:bg-accent" href="/login">
        前往登录
      </a>
    </section>
  {:else}
    {#if data.setupStatus.status === 'unavailable'}
      <div class="mb-6 rounded-xl border border-border bg-muted/40 p-4 text-sm text-muted-foreground" role="status" aria-live="polite">
        {data.setupStatus.message}
        {#if data.setupStatus.httpStatus}
          <span class="ml-1 font-mono text-xs">HTTP {data.setupStatus.httpStatus}</span>
        {/if}
      </div>
    {:else if !data.setupStatus.data.bootstrap_token_configured}
      <div class="mb-6 rounded-xl border border-border bg-muted/40 p-4 text-sm text-muted-foreground" role="status" aria-live="polite">
        服务端尚未配置 Bootstrap token。提交前请先完成服务端配置。
      </div>
    {/if}

    <form method="POST" class="space-y-8 rounded-xl border border-border bg-card p-6 shadow-xs sm:p-8">
      <section class="space-y-5" aria-labelledby="account-heading">
        <div>
          <h2 id="account-heading" class="text-lg font-semibold">管理员账号</h2>
          <p class="mt-1 text-sm text-muted-foreground">这个账号会获得平台管理员权限。</p>
        </div>

        <div class="grid gap-5 sm:grid-cols-2">
          <div class="sm:col-span-2">
            <label class="text-sm font-medium" for="bootstrap_token">Bootstrap token</label>
            <input
              id="bootstrap_token"
              name="bootstrap_token"
              type="password"
              autocomplete="off"
              required
              class="mt-2 h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
            />
          </div>

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

          <div class="sm:col-span-2">
            <label class="text-sm font-medium" for="password">Password</label>
            <input
              id="password"
              name="password"
              type="password"
              autocomplete="new-password"
              minlength="15"
              aria-describedby="password-hint"
              required
              class="mt-2 h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
            />
            <p id="password-hint" class="mt-2 text-xs text-muted-foreground">至少 15 个字符。出于安全原因，提交失败后不会回显密码。</p>
          </div>
        </div>
      </section>

      <section class="space-y-5 border-t border-border pt-8" aria-labelledby="tenant-heading">
        <div>
          <h2 id="tenant-heading" class="text-lg font-semibold">组织与 Workspace</h2>
          <p class="mt-1 text-sm text-muted-foreground">为第一个平台管理员创建默认租户上下文。</p>
        </div>

        <div class="grid gap-5 sm:grid-cols-2">
          <div>
            <label class="text-sm font-medium" for="organization_slug">Organization slug</label>
            <input
              id="organization_slug"
              name="organization_slug"
              type="text"
              autocomplete="off"
              value={values?.organization_slug ?? ''}
              required
              class="mt-2 h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
            />
          </div>

          <div>
            <label class="text-sm font-medium" for="organization_name">Organization name</label>
            <input
              id="organization_name"
              name="organization_name"
              type="text"
              value={values?.organization_name ?? ''}
              required
              class="mt-2 h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
            />
          </div>

          <div>
            <label class="text-sm font-medium" for="workspace_slug">Workspace slug</label>
            <input
              id="workspace_slug"
              name="workspace_slug"
              type="text"
              autocomplete="off"
              value={values?.workspace_slug ?? ''}
              required
              class="mt-2 h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
            />
          </div>

          <div>
            <label class="text-sm font-medium" for="workspace_name">Workspace name</label>
            <input
              id="workspace_name"
              name="workspace_name"
              type="text"
              value={values?.workspace_name ?? ''}
              required
              class="mt-2 h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
            />
          </div>
        </div>
      </section>

      <div class="flex flex-wrap items-center justify-between gap-4 border-t border-border pt-6">
        <p class="max-w-md text-xs leading-5 text-muted-foreground">Bootstrap token 和密码只会提交给 Zeus API，不会在错误页面中回显。</p>
        <button type="submit" class="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90">
          完成初始设置
        </button>
      </div>
    </form>
  {/if}
</main>
