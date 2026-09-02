<script lang="ts">
  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';
  import { Input } from '@zeus/ui/components/ui/input';

  import type { ActionData, PageData } from './$types';

  let { data, form } = $props<{ data: PageData; form: ActionData }>();
  let principal = $derived(data.principal);
  let totpEnabled = $derived(principal?.totp_enabled ?? false);
  let hasNativePassword = $derived(principal?.has_native_password ?? false);
  let isPlatformOwner = $derived(principal?.platform_roles.includes('platform_owner') ?? false);
  let returnTo = $derived(
    form?.type === 'totp_setup' || form?.type === 'totp_confirmed'
      ? form.return_to
      : data.return_to
  );

</script>

<svelte:head>
  <title>Zeus · 安全设置</title>
</svelte:head>

<main class="mx-auto max-w-[1100px] px-5 py-8 lg:px-8 lg:py-10">
  <div>
    <p class="text-sm font-medium text-muted-foreground">Account</p>
    <h1 class="mt-2 text-3xl font-semibold tracking-tight">安全设置</h1>
    <p class="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
      更新密码并管理当前账号的 TOTP 双因素认证。
    </p>
  </div>

  <div class="mt-8">
    <div class="space-y-6">
      {#if form?.type === 'error'}
        <div class="rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive" role="alert">
          {form.message}
        </div>
      {:else if form?.type === 'success'}
        <div class="rounded-xl border border-border bg-muted/40 p-4 text-sm" role="status" aria-live="polite">
          {form.message}
        </div>
      {/if}

      {#if form?.type === 'totp_confirmed'}
        <section class="rounded-xl border border-border bg-card p-5 shadow-xs" aria-labelledby="recovery-codes-heading">
          <div>
            <p class="text-xs font-semibold uppercase tracking-[0.12em] text-muted-foreground">Recovery codes</p>
            <h2 id="recovery-codes-heading" class="mt-2 text-lg font-semibold">请保存恢复码</h2>
            <p class="mt-2 text-sm leading-6 text-muted-foreground">
              这些恢复码只在本次设置完成后显示。请将它们保存在密码管理器中，不要与他人分享。
            </p>
          </div>
          <div class="mt-4 grid gap-2 rounded-lg border border-border bg-muted/40 p-4 sm:grid-cols-2">
            {#each form.recovery_codes as recoveryCode (recoveryCode)}
              <code class="font-mono text-sm">{recoveryCode}</code>
            {/each}
          </div>
          {#if returnTo !== '/account/security'}
            <div class="mt-4">
              <Button href={returnTo}>恢复之前的授权流程</Button>
            </div>
          {/if}
        </section>
      {/if}

      <Card.Root>
        <Card.Header>
          <Card.Title>修改密码</Card.Title>
          <Card.Description>
            {hasNativePassword
              ? '输入当前密码后更新。新密码至少需要 15 个 NFC Unicode 字符。'
              : '为当前联合账号设置一个 Zeus 原生密码。新密码至少需要 15 个 NFC Unicode 字符。'}
          </Card.Description>
        </Card.Header>
        <Card.Content>
          <form method="POST" action="?/changePassword" class="space-y-4">
            <div>
              <label class="text-sm font-medium" for="current_password">
                {hasNativePassword ? '当前密码' : '当前密码（首次设置无需填写）'}
              </label>
              <Input
                id="current_password"
                name="current_password"
                type="password"
                autocomplete="current-password"
                required={hasNativePassword}
                class="mt-2"
              />
            </div>
            <div>
              <label class="text-sm font-medium" for="new_password">新密码</label>
              <Input
                id="new_password"
                name="new_password"
                type="password"
                autocomplete="new-password"
                minlength={15}
                required
                class="mt-2"
              />
            </div>
            <div>
              <label class="text-sm font-medium" for="new_password_confirmation">确认新密码</label>
              <Input
                id="new_password_confirmation"
                name="new_password_confirmation"
                type="password"
                autocomplete="new-password"
                minlength={15}
                required
                class="mt-2"
              />
            </div>
            <Button type="submit">更新密码</Button>
          </form>
        </Card.Content>
      </Card.Root>

      <Card.Root>
        <Card.Header>
          <div class="flex flex-wrap items-start justify-between gap-3">
            <div>
              <Card.Title>双因素认证</Card.Title>
              <Card.Description>使用身份验证器应用保护账号。</Card.Description>
            </div>
            {#if totpEnabled}
              <Badge variant="secondary">已启用</Badge>
            {:else}
              <Badge variant="outline">未启用</Badge>
            {/if}
          </div>
        </Card.Header>
        <Card.Content>
          {#if form?.type === 'totp_setup'}
            <div class="space-y-4">
              <div>
                <h2 class="font-medium">在身份验证器中添加 Zeus</h2>
                <p class="mt-2 text-sm leading-6 text-muted-foreground">
                  手动输入下面的密钥，或使用身份验证器支持的方式导入 URI。密钥只在当前设置流程中显示。
                </p>
              </div>
              <div>
                <p class="text-xs font-medium uppercase tracking-wide text-muted-foreground">Secret</p>
                <code class="mt-2 block break-all rounded-lg border border-border bg-muted/40 p-3 font-mono text-sm">{form.secret}</code>
              </div>
              <div>
                <p class="text-xs font-medium uppercase tracking-wide text-muted-foreground">Provisioning URI</p>
                <code class="mt-2 block break-all rounded-lg border border-border bg-muted/40 p-3 font-mono text-xs leading-5">{form.provisioning_uri}</code>
              </div>
              <form method="POST" action="?/confirmTotp" class="space-y-4">
                <input type="hidden" name="return_to" value={returnTo} />
                <div>
                  <label class="text-sm font-medium" for="totp_setup_code">验证码</label>
                  <Input
                    id="totp_setup_code"
                    name="code"
                    inputmode="numeric"
                    autocomplete="one-time-code"
                    pattern="[0-9]*"
                    required
                    class="mt-2"
                  />
                </div>
                <Button type="submit">确认并启用 TOTP</Button>
              </form>
            </div>
          {:else if totpEnabled}
            <div class="space-y-4">
              <p class="text-sm leading-6 text-muted-foreground">
                TOTP 已保护当前账号。关闭前需要输入当前密码和身份验证器验证码。
              </p>
              {#if isPlatformOwner}
                <p class="rounded-lg border border-border bg-muted/40 p-3 text-sm" role="note">
                  平台 Owner 必须保持 TOTP 启用。
                </p>
              {:else}
                <form method="POST" action="?/disableTotp" class="space-y-4">
                  <div>
                    <label class="text-sm font-medium" for="disable_totp_password">当前密码</label>
                    <Input
                      id="disable_totp_password"
                      name="password"
                      type="password"
                      autocomplete="current-password"
                      required
                      class="mt-2"
                    />
                  </div>
                  <div>
                    <label class="text-sm font-medium" for="disable_totp_code">TOTP 验证码</label>
                    <Input
                      id="disable_totp_code"
                      name="code"
                      inputmode="numeric"
                      autocomplete="one-time-code"
                      pattern="[0-9]*"
                      required
                      class="mt-2"
                    />
                  </div>
                  <Button type="submit" variant="destructive">关闭 TOTP</Button>
                </form>
              {/if}
            </div>
          {:else}
            <div class="space-y-4">
              <p class="text-sm leading-6 text-muted-foreground">
                启用后，登录和敏感账号操作会要求身份验证器验证码。请先确认邮箱已验证。
              </p>
              <form method="POST" action="?/startTotp">
                <input type="hidden" name="return_to" value={returnTo} />
                <Button type="submit">开始设置 TOTP</Button>
              </form>
            </div>
          {/if}
        </Card.Content>
      </Card.Root>
    </div>
  </div>
</main>
