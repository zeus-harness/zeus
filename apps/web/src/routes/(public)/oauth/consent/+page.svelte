<script lang="ts">
  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';

  import type { ActionData, PageData } from './$types';

  let { data, form } = $props<{ data: PageData; form: ActionData }>();

  const scopeDescriptions: Record<string, string> = {
    openid: '确认你的 Zeus 身份',
    profile: '读取显示名称',
    email: '读取邮箱和验证状态',
    'zeus.organization': '读取当前组织的基本信息',
    'zeus.workspace': '读取你在该组织可访问的 Workspace ID'
  };
</script>

<svelte:head>
  <title>Zeus · 应用授权</title>
</svelte:head>

<main class="mx-auto flex min-h-screen max-w-2xl items-center px-5 py-10">
  <Card.Root class="w-full">
    <Card.Header>
      <div class="flex items-start justify-between gap-4">
        <div>
          <p class="text-sm font-medium text-muted-foreground">OIDC Authorization</p>
          <Card.Title class="mt-2 text-2xl">确认应用访问</Card.Title>
        </div>
        <Badge variant="outline">Zeus 0.1.0</Badge>
      </div>
      <Card.Description>
        请核对应用、组织和权限范围。拒绝后会将结果返回应用。
      </Card.Description>
    </Card.Header>

    <Card.Content>
      {#if form?.type === 'error'}
        <div class="mb-5 rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive" role="alert">
          {form.message}
        </div>
      {/if}

      {#if data.loadError || !data.authorizationRequest}
        <div class="rounded-xl border border-border bg-muted/40 p-5" role="alert">
          <h1 class="text-lg font-semibold">无法继续授权</h1>
          <p class="mt-2 text-sm leading-6 text-muted-foreground">
            {data.loadError ?? '授权请求不存在。'}
          </p>
          <Button href="/" variant="outline" class="mt-5">返回 Zeus</Button>
        </div>
      {:else}
        <div class="rounded-xl border border-border bg-muted/30 p-5">
          <p class="text-xs font-semibold uppercase tracking-[0.12em] text-muted-foreground">Application</p>
          <h1 class="mt-2 text-xl font-semibold">{data.authorizationRequest.client_name}</h1>
          <dl class="mt-4 grid gap-3 text-sm sm:grid-cols-2">
            <div>
              <dt class="text-muted-foreground">Organization</dt>
              <dd class="mt-1 font-medium">{data.authorizationRequest.organization_name}</dd>
            </div>
            <div>
              <dt class="text-muted-foreground">Client ID</dt>
              <dd class="mt-1 break-all font-mono text-xs">{data.authorizationRequest.client_public_id}</dd>
            </div>
          </dl>
        </div>

        <section class="mt-6" aria-labelledby="scope-heading">
          <h2 id="scope-heading" class="text-base font-semibold">该应用请求</h2>
          <ul class="mt-3 space-y-2">
            {#each data.authorizationRequest.scopes as scope (scope)}
              <li class="rounded-lg border border-border px-4 py-3">
                <code class="text-sm font-semibold">{scope}</code>
                <p class="mt-1 text-sm text-muted-foreground">
                  {scopeDescriptions[scope] ?? '使用该应用声明的权限范围'}
                </p>
              </li>
            {/each}
          </ul>
        </section>

        <div class="mt-7 grid gap-3 sm:grid-cols-2">
          <form method="POST" action="?/deny">
            <input type="hidden" name="request_id" value={data.authorizationRequest.request_id} />
            <Button type="submit" variant="outline" class="w-full">拒绝</Button>
          </form>
          <form method="POST" action="?/approve">
            <input type="hidden" name="request_id" value={data.authorizationRequest.request_id} />
            <Button type="submit" class="w-full">允许访问</Button>
          </form>
        </div>

        <p class="mt-5 text-xs leading-5 text-muted-foreground">
          你可以在账号的 OIDC Authorizations 页面撤销本次授权。
        </p>
      {/if}
    </Card.Content>
  </Card.Root>
</main>
