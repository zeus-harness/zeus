<script lang="ts">
  import { Button } from '@zeus/ui/components/ui/button';
  import type { PageData, ActionData } from './$types';
  let { data, form }: { data: PageData; form: ActionData } = $props();
</script>
<svelte:head><title>Zeus · 加入组织</title><meta name="referrer" content="no-referrer" /></svelte:head>
<main class="mx-auto max-w-xl px-5 py-12">
  <h1 class="text-2xl font-semibold">加入受邀组织</h1>
  <p class="mt-4 text-sm text-muted-foreground">使用受邀邮箱注册或登录。接受邀请后，会自动建立组织及邀请指定的工作空间成员关系。</p>
  {#if form?.message}<p class="mt-4 text-sm text-destructive" role="alert">{form.message}</p>{/if}
  {#if !data.tokenPresent}<p class="mt-4">请从完整邀请链接打开此页面。</p>
  {:else if data.signedIn}<form method="POST" class="mt-6"><Button type="submit">接受邀请并加入组织</Button></form>
  {:else}<div class="mt-6 flex gap-3"><Button href={data.loginHref}>已有账号，登录加入</Button><Button href={data.registerHref} variant="outline">注册并加入</Button></div>{/if}
</main>
