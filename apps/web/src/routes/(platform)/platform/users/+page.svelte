<script lang="ts">
  import * as Table from '@zeus/ui/components/ui/table';
  import { Input } from '@zeus/ui/components/ui/input';
  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import type { PageData } from './$types';
  let { data }: { data: PageData } = $props();
  const statuses: Record<string, string> = { pending_verification: '待验证邮箱', active: '正常', disabled: '已停用', anonymization_pending: '待匿名化', anonymized: '已匿名化' };
</script>

<svelte:head><title>Zeus · 平台用户</title></svelte:head>
<main class="space-y-6 px-5 py-7 lg:px-8 lg:py-9">
  <PageHeader eyebrow="Platform" title="用户" description="全平台已创建的账号，包括待验证邮箱和未加入组织的用户。仅 platform_owner 可查看。" />
  <form method="GET" class="flex flex-wrap items-end gap-3">
    <div class="min-w-0 flex-1 space-y-2"><label for="email" class="text-sm">按完整邮箱查找</label><Input id="email" name="email" type="email" value={data.email} placeholder="user@example.com" /></div>
    <Button type="submit">查找</Button><Button href="/platform/users" variant="outline">清除</Button>
  </form>
  <Table.Root>
    <Table.Caption>每页最多 50 位用户，按注册时间从新到旧显示。</Table.Caption>
    <Table.Header><Table.Row><Table.Head>用户</Table.Head><Table.Head>邮箱</Table.Head><Table.Head>状态</Table.Head><Table.Head>邮箱验证</Table.Head><Table.Head>MFA</Table.Head><Table.Head>注册时间（UTC）</Table.Head></Table.Row></Table.Header>
    <Table.Body>
      {#each data.users.items as user (user.id)}
        <Table.Row>
          <Table.Cell><p>{user.display_name}</p><details class="text-xs text-muted-foreground"><summary class="cursor-pointer">账号标识</summary><p class="mt-2">{user.id}</p></details></Table.Cell>
          <Table.Cell>{user.email}</Table.Cell><Table.Cell><Badge variant="outline">{statuses[user.status] ?? user.status}</Badge></Table.Cell>
          <Table.Cell>{user.email_verified ? '已验证' : '未验证'}</Table.Cell><Table.Cell>{user.mfa_enabled ? '已启用' : '未启用'}</Table.Cell><Table.Cell>{user.created_at}</Table.Cell>
        </Table.Row>
      {:else}<Table.Row><Table.Cell colspan={6}>没有匹配的用户。</Table.Cell></Table.Row>{/each}
    </Table.Body>
  </Table.Root>
  <nav class="flex gap-3" aria-label="用户分页">
    {#if data.cursor}<Button href={`?${new URLSearchParams({ email: data.email })}`} variant="outline">返回第一页</Button>{/if}
    {#if data.users.next_cursor}<Button href={`?${new URLSearchParams({ cursor: data.users.next_cursor, email: data.email })}`} variant="outline">下一页</Button>{/if}
  </nav>
</main>
