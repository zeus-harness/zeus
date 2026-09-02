<script lang="ts">
  import { ArrowRight, Plus } from '@lucide/svelte';

  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import { Input } from '@zeus/ui/components/ui/input';
  import { Label } from '@zeus/ui/components/ui/label';
  import { NativeSelect, NativeSelectOption } from '@zeus/ui/components/ui/native-select';
  import * as Sheet from '@zeus/ui/components/ui/sheet';
  import * as Table from '@zeus/ui/components/ui/table';

  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import type { ActionData, PageData } from './$types';

  let { data, form }: { data: PageData; form: ActionData } = $props();
</script>

<svelte:head><title>Zeus · Organizations</title></svelte:head>

<main class="px-5 py-7 lg:px-8 lg:py-9">
  <PageHeader eyebrow="Platform" title="Organizations" description="创建、暂停、归档和恢复企业租户。">
    {#snippet actions()}
      <Sheet.Root>
        <Sheet.Trigger>{#snippet child({ props })}<Button {...props}><Plus class="size-4" />创建 Organization</Button>{/snippet}</Sheet.Trigger>
        <Sheet.Content class="overflow-y-auto sm:max-w-lg">
          <Sheet.Header><Sheet.Title>创建 Organization</Sheet.Title><Sheet.Description>事务会同时创建首个 Workspace、Owner 邀请和邮件任务。</Sheet.Description></Sheet.Header>
          <form method="POST" action="?/create" class="space-y-4 px-4 pb-6">
            <div class="space-y-2"><Label for="platform-org-name">Organization 名称</Label><Input id="platform-org-name" name="name" required /></div>
            <div class="space-y-2"><Label for="platform-org-slug">Organization Slug</Label><Input id="platform-org-slug" name="slug" required /></div>
            <div class="space-y-2"><Label for="platform-workspace-name">首个 Workspace 名称</Label><Input id="platform-workspace-name" name="initial_workspace_name" required /></div>
            <div class="space-y-2"><Label for="platform-workspace-slug">首个 Workspace Slug</Label><Input id="platform-workspace-slug" name="initial_workspace_slug" required /></div>
            <div class="space-y-2"><Label for="platform-owner-email">首位 Owner 邮箱</Label><Input id="platform-owner-email" name="owner_email" type="email" required /></div>
            <div class="space-y-2"><Label for="platform-identity-mode">身份设置</Label><NativeSelect id="platform-identity-mode" name="identity_settings_mode" value="self_service"><NativeSelectOption value="self_service">Organization 自助管理</NativeSelectOption><NativeSelectOption value="platform_managed">平台托管</NativeSelectOption></NativeSelect></div>
            <Button type="submit" class="w-full">创建并发送邀请</Button>
          </form>
        </Sheet.Content>
      </Sheet.Root>
    {/snippet}
  </PageHeader>
  {#if form?.type === 'error'}<p class="mt-6 text-sm text-destructive" role="alert">{form.message}</p>{/if}

  <div class="mt-7 overflow-x-auto rounded-xl border border-border bg-background">
    <Table.Root class="min-w-[52rem]">
      <Table.Header><Table.Row><Table.Head>Organization</Table.Head><Table.Head>状态</Table.Head><Table.Head>身份设置</Table.Head><Table.Head>Workspaces</Table.Head><Table.Head>Owners</Table.Head><Table.Head></Table.Head></Table.Row></Table.Header>
      <Table.Body>
        {#each data.organizations as organization (organization.id)}
          <Table.Row>
            <Table.Cell><span class="font-medium">{organization.name}</span><span class="mt-1 block text-xs text-muted-foreground">{organization.slug}</span></Table.Cell>
            <Table.Cell><Badge variant={organization.status === 'active' ? 'secondary' : 'outline'}>{organization.status}</Badge></Table.Cell>
            <Table.Cell>{organization.identity_settings_mode}</Table.Cell>
            <Table.Cell>{organization.workspace_count}</Table.Cell>
            <Table.Cell>{organization.active_owner_count}</Table.Cell>
            <Table.Cell class="text-right"><Button href={`/platform/organizations/${organization.id}`} variant="ghost" size="sm">管理<ArrowRight class="size-4" /></Button></Table.Cell>
          </Table.Row>
        {:else}
          <Table.Row><Table.Cell colspan={6} class="py-12 text-center text-muted-foreground">还没有 Organization。</Table.Cell></Table.Row>
        {/each}
      </Table.Body>
    </Table.Root>
  </div>
</main>
