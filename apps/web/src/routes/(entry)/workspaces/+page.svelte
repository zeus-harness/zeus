<script lang="ts">
  import { enhance } from '$app/forms';
  import { ArrowRight, Building2 } from '@lucide/svelte';
  import type { Attachment } from 'svelte/attachments';

  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';

  import { enhanceWorkspaceSelection } from '$lib/features/tenancy/workspace-channel';
  import type { PageData } from './$types';

  let { data }: { data: PageData } = $props();

  function autoSelect(workspaceId: string): Attachment<HTMLFormElement> {
    return (node) => {
      if (data.autoSelect === workspaceId) queueMicrotask(() => node.requestSubmit());
    };
  }

  function selectionTarget(workspaceId: string): string {
    const requested = data.returnTo;
    return requested === `/${workspaceId}` || requested.startsWith(`/${workspaceId}/`)
      ? requested
      : `/${workspaceId}`;
  }
</script>

<svelte:head><title>Zeus · 选择 Workspace</title></svelte:head>

<main class="min-h-screen bg-muted/20 px-5 py-10 sm:px-8">
  <div class="mx-auto max-w-5xl">
    <div class="flex flex-col gap-4 border-b border-border pb-7 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <p class="text-xs font-semibold uppercase tracking-[0.14em] text-muted-foreground">Zeus</p>
        <h1 class="mt-2 text-3xl font-semibold tracking-tight">选择 Workspace</h1>
        <p class="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
          Workspace 按 Organization 分组显示。选择后会轮换当前 Session，并进入带 Workspace ID 的地址。
        </p>
      </div>
      <div class="flex gap-2">
        {#if data.isPlatformAdmin}<Button href="/platform" variant="outline">平台控制台</Button>{/if}
        <Button href="/account/profile" variant="ghost">账号设置</Button>
      </div>
    </div>

    {#if data.workspaces.length === 0}
      <Card.Root class="mt-8">
        <Card.Header>
          <Card.Title>还没有可用 Workspace</Card.Title>
          <Card.Description>接受 Organization 邀请，或联系 Owner 为你分配 Workspace。</Card.Description>
        </Card.Header>
      </Card.Root>
    {:else}
      <div class="mt-8 grid gap-4 md:grid-cols-2">
        {#each data.workspaces as workspace (workspace.id)}
          <Card.Root class="transition-colors hover:border-foreground/30">
            <Card.Header>
              <div class="flex items-start justify-between gap-4">
                <div class="min-w-0">
                  <Card.Title class="truncate">{workspace.name}</Card.Title>
                  <Card.Description class="mt-1 flex items-center gap-1.5">
                    <Building2 class="size-3.5" />
                    <span class="truncate">{workspace.organization.organization_name}</span>
                  </Card.Description>
                </div>
                <Badge variant={workspace.status === 'active' ? 'secondary' : 'outline'}>{workspace.status}</Badge>
              </div>
            </Card.Header>
            <Card.Content class="flex items-center justify-between gap-3 text-sm text-muted-foreground">
              <span>Workspace {workspace.role}</span>
              <span>Organization {workspace.organization.organization_role ?? 'support'}</span>
            </Card.Content>
            <Card.Footer>
              <form
                {@attach autoSelect(workspace.id)}
                method="POST"
                action="?/select"
                class="w-full"
                use:enhance={enhanceWorkspaceSelection(workspace.id)}
              >
                <input type="hidden" name="organization_id" value={workspace.organization.organization_id} />
                <input type="hidden" name="workspace_id" value={workspace.id} />
                <input type="hidden" name="return_to" value={selectionTarget(workspace.id)} />
                <Button type="submit" class="w-full" disabled={workspace.status !== 'active'}>
                  {workspace.id === data.autoSelect ? '正在进入…' : '进入 Workspace'}
                  <ArrowRight class="size-4" />
                </Button>
              </form>
            </Card.Footer>
          </Card.Root>
        {/each}
      </div>
    {/if}
  </div>
</main>
