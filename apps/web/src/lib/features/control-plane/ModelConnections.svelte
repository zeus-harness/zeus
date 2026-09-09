<script lang="ts">
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';
  import { Input } from '@zeus/ui/components/ui/input';
  import { Label } from '@zeus/ui/components/ui/label';
  import { NativeSelect, NativeSelectOption } from '@zeus/ui/components/ui/native-select';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import type { ModelConnectionsData } from '$lib/api/agent-studio';
  import type { StudioFeedback } from '$lib/server/agent-studio';

  let { models, resource, workspaceId, selectedConnection = '', saved = false, form }: {
    models: ModelConnectionsData;
    resource: 'connections' | 'model-profiles';
    workspaceId: string;
    selectedConnection?: string;
    saved?: boolean;
    form?: StudioFeedback | null;
  } = $props();
  let isConnection = $derived(resource === 'connections');
  let base = $derived(`/${workspaceId}`);
</script>

<main class="space-y-6 px-5 py-7 lg:px-8 lg:py-9">
  <PageHeader title={isConnection ? '模型连接' : '模型配置'} eyebrow="Workspace settings"
    description={isConnection ? '创建 OpenAI-compatible 连接。密钥加密保存，仅用于服务端模型调用。' : '为模型指定连接、API 地址和模型 ID，随后在 Workflow 中使用。'} />
  <nav class="flex flex-wrap gap-3 text-sm" aria-label="模型接入导航">
    <a class="underline underline-offset-4" href={`${base}/settings/connections`}>模型连接</a>
    <a class="underline underline-offset-4" href={`${base}/settings/model-profiles`}>模型配置</a>
    <a class="underline underline-offset-4" href={`${base}/agents`}>配置 Agent</a>
    <a class="underline underline-offset-4" href={`${base}/workflows`}>发布 Workflow</a>
  </nav>
  {#if form?.type === 'error'}<p class="rounded-lg border border-destructive p-4 text-sm text-destructive" role="alert">{form.message}</p>{/if}
  {#if saved}<p class="rounded-lg border border-border p-4 text-sm" role="status">模型配置已保存，可以在 Workflow 中选择此模型。</p>{/if}
  <div class="grid items-start gap-6 lg:grid-cols-2">
    <Card.Root>
      <Card.Header><Card.Title>{isConnection ? '添加模型连接' : '添加模型配置'}</Card.Title></Card.Header>
      <Card.Content>
        {#if !isConnection && models.connections.length === 0}
          <p class="mb-4 text-sm">先创建一个模型连接并保存 API Key。</p><Button href={`${base}/settings/connections`}>创建连接</Button>
        {:else}
          <form method="POST" action="?/save" class="space-y-5">
            <input type="hidden" name="intent" value="create" />
            <div class="space-y-2"><Label for="name">{isConnection ? '连接名称' : '配置名称'}</Label><Input id="name" name="name" required maxlength={160} value={form?.values?.name ?? ''} /></div>
            {#if isConnection}
              <div class="space-y-2"><Label for="api_key">API Key</Label><Input id="api_key" name="api_key" type="password" autocomplete="off" required /><p class="text-xs text-muted-foreground">保存后不显示密钥原文。</p></div>
            {:else}
              <div class="space-y-2"><Label for="connection_id">模型连接</Label><NativeSelect id="connection_id" name="connection_id" required class="w-full" value={form?.values?.connection_id || selectedConnection}>
                <NativeSelectOption value="" disabled>选择连接</NativeSelectOption>
                {#each models.connections as connection (connection.id)}<NativeSelectOption value={connection.id}>{connection.name}</NativeSelectOption>{/each}
              </NativeSelect></div>
              <div class="space-y-2"><Label for="base_url">API Base URL</Label><Input id="base_url" name="base_url" type="url" required placeholder="https://api.example.com/v1" value={form?.values?.base_url ?? ''} /></div>
              <div class="space-y-2"><Label for="model">模型 ID</Label><Input id="model" name="model" required maxlength={160} value={form?.values?.model ?? ''} /></div>
              <div class="space-y-2"><Label for="timeout_seconds">单次请求超时（秒）</Label><Input id="timeout_seconds" name="timeout_seconds" type="number" min={1} max={300} value={60} required /></div>
            {/if}
            <Button type="submit">{isConnection ? '保存连接' : '保存模型配置'}</Button>
          </form>
        {/if}
      </Card.Content>
    </Card.Root>
    <Card.Root>
      <Card.Header><Card.Title>{isConnection ? '可用模型连接' : '可用模型配置'}</Card.Title></Card.Header>
      <Card.Content class="space-y-3">
        {#if isConnection}
          {#each models.connections as connection (connection.id)}
            <div class="space-y-2 rounded-lg border border-border p-4"><p class="break-words text-sm font-medium">{connection.name}</p><Button href={`${base}/settings/model-profiles?connection=${connection.id}`} size="sm" variant="outline">添加模型配置</Button></div>
          {:else}<p class="text-sm text-muted-foreground">还没有模型连接。</p>{/each}
        {:else}
          {#each models.modelProfiles as model (model.id)}
            <div class="space-y-2 rounded-lg border border-border p-4"><p class="break-words text-sm font-medium">{model.name}</p><p class="break-all text-xs text-muted-foreground">{model.model}<br />{model.base_url}</p><Button href={`${base}/workflows`} size="sm" variant="outline">在 Workflow 中使用</Button></div>
          {:else}<p class="text-sm text-muted-foreground">还没有模型配置。</p>{/each}
        {/if}
      </Card.Content>
    </Card.Root>
  </div>
</main>
