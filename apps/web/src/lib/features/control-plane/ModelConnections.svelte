<script lang="ts">
  import SetupJourney from './SetupJourney.svelte';
  import { enhance } from '$app/forms';
  let testingModel = $state<string | null>(null);
  import { page } from '$app/state';
  import { taskReturnTo, withTaskReturn } from '$lib/task-return';
  let returnTo = $derived(taskReturnTo(page.url.searchParams.get('return_to')));
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';
  import { Input } from '@zeus/ui/components/ui/input';
  import { Label } from '@zeus/ui/components/ui/label';
  import { NativeSelect, NativeSelectOption } from '@zeus/ui/components/ui/native-select';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import type { ModelConnectionsData } from '$lib/api/agent-studio';
  import type { StudioFeedback } from '$lib/server/agent-studio';

  let { models, resource, organizationId, selectedConnection = '', saved = false, form }: {
    models: ModelConnectionsData;
    resource: 'connections' | 'model-profiles';
    organizationId: string;
    selectedConnection?: string;
    saved?: boolean;
    form?: StudioFeedback | null;
  } = $props();
  let isConnection = $derived(resource === 'connections');
  let base = $derived(`/organizations/${organizationId}`);
  let taskWorkspace = $derived(returnTo ? returnTo.split('/')[1] : null);
</script>

<main class="space-y-6 px-5 py-7 lg:px-8 lg:py-9">
  <PageHeader title={isConnection ? '模型供应商' : '模型目录'} eyebrow="Organization settings"
    description={isConnection ? '连接兼容 OpenAI API 的模型服务。先保存供应商密钥，再填写模型地址并检查连接。密钥加密保存。' : '为模型指定连接、API 地址和模型 ID，同一供应商可添加多个模型，供组织内所有工作空间的智能体使用。'} />
  {#if returnTo}<Button href={returnTo} variant="outline">返回原工作项继续处理</Button>{/if}
  <SetupJourney {organizationId} workspaceId={taskWorkspace} current={resource} {returnTo} configured={[...(models.connections.length ? ['connections'] : []), ...(models.modelProfiles.length ? ['model-profiles'] : [])]} />
  {#if isConnection && models.connections.length > 0}<Button href={withTaskReturn(`${base}/settings/model-profiles`, returnTo)}>继续：配置模型与检查连接</Button>{/if}
  {#if !isConnection && taskWorkspace && models.modelProfiles.length > 0}<Button href={withTaskReturn(`/${taskWorkspace}/agents?template=requirements`, returnTo)}>连接检查完成后：配置智能体</Button>{/if}
  <p class="text-xs text-muted-foreground">保存配置不会发起模型调用，不代表密钥或模型已经通过连接验证。保存后可在模型卡片中单独测试连接；业务结果仍需通过实际任务验证。</p>
  {#if form?.type === 'error'}<p class="rounded-lg border border-destructive p-4 text-sm text-destructive" role="alert">{form.message}</p>{/if}
  {#if form?.type === 'success'}<p role="status" class="rounded-lg border border-border p-4 text-sm">{form.message}</p>{/if}
  {#if saved}<p class="rounded-lg border border-border p-4 text-sm" role="status">{isConnection ? '供应商密钥已更新。' : '模型配置已保存，组织内的 Agent 可选择此模型。'}</p>{/if}
  {#if saved && !isConnection}<Button href="/workspaces">选择工作空间，继续配置 Agent</Button>{/if}
  <div class="grid items-start gap-6 lg:grid-cols-2">
    <Card.Root>
      <Card.Header><Card.Title>{isConnection ? '添加模型供应商' : '添加模型配置'}</Card.Title></Card.Header>
      <Card.Content>
        {#if !isConnection && models.connections.length === 0}
          <p class="mb-4 text-sm">先创建一个模型供应商并保存 API Key。</p><Button href={withTaskReturn(`${base}/settings/connections`, returnTo)}>添加模型供应商</Button>
        {:else}
          <form method="POST" action={withTaskReturn('?/save', returnTo)} class="space-y-5">
            <input type="hidden" name="return_to" value={returnTo} />
            <input type="hidden" name="intent" value="create" />
            <div class="space-y-2"><Label for="name">{isConnection ? '供应商名称' : '配置名称'}</Label><Input id="name" name="name" required maxlength={160} value={form?.values?.name ?? ''} /></div>
            {#if isConnection}
              <div class="space-y-2"><Label for="api_key">API Key</Label><Input id="api_key" name="api_key" type="password" autocomplete="off" required /><p class="text-xs text-muted-foreground">保存后不显示密钥原文。</p></div>
            {:else}
              <div class="space-y-2"><Label for="connection_id">模型供应商</Label><NativeSelect id="connection_id" name="connection_id" required class="w-full" value={form?.values?.connection_id || selectedConnection}>
                <NativeSelectOption value="" disabled>选择供应商</NativeSelectOption>
                {#each models.connections as connection (connection.id)}<NativeSelectOption value={connection.id}>{connection.name}</NativeSelectOption>{/each}
              </NativeSelect></div>
              <div class="space-y-2"><Label for="base_url">模型服务地址</Label><Input id="base_url" name="base_url" type="url" required placeholder="https://api.example.com/v1" value={form?.values?.base_url ?? ''} /></div>
              <div class="space-y-2"><Label for="model">模型 ID</Label><Input id="model" name="model" required maxlength={160} value={form?.values?.model ?? ''} /></div>
              <div class="space-y-2"><Label for="timeout_seconds">单次请求超时（秒）</Label><Input id="timeout_seconds" name="timeout_seconds" type="number" min={1} max={300} value={60} required /></div>
            {/if}
            <Button type="submit">{isConnection ? '保存供应商' : '保存模型配置'}</Button>
          </form>
        {/if}
      </Card.Content>
    </Card.Root>
    <Card.Root>
      <Card.Header><Card.Title>{isConnection ? '可用模型供应商' : '可用模型配置'}</Card.Title></Card.Header>
      <Card.Content class="space-y-3">
        {#if isConnection}
          {#each models.connections as connection (connection.id)}
            <div class="space-y-2 rounded-lg border border-border p-4"><p class="break-words text-sm font-medium">{connection.name}</p><Button href={withTaskReturn(`${base}/settings/model-profiles?connection=${connection.id}`, returnTo)} size="sm" variant="outline">添加模型配置</Button>
              <ul class="space-y-1 text-xs text-muted-foreground" aria-label="供应商模型">
                {#each models.modelProfiles.filter((model) => model.connection_id === connection.id) as model (model.id)}
                  <li>{model.name} · {model.model}</li>
                {:else}<li>尚未添加模型。</li>{/each}
              </ul>
              <details class="text-sm">
                <summary class="cursor-pointer">轮换 API Key</summary>
                <form method="POST" action={withTaskReturn('?/save', returnTo)} class="mt-3 space-y-3">
            <input type="hidden" name="return_to" value={returnTo} />
                  <input type="hidden" name="intent" value="rotate" />
                  <input type="hidden" name="resource_id" value={connection.id} />
                  <input type="hidden" name="revision" value={connection.revision} />
                  <Label for={`key-${connection.id}`}>新的 API Key</Label>
                  <Input id={`key-${connection.id}`} name="api_key" type="password" autocomplete="off" required />
                  <p class="text-xs text-muted-foreground">此输入框仅用于更换密钥，空白不表示已保存的密钥丢失。新密钥用于后续加载连接的运行，包括恢复中的运行。请先确认新密钥有效；旧密钥不会显示。</p>
                  <Button type="submit" size="sm">保存新密钥</Button>
                </form>
              </details>
            </div>
          {:else}<p class="text-sm text-muted-foreground">还没有模型供应商。</p>{/each}
        {:else}
          {#each models.modelProfiles as model (model.id)}
            <div class="space-y-2 rounded-lg border border-border p-4"><p class="break-words text-sm font-medium">{model.name}</p><p class="break-all text-xs text-muted-foreground">{model.model}<br />{model.base_url}</p><p class="text-xs text-muted-foreground">已保存 · 生成能力需通过任务验证。组织内所有工作空间的 Agent 均可选择。</p>
              <form method="POST" action={withTaskReturn('?/testModel', returnTo)} use:enhance={() => { testingModel = model.id; return async ({ update }) => { try { await update(); } finally { testingModel = null; } }; }} class="space-y-3 rounded-lg border border-border p-3">
                <input type="hidden" name="resource_id" value={model.id} /><input type="hidden" name="revision" value={model.revision} />
                <p class="text-xs text-muted-foreground">最长 20 秒；检查连接、认证和模型可见性，不发起生成、不创建运行。生成能力需另用工作项验证。</p>
                <Button type="submit" size="sm" variant="outline" disabled={testingModel !== null}>{testingModel === model.id ? '正在测试…' : '测试模型连接'}</Button>
              </form>
              <details class="text-sm">
                <summary class="cursor-pointer">编辑模型配置</summary>
                <form method="POST" action={withTaskReturn('?/save', returnTo)} class="mt-3 space-y-3">
            <input type="hidden" name="return_to" value={returnTo} />
                  <input type="hidden" name="intent" value="update" />
                  <input type="hidden" name="resource_id" value={model.id} />
                  <input type="hidden" name="revision" value={model.revision} />
                  <Label for={`name-${model.id}`}>配置名称</Label><Input id={`name-${model.id}`} name="name" value={model.name} required maxlength={160} />
                  <Label for={`connection-${model.id}`}>模型供应商</Label>
                  <NativeSelect id={`connection-${model.id}`} name="connection_id" value={model.connection_id} required class="w-full">
                    {#each models.connections as connection (connection.id)}<NativeSelectOption value={connection.id}>{connection.name}</NativeSelectOption>{/each}
                  </NativeSelect>
                  <Label for={`url-${model.id}`}>模型服务地址</Label><Input id={`url-${model.id}`} name="base_url" type="url" value={model.base_url} required />
                  <Label for={`model-${model.id}`}>模型 ID</Label><Input id={`model-${model.id}`} name="model" value={model.model} required maxlength={256} />
                  <Label for={`timeout-${model.id}`}>单次请求超时（秒）</Label><Input id={`timeout-${model.id}`} name="timeout_seconds" type="number" min={1} max={300} value={model.configuration && typeof model.configuration === 'object' && !Array.isArray(model.configuration) && 'timeout_seconds' in model.configuration && typeof model.configuration.timeout_seconds === 'number' ? model.configuration.timeout_seconds : 60} required />
                  <p class="text-xs text-muted-foreground">影响引用此配置的新运行及后续恢复；其他模型参数会保留。需隔离影响时请创建新配置。</p>
                  <Button type="submit" size="sm">保存修改</Button>
                </form>
              </details>
            </div>
          {:else}<p class="text-sm text-muted-foreground">还没有模型配置。</p>{/each}
        {/if}
      </Card.Content>
    </Card.Root>
  </div>
</main>
