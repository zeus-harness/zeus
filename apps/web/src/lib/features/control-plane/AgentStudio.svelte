<script lang="ts">
  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';
  import { Input } from '@zeus/ui/components/ui/input';
  import { Label } from '@zeus/ui/components/ui/label';
  import { NativeSelect, NativeSelectOption } from '@zeus/ui/components/ui/native-select';
  import { Textarea } from '@zeus/ui/components/ui/textarea';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import type { AgentStudioData } from '$lib/api/agent-studio';
  import type { StudioFeedback } from '$lib/server/agent-studio';

  let { studio, resource, workspaceId, form }: {
    studio: AgentStudioData;
    resource: 'agents' | 'workflows';
    workspaceId: string;
    form?: StudioFeedback | null;
  } = $props();
  let isAgent = $derived(resource === 'agents');
  let label = $derived(isAgent ? 'Agent' : 'Workflow');
  let selected = $derived(studio.selected);
  let versions = $derived(isAgent ? studio.agentVersions : studio.workflowVersions);
  let base = $derived(`/${workspaceId}`);
</script>

<main class="space-y-6 px-5 py-7 lg:px-8 lg:py-9">
  <PageHeader title={isAgent ? 'Agents' : 'Workflows'} eyebrow="Agent Studio"
    description={isAgent ? '编写 Agent 指令，保存版本后发布。Workflow 会绑定一个明确的 Agent 版本。' : '选择 Agent、模型和工具，保存版本后发布，即可从工作项启动。'} />
  <nav class="flex flex-wrap gap-3 text-sm" aria-label="Agent 接入步骤">
    <a class="underline underline-offset-4" href={`${base}/settings/connections`}>1. 模型连接</a>
    <a class="underline underline-offset-4" href={`${base}/settings/model-profiles`}>2. 模型配置</a>
    <a class="underline underline-offset-4" href={`${base}/agents`}>3. Agent 指令</a>
    <a class="underline underline-offset-4" href={`${base}/workflows`}>4. 发布 Workflow</a>
    <a class="underline underline-offset-4" href={`${base}/work-items`}>5. 运行工作项</a>
  </nav>
  {#if form?.type === 'error'}<p class="rounded-lg border border-destructive p-4 text-sm text-destructive" role="alert">{form.message}</p>{/if}
  <div class="grid items-start gap-6 xl:grid-cols-[20rem_minmax(0,1fr)]">
    <div class="space-y-5">
      <Card.Root>
        <Card.Header><Card.Title>创建 {label}</Card.Title></Card.Header>
        <Card.Content>
          <form method="POST" action="?/save" class="space-y-4">
            <input type="hidden" name="intent" value="create" />
            <div class="space-y-2"><Label for="name">{label} 名称</Label><Input id="name" name="name" required maxlength={160} value={form?.values?.name ?? ''} /></div>
            <div class="space-y-2"><Label for="description">用途说明</Label><Textarea id="description" name="description" rows={3} maxlength={8000} value={form?.values?.description ?? ''} /></div>
            <Button type="submit">创建 {label}</Button>
          </form>
        </Card.Content>
      </Card.Root>
      <Card.Root>
        <Card.Header><Card.Title>已有 {label}</Card.Title></Card.Header>
        <Card.Content class="space-y-2">
          {#each studio.resources as item (item.id)}
            <a href={`?selected=${item.id}`} aria-current={selected?.id === item.id ? 'page' : undefined}
              class={['block rounded-lg border p-3 text-sm', selected?.id === item.id ? 'border-foreground bg-muted' : 'border-border']}>
              <span class="block break-words font-medium">{item.name}</span>
              <span class="mt-1 block text-xs text-muted-foreground">{item.archived_at ? '已归档' : item.active_version_id ? '已发布' : '待发布'}</span>
            </a>
          {:else}<p class="text-sm text-muted-foreground">创建第一个 {label} 后，继续配置版本。</p>{/each}
        </Card.Content>
      </Card.Root>
    </div>
    {#if selected}
      <div class="min-w-0 space-y-5">
        <Card.Root>
          <Card.Header><Card.Title>{selected.name}</Card.Title><Card.Description>保存新版本后，在版本列表中发布。已有运行继续使用原来绑定的版本。</Card.Description></Card.Header>
          <Card.Content>
            {#if selected.archived_at}
              <p class="text-sm text-muted-foreground">该资源已归档。</p>
            {:else if !isAgent && (studio.agents.length === 0 || studio.modelProfiles.length === 0)}
              <p class="text-sm">先发布一个 Agent 版本，并配置可用模型，再创建 Workflow 版本。</p>
            {:else}
              <form method="POST" action="?/save" class="space-y-5">
                <input type="hidden" name="intent" value="version" />
                <input type="hidden" name="resource_id" value={selected.id} />
                {#if isAgent}
                  <div class="space-y-2"><Label for="instructions">Agent 指令</Label><Textarea id="instructions" name="instructions" rows={12} required maxlength={200000}
                    value={form?.values?.instructions ?? studio.agentVersions[0]?.instructions ?? ''}
                    placeholder="说明任务目标、工作步骤和输出要求。" /></div>
                {:else}
                  <div class="grid gap-4 md:grid-cols-2">
                    <div class="space-y-2"><Label for="agent_version_id">已发布的 Agent</Label>
                      <NativeSelect id="agent_version_id" name="agent_version_id" required class="w-full" value={form?.values?.agent_version_id || ''}>
                        <NativeSelectOption value="" disabled>选择 Agent</NativeSelectOption>
                        {#each studio.agents as agent (agent.id)}<NativeSelectOption value={agent.active_version_id ?? ''}>{agent.name}</NativeSelectOption>{/each}
                      </NativeSelect>
                    </div>
                    <div class="space-y-2"><Label for="model_profile_id">模型配置</Label>
                      <NativeSelect id="model_profile_id" name="model_profile_id" required class="w-full" value={form?.values?.model_profile_id || ''}>
                        <NativeSelectOption value="" disabled>选择模型</NativeSelectOption>
                        {#each studio.modelProfiles as model (model.id)}<NativeSelectOption value={model.id}>{model.name} · {model.model}</NativeSelectOption>{/each}
                      </NativeSelect>
                    </div>
                  </div>
                  <fieldset class="space-y-3 rounded-lg border border-border p-4">
                    <legend class="px-1 text-sm font-medium">允许使用的工具</legend>
                    <p class="text-xs text-muted-foreground">只选择本次任务需要的工具。未选择时仅调用模型；Workspace 的审批要求始终生效。</p>
                    {#each studio.capabilities as capability (capability.id)}
                      <label class="flex items-start gap-3 text-sm">
                        <input type="checkbox" name="capability_id" value={capability.capability_id} class="mt-1" />
                        <span class="min-w-0 break-all">{studio.catalog.find((definition) => definition.id === capability.capability_id)?.display_name ?? capability.capability_id}<span class="mt-1 block text-xs text-muted-foreground">{capability.approval_required ? '需要审批' : '按风险策略执行'} · {capability.timeout_seconds}s</span></span>
                      </label>
                    {:else}<p class="text-sm text-muted-foreground">当前 Workspace 尚未启用工具。</p>{/each}
                  </fieldset>
                  <div class="grid gap-4 sm:grid-cols-3">
                    <div class="space-y-2"><Label for="max_steps">最大模型步数</Label><Input id="max_steps" name="max_steps" type="number" min={1} max={1024} value={16} required /></div>
                    <div class="space-y-2"><Label for="max_runtime_seconds">运行时限（秒）</Label><Input id="max_runtime_seconds" name="max_runtime_seconds" type="number" min={1} max={86400} value={300} required /></div>
                    <div class="space-y-2"><Label for="token_budget">Token 预算</Label><Input id="token_budget" name="token_budget" type="number" min={1} max={10000000} value={16000} required /></div>
                  </div>
                {/if}
                <Button type="submit">保存新版本</Button>
              </form>
            {/if}
          </Card.Content>
        </Card.Root>
        <Card.Root>
          <Card.Header><Card.Title>版本与发布</Card.Title></Card.Header>
          <Card.Content class="space-y-4">
            {#each versions as version (version.id)}
              <section class="space-y-3 rounded-lg border border-border p-4">
                <div class="flex flex-wrap items-center justify-between gap-3">
                  <div class="flex items-center gap-2"><span class="text-sm font-medium">版本 {version.version_number}</span><Badge variant={selected.active_version_id === version.id ? 'default' : 'outline'}>{selected.active_version_id === version.id ? '已发布' : '未激活'}</Badge></div>
                  {#if selected.active_version_id !== version.id && !selected.archived_at}
                    <form method="POST" action="?/save">
                      <input type="hidden" name="intent" value="activate" /><input type="hidden" name="resource_id" value={selected.id} /><input type="hidden" name="revision" value={selected.revision} /><input type="hidden" name="version_id" value={version.id} />
                      <Button type="submit" size="sm">发布版本 {version.version_number}</Button>
                    </form>
                  {/if}
                </div>
                {#if 'instructions' in version}
                  <details><summary class="cursor-pointer text-sm">查看指令</summary><pre class="mt-3 max-h-64 overflow-auto whitespace-pre-wrap break-words text-xs">{version.instructions}</pre></details>
                {:else}
                  <p class="break-all text-xs text-muted-foreground">Agent 版本：{version.agent_version_id}<br />模型配置：{version.model_profile_id}</p>
                  <p class="text-xs text-muted-foreground">最多 {version.max_steps} 步 · {version.max_runtime_seconds} 秒 · {version.token_budget ?? '未设置'} Token</p>
                {/if}
              </section>
            {:else}<p class="text-sm text-muted-foreground">还没有版本。先保存配置，再发布。</p>{/each}
          </Card.Content>
        </Card.Root>
      </div>
    {:else}
      <Card.Root><Card.Header><Card.Title>配置 {label}</Card.Title><Card.Description>从左侧选择已有资源，或创建一个新的 {label}。</Card.Description></Card.Header></Card.Root>
    {/if}
  </div>
</main>
