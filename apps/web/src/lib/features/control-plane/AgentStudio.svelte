<script lang="ts">
  import { page } from '$app/state';
  import { taskReturnTo, withTaskReturn } from '$lib/task-return';
  let returnTo = $derived(taskReturnTo(page.url.searchParams.get('return_to')));
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

  let { studio, resource, workspaceId, organizationId, canManageOrganization, requirementsTemplate = false, form }: {
    studio: AgentStudioData;
    resource: 'agents' | 'workflows';
    workspaceId: string;
    organizationId: string;
    canManageOrganization: boolean;
    requirementsTemplate?: boolean;
    form?: StudioFeedback | null;
  } = $props();
  let isAgent = $derived(resource === 'agents');
  let label = $derived(isAgent ? 'Agent' : 'Workflow');
  let selected = $derived(studio.selected);
  let versions = $derived(isAgent ? studio.agentVersions : studio.workflowVersions);
  let publishedWorkflow = $derived(studio.workflowVersions.find((version) => version.id === selected?.active_version_id));
  let allowedTools = $derived.by(() => {
    const policy = publishedWorkflow?.capability_policy;
    return policy && typeof policy === 'object' && !Array.isArray(policy) && 'allowed' in policy && Array.isArray(policy.allowed) ? policy.allowed.filter((id): id is string => typeof id === 'string') : [];
  });
  const requirementsInstructions = '根据关联工作项中的需求，输出：1. 已知事实；2. 缺失信息；3. 建议；4. 待人工确认事项。明确区分事实与推断，不编造信息。若允许读取工作项工具，先读取当前关联工作项；否则只使用输入中已有信息。最终结果交由用户验收，不代替用户确认。';
  let base = $derived(`/${workspaceId}`);
</script>

<main class="space-y-6 px-5 py-7 lg:px-8 lg:py-9">
  <PageHeader title={isAgent ? '智能体（Agent）' : '流程（Workflow）'} eyebrow="Agent Studio"
    description={isAgent ? '选择组织提供的模型并编写指令，保存版本后发布。' : '选择 Agent 和工具；模型沿用 Agent 版本，保存版本后发布，即可从工作项启动。'} />
  {#if returnTo}<Button href={returnTo} variant="outline">返回原工作项继续处理</Button>{/if}
  <nav class="flex flex-wrap gap-3 text-sm" aria-label="Agent 接入步骤">
    {#if canManageOrganization}<a class="underline underline-offset-4" href={withTaskReturn(`/organizations/${organizationId}/settings/model-profiles`, returnTo)}>模型接入与检查</a>{/if}
    <a class="underline underline-offset-4" href={withTaskReturn(`${base}/agents`, returnTo)}>1. Agent 与模型</a>
    <a class="underline underline-offset-4" href={withTaskReturn(`${base}/workflows`, returnTo)}>2. 发布 Workflow</a>
    <a class="underline underline-offset-4" href={withTaskReturn(`${base}/work-items`, returnTo)}>3. 运行工作项</a>
  </nav>
  {#if studio.modelProfiles.length === 0}
    <div class="space-y-3 rounded-lg border border-border p-4"><p class="text-sm">当前最早的前置步骤：配置组织模型。完成模型连接检查后，再发布 Agent 和流程。可以先保存草稿。</p>{#if canManageOrganization}<Button href={withTaskReturn(`/organizations/${organizationId}/settings/model-profiles`, returnTo)} variant="outline">配置组织模型</Button>{:else}<p class="text-sm text-muted-foreground">请联系组织 Owner 配置模型。</p>{/if}</div>
  {:else if !isAgent && studio.agents.length === 0}
    <div class="space-y-3 rounded-lg border border-border p-4"><p class="text-sm">还没有已发布的 Agent，流程暂时无法运行。</p><Button href={withTaskReturn(`${base}/agents?template=requirements`, returnTo)} variant="outline">配置需求整理 Agent</Button></div>
  {/if}
  {#if isAgent}
    <div class="rounded-lg border border-border p-4"><p class="font-medium">需求整理模板</p><p class="mt-2 text-sm text-muted-foreground">从工作项提取事实、缺失信息和建议，交由人验收。模板只填入草稿内容，不自动发布或运行。</p><Button href={withTaskReturn(`?${selected ? `selected=${selected.id}&` : ''}template=requirements`, returnTo)} variant="outline" size="sm" class="mt-3">使用模板</Button></div>
  {:else}
    <ol class="grid gap-3 sm:grid-cols-4" aria-label="业务流程预览">{#each ['工作项：输入需求', 'Agent：整理与执行', '结果：事实和建议', '人工验收：接受或修改'] as step (step)}<li class="rounded-lg border border-border p-3 text-sm">{step}</li>{/each}</ol>
    <p class="text-xs text-muted-foreground">这是业务使用路径。流程版本定义 Agent、工具与预算；具体执行顺序见运行记录，人工验收在工作项中完成。</p>
  {/if}
  {#if form?.type === 'error'}<p class="rounded-lg border border-destructive p-4 text-sm text-destructive" role="alert">{form.message}</p>{/if}
  <div class="grid items-start gap-6 xl:grid-cols-[20rem_minmax(0,1fr)]">
    <div class="space-y-5">
      <Card.Root>
        <Card.Header><Card.Title>创建 {label}</Card.Title></Card.Header>
        <Card.Content>
          <form method="POST" action={withTaskReturn('?/save', returnTo)} class="space-y-4">
            <input type="hidden" name="return_to" value={returnTo} />
            <input type="hidden" name="intent" value="create" />
            <input type="hidden" name="template" value={requirementsTemplate ? 'requirements' : ''} />
            <div class="space-y-2"><Label for="name">{label} 名称</Label><Input id="name" name="name" required maxlength={160} value={form?.values?.name ?? (requirementsTemplate ? '需求整理助手' : '')} /></div>
            <div class="space-y-2"><Label for="description">用途说明</Label><Textarea id="description" name="description" rows={3} maxlength={8000} value={form?.values?.description ?? (requirementsTemplate ? '整理需求事实、缺失信息和建议，由人验收。' : '')} /></div>
            <Button type="submit">创建 {label}</Button>
          </form>
        </Card.Content>
      </Card.Root>
      <Card.Root>
        <Card.Header><Card.Title>已有 {label}</Card.Title></Card.Header>
        <Card.Content class="space-y-2">
          {#each studio.resources as item (item.id)}
            <a href={withTaskReturn(`?selected=${item.id}`, returnTo)} aria-current={selected?.id === item.id ? 'page' : undefined}
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
        {#if !isAgent}
          <Card.Root>
            <Card.Header><Card.Title>执行配置概览</Card.Title><Card.Description>{publishedWorkflow ? `已发布版本 ${publishedWorkflow.version_number}；从工作项启动时使用此版本。` : '尚未发布，保存配置并发布版本后即可从工作项启动。'}</Card.Description></Card.Header>
            <Card.Content>
              {#if publishedWorkflow}
                <ol class="grid gap-3 md:grid-cols-3" aria-label="Workflow 配置关系">
                  <li class="min-w-0 rounded-lg border border-border p-4"><p class="text-xs text-muted-foreground">1 · Agent 与模型</p><p class="mt-2 break-words font-medium">{studio.agents.find((agent) => agent.active_version_id === publishedWorkflow.agent_version_id)?.name ?? '已绑定的 Agent 版本'}</p><p class="mt-1 text-sm text-muted-foreground">{studio.modelProfiles.find((model) => model.id === publishedWorkflow.model_profile_id)?.name ?? '已绑定的模型'}</p><details class="mt-2 text-xs"><summary class="cursor-pointer">版本标识</summary><p class="mt-2 break-all">{publishedWorkflow.agent_version_id}</p></details></li>
                  <li class="min-w-0 rounded-lg border border-border p-4"><p class="text-xs text-muted-foreground">2 · 工具与审批</p>{#each allowedTools as id (id)}<p class="mt-2 break-words text-sm">{studio.catalog.find((entry) => entry.id === id)?.display_name ?? id}</p>{:else}<p class="mt-2 text-sm">未允许工具</p>{/each}<p class="mt-2 text-xs text-muted-foreground">调用时按 Workspace 要求和该版本的审批策略检查。</p></li>
                  <li class="min-w-0 rounded-lg border border-border p-4"><p class="text-xs text-muted-foreground">3 · 执行与结果</p><p class="mt-2 text-sm">最多 {publishedWorkflow.max_steps} 步 · {publishedWorkflow.max_runtime_seconds} 秒</p><p class="mt-1 text-sm">{publishedWorkflow.token_budget ?? '未设置'} Token</p><a class="mt-3 inline-block text-sm underline" href={withTaskReturn(`${base}/work-items`, returnTo)}>选择工作项并运行</a></li>
                </ol>
                <p class="mt-3 text-xs text-muted-foreground">此处展示执行配置；实际模型和工具调用顺序以 Run 记录为准。</p>
              {/if}
            </Card.Content>
          </Card.Root>
        {/if}
        <Card.Root>
          <Card.Header><Card.Title>{selected.name}</Card.Title><Card.Description>保存新版本后，在版本列表中发布。已有运行继续使用原来绑定的版本。</Card.Description></Card.Header>
          <Card.Content>
            {#if selected.archived_at}
              <p class="text-sm text-muted-foreground">该资源已归档。</p>
            {:else if (isAgent && studio.modelProfiles.length === 0) || (!isAgent && studio.agents.length === 0)}
              <p class="text-sm">{isAgent ? '组织尚无可用模型，请联系 Organization Owner 在组织设置中添加。' : '先发布一个已选择模型的 Agent 版本，再创建 Workflow 版本。'}</p>
            {:else}
              <form method="POST" action={withTaskReturn(`?selected=${selected.id}&/save`, returnTo)} class="space-y-5">
            <input type="hidden" name="return_to" value={returnTo} />
                <input type="hidden" name="intent" value="version" />
                <input type="hidden" name="resource_id" value={selected.id} />
                {#if isAgent}
                    <div class="space-y-2"><Label for="model_profile_id">模型</Label>
                      <NativeSelect id="model_profile_id" name="model_profile_id" required class="w-full" value={form?.values?.model_profile_id || studio.agentVersions[0]?.model_profile_id || ''}>
                        <NativeSelectOption value="" disabled>选择模型</NativeSelectOption>
                        {#each studio.modelProfiles as model (model.id)}<NativeSelectOption value={model.id}>{model.name} · {model.model}</NativeSelectOption>{/each}
                      </NativeSelect>
                    </div>
                  <div class="space-y-2"><Label for="instructions">Agent 指令</Label><Textarea id="instructions" name="instructions" rows={12} required maxlength={200000}
                    value={form?.values?.instructions ?? (requirementsTemplate ? requirementsInstructions : studio.agentVersions[0]?.instructions ?? '')}
                    placeholder="说明任务目标、工作步骤和输出要求。" /></div>
                {:else}
                  <div class="grid gap-4 md:grid-cols-2">
                    <div class="space-y-2"><Label for="agent_version_id">已发布的 Agent</Label>
                      <NativeSelect id="agent_version_id" name="agent_version_id" required class="w-full" value={form?.values?.agent_version_id || ''}>
                        <NativeSelectOption value="" disabled>选择 Agent</NativeSelectOption>
                        {#each studio.agents as agent (agent.id)}<NativeSelectOption value={agent.active_version_id ?? ''}>{agent.name}</NativeSelectOption>{/each}
                      </NativeSelect>
                    </div>

                  </div>
                  <fieldset class="space-y-3 rounded-lg border border-border p-4">
                    <legend class="px-1 text-sm font-medium">允许使用的工具</legend>
                    <p class="text-xs text-muted-foreground">只选择本次任务需要的工具。未选择时仅调用模型；Workspace 的审批要求始终生效。</p>
                    {#each studio.capabilities as capability (capability.id)}
                      <label class="flex items-start gap-3 text-sm">
                        <input type="checkbox" name="capability_id" value={capability.capability_id} checked={form?.values?.capability_ids?.split(',').includes(capability.capability_id) ?? false} class="mt-1" />
                        <span class="min-w-0 break-all">{studio.catalog.find((definition) => definition.id === capability.capability_id)?.display_name ?? capability.capability_id}<span class="mt-1 block text-xs text-muted-foreground">{capability.approval_required ? '需要审批' : '按风险策略执行'} · {capability.timeout_seconds}s</span></span>
                      </label>
                    {:else}<p class="text-sm text-muted-foreground">当前 Workspace 尚未启用工具。</p>{/each}
                  </fieldset>
                  <div class="grid gap-4 sm:grid-cols-3">
                    <div class="space-y-2"><Label for="max_steps">最大模型步数</Label><Input id="max_steps" name="max_steps" type="number" min={1} max={1024} value={form?.values?.max_steps ?? 16} required /></div>
                    <div class="space-y-2"><Label for="max_runtime_seconds">运行时限（秒）</Label><Input id="max_runtime_seconds" name="max_runtime_seconds" type="number" min={1} max={86400} value={form?.values?.max_runtime_seconds ?? 300} required /></div>
                    <div class="space-y-2"><Label for="token_budget">Token 预算</Label><Input id="token_budget" name="token_budget" type="number" min={1} max={10000000} value={form?.values?.token_budget ?? 16000} required /></div>
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
                    <form method="POST" action={withTaskReturn(`?selected=${selected.id}&/save`, returnTo)}>
            <input type="hidden" name="return_to" value={returnTo} />
                      <input type="hidden" name="intent" value="activate" /><input type="hidden" name="resource_id" value={selected.id} /><input type="hidden" name="revision" value={selected.revision} /><input type="hidden" name="version_id" value={version.id} />
                      <Button type="submit" size="sm">发布版本 {version.version_number}</Button>
                    </form>
                  {/if}
                </div>
                {#if 'instructions' in version}
                  <p class="text-xs text-muted-foreground">模型：{studio.modelProfiles.find((model) => model.id === version.model_profile_id)?.name ?? (version.model_profile_id ? '模型已不可用' : '旧版本未绑定模型，请保存新版本')}</p>
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
