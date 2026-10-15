<script lang="ts">
  import { withTaskReturn } from '$lib/task-return';
  let { organizationId, workspaceId, current, returnTo = '', configured = [], canManageOrganization = true }: {
    organizationId: string;
    workspaceId?: string | null;
    current: 'connections' | 'model-profiles' | 'agents' | 'workflows';
    returnTo?: string;
    configured?: string[];
    canManageOrganization?: boolean;
  } = $props();
  let steps = $derived([
    { key: 'connections', title: '供应商密钥', href: canManageOrganization ? `/organizations/${organizationId}/settings/connections` : '' },
    { key: 'model-profiles', title: '模型与连接检查', href: canManageOrganization ? `/organizations/${organizationId}/settings/model-profiles` : '' },
    { key: 'agents', title: '发布智能体', href: workspaceId ? `/${workspaceId}/agents?template=requirements` : '' },
    { key: 'workflows', title: '发布流程', href: workspaceId ? `/${workspaceId}/workflows` : '' },
    { key: 'task', title: '运行与验收', href: returnTo || (workspaceId ? `/${workspaceId}/work-items` : '') }
  ]);
</script>

<details class="rounded-lg border border-border p-3">
  <summary class="cursor-pointer text-sm font-medium">首次运行 · {steps.find(step => step.key === current)?.title}（查看全部步骤）</summary>
<nav aria-label="首次运行配置步骤" class="mt-3">
  <ol class="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
    {#each steps as step, index (step.key)}
      <li class="min-w-0 text-sm">
        {#if step.href}<a class="underline underline-offset-4" href={step.key === 'task' ? step.href : withTaskReturn(step.href, returnTo)} aria-current={current === step.key ? 'page' : undefined}>{index + 1}. {step.title}</a>{:else}<span>{index + 1}. {step.title}</span>{/if}
        <p class="mt-1 text-xs text-muted-foreground">{current === step.key ? '当前页面' : configured.includes(step.key) ? '已有配置' : !step.href ? (index < 2 ? '由组织所有者配置' : '选择工作空间后继续') : '可前往配置'}</p>
      </li>
    {/each}
  </ol>
  <p class="mt-3 text-xs text-muted-foreground">当前页面仅表示所在位置。下一待办见下方提示；已有配置不代表连接检查或业务验收通过。流程发布后才能运行任务。</p>
</nav>
</details>
