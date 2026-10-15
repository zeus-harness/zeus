<script lang="ts">
  import { Button } from '@zeus/ui/components/ui/button';
  import type { components } from '$lib/api/generated/schema';
  type Schema = components['schemas'];
  let { conversation, agents, workflows, workspaceId, owner, canOperate }: {
    conversation: string;
    agents: Schema['ImAgentMember'][];
    workflows: Schema['WorkflowResponse'][];
    workspaceId: string | null;
    owner: boolean;
    canOperate: boolean;
  } = $props();
</script>
<section class="mt-5 space-y-3 border-t pt-4" aria-label="会话 Agent">
  <h3 class="text-sm font-medium">Agent 成员</h3>
  {#each agents as agent (agent.id)}
    <div class="rounded-lg bg-muted/50 p-3 text-sm">
      <p class="font-medium">{agent.display_name} <span class="text-xs text-muted-foreground">Agent</span></p>
      <p class="mt-1 text-xs text-muted-foreground">仅处理明确交给它的消息 · 固定流程版本</p>
      <p class="mt-1 text-xs text-muted-foreground">从第 {agent.joined_sequence} 条消息起可调用；不读取其他历史。</p>
      {#if owner}<form method="POST" action="?/mutate" class="mt-2">
        <input type="hidden" name="operation" value="remove_agent" />
        <input type="hidden" name="conversation" value={conversation} />
        <input type="hidden" name="agent_member_id" value={agent.id} />
        <Button type="submit" variant="outline" size="sm">移出会话</Button>
      </form>{/if}
    </div>
  {:else}<p class="text-sm text-muted-foreground">还没有 Agent。加入后可将消息交给它，回复会回到当前会话。</p>{/each}
  {#if owner}
    {#if workspaceId && canOperate}
      <form method="POST" action="?/mutate" class="space-y-2">
        <input type="hidden" name="operation" value="add_agent" />
        <input type="hidden" name="conversation" value={conversation} />
        <label class="block text-sm">从当前 Workspace 的已发布流程添加
          <select name="workflow_version_id" required class="mt-2 w-full rounded border bg-background p-2" aria-label="Agent 使用的已发布流程">
            <option value="">选择流程</option>
            {#each workflows as workflow (workflow.id)}<option value={workflow.active_version_id ?? ''}>{workflow.name}</option>{/each}
          </select>
        </label>
        <Button type="submit" variant="outline" size="sm" disabled={!workflows.length}>添加 Agent</Button>
      </form>
      {#if !workflows.length}<a class="block text-sm underline" href={`/${workspaceId}/workflows`}>先配置并发布流程</a>{/if}
    {:else}<p class="text-sm text-muted-foreground">添加或调用 Agent 需要相应 Workspace 的执行权限。</p><a class="block text-sm underline" href="/workspaces">选择 Workspace</a>{/if}
  {/if}
  <p class="text-xs text-muted-foreground">移出会停止回传后续回复；已发起的任务需在运行详情单独取消。</p>
</section>
