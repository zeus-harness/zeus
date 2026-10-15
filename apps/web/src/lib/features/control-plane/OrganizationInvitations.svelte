<script lang="ts">
  import { enhance } from '$app/forms';
  import { Button } from '@zeus/ui/components/ui/button';
  import { Input } from '@zeus/ui/components/ui/input';
  import type { components } from '$lib/api/generated/schema';
  let { invitations, loadError, message }: { invitations: components['schemas']['InvitationResponse'][]; loadError: string; message: string } = $props();
  let busy = $state(false);
  const statuses: Record<string, string> = { pending: '等待接受', accepted: '已接受', expired: '已过期', revoked: '已撤销' };
  const roles: Record<string, string> = { member: '成员', auditor: '审计员', owner: 'Owner' };
  function submit() { busy = true; return async ({ update }: { update: () => Promise<void> }) => { try { await update(); } finally { busy = false; } }; }
</script>

<section class="mt-6 space-y-4 rounded-xl border p-5" aria-label="组织邀请">
  <h2 class="text-lg font-semibold">邀请同事加入组织</h2>
  <p class="text-sm text-muted-foreground">新用户通过邮件注册后加入组织；已有用户使用受邀邮箱登录并接受邀请。邀请有效期为 7 天，仅授予所选组织角色，不授予工作空间权限。</p>
  {#if message}<p role="status" class="text-sm">{message}</p>{/if}
  <form method="POST" action="?/invitation" use:enhance={submit} class="flex flex-wrap items-end gap-3">
    <input type="hidden" name="operation" value="create" />
    <label class="grid flex-1 gap-2 text-sm">受邀邮箱<Input name="email" type="email" required maxlength={254} placeholder="colleague@example.com" /></label>
    <label class="grid gap-2 text-sm">组织角色<select name="organization_role" class="rounded-md border bg-background p-2"><option value="member">成员</option><option value="auditor">审计员</option><option value="owner">Owner（组织管理权限）</option></select></label>
    <Button type="submit" disabled={busy}>{busy ? '处理中…' : '发送邀请'}</Button>
  </form>
  {#if loadError}<p role="alert">{loadError}</p>{/if}
  <p class="text-xs text-muted-foreground">最近 200 条邀请。重发会使旧邀请链接失效；撤销不会移除已加入的成员。</p>
  <div class="overflow-x-auto"><table class="w-full text-left text-sm"><thead><tr class="border-b"><th class="p-2">邮箱</th><th class="p-2">角色</th><th class="p-2">状态</th><th class="p-2">到期时间</th><th class="p-2">操作</th></tr></thead><tbody>
    {#each invitations as invitation (invitation.id)}
      <tr class="border-b"><td class="p-2">{invitation.email}</td><td class="p-2">{roles[invitation.organization_role] ?? invitation.organization_role}</td><td class="p-2">{statuses[invitation.status] ?? invitation.status}</td><td class="p-2">{invitation.expires_at.replace('T', ' ').replace('Z', ' UTC')}</td><td class="p-2">
        {#if invitation.status === 'pending'}<form method="POST" action="?/invitation" use:enhance={submit} class="flex gap-2"><input type="hidden" name="invitation_id" value={invitation.id} /><Button type="submit" variant="outline" name="operation" value="resend" disabled={busy}>重发</Button><Button type="submit" variant="outline" name="operation" value="revoke" disabled={busy}>撤销</Button></form>{:else}—{/if}
      </td></tr>
    {:else}<tr><td colspan="5" class="p-4 text-muted-foreground">暂无邀请记录。</td></tr>{/each}
  </tbody></table></div>
</section>
