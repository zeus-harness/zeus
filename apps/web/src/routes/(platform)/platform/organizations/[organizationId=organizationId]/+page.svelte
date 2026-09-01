<script lang="ts">
  import { ArrowLeft } from '@lucide/svelte';

  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';
  import { Input } from '@zeus/ui/components/ui/input';
  import { Label } from '@zeus/ui/components/ui/label';
  import { NativeSelect, NativeSelectOption } from '@zeus/ui/components/ui/native-select';
  import { Textarea } from '@zeus/ui/components/ui/textarea';

  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import type { ActionData, PageData } from './$types';

  let { data, form }: { data: PageData; form: ActionData } = $props();
  let organization = $derived(data.organization);
</script>

<svelte:head><title>Zeus · {organization.name}</title></svelte:head>

<main class="px-5 py-7 lg:px-8 lg:py-9">
  <a class="mb-5 inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground" href="/platform/organizations"><ArrowLeft class="size-4" />返回 Organizations</a>
  <PageHeader eyebrow="Platform Organization" title={organization.name} description="平台控制面修改租户状态；读取租户数据前必须建立限时支持会话。">
    {#snippet actions()}<Badge variant={organization.status === 'active' ? 'secondary' : 'outline'}>{organization.status}</Badge>{/snippet}
  </PageHeader>
  {#if form?.type === 'error'}<p class="mt-6 rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive" role="alert">{form.message}</p>{/if}

  <div class="mt-7 grid gap-6 xl:grid-cols-2">
    <Card.Root>
      <Card.Header><Card.Title>Organization 配置</Card.Title><Card.Description>状态动作与元数据修改分开提交。</Card.Description></Card.Header>
      <Card.Content>
        <form method="POST" action="?/update" class="space-y-4">
          <input type="hidden" name="revision" value={organization.revision} />
          <div class="space-y-2"><Label for="platform-detail-name">名称</Label><Input id="platform-detail-name" name="name" value={organization.name} required /></div>
          <div class="space-y-2"><Label for="platform-detail-slug">Slug</Label><Input id="platform-detail-slug" name="slug" value={organization.slug} required disabled={organization.status === 'active'} /></div>
          {#if organization.status === 'active'}<input type="hidden" name="slug" value={organization.slug} />{/if}
          <div class="space-y-2"><Label for="platform-detail-mode">身份设置模式</Label><NativeSelect id="platform-detail-mode" name="identity_settings_mode" value={organization.identity_settings_mode}><NativeSelectOption value="self_service">Organization 自助管理</NativeSelectOption><NativeSelectOption value="platform_managed">平台托管</NativeSelectOption></NativeSelect></div>
          <Button type="submit">保存配置</Button>
        </form>
      </Card.Content>
    </Card.Root>

    <Card.Root>
      <Card.Header><Card.Title>限时租户访问</Card.Title><Card.Description>验证原生密码和 TOTP。访问最长 60 分钟，不创建 Membership。</Card.Description></Card.Header>
      <Card.Content>
        <form method="POST" action="?/enterTenant" class="space-y-4">
          <div class="space-y-2"><Label for="support-reason">访问原因</Label><Textarea id="support-reason" name="reason" minlength={10} maxlength={500} required /></div>
          <div class="grid gap-4 sm:grid-cols-2"><div class="space-y-2"><Label for="support-password">当前密码</Label><Input id="support-password" name="password" type="password" autocomplete="current-password" required /></div><div class="space-y-2"><Label for="support-totp">TOTP</Label><Input id="support-totp" name="totp_code" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" required /></div></div>
          <div class="space-y-2"><Label for="support-duration">时长</Label><NativeSelect id="support-duration" name="duration_minutes" value="60"><NativeSelectOption value="15">15 分钟</NativeSelectOption><NativeSelectOption value="30">30 分钟</NativeSelectOption><NativeSelectOption value="60">60 分钟</NativeSelectOption></NativeSelect></div>
          <Button type="submit" disabled={organization.status === 'archived' || organization.status === 'provisioning'}>进入 Organization</Button>
        </form>
      </Card.Content>
    </Card.Root>

    <Card.Root>
      <Card.Header><Card.Title>生命周期</Card.Title><Card.Description>恢复归档 Organization 后会先进入 suspended。</Card.Description></Card.Header>
      <Card.Content class="flex flex-wrap gap-2">
        {#each ['activate', 'suspend', 'archive', 'restore'] as transition (transition)}
          <form method="POST" action="?/transition">
            <input type="hidden" name="revision" value={organization.revision} />
            <input type="hidden" name="transition" value={transition} />
            <Button type="submit" variant={transition === 'archive' ? 'destructive' : 'outline'} size="sm">{transition}</Button>
          </form>
        {/each}
      </Card.Content>
    </Card.Root>

    <Card.Root>
      <Card.Header><Card.Title>Provisioning Owner</Card.Title><Card.Description>{organization.pending_owner_email ?? '当前没有待处理的首位 Owner 邀请。'}</Card.Description></Card.Header>
      <Card.Content class="space-y-4">
        <form method="POST" action="?/resendInvitation"><input type="hidden" name="revision" value={organization.revision} /><Button type="submit" variant="outline" disabled={!organization.pending_owner_invitation_id}>重新发送</Button></form>
        <form method="POST" action="?/replaceInvitation" class="flex gap-2"><input type="hidden" name="revision" value={organization.revision} /><Input name="owner_email" type="email" placeholder="new-owner@example.com" required /><Button type="submit" variant="outline" disabled={organization.status !== 'provisioning'}>替换 Owner</Button></form>
      </Card.Content>
    </Card.Root>
  </div>
</main>
