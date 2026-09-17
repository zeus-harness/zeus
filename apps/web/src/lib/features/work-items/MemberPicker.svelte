<script lang="ts">
  import { Input } from '@zeus/ui/components/ui/input';
  import { NativeSelect, NativeSelectOption } from '@zeus/ui/components/ui/native-select';
  import type { MemberOption } from '$lib/server/member-options';
  let { id, name = 'assignee_user_id', members, value = '', emptyLabel = '未分配', limited = false }: {
    id: string; name?: string; members: MemberOption[]; value?: string; emptyLabel?: string; limited?: boolean;
  } = $props();
  let query = $state('');
  let selected = $state<string | undefined>();
  let current = $derived(selected ?? value);
  let options = $derived(members.filter(member => member.user_id === current || `${member.display_name} ${member.email}`.toLowerCase().includes(query.toLowerCase())));
</script>
<div class="space-y-2">
  <Input aria-label="搜索成员姓名或邮箱" placeholder="搜索姓名或邮箱" bind:value={query} />
  <NativeSelect {id} {name} value={current} onchange={(event) => selected = event.currentTarget.value} class="w-full">
    <NativeSelectOption value="">{emptyLabel}</NativeSelectOption>
    {#if current && !members.some(member => member.user_id === current)}<NativeSelectOption value={current}>当前已选成员（无法读取资料）</NativeSelectOption>{/if}
    {#each options as member (member.user_id)}<NativeSelectOption value={member.user_id}>{member.display_name || member.email}{member.display_name && member.email ? ` · ${member.email}` : ''}</NativeSelectOption>{/each}
  </NativeSelect>
  {#if limited}
    <details class="text-xs text-muted-foreground"><summary class="cursor-pointer">使用已知成员标识（高级）</summary><Input aria-label="成员标识" class="mt-2" value={current} oninput={(event) => selected = event.currentTarget.value.trim()} placeholder="由管理员提供的成员 UUID" /><p class="mt-2">仅用于当前列表未展示的成员；保存时仍由服务器检查权限。</p></details>
  {/if}
  {#if query && options.length === 0}<p class="text-xs text-muted-foreground">没有匹配的可选成员。</p>{/if}
</div>
