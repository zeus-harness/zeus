<script lang="ts">
  import { updated } from '$app/state';
  import { Button } from '@zeus/ui/components/ui/button';
  let acknowledged = $state(false);
  function refresh() {
    // Normal reload retains the application's beforeunload protection and Studio's tab draft.
    window.location.reload();
  }
</script>

{#if updated.current}
  <aside role="status" aria-label="版本更新" class="sticky top-0 z-50 flex flex-wrap items-center justify-center gap-3 border-b border-border bg-background p-3 text-sm">
    <p>新版本已就绪。会话草稿会保留；其他未提交表单请先保存。</p>
    <label class="flex items-center gap-2"><input type="checkbox" bind:checked={acknowledged} />已确认输入已保存</label>
    <Button size="sm" disabled={!acknowledged} onclick={refresh}>刷新到新版本</Button>
  </aside>
{/if}
