<script lang="ts">
  import { Button } from '@zeus/ui/components/ui/button';
  import { Input } from '@zeus/ui/components/ui/input';
  import { Label } from '@zeus/ui/components/ui/label';
  let { query, status, selected, nextCursor }: { query: string; status: string; selected: string; nextCursor?: string | null } = $props();
  let nextHref = $derived(`?${new URLSearchParams({ item_q: query, status, work_item_id: selected, item_cursor: nextCursor ?? '' })}`);
</script>

<form method="GET" class="w-full space-y-2" aria-label="查找历史工作项">
  <Label for="item-query">查找工作项标题（包含历史记录）</Label>
  <input type="hidden" name="status" value={status} />
  <input type="hidden" name="work_item_id" value={selected} />
  <div class="flex gap-2"><Input id="item-query" name="item_q" value={query} placeholder="输入关键词查找，再从下方选择工作项" maxlength={200} /><Button type="submit" variant="outline">查找工作项</Button></div>
  {#if nextCursor}<a class="inline-block text-sm underline" href={nextHref}>更多匹配工作项</a>{/if}
</form>
