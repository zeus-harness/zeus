<script lang="ts">
  import { enhance } from '$app/forms';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';
  import { Label } from '@zeus/ui/components/ui/label';
  import { Textarea } from '@zeus/ui/components/ui/textarea';
  import { displayTimestamp } from '$lib/display-timestamp';
  import type { WorkItem, WorkItemReview, WorkItemArchive } from '$lib/api/work-items';
  let { item, review, archive, canArchive, eligible, report = '' }: {
    item: WorkItem;
    review: WorkItemReview | undefined;
    archive: WorkItemArchive | null;
    canArchive: boolean;
    eligible: boolean;
    report?: string;
  } = $props();
  let submitting = $state(false);
  let interrupted = $state(false);
  let summary = $derived(report);
</script>

<section id="closure" aria-label="验证与归档" class="mt-6 scroll-mt-24">
  <Card.Root>
    <Card.Header><Card.Title>验证与归档</Card.Title><Card.Description>Owner 核对最新成功结果、记录问题解决证据后归档。归档后目标与执行记录保留，停止新增尝试。</Card.Description></Card.Header>
    <Card.Content class="space-y-4">
      {#if item.archived_at}
        <p role="status" class="font-medium">工作项已归档 · {displayTimestamp(item.archived_at)}</p>
        {#if archive}
          <p class="whitespace-pre-wrap break-words text-sm">{archive.resolution_summary}</p>
          <p class="break-all text-xs text-muted-foreground">验证运行：{archive.run_id} · 验收：{archive.review_id}<br />归档人：{archive.archived_by}</p>
        {:else}<p role="alert" class="text-sm">归档证据暂不可用，请刷新后重试。</p>{/if}
      {:else if canArchive}
        <form method="POST" action="?/archive" class="space-y-4" use:enhance={({ cancel }) => {
          if (submitting) { cancel(); return; }
          submitting = true;
          interrupted = false;
          return async ({ result, update }) => {
            try {
              if (result.type === 'error') interrupted = true;
              else await update({ reset: false });
            } finally { submitting = false; }
          };
        }}>
          <input type="hidden" name="review_id" value={review?.id ?? ''} />
          <input type="hidden" name="revision" value={item.revision} />
          <Label for="resolution-summary">问题解决验证报告</Label>
          <Textarea id="resolution-summary" name="resolution_summary" required maxlength={4000} rows={4} bind:value={summary} placeholder="说明核对了哪些结果、如何验证目标达成，以及相关证据。" />
          <label class="flex items-start gap-2 text-sm"><input type="checkbox" name="verified" value="yes" required disabled={!eligible || submitting} />我已验证目标达成，并核对最新成功运行的验收结果。</label>
          {#if !eligible}<p class="text-sm text-muted-foreground">请先由 Owner 接受最新成功运行的结果；目标修改后需要重新验收，所有运行须结束。</p>{/if}
          {#if interrupted}<p role="alert" class="text-sm text-destructive">连接中断，归档尚未确认。报告已保留，请刷新核对状态后重试。</p>{/if}
          <Button type="submit" disabled={!eligible || submitting}>{submitting ? '正在归档…' : '验证完成并归档'}</Button>
        </form>
      {:else}<p class="text-sm text-muted-foreground">由当前 Workspace Owner 验证结果并归档；工具批准或运行成功不会自动归档。</p>{/if}
    </Card.Content>
  </Card.Root>
</section>
