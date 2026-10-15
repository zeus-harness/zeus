import type { Run } from '$lib/api/runs';
import type { WorkItem, WorkItemReview } from '$lib/api/work-items';

export type TaskSummary = { item: WorkItem; run?: Run; progress: { label: string; detail: string; stage: number } };

/** A successful attempt remains awaiting human acceptance; failure never implies resolution. */
export function taskState(item: Pick<WorkItem, 'archived_at' | 'status'> & Partial<Pick<WorkItem, 'revision'>>, run?: Pick<Run, 'id' | 'status'>, review?: Pick<WorkItemReview, 'run_id' | 'decision'> & Partial<Pick<WorkItemReview, 'work_item_revision'>>) {
  if (item.archived_at) return { label: '已归档', detail: '目标已验证，结果与操作记录已保留。', stage: 4 };
  if (item.status === 'canceled') return { label: '已取消', detail: '目标已取消，历史记录保留。', stage: 0 };
  if (!run) return { label: '待开始', detail: '目标已保存，选择执行方式后开始处理。', stage: 0 };
  if (run.status === 'waiting_approval') return { label: '等待审批', detail: 'Agent 已暂停。核对下方具体内容，批准后从保存的进度继续。', stage: 1 };
  if (run.status === 'failed' || run.status === 'canceled') return { label: run.status === 'failed' ? '需要处理' : '尝试已取消', detail: '这次尝试没有完成目标。核对执行记录后决定是否重试。', stage: 1 };
  if (run.status === 'succeeded') {
    if (review && item.revision !== undefined && review.work_item_revision !== undefined && review.work_item_revision !== item.revision - 1) return { label: '待重新验收', detail: '目标已更新，请按当前目标重新核对结果。', stage: 2 };
    if (review?.run_id === run.id && review.decision === 'accepted') return { label: '待验证归档', detail: '结果已接受。由负责人验证目标达成后归档。', stage: 3 };
    if (review?.run_id === run.id && review.decision === 'needs_changes') return { label: '需要修改', detail: '结果仍需修改，按验收意见继续处理。', stage: 2 };
    return { label: '待验收', detail: 'Agent 已提交结果，请核对后接受或提出修改意见。', stage: 2 };
  }
  return { label: '进行中', detail: run.status === 'waiting_child' ? '正在等待关联任务，进度已保存。' : 'Agent 正在处理。可离开页面，回来后继续查看。', stage: 1 };
}

export function messageContent(payload: unknown): string {
  if (typeof payload === 'string') return payload;
  if (payload && typeof payload === 'object' && 'content' in payload && typeof payload.content === 'string') return payload.content;
  return '';
}
