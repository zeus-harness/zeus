import type { RunEvent } from '$lib/api/runs';
import { getTerminalRunStatus } from './run-stream';

export function eventLabel(event: RunEvent): string {
  const terminal = getTerminalRunStatus(event);
  if (terminal) return { succeeded: '运行完成', failed: '运行失败', canceled: '运行已取消' }[terminal] ?? terminal;
  const labels: Record<string, string> = {
    run_queued: '进入队列', 'run.claimed': '领取执行', 'runtime.started': '开始执行',
    'experience.selection_completed': '经验选择完成', 'model.requested': '请求模型',
    'model.completed': '模型响应完成', 'tool.requested': '请求工具调用',
    'tool.started': '执行工具', 'tool.result': '工具执行结果',
    approval_resolved: '审批已处理', 'run.status_changed': '运行状态更新'
  };
  return labels[event.event_type] ?? event.event_type;
}
