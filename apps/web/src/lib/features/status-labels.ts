const labels: Record<string, string> = {
  open: '待处理', in_progress: '处理中', blocked: '已阻塞', completed: '已完成', canceled: '已取消',
  queued: '排队中', running: '运行中', waiting_approval: '等待审批', waiting_child: '等待子任务',
  succeeded: '已成功', failed: '已失败', pending: '待审批',
  low: '低', normal: '普通', high: '高', urgent: '紧急',
  ready: '已加载', 'not-configured': '未配置', 'not-available': '暂不可用', unauthorized: '无访问权限', error: '加载失败'
};
export function statusLabel(value: string): string { return labels[value] ?? value; }
