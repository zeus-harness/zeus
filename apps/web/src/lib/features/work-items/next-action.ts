export function workItemNextAction(status: string, runStatus: string | undefined, hasWorkflow: boolean, canEdit: boolean) {
  if (status === 'canceled') return { title: '任务已取消', description: canEdit ? '要继续处理，请先将状态恢复为待处理。' : '请联系任务负责人恢复任务。', action: canEdit ? '恢复任务' : '', href: '#update-status' };
  if (runStatus === 'waiting_approval') return { title: '执行正在等待审批', description: '先查看需要授权的操作，再决定是否批准。', action: '查看运行与审批', href: '#execution' };
  if (runStatus && ['queued', 'running', 'waiting_child'].includes(runStatus)) return { title: '任务正在执行', description: '查看本次运行进度，完成后再核对结果。', action: '查看执行进度', href: '#execution' };
  if (runStatus === 'succeeded') return { title: '运行已完成', description: '请核对输出及验收记录；运行成功不代表业务验收通过。', action: '查看结果与验收', href: '#acceptance' };
  if (!hasWorkflow) return { title: '先准备可运行的流程', description: '接入模型，发布智能体与流程后，即可回来运行这项任务。', action: '查看配置入口', href: '#launch-run' };
  return { title: runStatus === 'failed' ? '上次运行失败' : '可以开始处理', description: runStatus === 'failed' ? '查看失败原因，调整配置后再发起运行。' : '选择已发布流程，开始处理这项任务。', action: runStatus === 'failed' ? '查看失败记录' : '选择流程并运行', href: runStatus === 'failed' ? '#execution' : '#launch-run' };
}
