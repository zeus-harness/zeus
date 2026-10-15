export function approvalKindLabel(kind: string): string {
  return kind === 'resource_access' ? '权限申请' : kind === 'execution' ? '执行确认' : '历史工具审批';
}
export function approvalAuthorityLabel(kind: string): string {
  return kind === 'resource_access' ? '等待 Workspace Owner 授权；仅本次调用，有效期最长 1 小时'
    : kind === 'execution' ? '等待运行发起人确认；不授予额外权限' : '按原工具审批策略处理';
}
