export function runRecovery(status: string, code: string | null): string | null {
  if (status === 'canceled') return '运行已取消。确认仍需处理后可创建重试 Run；原运行记录保留。';
  if (status !== 'failed') return null;
  switch (code) {
    case 'model_timeout':
    case 'model_transport_error':
    case 'model_stream_interrupted':
    case 'model_server_error':
      return '检查模型服务是否可用及请求超时设置。恢复后可创建重试 Run；供应商可能已产生部分用量。';
    case 'model_rate_limited':
      return '模型服务限流。等待额度恢复或降低并发后再创建重试 Run。';
    case 'model_request_rejected':
    case 'invalid_model_configuration':
    case 'runtime_configuration_unavailable':
      return '请 Workspace Owner 检查模型地址、模型 ID、连接密钥及配置是否已归档，再创建重试 Run。';
    case 'token_budget_exceeded':
    case 'token_budget_exhausted':
    case 'max_steps_exceeded':
    case 'run_timeout':
      return '运行达到预算或执行上限。缩小需求范围，或发布调整限额的新 Workflow 版本，再从工作项启动新运行。';
    default:
      return '先核对事件时间线、工具结果与审批记录，确认失败原因及是否已产生业务操作，再决定是否创建重试 Run。';
  }
}
