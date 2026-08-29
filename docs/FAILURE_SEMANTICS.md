# Zeus 失败语义

## HTTP

客户端错误和服务错误使用 `application/problem+json`。稳定字段：

```json
{
  "type": "https://zeus.example.com/problems/validation_failed",
  "title": "Validation failed",
  "status": 422,
  "code": "validation_failed",
  "detail": "request validation failed",
  "request_id": "019..."
}
```

`detail` 不包含 SQL、堆栈、Token、Cookie 或上游密钥。

## Run

- 自动网络重试保留在同一个 Run，并增加 Attempt。
- 人工重试创建新 Run，并写入 `retry_of_run_id`。
- 运行失败写 `error_code` 和安全的 `error_detail`。
- terminal Run 不接受新状态变化。
- 租约过期允许新副本重新领取。
- 旧副本提交时 fence 不匹配，更新返回 false。

## Tool

- `required` 或 `supported` 可带幂等键重试。
- `unavailable` 不自动重试。
- 审批等待期间释放 Run 租约。
- 审批拒绝写入持久工具结果。
- 工具超时也写入配对结果。
- 输入不符合 Capability Schema 时，调用不会越过校验边界。
- 输出不符合 Capability Schema 时，写入 `capability_output_schema_violation` 配对结果。
- Schema 无效时 Run 以 `invalid_capability_schema` 失败，不执行 Capability。
- 外部系统已经执行但响应丢失时，Zeus 记录 `outcome_unknown`，不猜测成功或失败。

## 模型

- 连接失败、限流和 5xx 可以按 Workflow 策略重试。
- 无效响应和安全策略错误不自动重试。
- 流式响应中断时不写入不完整助手消息。
- 已写入工具调用后发生取消，必须补写合成工具结果。

## 数据库

- claim 和 finish 使用短事务。
- 外部 HTTP 不在事务中执行。
- RLS 上下文缺失时查询应返回空集或被拒绝。
- HTTP 连接无法切换到 `zeus_http` 时进程启动失败。Runtime 连接无法切换到 `zeus_runtime` 时 Supervisor 启动失败。
- Migration 失败会阻止 API readiness。
- `LISTEN/NOTIFY` 丢失不会丢 Run，轮询负责恢复。

## 进程退出

API 收到终止信号后停止领取新 Run。活动任务等待 60 秒。超时任务中止并等待租约过期，由其他副本恢复。
