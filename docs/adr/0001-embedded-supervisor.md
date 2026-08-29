# ADR 0001：内嵌 ExecutionSupervisor

状态：Accepted（Zeus 0.1.0）

## Context

Zeus 0.1.0 需要调度模型、Tool 和 Workflow 工作。工作要能恢复，也要能受 lease 和容量限制。

单独创建 `zeus-worker` 会增加部署、身份、状态同步和故障域。0.1.0 还没有足够证据证明这层拆分的收益。

计划把可信状态、调度和运行时 IO 放在明确的边界内。`zeus-core` 不能依赖数据库或网络。

## Decision

- `ExecutionSupervisor` 运行在 `apps/zeus-api` 内。
- Supervisor 只领取 Zeus 已持久化的工作。claim、lease、重试和恢复都经过 PostgreSQL。
- 数据库事务保持短。模型、Webhook、Tool 和其他外部调用在事务外执行。
- 每次状态变化先经过 `zeus-core` 状态机，再追加 Session Event 和其他持久事实。
- Supervisor 使用有界并发、取消和停机排空。旧 lease 或 fencing token 不能继续写入。
- 0.1.0 不创建 `zeus-worker`，不运行第二套调度器，也不提供任意 shell、fs 或 profile 执行能力。
- 多个 API 副本可以同时运行 Supervisor，并通过 PostgreSQL lease 分工。独立 Worker 进程和 API/Run 分开扩缩不在本 ADR 的承诺内。

## Consequences

- 本地部署简单。API、调度、状态机和审计使用同一套认证与数据库边界。
- 恢复路径短。Supervisor 可以直接从 PostgreSQL 重新 claim 未完成工作。
- API 和工作负载共享进程资源。模型阻塞、内存峰值或 Worker 缺陷可能影响 HTTP。
- 扩缩容粒度较粗。必须设置租户配额、并发上限、超时和健康检查。
- 未来拆分只能沿已验证的持久协议进行，不能把进程拆开就当成完成高可用。
