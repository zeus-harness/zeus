# ADR 0003：Session Event 只追加

状态：Accepted（Zeus 0.1.0）

## Context

Agent 的模型历史、工具结果、UI 时间线和恢复都需要同一份事实。
如果直接修改 Session 快照，回放无法知道发生过什么，审计也无法判断谁改了状态。

0.1.0 计划把 Session 作为执行事实的载体。业务快照和搜索结果可以重建，但事件事实不能被覆盖。

## Decision

- Session Event 使用 append-only 写入。已提交事件禁止 UPDATE 和 DELETE。
- 每个事件带不可变 event id、Session、tenant、sequence、event type、schema version、UTC 时间、actor、correlation 和 causation。
- 用户消息、助手消息、模型可见的工具调用和工具结果都写入 Session Event。模型可见内容必须能从事件重建。
- Run、Turn、Step、ToolCall 和 Capability 状态变化先由 `zeus-core` 校验，再在同一事务中追加事件和所需的持久状态。
- 事件 sequence 连续且按 Session 单调。跳号、跨租户引用和重复 id 拒绝。
- 纠正、撤回和失败都追加新事件。不能修改旧事件来“修正历史”。
- 事件载荷有 schema、大小和字段白名单。Secret、Authorization、Cookie 和内部堆栈不进入事件。
- Session Event 是回放和审计的事实源。日志、Trace、Metric、缓存和派生投影不是事实源，也不能反写事件。

## Consequences

- 重启、回放和审计使用同一条事件链。客户端可以按 event id 去重。
- 事件表只增不改，存储会持续增长。需要保留策略、分页、压缩或新事件表达过期状态。
- schema 兼容和事件版本很重要。改字段要新增版本，不得悄悄改变旧事件含义。
- 脱敏不能通过改历史事件完成。敏感数据应在写入前拒绝或按 0.1.0 的数据策略单独处理。
- UI 和查询看到的是投影。投影损坏可以重建，不能用投影修补权威事件。
