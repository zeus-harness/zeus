# ADR 0002：只使用 PostgreSQL

状态：Accepted（Zeus 0.1.0）

## Context

0.1.0 需要一个能同时保存租户数据、Session Event、幂等记录、审批、lease 和执行状态的权威存储。
这些写入需要同一事务、RLS 和可检查的租户边界。

PGMQ、Redis、NATS 和其他队列可以提供部分能力，但会增加部署、版本和故障恢复面。PGMQ 的固定提交只用于研究，不代表要接入扩展。

## Decision

- PostgreSQL 18.6 是 Zeus 0.1.0 的唯一权威数据库。
- 业务表、Session Event、幂等记录、Capability 运行记录、lease、审计和调度状态都写入 PostgreSQL。
- 迁移放在 `db/migrations`，使用 SQLx 前向迁移。已合并迁移不改写。
- 租户表启用并强制 RLS。外键列有索引。租户、Organization、Workspace 和资源 scope 在数据库与应用层都校验。
- 队列 claim 使用短事务和 `FOR UPDATE SKIP LOCKED`。不引入 Redis、NATS、PGMQ 扩展、pgvector 或对象存储。
- 大功能或新的存储后端必须另开 ADR。研究记录中的 PGMQ 只能提供语义对照。

## Consequences

- 事务边界清楚。事件、幂等、lease 和业务状态可以一起提交或一起回滚。
- 运维组件少。开发、测试和恢复只需要维护 PostgreSQL。
- 数据库承担队列、审计和事件增长压力。必须设置索引、配额、保留和归档策略，并做容量验证。
- 不使用专用消息队列的吞吐和隔离能力。超过 0.1.0 目标后，新增后端要证明租户、幂等和审计语义不变。
- PostgreSQL 不会自动解决授权。RLS、`zeus-core` 策略和服务端 scope 校验仍是必需的。
