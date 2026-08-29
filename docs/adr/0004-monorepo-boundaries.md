# ADR 0004：Monorepo 模块边界

状态：Accepted（Zeus 0.1.0）

## Context

Zeus 同时有 Rust 服务、无 IO 的领域逻辑和 SvelteKit Web。边界不清会让 HTTP、数据库和领域状态机互相渗透，也会让共享 UI 变成业务依赖。

0.1.0 需要一个小而明确的模块化单体。增加 crate 或 package 只有在依赖方向、测试/发布、复用或安全隔离确实需要时才有理由。

## Decision

- `apps/zeus-api` 保存 HTTP、数据库、OIDC、模型、Capability、调度和运行时 IO。
- `crates/zeus-core` 只保存无 IO 的领域类型、状态机和策略。它不得依赖 SQLx、Axum、Tokio 或 HTTP SDK。
- `ExecutionSupervisor` 属于 `apps/zeus-api`。不创建 `zeus-worker`。
- `apps/web` 保存业务页面和 SvelteKit 服务端代码。业务组件留在这里。
- `packages/ui` 只保存共享视觉组件。shadcn-svelte 只在这里初始化，组件固定放在 `packages/ui/src/lib/components/ui`。
- Rust 路由和 DTO 注解是 OpenAPI 来源。公开接口变化时同步更新 `openapi/zeus.v1.yaml` 和 Web API 类型。
- `db/migrations` 只放 PostgreSQL SQLx 前向迁移。核心领域代码不能直接读取数据库或发 HTTP。
- Package 之间只沿声明的依赖方向引用。新边界必须同时补测试和文档，不用跨目录复制实现来绕开边界。

## Consequences

- 领域状态机可以独立测试，且不会被运行时依赖污染。
- API 负责组合真实 IO，故障和凭据边界集中，调度也不会漂到另一个未定义的进程。
- Web 与共享 UI 的责任清楚。修改公共接口时需要同步生成类型和检查 Web。
- 模块数量少时会有一些适配代码。不能为了减少几行代码而反向依赖。
- 以后拆进程或新增 crate 需要新的 ADR、依赖图和恢复证据。
