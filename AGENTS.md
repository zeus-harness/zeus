# Zeus 开发约定

Zeus 是面向企业团队的云端 Harness Agent。代码从 `0.1.0` 开始，HTTP 协议使用 `/api/v1`。

## 工作方式

- 先读相关模块和测试，再修改。
- 只改当前任务需要的文件。
- 新行为必须有测试或可执行验证。
- 不提交密码、Token、Cookie、私钥、数据库凭据或真实客户数据。
- 日志不得输出 Authorization、Cookie、模型密钥、连接密钥或完整 OIDC claims。

## 架构边界

- `apps/zeus-api` 保存 HTTP、数据库、OIDC、模型、Capability、调度和运行时 IO。
- `crates/zeus-core` 只保存无 IO 的领域类型、状态机和策略。
- `apps/web` 保存业务页面和 SvelteKit 服务端代码。
- `packages/ui` 保存共享视觉组件。
- shadcn-svelte 只能在 `packages/ui` 初始化。
- shadcn-svelte 组件固定放在 `packages/ui/src/lib/components/ui`。
- 不创建 `zeus-worker`。`ExecutionSupervisor` 运行在 `zeus-api` 内。
- 当前架构不使用 Redis、NATS、PGMQ 扩展、pgvector或对象存储。
- 不提供任意 shell、用户代码执行或服务器文件系统工具。

增加 crate 或 package 前，至少满足一项：

- 有独立依赖方向。
- 需要独立测试或发布。
- 被两个以上模块复用。
- 需要隔离安全能力或第三方依赖。

## Rust

- Rust 版本由 `rust-toolchain.toml` 固定。
- workspace dependency 统一写在根 `Cargo.toml`。
- `zeus-core` 不得依赖 SQLx、Axum、Tokio 或 HTTP SDK。
- 公开错误使用稳定错误码，不向客户端返回内部堆栈或 SQL。
- Run 状态变化必须经过 `zeus-core` 状态机。
- 模型可见的消息和工具事件必须写入 append-only Session Event。

验证命令：

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Web

- 使用 Svelte 5 runes。
- 使用 `$derived` 计算状态，避免用 `$effect` 同步内部状态。
- SSR 用户状态不得保存在模块全局变量中。
- 通用 UI 从 `@zeus/ui` 导入。业务组件留在 `apps/web`。
- API 类型由 `openapi/zeus.v1.yaml` 生成到 `apps/web/src/lib/api`。

验证命令：

```bash
pnpm check
pnpm test
pnpm build
```

修改 `.svelte` 或 `.svelte.ts` 后运行：

```bash
npx @sveltejs/mcp svelte-autofixer <file> --svelte-version 5
```

## PostgreSQL

- 迁移保存在 `db/migrations`，使用 SQLx 前向迁移。
- 已合并迁移不得改写。新变更增加迁移文件。
- 租户表必须有 Organization；Workspace 资源必须同时有 Workspace。
- 租户表启用并强制 RLS。
- 外键列必须有索引。
- 队列 claim 使用短事务和 `FOR UPDATE SKIP LOCKED`。
- 外部 HTTP、模型和工具调用不得放在数据库事务中。
- JSONB 只给实际查询路径建索引。
- 版本表和事件表禁止原地修改。
- 本地和新环境必须先运行 `pnpm db:bootstrap`，再运行 migration。
- HTTP 池固定使用 `zeus_http`。Runtime 池固定使用 `zeus_runtime`。不要让服务以 migration owner 身份执行请求。

## API 契约

- Rust 路由和 DTO 注解是 OpenAPI 来源。
- `openapi/zeus.v1.yaml` 必须随公开接口变化更新。
- 时间使用 UTC RFC3339，ID 使用 UUIDv7 字符串。
- 列表使用 opaque cursor。
- 错误使用 `application/problem+json`。
- 创建 Run、WorkItem 和 webhook 请求要求 `Idempotency-Key`。
- 原始密钥没有读取接口。
- Capability 输入输出 Schema 必须是有效 JSON Schema。禁止外部 `$ref`。

## 本地环境

- 本机使用 Apple `container`，不依赖 Docker Compose。
- PostgreSQL 版本为 `18.6`。
- 本地密码由 `scripts/container/init-env` 生成到 `.zeus/local.env`。
- `.zeus/local.env` 权限必须是 `0600`，脚本和日志不得打印密码。
