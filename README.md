# Zeus

Zeus 是面向企业团队的云端 Harness Agent。它把 Agent、流程、运行记录、审批和团队经验保存在共享服务中。

当前版本：`0.1.0`
HTTP 协议：`/api/v1`

## 架构

- Rust + Axum API。
- `zeus-api` 内嵌 `ExecutionSupervisor`。
- PostgreSQL 18.6 保存租户数据、运行队列、事件、审计和全文检索。
- SvelteKit 5 控制台。
- shadcn-svelte 位于 `packages/ui`。
- 本地使用 Apple `container`。

不需要 Redis，也没有独立 `zeus-worker`。

## 本地启动

```bash
scripts/container init-env
scripts/container up
```

`up` 会创建 Zeus 专用网络，启动 PostgreSQL，创建数据库角色，执行 migration，随后启动内嵌 Supervisor 的 `zeus-api` 和 Web。缺少本地镜像时会自动构建。代码变化后重新构建并启动：

```bash
scripts/container build all
scripts/container up all
```

本地 API 构建会在 `.zeus` 下创建短生命周期的 Cargo vendor 上下文，让 BuildKit 离线编译；Web 在宿主机完成 SvelteKit 构建后再封装。构建退出时会删除临时上下文。云端构建仍使用生产 Containerfile。

常用运维命令：

```bash
scripts/container status all
scripts/container logs api -n 100
scripts/container down all
```

需要从宿主机运行数据库检查时再加载本地环境：

```bash
set -a
source .zeus/local.env
set +a
```

容器启动脚本会创建 `zeus_http` 和 `zeus_runtime` 固定角色。生产数据库的登录账号由部署平台创建：HTTP 登录账号只能切换到 `zeus_http`，Runtime 登录账号只能切换到 `zeus_runtime`。Migration 使用单独的 owner 连接。

数据库冒烟测试：

```bash
scripts/db/check-schema
psql "$DATABASE_URL" --set ON_ERROR_STOP=1 --file scripts/db/rls-smoke.sql
psql "$DATABASE_URL" --set ON_ERROR_STOP=1 --file scripts/db/queue-smoke.sql
psql "$DATABASE_URL" --set ON_ERROR_STOP=1 --file scripts/db/bcd-smoke.sql
psql "$DATABASE_URL" --set ON_ERROR_STOP=1 --file scripts/db/efg-smoke.sql
psql "$DATABASE_URL" --set ON_ERROR_STOP=1 --file scripts/db/runtime-fencing-smoke.sql
scripts/db/queue-concurrency
```

不使用容器时，API 和 Web 也可以分别启动：

```bash
pnpm dev:api
pnpm dev:web
```

Web SSR 通过 `ZEUS_API_URL` 请求 API。Apple `container` 1.0.0 本地脚本会注入同网络 API 地址；Kubernetes 使用 Service 地址。当前 Workspace 来自登录 Session，不使用部署级固定 Workspace。

## 已实现链路

- WorkItem 创建、分配、状态更新、外部引用和附件。
- Session、Run、Trace、Approval 与 SSE。
- Experience Candidate 审阅、发布、撤回、PostgreSQL FTS 和运行时注入记录。
- 持久化 Child Run，包含独立 Session、权限与预算收窄、父子恢复和取消传播。
- Kubernetes API/Web/Migration、OpenTelemetry Collector、HPA 基线和故障手册。

容量驱动默认要求 1,000 个用户 Session、100 个 Workspace、200 个并发 Run 和 1,800 秒测试窗口：

```bash
pnpm load:capacity -- --config /secure/path/zeus-capacity.json
```

配置格式和通过条件见 `docs/runbooks/capacity-test.md`。真实云 KMS、企业 IdP、托管 PostgreSQL、集群网络策略和容量结果需要在生产形态环境验收。

## 验证

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
pnpm check
pnpm test
pnpm build
```

技术设计见 `docs/TECHNICAL_SPEC.md`。开发阶段见 `docs/IMPLEMENTATION_PLAN.md`。
