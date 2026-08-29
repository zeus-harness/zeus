# Zeus 实现计划

## 状态标记

- `done`：代码和静态验证已完成。
- `active`：已有可运行链路，阶段目标还没全部完成。
- `pending`：还未实现。
- `external`：需要企业 IdP、云 KMS 或生产集群。

## A：仓库基线

状态：`done`

- 安全备份旧工作区。
- 创建 `AGENTS.md`。
- 创建 Cargo、pnpm 和 Turbo workspace。
- 建立 `zeus-core`、`zeus-api`、SvelteKit 和 `packages/ui`。
- 在 `packages/ui` 初始化 shadcn-svelte。
- 建立 Apple `container`、OCI 和 Kubernetes 文件。
- 写入技术规范、研究记录、失败语义、威胁模型和 ADR。

本机验收：

- PostgreSQL 18.6 已通过 Apple `container` 启动、迁移和连接检查。
- Rust、Svelte、pnpm 和 Turbo 门禁通过。
- API 健康检查、元数据和 OpenAPI 已实机请求。
- OCI 构建进入 BuildKit 后被 DNS 解析失败阻断。Apple container 已有同类
  [问题 #1033](https://github.com/apple/container/issues/1033)；代码编译和 Containerfile 静态检查不受影响。

## B：数据库与租户

状态：`done`

- 完成基础表、外键、索引、约束、RLS 和审计写入。
- 完成 OIDC discovery、Authorization Code + PKCE、回调校验、JIT 用户与 Group Mapping。
- 完成 Web Session、Service Account、Organization/Workspace 成员和 RBAC。
- Session Token 只保存 SHA-256 摘要。Service Account Token 使用 Argon2。
- OIDC、Connection Secret 使用 envelope encryption，本地实现为 AES-256-GCM。
- HTTP 连接固定使用 `zeus_http`。Supervisor 连接固定使用 `zeus_runtime`。
- `run_usage` 通过受租户上下文约束的 security-definer 函数读取，HTTP 角色没有表级读取权限。
- 跨 Workspace 请求、JIT 角色映射、受限角色 CRUD 和密钥只写响应已通过真实 PostgreSQL 测试。

云 KMS 和真实企业 IdP 联调属于 H。代码不把本地 envelope key 当成生产 KMS。

## C：控制面

状态：`done`

- 完成 Agent、Workflow、不可变 Version、Model Profile、Connection、Capability、Schedule 和 Webhook API。
- 可变资源使用 `revision`、ETag 和 `If-Match`。旧 revision 返回 `412`。
- 列表使用 opaque cursor。Run 和 Webhook 创建使用 `Idempotency-Key`。
- Connection Secret 和 Webhook Secret 只在写入时返回，之后没有读取接口。
- OpenAPI 由 Rust 路由注册表和 DTO 生成。E–G 合入后当前文件包含 83 条路径、118 个公开操作，没有保留的 `501` 路由。
- SvelteKit `/admin` 提供七类控制面资源入口。SSR 从 `/api/v1/auth/me` 读取当前 Workspace，不用部署级固定 Workspace。
- 控制面创建链路、ETag 冲突、跨 Workspace 拒绝和 Web 构建已通过。

## D：持久化 Runtime

状态：`done`

- 完成 Run 领域状态机、claim、lease、heartbeat、attempt、fence 和过期租约恢复。
- `zeus-api` 内嵌 `ExecutionSupervisor`。HTTP 与 Run 使用独立连接池和 semaphore。
- 完成 append-only Session/Run Event、上下文重建、取消补齐和 usage ledger。
- 完成 OpenAI-compatible Chat Completions 流式适配器、工具调用分片合并和稳定 Provider 错误码。
- 模型网络重试保留在同一个 Run。人工重试创建新 Run。
- Tool Pipeline 执行租户策略、Capability 策略、审批、JSON Schema 输入输出校验、持久化、脱敏和审计。
- JSON Schema 不允许外部 `$ref`。运行时不会为 Schema 访问网络或文件系统。
- 初版注册表只开放 `builtin.echo` 测试 Capability。未知 executor 返回配对错误结果。
- 32 路并发 claim、租约恢复、旧 fence 拒绝、取消配对、模型流、工具往返和受限 Runtime 角色已通过测试。

本地 `ZEUS_SUPERVISOR_ENABLED` 默认关闭，便于只调 API。Kubernetes 基线开启 Supervisor。

## E：WorkItem 链路

状态：`done`

- 完成 WorkItem 创建、列表、详情、revision 更新、分配、外部引用和附件 API。
- 外部引用和附件事实追加写入。附件执行 5MiB 单文件和 25MiB 累计限制。
- 完成 Session、Message、Run、Run Event、SSE、Usage、Trace 和 Approval API。
- Web 提供 WorkItem 列表/创建/状态更新、Run 列表/Trace/Child Run 和审批处理页面。
- `builtin.echo` 保留为无企业副作用的 Tool Pipeline 测试 Capability。
- `scripts/db/efg-smoke.sql` 覆盖协作表约束和追加写入规则。

## F：团队经验

状态：`done`

- Candidate 从成功 Run 和可验证事件生成。
- 审阅、Workspace/Organization 发布、撤回和 PostgreSQL FTS API 已完成。
- 发布 Entry 不允许 UPDATE/DELETE；撤回保留独立事实。
- Runtime 只注入已发布且未撤回的 Experience，并记录 ID、版本、排名和查询摘要。
- Run 恢复时复用持久注入记录。经验内容带不可信标记和边界转义。
- Web 提供 Candidate 创建/审阅/发布、Entry 撤回和全文检索。

## G：Child Run

状态：`done`

- `builtin.child_run` 创建独立 Session 和持久 Run。
- 子 Run 的 Token、运行时间、Capability 和审批规则只能收窄；深度最多 8。
- 父 Run 使用 `waiting_child` 持久等待。子 Run 终态通过数据库触发器唤醒父 Run。
- 父进程重启后从数据库事实恢复。父取消会递归请求取消子 Run。
- 快速完成竞态、工具结果配对、租约和 fence 仍由 PostgreSQL 状态机处理。
- Run Trace 和 `/runs/{run_id}/children` 提供父子观察面。
- 数据库冒烟和忽略式真实 PostgreSQL 集成测试覆盖父子执行与恢复。

## H：生产准备

状态：`active`

仓库已完成：

- API、Web、Migration Job、PDB、NetworkPolicy、资源限制、CPU HPA 和可选 custom metrics overlay。
- API Pod 内继续运行 Supervisor，给活动任务 60 秒退出时间，并给进程清理额外保留 15 秒；未完成 Run 由租约恢复。
- JSON 日志、OTLP Trace、Pod 级 metrics 抓取、`zeus_http_inflight_requests`、`zeus_active_runs`、`zeus_queue_depth` 和 OpenTelemetry Collector 基线。
- 响应头、Problem Details 和 HTTP Trace 共用 UUIDv7 `request_id`；Runtime span 带 `run_id` 和 `session_id`。
- 生产 key 使用严格 `ZEUS_ENVELOPE_KEY_FILE` 契约；Kubernetes 由非 root init container 把 Secret 源暂存为内存卷普通 `0400` 文件。
- 容量驱动要求 1,000 个用户 Session、100 个 Workspace、200 个并发 Run 和 1,800 秒窗口。
- 备份恢复、租约积压、OIDC、Provider 和容量测试手册。
- `docs/security/hardening/phase-h` 记录 KMS-backed mount 与应用直连 KMS 的选择、成本和迁移计划。

外部验收：

- 选定云 KMS、工作负载身份、Secret driver 和 egress gateway，完成环境 overlay。
- 在托管 PostgreSQL 上校准连接池、PITR 和恢复目标。
- 联调真实企业 IdP、模型 Provider 和遥测后端。
- 安装指标适配器后验证基于活动 Run 和队列深度的 HPA。
- 在生产形态集群执行 30 分钟容量测试、跨租户测试、密钥轮换和四类故障演练。

这些外部结果齐备前，H 不标记为 `done`。
