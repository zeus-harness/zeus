# Zeus 实现计划

当前增量：M 需求整理试点与生产验收准备，见文末；H/I5 保持 `active`。

## 状态标记

- `done`：代码和静态验证已完成。
- `active`：已有可运行链路，阶段目标还没全部完成。
- `pending`：还未实现。
- `external`：需要企业 IdP、云 KMS 或生产集群。

H 和 I5 的外部门禁继续保持 `active`。本地静态检查、容器检查或 J0 文档验收都不能把它们标为 `done`。

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
- 生产 Containerfile 的在线依赖步骤仍会被本机 BuildKit DNS 解析失败阻断。Apple container 已有同类
  [问题 #1033](https://github.com/apple/container/issues/1033)。本地脚本通过临时 Cargo vendor 和宿主机 Web 构建绕开该限制；API/Web 镜像、migration、健康检查和同网络调用已通过 Apple `container` 实机验证。

## B：数据库与租户

状态：`done`

- 完成基础表、外键、索引、约束、RLS 和审计写入。
- 完成企业联合 OIDC discovery、Authorization Code + PKCE、回调校验、JIT 用户与 Group Mapping。
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
- OpenAPI 由 Rust 路由注册表和 DTO 生成。身份系统合入后当前文件包含 123 条路径、167 个公开操作，没有保留的 `501` 路由。
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
- JSON 日志、OTLP Trace、Pod 级 metrics 抓取、Run/HTTP 指标、身份安全指标和 OpenTelemetry Collector 基线。
- 响应头、Problem Details 和 HTTP Trace 共用 UUIDv7 `request_id`；Runtime span 带 `run_id` 和 `session_id`。
- 生产 key 使用严格 `ZEUS_ENVELOPE_KEY_FILE` 契约；Kubernetes 由非 root init container 把 Secret 源暂存为内存卷普通 `0400` 文件。
- 容量驱动要求 1,000 个用户 Session、100 个 Workspace、200 个并发 Run 和 1,800 秒窗口。
- 备份恢复、租约积压、联合 IdP、SMTP、签名 key、身份压力、OpenID Conformance 和容量测试手册。
- `docs/security/hardening/phase-h` 记录 KMS-backed mount 与应用直连 KMS 的选择、成本和迁移计划。

外部验收：

- 选定云 KMS、工作负载身份、Secret driver 和 egress gateway，完成环境 overlay。
- 在托管 PostgreSQL 上校准连接池、PITR 和恢复目标。
- 联调真实企业 IdP、模型 Provider 和遥测后端。
- 运行 OpenID Foundation Basic OP、Config OP、Authorization Code、PKCE、Refresh Token 和 RP-Initiated Logout 计划。
- 安装指标适配器后验证基于活动 Run 和队列深度的 HPA。
- 在生产形态集群执行 30 分钟容量测试、跨租户测试、密钥轮换和四类故障演练。

这些外部结果齐备前，H 不标记为 `done`。

## I：身份系统重构

### I1：身份基础与本地入口

状态：`done`

- 增加 `zeus-identity`，完成 Setup、平台 Owner、用户级 Session 和租户 Context 分离。
- Apple `container` 通过一个脚本管理 PostgreSQL、Mailpit、API、Web 和同源 Gateway。
- 浏览器只访问 `http://127.0.0.1:3000`。API 与 Web 不发布宿主机端口。

### I2：原生账号与组织管理

状态：`done`

- 完成注册、验证、密码登录、找回、TOTP、恢复码、Session 和身份限流。
- 完成 Organization、Workspace、邀请、成员、注册策略和平台管理 API/Web。
- IdentityMaintenance 使用 PostgreSQL lease/fence 投递加密邮件，并支持进程退出后的恢复。

### I3：企业联合登录

状态：`done`

- 上游表和路由统一使用 `federated_*` 语义。
- 一个 Zeus 用户可以绑定多个企业身份；同邮箱不自动合并。
- 完成显式绑定、邀请/域名/Group Mapping JIT、Organization 强制 SSO 和可信 ACR/AMR。

### I4：Zeus OIDC Provider

状态：`done`

- 完成 Authorization Code + S256 PKCE、Consent、Refresh Family、UserInfo、Discovery、JWKS、Revocation 和 Logout。
- 支持 Public Client 的 `none`，以及 Confidential Client 的 `client_secret_basic`、`client_secret_post`。
- RS256 签名 key 经过 envelope encryption 保存；协议状态、敏感列和数据库角色边界已经迁移约束。

### I5：安全与生产门禁

状态：`active`

仓库已完成：

- 身份、联合 IdP、Refresh 重放、邮件积压和签名 key 指标。
- 100 并发恶意登录驱动、邮件 lease/fence 冒烟和 32 并发 key 安装测试。
- 源码绑定的威胁模型、身份失败语义、SMTP、签名 key、备份恢复和 Conformance 手册。
- OpenID 静态 Client 所需的 `client_secret_basic` 与 `client_secret_post` 本地集成测试。
- Organization/Workspace 权限求值分离，Service Account Argon2 有界执行和 PHC 成本上限。
- 部署方弱密码表加载契约，以及 Migration/API 数据库 Secret 分离的 Kubernetes 基线。
- 2026-08-30 本机 Apple `container` 最终镜像验证发送 200 次合成无效登录，并发数 100；耗时 1,143ms，结果为 38 次 `401`、162 次 `429`、无网络失败、无异常状态码，结束后 readiness 正常。该结果只代表本机开发环境。

外部验收：

- OpenID Foundation Conformance Suite 状态是 `external_not_run`。
- 100 并发恶意登录仍要在生产规格的 API、连接池和托管 PostgreSQL 上记录 RSS、重启和连接数据。
- 云 KMS、受控 SMTP、真实 IdP、PITR 身份失效和下游 JWKS 缓存需要故障演练。
- 生产 PostgreSQL 要核对 migration owner、HTTP 和 Runtime login 的真实 grant chain。

这些外部结果齐备前，I5 不标记为 `done`。

## J：WorkItem-first Web

J 阶段把 WorkItem 设为 Workspace 的工作入口。`/` 保留为 Workspace 工作台；`/work-items`、`/work-items/{work_item_id}`、`/runs`、`/runs/{run_id}` 和 `/approvals` 保持兼容。服务端协议仍是 `/api/v1`。业务组件留在 `apps/web`，共享基础组件留在 `packages/ui/src/lib/components/ui`。

### J0：文档与交互基线

状态：`done`（文档基线）

交付：

- `docs/ui/workspace-workbench.svg`：Workspace 工作台灰度线框。
- `docs/ui/workitem-detail-agent-launch.svg`：WorkItem 详情和 Agent 启动灰度线框。
- `docs/ui/run-timeline-approvals.svg`：Run 时间线和审批灰度线框。
- `docs/ui/WORKITEM_UX.md`：桌面、平板、移动布局；主要动作；空、加载、失败、断线、冲突、无权限状态；SSE 续传和审批交互。
- `docs/adr/0007-workitem-first-information-architecture.md`：WorkItem-first、URL 兼容和 Web 组件归属决策。
- `docs/TECHNICAL_SPEC.md`、`AGENTS.md` 和本计划记录 J 阶段边界与门禁。

验收：

- 三张 SVG 是有效 XML，带标题和说明，使用灰度。实现页面以 `packages/ui` 当前导出和 token 为准。
- UX 文档能从 WorkItem 详情走到 Agent、Run、Approval，并写清服务端事实、权限、冲突和断线后的动作。
- 只改 J0 文档范围。J0 不代表 Web 代码、API 契约、生产部署或 H/I5 外部门禁完成。

### J1：拆分 Rust 单体内部结构

状态：`done`

验收：

- 保留单个 `zeus-api` crate。模块按 identity、control_plane、collaboration、execution、platform、http 组织。
- `AppState` 只组合平台服务、身份运行配置、外部客户端和执行配置四组轻量共享状态。
- 每个领域注册自己的路由、DTO 和 OpenAPI 片段。根 HTTP 模块只组合，不保存集中注册表。
- `integrations.rs` 按 Connection、Model Profile、Capability、Schedule、Webhook 拆分。
- `runtime.rs` 按执行循环、上下文恢复、工具、Child Run 和事件持久化拆分。
- Session 和 Run 的事务命令可由现有接口和 WorkItem 启动接口复用。
- 公开行为、数据库迁移和 OpenAPI 路径不变。不增加 DI 框架、crate、Redis 或 Worker。

### J2：整理 Web 工程

状态：`done`

验收：

- SvelteKit 使用 `(public)`、`(app)`、`(account)`、`(admin)` route group，浏览器 URL 不变。
- 登录后的 App Shell、Workspace 切换器、用户菜单、移动导航、账号导航和管理导航只有一份实现。
- `$lib/api` 分为 client、generated、work-items、runs、identity、control-plane 等领域文件。
- 删除聚合 `workspace.ts`。DTO 直接引用 OpenAPI 生成类型。
- `features/*` 保存业务组件，`components/layout` 保存页面外壳。
- `packages/ui` 导出共享基础组件。Web 从 `@zeus/ui` 使用，不复制基础控件。

### J3：WorkItem 执行契约

状态：`done`

验收：

- 增加 `POST /api/v1/workspaces/{workspace_id}/work-items/{work_item_id}/runs`。
- 请求要求 `OperateRun` 和 `Idempotency-Key`，并校验 WorkItem、Workflow 和活动版本属于当前 Workspace。
- 同一事务创建 Session、Run、用户消息和 `run_queued` 事件。幂等重放返回相同 Session 和 Run。
- 没有活动 Workflow Version 返回稳定 `409`。事务失败不留下部分 Session、Run 或 Event。
- Run 查询支持 `work_item_id`、`status`。Approval 查询支持 `work_item_id`、`status`。
- 原有 Session、Run、Approval API 保持可用。OpenAPI 与 Web 生成类型同步。

### J4：WorkItem 完整流程

状态：`done`

验收：

- `/` 展示我的开放 WorkItem、阻塞项、待审批和最近运行。
- `/work-items` 使用可筛选列表和创建 Sheet。详情展示负责人、状态、附件、外部引用、关联运行和最终结果。
- WorkItem 详情选择 Workflow，调用 J3 原子接口启动 Agent。
- Run 页面先读 Trace 快照，再用 SSE 增量展示模型、工具、审批、Child Run 和结果。
- SSE 按 sequence 去重，重连发送 `Last-Event-ID`，终态关闭连接。
- 审批、取消和重试使用安全 SvelteKit Server Action。
- 空、加载、断线、冲突、无权限和 API 失败都有可见状态。
- 桌面 `1440×900`、平板 `1024×768`、移动 `390×844` 完成浏览器检查。
- Rust、数据库、Web、UI 和 Apple `container` 全流程提供可执行验证证据。

2026-09-01 验收记录：

- Rust 格式、Clippy 和 workspace 测试通过。118 个单元测试通过；4 个需要真实 PostgreSQL 和测试 envelope key 的集成测试在普通门禁中保持 ignored，由隔离 E2E profile 补充本轮主链路验证。
- `control_plane_postgres` 在独立 PostgreSQL 18.6 临时数据库中通过，覆盖 WorkItem 启动事务、幂等、跨 Workspace 拒绝和筛选。测试库随后删除。
- Web 105 个测试、UI 1 个测试、E2E 脚本 6 个测试、身份负载参数 3 个测试通过。Svelte check 为 0 error、0 warning，Web、UI 和 Rust workspace 构建通过。
- 新增 Apple `container` 隔离 E2E profile。它使用 `zeus-e2e-*` 容器、独立网络、独立 PostgreSQL volume、`127.0.0.1:3100` 和确定性 OpenAI-compatible fixture，不触碰日常开发数据。
- API 验收完成 Setup、Mailpit 邮箱验证、密码登录、TOTP、Workspace 配置、Connection、Model Profile、Capability、Agent、Workflow、WorkItem、Run、Approval、Trace、Usage 和 SSE 断点续传。WorkItem/Run 筛选与 RFC3339 时间格式同时检查。
- 浏览器完成登录、MFA、Workspace 选择、WorkItem 创建、Agent 启动、SSE 自动刷新、审批和结果查看。最终 Run 为 `succeeded`，持久事件 17 条，工具调用 1 次，审批状态为 `approved`，浏览器控制台没有 warning 或 error。
- Run 页面完成 `1440×900`、`1024×768`、`390×844` 响应式检查。桌面使用双栏时间线，平板摘要转为两列，移动端使用单列卡片和折叠导航，没有横向溢出。
- 真实链路发现并修复四个问题：登录页 default/named action 冲突；Axum flatten query 在实际请求中返回 400；公开运行 DTO 未固定 RFC3339；SSE 新事件没有刷新 Trace 和 Approval 快照。
- API 重启后的首个 TOTP 验证曾受容器时钟偏差影响。Session 轮换改用 PostgreSQL `now()` 作为权威时间，随后在全新 API 进程上首次验证通过。

J0-J4 已完成。H 和 I5 仍为 `active`。OpenID Conformance、云 KMS、受控 SMTP、真实企业 IdP、托管 PostgreSQL 权限、生产规格容量和故障演练仍按各自外部清单执行。

## K：租户导航、Owner 角色与身份信任

K 阶段使用 ADR 0008。版本保持 `0.1.0`，API 前缀保持 `/api/v1`。不增加 crate、package、Redis 或独立 Worker。

### K0：契约和文档

状态：`done`

- Workspace URL 统一为 `/:workspaceId`。Context 只通过带 CSRF 的 POST 切换。
- 全局平台治理角色使用 `platform_owner`。Organization/Workspace 的 `admin` 迁移为 `owner`。
- 固定 Organization 状态、角色矩阵、平台支持 Grant、外部身份两层模型和 Provisioning 邀请边界。
- ADR 0008 覆盖 ADR 0007 的 URL 决策。
- H 和 I5 保持 `active`。

### K1：Owner 和治理

状态：`done`

- 新增 `0025_tenant_owner_governance.sql`。
- 原子迁移 Membership、Invitation 和 Group Mapping 中的 `admin`。
- Setup、创建函数和校验器改用新角色。JIT 默认保持 `member`。
- Organization 权限不再参与 Workspace Permission 求值。
- 增加 Workspace 最后 Owner、用户停用和角色降级保护。
- 增加 `organization_governance`、`provisioning` 和平台唯一的 Organization 状态动作。
- 更新 Rust DTO、OpenAPI、Web 类型和 PostgreSQL 矩阵测试。

验收记录：PostgreSQL 18.6 空库迁移到 `25`。5 个真实 PostgreSQL 集成测试串行通过；Rust Clippy、Workspace 测试、Web 检查和生产构建通过。H 和 I5 状态未变。

### K2：全局外部身份

状态：`done`

- 新增 `0026_global_external_identities.sql`。
- 迁移为 `external_identities` 和 `organization_federated_bindings`，保留 claims、绑定时间和最后登录时间。
- 使用 Organization/Provider 复合外键。旧表和函数只在停掉旧 API 后删除。
- 重写登录、JIT、显式绑定、解绑和 Account Federation API。
- 保留同邮箱不自动合并、近期认证、state/nonce/PKCE 和 Provider 精确校验。

验收记录：PostgreSQL 18.6 空库迁移到 `26`。旧表数据升级时保留全局身份与 Binding 数量。真实数据库测试覆盖同一 `(issuer, subject)` 在两个 Organization 建立独立 Binding、复合外键拒绝跨 Organization Provider、单 Binding 撤销隔离、active Binding 阻止全局撤销和最后登录方式保护。Account Federation API、OpenAPI 与 Web 页面已切换到 `/api/v1/users/me/external-identities`，旧 `federated-identities` 路径已移除。H 和 I5 状态未变。

### K3：平台租户管理

状态：`done`

- 新增 `0027_platform_tenant_access.sql`。
- 实现平台 Organization 创建、修改、状态动作、初始 Owner 邀请重发/替换和治理模式。
- Organization 创建要求 `Idempotency-Key`；可变配置要求 `revision` 与 `If-Match`。
- 实现原生密码 + TOTP 重新认证和最多 60 分钟的支持 Grant。
- Principal/AuthContext 携带 Grant ID。每个请求从 PostgreSQL 校验，不写 Membership，不绕过 RLS。
- 平台和支持操作同时写 Organization Audit 与 Security Event。

验收记录：PostgreSQL 18.6 空库迁移到 `27`。7 个真实 PostgreSQL 集成测试串行通过；平台测试覆盖 Organization 幂等创建、Provisioning Owner 邀请、revision 冲突、状态恢复、Grant 与 Web Session 绑定、跨 Session 拒绝、RLS、撤销、Audit 和 Security Event。Rust Clippy 与 Workspace 测试通过，单元测试为 `76 + 23 + 22`；Web `105`、UI `1`、Node `9` 项测试、静态检查和生产构建通过。H 和 I5 状态未变。

### K4：Web 路由与设置区域

状态：`done`

- 新增 `/workspaces` 和 `/:workspaceId` 路由树。
- 拆开 Agent Studio、Workspace Settings、Organization Settings 和 Platform Console。
- Workspace 切换只使用 Server Action POST。旧标签页收到 BroadcastChannel 后停止写入。
- `platform_managed` 身份设置不渲染入口，服务端 load 也不读取受限资源。
- 删除旧 Workspace 根路径和 `/admin/*`，不保留重定向。
- Svelte 页面继续使用 `@zeus/ui` 和 Svelte 5 runes。

验收记录：新增 `0028_web_tenant_navigation.sql`，平台支持 Grant 可以在不创建 Membership 的前提下选择目标 Organization 的 active Workspace；Grant 撤销会清空对应 Session Context。Web 已迁移到 `/:workspaceId`、`/organizations/:organizationId/settings/*` 和 `/platform/*`，旧根路径已删除。Workspace 选择只走带 CSRF 的 Server Action POST，URL 与 Session 不一致时返回选择页，旧标签页写入由服务端 `409 workspace_context_changed` 拒绝。30 个新增或移动后的 Svelte 文件通过 Svelte 5 autofixer；Rust Clippy、Workspace 单元测试、Web `107` 项测试、静态检查、OpenAPI 确定性检查和生产构建通过。三档浏览器与多租户 E2E 留在 K5。

### K5：联调和门禁

状态：`done`

- E2E 覆盖多个 Organization/Workspace、Owner 权限、Google 风格身份跨 Organization Binding、支持 Grant 和状态阻断。
- 覆盖零、一个、多个 Workspace 的入口和三档响应式页面。
- 验证 Suspend 的 Run 取消、Schedule/Webhook 阻断、OIDC Authorization/Refresh 阻断和 5 分钟 Access Token 边界。
- 按 K0-K5 分段提交并推送。

验收记录：新增 `0029_tenant_state_execution_guard.sql`，平台支持 Grant 可以保留选中的 active Workspace，Runtime claim 只领取 active Organization 的 Run。Workspace Service Account 补齐创建、列表和撤销 API。真实 PostgreSQL 18.6 空库迁移到 `29`，7 个 ignored 集成测试串行通过；测试覆盖多 Organization/Workspace、同一 Google 风格 `(issuer, subject)` 的独立 Binding、跨 Organization Context 拒绝、支持 Grant、Workspace Service Account、Suspend 写入和 claim 阻断、OIDC Authorization/Refresh 阻断及 5 分钟 Access Token 上界。

Rust 单元测试 `77 + 23 + 22` 通过。Web `122`、UI `1`、Node 驱动 `9` 项测试通过。Rust 格式、Clippy、Svelte check、生产构建和 OpenAPI 确定性检查通过。入口测试覆盖零、一个、多个 active Workspace 和当前 Context。登录页在 `1440×900`、`1024×768`、`390×844` 下没有横向溢出，浏览器控制台为 0 error、0 warning。Apple `container` 空库 smoke 完成 Setup、确定性 fixture、WorkItem、Run 和模型工具循环，终态为 `succeeded`。真实 PostgreSQL 测试只启动数据库；同时运行指向同一测试库的 API 会让 Supervisor 正常领取 queued Run，不能作为测试前置环境。

K 完成不能关闭 H 或 I5。OpenID Conformance、云 KMS、真实企业 IdP、受控 SMTP、托管 PostgreSQL 权限和生产容量仍需要外部证据。

## L：Alpha 验收自动化与内置 Agent 接入

状态：`done`（2026-09-10，限本节内置 Agent Alpha 范围；H/I5 不变）

按以下顺序执行。H/I5 保持 `active`，真实外部服务的结果单独记录。

1. 固化隔离数据库验收：每个 PostgreSQL 集成测试使用新建临时数据库，包含空库迁移与带数据的 `0029 → 0030` 升级；测试结束删除本次创建的数据库。
2. 加入 Rust/Web、OpenAPI、数据库和生产镜像 CI；将登录、MFA、Workspace 选择、WorkItem、审批和 SSE 固化为浏览器回归。
3. 完善内置 Agent 接入：模型连接与密钥写入、Agent 不可变版本、Workflow 发布、工具选择、WorkItem 启动和可追溯结果。使用现有 Runtime 和权限边界。
4. 增加一个受 Workspace 限制的只读业务 Capability，验证真实业务数据进入模型工具循环。确定性模型用于自动回归；真实模型验收需要部署方配置连接。

本阶段不接入外部 Codex/Claude Code 进程或远程 Agent，不增加任意 shell、用户代码执行、独立 Worker 或新视觉系统。

### 本地验收记录（2026-09-09）

- 隔离数据库驱动已完成。PostgreSQL 18.6 的 8 组 ignored 集成测试全部通过，每组独立新建数据库并在结束后删除，包含带 `platform_admin` 赋权数据的 `0029 → 0030` 升级和重复迁移。
- CI 配置已加入，覆盖 Rust/Web/OpenAPI、PostgreSQL、生产 Containerfile 和浏览器链路；actionlint 1.7.12 通过。修复生产 API Containerfile 缺少 `zeus-identity` 的构建输入。GitHub 执行结果仍待推送后确认，不能用本地镜像构建替代。
- 内置 Agent 首次接入已贯通：Web 创建连接与模型配置，保存/发布 Agent 和 Workflow 不可变版本，显式选择工具和预算，WorkItem 启动、审批、SSE 与持久结果。连接密钥轮换、模型配置更新仍使用已有 API；真实模型连接与业务回答质量尚未验收。
- `builtin.work_item_read` 已完成。测试证明只能读取当前 Run 关联工作项，目录 Schema 被放宽时仍拒绝指定其他工作项；合法与拒绝调用均保留配对事件。Web 测试覆盖 revision 冲突、密钥不回显、Workspace Context 变化、Organization/Workspace 独立授权。
- 本轮工作区通过 Rust 格式、Clippy、`pnpm check/test/build`、OpenAPI 确定性与生成类型检查；Rust `77 + 23 + 22`、Web `139`、UI `1`、Node `13` 项测试通过。共享 UI 打包曾因并行命令争用临时目录失败，改为串行并强制重跑后通过。
- 更新后的 Apple `container` 隔离 E2E 冒烟通过。2 条 Chromium 自动回归在 51.9 秒内通过，覆盖原有主链路，以及从零配置模型/Agent/Workflow 后读取工作项。Agent、Workflow、Run 页在 `1440×900`、`1024×768`、`390×844` 无横向溢出；浏览器控制台 0 warning、0 error。截图仅在登录后保存至系统临时目录。

以上是本轮未提交工作区的本地证据，模型为确定性 fixture。L 继续保持 `active`，等待 GitHub CI 实跑与真实模型验收；H/I5 的外部门禁不变。

### GitHub CI 核实（2026-09-09）

- 提交 `fac9d9755ae9c5ed80986cfdfa916801a3af94f8` 已有两次成功 CI：[运行 34310669233](https://github.com/zeus-harness/zeus/actions/runs/34310669233)、[运行 34310665814](https://github.com/zeus-harness/zeus/actions/runs/34310665814)。PR #1 的检查也对应这个提交。
- 两次运行中的 Rust/Web/OpenAPI、PostgreSQL isolation and upgrade、Production images and browser flow 三组 Job 均为 `SUCCESS`。这补齐了上述本地记录中待确认的 GitHub CI 证据。
- 真实模型验收尚未执行，按 [真实模型验收手册](runbooks/real-model-acceptance.md) 推进。L、H 和 I5 保持 `active`；确定性 CI 不能替代模型质量或生产环境验收。

### 隔离 E2E 复验（2026-09-09）

- 使用既有本地镜像，在 `127.0.0.1:3100` 执行 `scripts/container e2e smoke`，专用测试账号与确定性模型链路通过；本次未重新构建镜像。
- Run `01a085a8-19a8-738b-84e3-27cdc0b0029e` 为 `succeeded`。脚本验证工作项筛选、审批、工具配对结果、模型最终消息、用量和 SSE 断点续传。
- `pnpm test:browser` 的两条 Chromium 回归在 16.7 秒内通过，覆盖登录/MFA、Workspace POST 选择、审批与实时结果，以及模型配置、Agent/Workflow 发布和当前工作项读取；三档响应式与页面控制台断言通过。首次执行缺少 Chromium，安装后又受到沙箱 MachPort 权限限制，改为获准的沙箱外执行后通过，无业务代码修改。
- 开发环境 `127.0.0.1:3000` 的 readiness 和登录页均返回 HTTP 200；同一 E2E 账号的登录请求返回 401，不能据此复用隔离环境的账号配置。
- 本轮模型仍为确定性 fixture；真实模型兼容性、回答质量及真实服务故障场景保持未验收。

### 真实模型验收（2026-09-09）

- DeepSeek `deepseek-v4-flash` 的非思考模式已完成正常审批、拒绝审批、等待审批时取消、SSE 续传和客户端超时验证，具体 Run 与用量见 [实跑记录](runbooks/real-model-acceptance.md#deepseek-实跑记录2026-09-09)。正常回答识别合成需求的事实与缺失信息，拒绝时未编造工具内容。
- 实跑发现 Apple container 默认 DNS 无法解析外网域名。启动脚本增加可选的 API DNS 配置，在隔离 E2E 环境验证解析恢复及确定性冒烟通过。
- 实际页面暴露最终回答以 JSON 显示的问题；Run 页改为优先显示转义后的文本正文，保留折叠的原始 JSON，非文本输出保持原有展示。
- 本轮修改通过 Svelte autofixer、Web check（0 error / 0 warning）、139 项 Web 测试、7 项 E2E 脚本测试、Web 构建与镜像构建、更新后的确定性 API 冒烟及 2 条浏览器回归（56.9 秒）。已保存的真实模型回答在三档页面复验通过，控制台无 warning/error；正文展示修复没有再次调用模型。
- 本次新增修改尚未提交或执行 GitHub CI；已有 CI 成功证据仍只对应 `fac9d97`。L 保持 `active`，等待本轮修改的 CI 收尾；H/I5 不变，真实服务故障演练和思考模式不在本次已验收范围内。
- 用户现有 `127.0.0.1:3000` 页面已完成第 2 版 Workflow 发布、合成 WorkItem 启动、批准读取和真实模型结果持久化。Run `01a085d5-ddd5-7464-95bf-f29eba689ad2` 成功，工具调用 1 次，刷新后可见 17 条事件及最终正文。严格 350 字与事实表述要求未完全满足；事件流终态与摘要自动刷新的不一致待复现。详见手册“本机用户页面复验（3000）”，不将此标为全部质量门禁通过。

### 自动刷新收尾（2026-09-10）

- 已复现并修复工具成功被误判为 Run 终态、导致 SSE 提前关闭的问题。仅 Run 自身终态关闭事件流；工具和子运行结果不再终止订阅。
- 140 项 Web 测试、1 项 UI 测试、7 项 E2E 驱动测试、静态检查及构建通过。带 1.5 秒最终回答延迟的两条浏览器流程通过；旧 fixture 地址失效的用例重新 seed 后单独重跑通过。
- 新验收指令明确事实与建议边界、350 字符硬验收标准；3000 用户会话过期，等待登录后发布和真实模型复验。L、H/I5 保持 `active`。

### L 验收完成（2026-09-10）

- 修复提交 `7b130ae5b8883e5efd70686b7ac90c7adc805b37` 的 [PR CI](https://github.com/zeus-harness/zeus/actions/runs/34381240762) 和 [Push CI](https://github.com/zeus-harness/zeus/actions/runs/34381235360) 均成功，覆盖 Rust/Web/OpenAPI、PostgreSQL 隔离与升级、生产镜像和浏览器流程。
- 用户重新登录后，从 3000 页面发布 Agent 第 2 版和 Workflow 第 3 版，复用原合成工作项。Run `01a0872e-58ac-7508-86ba-e964b49f85ea` 经 1 次审批读取后成功；无需手动刷新即显示最终状态、17 条事件和正文。
- 回答含标题、标点和空白共 187 字符，三部分齐全，正确陈述已知事实和四项缺失信息，建议使用“建议/待确认”表述。该合成样例质量通过，不等于所有业务输入或思考模式均已验证。
- 本节四项交付已具备本地、CI 与真实模型证据，L 标为 `done`。H/I5 外部门禁、真实服务故障演练和外部 Agent 接入不在本次完成声明内。上述历史 `active` 记录保留当时的证据边界。

## M：需求整理试点与生产验收准备

状态：`active`。只使用当前工作项读取能力，人工在 WorkItem 的验收入口中确认指定运行的结果。

1. 固定试点契约：事实、缺失信息、建议，350 字符上限，明确拒绝、取消、越权和事实错误的失败条件。见 `docs/runbooks/requirements-pilot.md`。
2. 七类合成回归：完整、缺失、冲突、注入、拒绝、取消、模型超时。自动规则和确定性 Runtime 回归不等于真实模型质量；报告记录用量、耗时和人工未审阅状态。
3. 现有 Web 补齐模型配置更新、密钥轮换和 Run 恢复指引。复用已有 API 和 revision 校验，不增加数据库迁移。
4. 生产验收清单明确负责人、执行顺序及证据；外部 KMS、IdP、SMTP、托管 PostgreSQL、Conformance、容量和故障演练仍未执行。

### 本地验证（2026-09-10）

- `pnpm check`、`pnpm test`、`pnpm build`、Rust fmt/Clippy 通过。两个修改的 Svelte 文件经 Svelte 5 autofixer 检查，无问题或建议；OpenAPI 与生成类型无差异。
- `scripts/container e2e test-db` 的 8 组 PostgreSQL 集成测试通过，包含权限、身份、Runtime 和带数据升级；临时库已删除。
- `pnpm e2e:pilot` 七类案例通过，校验工具确实读取对应 WorkItem，记录状态、耗时及确定性 fixture 用量。报告 `.zeus/pilot-report-1789043634877.json` 权限为 `0600`；本轮耗时约 0.9–3.7 秒，不代表真实模型延迟。fixture 的脚本化回答不能证明模型抵抗提示注入或真实业务质量。
- 3100 更新 Web 镜像后的三个 Chromium 流程分别通过。原有 Run/SSE 与失败/取消指引通过；模型配置流程修正新增表单导致的测试定位歧义后单独复验通过。覆盖 API Key 轮换后空输入、模型超时修改并刷新保留、Agent/Workflow 发布及工具结果，三个视口为 1440×900、1024×768、390×844，无横向溢出或应用控制台异常。
- CI 已接入试点回归，actionlint 与容器脚本语法检查通过。本轮改动未提交，GitHub CI 未实跑；真实模型费用预算、连接及生产验收环境尚待确定。

M 的真实模型及人工业务验收未完成前保持 `active`，H/I5 状态不变。


### 组织模型管理调整（2026-09-12）

- Organization Owner 统一管理多个模型供应商及其多个模型，组织内 Workspace 通过只读目录选用。Agent 版本选择模型，Workflow 继承并禁止覆盖；普通工具连接仍保留 Workspace 范围。
- 组织设置承载供应商、密钥轮换和模型编辑；Agent 页面只选择模型及填写指令。保留 revision 冲突保护和未编辑参数。
- migration `0031` 保留已有模型/连接 ID、密钥密文及历史版本。同名模型和供应商加 ID 后缀，不合并凭据。升级必须先停旧 API/Supervisor；详见 ADR 0009。
- 本地 `pnpm check/test/build`、Rust fmt/Clippy、Svelte autofixer 和 OpenAPI 确定性检查通过。Web 146 项、UI 1 项、Rust 77 + 23 + 22 项通过；9 组隔离 PostgreSQL 测试通过，覆盖多模型共享、组织权限、Workflow 继承、Runtime 与带数据升级。
- 更新后的隔离 3100 镜像已执行 `0031`，旧 Workflow/密钥运行通过；七类试点及三条 Chromium 流程通过。浏览器覆盖同一供应商添加两个模型、密钥轮换、模型编辑、Agent 选模与 Workflow 继承；三档视口无横向溢出或应用控制台异常。
- 目录积累导致 seed 漏掉首屏外模型的问题已修复，新增分页回归通过。截图复核后补齐组织设置顶部模型导航；更新 Web 镜像后，从导航进入的多模型/Agent/Workflow 完整流程再次通过（36.7 秒）。
- 本轮尚未提交或执行 GitHub CI；真实模型质量、人工确认和 H/I5 外部生产验收仍未完成。

### 页面分层与人工验收（2026-09-16）

WorkItem 结果优先并增加持久化人工验收入口；Workflow 显示已发布配置关系；Run 保留折叠执行事件、精确事件名称，将工具审批与业务验收分开。新增 `0032` 和验收 GET/POST API，要求用户身份、Workspace 权限、成功关联 Run 和工作项 revision；验收不自动完成工作项。该增量不包含 BPM 引擎或思考模式适配。M/H/I5 保持原有验收边界，页面和记录能力不代表业务质量或生产放行。

### 平台用户目录与注册反馈（2026-09-16）

- 已实现 platform_owner 专属全局用户目录、opaque cursor 分页、邮箱与 MFA 状态展示；覆盖无租户成员关系的待验证用户。迁移 0033 使用限定列的 SECURITY DEFINER 函数，并在数据库中校验平台用户、有效会话及 MFA。
- 注册页说明邀请制行为；400/422/429 不再误报提交成功，保留身份接口防枚举的通用接受回应。未改变生产注册策略、未创建账号或提升权限。
- 本地证据：Web 152 项测试、Rust workspace 测试与 Clippy、9 组隔离 PostgreSQL 测试通过。已部署到 3000 并应用迁移 0033；已登录平台页面显示真实账号且详情可展开，注册页显示邀请制提示。浏览器只观察到第三方扩展警告，无 Zeus 页面错误。这些证据不替代生产验收。

### 自主注册、邀请与用户表格（2026-09-16，替代上述默认邀请制说明）

- 迁移 0034 开启自主注册并原子创建个人组织与默认工作空间；保留邮箱验证，邀请注册只加入指定组织，已有账号经登录和 POST 接受邀请加入。显式 disabled 配置保留。验证邮件任务与注册使用同一事务。
- 平台用户表格使用有索引的游标分页和完整邮箱精确查找；无全量加载、OFFSET 或全表总数查询。
- Web 154 项测试、Rust workspace 测试和 Clippy、9 组隔离 PostgreSQL 测试通过，包含三种入驻路径、无效邀请拒绝及目录权限检查。
- 已部署 3000，浏览器验证邮箱命中/空结果/清除查询、桌面表格和窄屏横向滚动，注册页说明已更新。真实新账号注册和邮箱验证需用户完成密码设置；未声称亿级容量已验证。

### MFA 设置页二维码与密钥展示（2026-09-16）

- 本地生成 PNG 绑定二维码，不调用外部二维码服务；不再展示含密钥的完整 otpauth URI。Secret 默认遮罩，由用户主动显示/隐藏或复制；二维码失败保留手动设置入口。
- 156 项 Web 测试、类型检查与 Svelte autofixer 通过。临时合成页面验证二维码、显示/隐藏和复制成功提示，测试页已移除；浏览器工具的剪贴板读取未能确认复制值，未据此声称真实剪贴板内容已验证。未读取或操作真实用户 MFA 密钥。

- MFA 部署修复：qrcode 最初被 SSR 外置，只有 build 的生产镜像缺少该依赖而导致安全设置页 500。现通过 Vite ssr.noExternal 打包二维码库；在无 node_modules 的实际镜像中成功导入安全设置页模块，部署后未登录请求恢复 303，已登录浏览器恢复“安全设置”及“开始设置 TOTP”入口。未操作用户的真实 MFA 设置。
