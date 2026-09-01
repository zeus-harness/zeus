# Zeus 实现计划

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

- 增加 `zeus-identity`，完成 Setup、平台管理员、用户级 Session 和租户 Context 分离。
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
- 平台角色保留 `platform_admin`。Organization/Workspace 的 `admin` 迁移为 `owner`。
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

状态：`pending`

- 新增 `0027_platform_tenant_access.sql`。
- 实现平台 Organization 创建、修改、状态动作、初始 Owner 邀请重发/替换和治理模式。
- Organization 创建要求 `Idempotency-Key`；可变配置要求 `revision` 与 `If-Match`。
- 实现原生密码 + TOTP 重新认证和最多 60 分钟的支持 Grant。
- Principal/AuthContext 携带 Grant ID。每个请求从 PostgreSQL 校验，不写 Membership，不绕过 RLS。
- 平台和支持操作同时写 Organization Audit 与 Security Event。

### K4：Web 路由与设置区域

状态：`pending`

- 新增 `/workspaces` 和 `/:workspaceId` 路由树。
- 拆开 Agent Studio、Workspace Settings、Organization Settings 和 Platform Console。
- Workspace 切换只使用 Server Action POST。旧标签页收到 BroadcastChannel 后停止写入。
- `platform_managed` 身份设置不渲染入口，服务端 load 也不读取受限资源。
- 删除旧 Workspace 根路径和 `/admin/*`，不保留重定向。
- Svelte 页面继续使用 `@zeus/ui` 和 Svelte 5 runes。

### K5：联调和门禁

状态：`pending`

- E2E 覆盖多个 Organization/Workspace、Owner 权限、Google 风格身份跨 Organization Binding、支持 Grant 和状态阻断。
- 覆盖零、一个、多个 Workspace 的入口和三档响应式页面。
- 验证 Suspend 的 Run 取消、Schedule/Webhook 阻断、OIDC Authorization/Refresh 阻断和 5 分钟 Access Token 边界。
- 按 K0-K5 分段提交并推送。

K 完成不能关闭 H 或 I5。OpenID Conformance、云 KMS、真实企业 IdP、受控 SMTP、托管 PostgreSQL 权限和生产容量仍需要外部证据。
