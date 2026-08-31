# Zeus 0.1.0 技术规范

## 目标

Zeus 是云端共享的企业 Harness Agent。一个 Organization 可以创建多个 Workspace。团队在 Workspace 中管理 Agent、Workflow、WorkItem、Run、审批和经验。

Zeus 不依赖员工本机的 Agent 状态。模型历史、工具调用、审批和经验都保存在服务端。

## 进程

Zeus 初版只有两个部署单元：

- `zeus-api`：Rust API 和 `ExecutionSupervisor`。
- `zeus-web`：SvelteKit 控制台。

每个 API 副本运行一个 Supervisor。多个副本通过 PostgreSQL 租约领取不同 Run。不创建 `zeus-worker`。

HTTP 和 Run 使用不同的 SQLx 连接池与 semaphore。Run 执行时不持有数据库事务。

## 模块

```text
apps/zeus-api       HTTP、SQLx、认证、模型、Capability、Supervisor
crates/zeus-core    无 IO 的状态机、策略、事件和 ID
crates/zeus-identity 密码、TOTP、OIDC 值对象和安全策略
apps/web            SvelteKit 业务页面
packages/ui         shadcn-svelte 和共享 UI
db/migrations       PostgreSQL 前向迁移
openapi             公开 HTTP 契约
```

`zeus-core` 保存 Agent 领域逻辑。`zeus-identity` 隔离密码、TOTP、OIDC 请求校验、Token Claim 和安全策略。两个 crate 都不依赖 Axum 或 SQLx。SMTP、数据库、HTTP 和 envelope encryption 适配留在 `zeus-api`。

## 身份系统

Zeus 管理全局用户、凭据、Session、平台角色和 Organization/Workspace 成员关系。企业 IdP 只提供联合认证证明。每个联合身份以 `(issuer, subject)` 唯一绑定到一个 Zeus 用户；同邮箱不会自动合并。

原生身份支持：

- Setup、注册模式、邮箱验证、密码登录和密码找回。
- Argon2id `m=65536,t=3,p=4` PHC。原生密码、OIDC Client Secret 和 Service Account Token 共用最多四个活跃任务和有界等待队列。
- 存量 PHC 的成本参数不得高于当前生成参数。生产环境通过 `ZEUS_WEAK_PASSWORD_FILE` 注入最多 16MiB、200000 条的弱密码表。
- RFC 6238 TOTP、十个单次恢复码、账号/IP/PostgreSQL 持久限流。
- 2 小时 idle、12 小时 absolute 的用户级 Session。数据库只保存 Session 与 CSRF Token 摘要。
- Organization、Workspace、邀请、成员角色、MFA 策略和企业 IdP 强制策略。
- 独立的 `platform_admin`。平台角色不提供租户业务数据读取权限。

联合登录入口固定为：

```text
/auth/federated/{organization_slug}/{provider_slug}
/auth/federated/{organization_slug}/{provider_slug}/callback
```

JIT 必须命中邀请、已验证企业域名或 Group Mapping。已有同邮箱账号返回 `account_link_required`，用户登录 Zeus 后再显式绑定。Provider 的可信 ACR/AMR 可以满足 Zeus MFA；未命中时继续要求 TOTP。可信 Claim 配置属于高风险管理动作，生产变更需要复核 IdP 的真实 Claim 语义。

Zeus 同时提供一个全局 OIDC Issuer。0.1.0 支持 Authorization Code + S256 PKCE、Refresh Token、UserInfo、Discovery、JWKS、Revocation 和 RP-Initiated Logout。Public Client 使用 `none`，Confidential Client 支持 `client_secret_basic` 和 `client_secret_post`。Redirect URI 精确匹配。Client 属于 Organization，授权用户必须是该 Organization 的有效成员。Client 创建、修改和撤销要求十分钟内的交互式认证，Service Account 不能代办。

Access Token 是 5 分钟有效的 RS256 `at+jwt`。Authorization Code 和 ID Token 有效期也是 5 分钟。Refresh Token 每次使用都轮换，idle expiry 7 天，absolute expiry 30 天；旧 Token 重放会撤销整个 Family。3072-bit RSA 私钥经过 envelope encryption 保存，90 天轮换，常规旧公钥在 JWKS 保留 7 天。

每个 `zeus-api` 副本运行 `IdentityMaintenance`。它处理可恢复邮件任务、OIDC 协议清理、签名 key 维护和身份聚合指标。不增加独立 Worker、Redis 或消息队列。

## 租户与权限

租户层级为 `Organization → Workspace`。

Organization 角色：

- `owner`
- `admin`
- `member`
- `auditor`

Workspace 角色：

- `admin`
- `builder`
- `operator`
- `viewer`

应用在事务中设置：

```text
zeus.user_id
zeus.organization_id
zeus.workspace_id
```

租户表启用 `ENABLE ROW LEVEL SECURITY` 和 `FORCE ROW LEVEL SECURITY`。应用 RBAC 负责动作权限，RLS 负责行隔离。

HTTP SQLx 连接在 PostgreSQL startup packet 中切换到 `zeus_http`。Supervisor 连接切换到 `zeus_runtime`。迁移连接不切换角色。

`zeus_http` 受 RLS 限制。`zeus_runtime` 带 `BYPASSRLS`，每条运行时 SQL 仍显式携带 Organization 和 Workspace。生产登录角色由部署平台创建，并只获得对应角色的 `SET ROLE` 权限。

## 不可变版本

`agents` 和 `workflows` 保存稳定 ID、名称和活动版本指针。

`agent_versions` 和 `workflow_versions` 创建后禁止 UPDATE 和 DELETE。配置变化创建新版本。Run 固定引用 `workflow_version_id`，保证历史可复现。

Workflow 是一个版本化 Agent 流程。初版没有 DAG、脚本节点或用户代码。

默认限制：

- `max_steps = 32`
- `max_runtime_seconds = 900`
- 模型网络重试 2 次
- Capability 自动重试 0 次

## Session Event

`session_events` 是模型可见历史的事实来源。

- 用户消息、助手消息、工具调用、工具结果和审批结果使用追加写入。
- 工具调用必须有配对结果。
- 取消时写入合成工具结果。
- 流式 Token 增量只走 SSE。完整消息完成后持久化。
- steering 在当前工具边界后插入。
- follow-up 在当前 Run 结束后创建后续 Run。

`run_events` 保存租约、状态、策略、用量和错误。模型事件通过 `session_event_id` 引用，正文不重复保存。

## Run 队列

`runs` 同时是业务记录和持久队列。

状态：

```text
queued
running
waiting_approval
waiting_child
succeeded
failed
canceled
```

领取过程调用 `zeus_private.claim_run`：

1. 查询已到期的 queued Run 或租约过期的 running Run。
2. 使用 `FOR UPDATE SKIP LOCKED` 跳过其他副本已锁定的行。
3. 写入 `lease_owner`、`lease_expires_at`。
4. 增加 `fence_token` 和 `attempt_count`。
5. 写入 `run_attempts`。
6. 提交短事务。

运行结果调用 `finish_run`。SQL 同时校验 owner 和 fence。过期执行者不能覆盖新结果。

`LISTEN/NOTIFY` 只用于唤醒。轮询负责可靠性。Supervisor 已实现心跳、取消轮询、并发上限和 60 秒退出窗口。

OpenAI-compatible Chat Completions 适配器支持 SSE、分片工具调用和 usage。完整助手消息完成后才写入 Session Event。模型请求失败会转成稳定错误码。

## Capability

Capability 在服务端注册。定义包含输入 Schema、输出 Schema、风险级别、executor key 和幂等模式。

```text
required
supported
unavailable
```

只有前两种模式允许自动重试。高风险 Capability 必须审批。

固定调用顺序：

```text
validate
→ tenant policy
→ capability policy
→ approval
→ persist call
→ execute
→ normalize and redact
→ persist result
→ audit
```

初版不提供 shell、服务器文件系统和任意代码执行。

输入和输出使用 JSON Schema 校验。Schema 创建时会校验元 Schema，并拒绝外部 `$ref`。验证器关闭 HTTP 和文件引用解析，Schema 不能触发 SSRF 或服务器文件读取。

服务端注册表包含 `builtin.echo` 测试执行器和 `builtin.child_run` 平台执行器。`builtin.child_run` 只能由已启用、要求幂等的 `zeus.child-run` Capability 使用。企业 Capability 需要显式加入注册表后才能执行。

## 数据

PostgreSQL 18.6 保存：

- 用户、密码/TOTP、Session、邀请、联合身份和成员关系
- OIDC Client、Consent、Code、Refresh Family、签名 key 和撤销记录
- 邮件 outbox、认证限流和安全事件
- Agent、Workflow 和 Capability 配置
- WorkItem、Session 和附件
- Run、Attempt、Event 和 Approval
- Experience Candidate 和发布内容
- Audit Event 和 Outbox Event

主键默认使用 `uuidv7()`。时间使用 `timestamptz`。状态使用 `text + CHECK`。

附件单文件最大 5MiB。一个 WorkItem 最多 25MiB。经验搜索使用 `tsvector('simple', ...)` 和 GIN。初版不使用 pgvector。

Redis 当前没有必要。PostgreSQL 已提供事务、队列、JSONB、Session、全文检索和审计一致性。

## WorkItem 与附件

WorkItem 使用 `revision` 做并发更新。创建要求 `Idempotency-Key`。分配对象必须是当前 Workspace 成员。外部引用和附件事实采用追加写入，应用角色不能修改或删除。

附件通过 API 接收 base64 内容。单文件上限 5MiB，同一 WorkItem 累计上限 25MiB。服务端保存 SHA-256、MIME、长度和 `bytea` 数据。HTTP 全局请求体上限为 8MiB，能容纳一个 5MiB 文件的 base64 JSON 请求。

Run Trace 聚合 Run Event、Session Event、Tool Call、Approval、usage、Experience 注入和 Child Run。聚合结果只读取同一 Organization 与 Workspace 的持久事实。

## Experience

Candidate 必须引用同一 Workspace 内已经成功的 Run 和可验证的 Session/Run Event。只有用户身份可以审阅与发布，Service Account 不能代替人工审阅。

发布后的 Entry 不允许 UPDATE 或 DELETE。撤回写入独立追加事实。Workspace Entry 只在本 Workspace 检索；Organization Entry 需要授权角色发布。检索使用 PostgreSQL `tsvector('simple', ...)` 和 GIN。

Runtime 在第一次模型调用前按 Workflow 的 Experience Policy 查询已发布且未撤回的内容。实际注入的 Entry ID、版本、排名和查询摘要写入 `run_experience_injections`。Run 恢复后复用同一组记录，不因后来发布或撤回改变本次上下文。经验正文带不可信标记和边界转义，不获得策略或 Capability 权限。

## Child Run

`builtin.child_run` 创建独立 Session 和 Run，不共享父 Run 的可变内存。父 Run 进入 `waiting_child`，子 Run 到达终态后由数据库触发器重新排队父 Run。父进程重启后从 `run_links`、`tool_calls`、Session Event 和 Run Event 恢复。

子 Run 继承 Organization 与 Workspace，并满足以下收窄规则：

- 深度最多 8。
- Token 预算不得超过父 Run 剩余预算或目标 Workflow 上限。
- 运行时间不得超过父 Run 持久化剩余时间或目标 Workflow 上限。
- Capability 必须同时出现在父流程、目标流程和 Workspace 启用集合中。
- 子流程审批规则不能放宽父流程的高风险要求。

父 Run 取消会递归请求取消未完成子 Run。工具调用与子 Run 通过 `child_run_id` 配对。快速完成、租约恢复和旧 fence 写入仍由数据库状态机裁决。

## HTTP

协议前缀是 `/api/v1`。项目软件版本是 `0.1.0`。

- ID 使用 UUIDv7 字符串。
- 时间使用 UTC RFC3339。
- 列表使用 opaque cursor。
- 错误使用 `application/problem+json`。
- Run、WorkItem 和 webhook 创建要求 `Idempotency-Key`。
- SSE 使用 `Last-Event-ID` 续传。
- 可变配置使用 `revision` 和 `If-Match`。
- 原始密钥没有读取接口。

Rust DTO、Utoipa Schema 和公开路由注册表生成 `openapi/zeus.v1.yaml`。当前契约包含 123 条路径和 167 个公开操作。内部 claim、heartbeat、finish、邮件租约和签名 key 维护函数不暴露为 HTTP。

## Web

Web 使用 SvelteKit 5 SSR。组件使用 Svelte 5 runes。根 layout 的服务端 load 调用 `/api/v1/auth/me`，读取当前用户和 Workspace。Session Cookie 转发到内部 API，但不会进入客户端状态或日志。

控制台提供 Agent、Workflow、Model Profile、Connection、Capability、Schedule、Webhook、WorkItem、Run Trace、Approval 和 Experience 入口。业务数据为空时显示真实空状态，不填充 mock 数据。

shadcn-svelte 在 `packages/ui` 初始化。组件固定位于：

```text
packages/ui/src/lib/components/ui
```

业务组件留在 `apps/web`。OpenAPI 类型生成到 `apps/web/src/lib/api/generated/schema.d.ts`。

## J：WorkItem-first Web 结构

J 阶段收敛 Rust 单体内部结构、Web 工程和 WorkItem 执行体验。它不改变 `0.1.0` 的 API 前缀、租户模型、Session Event 事实源或组件目录，也不增加 crate、package、Redis 或独立 Worker。

### 信息架构

WorkItem 是 Workspace 的工作入口。工作台汇总队列、活动 Run 和待审批项；WorkItem 详情承载状态、输入、附件、外部引用和 Agent 启动；Run 详情承载时间线、Tool Call、Approval、usage、Experience 注入和 Child Run。Run 与 Approval 保留直接导航，记录回链 WorkItem。

浏览器 URL 保持兼容：

```text
/                         Workspace 工作台
/work-items               WorkItem 列表和创建
/work-items/{work_item_id} WorkItem 详情和启动 Agent
/runs                     Run 列表
/runs/{run_id}            Run Timeline 和 Trace
/approvals                Approval 队列
```

现有 `status`、`cursor` 查询参数继续有效，`/work-items?create=1` 打开创建 Sheet。Web URL 不增加 Workspace 段。当前 Workspace 来自 Session 和 Workspace context。服务端调用继续使用 `/api/v1/workspaces/{workspace_id}/...`。需要破坏旧深链接时必须另开 ADR。

### 结构边界

- 桌面使用工作队列/快捷动作、内容/动作栏、时间线/检查栏三种两列布局。
- 平板把辅助列移到主内容后方，保留当前 Workspace、主动作和审批上下文。
- 移动使用单列卡片、全屏或底部 Agent 面板、垂直时间线和纵向审批按钮。
- `apps/web` 保存路由、SvelteKit `load`/`action`、业务状态映射、权限判断以及 WorkItem/Run/Approval 组件。
- `packages/ui/src/lib/components/ui` 保存共享基础组件。Web 从 `@zeus/ui` 子路径导入。当前 shadcn-svelte 配置使用 `lyra`、neutral base color、Phosphor 图标和 JetBrains Mono 字体资源。不创建第二套基础 UI 或品牌 token。
- `docs/ui/WORKITEM_UX.md` 固定空、加载、失败、断线、冲突、无权限、SSE 续传和审批交互。J0 不修改 Rust、TypeScript、Svelte、package、lock 或 OpenAPI 文件。

### J0-J4 验收

| 阶段 | 验收边界 | 状态 |
| --- | --- | --- |
| J0 | 三张灰度 SVG、UX 基线和 WorkItem-first ADR 可读；SVG/XML 和文档范围检查通过。只验收文档。 | `done` |
| J1 | `zeus-api` 在单 crate 内按领域拆分。公开路径、数据库和行为不变。 | `pending` |
| J2 | Web route group、App Shell、API 客户端、业务组件和 `packages/ui` 导出边界收敛。 | `pending` |
| J3 | WorkItem 原子启动 Run、Run/Approval WorkItem 筛选、OpenAPI 和生成类型完成。 | `pending` |
| J4 | 工作台到结果查看的完整流程、SSE、审批、取消、重试和响应式故障状态完成可执行验收。 | `pending` |

J0 的 `done` 只表示本次文档基线已验收。H 生产准备和 I5 安全与生产门禁的外部验收继续为 `active`，OpenID Conformance、真实 KMS/SMTP/企业 IdP、托管 PostgreSQL 权限、PITR、生产规格压力和故障演练仍未完成。

## 密钥

- 浏览器 Session Token 使用 256-bit 随机值，数据库只保存哈希。
- CSRF Token 使用独立 256-bit 随机值，数据库只保存哈希。
- 用户密码和 OIDC Client Secret 使用 Argon2id PHC。TOTP、邮件正文和 OIDC 签名私钥使用 envelope encryption。
- Service Account Token 只显示一次，数据库保存 Argon2 PHC；创建与校验走同一个有界执行器。
- Connection Secret 使用 envelope encryption。
- 本地密钥写入 `.zeus/local.env`，权限为 `0600`。
- 生产进程优先读取 `ZEUS_ENVELOPE_KEY_FILE`。文件必须是普通文件、不能是符号链接、大小不超过 4KiB，并且在 Unix 上不能向 group 或 other 开放权限。
- Kubernetes Secret 卷本身使用 symlink 且默认归 root。基线通过非 root init container 把 group-readable Secret 源复制到内存 `emptyDir`，生成归 API 用户所有的普通 `0400` 文件。主容器只挂载暂存卷。
- 生产环境由工作负载身份和 KMS 支持的 Secret driver 提供源 Secret。密钥变更后必须滚动 API Pod，不能依赖原地文件更新。
- 应用直连 KMS 的 per-secret data key 方案留作后续选项。0.1.0 不声称已经完成云 KMS 联调。
- 日志不记录 Authorization、Cookie、OIDC Secret、模型密钥或连接密钥。

## 部署

本地使用 Apple `container` 1.0.0 和 PostgreSQL 18.6。PostgreSQL 18 官方镜像的卷挂载点是 `/var/lib/postgresql`。

`scripts/container status` 只输出容器列表字段。不要用 `container inspect`
分享诊断结果；inspect 会包含容器环境变量。`scripts/container up` 在 Zeus
专用网络内启动 PostgreSQL、Mailpit、内嵌 Supervisor 的 API、Web 和 Gateway。Apple `container`
1.0.0 本机不依赖容器名解析，脚本只提取运行时 IP 并注入内部连接地址。
浏览器只访问 `http://127.0.0.1:3000`。API 和 Web 不发布宿主机端口；Mailpit
通过 `/mailpit/` 查看。`/api`、`/auth`、`/oauth2`、`/.well-known`、`/health`
和 `/metrics` 由 Gateway 转发到 API。
本地 API 镜像通过临时 Cargo vendor 上下文离线编译，Web 镜像封装宿主机生成的
SvelteKit 产物。临时上下文放在被忽略的 `.zeus` 下，构建退出时删除。生产镜像
继续使用 `zeus-api.Containerfile` 和 `web.Containerfile` 的完整构建链路。

生产使用 Kubernetes 和托管 PostgreSQL。Web 与 API 独立扩缩。Migration 由 Job 执行。Job 只读取 `zeus-migration` 的 owner URI；API 只读取 `zeus-runtime` 的 HTTP/Runtime URI。Secret 名分离不能替代 PostgreSQL login、membership、`SET ROLE` 和 `BYPASSRLS` 验收。API Pod 停止时停止领取新 Run，活动任务最多等待 60 秒；Kubernetes 终止窗口额外留出 15 秒做清理，未完成任务由租约恢复。

API 进程输出 JSON 日志，并在配置 OTLP endpoint 时导出 Trace。OpenTelemetry Collector 基线接收 OTLP，通过 headless Service 抓取每个 API Pod 的 `/metrics`，再把 Trace 和指标发到环境指定的后端。`zeus_http_inflight_requests`、`zeus_active_runs` 和 `zeus_queue_depth` 可供 HPA 指标适配器使用；适配器保留 Pod 映射且指标数据存在前不能应用 custom metrics overlay。

身份指标包括密码失败、MFA 失败、限流、邮件积压、最老邮件年龄、联合 Provider 错误、Refresh 重放、当前签名 key 是否存在和 key 年龄。Counter 不带用户或租户标签。邮件和 key Gauge 每 30 秒从 PostgreSQL 聚合函数刷新；查询失败时 `zeus_identity_operational_metrics_up` 变为 `0`。

HTTP 边界只接受 UUIDv7 格式的 `x-request-id`，无效或缺失时由服务端生成。响应头、Problem Details 和 HTTP Trace 使用同一个值。HTTP Trace 只记录路径，不记录查询串。Runtime span 使用 `run_id`、`session_id`、Organization 和 Workspace 关联持久事件。

Kubernetes 基线启用非 root、只读根文件系统、capability drop、默认拒绝 NetworkPolicy、PDB、拓扑分散和 CPU HPA。API 必须挂载平台维护的 `zeus-password-policy/weak-passwords.txt`。HTTPS 目的地由云环境 egress gateway 或 overlay 收窄。仓库中的通用 TCP 443 规则不等于生产 allowlist。生产 Ingress 不路由 `/metrics`，指标只通过集群内 headless Service 抓取。

数据库角色必须在 migration 前创建。`scripts/db/bootstrap-roles.sql` 只创建固定角色和默认权限，不创建带密码的生产登录账号。
