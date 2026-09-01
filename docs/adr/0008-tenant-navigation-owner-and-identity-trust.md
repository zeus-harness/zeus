# ADR 0008：租户导航、Owner 角色与身份信任

状态：Accepted（K0 契约基线，Zeus `0.1.0`）

## Context

一个 Zeus 用户可以属于多个 Organization 和 Workspace。现有 Web URL 不携带 Workspace，`/admin` 又混放 Workspace 构建资源和 Organization 身份设置。Organization 的 `owner` 与 `admin` 权限相同，Workspace 只有 `admin`。`federated_identities` 同时承担全局外部账号和 Organization 信任关系，无法准确表达同一个 Google 账号被多个 Organization 信任。

## Decision

### URL 与 Session

- Workspace 页面统一使用 `/:workspaceId`。不增加 `/dashboard` 或 `/workspace` 前缀。
- `/` 只解析登录后的入口。零 Workspace 进入 `/workspaces` 空状态；一个 Workspace 通过安全 POST 选择后进入 `/:workspaceId`；多个 Workspace 进入 `/workspaces`。
- Session 保存一个活动 Organization 和 Workspace。一个 Session 不支持不同 Workspace 的并行标签页。
- GET 页面不能修改 Session。URL 与 Session 不一致时跳转到 `/workspaces?return_to=...`。选择动作调用 `POST /api/v1/auth/context`，校验 Origin 和 CSRF，轮换 Session/CSRF Cookie，再以 `303` 返回目标页面。
- `return_to` 只接受站内绝对路径。目标 Workspace 必须属于当前用户或有效平台支持会话。
- `BroadcastChannel` 只用于通知其他标签页。服务端仍校验 URL、Session 和 Workspace，一致性失败返回 `409 workspace_context_changed`。
- ADR 0007 的无 Workspace URL 决策被本 ADR 覆盖。旧 `/work-items`、`/runs`、`/approvals`、`/experience` 和 `/admin/*` 在 `0.1.0` 发布前直接移除，不保留重定向。

### 角色

- 平台角色继续命名为 `platform_admin`。它不属于 Organization/Workspace 角色体系。
- Organization 角色为 `owner | member | auditor`。
- Workspace 角色为 `owner | builder | operator | viewer`。
- Organization Owner 不再给 Workspace 动作提供隐式权限。Workspace 业务请求必须有活动 Workspace Membership，平台支持会话除外。
- Workspace Owner 拥有 Workspace 管理、构建、运行、审批、经验发布和审计权限。
- Builder 可以管理 Agent、Workflow、Schedule、Webhook，启动和观察 Run，发布 Workspace Experience；不能管理成员、连接密钥、Capability Policy 或审批高风险调用。
- Operator 可以管理 WorkItem、Run 和 Approval。Viewer 只读 Workspace。
- Organization Auditor 只读 Organization 元数据、Audit 和 Security Event。Organization Member 只能发现 Organization 以及自己有 Membership 的 Workspace。
- Setup、Organization 创建者和 Workspace 创建者写入 `owner`。联合 JIT 默认写 `member`；邀请和 Group Mapping 只能写其明确配置的角色。
- 每个 active Organization 和 active Workspace 至少保留一个 active Owner。

### Organization 治理

- `organization_governance.identity_settings_mode` 为 `self_service | platform_managed`。
- `self_service` 允许 Organization Owner 管理 Identity Provider、Verified Domain、Identity Policy 和 OIDC Client。
- `platform_managed` 对 Organization Owner 隐藏入口，并让相关读写 API 返回 `403 organization_identity_settings_managed`。平台接口仍可管理。
- Organization Owner 可以修改名称、成员、邀请、Workspace 生命周期和 Organization Capability Catalog。Organization 状态只能由平台动作接口修改。
- 平台创建 Organization 时同时创建初始 Workspace 和首位 Owner 邀请。Organization 保持 `provisioning`，直到已验证且邮箱匹配的 Zeus Session 单次消费邀请。
- 平台 Organization 创建要求 `Idempotency-Key`。平台可重发或替换未消费的首位 Owner 邀请。
- slug 在 Organization 激活后不可修改。删除表示归档。归档可恢复且不清除业务、OIDC Subject 或审计事实。

Organization 状态行为：

| 状态 | 用户读取 | 用户写入 | Run/Schedule/Webhook | OIDC | 平台支持 |
| --- | --- | --- | --- | --- | --- |
| `provisioning` | 仅邀请流程 | 禁止 | 禁止 | 禁止 | 平台控制面 |
| `active` | 允许 | 按 RBAC | 允许 | 允许 | 60 分钟读写 |
| `suspended` | 允许只读 | 禁止 | 不创建、不领取；活动 Run 请求取消 | 不授权、不刷新 | 租户数据只读，平台修复接口可写 |
| `archived` | 禁止 | 禁止 | 禁止 | 禁止 | 禁止；先恢复为 `suspended` |

Suspend 会阻止新的 Run、Schedule 和 Webhook 投递。queued、running、waiting approval 和 waiting child Run 写入取消请求；Supervisor 在安全边界停止。未知外部结果继续使用 `outcome_unknown`，不盲目重放。已签发 Access Token 最多保留现有 5 分钟寿命。

### 外部身份

- `external_identities` 保存全局 `(issuer, subject) → user_id`。
- `organization_federated_bindings` 保存目标 Organization、Provider 和全局身份之间的信任。
- Provider 令牌完成签名、issuer、audience、nonce 和时间校验后，才能按 `(issuer, subject)` 查询全局身份。
- 已有全局身份且用户是目标 Organization 成员时，可自动创建或恢复 Binding。同邮箱但未绑定继续返回 `account_link_required`。
- 显式绑定要求已验证 Zeus 用户、十分钟内认证、Session 绑定的 link transaction、state、nonce 和 S256 PKCE。
- JIT 必须命中邀请、已验证域名或 Group Mapping。默认 Organization 角色是 `member`。
- Binding 使用 `(organization_id, provider_id)` 复合外键，拒绝跨 Organization Provider。解除 Binding 不删除全局身份。
- 全局身份只有在没有 active Binding，且用户仍有密码或其他 active 外部身份时才能撤销。
- Zeus OIDC Subject 继续按 Organization 稳定。平台支持会话不构成 Membership，不能据此签发下游 Token。

### 平台支持会话

- `platform_admin` 使用原生密码、TOTP 和十分钟内的重新认证创建 Grant。有效期为 60 分钟，但不能超过 Web Session 的 idle/absolute expiry。
- 一个 Web Session 同时最多一个未撤销 Grant。创建新 Grant 时先在同一事务结束过期 Grant。
- Grant 不写入 Membership。Principal 和 AuthContext 携带 `tenant_access_grant_id`，每个租户请求都从 PostgreSQL 校验 Session、平台角色、Organization、到期和撤销状态。
- 支持会话可绕过目标 Organization 的 `federated_required`，不能绕过邮箱验证、平台 TOTP、Organization 状态、RLS 或资源 Workspace 边界。
- 租户 SQL 仍使用 `zeus_http` 和 Organization/Workspace RLS Context。不得为支持会话切换到 migration owner 或 `BYPASSRLS` 角色。
- Audit Actor 始终是平台管理员。Audit 和 Security Event 保存 Grant ID 与创建时的原因快照。
- SSE 在 Grant 到期时关闭。退出、Session 撤销或到期后，新请求立即失权。

## Consequences

- URL 可以表达 Workspace，分享链接不会依赖接收者之前选择的 Workspace。
- Session 仍是单 Workspace 上下文。多标签页冲突会明确失败，不允许旧标签页静默写入新 Workspace。
- Organization 与 Workspace 权限完全分开。平台访问有时间、原因和真实 Actor，不产生虚假 Membership。
- 外部账号可以被多个 Organization 信任，同时保持 Zeus 用户和 OIDC Subject 的事实边界。
- K2 在正式生产前完成。`0026` 不支持旧 API Pod 与新 Schema 混跑；执行迁移前必须停止旧版本并确认没有生产滚动升级窗口。

