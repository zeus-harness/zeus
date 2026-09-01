# Zeus 0.1.0 威胁模型

## 1. 系统概览

本模型覆盖 Zeus Web、API、原生账号、企业联合登录、Zeus OIDC Provider、PostgreSQL、邮件投递、Agent Runtime、Capability 和审计。0.1.0 不运行用户代码，也不开放 shell 或服务器文件系统工具。

| 组件 | 职责 | 代码依据 |
| --- | --- | --- |
| Gateway / Web | 同源入口、SSR 页面、Cookie 转发 | `scripts/container:579`、`scripts/container:629` |
| `zeus-api` 身份边界 | Session、CSRF、RBAC、联合登录和租户 Context | `apps/zeus-api/src/auth.rs:110`、`apps/zeus-api/src/auth.rs:334` |
| `zeus-identity` | 密码规范、弱密码表、Argon2 队列与 PHC 成本上限、TOTP、OIDC 值校验 | `crates/zeus-identity/src/password.rs`、`crates/zeus-identity/src/password_executor.rs`、`crates/zeus-identity/src/totp.rs` |
| Zeus OIDC Provider | Authorization Code、PKCE、Consent、JWT、Refresh 和 JWKS | `apps/zeus-api/src/oidc_provider/authorization.rs:91`、`apps/zeus-api/src/oidc_provider/token.rs:501`、`apps/zeus-api/src/oidc_provider/keys.rs:125` |
| IdentityMaintenance | 邮件租约、OIDC 状态清理、签名密钥维护和聚合指标 | `apps/zeus-api/src/identity_maintenance.rs:96`、`apps/zeus-api/src/identity_maintenance.rs:244` |
| PostgreSQL | 用户事实、租户隔离、一次性 Token、协议状态、队列和审计 | `db/migrations/0019_native_identity.sql:35`、`db/migrations/0022_oidc_authorization_server.sql:683`、`db/migrations/0005_rls_runtime.sql:1` |
| ExecutionSupervisor | Run claim、lease、fence、恢复和工具管线 | `db/migrations/0009_runtime_fencing.sql:138` |

```text
Browser
  │
  ▼
Gateway ──► SvelteKit Web
  │
  ▼
zeus-api ─────────────► Enterprise IdP
  │  │                 SMTP
  │  └───────────────► Model / Capability
  ▼
PostgreSQL
  ▲
  │
Third-party OIDC Client ◄── Zeus OIDC Provider
```

受保护资产包括：

- Zeus 用户、密码 PHC、Session/CSRF 摘要、TOTP Secret、恢复码和一次性 Token。
- Organization、Workspace、成员角色、联合身份绑定、Provider Secret 和企业域名证明。
- OIDC Client Secret、Consent、Code、Refresh Token Family、Subject、签名私钥和 JWKS 生命周期。
- WorkItem、Session Event、Run、Experience、Capability 凭据和审批记录。
- 邮件正文、审计事件、安全事件、租约、fence 和幂等记录。
- envelope key、数据库角色、SMTP 凭据、模型凭据和外部系统凭据。

## 2. 威胁边界与假设

| 边界 | 不可信输入 | 必须成立的控制 |
| --- | --- | --- |
| Browser → Gateway/API | Cookie、Origin、CSRF Header、JSON、OAuth 参数 | 写请求同时校验 Origin、CSRF Cookie、Header 和数据库摘要；登录后轮换随机 Session Token。实现见 `apps/zeus-api/src/auth.rs:334`。 |
| Gateway / Proxy → API | Host、Origin、客户端地址和 forwarded headers | 浏览器保持同源；生产代理必须覆盖客户端伪造的 forwarded headers；只有受控代理部署才可开启 `ZEUS_TRUST_PROXY_HEADERS`。 |
| API → PostgreSQL | 用户、Organization、Workspace 和资源 ID | HTTP 使用 `zeus_http`；事务通过 `set_config(..., true)` 注入 RLS Context。实现见 `apps/zeus-api/src/database.rs:35` 和 `db/migrations/0005_rls_runtime.sql:19`。 |
| Zeus → 企业 IdP | Discovery、Authorization Response、Token、UserInfo、Claim | Provider 按 Organization 和 slug 选择；state 事务单次消费；同邮箱账号要求显式绑定。实现见 `apps/zeus-api/src/auth.rs:604` 和 `apps/zeus-api/src/auth.rs:658`。 |
| 第三方 Client → Zeus OP | Redirect URI、Scope、PKCE、Client 凭据、Code、Refresh Token | Redirect URI 精确匹配；S256 固定；Code 单次 claim；Refresh 重放撤销 Family。实现见 `apps/zeus-api/src/oidc_provider/authorization.rs:128`、`db/migrations/0022_oidc_authorization_server.sql:683` 和 `db/migrations/0022_oidc_authorization_server.sql:743`。 |
| API → SMTP | 收件人、邮件 Token、SMTP 未知结果 | 正文 envelope encryption；任务使用 lease/fence；未知投递结果允许重复邮件，Token 仍单次使用。实现见 `apps/zeus-api/src/identity_maintenance.rs:133` 和 `apps/zeus-api/src/identity_maintenance.rs:210`。 |
| API → KMS/envelope key | 数据库密文、AAD、key id | 本地实现要求 AES-256-GCM 和 AAD；生产 key 来源、工作负载身份和轮换仍由云环境验证。实现见 `apps/zeus-api/src/crypto.rs:63`。 |
| API → Model/Capability | Prompt、模型输出、Tool 参数和外部响应 | 模型不能授予权限；Capability schema、租户策略、审批和幂等在服务端执行。网络 egress allowlist 仍是部署门禁。 |
| Supervisor → PostgreSQL/外部系统 | 过期进程、重复 claim、未知外部结果 | Run 写入检查 lease owner 和 fence；不支持幂等的外部调用不自动重试。实现见 `db/migrations/0009_runtime_fencing.sql:165`。 |
| Migration owner / 平台运维 | 高权限 SQL、备份、密钥轮换 | owner 凭据不进入应用；高权限操作需变更记录和双人复核。该流程依赖部署环境。 |
| Metrics scraper → API | 运行和身份聚合指标 | 生产 Ingress 不发布 `/metrics`；采集器通过集群内 Service 访问。环境 overlay 不能把该路径转到公网。 |

攻击者可能是匿名互联网用户、其他租户成员、被停用成员、恶意 OIDC Client、被攻破的企业 IdP、恶意邮件接收方、过期 API 副本、被提示注入影响的模型，或取得数据库备份但没有 envelope key 的人员。

已实现的安全假设：

- Zeus `users` 是账号、成员关系、审计 actor 和 OIDC Subject 的事实来源。联合 IdP 只提供登录证明。
- 原生密码、OIDC Client Secret 和 Service Account Token 共用 Argon2 有界执行器。活跃任务最多四个，等待队列满载时返回限流错误。实现见 `crates/zeus-identity/src/password_executor.rs`、`apps/zeus-api/src/auth.rs` 和 `apps/zeus-api/src/native_auth.rs`。
- PHC 校验在执行 Argon2 前拒绝高于 Zeus 当前内存、迭代或并行度上限的参数。生产 API 还必须挂载 `ZEUS_WEAK_PASSWORD_FILE`；文件大小和条目数有界。实现见 `crates/zeus-identity/src/password.rs` 和 `apps/zeus-api/src/config.rs`。
- Organization 与 Workspace 权限分开求值。Workspace 角色和 Workspace 级 Service Account scope 不能授权 Organization 路由。实现见 `apps/zeus-api/src/auth.rs`。
- Organization 角色不再对 Workspace 动作提供隐式授权。平台支持使用绑定 Web Session 的限时 Grant，不生成 Membership，也不切换到高权限数据库角色。Grant 创建验证原生密码与 TOTP；每个请求从 PostgreSQL 校验用户、Session、Organization、撤销状态和到期时间。
- TOTP 接受当前窗口前后各一步，并返回准确 counter 供数据库原子防重放。实现见 `crates/zeus-identity/src/totp.rs:125`。
- OIDC 协议表不给 `zeus_http` 直接读取敏感列，通过用途明确的函数访问。实现见 `db/migrations/0023_identity_role_contract.sql:1`。
- 身份运维指标只返回聚合值，不带用户、邮箱、Provider 或 key id。实现见 `db/migrations/0024_identity_observability.sql:1`。

仍需外部证据的假设：

- 生产 TLS、KMS、工作负载身份、SMTP、托管 PostgreSQL、备份和 egress gateway 配置正确。
- 企业 IdP 的 issuer、DNS、证书和管理员权限可信。`trusted_acr`、`trusted_amr` 只包含该 IdP 能可靠证明的 MFA 方法，并经过双人复核。
- 生产 API 登录账号不能继承 migration owner。基础清单使用独立的 `zeus-migration` 与 `zeus-runtime` Secret；真实 PostgreSQL grant chain 仍需环境验收。
- 生产代理覆盖客户端提供的 forwarded headers，`/metrics` 只允许集群内采集器访问。
- 下游 Resource Server 严格验证 JWT `iss`、`aud`、`typ`、`kid`、`exp`、`nbf` 和 RS256 签名。
- OpenID Foundation Conformance Suite 尚未运行。当前集成测试不能替代该结果。
- 恢复点之后丢失的凭据撤销记录可从外部审计或变更系统重建；无法重建时必须执行全量凭据失效流程。

## 3. 攻击者故事与处置优先级

下表是风险场景。`已验证控制` 只表示仓库代码或本地测试存在，不代表生产环境已经验收。`外部门禁` 需要真实基础设施证据。

| ID | 级别 | 攻击者故事 | 已有控制与证据 | 剩余动作 |
| --- | --- | --- | --- | --- |
| ZI-01 | Critical | 租户成员伪造 Organization/Workspace 或复用连接残留 Context，读取另一团队的 WorkItem、Run、Session 或 Experience。 | 强制 RLS；`SET LOCAL` 语义；HTTP 与 Runtime 分角色。`apps/zeus-api/src/database.rs:42`、`db/migrations/0005_rls_runtime.sql:38` | 在生产角色和连接池上重复跨租户负面测试。 |
| ZI-02 | Critical | 攻击者取得签名私钥或 envelope key，伪造 Zeus Token 或解密 Provider、TOTP 和邮件内容。 | 私钥 envelope encryption；RS256/`kid` 固定；签名失败关闭 Token 发放。`apps/zeus-api/src/oidc_provider/keys.rs:125`、`apps/zeus-api/src/oidc_provider/token.rs:612` | 绑定云 KMS、工作负载身份和受控 egress；完成泄漏轮换演练。 |
| ZI-03 | High | 上游 IdP 返回与现有 Zeus 用户相同的邮箱，攻击者借此接管账号。 | `(issuer, subject)` 绑定优先；同邮箱返回 `account_link_required`；绑定要求已有 Session 和近期认证。`apps/zeus-api/src/auth.rs:623`、`apps/zeus-api/src/auth.rs:733` | 用真实 IdP 验证 JIT、邀请、域名和 Group Mapping 组合。 |
| ZI-04 | High | 攻击者利用 OIDC mix-up、伪造 state、错误 Redirect URI 或 PKCE downgrade 截获 Code。 | Provider 路径带 Organization/slug；state 摘要单次消费；Redirect URI 精确匹配；只支持 S256。`apps/zeus-api/src/auth.rs:658`、`apps/zeus-api/src/oidc_provider/authorization.rs:91` | 运行 OpenID Conformance Suite，并做双 Provider mix-up 测试。 |
| ZI-05 | High | 被盗 Refresh Token 被旧客户端再次使用，攻击者继续换取 Access Token。 | Refresh 单次 claim；旧 Token 重放会撤销整个 Family 并计数。`db/migrations/0022_oidc_authorization_server.sql:743`、`apps/zeus-api/src/oidc_provider/token.rs:524` | 对重放指标告警；验证多副本并发刷新。 |
| ZI-06 | High | 攻击者固定 Session、跨站发写请求，或在 Workspace 切换后继续使用旧 Token。 | 256-bit 随机 Token；数据库只存摘要；写请求校验 Origin/CSRF；切换 Context 和 MFA 后轮换。`apps/zeus-api/src/native_auth.rs:1198`、`apps/zeus-api/src/auth.rs:334`、`db/migrations/0020_identity_security_functions.sql:295` | 生产 HTTPS 下复测 Cookie flags、代理 Header 和跨源行为。 |
| ZI-07 | High | 100 个并发恶意登录耗尽 Argon2 内存、数据库连接或 Tokio Worker。 | Argon2 在 `spawn_blocking` 执行；四个活跃槽和有界队列；账号/IP 使用 PostgreSQL 限流。`crates/zeus-identity/src/password_executor.rs:55`、`apps/zeus-api/src/native_auth.rs:186` | 在生产规格上运行 `scripts/load/identity.mjs`，记录 RSS、连接池和重启数。 |
| ZI-08 | High | 数据库 PITR 回滚了 Session、Refresh、一次性 Token、密码、MFA、Service Account 或 Client 撤销状态。 | 恢复手册要求入口关闭、等待 Access Token 过期、失效恢复库中的协议状态并轮换签名 key。 | 用真实 PITR 演练；恢复缺口无法对账时撤销全部相关凭据。 |
| ZI-09 | High | 平台管理员借平台角色直接读取租户业务数据。 | 平台角色独立存储；业务访问仍需 Organization/Workspace Context 和 RLS。`db/migrations/0019_native_identity.sql:74`、`apps/zeus-api/src/auth.rs:246` | 生产数据库执行平台管理员跨租户负面测试；平台运维 SQL 需审计。 |
| ZI-10 | High | 恶意 Provider issuer、模型 URL 或 Capability 目标触发 SSRF 或把凭据发往错误主机。 | OIDC/model 适配器默认限制私网目标；Capability 服务端注册；JSON Schema 禁外部 `$ref`。 | 通用 Kubernetes TCP 443 规则仍过宽；生产必须部署目的地 allowlist。 |
| ZI-11 | Medium | SMTP 已接收邮件但连接中断，Zeus 重试并发送重复验证、重置或邀请邮件。 | 邮件任务有 lease/fence；Token 摘要单次消费；未知结果不伪造成功。`apps/zeus-api/src/identity_maintenance.rs:170`、`apps/zeus-api/src/identity_maintenance.rs:218` | 接受重复邮件；模板提示忽略旧邮件；监控积压和最老任务年龄。 |
| ZI-12 | Medium | OIDC Client 扩大 Scope、替换 Redirect URI 或混用 Basic 与 form secret 绕过 Consent。 | Scope 增加重新 Consent；Redirect URI 精确匹配；混用两种 Client 认证返回 `invalid_client`。`apps/zeus-api/src/oidc_provider/authorization.rs:227`、`apps/zeus-api/src/oidc_provider/token.rs:623` | 外部 Suite 复测 `client_secret_basic`、`client_secret_post` 和 Public Client。 |
| ZI-13 | Medium | 日志、Trace、Problem Details 或 metrics 泄漏密码、Code、Token、Cookie、邮箱或 key id。 | 指标无标签且只使用计数/聚合值。`apps/zeus-api/src/http.rs:2406`、`db/migrations/0024_identity_observability.sql:1` | 对构建产物、日志和 Trace 做持续 secret scan；真实后端仍需检查。 |
| ZI-14 | Medium | 密钥轮换并发生成多个当前 key，或 JWKS 过早移除旧 key。 | 安装函数使用数据库锁；常规旧公钥保留 7 天；聚合指标监控 key 是否存在和年龄。`apps/zeus-api/src/oidc_provider/keys.rs:138`、`db/migrations/0024_identity_observability.sql:53` | 用下游缓存做重叠窗口演练；泄漏场景按事故流程缩短旧 key 寿命。 |
| ZI-15 | Medium | 过期 API 副本继续提交 Run 或邮件结果，覆盖新执行者。 | claim 使用 `FOR UPDATE SKIP LOCKED`，接管时 fence 递增，finish 校验 fence。`db/migrations/0009_runtime_fencing.sql:165`、`apps/zeus-api/src/identity_maintenance.rs:210` | 多副本故障注入继续保留为发布门禁。 |
| ZI-16 | Medium | Webhook、Experience 或模型输出注入指令，诱导 Agent 泄漏数据或调用高风险 Capability。 | 模型文本不能修改 RBAC、Capability、审批、lease 或审计；Experience 保留不可信标记；工具输入输出在服务端校验。 | 接入真实企业 Capability 时增加目标、动作和输出级负面测试。 |
| ZI-17 | High | Workspace Admin 或 Workspace 级 Service Account 利用混合角色判断进入 Organization 路由，创建 Workspace 或扩大 Service Account 权限。 | Organization 和 Workspace 权限已拆开；Workspace Service Account 禁止 `organization:manage`；单元测试覆盖角色和 scope 负面路径。`apps/zeus-api/src/auth.rs` | 在真实 PostgreSQL/RLS 环境对 Organization、Workspace 和 Service Account 路由做矩阵测试。 |
| ZI-18 | High | 攻击者拿到可见的 Service Account prefix 后并发提交错误 Token，绕过原生登录的 Argon2 队列并耗尽内存。 | Service Account 创建与校验改用同一个四槽有界执行器；队列满返回 `429`；PHC 成本在计算前封顶。`apps/zeus-api/src/auth.rs`、`crates/zeus-identity/src/password.rs` | 生产规格压力测试同时覆盖原生登录、Client Secret 和 Service Account Token。 |
| ZI-19 | High | Organization 管理员把只证明普通登录的 ACR/AMR 标记为可信 MFA，联合登录后绕过 Zeus TOTP。 | 只有 Provider 配置中的精确值会满足 MFA；配置修改受 Organization 管理权限和审计约束。 | 把可信 Claim 清单纳入 IdP 联调和双人复核；错误配置仍可降低 MFA 强度。 |
| ZI-20 | Critical | 部署把 migration owner URI 同时注入 API，RLS 和数据库函数授权被 owner 权限绕过。 | 基础清单把 Migration Job 指向 `zeus-migration` Secret，API 只引用 `zeus-runtime`。`deploy/kubernetes/zeus.yaml` | 在真实数据库核对 login、membership、`SET ROLE` 和 `BYPASSRLS`；发布证据不能只检查 Secret 名。 |
| ZI-21 | Medium | 错误代理配置信任客户端伪造 IP，导致 IP 限流失效；或把 `/metrics` 暴露到公网。 | proxy header 信任默认关闭；生产 Ingress 没有 `/metrics` 路由，采集使用集群内 Service。 | 每个环境验证代理覆盖规则、来源网段和公网路由表。 |
| ZI-22 | Medium | Organization 管理员误把外部 OIDC Client 标记为 trusted，用户不经 Consent 获得预批准 Scope。 | Client 创建、修改和撤销要求十分钟内的用户认证；Service Account 不能执行；只跳过预批准 Scope；新增 Scope 仍需重新授权。 | trusted Client 的审计告警和双人复核仍需由生产变更流程落实。 |
| ZI-23 | Critical | 平台角色伪造租户 Context，绕过 Membership 或长期保留对租户数据的访问。 | K3 只允许绑定 Web Session 的 60 分钟 Grant；每个请求校验 PostgreSQL 状态；Actor、Grant ID 和原因进入 Audit 与 Security Event；租户 SQL 继续使用 `zeus_http` 与 RLS。真实数据库测试覆盖错误 Session、撤销和 RLS。 | K5 增加浏览器双 Session、到期和跨 Organization E2E；生产数据库继续执行角色链负面测试。 |
| ZI-24 | High | JIT 角色迁移把普通联合用户错误提升为 Organization/Workspace Owner。 | K 契约规定 JIT 默认 `member`，只有邀请或 Group Mapping 可以指定角色；`admin` 数据迁移不改变无映射默认值。 | K1/K2 增加默认 JIT、恶意 Group Claim 和跨 Organization Provider 测试。 |
| ZI-25 | High | Binding 的 Organization 与 Provider 不一致，攻击者借另一个租户的 Provider 建立信任。 | K2 使用 `(organization_id, provider_id)` 复合外键；Provider Token 完整校验后才解析全局身份。 | 数据库约束、登录回调和显式绑定都要覆盖交叉引用负面测试。 |
| ZI-26 | High | 外部链接触发 GET Workspace 切换，轮换用户 Session 并让旧标签页向错误租户提交数据。 | K 只允许带 Origin/CSRF 的 Context POST；URL 不一致返回稳定冲突；BroadcastChannel 只做 UX 通知。 | K4 浏览器测试覆盖外部链接、双标签页和旧 Cookie 写入。 |
| ZI-27 | High | `platform_managed` 只隐藏导航，Organization Owner 仍能直接调用身份设置 API。 | 服务端权限与 RLS 拒绝 Owner 的受管身份设置访问；平台支持路径要求有效 Grant，并写 Audit 与 Security Event。真实数据库测试覆盖受管 Provider 的 Grant/RLS 访问和错误 Session 拒绝。 | K4 验证服务端 load 不读取受限资源；K5 对 Provider、Domain、Identity Policy 和 OIDC Client 执行直接 API 与浏览器负面测试。 |

本轮源码审查确认了 ZI-17 的权限混淆路径，并在同一变更中修复。ZI-18 的无界哈希路径也已收口。其余场景是代码审查和架构分析得到的攻击假设；只有复现、影响证明和独立验证齐备后，才记为安全发现。

## 4. 严重级别与验收规则

| 级别 | Zeus 判定 | 合并和上线要求 |
| --- | --- | --- |
| Critical | 可跨租户读取或修改；可伪造有效 Token；可取得核心明文密钥；可远程执行任意代码。 | 阻止合并和上线。修复后需要负面测试、独立复核和生产形态验证。 |
| High | 可接管账号、绕过 MFA/Consent、恢复已撤销凭据、造成持久高权限副作用或大范围认证不可用。 | 阻止上线。代码修复和故障演练都要有证据。 |
| Medium | 需要较强前置条件，影响范围受限，或主要造成可恢复的可用性、重复副作用和敏感元数据泄漏。 | 进入发布清单。没有缓解措施和负责人时不能忽略。 |
| Low | 不直接破坏保密性、完整性或核心可用性，影响局部且容易恢复。 | 记录原因、测试和修复窗口。 |

关闭一项风险需要四类证据：触发条件、代码或配置控制、负面测试、生产形态结果。仓库测试能证明协议和数据库语义，不能代替 TLS、KMS、企业 IdP、SMTP、托管 PostgreSQL、OpenID Suite 或云网络策略的外部证据。
