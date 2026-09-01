# Zeus 失败语义

## HTTP

客户端错误和服务错误使用 `application/problem+json`。稳定字段：

```json
{
  "type": "https://zeus.example.com/problems/validation_failed",
  "title": "Validation failed",
  "status": 422,
  "code": "validation_failed",
  "detail": "request validation failed",
  "request_id": "019..."
}
```

`detail` 不包含 SQL、堆栈、Token、Cookie 或上游密钥。

## 原生身份

- 邮箱格式错误、未知账号、错误密码和不可登录账号统一返回 `401 unauthorized`。格式错误和未知账号仍执行一次受限的 Argon2 工作，并记录 IP 失败，减少账户枚举、时序差异和格式绕过限流。
- 注册、验证邮件重发和密码找回请求统一返回 `202`。响应不说明邮箱或账号是否存在。
- PostgreSQL 记录账号、IP、TOTP 和邮件限流。达到限制返回 `429 rate_limited` 和 `Retry-After`。
- Argon2 活跃槽和等待队列都满时返回 `429`。请求不会绕过队列在 Tokio Worker 上执行哈希。
- Service Account Token 和 OIDC Client Secret 也使用同一个 Argon2 执行器。队列满时拒绝请求，不能另起无界 `spawn_blocking` 哈希。
- 存量 PHC 的 `m`、`t` 或 `p` 高于 Zeus 当前生成参数时，在执行 Argon2 前返回内部凭据失败。数据库异常值不能把单次校验放大成未封顶计算。
- 配置了 `ZEUS_WEAK_PASSWORD_FILE` 时，注册、Setup 和密码修改拒绝表内值。文件缺失、为空、超过 16MiB、超过 200000 条或包含超长条目会阻止 API 启动。
- 登录成功后发现旧 Argon2 参数，会在同一次认证流程中尝试更新 PHC。并发更新失败不改变本次已验证结果。
- Setup Token 错误返回 `401`。已有平台管理员时返回 `409`。并发 Setup 只有取得 advisory lock 且先提交的事务成功。
- 邮箱验证、密码重置、邀请和恢复码都单次消费。过期、重复或摘要不匹配时不执行状态变化。

## MFA 与 Session

- TOTP 格式错误、验证码错误和 counter 重放统一返回 `401`。失败进入账号级限流。
- TOTP、恢复码、密码、Organization/Workspace Context 或联合认证状态变化后轮换 Session Token 和 CSRF Token。
- Session 同时检查撤销时间、2 小时 idle expiry 和 12 小时 absolute expiry。过期后不自动延长绝对有效期。
- Cookie 写请求缺少匹配的 Origin、CSRF Cookie、CSRF Header 或数据库摘要时返回 `403`，不执行 handler。
- 需要 MFA、邮箱验证、近期认证或企业联合认证时分别返回稳定的 `403` code。客户端据此进入对应流程。
- 删除当前 Session 后清除认证和 CSRF Cookie。删除其他 Session 不改变当前 Token。
- Organization 路由只接受 Organization 角色或 Organization 级 Service Account scope。Workspace 角色与 Workspace 级 Service Account 只能通过当前 Workspace 的权限检查。

## 企业联合登录

- Discovery、Token Exchange、UserInfo 或 Claim 校验失败返回 `502 identity_provider_error`。响应不包含上游正文、Client Secret 或 Token。
- state 事务先按 Provider 和摘要单次消费，再交换 Code。重复 callback 返回 `401`。
- 已绑定 `(issuer, subject)` 才直接登录。相同邮箱已存在但未绑定时跳转到 `account_link_required`，不会自动合并用户。
- JIT 未命中邀请、已验证企业域名或 Group Mapping 时跳转到 `federated_not_allowed`。
- Provider 与 Organization 不匹配时返回 `401`。强制企业登录的 Organization 对只有密码认证的 Session 返回 `403 federated_authentication_required`。
- 只有可信 ACR/AMR 命中时，联合登录才满足 Zeus MFA。其他 Session 继续进入 TOTP。
- Provider Token 完成签名、issuer、audience、nonce 和时间校验后，才查询全局 `(issuer, subject)`。校验失败不能创建全局身份或 Organization Binding。
- 显式绑定要求已验证 Session 和十分钟内认证。Binding 冲突返回 `409 external_identity_conflict`，不会改绑已有 Zeus 用户。
- `platform_managed` Organization 对 Owner 的身份设置读写统一返回 `403 organization_identity_settings_managed`。

## 租户 Context 与平台支持

- Workspace URL 与 Session Context 不一致返回 `409 workspace_context_changed`。Web 跳转到 Workspace 选择页，不在 GET 请求中轮换 Session。
- Context POST 校验 Membership 或有效平台 Grant、Origin 和 CSRF。成功后轮换 Session/CSRF Token，并以新 Cookie 继续。
- 平台 Grant 缺失、到期、撤销、Session 不匹配或 Organization 不匹配返回 `403 platform_tenant_access_required`。
- 有效平台 Grant 可以选择创建 Grant 时绑定的 active Workspace，不要求平台用户拥有 Membership。Grant 不能选择其它 Organization 的 Workspace。
- 创建平台 Grant 时密码、TOTP、近期认证或原因不满足要求，分别返回现有认证错误或 `422 validation_failed`。
- Grant 到期会关闭对应 SSE。已经开始的短数据库事务可以完成；后续请求和事件续传必须重新授权。
- `provisioning` Organization 只接受平台控制和首位 Owner 邀请。普通租户 API 返回 `409 organization_provisioning`。
- `suspended` Organization 的业务写入返回 `423 organization_suspended`。读请求按 RBAC 保留；Run claim、Schedule、Webhook、联合登录、OIDC Authorization 和 Refresh 被拒绝。已经 queued 的 Run 保留用于审计并收到取消请求；恢复 active 不会自动清除该请求，用户需要创建新 Run。
- `archived` Organization 返回 `404` 给普通租户请求。平台恢复动作把它变为 `suspended`，不会直接激活。

## Zeus OIDC Provider

- `/oauth2/authorize`、`/oauth2/token` 和 `/oauth2/revoke` 使用 OAuth JSON 或 redirect error。它们不使用 Zeus `application/problem+json`。
- 未验证 Redirect URI 时直接返回错误，不能跳转到客户端提供的地址。完成精确匹配后，协议错误才带 `state` 跳回 Client。
- 所有 Client 必须使用 S256 PKCE。缺少 verifier、挑战不匹配或 downgrade 返回 `invalid_grant` 或 `invalid_request`。
- Confidential Client 支持 `client_secret_basic` 和 `client_secret_post`。同时使用两种方式返回 `401 invalid_client`，且不会消费 Authorization Code。
- Authorization Code 只有一次 claim 机会。过期、重复、Client 不匹配、Redirect URI 不匹配或 PKCE 失败都不能签发 Token。
- Refresh Token 每次成功使用后轮换。旧 Token 重放会撤销整个 Family，当前和后代 Token 都返回 `invalid_grant`。
- Access Token、Authorization Code 和 ID Token 有效期为 5 分钟。Refresh Token idle expiry 为 7 天，absolute expiry 为 30 天。
- Suspend 不伪造已经签发 JWT 的即时撤销。外部 Resource Server 只依赖签名和 `exp` 时，现有 Access Token 最多继续有效 5 分钟；需要即时阻断的部署必须增加受控的撤销查询或网关策略。
- Token 签名只接受 RS256、固定 `kid` 和 `typ`。当前私钥缺失、解密失败或签名失败时返回 `server_error`，不会降级为无签名或对称算法。
- 常规密钥轮换保留旧公钥 7 天。泄漏处置可以缩短该窗口；下游缓存仍需单独清理。
- Revocation 对未知 Token 返回成功，避免泄漏 Token 存在性。Client 认证失败仍返回 `invalid_client`。
- OIDC Client 创建、修改和撤销要求十分钟内完成过用户认证。过期 Session 返回 `403 reauthentication_required`；Service Account 返回 `403 forbidden`。

## 身份邮件

- `email_outbox` 状态是 `queued → sending → sent`，失败时按退避重新进入 `queued`，达到尝试上限后进入 `failed`。
- claim 和 finish 使用 lease owner 与 fence。旧投递者无法把已经接管的邮件标成 `sent`。
- SMTP 接收邮件后断开连接属于未知结果。Zeus 会重试并可能产生重复邮件，不把未知结果写成成功。
- 邮件密文无法解开、收件地址无效或模板无法构造时进入 `failed`，不向日志写正文和 Token。
- IdentityMaintenance 进程退出后，`sending` 任务在租约到期后由其他 API 副本恢复。

## 身份观测

- 密码失败、MFA 失败、限流、联合 Provider 错误和 Refresh 重放是进程内单调 Counter。Pod 重启后从零开始，由指标后端负责跨重启聚合。
- 邮件积压和签名密钥年龄每 30 秒从 PostgreSQL 刷新。查询失败时 `zeus_identity_operational_metrics_up` 变为 `0`，其他 Gauge 保留上次值，不能当成当前事实。
- 指标不带用户、邮箱、Organization、Provider、Client 或 key id 标签。

## 恢复点回滚

- PostgreSQL PITR 可能恢复已经被使用或撤销的 Session、Refresh Token、一次性 Token、邀请、密码、MFA、Service Account、OIDC Client 和 Connection Secret。
- 恢复时保持入口关闭。等待 5 分钟让恢复前签发的 Access Token 过期，再失效恢复库中的 Session、Refresh Family 和一次性协议状态。
- 恢复缺口能从外部审计和变更记录准确对账时，只轮换受影响凭据。无法对账时采用全量失效，不能假定备份中的凭据状态仍然安全。
- 恢复后请求新的 OIDC 签名 key，验证新旧 JWKS 重叠，再开放流量。真实步骤见 `docs/runbooks/backup-restore.md`。

## Run

- 自动网络重试保留在同一个 Run，并增加 Attempt。
- 人工重试创建新 Run，并写入 `retry_of_run_id`。
- 运行失败写 `error_code` 和安全的 `error_detail`。
- terminal Run 不接受新状态变化。
- 租约过期允许新副本重新领取。
- 旧副本提交时 fence 不匹配，更新返回 false。

## Tool

- `required` 或 `supported` 可带幂等键重试。
- `unavailable` 不自动重试。
- 审批等待期间释放 Run 租约。
- 审批拒绝写入持久工具结果。
- 工具超时也写入配对结果。
- 输入不符合 Capability Schema 时，调用不会越过校验边界。
- 输出不符合 Capability Schema 时，写入 `capability_output_schema_violation` 配对结果。
- Schema 无效时 Run 以 `invalid_capability_schema` 失败，不执行 Capability。
- 外部系统已经执行但响应丢失时，Zeus 记录 `outcome_unknown`，不猜测成功或失败。

## 模型

- 连接失败、限流和 5xx 可以按 Workflow 策略重试。
- 无效响应和安全策略错误不自动重试。
- 流式响应中断时不写入不完整助手消息。
- 已写入工具调用后发生取消，必须补写合成工具结果。

## 数据库

- claim 和 finish 使用短事务。
- 外部 HTTP 不在事务中执行。
- RLS 上下文缺失时查询应返回空集或被拒绝。
- HTTP 连接无法切换到 `zeus_http` 时进程启动失败。Runtime 连接无法切换到 `zeus_runtime` 时 Supervisor 启动失败。
- Migration 失败会阻止 API readiness。
- `LISTEN/NOTIFY` 丢失不会丢 Run，轮询负责恢复。

## 进程退出

API 收到终止信号后停止领取新 Run。活动任务等待 60 秒。超时任务中止并等待租约过期，由其他副本恢复。
