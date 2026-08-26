# Zeus Harness Alpha+ 设计冻结

状态：主机 Alpha+ 与 Actor Boundary Foundation 验收通过；Apple container 新镜像验收待完成
基线：`4fede62`（Alpha+）

## 1. 产品术语

- **Session** 是用户在侧栏创建、切换和继续的会话。界面统一使用 `New Session`。
- **Run** 是 Session 内部的一次受策略约束的执行记录。一个 Session 可以没有 Run，也可以按时间拥有多个 Run。
- `/api/v1/overview` 仅保留 Alpha 演示兼容；Alpha+ 的主导航以 Session API 为事实源。

该边界避免为每次新对话复制一套虚假的 incident/tool Run，也与 Harness 的 Session/Agent 入口保持一致。

## 2. 本地用户与认证

Alpha+ 只支持一个本地实例 owner，并为后续迁移保留 member 枚举与数据库字段：

1. 数据库尚未配置 owner 时，每次启动都会轮换 32-byte 随机 bootstrap token，使旧 token 失效，
   并只向该进程终端输出当前 bearer 一次；数据库仅保存 SHA-256 digest 和过期时间。
2. `POST /api/v1/auth/bootstrap` 使用 token、用户名和密码创建首位 owner，并在同一事务中认领 Alpha 遗留的 Session/Run。
3. 密码使用 Argon2id PHC 字符串保存；不存在的用户名仍执行 dummy Argon2 校验，避免明显的用户名枚举时序差异。
4. 登录返回 32-byte opaque session token。Cookie 为 `HttpOnly; SameSite=Strict; Path=/`；
   浏览器入口为 HTTPS 时，部署必须显式设置 `ZEUS_COOKIE_SECURE=true` 才会附加 `Secure`。
5. 写请求要求同一登录会话的 CSRF token，并校验 `Origin`/`Host`。SSE 使用同源 Cookie 鉴权。
6. 未登录业务 REST/SSE 返回 `401`。本阶段所有认证入口和中间件均拒绝
   member；不能把预留的 member 行理解为已支持多用户。

Health 路由保持公开。公开注册、邮件找回、OAuth/SSO、WebAuthn 不属于本阶段。

## 3. 所有权与幂等

- `sessions.owner_user_id` 与 `runs.owner_user_id` 在首次 bootstrap 前允许为 `NULL`；业务路由在 bootstrap 前不可访问。
- bootstrap 事务把所有遗留空 owner 行认领给首位 owner，此后 ownership trigger 禁止再次修改。
- 正式 REST/SSE 的 Session/Run 读取、事件回放、resume、turn、review 和
  receipt 全部传入当前 actor，并在同一 SQLite 查询或事务中重新校验账号状态、
  role 与资源 owner。不存在、不拥有或不具备 Run owner 权限统一映射为 `404`。
- 所有 Session/Run command receipt 的身份为
  `(actor_scope, operation, idempotency_key)`；资源授权发生在 receipt replay 之前，
  猜中其他 actor 的 key 不能重放响应或改变错误类型。
- 既有 Alpha receipt 在迁移后使用 `__legacy__` scope，并在 owner bootstrap 时一并认领。
- reply claim 会重新校验 active Session owner；dispatch job 永久绑定批准它的 active
  owner。授权在排队后被撤销时，任务在一个事务中进入 durable 拒绝终态并追加
  `authorization_revoked` 证据，provider/connector 调用次数必须为零。

这些边界只是未来 member 能力的安全底座。当前 API 仍拒绝 member 登录；字段/队列配额、
分页、SSE 连接上限和登录限速完成前不得开放 member。

## 4. 设置

用户设置只保存安全偏好：

- `theme`: `system | light | dark`
- `preferred_model`: 服务端 allowlist 中的模型标识，可为空
- `revision`: 乐观并发版本；更新必须提交 `expected_revision`

Provider endpoint 和 API key 只从服务端环境或后续 SecretRef 解析，禁止由普通 Settings API 明文写入 SQLite。

## 5. 回复执行链

浏览器只提交用户 prompt，不再调用公开 flush 或上传 `assistant_message`：

```text
POST /sessions/{id}/turns
  -> transaction: user_message + open turn + queued reply_job
  -> 202 Accepted
  -> worker claims queued job (started checkpoint)
  -> ReplyProvider
  -> transaction: assistant_message + turn_flushed + job succeeded
  -> Session SSE
```

安全与恢复规则：

- Provider 调用前必须存在 durable `started` checkpoint。
- `queued` job 可在重启后继续；`started` 且无持久结果的 job 变为 `outcome_unknown`，不得自动重放可能计费的模型请求。
- Provider 失败必须形成明确的 durable failure/interrupted 状态，不能做空 flush，也不能伪造 assistant 成功。
- 本地 fallback 只说明“消息已保存但未配置模型”，事件必须标注 `local-fallback/non-model`，不能冒充智能回复。
- OpenAI-compatible provider 限制连接/总超时、响应体大小，禁止重定向，并对非 2xx、畸形 JSON 和空 choices fail closed。

## 6. 数据库迁移

- `0005_accounts.sql`：users、auth sessions、bootstrap tokens、user preferences、Session/Run owner。
- `0006_actor_receipts.sql`：actor-scoped Session/Run command receipts。
- `0007_reply_jobs.sql`：durable reply job 与 forward-only 状态 trigger。
- `0008_actor_boundaries.sql`：dispatch approving actor、授权撤销终态、owner 一致性
  trigger，以及 v7 receipt/dispatch 的唯一 owner 认领。

迁移必须原地保留 Alpha append-only ledger、事件外键与 runtime identity。任何一步失败都回滚整个 migration transaction。

## 7. Alpha+ 验收门槛

- 首次 bootstrap 只能成功一次，token 过期/重用均失败。
- 登录、登出、过期、禁用用户、CSRF、Origin 和 Cookie 属性有自动测试。
- owner-only 认证门槛和 Alice/Bob 的 REST、SSE、receipt collision 隔离有自动测试；
  未拥有资源统一为 `404`，member cookie 在产品 gate 打开前保持 `401`。
- New Session 创建、切换和刷新后恢复通过浏览器测试，旧 SSE 会被关闭。
- user message 之后由服务端产生 durable assistant/failure event；浏览器不能提交 assistant content。
- `system/light/dark` 首屏无闪白，刷新后保持，系统主题变化可跟随。
- reply job 的 queued/start/success/failure/outcome_unknown 和重启语义有存储测试。
- disabled/降权/owner mismatch 的 reply 与 dispatch claim 不触达外部执行，并留下
  durable terminal evidence。
- host 与 container 都通过完整 Rust/Web 测试和重启恢复检查。
