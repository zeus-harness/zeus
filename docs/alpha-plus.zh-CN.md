# Zeus Harness Alpha+ 设计冻结

状态：主机 Alpha+、Actor Boundary Foundation、API Resource Envelope、Bounded Event Feed、Point-query Durable Context 与 Bounded Read Models 验收通过；Apple container 新镜像验收待完成
前置基线：`78a65e1`（Point-query Durable Context）

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
7. bootstrap/login 在 Argon2 前按真实 TCP peer、canonical account 和全局固定窗口限速；
   默认不信任 `Forwarded`/`X-Forwarded-For`。登录默认每分钟 global/source/account
   为 60/10/5，bootstrap 为 10/3；超限统一返回带 `Retry-After` 的 `429`。

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

这些边界只是未来 member 能力的安全底座。当前 API 仍拒绝 member 登录；字段、HTTP/SSE
连接、事件页边界、内部 point/batch read 和 Session/Run 有界 read model 已经落地，但
SQLite 存储/队列配额完成前不得开放 member。

Resource Envelope 的固定边界：auth JSON 8 KiB、command JSON 512 KiB；新建 Session/turn
ID 128 UTF-8 bytes、Session title 256 bytes、user message 64 KiB、review note 8 KiB；
`Idempotency-Key` 必须是单一的 1–128 ASCII graphic bytes。新 Session event ID 是有界的
ledger-local ID；pre-v9 durable ID 继续可寻址，避免升级后数据失联。字段校验发生在
fingerprint/receipt 之前。Run/Session SSE 共用 global 64、每 actor 4 条连接配额，permit
由 response body 持有。initial/hint/lag/poll 每次只从 SQLite 读取最多 128 条事件的
`LIMIT + 1` page；积压通过 cooperative continuation 分页补齐，cursor 只随已发送事件推进。

生产读取同样固定为 indexed `LIMIT + 1` keyset page：Session 列表默认 50、最大 100，
保持裸数组响应并通过 `X-Zeus-Next-Cursor` 返回续页 cursor；Session detail 的 Run ID/turn
分别默认 50、最大 100，Session event 默认 128、最大 256；Run detail 与 overview 的 Run
event 默认 128、最大 256。详情 collection 以 `pagination.*.{next_before,has_more}` 返回独立、
actor/resource scope 绑定的 opaque cursor，页内仍按原顺序升序输出。鉴权、projection/tail 校验和各页
读取位于同一 SQLite snapshot；foreign resource 在 limit/cursor 语义检查前统一得到 `404`。
不在 bounded turn tail 中的 durable retry identity 通过 actor-scoped turn point GET 确认；无法
确认时保留原 idempotency key，不把旧消息改成新命令重发。异步点查返回前若用户切换 Session
或 attempt identity 已改变，selection epoch/session/turn/key guard 会丢弃旧结果。

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
- `0009_point_queries.sql`：Run event typed lookup projection；Rust 以 128 行 keyset batch
  解码并原位回填既有事件，随后安装 approval/call/policy 与恢复队列索引、Run ledger
  连续序列 trigger。审批、派发、reply completion、attachment 与冷恢复只使用 point query
  或固定 64 行 batch。

迁移必须原地保留 Alpha append-only ledger、事件外键与 runtime identity。任何一步失败都回滚整个 migration transaction。

## 7. Alpha+ 验收门槛

- 首次 bootstrap 只能成功一次，token 过期/重用均失败。
- 登录、登出、过期、禁用用户、CSRF、Origin 和 Cookie 属性有自动测试。
- owner-only 认证门槛和 Alice/Bob 的 REST、SSE、receipt collision 隔离有自动测试；
  未拥有资源统一为 `404`，member cookie 在产品 gate 打开前保持 `401`。
- New Session 创建、切换和刷新后恢复通过浏览器测试，旧 SSE 会被关闭。
- 101 个 Session 可按 50/50/1 无重漏遍历；活动 Session 即使位于后续页也先用 point detail
  恢复，只有权威 `404` 才回退 primary Session。侧栏续页追加时按 ID 去重并保留已加载摘要。
- 51 个 turn 后，最旧 turn 即使离开默认 tail 仍可通过 actor-scoped point GET 恢复；Web
  使用 primary Session identity 判断主 Run 展示，不把 attachment tail 误当全集。
- user message 之后由服务端产生 durable assistant/failure event；浏览器不能提交 assistant content。
- `system/light/dark` 首屏无闪白，刷新后保持，系统主题变化可跟随。
- reply job 的 queued/start/success/failure/outcome_unknown 和重启语义有存储测试。
- v8 到 v9 的 typed lookup 回填不改写 payload；不连续 ledger 整体回滚，64+1 条恢复任务
  通过两批排空，同 key 并发审批只提交一次并重放其余响应。
- Session/Run detail 只返回最新 bounded tail；opaque cursor 的 kind、resource scope、canonical
  encoding、future-head 和跨资源使用均有自动测试，返回页保持连续且升序。
- disabled/降权/owner mismatch 的 reply 与 dispatch claim 不触达外部执行，并留下
  durable terminal evidence。
- body、字段和幂等键超限在 fingerprint/receipt/ledger/job 前失败；413/415/422/429
  problem 合约、真实 peer 限流、XFF 不可信与 SSE body-drop 释放 permit 有自动测试。
- host 通过完整 Rust/Web 测试；Apple container 的当前镜像验收状态按下文边界单独记录。
