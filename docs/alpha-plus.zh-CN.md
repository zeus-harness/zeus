# Zeus Harness Alpha+ 设计冻结

状态：主机 Alpha+、Actor Boundary Foundation、API/Terminal Payload Resource Envelope、Bounded
Event Feed、Point-query Durable Context、Bounded Read Models、SQLite Capacity Slice 2、SQLite
Physical/Operation Capacity、Bootstrap Audit Retention、schema v13 Account Membership
Foundation、schema v14 Account-scoped Durable Authorization、schema v15 Member Lifecycle /
Account Audit、schema v16 Session Reply Context Index 至 schema v25 Durable Session Context
Compaction 已实现；Apple 保留此前 Operation Capacity 指定压力证据与历史
v11→v12→v13→v14 迁移证据，current-image 证据见本节验收结果，Linux Docker PID/OOM
authoritative gate 待完成。

历史前置基线：`8117ed6`（SQLite Physical Capacity）

## 1. 产品术语

- **Session** 是用户在侧栏创建、切换和继续的会话。界面统一使用 `New Session`。
- **Run** 是 Session 内部的一次受策略约束的执行记录。一个 Session 可以没有 Run，也可以按时间拥有多个 Run。
- `/api/v1/overview` 仅保留 Alpha 演示兼容；Alpha+ 的主导航以 Session API 为事实源。

该边界避免为每次新对话复制一套虚假的 incident/tool Run，也与 Harness 的 Session/Agent 入口保持一致。

## 2. 本地用户与认证

Alpha+ 支持一个本地 `acc_local` account 内的 owner/member 协作：

1. 数据库尚未配置 owner 时，每次启动都会轮换 32-byte 随机 bootstrap token，使旧 token 失效，
   并只向该进程终端输出当前 bearer 一次；数据库仅保存 SHA-256 digest 和过期时间。
2. `POST /api/v1/auth/bootstrap` 使用 token、用户名和密码创建首位 owner，并在同一事务中认领 Alpha 遗留的 Session/Run。
3. 密码使用 Argon2id PHC 字符串保存；不存在的用户名仍执行 dummy Argon2 校验，避免明显的用户名枚举时序差异。
4. 登录返回 32-byte opaque session token。Cookie 为 `HttpOnly; SameSite=Strict; Path=/`；
   浏览器入口为 HTTPS 时，部署必须显式设置 `ZEUS_COOKIE_SECURE=true` 才会附加 `Secure`。
5. 写请求要求同一登录会话的 CSRF token，并校验 `Origin`/`Host`。SSE 使用同源 Cookie 鉴权。
6. owner 创建 member 时只在一次响应中返回 32-byte opaque setup token；数据库保存域分离
   SHA-256 digest 和 24 小时过期时间。member 用 token 设置密码并登录，token 过期、轮换、重用
   或猜错都统一失败且不泄露状态。
7. 未登录业务 REST/SSE 返回 `401`。member 可使用 Session/Run 与 reply，不能 approval、
   connector dispatch、成员管理或 audit 管理。
8. bootstrap/login/member setup 在 Argon2 前按真实 TCP peer 和全局固定窗口限速；login 另按
   canonical account 限速，setup token 不作为 rate-limit map key，避免持久化攻击者输入；
   默认不信任 `Forwarded`/`X-Forwarded-For`。登录默认每分钟 global/source/account
   为 60/10/5，bootstrap 为 10/3；超限统一返回带 `Retry-After` 的 `429`。

Health 路由保持公开。公开注册、邮件找回、OAuth/SSO、WebAuthn 不属于本阶段。

## 3. 所有权与幂等

- `sessions.owner_user_id` 与 `runs.owner_user_id` 在首次 bootstrap 前允许为 `NULL`；业务路由在 bootstrap 前不可访问。
- bootstrap 事务把所有遗留空 creator 行认领给首位 owner；v14 后这些列是 write-once metadata，
  授权只读取 `account_memberships`。
- 正式 REST/SSE 的 Session/Run 读取、事件回放、resume、turn、review 和
  receipt 全部传入完整 `AuthzContext`，并在同一 SQLite 查询或事务中重新校验 auth session、
  User/Account、membership role/status/revision 与资源 account。不存在或跨 account 统一映射为
  `404`；同 account 但缺 capability 映射为 `403 permission_denied`。
- 所有 Session/Run command receipt 的身份为
  `(account_id, actor_user_id, operation, idempotency_key)`；资源授权发生在 receipt replay 之前，
  猜中其他 actor 的 key 不能重放响应或改变错误类型。
- v14 把未配置实例的 legacy receipt/dispatch/reservation scope 迁移为窄化 `NULL` 状态，只允许
  revision-1 bootstrap owner 在同一事务中认领一次；配置后的新写入必须有 account+actor。
- reply claim 会重新校验固化的 actor membership revision/capability；dispatch job 永久绑定
  initiating 与 approving 两个主体并在 claim 同时复核。授权在排队后被撤销时，任务在一个事务中进入 durable 拒绝终态并追加
  `authorization_revoked` 证据，provider/connector 调用次数必须为零。

v14 把这些边界建成 member 能力的安全底座；v15 增加 setup、revisioned disable/role change、
SSE authority poll、worker dual-subject claim 与 account security audit 后才开放 member。
字段、HTTP/SSE 连接、事件页边界、内部 point/batch read 和 Session/Run 有界 read model，
SQLite 行数、活跃队列、event-slot、事件载荷逻辑字节、主库/WAL/磁盘 headroom，以及
bootstrap/account audit bounded retention 均继续独立生效。

Resource Envelope 的固定边界：auth JSON 8 KiB、command JSON 512 KiB；新建 Session/turn
ID 128 UTF-8 bytes、Session title 256 bytes、user/assistant message 64 KiB、review note 8 KiB；
`Idempotency-Key` 必须是单一的 1–128 ASCII graphic bytes。新 Session event ID 是有界的
ledger-local ID；pre-v9 durable ID 继续可寻址，避免升级后数据失联。字段校验发生在
fingerprint/receipt 之前。Run/Session SSE 共用 global 64、每 actor 4 条连接配额，permit
由 response body 持有。initial/hint/lag/poll 每次只从 SQLite 读取最多 128 条事件的
`LIMIT + 1` page；积压通过 cooperative continuation 分页补齐，cursor 只随已发送事件推进。

终端载荷进一步固定：typed reply response 512 KiB；provider/model/finish reason、reply
failure code、tool digest/code 各 128 bytes；reply/tool diagnostic 4 KiB；compact tool output
与 dispatch arguments JSON 各 64 KiB。超限 provider/executor 结果只结算一次为固定、脱敏、
有界的 durable failure，原始超限内容不进入 ledger 或 job result。dispatch admission 在同一
事务重新读取 runtime identity 与此前 immutable `ToolCallRequested`，严格比对 policy、
tool/version/effect、arguments/digest 和 sandbox；错误任务不能占住 queue head 与 reservation。

生产读取同样固定为 indexed `LIMIT + 1` keyset page：Session 列表默认 50、最大 100，
保持裸数组响应并通过 `X-Zeus-Next-Cursor` 返回续页 cursor；Session detail 的 Run ID/turn
分别默认 50、最大 100，Session event 默认 128、最大 256；Run detail 与 overview 的 Run
event 默认 128、最大 256。详情 collection 以 `pagination.*.{next_before,has_more}` 返回独立、
`(account, actor, kind, resource)` scope 绑定的 opaque cursor，页内仍按原顺序升序输出。鉴权、projection/tail 校验和各页
读取位于同一 SQLite snapshot；foreign resource 在 limit/cursor 语义检查前统一得到 `404`。
不在 bounded turn tail 中的 durable retry identity 通过 actor-scoped turn point GET 确认；无法
确认时保留原 idempotency key，不把旧消息改成新命令重发。异步点查返回前若用户切换 Session
或 attempt identity 已改变，selection epoch/session/turn/key guard 会丢弃旧结果。

SQLite Capacity Slice 2 在每个 `BEGIN IMMEDIATE` admission 事务内执行 actor/account/global
三层限制：Session 1,000/10,000/10,000、open turn 32/64/64、active reply 32/64/64、active
dispatch 16/32/32；auth session 仍为每用户/全局 32/256。每个 Session 的 ledger head 加未消费预留槽默认
最多 10,000，每个 Run 默认 50,000；Session/Run 的 `payload_json` 逻辑 UTF-8 字节默认分别
限制为 64 MiB/256 MiB，全局合计默认 1 GiB；bootstrap audit 详细窗口默认最多 1,024 行。配置可调但
不得为 0、不得让 actor 超过 account、account 超过 global、per-ledger 超过 global，也不得越过
编译期 hard ceiling。鉴权和 exact
receipt replay 先于容量检查，所以 foreign resource 仍是 `404`，已成功命令在满配额时仍能 replay。

接受 turn 时同时预留两个 Session 终结事件槽和保守载荷字节；接受 dispatch 时同时预留两个
Run 槽和 start+terminal 字节。reply claim 必须确认完整预留仍在；dispatch claim 把 2 个槽
变为 1 个，并把字节预留收敛为 terminal 上界；success/failure/rejection/recovery 在同一事务
消费或释放剩余槽与字节并删除空 reservation。reservation 丢失或不足时在 provider/connector
之前 fail closed 为脱敏 `503`。普通容量拒绝为带 `Cache-Control: no-store` 的 `429`；reply/
dispatch queue 另带 `Retry-After: 2`。计量只覆盖 `session_events.payload_json` 与
`run_events.payload_json` 的实际 UTF-8 序列化字节，不宣称 DB file、WAL、索引、page overhead
或宿主磁盘空间有保证。过期，以及绑定 missing/disabled/suspended/stale-revision authority 的 auth
session，只在启动和新建登录会话前按稳定顺序清理最多 64 行。
ledger、receipt、job 和 turn 不做静默删除；bootstrap token detail 采用明确的 v12 retention：
live 永不压缩，terminal lifecycle 按 sequence 最多 64 行一批链入 singleton SHA-256 rollup
后才删除，原因区分 `superseded/consumed/expired/legacy_unknown`。

v15 account audit 默认 detailed target 4,096、每 account hard limit 8,192、global hard limit
32,768、每 account/global progress reserve 64/256、compaction batch 64。普通可审计 mutation 只能
使用 ordinary capacity；仅 active→disabled、active owner→member、audit policy update 与 archive
checkpoint 可使用有限 reserve。member create、token rotate、setup、enable 与 member→owner 仍走
ordinary lane。legal hold 阻止详细行压缩，
archive-required 只允许压缩已 checkpoint 的前缀，容量不足时普通 mutation 原子失败为 `507`。
两类 rollup/hash chain 都只是数据库内 commitment，不是外部防篡改锚。

SQLite Physical Capacity Slice 已实现并通过本地主机验证，采用以下默认值与编译期 hard ceiling：

| 配置                                  |                 默认值 | hard ceiling | 含义                                  |
| ------------------------------------- | ---------------------: | -----------: | ------------------------------------- |
| `ZEUS_SQLITE_MAX_MAIN_BYTES`          | 4 GiB（4,294,967,296） |       32 GiB | 主库 page 预算                        |
| `ZEUS_SQLITE_WAL_TARGET_BYTES`        |   16 MiB（16,777,216） |      256 MiB | WAL autocheckpoint/reset 目标         |
| `ZEUS_SQLITE_MIN_FREE_BYTES`          | 256 MiB（268,435,456） |        8 GiB | 文件系统最小剩余空间                  |
| `ZEUS_SQLITE_ADMISSION_RESERVE_BYTES` | 512 MiB（536,870,912） |        8 GiB | admission 文件系统 headroom watermark |

启动必须校验 `WAL target < admission reserve < max main`，并以 checked addition
保证 `min free + admission reserve` 不溢出。`max_page_count` 只限制 SQLite 主库页数；WAL
target 是 autocheckpoint 与 journal reset 的目标，不是 active WAL 的绝对硬上限。可用空间通过
`statvfs` 读取，存在不可避免的 TOCTOU，因此它只能作为 admission signal，不能当作持久磁盘
预留。上面的逻辑 event-payload 配额仍是独立限制，不因物理容量门禁而替代或放宽。

每个 file-backed connection 都重新应用并核对 `max_page_count`、`wal_autocheckpoint`、
`journal_size_limit`、有界 cache 与禁用 `mmap`。普通 `Admission` 要求主库低于保留 headroom
后的 watermark、active WAL 不超过 target，并保有 `min free + admission reserve` 可用空间；
`ReservedProgress`/`Finalization` 为已接受工作保留排空能力，只继续要求主库不越绝对上限且
可用空间不少于 `min free`。admission reserve 是单一 watermark，不会按每个请求或 active job
重复累加。

物理门禁拒绝业务操作时返回脱敏的 `507 physical_storage_exhausted + Cache-Control: no-store`；
`/health/ready` 对相同 watermark 返回脱敏 `503 + Cache-Control: no-store`。readiness 只做
schema/PRAGMA metadata 与物理 watermark 检查；启动在监听端口开放前完成深度业务/ledger/FK/
SQLite integrity 检查和 truncating WAL checkpoint。运维或测试可显式调用
`SqliteStore::verify_integrity` 重跑昂贵检查，不把它放进每次 health probe。

SQLite blocking operation 也有独立的并发边界：

| 配置                                       |   默认值 | hard ceiling | 含义                                |
| ------------------------------------------ | -------: | -----------: | ----------------------------------- |
| `ZEUS_SQLITE_MAX_CONCURRENT_OPERATIONS`    |        8 |           32 | file/memory SQLite operation 总槽位 |
| `ZEUS_SQLITE_RESERVED_PROGRESS_OPERATIONS` |        1 |            8 | 为 durable progress 留出的槽位      |
| `ZEUS_SQLITE_OPERATION_ACQUIRE_TIMEOUT_MS` | 1,000 ms |     5,000 ms | 已进入等待路径后的最长等待时间      |

默认普通 lane 只有 7 个槽位。普通 read/admission 先 `try_acquire` general permit，饱和即
fail fast，不形成无界等待者；progress lane 可使用全部 8 个 total permit，但也只等待配置的
有界 timeout。total gate 与 memory 单连接 gate 共用同一个 deadline，不会各自重新取得完整
timeout；memory 普通 waiter 不进入连接 FIFO，已有 progress waiter 会优先取得下一次连接。
reply/dispatch 的 claim、worker 所需 point read、completion、recovery，以及
显式 manual-flush finalization 都走 progress lane。memory store 在进入 blocking pool 前还要取得
单连接 async gate，避免把 mutex 等待者堆入 `spawn_blocking`。

permit 被 move 进 `spawn_blocking`，覆盖 file connection open/drop、SQLite busy wait 和完整
transaction；调用方 async future 被 abort 时，仍在运行的 blocking closure 不会提前释放容量。
Provider/connector 的外部 `await` 位于 SQLite transaction 之外，不持有 operation permit。
业务请求饱和时稳定返回
`503 sqlite_operation_capacity_exceeded + Retry-After: 1 + Cache-Control: no-store`。
`/health/live` 不访问 SQLite；`/health/ready` 无法取得 operation capacity 时返回脱敏 `503`。
内部 reply/dispatch worker 只对该瞬时 capacity error 使用固定有界延迟重试；provider/connector
已经返回后，其结果会保留到幂等 finalization 成功，不会因 permit timeout 被丢弃。重复 wakeup
最多合并为一个 running worker 和一个 pending drain cycle，不再为每次 replay/kick 创建 mutex
等待任务。

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
  -> transaction: user_message + open turn + Agent + manifest + queued model job
  -> 202 Accepted
  -> worker prepares and exactly starts queued model job
  -> ReplyProvider
  -> transaction: assistant_message + turn_flushed + Agent/job succeeded
  -> Session SSE
```

安全与恢复规则：

- 每次接受 turn 时，以请求中的 `expected_sequence` 为历史边界，只读取已经完整 flush 的
  user/assistant 对，再追加当前 user message。Session-native Agent request 的第一条且唯一一条
  system message 是当时 active 的 account Agent prompt；其 ID、revision 与域分离 content digest
  绑定在 canonical secret-free deployment manifest，精确内容只随 immutable request 持久化。
- system prompt、可选 durable `checkpoint`、最新至多 26 对未压缩历史消息、当前 user message
  及其后的 durable `context` message 共享 64 KiB 初始 UTF-8 内容预算。初始最多 56 条 message；
  Agent 全程最多 64 条，为四组 assistant tool call / tool result
  预留八条。当前 user message 无法与固定 prompt 一起装入该预算时，在任何 durable write 前
  返回 `413 agent_request_too_large`。interrupted 或尚未 flush 的 turn 不进入模型上下文。
- admission、model claim、tool continuation 与 deep-integrity 都要求 system message 首位唯一、
  内容匹配 manifest digest。admission 发现 prompt 缺失、重复、位置或内容错误时拒绝命令并回滚
  整个事务；已经 queued 的 work 在 claim 时发现持久化 authority 损坏、promptless 或与当前
  manifest 漂移，才 durable settle 为 `deployment_unavailable`。两条路径都发生在 provider I/O 前。
- 组装后的 provider request 随 immutable model job 持久化。相同命令的迟到重试、known tool
  completion continuation 和重启恢复都复用 exact persisted request，不根据当前 prompt、live knowledge 或
  Session 的新状态重建上下文，也不会再次调用 provider。
- Provider 调用前必须存在同一 prepared claim 对应的 durable `started` checkpoint。
- `queued` job 可在重启后继续；`started` 且无持久结果的 job 变为 `outcome_unknown`，不得自动重放可能计费的模型请求。
- 最后一个成功 checkpoint 后出现第 27 个完整 flushed turn 时，schema v25 从最老 13 对中选择
  provider envelope 可完整容纳的最大 whole-turn 前缀并原子排入 compaction job，不切分消息。
  原始 Session event/turn 永不删除或改写；成功摘要以独立 durable
  `checkpoint` role 注入未压缩 tail 之前。compaction 的 `queued` 可恢复，`started` 无结果只变为
  `outcome_unknown`；failed/unknown generation 阻断自动重排队，不得用新 job ID 重放可能已经
  计费的摘要请求。
- Provider 失败必须形成明确的 durable failure/interrupted 状态，不能做空 flush，也不能伪造 assistant 成功。
- `local-development` 可显式配置 capability-rooted `workspace_list_directory`、
  `workspace_find_paths`、`workspace_search_text`、`workspace_read_file`、`workspace_read_lines`、`workspace_replace_text`、
  `workspace_insert_text` 与 `workspace_create_file`：模型可列出根内 canonical relative directory
  的至多 64 个排序子项，以相对 glob 和固定目录/文件/总条目/深度预算发现至多 32 个普通文件，
  再以固定目录/文件/深度/字节预算查找至多 32 个字面量文本匹配，并读取
  canonical relative path 对应的 UTF-8 普通文件，最多 8 KiB；也可从至多 64 KiB 的 UTF-8
  普通文件读取至多 200 行的 inclusive range，选择结果仍限制为 8 KiB 且不静默截断。穿越、
  symlink、越界目录或内容在 connector 内 fail closed。前五者以 read-only policy 自动执行。文本替换仅允许在至多 64 KiB
  的现有 UTF-8 普通文件中替换唯一 exact `old_text`，以同目录临时文件、权限复制、原文复验和
  atomic rename 提交，并固定要求 owner approval；同参近期重试返回有界 receipt，异参 call-ID
  重用或目标变化拒绝。行插入以 0 表示文件开头、其余值表示指定 logical line 之后，限制 4 KiB
  插入文本和 64 KiB 最终文件，使用相同的权限复制、原文复验、atomic rename、owner approval
  与 receipt 语义；行读取与插入都把 final newline 后的空内容视为 trailing logical line。
  文件创建仅接受至多 12 KiB UTF-8 内容和已存在的根内父目录，通过同目录
  临时文件、file sync、create-new hard-link publication 与 directory sync 原子发布，绝不覆盖
  现有路径或隐式创建父目录，并同样要求 owner approval。所有结果仍按 exact tool completion
  持久化后再进入下一模型步骤；没有 shell、外部进程或隐式写权限。
- persistent terminal 只在 embedding runtime 显式注入 isolated backend 时进入 Agent manifest；
  Zeus 核心自身不启动 host process，也不提供 host-shell fallback。session owner 使用 durable work
  中服务端校验的 account/actor/Session/turn/Agent scope，foreign scope 只能得到 unknown；每 owner
  最多 4 个 session，service 全局最多 128 个 live/pending session，输入、输出和 read 行数均有硬上限。
  Agent durable terminal state 提交后必须按 exact scope 移除并 best-effort close 全部 session；close
  失败只记录 backend 泄漏风险，不能保留内部容量或重开 Agent。open/send/signal/close 必须逐次 owner
  approval，read/list 为 read-only allow；mutation receipt 绑定 scope、call ID、tool 与 arguments
  digest。backend call 还必须受 Zeus 外层 deadline 约束：spawn 与 initial snapshot 默认共用 60 秒，
  send/control/cleanup 分别为 45/10/10 秒，可在 5 分钟 hard ceiling 内由 embedding application 调整，cleanup 是一个 owner
  全部 close 的总预算。backend 的 `wait_reason=timeout` 不等同 Zeus deadline，也不证明进程退出。
  started checkpoint 后 mutation 跨过 deadline 或无法确认副作用结果时必须 durable settle 为
  `outcome_unknown`，终止当前 Agent turn 且不得自动重试；read-only deadline 返回确定失败。
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
- `0010_capacity.sql`：`finalization_reservations`、Session turn/dispatch 的 owner scope 与
  2→1→0 event-slot 状态机、legacy active-work 回填、auth expiry index，以及 reservation
  binding/scope/单调递减/空槽删除 trigger。旧库即使已经超过新配额仍可迁移、读取和排空；
  只拒绝新的 admission。
- `0011_event_payload_bytes.sql`：为 Session/Run ledger 与 active finalization reservation
  增加逻辑载荷字节计数和预留，按既有 UTF-8 `payload_json` 的 BLOB byte length 精确回填，
  并由 trigger 在同一事务中记账。
- `0012_bootstrap_audit_retention.sql`：把旧 `used_at` 保守迁移为 `legacy_unknown`，增加单调
  sequence 与明确 terminal reason；rotation/open 按当前 detailed-row limit 以最多 64 行批次
  更新 SHA-256 rollup 并删除已承诺前缀，live token 永不压缩。v11 旧顺序按 `rowid` 保留，
  wall-clock 回拨不会阻止 compaction；current-v12 因降限需要写入时先通过 Migration physical gate。
- `0013_account_membership_foundation.sql`：创建唯一 `acc_local` 与 `account_memberships`，只把既有
  唯一 active owner 回填为 revision 1 membership；为 Incident/Session/Run/runtime identity 原地
  回填 immutable `account_id`，并安装 account/revision/last-active-owner/跨根一致性 trigger、索引
  与 readiness/deep-integrity 检查。迁移先证明旧 owner、actor、receipt、job、reservation 和
  runtime boundary；member-owned、跨 owner 或外键损坏的 v12 数据整体回滚。v13 不切换现有
  owner-based API 授权，也不开放 member。
- `0014_account_scoped_durable_authorization.sql`：把 auth session、Session/Run receipt、reply/
  dispatch job 与 finalization reservation 重建为 account+actor scope，固化 membership revision
  与 dispatch 双主体；删除旧 owner 授权 trigger/index，安装 v2 cursor、actor/account/global
  capacity 与 durable capability 校验。迁移在同一 transaction 内执行 preflight、row/FK/schema/
  actor-state postflight，无法证明的 authority 回滚并保留 schema v13；API member gate不变。
- `0015_member_lifecycle_account_audit.sql`：增加 digest-only member setup token、account audit
  event/hash chain、bounded rollup、policy 与 archive checkpoint；owner lifecycle transition 在同一
  事务推进 membership revision、撤销 auth/setup token、返回已 claim 工作摘要并写入 audit。
  migration/readiness/deep integrity 校验 token、单调 sequence/hash、rollup/checkpoint 与 policy
  约束，完成后才开放 capability-gated member 路径。
- `0016_session_reply_context_index.sql`：为 `assistant_message` Session event 增加 partial index，
  使模型上下文按 `expected_sequence` 直接读取最新至多 31 个完整 user/assistant 对；合法的
  assistant-less flush 被排除，查询不再收集完整 Session ledger。
- `0017_session_agent_loop.sql`：增加 Session-native Agent、immutable model job、顺序 tool call、
  approval receipt 与固定 loop limit。
- `0018_agent_tool_completion_replay.sql`：把 known tool result 绑定到 exact continuation request，
  completion 重放不能在重启后改变下一次模型输入。
- `0019_agent_deployment_manifest.sql`：持久化 canonical、secret-free deployment manifest，并把
  每个新 Agent turn 绑定到不可变 digest；无法证明绑定的 legacy queued work fail closed。
- `0020_agent_execution_ledger.sql`：为每次真正 external start 写入 immutable RunEpoch，并以
  Agent-local hash chain 记录 workflow transition；legacy history 只记录诚实的不完整 snapshot。
- `0021_agent_operation_claims.sql`：在 external start 之前增加 append-only prepared claim 与连续
  generation。prepared 可过期/重领且不写 unknown；started 不按 TTL 重放，只能由 durable
  terminal commit 或启动恢复释放。
- `0022_agent_knowledge_context.sql`：持久化 account-scoped immutable corpus revision、selection
  snapshot、canonical context 与 Agent/initial-job/execution admission digest；迁移时冻结 exact
  legacy Agent 集合并写入 domain-separated count+digest commitment，防止 post-v22 binding 被剥离后
  伪装为 legacy。
- `0023_account_knowledge_catalog.sql`：增加 account active corpus head 和 actor-scoped ingestion
  receipt。Owner 通过 expected revision CAS 与 canonical `Idempotency-Key` 原子替换 catalog，
  mutation 同事务写 account audit；revision 0 是不落库的隐式空 catalog。Head revision 最多 256，
  每个 account 最多保留 128 个不同 corpus revision 与 64 MiB canonical envelope。
- `0024_account_agent_prompt.sql`：增加 owner-governed Agent prompt head、immutable
  content-addressed revision 与 actor-scoped receipt。revision 0 是原内置 prompt 与 manifest
  revision `1`；第一次自定义更新映射到 manifest revision `2`。内容最多 16 KiB，catalog head
  最多推进 256 次，每个 account 最多保留 128 个不同内容和 2 MiB aggregate bytes。
- `0025_session_context_compaction.sql`：增加不可变 source boundary/digest、上代 checkpoint、模型
  配置和 exact request 绑定，以及 `queued -> started -> succeeded|failed|outcome_unknown` 单向状态
  机。成功 summary 最多 16 KiB 且必须严格小于被替换 source；raw Session ledger 保持不变。

schema v24 的 system prompt governance 复用 `0019` 的 prompt binding，并增加 durable
head/revision/receipt。Owner-only `GET/PUT /api/v1/agent/prompt` 通过 expected-revision CAS 和
canonical `Idempotency-Key` 更新；普通 member 不能管理，但新 Agent 使用当时 active revision。
更新不改写既有 Agent；旧 queued governed revision 在 claim 时 fail closed，已经 started 的工作
继续使用已持久化 request。Owner-only history 列表返回 newest-first bounded metadata，exact point
route 可读取 revision 0 或任一 committed content；恢复旧内容仍通过 CAS `PUT` 创建新 revision。
schema v25 的 compaction 与 prompt/knowledge 分离：它只压缩已经完整 flush 且绑定到不可变事件
边界的历史 turn；后续 Agent request 同时绑定成功 checkpoint 和 checkpoint 之后的原始 tail。
新回合组装与 compaction 成功并发时，存储层按请求实际携带的 checkpoint（包括没有 checkpoint）
做精确重建，避免把安全的旧快照误判为损坏。
Knowledge v1 生成独立、受治理、带完整 digest 的 canonical context
snapshot，不修改 system prompt。schema v22 已完成数据库绑定、
Agent request 注入和 exact replay；LLM 协议层使用独立 durable `context` role，并只在
OpenAI-compatible provider wire 上映射为另一条 `user` message。schema v23 已完成 owner-only
`GET/PUT /api/v1/knowledge/catalog`、持久 revision/idempotency receipt、权限与篡改校验。未配置时
runtime 使用隐式空 corpus；配置后 owner/member 的新 Agent 从 active corpus 做确定性选择，并把
exact corpus/snapshot 固化到该 Agent，之后的 catalog 更新不会改写旧 turn。Actor-scoped
`GET .../agent/knowledge/explain` 可审计实际 selection 与完整 digest binding，但不会返回未命中的
account corpus entry；pre-v22 Agent 返回明确的 `legacy_unbound`。Owner 还可通过
`GET /api/v1/knowledge/catalog/revisions` 做 newest-first 有界历史分页，并通过
`GET /api/v1/knowledge/catalog/revisions/{revision}` 读取 exact immutable corpus。恢复旧版本时把该
corpus 的 `entries` 作为现有 CAS `PUT` 的新输入，因此生成新 revision，不覆盖或删除历史；这组
只读能力复用 v23 receipt/corpus，不增加 schema migration。

迁移必须原地保留 Alpha append-only ledger、事件外键与 runtime identity。任何一步失败都回滚整个 migration transaction。

## 7. Alpha+ 验收门槛

- 首次 bootstrap 只能成功一次，token 过期/重用均失败。
- 登录、登出、过期、禁用用户、CSRF、Origin 和 Cookie 属性有自动测试。
- owner/member capability 门槛和 Alice/Bob 的 REST、SSE、receipt collision 隔离有自动测试；
  未拥有资源统一为 `404`，member 普通 Session/Run/reply 成功而 approval/admin 为 `403`。
- New Session 创建、切换和刷新后恢复通过浏览器测试，旧 SSE 会被关闭。
- 101 个 Session 可按 50/50/1 无重漏遍历；活动 Session 即使位于后续页也先用 point detail
  恢复，只有权威 `404` 才回退 primary Session。侧栏续页追加时按 ID 去重并保留已加载摘要。
- 51 个 turn 后，最旧 turn 即使离开默认 tail 仍可通过 actor-scoped point GET 恢复；Web
  使用 primary Session identity 判断主 Run 展示，不把 attachment tail 误当全集。
- user message 之后由服务端产生 durable assistant/failure event；浏览器不能提交 assistant content。
- Agent system prompt 的 manifest ID/revision/content digest、request 首位唯一性、64 KiB 初始
  content 与 64-message 全程预算，以及 admission/claim/continuation/deep-integrity fail-closed
  语义有自动测试；revision-0 兼容、owner/member capability、CAS/idempotency、v23→v24 migration、
  HTTP 到真实 provider request 的 binding 和 queued drift 都有覆盖；prompt drift 时 provider
  调用数为零，恢复复用 exact persisted request。
- `system/light/dark` 首屏无闪白，刷新后保持，系统主题变化可跟随。
- reply job 的只读队首观察、固定 job ID 精确 start/replay、queued/start/success/failure/
  outcome_unknown 和重启语义有存储测试；模糊 start ACK 不会跳到下一条任务。
- v8 到 v9 的 typed lookup 回填不改写 payload；不连续 ledger 整体回滚，64+1 条恢复任务
  通过两批排空，同 key 并发审批只提交一次并重放其余响应。
- v9 到 v10 为既有 open turn、queued dispatch 和 started dispatch 分别回填 2/2/1 个
  event slots；oversized durable TEXT 和已超配额旧库不得导致迁移失败。配额 exact/+1、
  满额 replay、reservation 消费/回滚、auth expiry cleanup 与稳定 429/503 合约有自动测试。
- v10 到 v11 精确回填 Session/Run event payload bytes 与 active finalization reservation；
  逻辑字节 exact/+1、物理主库边界、Admission/ReservedProgress/Finalization、507/503 合约、
  startup deep check 与显式 `verify_integrity` 都有自动测试。
- v11 到 v12 保留 token 插入顺序并将旧 terminal reason 标为 `legacy_unknown`；超过 detailed
  window 的 rotation/open、多批 64 行压缩、canonical digest、时钟回拨、current-v12 降限、
  低磁盘 pre-write gate、非法 transition/delete/rollup 回退和 deep corruption 都有自动测试。
- v12 到 v13 对 fresh/未配置与既有 owner 数据原地建立 `acc_local`；v1/v5/v8/v12 fixture 的
  account 回填、bootstrap 同事务建 membership、revision/identity/last-owner trigger、root scope
  immutability、deep integrity，以及 member-owned history/外键破坏时无部分写入回滚都有自动测试。
- v13 到 v14 原地重建 account-scoped auth session、receipt、reply/dispatch job 与 reservation；
  configured/unconfigured active work、窄化 NULL bootstrap claim、owner-only auth session 保留、
  disabled owner/额外 account preflight 与 version-13 原子回滚都有自动测试。
- v14 到 v15 原地增加 member setup 与 account audit；token 明文不落库、轮换/过期/单次消费、
  last-owner、revision conflict、session/token revoke、disable-before/after-claim、audit hash/rollup/
  cursor、legal hold、archive checkpoint、ordinary/progress/global capacity 与事务回滚都有自动测试。
- operation gate 的普通 lane fail-fast、单一 deadline、memory progress 优先、等待 future cancel 与
  partial permit 回收、caller abort 后 permit 生命周期、内部 capacity-only retry、worker wake
  合并、最后一个 progress waiter 取消后的主动唤醒、provider/connector panic 的
  `outcome_unknown` 收口、普通流量饱和时 worker progress，以及稳定
  503/Retry-After/no-store 映射合约都有确定性主机测试。
- Session/Run detail 只返回最新 bounded tail；opaque cursor 的 kind、resource scope、canonical
  encoding、future-head 和跨资源使用均有自动测试，返回页保持连续且升序。
- disabled/降权/owner mismatch 的 reply 与 dispatch claim 不触达外部执行，并留下
  durable terminal evidence。
- body、字段和幂等键超限在 fingerprint/receipt/ledger/job 前失败；413/415/422/429
  problem 合约、真实 peer 限流、XFF 不可信与 SSE body-drop 释放 permit 有自动测试。
- assistant/reply/tool terminal payload 的 exact/+1 边界、非法 provenance、超限
  provider/executor 的单次有界结算，以及不可 claim dispatch 在 admission 前完整回滚有自动测试。
- host 按项目既有统计口径通过 565 个 Rust 测试（connectors 18、deployment 8、knowledge 29、
  storage 248、runtime 48、API library 71、API main/config 6）与 28 个 Web Node 测试。
- `cargo fmt --all -- --check`、workspace all-target clippy、Web check/lint/production build 均通过。

## 8. 容器与 OOM 验收边界

- Docker Compose `full` 是 `cargo-watch`/Vite 开发拓扑，不是 release runtime 基准。API、Web、
  gateway 的 CPU/memory/PID ceiling 已通过
  `ZEUS_COMPOSE_{API,WEB,GATEWAY}_{CPUS,MEMORY,PIDS_LIMIT}` 静态接线；本机没有 Docker CLI，
  因而不声明 Compose build/up 或 Linux OOM 验收通过。
- 独立 `compose.linux-acceptance.yaml` 与 `scripts/linux-container-acceptance.sh` 现已定义 Linux
  release-runtime 门禁：normal API 2 CPU/1 GiB/128 PID，low-memory API 1 CPU/256 MiB/64 PID，
  两者均令 memory-swap 等于 memory，并核对 release image、非 root/read-only/cap-drop、internal
  network、cgroup v2、Argon2、durable reply、operation pressure、OOM/PID 时间序列与保留卷重启。
  GitHub Actions 会运行两个 profile 并上传脱敏证据；在真实 Linux job 通过前，这仍是“自动化已
  落地、live gate 未通过”，精确契约见 `docs/linux-container-acceptance.zh-CN.md`。
- Apple helper 的 release API 默认 2 CPU/1 GiB，可由 `ZEUS_CONTAINER_API_CPUS` 与
  `ZEUS_CONTAINER_API_MEMORY` 调整并在创建后核对。`scripts/apple-container.sh resources` 只读
  输出 inspect、cgroup v2 与 `/proc` 证据。
- `af29089` 曾构建为独立 `zeus-operation-acceptance` 验收栈；它使用独立 image/network/
  named volume 与 `18089`，未替换既有 `zeus-alpha`。`build`、`up`、`verify` 和保留 volume 的
  `restart-verify` 均通过，栈保留运行供本地检查。
- `cdaa211`（schema v12）随后在同一隔离 project 上重建镜像，并保留由 schema v11 创建的 named
  volume。第一次 `up/verify` 完成 v11→v12 migration；再次执行 `restart-verify` 重建容器与网络但
  保留该 volume，API/Web/gateway、认证状态、匿名保护边界与 `configured=false` 未配置状态在重启
  前后保持一致的检查全部通过。当时 v12 readiness 的 exact-schema 检查还覆盖了迁移后的再次
  打开。
- schema v13 镜像随后在同一个 `zeus-operation-acceptance` project 上保留上述现为 v12 的 named
  volume，原地完成 v12→v13 migration；保留 volume 的 `restart-verify` 通过。
- 历史 schema v14 镜像又保留上述现为 v13 的 named volume，原地完成 v13→v14 migration；
  `verify` 与保留 volume 的 `restart-verify` 都通过。当时 API effective limit 核对为 2 CPU/1 GiB；
  重启后 `memory.current=79,466,496`、
  `memory.peak=98,201,600`、Zeus RSS 9,824 KiB、`pids.current=6`，`memory.events` 为
  `oom=0`、`oom_kill=0`。该历史验证证明 migration/reopen 与当时仍关闭的 member 产品 gate；Apple
  `pids.max=max`，不是 PID-limit 保证。
- 最近一次容器证据仍是 schema v15 镜像：它继续保留该 now-v14 volume，并通过 v14→v15 原地
  migration、再次打开与 `configured=false` 恢复。API 仍为 2 CPU/1 GiB，记录的
  `memory.current=80,617,472`、`memory.peak=99,479,552`、Zeus RSS 10,252 KiB、
  `pids.current=7`，OOM/kill 为 0。
- schema v16 的 reply-context index 已通过主机 migration、readiness、query-plan 与多轮上下文
  测试；尚未把上述历史容器证据改写为 v16 运行证据。
- fresh `zeus-audit-acceptance` 在端口 `18090` 以 detail 2、每 account ceiling 8、progress reserve 2
  实测 member setup/reply、owner-only 403、checkpoint、legal-hold 507、普通容量拒绝、disable reserve、
  session revocation、完整 export manifest 与 hold release；浏览器验证 New Session、消息回复、
  Settings/Members/Audit 和 dark mode，无 console warning/error。保留卷 restart 后
  `configured=true`；`memory.peak=43,433,984`、Zeus RSS 10,340 KiB、OOM/kill 为 0。
- 此前 Operation Capacity 指定压力场景中，API 实际限制为 2 CPU/1 GiB。`/health/ready` 的 30,000
  请求、并发 128 压力在 4.493 秒内
  完成：2,670 个 `200`、27,330 个 fail-fast `503`、transport error 0。第二轮 10,000 请求、
  并发 64 得到 414 个 `200` 与 9,586 个 `503`，所有 `503` code 都是
  `sqlite_operation_capacity_exceeded`。
- 该历史压力期间及之后 cgroup `memory.peak=97,595,392` bytes（约 93 MiB），Zeus RSS 约 23 MiB，
  `oom=0`、`oom_kill=0`；CPU throttling 证明 2 CPU quota 生效。VM 无 Swap，Apple 1.0 仍没有
  per-container PID limit，`pids.max=max`。因此只声明此前 Operation Capacity Apple
  readiness-pressure 与历史 v14 migration/restart 各自通过；v14 当轮没有重跑该压力。Linux
  Docker PID/OOM authoritative evidence 与更低内存/对抗性压力仍是 deployment gate。
