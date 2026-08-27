# Zeus Harness Alpha+ 设计冻结

状态：主机 Alpha+、Actor Boundary Foundation、API/Terminal Payload Resource Envelope、Bounded Event Feed、Point-query Durable Context、Bounded Read Models、SQLite Capacity Slice 2、SQLite Physical/Operation Capacity 与 Bootstrap Audit Retention 已实现并通过主机全量验收；current-image Apple 指定压力场景已通过，v12 current-image restart 与 Linux Docker PID/OOM authoritative gate 待完成
前置基线：`8117ed6`（SQLite Physical Capacity）

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
即使 SQLite 行数、活跃队列、event-slot 和事件载荷逻辑字节配额已落地，也不得开放 member。
SQLite 主库/WAL/磁盘 headroom 门禁和 bootstrap audit bounded retention 已经落地，但 member
仍须等待 tenant/account membership scope、account-scoped authorization 与安全审计生命周期。

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
actor/resource scope 绑定的 opaque cursor，页内仍按原顺序升序输出。鉴权、projection/tail 校验和各页
读取位于同一 SQLite snapshot；foreign resource 在 limit/cursor 语义检查前统一得到 `404`。
不在 bounded turn tail 中的 durable retry identity 通过 actor-scoped turn point GET 确认；无法
确认时保留原 idempotency key，不把旧消息改成新命令重发。异步点查返回前若用户切换 Session
或 attempt identity 已改变，selection epoch/session/turn/key guard 会丢弃旧结果。

SQLite Capacity Slice 2 在每个 `BEGIN IMMEDIATE` admission 事务内执行 owner scope 与 global
双层限制：Session 1,000/10,000、open turn 32/64、active reply 32/64、active dispatch
16/32、auth session 每用户/全局 32/256。每个 Session 的 ledger head 加未消费预留槽默认
最多 10,000，每个 Run 默认 50,000；Session/Run 的 `payload_json` 逻辑 UTF-8 字节默认分别
限制为 64 MiB/256 MiB，全局合计默认 1 GiB；bootstrap audit 详细窗口默认最多 1,024 行。配置可调但
不得为 0、不得让 scope/per-ledger 超过 global，也不得越过编译期 hard ceiling。鉴权和 exact
receipt replay 先于容量检查，所以 foreign resource 仍是 `404`，已成功命令在满配额时仍能 replay。

接受 turn 时同时预留两个 Session 终结事件槽和保守载荷字节；接受 dispatch 时同时预留两个
Run 槽和 start+terminal 字节。reply claim 必须确认完整预留仍在；dispatch claim 把 2 个槽
变为 1 个，并把字节预留收敛为 terminal 上界；success/failure/rejection/recovery 在同一事务
消费或释放剩余槽与字节并删除空 reservation。reservation 丢失或不足时在 provider/connector
之前 fail closed 为脱敏 `503`。普通容量拒绝为带 `Cache-Control: no-store` 的 `429`；reply/
dispatch queue 另带 `Retry-After: 2`。计量只覆盖 `session_events.payload_json` 与
`run_events.payload_json` 的实际 UTF-8 序列化字节，不宣称 DB file、WAL、索引、page overhead
或宿主磁盘空间有保证。过期 auth session 只在启动和新建登录会话前按稳定顺序清理最多 64 行。
ledger、receipt、job、turn 和 account audit 不做静默删除；bootstrap token detail 采用明确的
v12 retention：live 永不压缩，terminal lifecycle 按 sequence 最多 64 行一批链入 singleton
SHA-256 rollup 后才删除，原因区分 `superseded/consumed/expired/legacy_unknown`。rollup 是数据库内
历史压缩 commitment，不是外部防篡改锚。

SQLite Physical Capacity Slice 已实现并通过本地主机验证，采用以下默认值与编译期 hard ceiling：

| 配置 | 默认值 | hard ceiling | 含义 |
| --- | ---: | ---: | --- |
| `ZEUS_SQLITE_MAX_MAIN_BYTES` | 4 GiB（4,294,967,296） | 32 GiB | 主库 page 预算 |
| `ZEUS_SQLITE_WAL_TARGET_BYTES` | 16 MiB（16,777,216） | 256 MiB | WAL autocheckpoint/reset 目标 |
| `ZEUS_SQLITE_MIN_FREE_BYTES` | 256 MiB（268,435,456） | 8 GiB | 文件系统最小剩余空间 |
| `ZEUS_SQLITE_ADMISSION_RESERVE_BYTES` | 512 MiB（536,870,912） | 8 GiB | admission 文件系统 headroom watermark |

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

| 配置 | 默认值 | hard ceiling | 含义 |
| --- | ---: | ---: | --- |
| `ZEUS_SQLITE_MAX_CONCURRENT_OPERATIONS` | 8 | 32 | file/memory SQLite operation 总槽位 |
| `ZEUS_SQLITE_RESERVED_PROGRESS_OPERATIONS` | 1 | 8 | 为 durable progress 留出的槽位 |
| `ZEUS_SQLITE_OPERATION_ACQUIRE_TIMEOUT_MS` | 1,000 ms | 5,000 ms | 已进入等待路径后的最长等待时间 |

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
- v9 到 v10 为既有 open turn、queued dispatch 和 started dispatch 分别回填 2/2/1 个
  event slots；oversized durable TEXT 和已超配额旧库不得导致迁移失败。配额 exact/+1、
  满额 replay、reservation 消费/回滚、auth expiry cleanup 与稳定 429/503 合约有自动测试。
- v10 到 v11 精确回填 Session/Run event payload bytes 与 active finalization reservation；
  逻辑字节 exact/+1、物理主库边界、Admission/ReservedProgress/Finalization、507/503 合约、
  startup deep check 与显式 `verify_integrity` 都有自动测试。
- v11 到 v12 保留 token 插入顺序并将旧 terminal reason 标为 `legacy_unknown`；超过 detailed
  window 的 rotation/open、多批 64 行压缩、canonical digest、时钟回拨、current-v12 降限、
  低磁盘 pre-write gate、非法 transition/delete/rollup 回退和 deep corruption 都有自动测试。
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
- host 通过 281 个 Rust 测试（storage 131、runtime 28、API library 44、API main/config 4）与
  25 个 Web Node 测试。

## 8. 容器与 OOM 验收边界

- Docker Compose `full` 是 `cargo-watch`/Vite 开发拓扑，不是 release runtime 基准。API、Web、
  gateway 的 CPU/memory/PID ceiling 已通过
  `ZEUS_COMPOSE_{API,WEB,GATEWAY}_{CPUS,MEMORY,PIDS_LIMIT}` 静态接线；本机没有 Docker CLI，
  因而不声明 Compose build/up 或 Linux OOM 验收通过。
- Apple helper 的 release API 默认 2 CPU/1 GiB，可由 `ZEUS_CONTAINER_API_CPUS` 与
  `ZEUS_CONTAINER_API_MEMORY` 调整并在创建后核对。`scripts/apple-container.sh resources` 只读
  输出 inspect、cgroup v2 与 `/proc` 证据。
- `af29089` 已构建为独立 `zeus-operation-acceptance` current-image 栈；它使用独立 image/network/
  named volume 与 `18089`，未替换既有 `zeus-alpha`。`build`、`up`、`verify` 和保留 volume 的
  `restart-verify` 均通过，栈保留运行供本地检查。
- API 实际限制为 2 CPU/1 GiB。`/health/ready` 的 30,000 请求、并发 128 压力在 4.493 秒内
  完成：2,670 个 `200`、27,330 个 fail-fast `503`、transport error 0。第二轮 10,000 请求、
  并发 64 得到 414 个 `200` 与 9,586 个 `503`，所有 `503` code 都是
  `sqlite_operation_capacity_exceeded`。
- 压力期间及之后 cgroup `memory.peak=97,595,392` bytes（约 93 MiB），Zeus RSS 约 23 MiB，
  `oom=0`、`oom_kill=0`；CPU throttling 证明 2 CPU quota 生效。VM 无 Swap，Apple 1.0 仍没有
  per-container PID limit，`pids.max=max`。因此只声明该 current-image Apple readiness-pressure
  场景通过；Linux Docker PID/OOM authoritative evidence 与更低内存/对抗性压力仍是 deployment
  gate。
