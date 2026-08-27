# Zeus Harness Alpha+ 架构

本文描述当前 Alpha+ 的实现边界和必须由测试证明的运行语义。它不是未来路线图。

## 运行拓扑

```text
Client / SvelteKit Web
          │ same-origin REST + Run/Session SSE
          ▼
  Actor Auth / CSRF ───────► Axum API
                                 │
                                 ▼
                   Runtime（Session + Run Coordinator）
                      │           │              │
                      │           │              ├──► Authz / Tool Registry
                      │           │              │          │
                      ▼           ▼              ▼          ▼
              Session ledger   Run ledger   Reply worker  Connector
              turn / receipt   dispatch     LLM boundary  / Sandbox
```

- `protocol`：认证、设置、Session/Run HTTP、SSE、turn 与可版本化事件合约。
- `tenancy`：本地 owner 身份、Argon2id 密码、opaque token、CSRF 与域分离 digest。
- `llm`：object-safe reply provider、本地非模型 fallback 和有界 OpenAI-compatible 客户端。
- `kernel`：纯状态转换，不读数据库、不执行外部工具。
- `authz`：精确工具名规则、策略 revision、环境和 effect guard；没有命中即拒绝。
- `tools`：工具描述、注册表、参数验证和 object-safe executor 边界。
- `connectors`：具体工具适配器。生产 RDS executor 在 Alpha 中不存在。
- `storage`：schema v12 migration、用户/偏好、独立 Session/Run ledger、typed event lookup、
  actor-scoped 回执、durable reply/dispatch queue，以及 logical/physical/operation capacity。
- `runtime`：Session 命令编排、reply/Run worker、提交后 SSE 提示和启动恢复。
- `zeus-api`：进程组合、owner 认证、CSRF、provider 配置、REST/SSE 和 readiness。

SQLite 是本地单实例 Alpha+ 的权威存储。Restate、MinIO 和 PostgreSQL 当前不是第二套事实源。
当前 Web 认证后列出用户 Session，恢复仍存在的上次活动 Session，并行订阅 Run/Session SSE；
命令响应和后续权威 Session GET 用于合并事件并校准投影。浏览器只能提交 user message，不能
提交 assistant content 或调用生产 flush route。
Session 列表按 opaque cursor 逐页追加；保存的活动 Session 即使不在首屏，也先通过 actor-scoped
point detail 恢复，只有权威 `404` 才回退 primary Session。

## 事件与状态

每个 Run 和每个 Session 各自拥有从 1 连续递增的 `sequence`。它们只在所属 ledger 内用于
排序、回放、CAS 和 SSE 去重，不能跨 ledger 比较。命令幂等使用独立的 `Idempotency-Key`
回执，sequence 不是幂等键。

```text
ToolCallRequested
        │
        ▼
ToolPolicyDecided
   ├─ deny ───────────────► NotDispatched::PolicyDenied
   ├─ allow ──────────────► Queued
   └─ require_approval
             │
             ▼
      ApprovalRequested
        ├─ reject ────────► ApprovalDecided(status=not_dispatched)
        └─ allow_once ────► Queued
                                  │
                                  ▼
                     ToolDispatchStarted
                     (durable checkpoint)
                                  │
                         executor / sandbox
                                  │
                ┌─────────────────┼──────────────────┐
                ▼                 ▼                  ▼
            Succeeded           Failed         OutcomeUnknown
```

审批通过只表示这个 `call_id` 获得一次授权并进入队列。只有持久化的 `ToolResult::Succeeded`
才表示工具成功。UI 不得从审批事件自行推导执行成功。

Session 状态机独立于 Run 状态机：

```text
create
  │
  ▼
ready ── start_turn ──► running / open turn + queued reply job
                              │
                              ├─ worker success ──► assistant_message + turn_flushed ──► ready
                              │
                              └─ failure / unknown / restart ──► needs_attention / interrupted
                                                                    │
                                                                    └─ resume ──► ready
```

Session ledger 记录 `session_created`、`run_attached`、`user_message`、可选的
`assistant_message`、`turn_flushed`、`turn_interrupted` 和 `session_resumed`。一个 Session
可以拥有多个 Run，但一个 Run 只能属于一个 Session。Session 命令不推进 Run sequence，
也不触发 dispatch worker。

## 写入边界

所有 Session POST 都要求非空 `Idempotency-Key`。同 key、同请求返回持久化的第一次响应；
同 key、不同请求返回冲突。除 create 外，命令还必须携带 `expected_sequence`，在
`BEGIN IMMEDIATE` 中对 Session head 做 CAS。

- create：写入 `ready` 投影、`session_created` 和完整响应回执。
- start：只允许 actor 拥有的 `ready` Session；在一个事务中创建唯一 open turn、追加
  `user_message`、投影进入 `running`、保存 actor-scoped 响应回执，并插入 immutable queued
  reply job。真实 API 返回 `202`。
- reply worker：claim 事务先复验 active actor 与 Session owner，再把 queued job durable
  claim 为 `started`，随后在数据库锁之外调用 provider。
  成功事务追加带 `provider_id/model/reply_kind` 的 `assistant_message`、flush turn、追加
  `turn_flushed` 并把 job 标为 `succeeded`。确定失败写 `failed`；timeout/transport 等不确定
  远端结果写 `outcome_unknown`，两者都把 Session 转为 `needs_attention`，不得自动重调 provider。
- flush：仅保留在不带认证的 storage/runtime 合约测试 router；真实 authenticated server 不注册
  此路由，浏览器不能上传 assistant content。
- resume：只允许没有 active turn 的 `needs_attention` Session；追加
  `session_resumed`，投影回到 `ready` 并保存响应回执。

Session commit 后才发布进程内提示。start/reply/resume 不修改 Run ledger、approval 或 dispatch
job；reply job 与 Run dispatch job 是两条独立队列。

审批命令也在一个 `BEGIN IMMEDIATE` 事务内完成：

1. 重新校验 active owner 与 Run ownership，再读取 actor-scoped 持久幂等回执。
2. 对 Run head sequence 做 CAS。
3. 追加 `ApprovalDecided` 事件并更新 Run 投影。
4. Approve 时插入唯一的 queued dispatch job。
5. 保存第一次响应的完整 JSON。
6. Commit 后才发送进程内 SSE 提示。

Session 和 Run 的进程内 broadcast 都只负责低延迟提示，不是事件事实源。两种 SSE 都从各自
的 sequence cursor 每 2 秒补读一次持久 ledger；即使提示丢失，也不会永久漏掉已提交事件。

worker 在调用 connector 之前，必须先在另一个事务中复验 dispatch job 绑定的批准 actor 仍是
active owner 且仍拥有 Run，再把 job 从 queued CAS 为 started、追加 `ToolDispatchStarted` 并推进
Run sequence。授权已撤销时，该事务直接把 job 置为 rejected、Run 置为 `needs_attention`，追加
`ToolResult::NotDispatched(reason=authorization_revoked)`；不会生成假的 started checkpoint，也不会
调用 connector。该事务失败时 executor 调用次数同样必须为零。
connector 在数据库事务和锁之外运行。

结果事务把 started job 变成 finished，追加一个 ToolResult 并更新 Run 投影。外部执行已经发生
但结果事务失败时，不得立即重试外部工具。

## 冷恢复

API 监听端口之前按固定顺序完成：

1. 取得数据库相邻 `.zeus.lock` 的 OS 排他锁，配置 SQLite 并迁移到 schema v12；按当前
   detailed-row limit 以最多 64 行 batch 压缩 bootstrap terminal audit prefix，再按
   `(expires_at, token_hash)` 最多清理 64 个过期 auth session。
2. 绑定并核对 runtime identity、primary Session/Run 和 demo attachment。
3. 以固定 64 行 batch 读取 `started` 且没有持久结果的 reply job，循环排空：结算为 `outcome_unknown`，追加
   `turn_interrupted`，不得重放可能已经计费的 provider 请求。queued reply 原样保留并可安全领取。
4. 再以固定 64 行 batch 循环处理没有 reply job 终态解释的 open Session turn：将 turn 标为 `interrupted`，追加
   `turn_interrupted`，Session
   进入 `needs_attention`。不生成 flush ack，也不修改 Run ledger。
5. 以固定 64 行 batch 循环处理 started 且没有 ToolResult 的 dispatch：追加 `OutcomeUnknown`，Run 进入
   `needs_attention`，不自动重试外部调用。
6. waiting-for-approval 原样保留；queued 且没有 started checkpoint 的 job 才可以继续派发；
   已有终态结果不重新执行。
7. 恢复和安全派发完成后，进程才绑定监听端口。

锁由最后一个 Store clone 的生命周期持有；第二个进程不能进入 migration 或恢复路径。被中断的
Session 必须通过幂等、sequence-checked resume 显式回到 `ready`。

SQLite Physical Capacity Slice 已在监听端口开放前的启动阶段完成深度业务/ledger/FK/SQLite
integrity 检查与 truncating WAL checkpoint。`/health/ready` 只保留 schema/PRAGMA metadata
和物理 watermark 检查；运维或测试需要重跑昂贵检查时显式调用
`SqliteStore::verify_integrity`，避免 readiness 触发全 ledger 扫描或 checkpoint。

稳定的 `call_id` 会传给 provider 作为幂等键，但 Zeus 不据此宣称任意外部系统都具有
exactly-once 语义。

## 策略与执行边界

- 除 health、auth status、首次 bootstrap 和 login 外，真实服务的业务 REST/SSE 都要求 active
  owner。bootstrap/login 必须 exact same-origin；写请求还要求与登录会话绑定的 CSRF token。
  session cookie 为 opaque、`HttpOnly; SameSite=Strict`；HTTPS 部署必须显式设置
  `ZEUS_COOKIE_SECURE=true` 才附加 `Secure`。
- Alpha+ 明确拒绝 schema 预留的 `member` 登录。正式 Run/Session 查询、SSE、resume、turn、
  review 和 receipt 已全部 actor-scoped，并有 Alice/Bob 隔离测试；字段、HTTP/SSE 连接和
  event page 边界、内部 point/batch read、有界 list/detail，以及 SQLite 行数、active queue、
  event-slot、事件载荷逻辑字节配额和 DB/WAL/disk headroom 门禁已落地。但 member 仍须等待
  tenant/account membership scope、account-scoped authorization 与安全审计生命周期，不能仅因
  数据面已隔离就开放。
- auth JSON 明确限制为 8 KiB、command JSON 为 512 KiB；新建 Session/turn ID、title、
  user/assistant message、review note 与严格幂等键分别按 UTF-8 bytes 设置硬上限。typed
  reply response 为 512 KiB，compact tool output 与 dispatch arguments JSON 为 64 KiB，
  provider/model/finish/code/digest 和 diagnostic 也分别具有 128 bytes/4 KiB 固定边界。新 Session event
  使用有界 ledger-local ID；pre-v9 durable reference 继续可寻址。共享纯校验在相关 API、
  runtime、storage 入口的 fingerprint 和 receipt 前执行，超限不得产生持久副作用。
- bootstrap/login 的 fixed-window limiter 在 Argon2 前一次锁内完成 prune/check/charge；默认只认
  `ConnectInfo` 的直连 `IpAddr`，不读取不可信 proxy header。key map 上限为 4096，满表时
  fail closed，定时清理避免由新来源触发逐请求全表扫描。
- Run/Session SSE 共用 global 64、每 actor 4 条连接配额；owned permit 被移动进 response
  stream，只有 body drop 或流结束才释放。initial replay、hint reconciliation、Lagged recovery
  和 durable poll 都使用 SQL `LIMIT + 1` page，默认 128、硬上限 256；`has_more` 通过页间
  `yield_now` cooperative continuation 补齐，cursor 只随实际发送的 sequence 前进。
- Session summary list 使用 `(owner, updated_at DESC, id ASC)` indexed keyset，默认 50、最大
  100，并以响应头续页。Session detail 的 attachment/turn/event tail 和 Run detail/overview 的
  event tail 都使用 `LIMIT + 1`，collection 上限 100、event 上限 256；opaque cursor 绑定 kind
  与 actor/resource scope。actor 鉴权先于 cursor/limit 语义，projection、tail 和各独立 page 在同一
  SQLite read transaction 中校验，页内再恢复为原始升序。
- Session turn 提供 actor-scoped `(session_id, turn_id)` point GET。Web 的 durable retry 不会因
  turn 离开默认 50 条 tail 就清除原 command identity；回执重放后会再次读取权威 turn 终态。
  点查跨越 Session 切换时由 selection epoch、Session ID、turn ID 和 command key 联合 guard，
  旧异步结果不得覆盖新 Session 的 attempt 或 draft。
  主 Run 是否属于当前页面由启动时已校验的 primary Session identity 决定，不从 attachment tail
  反推。
- 未知工具、缺失策略、重复/冲突规则、effect 或 environment 不匹配：默认拒绝。
- Approval 只能解除 `require_approval`，不能覆盖显式 deny。
- dispatch 前用同一 policy revision 和不可绕过 guard 再检查一次。
- dispatch admission 在 `BEGIN IMMEDIATE` 内重新读取 bound runtime identity 与 durable
  `ToolCallRequested`，严格比对 policy、tool/version/effect、arguments/digest 和 sandbox；
  任何不匹配都在 projection、receipt、job 与 reservation 写入前失败，不能形成永久阻塞队首。
- SQLite schema v4 增加 Session ledger；v5 增加用户、认证会话、偏好和 write-once owner；
  v6 把命令 receipt 主键迁移为 actor scope；v7 增加 immutable、forward-only reply job。
  v8 为 dispatch 持久化 approving actor，并增加 Session/Run/reply/receipt owner 一致性 trigger
  与授权撤销拒绝终态。v9 增加从 typed payload 派生并逐行核对的 Run event lookup
  projection、approval/call/policy 和恢复队列索引、连续 Run sequence trigger；既有 payload
  在 128 行 keyset batch 中解码回填，失败时整个 migration 回滚。
  v10 增加 owner/global admission quota、过期 auth session 的 64 行确定性清理，以及
  `finalization_reservations`。open turn、queued dispatch、started dispatch 在迁移中分别回填
  2/2/1 个 event slots；旧库已超配额不阻止迁移、读取或 recovery，只拒绝新 admission。
  v11 为 Session/Run 增加事件载荷累计计数，为 active finalization reservation 增加逻辑字节
  预留，并用 SQLite trigger 按实际存储的 UTF-8 `payload_json` 原子记账。迁移按 BLOB byte
  length 精确回填历史 ledger，为 open turn 与 queued/started dispatch 回填保守终结预算；
  历史用量超过当前配置仍可读取和排空，只阻止新的 admission。
  v12 为 bootstrap token lifecycle 增加单调 sequence 和
  `superseded/consumed/expired/legacy_unknown` terminal reason；详细窗口超限时，rotation 与 open
  在同一事务内按最多 64 行 batch 更新 versioned SHA-256 rollup 后删除 terminal 前缀，live
  token 永不压缩。旧 v11 行按 `rowid` 保持插入顺序，时钟回拨不阻断压缩；current-v12 因降限
  需要写入时先通过 Migration physical gate。rollup 只是数据库内 commitment，不是外部可信锚。
  每个 pre-v4 Run 会绑定到生成的 `session-{run_id}`，原 Run/Event 不重写、不丢弃。
- runtime identity 持久绑定 profile、environment、primary Session/Run、policy ID 和
  revision；不一致时启动失败。Run attachment 当前用于 migration 和 demo seed，Alpha 不公开
  attach-Run HTTP route。
- queue claim 与 started recovery 在任何外部调用前再次核对 actor 状态、role、resource owner、
  job 的 run、policy ID 和 revision。
- Session/Run command 在鉴权与 exact receipt replay 之后、状态写入之前检查 logical capacity。
  turn admission 预留两个 Session event slots 与完整终结载荷预算；dispatch admission 预留两个
  Run slots 与 start+terminal 载荷预算。reply claim 必须仍持有完整预留；dispatch started 将
  2→1 并把字节预算收敛为 terminal 上界；success/failure/rejection/recovery 在终态事务降到
  0 后删除 reservation。缺失/不足/错绑时在 provider/connector 前脱敏 `503`，普通容量拒绝
  使用 `429 + Cache-Control: no-store`，reply/dispatch queue 另返回 `Retry-After: 2`。
  字节计量只覆盖两张 event ledger 的序列化 `payload_json`，不等于 SQLite 主库、WAL、索引、
  page overhead 或宿主磁盘保证。
- SQLite Physical Capacity Slice 已实现并通过本地主机验证：主库 4 GiB（hard ceiling 32 GiB）、WAL
  target 16 MiB（hard ceiling 256 MiB）、最小可用空间 256 MiB（hard ceiling 8 GiB）、
  admission headroom watermark 512 MiB（hard ceiling 8 GiB）。配置必须满足 `WAL target < admission
  reserve < max main`，并用 checked addition 保证 `min free + admission reserve` 不溢出。
  `max_page_count` 是主库 page 上限；WAL target 只用于 autocheckpoint/journal reset，不是
  active WAL 的绝对硬上限。`statvfs` 可用空间检查存在 TOCTOU，只能降低风险，不能提供磁盘
  预留保证；该 headroom 是单一 admission watermark，不按请求或 active job 累加，逻辑
  event-payload 配额仍独立执行。每个 file-backed connection 都应用并核对物理 PRAGMA；
  `Admission` 同时检查主库/WAL/free-space watermark，`ReservedProgress`/`Finalization` 则允许
  已接受工作在主库绝对上限与 `min free` 内排空。业务拒绝为脱敏 `507 + no-store`，
  `/health/ready` 对 watermark 不满足返回脱敏 `503 + no-store`。
- SQLite Operation Capacity Slice 把所有 blocking SQLite work 放在总量 semaphore 下：默认
  `max=8`、`reserved progress=1`、acquire timeout 1,000 ms，hard ceiling 分别为 32、8、
  5,000 ms。普通 lane 因 reserve 只有 7 个槽位，先用 `try_acquire` fail fast，避免在 total gate
  前形成无界 waiter；progress lane 可使用全部 total 槽位，但其等待也受 timeout 限制。total 与
  memory gate 共用单一 deadline。memory backend 在进入 blocking pool 前另有单连接 async gate；
  普通 waiter 留在 FIFO 之外，已有 progress waiter 优先取得下一连接。
- operation permit 被 move 进 `spawn_blocking`，覆盖 file connection open/drop、busy wait 和完整
  transaction；即使 caller future abort，仍在运行的 blocking closure 也不会提前归还 permit。
  Provider/connector 外部 `await` 不持有 permit。reply/dispatch claim、worker point read、
  completion、recovery 与显式 manual-flush finalization 走 progress lane，普通 reads/admission 不能挤占
  reserve。业务饱和稳定返回
  `503 sqlite_operation_capacity_exceeded + Retry-After: 1 + no-store`；`/health/live` 完全不访问
  SQLite，`/health/ready` 进入 operation gate 失败时返回脱敏 `503`。
- 内部 reply/dispatch worker 对 operation capacity 使用固定 25 ms 延迟继续重试，并保留已经
  产生的 provider/connector outcome 直到幂等 completion 成功。wake state 把任意重复 kick
  合并为一个 running worker 与至多一个 pending cycle；非 capacity 错误只在已有 pending cycle
  时延迟后再 drain，避免在 worker mutex 后堆积或忙转 Tokio task。
- provider 与 connector future 在独立 Tokio task 内执行；panic 不会把 wake state 永久留在
  running，而是在 durable started checkpoint 之后按 at-most-once 语义结算为
  `outcome_unknown`，不重试外部操作。
- OpenAI-compatible reply endpoint 默认只接受 HTTPS 或 loopback HTTP，禁止 redirect，限制连接/
  总超时和响应体；queued job 绑定 endpoint/model/limits 的非秘密配置 digest，API key 不入 ledger。
- provider assistant 或 executor output/diagnostic 超过终端字段边界时，runtime 使用固定、脱敏、
  有界 failure 一次性结算；原始超限载荷不进入 event、reply/dispatch job，也不会自动重试。
- sandbox 或 executor 不可用：写入 `NotDispatched`，禁止回退到宿主机裸执行。
- `production-guarded` profile 即使 owner 已认证，仍因真实生产 connector 缺失而保持执行禁用。
- `dev.marker.write` 仅在 `local-development` profile 注册，只能在服务端固定目录写服务器生成的
  marker 文件；参数不能提供路径。
- `ZEUS_DEMO_PROFILE=production-guarded` 是默认值；切到 `local-development` 时必须使用独立
  SQLite 数据库，并由 `ZEUS_LOCAL_MARKER_ROOT` 固定写入根目录。

## 容器边界

- Docker Compose 是开发拓扑：`full` 使用 `zeus_data:/var/lib/zeus`，`infra`、`postgres`、
  `debug` 和 `sandbox` 是独立 profile。Compose `.env` 和 project name 只作用于这条路径。
  API、Web、gateway 已分别静态接线可配置的 CPU/memory/PID ceiling；`full` 的 API 是
  `cargo-watch` 开发服务，默认 4 CPU/4 GiB/512 PID 包含编译余量，不是 runtime/OOM 基准。
- Apple `container` helper 只运行 production-guarded API、Web 和 gateway，不启动 Compose
  基础设施或 local marker executor。默认 project 是 `zeus-alpha`，资源名为
  `zeus-alpha-{api,web,gateway,net,data}`。只有 gateway 尝试发布 loopback `18088`；API 和
  Web 只在 project network 暴露，由 Caddy 作为唯一入口。数据卷是
  `zeus-alpha-data:/var/lib/zeus`。
- Apple helper 的 Web/API health、匿名 auth status 和 protected overview `401` 检查优先使用
  动态 gateway container IP，必要时回退 loopback；所有请求强制绕过代理并设置连接/响应超时。
  `status` 同时报告 direct 和 published URL，当前运行时的 port-forward reset 不会被误报成
  应用健康。
- Apple release API VM 默认 2 CPU/1 GiB，可通过 `ZEUS_CONTAINER_API_CPUS`/
  `ZEUS_CONTAINER_API_MEMORY` 调整并由 helper 在创建后核对。`resources` 子命令只读采集
  `container inspect`、cgroup v2 CPU/memory/swap/PID 与 `/proc` 证据。Apple `container` 1.0
  没有 per-container PID-limit 参数；观测到的 `pids.max` 不是配置保证。
- Apple build 使用仓库物理路径下的过滤临时 context，规避 `/tmp` 与 `/private/tmp` 前缀不一致
  导致的空 context；完成或收到 INT/TERM 都清理 context，并保留正确退出状态。
- Apple helper 给 container、network 和 volume 写入
  `dev.zeus-harness.managed=true` 与 matching project label；同名 foreign/unlabeled 资源会被
  拒绝。`down` 只删除 owned container/network 并保留 volume。
- Apple reset 先执行 owned-resource `down`，且只有
  `ZEUS_CONTAINER_CONFIRM_RESET=zeus-alpha-data scripts/apple-container.sh reset` 才删除默认
  volume；project override 时确认值必须改成对应 `${project}-data`。
- 两条路径都挂载完整数据目录，不能只挂单个 SQLite 文件，因为 WAL 还需要 `-wal` 和
  `-shm`。API 容器不挂 Docker socket；Apple gateway 使用 read-only root 和独立 tmpfs。
- Compose `tool-sandbox` 只是隔离形态样例，不是已接通的 executor；没有 RPC/Unix socket
  时必须返回 unavailable。
- SQLite volume 只允许一个 API/worker 实例；竞争实例由持久 sidecar 排他锁拒绝，不支持
  NFS 或多副本共享。sidecar 是协调文件，不在正常 Drop 时删除。

## Alpha+ 验收

- schema v1/v3/v7/v8/v9/v10/v11 原地迁移到 v12 后，原 Run/Event payload 保留，primary Session/Run 绑定稳定；迁移时
  尚未 bootstrap 的 legacy actor 只允许在首次 owner bootstrap 事务中认领一次。
- 重启后用户/偏好、Session/turn/event、reply job、Run/Event、审批决定、dispatch job 和命令
  回执仍存在。
- Session start 与 reply enqueue 同事务；reply success 把 assistant provenance、连续事件、turn
  和 job 终态原子提交，注入失败时整体回滚。测试专用 flush 合约仍证明旧迁移路径的原子性。
- open turn 重启后只追加一次 `turn_interrupted`，Session 进入 `needs_attention`，不生成 flush
  ack、不改变 Run ledger；显式 resume 后才能开始新 turn。
- 同 key 同输入只提交一次并重放响应；同 key 不同输入返回冲突；不同 key 由对应 ledger 的
  head sequence CAS 仲裁。
- 未知工具和策略拒绝路径的 executor 调用数为零。
- checkpoint 写入失败时外部副作用为零。
- reply/dispatch 排队后 actor 被禁用、降权或失去 ownership 时，claim 写入 durable
  `authorization_revoked` 终态，provider/connector 调用数为零。
- reply/dispatch started 后模拟崩溃，均恢复为 `outcome_unknown` 且不发生第二次外部执行。
- 首次 bootstrap 只能消费一次 token；登录、CSRF、同源、Cookie 属性、设置 revision、退出后
  401 以及退出/失效后 SSE 关闭有自动化或 live 验收。
- bootstrap audit 的 v11 reason 迁移、canonical digest、64 行多批压缩、rotation/open 降限、
  wall-clock rollback、低磁盘 pre-write gate、非法 lifecycle/删除/rollup 回退与 deep corruption
  都有确定性存储测试。
- 第二个进程不能同时打开同一个持久数据库；profile/policy identity 不匹配时 fail closed。
- 活跃 Run/Session SSE 不能无限拖住进程退出；SIGINT/SIGTERM 的 graceful drain 最长五秒，
  随后关闭剩余连接并释放 SQLite lease。
- local-development marker：批准前不存在、拒绝后不存在、allow-once 后只生成一个稳定文件。
- 生产 RDS 路径只能得到 executor unavailable，不能得到伪造成功。
- Session/Run SSE 重连都严格从各自大于 cursor 的 sequence 补齐事件。请求同时携带 query
  cursor 和 `Last-Event-ID` 时，后者优先。
- 请求或状态错误按 400/401/403/404/409/413/415/422/429 返回 problem details；内部执行不变量返回脱敏的
  `500 runtime_unavailable`；storage/config/registry 不可用返回脱敏的
  `503 runtime_unavailable`。内部错误只写服务端日志。
- 本地 Alpha+ 已按 UTF-8 bytes 限制 Session ID/title/user+assistant message/review note、
  typed reply/tool terminal payload 与幂等键；SSE
  replay 已在 storage 层分页，future cursor 对已授权资源返回 `409`，foreign resource 仍为
  `404`。审批、派发、reply completion、attachment 和启动恢复已改为 typed point query 或
  固定 64 行 batch；Session list/detail 与 Run detail/overview 也已改为 indexed bounded read
  model。SQLite row/active/event-slot、逻辑 event-payload byte quota 与 physical capacity gate
  和 operation capacity gate 已落地；bootstrap audit detailed retention 与 rollup 已落地，对外或
  多租户部署前仍必须完成 tenant/account membership scope 与 account security-audit retention。
  current-image Apple 指定 readiness-pressure 已通过；完整低内存/
  对抗性压力与 Linux Docker PID/OOM authoritative evidence 仍是 deployment gate。
- Web 保持紧凑时间线、一个内联审批卡和一个 composer；支持真实 New Session、活动 Session
  刷新恢复、owner 设置/退出和 system/light/dark。持久 command identity 在刷新后恢复，丢失
  start 响应不会生成重复 turn；浏览器等待 server worker/SSE，不自行 flush。
- 当前自动化结果是 281 个 Rust 测试（storage 131、runtime 28、API library 44、API
  main/config 4）和 25 个 Web Node 测试全部通过；Rust fmt/clippy、Svelte
  check/autofixer、lint 和 production build 也通过。

提交 `af29089` 已构建并运行在独立 `zeus-operation-acceptance` project（端口 `18089`）；既有
`zeus-alpha` 容器与 volume 未被替换。current-image 的 `build/up/verify/restart-verify` 均通过。
提交 `cdaa211` 的 schema v12 镜像随后在相同隔离 project 上重建，并保留 schema v11 named
volume；首次启动完成 v11→v12 migration，保留 volume 的第二次 `restart-verify` 也通过。API、
Web、gateway、认证状态、匿名保护边界均通过，且 `configured=false` 未配置状态在重启前后一致；
v12 readiness 的 exact-schema 检查覆盖迁移后的再次打开。验收栈继续运行在
`127.0.0.1:18089`。
API 限制核对为 2 CPU/1 GiB；30,000 次 readiness、并发 128 的压力结果为 2,670 个 `200`、
27,330 个预期 operation-capacity `503`、transport error 0、约 6,677 req/s。第二轮 10,000 次、
并发 64 的 9,586 个 `503` 全部携带 `sqlite_operation_capacity_exceeded`。压力期间/之后
`memory.peak=97,595,392` bytes、Zeus RSS 约 23 MiB、`oom=0`、`oom_kill=0`，且 CPU quota
发生 throttling。Apple VM 无 Swap，1.0 无 per-container PID limit 且 `pids.max=max`；因此这只
证明当前镜像在该 Apple readiness-pressure 场景下保持有界，不替代 Linux Docker PID/OOM
authoritative acceptance 或更低内存/对抗性压力。
Docker Compose 当前只有静态配置检查；本机缺少 Docker CLI 时不声明 Compose build/up 已通过。
