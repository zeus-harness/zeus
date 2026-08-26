# Zeus Harness Alpha 架构

本文描述当前 Alpha 的实现边界和必须由测试证明的运行语义。它不是未来路线图。

## 运行拓扑

```text
Client / SvelteKit Web
          │ REST + Run/Session SSE
          ▼
      Axum API
          │
          ▼
Runtime（Session 编排 + Run Coordinator）
     │                 │
     │                 ├────────► Authz Policy（pure, default deny）
     │                 │                    │
     │                 │                    ▼
     │                 │               Tool Registry
     │                 │                    │
     ▼                 ▼                    ▼
SQLite Session ledger  SQLite Run ledger   Sandbox / Connector
turn / receipt         event / dispatch
```

- `protocol`：Session/Run HTTP、SSE、turn、flush ack 以及可版本化事件合约。
- `kernel`：纯状态转换，不读数据库、不执行外部工具。
- `authz`：精确工具名规则、策略 revision、环境和 effect guard；没有命中即拒绝。
- `tools`：工具描述、注册表、参数验证和 object-safe executor 边界。
- `connectors`：具体工具适配器。生产 RDS executor 在 Alpha 中不存在。
- `storage`：schema v4 migration、独立 Session/Run ledger、投影、幂等回执和 durable dispatch queue。
- `runtime`：Session 命令编排、Run worker、提交后 SSE 提示和启动恢复。
- `zeus-api`：进程组合、配置、Session/Run REST/SSE 和 readiness。

SQLite 是本地单实例 Alpha 的权威存储。Restate、MinIO 和 PostgreSQL 当前不是第二套事实源。
当前 Web 从 `overview.primary_session_id` 加载 Session，并行订阅 Run/Session SSE；命令响应和
后续权威 Session GET 用于合并事件并校准投影。

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
ready ── start_turn ──► running / open turn ── flush ──► ready / flushed turn
                              │
                              └─ process restart ──► needs_attention / interrupted
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
- start：只允许 `ready` Session；创建唯一 open turn，追加 `user_message`，投影进入
  `running`，并保存响应回执。
- flush：只允许当前 active/open turn；可先追加 `assistant_message`，再把 turn 变成
  `flushed`、追加 `turn_flushed`、清除 active turn、投影回到 `ready`，最后保存包含
  `ack.durability_sequence` 的完整响应。任一步失败都整体回滚。
- resume：只允许没有 active turn 的 `needs_attention` Session；追加
  `session_resumed`，投影回到 `ready` 并保存响应回执。

Session commit 后才发布进程内提示。start/flush/resume 不修改 Run ledger、approval、dispatch
job 或 worker 状态。

审批命令也在一个 `BEGIN IMMEDIATE` 事务内完成：

1. 读取并核对持久幂等回执。
2. 对 Run head sequence 做 CAS。
3. 追加 `ApprovalDecided` 事件并更新 Run 投影。
4. Approve 时插入唯一的 queued dispatch job。
5. 保存第一次响应的完整 JSON。
6. Commit 后才发送进程内 SSE 提示。

Session 和 Run 的进程内 broadcast 都只负责低延迟提示，不是事件事实源。两种 SSE 都从各自
的 sequence cursor 每 2 秒补读一次持久 ledger；即使提示丢失，也不会永久漏掉已提交事件。

worker 在调用 connector 之前，必须先在另一个事务中把 job 从 queued CAS 为 started、追加
`ToolDispatchStarted` 并推进 Run sequence。该事务失败时 executor 调用次数必须为零。
connector 在数据库事务和锁之外运行。

结果事务把 started job 变成 finished，追加一个 ToolResult 并更新 Run 投影。外部执行已经发生
但结果事务失败时，不得立即重试外部工具。

## 冷恢复

API 监听端口之前按固定顺序完成：

1. 取得数据库相邻 `.zeus.lock` 的 OS 排他锁，配置 SQLite 并迁移到 schema v4。
2. 绑定并核对 runtime identity、primary Session/Run 和 demo attachment。
3. 扫描 open Session turn：将 turn 标为 `interrupted`，追加 `turn_interrupted`，Session
   进入 `needs_attention`。不生成 flush ack，也不修改 Run ledger。
4. 扫描 started 且没有 ToolResult 的 dispatch：追加 `OutcomeUnknown`，Run 进入
   `needs_attention`，不自动重试外部调用。
5. waiting-for-approval 原样保留；queued 且没有 started checkpoint 的 job 才可以继续派发；
   已有终态结果不重新执行。
6. 恢复和安全派发完成后，进程才绑定监听端口。

锁由最后一个 Store clone 的生命周期持有；第二个进程不能进入 migration 或恢复路径。被中断的
Session 必须通过幂等、sequence-checked resume 显式回到 `ready`。

稳定的 `call_id` 会传给 provider 作为幂等键，但 Zeus 不据此宣称任意外部系统都具有
exactly-once 语义。

## 策略与执行边界

- 未知工具、缺失策略、重复/冲突规则、effect 或 environment 不匹配：默认拒绝。
- Approval 只能解除 `require_approval`，不能覆盖显式 deny。
- dispatch 前用同一 policy revision 和不可绕过 guard 再检查一次。
- SQLite schema v4 增加 Session、Session/Run ownership、turn、append-only Session event、
  Session command receipt 和 `runtime_identity.primary_session_id`。每个 pre-v4 Run 会绑定到
  生成的 `session-{run_id}`，原 Run/Event 不重写、不丢弃。
- runtime identity 持久绑定 profile、environment、primary Session/Run、policy ID 和
  revision；不一致时启动失败。Run attachment 当前用于 migration 和 demo seed，Alpha 不公开
  attach-Run HTTP route。
- queue claim 与 started recovery 在任何落盘前再次核对 job 的 run、policy ID 和 revision。
- sandbox 或 executor 不可用：写入 `NotDispatched`，禁止回退到宿主机裸执行。
- `production-guarded` profile 在认证、租户和真实 connector 缺失时保持执行禁用。
- `dev.marker.write` 仅在 `local-development` profile 注册，只能在服务端固定目录写服务器生成的
  marker 文件；参数不能提供路径。
- `ZEUS_DEMO_PROFILE=production-guarded` 是默认值；切到 `local-development` 时必须使用独立
  SQLite 数据库，并由 `ZEUS_LOCAL_MARKER_ROOT` 固定写入根目录。

## 容器边界

- Docker Compose 是开发拓扑：`full` 使用 `zeus_data:/var/lib/zeus`，`infra`、`postgres`、
  `debug` 和 `sandbox` 是独立 profile。Compose `.env` 和 project name 只作用于这条路径。
- Apple `container` helper 只运行 production-guarded API、Web 和 gateway，不启动 Compose
  基础设施或 local marker executor。默认 project 是 `zeus-alpha`，资源名为
  `zeus-alpha-{api,web,gateway,net,data}`。只有 gateway 尝试发布 loopback `18088`；API 和
  Web 只在 project network 暴露，由 Caddy 作为唯一入口。数据卷是
  `zeus-alpha-data:/var/lib/zeus`。
- Apple helper 的健康检查、overview、Session 和 SSE 请求优先使用动态 gateway container IP，
  必要时回退 loopback；所有请求强制绕过代理并设置连接/响应超时。`status` 同时报告 direct 和
  published URL，当前运行时的 port-forward reset 不会被误报成应用健康。
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

## Alpha 验收

- schema v1/v3 原地迁移到 v4 后，原 Run/Event 保留，primary Session/Run 绑定稳定。
- 重启后 Session/turn/event、Run/Event、审批决定、dispatch job 和两类命令回执仍存在。
- Session start/flush 事务保持连续事件、投影和 durability ack 原子一致；注入失败时整体回滚。
- open turn 重启后只追加一次 `turn_interrupted`，Session 进入 `needs_attention`，不生成 flush
  ack、不改变 Run ledger；显式 resume 后才能开始新 turn。
- 同 key 同输入只提交一次并重放响应；同 key 不同输入返回冲突；不同 key 由对应 ledger 的
  head sequence CAS 仲裁。
- 未知工具和策略拒绝路径的 executor 调用数为零。
- checkpoint 写入失败时外部副作用为零。
- started 后模拟崩溃，恢复为 `outcome_unknown` 且不发生第二次执行。
- 第二个进程不能同时打开同一个持久数据库；profile/policy identity 不匹配时 fail closed。
- 活跃 Run/Session SSE 不能无限拖住进程退出；SIGINT/SIGTERM 的 graceful drain 最长五秒，
  随后关闭剩余连接并释放 SQLite lease。
- local-development marker：批准前不存在、拒绝后不存在、allow-once 后只生成一个稳定文件。
- 生产 RDS 路径只能得到 executor unavailable，不能得到伪造成功。
- Session/Run SSE 重连都严格从各自大于 cursor 的 sequence 补齐事件。请求同时携带 query
  cursor 和 `Last-Event-ID` 时，后者优先。
- 请求或状态错误返回 400/404/409 problem details；内部执行不变量返回脱敏的
  `500 runtime_unavailable`；storage/config/registry 不可用返回脱敏的
  `503 runtime_unavailable`。内部错误只写服务端日志。
- 本地 Alpha 只校验 Session ID/title/message 非空与 canonical，detail 仍一次返回完整 ledger；
  对外或多租户部署前必须增加字段字节上限、保留策略和 cursor pagination。
- Web 保持单会话时间线、一个内联审批卡和一个 composer；持久 command identity 可在刷新后
  恢复，丢失响应和显式 sequence rebase 不会生成重复 turn。
- 当前自动化结果是 99 个 Rust 测试和 10 个 Web Node 测试全部通过；Svelte check、lint 和
  production build 也通过。

Apple `container` 在 macOS 26.6.2 / CLI 1.0.0 上完成 runtime image build、完整 `up`、
gateway Web/API health、双 SSE replay 和 `restart-verify`：重建 container/network 后，同一
Run、Session、turn 与全部事件从 `zeus-alpha-data` 恢复。本机曾间歇出现 Apple localhost
forwarder reset，随后一次重建又恢复；因此验收固定优先走 gateway container IP，`status` 则
报告当前 loopback 是否可达。Docker Compose 当前只有静态配置检查；本机缺少 Docker 时不声明
Compose build/up 已通过。
