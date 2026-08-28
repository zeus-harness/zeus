# Zeus Harness Alpha+ 架构

本文描述当前 Alpha+ 的实现边界和必须由测试证明的运行语义。它不是未来路线图。

## 运行拓扑

```text
Client / SvelteKit Web
          │ same-origin REST + Run/Session/Agent-output SSE
          ▼
  Actor Auth / CSRF ───────► Axum API
                                 │
                                 ▼
                   Runtime（Session + Run Coordinator）
                      │           │              │
                      │           │              ├──► Authz / Tool Registry
                      │           │              │          │
                      ▼           ▼              ▼          ▼
              Session ledger   Run ledger   Agent workers  Connector
              turn / receipt   dispatch     model + tool   / Sandbox
```

- `protocol`：认证、设置、Session/Run HTTP、SSE、turn、Agent output page 与可版本化事件合约。
- `deployment`：版本化、规范化且不含 secret 的 Agent Spec / Deployment Manifest，负责稳定
  digest、系统提示词 ID/revision/content digest 绑定与确定性 JSON-pointer diff。
- `tenancy`：本地身份、account/membership 授权上下文、Argon2id 密码、opaque token、CSRF 与域分离 digest。
- `llm`：object-safe reply provider、本地非模型 fallback 和有界 OpenAI-compatible 客户端。
- `kernel`：纯状态转换，不读数据库、不执行外部工具。
- `authz`：account capability matrix，以及精确工具名规则、策略 revision、环境和 effect guard；没有命中即拒绝。
- `tools`：工具描述、注册表、参数验证和 object-safe executor 边界。
- `planning`：Agent turn 自有的结构化计划、`todo_write` whole-list/CAS 语义、规范化 digest 与
  policy-allow executor；它不直接写数据库。
- `goals`：Session 级单一完成目标、`get_goal` / `create_goal` / `update_goal` 工具契约、严格
  生命周期与 revision CAS；它只准备有界规范状态，持久化权威仍由 SQLite 掌握。
- `skills`：启动时一次性加载的 strict version 1 Skill Catalog、确定性 digest，以及只读
  `skill_list` / `skill_load` executor；Skill body 只有通过普通工具结果才对模型可见。
- `subagents`：`spawn_agent` / `list_agents` / `get_agent_result` / `send_message` / `interrupt_agent` / `wait_agent` 工具契约、
  严格参数边界、确定性 child/message identity 与有界结果；durable scope、原子 admission、目录分页、
  终态结果读取和 follow-up 入队由 runtime/storage 掌握，不由通用 executor 接受调用方自报身份。
- `connectors`：具体工具适配器。生产 RDS executor 在 Alpha 中不存在。
- `storage`：schema v36 migration、有界 account/membership 权威、一次性 member setup、用户/偏好、
  account audit/rollup/policy/archive state、独立 Session/Run ledger、typed event lookup、
  account+actor-scoped 回执、durable Agent/model/tool/dispatch queue、不可变 model output、
  不可变 deployment manifest，
  revisioned account knowledge catalog、owner-governed Agent prompt、account-scoped
  secret-free reply provider selection，以及
  actor/account/global logical capacity、physical capacity 和 operation capacity。
- `runtime`：Session 命令编排、Agent model/tool 与 Run worker、运行时 manifest 构建、model delta
  持久化、提交后 SSE 提示和启动恢复。
- `zeus-api`：进程组合、owner/member 认证、账户创建/列表/原子切换、CSRF、owner-only 管理面、
  provider 配置、REST/SSE、durable Agent output replay 和 readiness。

SQLite 是本地单实例 Alpha+ 的权威存储。Restate、MinIO 和 PostgreSQL 当前不是第二套事实源。
当前 Web 认证后列出用户 Session，恢复仍存在的上次活动 Session，并行订阅 Run/Session SSE；
命令响应和后续权威 Session GET 用于合并事件并校准投影。浏览器只能提交 user message，不能
提交 assistant content 或调用 legacy turn-finalization flush route；Session-level flush barrier
只观察服务端已接收的 durable work。
Session 列表按 opaque cursor 逐页追加；保存的活动 Session 即使不在首屏，也先通过 actor-scoped
point detail 恢复，只有权威 `404` 才回退 primary Session。

schema v24 把系统提示词升级为 owner-governed account 配置。revision 0 精确保留原内置内容和
manifest revision `1`；第一次自定义更新产生 prompt config revision 1 和 manifest revision `2`。
每次更新使用 expected-revision CAS、actor-scoped `Idempotency-Key` receipt、当前 owner authority
与 account audit 单事务提交；内容非空、control-safe 且最多 16 KiB。新 Agent 只把 prompt
ID/revision/content digest 写入 secret-free manifest，并把 exact 内容写入 immutable model request。
更新不会改写既有 Agent；仍 queued 且绑定旧 governed prompt 的工作会在 provider/tool I/O 前以
deployment drift fail closed。Owner-only prompt history 提供 newest-first 有界摘要和 exact revision
点查；revision 0 是内置基线，恢复旧内容必须通过现有 CAS `PUT` 创建新 head。动态 knowledge
不拼入系统提示词。Knowledge v1 已实现 immutable entry
revision 校验、固定 tokenizer/整数排序、整条 entry 丢弃、16 KiB canonical context 与完整
selection snapshot digest。schema v22 把 exact corpus、snapshot、canonical context、Agent、
initial model job 和 execution admission digest 绑定后持久化，重放不从 live state 重新检索。
LLM 协议层使用独立 durable `context` role，仅在 OpenAI-compatible wire 边界映射为单独的
`user` message。schema v23 增加 owner-only account knowledge catalog：revision 0 表示未配置的
隐式空 corpus；每次替换通过 expected revision CAS、actor-scoped `Idempotency-Key` receipt、当前
owner authority 和 account audit 在一个事务内提交。Owner 和 member 新建 Agent 时都以 Reply
capability 读取当时的 active corpus，随后仍把 exact corpus/snapshot 固化到 Agent，之后的 catalog
更新不会改写既有 turn。Catalog revision 最多 256，单 account 最多保留 128 个不同 corpus revision
与 64 MiB canonical envelope；超过边界 fail closed。SQLite 内 trigger/deep readiness 可检测缺失、
不连续或投影不一致，但与其它本地 commitment 一样，不是防止拥有任意数据库写权限者同时替换数据
和校验逻辑的外部信任锚。Actor-scoped `agent/knowledge/explain` 返回已经固化的 selection snapshot
与 binding/corpus/query/context digest，但不返回未命中的完整 account corpus；pre-v22 history 明确
标记为 `legacy_unbound`，不伪造空 selection。Owner-only catalog history 以 receipt revision 做
newest-first 有界分页，列表只返回 digest/count/actor/timestamp 摘要，精确 revision 点查才解码并
校验完整 corpus。revision 0 始终是隐式空基线；恢复历史 corpus 必须通过现有 expected-revision CAS
写入新 head，不能原地改写旧 revision。

schema v25 增加非破坏性的 Session context compaction。最后一个成功 checkpoint 之后出现第 27
个完整 flushed turn 时，从最老 13 对中选取 provider envelope 能完整容纳的最大 whole-turn
前缀，绑定为 immutable compaction request；不切分任何消息，原始
`session_events` 和 `session_turns` 不删除、不改写。成功摘要以独立 durable `checkpoint` role
插在 system prompt 之后、未压缩 tail 之前，仅在 OpenAI-compatible wire 边界映射为 `user`。
compaction job 只允许 `queued -> started -> succeeded|failed|outcome_unknown` 单向迁移；重启可继续
queued job，但 started 且无 durable 结果的调用只结算为 `outcome_unknown`。failed 或
outcome_unknown generation 都会阻断自动重排队，不得换一个 job ID 重放同一 source。

schema v26 增加 account-scoped reply provider 选择。revision 0 表示进程启动时注册的隐式默认
Provider；owner 只能从启动注册表暴露的 secret-free `provider_id/model/reply_kind` 中选择，并通过
expected-revision CAS、`Idempotency-Key` receipt 与 account audit 单事务提交。HTTP 和 SQLite 均不
接收 endpoint、credential 或 SecretRef。选择只影响新 turn；已排队的 reply、compaction、Agent
model 与 tool work 保留 admission 时的精确 Provider binding，并由 worker 按该 binding 从注册表
解析。重启后若显式选择或 queued binding 已不在注册表，执行 fail closed，不静默切换默认 Provider。
启动注册表由 `ZEUS_LLM_PROVIDERS_FILE` 指向的 version 1 JSON 定义：regular file 上限 64 KiB，
只允许 1–16 个远端 Provider，逻辑名称唯一且限制为 64-byte ASCII，`default` 必须命名其中一项或
保留的 `local-fallback`。每项只接收 endpoint、model 与 `api_key_ref`；strict unknown-field
解析会拒绝 inline key。该文件不能与旧单 Provider 环境变量混用。Zeus 在打开 SQLite 前构造全部
Provider、拒绝重复 durable identity 并预检全部 SecretRef；任一失败都会终止启动。逻辑名称仅用于
选择启动默认项，不进入持久身份；账户与 queued work 仍绑定计算出的 secret-free `provider_id`。

schema v27 增加 Agent 安全取消的 SQLite durability boundary。Actor 以 Agent revision 做 CAS，
只能取消 `waiting_model`、`waiting_approval` 或 `tool_queued`；prepared claim 被原子释放，且不生成
RunEpoch。取消事务写入精确的 epochless `user_cancelled` execution fact、固定错误码与
`turn_interrupted`。若 model/tool 已有 durable `started` checkpoint，取消返回 conflict，不能把
可能已经计费或产生副作用的外部调用伪装为已取消。相同旧 revision 只重建第一次终态响应。

schema v33 将运行中的 model 纳入取消边界，但不放宽 tool。`model_running` 取消与 provider completion
在 SQLite immediate transaction 上竞争；取消胜出时写入绑定精确 RunEpoch 的 `user_cancelled` fact，
把 started model job 终止为 `failed`、释放 started claim，并保留所有已落盘 output chunks。Runtime 在
model durable start 之前注册进程内 cancellation handle，事务提交后通知匹配 worker 丢弃 provider
stream；尚未落盘的小尾巴从未通过 durable SSE 发布，不会形成可见回滚。已 started 的 tool 仍返回
`agent_operation_in_flight`，因为 connector 副作用可能已经发生。

schema v34 增加 durable Session fork。Actor 提交 parent Session 与历史 `through_sequence`；
storage 在同一个 `BEGIN IMMEDIATE` 中先复验当前 account/membership/SessionWrite 权限，再创建
独立 child Session，只复制该边界内已经完整 `user_message -> assistant_message -> turn_flushed`
的对话对。`session_forks` 固化 parent boundary、创建 actor/revision 与 inherited count，
`session_fork_turns` 逐项绑定 parent/child turn 和两边的事件 sequence；child turn ID 使用域分离
SHA-256 确定性生成。child 以后只从自己的 ledger 构建模型上下文，parent 后续输入不会渗入。
映射、事件副本、谱系和 actor-scoped receipt 原子提交；trigger 与 deep integrity 复验 exact
content/provenance/timestamp、连续映射、无环谱系和唯一回执。

schema v35 增加 durable direct-child fork catalog。读取先复验 parent 的当前 actor authority，再解析
绑定 cursor kind/account/actor/parent 的 opaque cursor；SQLite 按
`created_at DESC, child_session_id ASC` 做 `LIMIT + 1` keyset page，并由对应复合索引避免全量
lineage 扫描或临时排序。Catalog 只返回直接 child 的 Session summary 与 immutable fork metadata，
递归分支遍历由调用方逐层完成。

schema v36 增加 Agent-native durable child admission。`spawn_agent@1-durable-session-fork`
在 exact parent tool 已 durable started 后生成确定性 child Session/turn/Agent ID；known-success
completion 与 fork、首个 user turn、deployment-bound Agent/model job、parent call binding 在同一
SQLite transaction 提交。Child 只继承 parent 当前 user event 之前已经完整 flush 的历史；直属 child
上限 8、ancestry 上限 3，容量失败全量回滚并作为 known failure 回灌 parent。

Agent-facing `list_agents@1-direct-session-forks` 只读取 `agent_subagent_spawns` 绑定的直接 child，
不会把普通 Session fork 冒充 Agent。Runtime 只在 exact Agent tool call 已落盘为 `started` 后分派，
storage 在同一只读事务中复验 account/actor/Session/turn/Agent/call ID、工具名与版本；cursor 另用
独立 kind 并绑定 account/actor/parent。`get_agent_result@1-direct-child-snapshot` 复用相同 scope，
只允许读取该 parent 通过 `spawn_agent` 创建的直属 child。运行中只返回状态；成功终态返回最多
8 KiB、UTF-8 边界安全的 assistant output page，并用 `next_after_byte` 续页；failed 或
`needs_attention` 不返回 partial output。

`send_message@1-direct-child-followup` 同样要求 exact durable `started` parent tool scope，并且只接受
该 parent 由 `spawn_agent` 创建的直属 child。Runtime 用 parent Session/call/child 派生确定性 message
turn ID 与 idempotency key；storage 复用 schema v31 Session follow-up FIFO 和 receipt，在入队事务内
重新验证 account、actor、membership revision、父子绑定与 child 状态。Ready child 会被 worker 调度，
Running child 在当前 turn 结束后按 FIFO 消费；`needs_attention` child 在具备显式恢复协议前拒绝续发。
进程自有 continuation 不依赖短期浏览器登录 session，但仍要求原 account/member/user 有效且具备
SessionWrite/Reply 权限。入队之后、parent tool completion 之前若进程崩溃，parent call 按既有
LocalWrite 语义进入 `outcome_unknown`，不会盲目重发。

`interrupt_agent@1-direct-child-cancel` 继续沿用 exact started parent scope 和 immutable direct-child
binding，并从 child 当前 active turn 派生 Agent revision，不信任模型提供 revision/turn/account/actor。
Storage 复用既有 cancellation transaction：queued/running model 与 waiting-approval/queued tool 会写入
`user_cancelled` fact 和 `turn_interrupted`；running model 同时通知本进程 drop provider stream。已经
durable started 的 tool 返回 `interrupt_agent_operation_in_flight`，不会伪造“已取消外部副作用”。
`wait_agent@1-direct-child-activity` 在 durable direct-child snapshot 之前建立 Session event 订阅。
snapshot 将 Running child 与存在 queued durable follow-up 的 Ready child 都视为可推进，避免 enqueue
已提交但 worker 尚未 claim 时错误返回 `no_progress`。没有可推进 child 时立即返回 `no_progress`；否则等待
10 秒至 1 小时的显式有界 timeout。它不唤醒 child，也不把进程内通知当作权威状态；唤醒或超时后
调用方必须重新 List/Result。`get_agent_result` 从 child 最新 turn 解析状态与终态输出，follow-up 完成
后不会返回首次 spawn 的陈旧结果。
Process-owned 中断复验原 membership revision 与 SessionWrite/Reply 权限，不依赖短期登录 session；
成功 parent tool result 的 deep integrity 还必须能还原直属 child 的 exact user-cancelled terminal evidence。
当前阶段不递归加载完整 child graph。

schema v28 增加 Agent turn 自有的 durable plan。`todo_write@1-single-active` 每次提交完整列表，
最多 24 项、每项 256 UTF-8 bytes、至多一个 `in_progress`；首写 `expected_revision=0`，之后严格
CAS。Runtime 在 executor 前按 server-derived account/actor/Session/turn/Agent scope 预检 revision，
SQLite 在 known-success 事务内再次校验并写入 append-only snapshot。Snapshot 与 exact call、result、
counts、domain-separated SHA-256 digest 和 finished timestamp 绑定；重放必须命中同一 snapshot，
deep readiness 会重算全部链。失败或 stale CAS 是已知 tool result，不写 snapshot，也不会伪装为
`outcome_unknown`。每个 Agent 的快照数自然受现有四次 tool-call 上限约束。

schema v29 增加 Session 级 durable completion Goal。`get_goal@1-session-cas` 只读当前快照或
`null`；`create_goal@1-session-cas` 仅在没有 Goal 或当前 Goal 已完成时创建新 Goal；
`update_goal@1-session-cas` 必须携带精确 goal ID 与 expected revision，并执行 edit、pause、resume、
complete 或 blocked 转换。Mutation 在 runtime 预检后仍由 SQLite 在 known-success tool completion
事务内重复 CAS，写入 Session 内连续 sequence 和 Goal 内连续 revision 的 append-only snapshot；
snapshot 与 exact account/Session/turn/Agent、started call、canonical result、phase、blocker 和时间绑定。
Deep readiness 会从头重放全部 Goal 状态机并拒绝 missing snapshot、跨 scope 绑定、修改/删除及
弱化 trigger。

schema v30 在该 CAS 权威之上增加 same-Session Goal Round driver。`create_goal` 成功或显式
`resume` 只在当前进程内 armed；数据库重开后 activation 为空，active Goal 不会自行恢复执行。
每一轮必须原子写入真实 Session user turn、Agent、首个 model job 与 append-only
`agent_goal_rounds` admission，绑定 exact Goal ID/revision、连续 round、actor membership revision、
canonical prompt digest 与同一 timestamp；Goal Round Agent 的 complete/blocked 必须匹配本轮
Goal revision，且自动 blocked 至少要求连续三轮；direct-human turn 仍可显式 complete 或 blocked。
用户新 turn、取消、provider/tool 失败、`needs_attention`、完成、阻塞、权限失效或
round cap 都会 disarm；只有已通过 Session 授权的 actor 可以人工 disarm，且 activation 复核与
durable admission 共用同一个进程内互斥门，已取得门的人工 disarm 不会再被 stale worker candidate
越过。失败和歧义结果不自动重试。Deep readiness 会重建
每轮之前的 Goal 状态、精确 driver prompt、turn/Agent/job 绑定和完整生命周期链。

schema v31 增加普通用户 follow-up 的 durable FIFO inbox。入队在 `BEGIN IMMEDIATE` 中校验
当前 login authority、Session scope、`expected_sequence`、幂等回执、每 Session 32 条上限及既有
active-reply actor/account/global 配额，但不提前追加 `user_message` 或推进 Session sequence。
Session 回到 `ready` 后，worker 只选择该 Session 最早的 queued row，复验捕获的 membership
revision，并在同一事务中创建正常 Session turn、Agent、首个 model job 和事件，再把 inbox row
绑定为 `claimed`。重启会恢复 queued 工作；撤权 row 按 FIFO durable `discarded` 且绝不触发
provider I/O；`needs_attention` 时保持 parked，显式 resume 后继续。表、回执和状态迁移均由
权威 trigger 与 deep readiness 校验。

schema v32 增加 Agent model output 的 append-only display ledger。OpenAI-compatible provider
改为读取有界 Chat Completions SSE；只有 model job 已经 durable `started` 后，runtime 才把文本
delta 按 UTF-8 边界合并为最多 4 KiB 的 chunk。每 job 累计文本最多 64 KiB，每 chunk 绑定 exact
account、actor membership revision、Session、turn、Agent、job、step、连续 Agent sequence、连续
job ordinal、累计 byte count 与 timestamp。chunk 不推进 Session/Agent 状态，也不进入后续模型
transcript；成功终态仍以 typed response 为权威，并必须逐字节等于该 job chunk 串联。若 transport
在 `[DONE]` 前终止，已收到的尾部先落盘，再以 `outcome_unknown` 收口且不重试 provider。SQLite
trigger 禁止修改/删除并约束 started binding，deep readiness 重算连续性、累计字节与成功终态相等性。
Actor-scoped output page 使用 `LIMIT + 1` keyset；`agent.output` SSE 直接从 SQLite 重放、定期复验
login authority，并在 terminal head 发完后关闭，不依赖进程内 broadcast 才能恢复。

可选 `ZEUS_SKILLS_FILE` 在 SQLite 打开前加载 immutable Skill Catalog。文件使用 strict version 1
JSON，regular file 上限 512 KiB，包含 1–64 个唯一的 lowercase provider-safe 名称；description
上限 256 bytes，单个 UTF-8 body 上限 24 KiB，未知字段、重复名称、非规范 description 与不安全
control character 均 fail closed。Unix 打开 final path component 时使用 no-follow。Catalog 构造后
不再读取文件，`skill_list` 和 `skill_load` 以 read-only / policy-allow 工具进入普通 Agent Tool
Registry。二者的 tool version 是完整 64-byte catalog SHA-256 digest，因此 name/version/description/
body 任一变化都会改变 DeploymentManifest；旧 manifest 的 queued work 在 model/tool claim 前拒绝，
不会用漂移后的说明继续执行。Manifest 只含工具描述与 digest，不内联 body；被选择的 body 作为
普通工具结果完整持久化后才进入下一次模型请求，所以 Catalog 不得保存 secret。

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
ready ── start_turn ──► running / open turn + Agent + queued model job
                              │
                              ├─ final text ──► assistant_message + turn_flushed ──► ready
                              │
                              ├─ tool proposal ──► policy / optional approval
                              │                         │
                              │                         └─ known result + queued model continuation
                              │                                  (loop remains running)
                              │
                              └─ failure / unknown / restart ──► needs_attention / interrupted
                                                                    │
                                                                    └─ resume ──► ready

queued follow-up ──(Session ready + exact authority)──► start_turn

parent ready/running/needs_attention ── fork@historical sequence ──► independent child ready
```

Session ledger 记录 `session_created`、`run_attached`、`user_message`、可选的
`assistant_message`、`turn_flushed`、`turn_interrupted` 和 `session_resumed`。一个 Session
可以拥有多个 Run，但一个 Run 只能属于一个 Session。Session 命令不推进 Run sequence，
也不触发 dispatch worker。Fork child 拥有全新的连续 ledger；parent/child 对应关系只保存在
不可变 lineage/mapping 表，不通过共享 sequence 或读取 parent live state 维持。

## 写入边界

所有 Session POST 都要求非空 `Idempotency-Key`。同 key、同请求返回持久化的第一次响应；
同 key、不同请求返回冲突。普通状态命令除 create 外携带 `expected_sequence`，在
`BEGIN IMMEDIATE` 中对 Session head 做 CAS；fork 使用不可为零且不超过 parent head 的
`through_sequence` 作为不可变历史边界。

- create：写入 `ready` 投影、`session_created` 和完整响应回执。
- fork：`POST /sessions/{parent_id}/forks` 写入新的 `ready` child、独立 `session_created`、
  所有边界内完整对话对的事件/turn 副本、逐 turn source mapping、immutable lineage 和完整响应
  回执。首次提交返回 `201`，同 key/同输入返回 stored response 并标记 replay、HTTP 返回 `200`；
  同 key/异输入冲突。授权先于 receipt replay，foreign account 的 parent 与不存在资源同为 `404`。
- fork catalog：`GET /sessions/{parent_id}/forks` 返回稳定的直接 child keyset page；默认 50、上限
  100，下一页 cursor 仅能由同一 account、actor 和 parent 使用。授权先于 query/cursor 错误解析。
- start：只允许 actor 拥有的 `ready` Session；在一个事务中创建唯一 open turn、追加
  `user_message`、投影进入 `running`、保存 actor-scoped 响应回执，创建 Agent，绑定 canonical
  deployment manifest digest，并插入 immutable queued model job。事务前先以当前 actor 的 Reply
  capability 读取 account active knowledge corpus，再对当前 user message 生成确定性 selection；
  provider request 以命令的
  `expected_sequence` 为快照边界：第一条且唯一一条 system message 是当前 account active
  prompt 的精确内容，且其 ID/revision/content digest 与 manifest 绑定；随后是可选的 durable
  compaction checkpoint、最新完整 flushed user/assistant tail 和当前 user message。manifest 只保存
  稳定 prompt ID、revision 与域分离 content digest，不保存提示词内容或 secret；精确内容随
  immutable request 持久化；当前 user message 后追加一条 exact durable `context` message。
  system prompt、checkpoint、最多 26 对未压缩历史消息、当前 user message 和 context 共享
  64 KiB 初始 UTF-8 内容预算；初始最多 56 条 message，为 Agent 全程 64-message 上限预留四组
  assistant tool call / tool result。interrupted、缺少 assistant 或尚未 flush 的 turn 不进入
  上下文。组装结果持久化在 job 中，迟到的幂等重试复用该 durable request，而不是从更晚的
  Session 状态重新生成。当前 user message 无法与 active prompt 一起装入初始预算时，API 在任何
  turn/job 写入前返回 `413 agent_request_too_large`；合法请求返回 `202`。
- follow-up enqueue：允许现有 Session 在任意生命周期状态接收下一条用户输入；命令只写
  `session_followups` 与独立 actor-scoped receipt，不推进 Session sequence。Worker 在 Session
  `ready` 时按 FIFO 把它原子转换为上述普通 start 边界，因此历史、事件、Agent 与 provider
  执行仍只有一套权威状态机。
- Agent model worker：claim 事务先复验 active actor、Session owner、manifest digest、provider/
  model、profile/environment、policy revision、workflow limits、完整 typed transcript、prompt
  绑定与 provider-visible tool schema，再把 queued job durable claim 为 `started`。admission、
  claim 和 deep-integrity 都校验消息顺序、数量、content 预算、system message 位置唯一及内容与
  manifest digest 精确匹配。admission 发现错误会拒绝命令并回滚；已经 queued 的 work 在 claim
  时发现持久化 authority 缺失、损坏、promptless 或与当前 deployment drift，才 durable settle
  为 `deployment_unavailable`。两条路径都发生在 provider I/O 前，外部调用数为零。claim 成功后
  才在数据库锁之外调用 provider。流式文本先写上述 append-only output ledger；最终 typed 文本
  只有与全部 durable chunks 精确相等时，才原子追加带 provenance 的 `assistant_message`、flush
  turn 并写 `turn_flushed`。确定失败和 outcome unknown 都进入 `needs_attention`，不得自动重调
  provider；已落盘 prefix 仍可由授权 actor 重放。
- Agent tool worker：模型只能提出工具名与 arguments；服务端 registry/policy 生成不可变 call。
  require-approval 保留在 `waiting_approval`，拒绝和 policy deny 作为结构化 known result 返回模型。
  允许执行的 call 在 durable `started` checkpoint 后再次校验 manifest/registry/policy；只有通过
  才调用 executor。known completion 与它的 exact next-request JSON 在同一事务提交，SQL `NULL`
  与 model-visible JSON `null` 不得混淆。continuation 再次校验同一 prompt 绑定，并原样保留已
  持久化的 system message 与 transcript；重启恢复只重放该 exact request，不从当前 prompt 或
  Session 状态重新拼接输入。
- Agent cancel：`PUT .../agent/cancel` 接收 `expected_revision`。queued、prepared、
  waiting-approval 或 model-running 状态可终止；model-running 取消绑定既有 RunEpoch 并协作式停止
  本进程 provider stream，已落盘 prefix 保持可重放。tool-running 返回
  `agent_operation_in_flight`。成功取消后 Session 进入 `needs_attention`，由显式 resume 回到
  `ready`；重放不创建第二个终态。
- Session flush barrier：`POST /sessions/{id}/flush` 不接收 body，只在同一 SQLite snapshot 冻结
  调用时的 active turn、Session sequence 与最大 follow-up ordinal，并等待这段 durable prefix 达到
  `quiescent` 或 `needs_attention`。调用前已经 terminal 的历史 follow-up 不进入区间；调用之后的
  新 turn/follow-up 不扩张边界；默认等待 10 秒、最大
  30 秒，超时返回 `202 pending` 与 `Retry-After`，每次观察都重新校验 actor authority。
- legacy turn flush：可上传 `assistant_message` 的
  `POST /sessions/{id}/turns/{turn_id}/flush` 仅保留在 storage/runtime 合约和测试 router；真实
  authenticated server 不注册此路由，浏览器不能上传 assistant content。
- resume：只允许没有 active turn 的 `needs_attention` Session；追加
  `session_resumed`，投影回到 `ready` 并保存响应回执。

Session commit 后才发布进程内提示。start/Agent/resume 不修改 Run ledger 或 Run dispatch job；
Session Agent job 与 Run dispatch job 是相互独立的 durable queue。

审批命令也在一个 `BEGIN IMMEDIATE` 事务内完成：

1. 在同一 SQLite snapshot 重新校验 auth session、membership revision/capability 与 Run account，
   再读取 `(account, actor, operation, key)` 持久幂等回执。
2. 对 Run head sequence 做 CAS。
3. 追加 `ApprovalDecided` 事件并更新 Run 投影。
4. Approve 时插入唯一的 queued dispatch job。
5. 保存第一次响应的完整 JSON。
6. Commit 后才发送进程内 SSE 提示。

Session 和 Run 的进程内 broadcast 都只负责低延迟提示，不是事件事实源。两种 SSE 都从各自
的 sequence cursor 每 2 秒补读一次持久 ledger；即使提示丢失，也不会永久漏掉已提交事件。

worker 在调用 connector 之前，必须先在另一个事务中复验 dispatch job 固化的 initiating actor
仍有 SessionWrite capability、approving actor 仍有 ApproveDispatch capability，且两者的
account/membership revision、User、Account 都仍有效，再把 job 从 queued CAS 为 started、追加
`ToolDispatchStarted` 并推进 Run sequence。授权已撤销时，该事务直接把 job 置为 rejected、Run
置为 `needs_attention`，追加
`ToolResult::NotDispatched(reason=authorization_revoked)`；不会生成假的 started checkpoint，也不会
调用 connector。该事务失败时 executor 调用次数同样必须为零。
connector 在数据库事务和锁之外运行。

结果事务把 started job 变成 finished，追加一个 ToolResult 并更新 Run 投影。外部执行已经发生
但结果事务失败时，不得立即重试外部工具。

## 冷恢复

API 监听端口之前按固定顺序完成：

1. 取得数据库相邻 `.zeus.lock` 的 OS 排他锁，配置 SQLite 并迁移到 schema v36；按当前
   detailed-row limit 以最多 64 行 batch 压缩 bootstrap terminal audit prefix，再按稳定
   `(priority actor, expires_at, auth-session ID)` 顺序最多清理 64 个过期或绑定
   missing/disabled/suspended/stale-revision authority 的 auth session。
2. 绑定并核对 runtime identity、primary Session/Run 和 demo attachment。
3. 以固定 64 行 batch 读取 `started` 且没有持久结果的 legacy reply job，循环排空：结算为
   `outcome_unknown`，追加 `turn_interrupted`，不得重放可能已经计费的 provider 请求。
4. 以固定 64 行 batch 把 `started` 且没有持久结果的 Session compaction 结算为
   `outcome_unknown`；`queued` compaction 原样保留，监听启动后由 worker 继续。
5. 先把 Agent 中仅 `prepared` 的 model/tool claim 标为 expired；这些 claim 没有外部 I/O
   权限，底层 operation 仍为 queued，可由下一 generation 安全继续。再循环处理已 `started`
   的 model/tool operation：两者都结算为 `outcome_unknown`，Agent/Session 进入
   `needs_attention`，且绝不重放可能已计费或已产生副作用的外部调用；waiting-for-approval 原样保留。
6. 随后以固定 64 行 batch 处理没有 durable terminal 解释的其它 open Session turn：标记
   `interrupted`、追加 `turn_interrupted`，不生成 flush ack，也不修改 Run ledger。
7. 以固定 64 行 batch 循环处理 started 且没有 ToolResult 的 Run dispatch：追加 `OutcomeUnknown`，Run 进入
   `needs_attention`，不自动重试外部调用。
7. 只有 queued 且没有 started checkpoint 的工作才可以继续派发；已有终态结果不重新执行。
8. 恢复和安全派发完成后，进程才绑定监听端口。

锁由最后一个 Store clone 的生命周期持有；第二个进程不能进入 migration 或恢复路径。被中断的
Session 必须通过幂等、sequence-checked resume 显式回到 `ready`。

SQLite Physical Capacity Slice 已在监听端口开放前的启动阶段完成深度业务/ledger/FK/SQLite
integrity 检查与 truncating WAL checkpoint。`/health/ready` 只保留 schema/PRAGMA metadata
和物理 watermark 检查；运维或测试需要重跑昂贵检查时显式调用
`SqliteStore::verify_integrity`，避免 readiness 触发全 ledger 扫描或 checkpoint。deep-integrity
还会复验每个带 prompt 绑定的 Agent request：system message 必须位于首位且仅出现一次，内容
digest、provider-visible tools 与 immutable manifest 必须一致。

稳定的 `call_id` 会传给 provider 作为幂等键，但 Zeus 不据此宣称任意外部系统都具有
exactly-once 语义。

## 策略与执行边界

- 除 health、auth status、首次 bootstrap、login 和一次性 member setup 外，真实服务的业务
  REST/SSE 都要求 active account membership。bootstrap/login/member setup 必须 exact
  same-origin；已认证写请求还要求与登录会话绑定的 CSRF token。
  session cookie 为 opaque、`HttpOnly; SameSite=Strict`。默认 direct ingress 以请求的
  `Origin`/`Host` 为同源权威，并由 `ZEUS_COOKIE_SECURE` 决定是否附加 `Secure`；trusted-proxy
  ingress 则以唯一 canonical `ZEUS_PUBLIC_ORIGIN` 为权威，并强制 session/CSRF Cookie 都带
  `Secure`。
- `ZEUS_PUBLIC_ORIGIN` 与 `ZEUS_TRUSTED_PROXY_CIDRS` 必须成对配置。trusted-proxy 模式只接受
  allowlist CIDR 内的 TCP peer，并要求代理覆盖为唯一、单跳、无歧义的
  `Forwarded: for=<client-ip>;proto=https;host=<public-authority>`；validated `for` 才进入认证
  source limiter，其中 IPv4 使用裸字面量，IPv6 使用带双引号的 `[address]`。缺失、重复、多跳、
  非 HTTPS、host drift 在路由和认证之前 fail closed；direct
  模式继续只认 TCP peer 并忽略 `Forwarded`/`X-Forwarded-For`。两种模式都不把 API listener
  本身视为公网入口，trusted proxy 必须是私网 listener 的唯一网络路径。
- Alpha+ 允许 `member` 登录并执行 Run/Session 查询、SSE、resume、turn 和 reply；review、
  connector dispatch、member/audit 管理保持 owner-only。正式业务路径已全部 account+actor-scoped，
  并有跨 account/actor 隔离测试；字段、HTTP/SSE 连接和
  event page 边界、内部 point/batch read、有界 list/detail，以及 SQLite 行数、active queue、
  event-slot、事件载荷逻辑字节配额和 DB/WAL/disk headroom 门禁已落地。v14 已把初始
  `acc_local` membership 切为 capability 权威，并为 auth session、receipt、reply/dispatch、
  reservation、cursor 和 capacity 建立 account/actor 边界；v15 再用 setup token、revisioned
  disable/role change、两秒 SSE authority poll 和 account audit 完成产品路径。管理 middleware
  不是最终授权点，storage mutation 与 worker claim 仍在同一事务内复核 durable capability。
  当前控制面允许 owner 幂等创建账户，固定限制为每 User 16 个 membership、每库 64 个 account；
  登录可选 account，切换会原子轮换 auth session，资源读取继续只使用 session 中固化的 account。
- auth JSON 明确限制为 8 KiB、command JSON 为 512 KiB；新建 Session/turn ID、title、
  user/assistant message、review note 与严格幂等键分别按 UTF-8 bytes 设置硬上限。typed
  reply response 为 512 KiB，compact tool output 与 dispatch arguments JSON 为 64 KiB，
  provider/model/finish/code/digest 和 diagnostic 也分别具有 128 bytes/4 KiB 固定边界。新 Session event
  使用有界 ledger-local ID；pre-v9 durable reference 继续可寻址。共享纯校验在相关 API、
  runtime、storage 入口的 fingerprint 和 receipt 前执行，超限不得产生持久副作用。
- bootstrap/login 的 fixed-window limiter 在 Argon2 前一次锁内完成 prune/check/charge；默认只认
  direct `ConnectInfo` 的直连 `IpAddr`；trusted-proxy 模式只使用上述已验证 client IP。key map
  上限为 4096，满表时 fail closed，定时清理避免由新来源触发逐请求全表扫描。
- Run/Session SSE 共用 global 64、每 actor 4 条连接配额；owned permit 被移动进 response
  stream，只有 body drop 或流结束才释放。initial replay、hint reconciliation、Lagged recovery
  和 durable poll 都使用 SQL `LIMIT + 1` page，默认 128、硬上限 256；`has_more` 通过页间
  `yield_now` cooperative continuation 补齐，cursor 只随实际发送的 sequence 前进。
- Session summary list 使用 account scope 内 `(updated_at DESC, id ASC)` indexed keyset，默认
  50、最大 100，并以响应头续页；cursor 另绑定当前 actor。Session detail 的
  attachment/turn/event tail 和 Run detail/overview 的
  event tail 都使用 `LIMIT + 1`，collection 上限 100、event 上限 256；opaque cursor v2 绑定
  `(account, actor, kind, parent resource)`，不绑定 auth-session ID 或 membership revision，因此
  同一 actor 重新登录仍可续页。鉴权先于 cursor/limit 语义，projection、tail 和各独立 page 在同一
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
  v13 创建唯一 `acc_local` 和 `account_memberships`，只为既有唯一 active owner 建 revision 1
  membership，并给 Incident/Session/Run/runtime identity 回填 immutable `account_id`。迁移在任何
  account 写入前验证 legacy owner、actor、receipt、job、reservation、runtime binding 与外键；
  member-owned/cross-owner/损坏关系使 v12→v13 整体回滚。v14 重建 auth session、command
  receipt、reply/dispatch job 与 finalization reservation，固化 account、actor 和 membership
  revision；`account_memberships` 成为唯一 capability 权威，`users.role`/`owner_user_id` 只保留
  creator metadata。迁移前后在同一事务核对 row/FK/index/trigger/actor state，无法证明的旧
  authority 整体回滚；member 产品 gate 在 v14 保持关闭。v15 新增 member setup token、account
  audit event/hash chain、bounded rollup、policy 与 archive checkpoint；token 只保存
  `SHA256("zeus.member-setup-token.v1\0" || canonical_token)`，明文只在创建/轮换响应中出现。
  owner 的 role/status transition、auth/setup-token revoke、in-flight 摘要和审计事件在同一
  `BEGIN IMMEDIATE` 事务提交；最后一个 active owner 不能被禁用或降级。
  v16 为 `assistant_message` Session event 增加 partial reply-context index；历史读取由索引按
  `expected_sequence` 倒序限定后恢复为时间正序，只返回带相邻 `assistant_message` event 的
  最新完整对话，assistant-less flush 合法但不进入模型上下文。
  每个 pre-v4 Run 会绑定到生成的 `session-{run_id}`，原 Run/Event 不重写、不丢弃。
- runtime identity 持久绑定 profile、environment、primary Session/Run、policy ID 和
  revision；不一致时启动失败。Run attachment 当前用于 migration 和 demo seed，Alpha 不公开
  attach-Run HTTP route。
- queue claim 在任何外部调用前再次核对固化 account、User、membership role/status/revision、
  capability、job 的 Run、policy ID 和 revision；dispatch 同时复核可信 initiating 与 approving
  主体。没有持久 initiator provenance 的 actorless 请求在 connector 前 fail closed，不能用
  approver 身份补造。已经 claim 的 completion 不因后续撤权重放外部调用。
- Session/Run command 在鉴权与 exact receipt replay 之后、状态写入之前检查 actor/account/global
  三层 logical capacity；每个窄层配置都必须小于等于下一层。
  turn admission 预留两个 Session event slots 与完整终结载荷预算；dispatch admission 预留两个
  Run slots 与 start+terminal 载荷预算。reply claim 必须仍持有完整预留；dispatch started 将
  2→1 并把字节预算收敛为 terminal 上界；success/failure/rejection/recovery 在终态事务降到
  0 后删除 reservation。缺失/不足/错绑时在 provider/connector 前脱敏 `503`，普通容量拒绝
  使用 `429 + Cache-Control: no-store`，reply/dispatch queue 另返回 `Retry-After: 2`。
  字节计量只覆盖两张 event ledger 的序列化 `payload_json`，不等于 SQLite 主库、WAL、索引、
  page overhead 或宿主磁盘保证。
- Account audit 默认保留每 account 4,096 条详细事件，普通 hard ceiling 为每 account 8,192、
  global 32,768，并额外为 active→disabled、active owner→member、audit policy update 与 archive
  checkpoint 保留每 account 64、global 256 个 progress slot；member create、token rotate、setup、
  enable 与 member→owner 使用 ordinary lane。compaction 每事务最多推进 64 条。legal hold 禁止
  删除详细行，`archive_required`
  只允许压缩已由 owner checkpoint 覆盖的前缀。普通可审计 mutation 无容量时原子回滚并返回
  `507 audit_storage_exhausted`；进度 reserve 也有绝对上限，不承诺无限写入。hash chain 与
  rollup 只是 SQLite 内 commitment，不是外部防篡改锚。
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
  合并为一个 running worker 与至多一个 pending cycle。可恢复的 durable queue 错误按 25 ms
  到 1 s 有界指数退避继续 drain，避免一次错误让 queued work 永久失联，也避免忙转 Tokio task；
  不可恢复的 contract/corruption 错误记录后停止当前 worker，不做永久 1 Hz 自旋。
  Agent 的 prepare 不授权外部 I/O；worker 必须持有同一 claim 重试 exact start，只有确认过期后
  才返回 prepare 取得下一 generation。start 成功后只能重试幂等 completion，不能再次外调。
- provider 与 connector future 在独立 Tokio task 内执行；panic 不会把 wake state 永久留在
  running，而是在 durable started checkpoint 之后按 at-most-once 语义结算为
  `outcome_unknown`，不重试外部操作。
- OpenAI-compatible reply endpoint 默认只接受 HTTPS 或 loopback HTTP，禁止 redirect，限制连接/
  总超时和响应体；queued job 绑定 endpoint/model/limits/可选 SecretRef 的非秘密配置 digest，API
  key 不入 ledger。兼容 inline key 之外，`env:VARIABLE` 与 Unix
  `file:/absolute/normalized/path` resolver 会在每次 provider 操作前解析短生命周期 secret；file
  adapter 对 final path component 使用 `O_NOFOLLOW`、regular-file 检查、16 KiB read cap，并允许同路径原子换值。启动在
  打开 SQLite 前预检当前值；运行期 unavailable 在任何 provider I/O 前以脱敏
  `provider_secret_unavailable` 已知失败结算，不进入 `outcome_unknown`。
  多 Provider 启动注册表采用 strict versioned JSON、64 KiB 文件上限和 16 个远端 Provider 上限；
  只接受 SecretRef，不接受明文 key，并在 SQLite 打开前完成全部身份冲突检查与 credential preflight。
- provider assistant 或 executor output/diagnostic 超过终端字段边界时，runtime 使用固定、脱敏、
  有界 failure 一次性结算；原始超限载荷不进入 event、reply/dispatch job，也不会自动重试。
- sandbox 或 executor 不可用：写入 `NotDispatched`，禁止回退到宿主机裸执行。
- `production-guarded` profile 即使 owner 已认证，仍因真实生产 connector 缺失而保持执行禁用。
- `dev_marker_write` 仅在 `local-development` profile 注册，只能在服务端固定目录写服务器生成的
  marker 文件；参数不能提供路径。
- `workspace_list_directory`、`workspace_find_paths`、`workspace_search_text`、`workspace_read_file`、
  `workspace_read_lines`、`workspace_replace_text`、`workspace_insert_text` 与
  `workspace_create_file` 仅在显式配置
  `ZEUS_LOCAL_WORKSPACE_ROOT` 的 `local-development` profile 注册。服务启动时把该目录转换为
  capability root；模型只能提交 canonical relative UTF-8 path。目录发现最多返回 64 个按名称
  排序的直接子项并标注 file/directory/symlink/other。路径发现以相对 glob 匹配普通文件，支持
  单路径组件内的 `*`、`?`、字符类和完整组件 `**`，按固定目录数、文件数、总条目数、深度与
  32 个结果上限稳定返回。字面量文本搜索按稳定路径与行号返回最多
  32 个匹配，并固定限制目录数、文件数、深度、单文件 64 KiB 与总扫描 1 MiB；它跳过
  `.git`、`.svelte-kit`、`.zeus`、`node_modules`、`target` 与 `dist`。文件读取拒绝路径穿越、
  符号链接、非普通文件、非 UTF-8 内容和超过 8 KiB 的文件。行区间读取可处理至多 64 KiB 的
  UTF-8 普通文件，每次只接受至多 200 行的 inclusive range；超过 EOF 的 end line 向文件末尾
  收缩，start line 越界或所选内容超过 8 KiB 时明确失败，不做静默截断。前五个工具均不跟随
  符号链接，均为 `read_only + read_only sandbox`，策略自动允许。文本替换只处理现有、至多 64 KiB 的 UTF-8
  普通文件，要求 `old_text` 唯一出现，使用同目录临时文件、权限复制、file sync、原文复验、
  atomic rename 与 directory sync；相同 call ID 的近期同参重试返回有界内存 receipt，异参重用、
  目标变化、穿越或 symlink 均 fail closed。mutation receipt 以完整的服务端
  account/actor/Session/turn/Agent execution scope 加 call ID 为键，跨 scope 的 call-ID 碰撞不会
  复用结果。该工具固定为 `local_write + workspace_write sandbox`
  并要求 owner 对 exact persisted call 批准。行插入以 `after_line=0` 表示文件开头，其余值表示
  指定 logical line 之后；文件末尾换行产生一个可寻址的 trailing empty logical line，与行区间
  读取保持一致。插入文本限制为 4 KiB、结果限制为 64 KiB，并同样使用权限复制、file sync、
  原文复验、atomic rename、directory sync、owner exact-call approval 与有界 receipt。文件创建只允许在现有根内目录下写入至多 12 KiB
  UTF-8 内容，以同目录临时文件、file sync、create-new hard-link publication 与 directory sync
  原子发布；目标已存在、父目录缺失、穿越或 symlink 均 fail closed，且绝不隐式创建父目录或覆盖
  目标。它同样固定为 `local_write + workspace_write sandbox` 并要求 owner 批准 exact persisted
  call；近期同参重试复用有界 receipt。所有 workspace 工具都没有 shell 权限。
- persistent terminal 核心由独立、backend-neutral 的 `TerminalService` 管理，不直接启动宿主机进程。
  只有 embedding runtime 显式注入已配置的 isolated backend 时，才注册 `terminal_open`、
  `terminal_send`、`terminal_read`、`terminal_signal`、`terminal_close` 与 `terminal_list`；默认 API
  启动路径不注入 backend，因此 manifest 中不存在这些工具，也不存在 host-shell fallback。
  每个 terminal session 精确绑定服务端从 durable Agent work 还原的
  account/actor/Session/turn/Agent scope；其它 scope 查询同一 ID 只得到 unknown。每个 owner 最多
  4 个 session，整个 service 最多 128 个 live/pending session；send 输入、read 行数和返回字节均有
  硬上限，同一 session 不允许并发 send。任何 Agent durable terminal state 提交后，runtime 按 exact
  scope 移除并 best-effort close 全部 terminal；backend close 失败会记录，但不能占住 Zeus 内部容量，
  也不能重开已终止的 Agent。
  Zeus 对 backend 调用另设经校验的外层 deadline：spawn 与 initial snapshot 默认共用 60 秒总预算、
  send 45 秒、read/list/signal 10 秒，并为一个 owner 的全部并发 cleanup 共用 10 秒总预算；embedding application 构造 service
  时可在 5 分钟 hard ceiling 内调整。backend 返回 `wait_reason=timeout` 仍是已结算的 send 结果，且不
  证明进程退出；Zeus deadline 到期则表示 backend call 未结算。spawn timeout 会释放 pending name 与
  容量，send timeout 会释放 exclusive send slot，cleanup timeout 也必须先移除内部记录。
  open/send/signal/close 为 approval-gated mutation，read/list 为 read-only allow；mutation receipt
  同时绑定 scope、call ID、tool 和 arguments digest。durable started 之后 backend 报告不确定结果
  或 mutation 跨过 Zeus deadline 时结算 `outcome_unknown` 并中断 Agent turn，禁止自动重试可能已
  产生的副作用；read/list deadline 是确定的 `terminal_backend_failed`。
- `ZEUS_DEMO_PROFILE=production-guarded` 是默认值；切到 `local-development` 时必须使用独立
  SQLite 数据库，并由 `ZEUS_LOCAL_MARKER_ROOT` 固定写入根目录。只有显式设置
  `ZEUS_LOCAL_WORKSPACE_ROOT` 时才注册 workspace 工具；未设置时保留原 marker-only 行为。

## 容器边界

- Docker Compose 是开发拓扑：`full` 使用 `zeus_data:/var/lib/zeus`，`infra`、`postgres`、
  `debug` 和 `sandbox` 是独立 profile。Compose `.env` 和 project name 只作用于这条路径。
  API、Web、gateway 已分别静态接线可配置的 CPU/memory/PID ceiling；`full` 的 API 是
  `cargo-watch` 开发服务，默认 4 CPU/4 GiB/512 PID 包含编译余量，不是 runtime/OOM 基准。
- Linux release-runtime 验收使用独立 `compose.linux-acceptance.yaml`，只有 API、Web、gateway，
  以两个 internal network 隔离 API/Web，由 gateway 双连并只发布动态 loopback port。三个服务
  都使用 exact CPU/memory/no-swap/PID、非 root、read-only root、`cap_drop: ALL`、
  `no-new-privileges` 和 `restart: "no"`。配套脚本执行 fresh bootstrap、两路 Argon2、durable
  reply、operation-pressure/cgroup 时间序列与保留卷重建；normal/low-memory CI 会保存脱敏证据。
  当前主机无 Docker，因此只完成静态校验，不能把 Linux live gate 写成已通过。
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

- schema v1/v3/v5/v7/v8/v9/v10/v11 原地迁移到 v12 的历史证据继续保留；v12→v13 又原地建立
  `acc_local`、owner membership 与 root account scope。原 Run/Event payload、receipt 与 primary
  Session/Run 绑定稳定；迁移时尚未 bootstrap 的 legacy actor 只允许在首次 owner bootstrap
  事务中认领一次。v13→v14 再原地重建 auth session、receipt、reply/dispatch job 与 reservation；
  configured/unconfigured active work、窄化 NULL claim、owner-only auth 保留和 version-13 原子回滚
  都有确定性覆盖。后续 v15 member/audit、v16 context index、v17 Agent loop、v18 exact tool
  completion replay、v19 deployment manifest、v20 RunEpoch/execution fact ledger 与 v21
  prepared operation claim，以及 v22 knowledge context binding 与 domain-separated count+digest
  legacy-set commitment、v23 owner-governed knowledge catalog head/ingestion receipt、v24
  owner-governed Agent prompt head/revision/receipt，以及 v25 non-destructive Session context
  compaction state machine、v26 account-scoped reply provider、v27 safe Agent cancellation 与
  v28 durable Agent planning、v29 durable Session Goal 与 v30 same-Session Goal Round，
  也覆盖 fresh schema
  和历史原地迁移；畸形 v21 升级会整体回滚，不留下 v22 版本或表，既有 v22 数据库则原地增加
  空的 revision-0 catalog projection，不改写已经固化的 Agent knowledge context。
- 重启后用户/偏好、Session/turn/event、Agent/model/tool job、deployment manifest、Run/Event、
  审批决定、dispatch job 和命令回执仍存在。
- Session start 与 Agent/first-model enqueue/manifest binding 同事务；最终 reply 把 assistant
  provenance、连续事件、turn、Agent 和 job 终态原子提交，注入失败时整体回滚。测试专用 flush
  合约仍证明旧迁移路径的原子性。
- open turn 重启后只追加一次 `turn_interrupted`，Session 进入 `needs_attention`，不生成 flush
  ack、不改变 Run ledger；显式 resume 后才能开始新 turn。
- 同 key 同输入只提交一次并重放响应；同 key 不同输入返回冲突；不同 key 由对应 ledger 的
  head sequence CAS 仲裁。
- 未知工具、策略拒绝和 deployment drift 路径的 provider/executor 调用数为零。
- checkpoint 写入失败时外部副作用为零。
- Agent/legacy reply/dispatch 排队后 actor 被禁用、降权或失去 ownership 时，claim 写入 durable
  `authorization_revoked` 终态，provider/connector 调用数为零。
- legacy reply worker 先只读观察队首，再在同一执行上下文中保留固定 job ID 重试精确 start；
  start commit 的 ACK 模糊时只重放同一条 started/rejected 结果，不会选择下一条 queued work。
- Agent model/tool、legacy reply 或 dispatch 在 started 后模拟崩溃，均恢复为
  `outcome_unknown` 且不发生第二次外部执行。
- 新 Agent 的 manifest canonical/digest/reuse/secret-free、actor isolation、provider-visible tools
  及 prompt ID/revision/content digest 精确匹配和 provider/tool/policy/profile/prompt drift 均有
  自动化覆盖；prompt 缺失、重复、位置或内容不符在 provider I/O 前 fail closed。continuation 与
  重启恢复复用 exact persisted request，不重新解析当前提示词。v18 terminal history 可读，旧
  queued/waiting-approval 或 promptless work 在首次可执行边界以 `deployment_unavailable` fail
  closed。
- Account knowledge catalog 的 owner/member capability、revision CAS、相同 key 精确重放、异输入
  冲突、重启持久性、receipt 篡改检测，以及“HTTP 入库后 Agent 真实命中 active entry”都有自动化
  覆盖；catalog 更新不对已经持久化的 Agent 做 live reselection。历史列表/点查覆盖 owner 权限、
  newest-first 分页、revision 0、缺失 revision、重启持久性，并证明读取旧 corpus 后通过 CAS `PUT`
  只会创建新的恢复 revision。
- Account Agent prompt 的 revision-0 兼容、owner/member capability、16 KiB envelope、revision
  CAS、相同 key 精确重放、异输入冲突、v23→v24 migration、HTTP 入库后真实 provider request 与
  manifest 绑定，以及 prompt 更新后旧 queued Agent 在 provider I/O 前拒绝都有自动化覆盖。历史
  列表/点查还覆盖 newest-first 分页、revision 0、缺失 revision 和用旧内容创建新恢复 revision。
- 首次 bootstrap 只能消费一次 token；登录、CSRF、同源、Cookie 属性、设置 revision、退出后
  401 以及退出/失效后 SSE 关闭有自动化或 live 验收。
- bootstrap audit 的 v11 reason 迁移、canonical digest、64 行多批压缩、rotation/open 降限、
  wall-clock rollback、低磁盘 pre-write gate、非法 lifecycle/删除/rollup 回退与 deep corruption
  都有确定性存储测试。
- account foundation 的 fresh/v1/v5/v8/v12 migration、唯一旧 owner 回填、bootstrap 原子
  membership、revision/identity/last-owner trigger、root account immutability、deep integrity，
  以及 member-owned history/外键损坏时无部分 schema 的整体回滚都有确定性存储测试。
- 第二个进程不能同时打开同一个持久数据库；profile/policy identity 不匹配时 fail closed。
- 活跃 Run/Session SSE 不能无限拖住进程退出；SIGINT/SIGTERM 的 graceful drain 最长五秒，
  随后关闭剩余连接并释放 SQLite lease。
- local-development marker：批准前不存在、拒绝后不存在、allow-once 后只生成一个稳定文件。
- read-only workspace：真实 Agent tool loop 覆盖免审批执行、root confinement、canonical path、
  symlink/UTF-8/8 KiB 边界、有界字面量搜索、64 KiB 文件中的有界行区间读取，以及
  search → line read 的 exact tool result 逐步回灌。
- workspace exact edit：真实 Agent 在 owner 批准前不改文件，批准后只执行一次 unique text
  replacement，结果持久化并回灌下一模型步骤；拒绝、同参重放、异参 call-ID 冲突、目标变化、
  symlink、UTF-8 与 64 KiB 边界均 fail closed。
- workspace line insert：真实 Agent 在 owner 批准前不改文件，批准后只在 exact logical line
  boundary 原子插入一次并回灌 exact result；负数/越界行号、4 KiB 插入文本、64 KiB 结果、
  同参重放、异参 call-ID 冲突、目标变化与 symlink 边界均 fail closed。
- workspace create-new：真实 Agent 在 owner 批准前不创建文件，批准后只原子发布一个新文件并把
  exact tool result 持久化、回灌下一模型步骤；目标已存在、父目录缺失、同参重放、异参 call-ID
  冲突、symlink 与 12 KiB 边界均 fail closed。
- isolated terminal：显式注入 fake isolated backend 的真实 Agent loop 覆盖 open 与 send 两次
  exact-call approval、完整 server-owned execution scope、精确 tool-result 回灌，以及 backend
  send 跨过 Zeus deadline 时 durable `outcome_unknown`、Session `needs_attention` 且不重试外部操作；成功与
  outcome-unknown 终态都会自动 close exact-scope terminal。单元测试另覆盖 4/128 容量、owner 隔离、
  幂等 cleanup、spawn/send deadline、单一 cleanup 总 deadline，以及 backend close 失败或超时时释放
  内部容量。
- 生产 RDS 路径只能得到 executor unavailable，不能得到伪造成功。
- Session/Run SSE 重连都严格从各自大于 cursor 的 sequence 补齐事件。请求同时携带 query
  cursor 和 `Last-Event-ID` 时，后者优先。
- 请求或状态错误按 400/401/403/404/409/413/415/422/429/507 返回 problem details；内部执行不变量返回脱敏的
  `500 runtime_unavailable`；storage/config/registry 不可用返回脱敏的
  `503 runtime_unavailable`。内部错误只写服务端日志。
- 本地 Alpha+ 已按 UTF-8 bytes 限制 Session ID/title/user+assistant message/review note、
  typed reply/tool terminal payload 与幂等键；SSE
  replay 已在 storage 层分页，future cursor 对已授权资源返回 `409`，foreign resource 仍为
  `404`。审批、派发、Agent completion、attachment 和启动恢复已改为 typed point query 或
  固定 64 行 batch；Session list/detail 与 Run detail/overview 也已改为 indexed bounded read
  model。SQLite row/active/event-slot、逻辑 event-payload byte quota 与 physical capacity gate
  和 operation capacity gate 已落地；bootstrap audit detailed retention/rollup、v13 account
  membership foundation、v14 account-scoped durable authorization 与 v15 member lifecycle /
  account audit，以及 v17 Agent loop、v18 exact completion replay、v19 deployment manifest
  binding 已落地。对外或多租户部署仍必须完成共享部署门禁。
  此前 Operation Capacity Apple 指定 readiness-pressure 与历史 v14 migration/restart 已分别
  通过；v14 当轮没有重跑该压力。完整低内存/对抗性压力与 Linux Docker PID/OOM authoritative
  evidence 仍是 deployment gate。
- Web 保持紧凑时间线、一个内联审批卡和一个 composer；支持真实 New Session、活动 Session
  刷新恢复、owner/member setup/登录、owner 成员与 audit 管理、设置/退出和
  system/light/dark。member 的审批卡只读。持久 command identity 在刷新后恢复，丢失
  start 响应不会生成重复 turn；浏览器等待 server worker/SSE，不自行 flush。
- 当前自动化按项目既有统计口径是 704 个 Rust 测试（其中 connectors 22、deployment 8、knowledge 29、LLM unit 30、
  provider contract 18、skills 5、subagents 12、storage 286、workflows 21、runtime 52、API library 99、API main/config 18）和 28 个 Web Node 测试全部通过；Rust fmt/clippy、Svelte
  check/autofixer、lint 和 production build 也通过。

提交 `af29089` 曾构建并运行在独立 `zeus-operation-acceptance` project（端口 `18089`）；既有
`zeus-alpha` 容器与 volume 未被替换。当时镜像的 `build/up/verify/restart-verify` 均通过。
提交 `cdaa211` 的 schema v12 镜像随后在相同隔离 project 上重建，并保留 schema v11 named
volume；首次启动完成 v11→v12 migration，保留 volume 的第二次 `restart-verify` 也通过。API、
Web、gateway、认证状态、匿名保护边界均通过，且 `configured=false` 未配置状态在重启前后一致；
该历史 v12 readiness 的 exact-schema 检查覆盖迁移后的再次打开。
schema v13 镜像又在同一 `zeus-operation-acceptance` project 上保留上述现为 v12 的 named
volume，原地完成 v12→v13 migration；保留卷 `restart-verify` 通过。
历史 schema v14 镜像继续保留上述现为 v13 的 named volume，原地完成 v13→v14 migration；
`verify` 与保留卷 `restart-verify` 均通过。当时 API effective limit 为 2 CPU/1 GiB；重启后
`memory.current=79,466,496`、`memory.peak=98,201,600`、Zeus RSS 9,824 KiB、
`pids.current=6`，`memory.events` 为 `oom=0`、`oom_kill=0`；member 登录/API gate 当时仍关闭，
Apple `pids.max=max`。
最近一次容器证据仍是 schema v15 镜像：它继续保留 now-v14 volume，在 `127.0.0.1:18089`
完成 v14→v15 migration；
`verify` 与保留卷 `restart-verify` 通过且 `configured=false` 保持一致。API 仍为 2 CPU/1 GiB，
`memory.peak=99,479,552`、Zeus RSS 10,252 KiB、`pids.current=7`，OOM/kill 为 0。
schema v16 已通过主机 migration、readiness、query-plan 与多轮上下文测试，未把该历史容器结果
表述为 v16 运行证据。
独立 fresh `zeus-audit-acceptance` 以 detail 2、每 account ceiling 8、progress reserve 2 完成真实
member setup/reply、403、checkpoint、legal-hold 507、普通容量拒绝、disable reserve、session revoke、
NDJSON manifest 与 release-hold readiness 验收；浏览器覆盖 New Session、消息回复、Settings、
Members、Audit、dark mode 且无 console warning/error。保留卷 restart 后 `configured=true`，
`memory.peak=43,433,984`、Zeus RSS 10,340 KiB、OOM/kill 为 0。
此前 Operation Capacity 指定压力中，API 限制核对为 2 CPU/1 GiB；30,000 次 readiness、并发
128 的压力结果为 2,670 个 `200`、
27,330 个预期 operation-capacity `503`、transport error 0、约 6,677 req/s。第二轮 10,000 次、
并发 64 的 9,586 个 `503` 全部携带 `sqlite_operation_capacity_exceeded`。该历史压力期间及之后
`memory.peak=97,595,392` bytes、Zeus RSS 约 23 MiB、`oom=0`、`oom_kill=0`，且 CPU quota
发生 throttling。Apple VM 无 Swap，1.0 无 per-container PID limit 且 `pids.max=max`；因此这只
证明当时 Operation Capacity 镜像在该 Apple readiness-pressure 场景下保持有界；v14 本轮没有
重跑该压力，也不替代 Linux Docker PID/OOM authoritative acceptance 或更低内存/对抗性压力。
Docker Compose 当前只有静态配置检查；本机缺少 Docker CLI 时不声明 Compose build/up 已通过。
