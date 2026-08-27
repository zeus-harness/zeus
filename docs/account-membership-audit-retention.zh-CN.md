# Account Membership 与审计保留设计

状态：v12 Bootstrap Audit Retention、schema v13 Account Membership Foundation、schema v14
Account-scoped Durable Authorization 与 schema v15 Member Lifecycle / Account Audit 已实现。
Apple `zeus-operation-acceptance` 保留了历史 v11→v12→v13→v14 迁移链；current-image 的 v15
迁移与验收证据见本文第 9 节。当前版本允许同一 `acc_local` account 内的 owner/member 协作，
但仍是单实例本地部署，不表示共享网络、多 account 或公网部署已经具备上线条件。

## 1. 为什么不能只删除 member gate

v13 以前的 `owner_user_id` 同时承担三种不同职责：

1. Session/Run 的资源所属作用域；
2. 发起命令、reply 或 approval 的 actor 身份；
3. receipt、队列和容量限制的 scope key。

这三种职责在单 owner 模式下恰好相同，在 account 内协作时不再相同。v14 已把资源 account、
命令 actor、receipt/capacity scope 分列，并用 capability 区分 Session/reply 与 approval/dispatch；
v15 在此基础上增加 setup、disable、revision revoke、SSE 复核、worker claim 复核与 account audit，
完成后才移除最外层 member gate。当前 member 能进入普通 Session/Run 与 reply 路径，不能进入
approval、connector dispatch、成员管理或 audit 管理路径。

因此实施必须遵守：

- 先建立 account scope，再开放 member；
- account ID 与 actor user ID 永远分列；
- worker 在 provider/connector 调用前重新验证 membership 与 capability；
- foreign account 与无 membership 的对象继续统一返回 `404`；
- member 只开放权限矩阵明确授予的路径；owner-only 路径在 API、runtime 与 storage 三层复核。

## 2. 术语和权威实体

- **User**：全局登录身份。用户名在首版仍全局唯一，`users.status` 表示身份是否可登录。
- **Account**：数据、容量、配置和审计的隔离边界；产品 UI 可显示为 workspace。
- **Membership**：User 在 Account 内的角色、状态和单调 revision。
- **Actor**：执行某次命令的 User；它是审计作者，不是资源所属者。
- **Capability**：在一个 Account 内执行某类动作的权限。

schema v13 已落地的 foundation 表：

```sql
accounts(
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'suspended')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

account_memberships(
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  role TEXT NOT NULL CHECK (role IN ('owner', 'member')),
  status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
  revision INTEGER NOT NULL CHECK (revision > 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(account_id, user_id)
);
```

v13 只创建一个 `acc_local`，并只把既有唯一 owner 回填为 active owner membership。数据库中
手工存在的 member 不自动加入 account；无法证明的授权必须保持关闭。schema 可以容纳多个
owner，但成员管理事务必须禁止禁用或降级最后一个 active owner。

membership identity 和权限 revision 由 schema trigger 强制：`account_id`、`user_id`、
`created_at` 不可修改；role/status 变化必须满足 `NEW.revision = OLD.revision + 1`；membership
禁止 DELETE，只能 durable disable。last-active-owner 检查与 revision 更新位于同一个
`BEGIN IMMEDIATE` 事务。非权限字段是否推进 revision 必须由字段级 trigger 明确，不能由调用者
自行选择。

以下根实体最终都必须有不可变 `account_id`：

- `incidents`、`sessions`、`runs`；
- `runtime_identity`；
- `auth_sessions`；
- `reply_jobs`、`dispatch_jobs`；
- Session/Run receipts 与 `finalization_reservations`。

v14 中 `owner_user_id` 已退出访问控制，只作为 legacy creator metadata；后续可明确命名为
`created_by_user_id`。历史事件 payload 不重写。

v11 允许通过 storage 构造 member-owned Session，因此 configured migration 不能无条件把所有
数据并入 `acc_local`。v13 迁移在写入任何 account 字段前证明：所有 Session/Run owner 都等于
唯一旧 owner；receipt、reply/dispatch job 与 reservation actor/scope 都能追溯到该 owner；同一
Incident 不跨旧 owner。任一条件不成立，migration 整体回滚并停在 v12，不自动给旧 member
membership，也不扩大旧 owner 的可见范围。无法证明归属的旧 member auth session 在 v14 必须
撤销，不能猜测绑定到 `acc_local`。

## 3. 统一授权上下文

本节描述 v14 建立、v15 对外启用的授权边界。

HTTP、runtime 和 storage 的业务入口使用一个显式上下文，不能继续只传裸 `actor_user_id`：

```rust
struct AuthzContext {
    account_id: AccountId,
    user_id: UserId,
    membership_role: MembershipRole,
    membership_revision: u64,
    auth_session_id: AuthSessionId,
}
```

登录 session 绑定 `account_id` 与签发时的 `membership_revision`。每次认证都 JOIN active User、
active Account 和 active Membership；revision、角色或状态发生变化后，旧 session 立即失效。
当前设计只支持一个 `acc_local`，不提供 account picker 或多 account runtime。
未来若增加 account 切换，一个登录 session 仍只能绑定一个 account，切换必须轮换 session
token，避免请求头临时选 tenant 带来的 confused-deputy 风险。

首版权限矩阵：

| Capability                      | owner | member |
| ------------------------------- | :---: | :----: |
| Account 内 Session/Run 读取     |   ✓   |   ✓    |
| 创建 Session、发送 turn、resume |   ✓   |   ✓    |
| 调用 reply provider             |   ✓   |   ✓    |
| approval、connector dispatch    |   ✓   |   —    |
| 成员管理、Account/provider 设置 |   ✓   |   —    |
| 安全审计读取与导出              |   ✓   |   —    |

member 发起的 reply job 固化 `account_id + actor_user_id + membership_revision`。由 member
发起、owner 批准的 dispatch 同时固化 `initiating_actor_user_id + initiating_revision` 和
`approving_actor_user_id + approving_revision`；同一人发起并批准时两个主体可以相同。claim
事务同时复核 initiating actor 仍有发起工作 capability、approving actor 仍有 dispatch
capability。

所有 durable mutation 都必须在最终 `BEGIN IMMEDIATE` 事务内重新读取 membership revision、
capability 和资源 account，并在同一事务中完成授权、receipt lookup 与状态写入。middleware 中
的 `AuthzContext` 只做入口筛选，不是授权线性化点。

撤权与 claim 的承诺以事务提交顺序定义：membership 变更先提交时，后续 claim 必须原子写入
`authorization_revoked` 终态且外部调用为零；claim 先提交时，job 已进入 in-flight，后续撤权
不能承诺取消 provider 请求或远端副作用。disable 响应必须返回仍在执行的 job 摘要，不能把它们
描述为已取消。

授权复核失败不是只改 job 状态。reply 必须在一个事务内提交 terminal job、turn/Session
projection、terminal ledger event 并消费/删除 reservation；dispatch 同样提交 terminal job、
Run projection、not-dispatched evidence 与 reservation settlement，SSE 必须能够观察终态。

面向业务的新 handler 只能调用带 `AuthzContext` 的方法。现有无 actor 方法应降为
crate-private、seed/recovery 专用或删除，避免未来 handler 误用。

v14 仍保留 `users.role` 作为 creator metadata，但已删除 `users_single_owner_idx`，所有认证、API
返回 role、Run/reply/dispatch 授权均读取 `account_memberships`。Storage 每次在事务内从 durable
membership 取得 role/capability，不信任调用方携带的 legacy role；v15 的登录和业务 API 使用
同一 durable membership 权威。

## 4. 数据与幂等作用域

以下 account-scoped receipt、capacity 与 cursor 已在 v14 落地，并由 v15 member 路径复用。

- 资源查询以 `account_id` 隔离，actor capability 决定动作；不再要求 actor 直接“拥有”资源。
- receipt identity 为
  `(account_id, actor_user_id, operation, idempotency_key)`。不能只用 account，否则两个成员会
  replay 对方的响应。
- Session/open-turn/reply/dispatch admission 保留 actor、account、global 三层上限；account 是
  资源隔离边界，但单个 member 不能耗尽整个 account 配额而没有 actor 级门禁。
- reply/dispatch 的 actor 字段永久保留，成员退出或删除不能改写历史作者。
- Session/Run/Incident 关系使用 composite FK 或 trigger 确认 account 一致；跨 account 绑定
  必须在写入 ledger、receipt 或 reservation 前失败。
- cursor digest 绑定 `(account, actor, cursor_kind, parent_scope)`；collection 使用 collection
  scope，resource tail 使用 resource ID。foreign resource 的授权发生在 limit/cursor/receipt
  语义解析前。

Account scope 清单还包括 member setup token、provider/connector 配置与 secret
reference、tool policy/config revision、account preferred-model policy、event-payload account
aggregate、legal hold、retention policy、archive/export job，以及 dispatch 的双主体授权证据。
这些对象都必须有 account FK、revision、明确生命周期和跨 account trigger。

v13 已对既有 SQLite 表采用 additive migration，不依赖带默认值的 `NOT NULL REFERENCES`：先增加
nullable FK 列，在同一 migration transaction 内完成上述预检和 `acc_local` 回填，再安装
INSERT trigger 拒绝 NULL、UPDATE trigger 禁止 account_id 变化。deep integrity 必须断言没有
NULL、孤儿或跨 account 关系，并为 `(account_id, id/order key)` 建索引。只有在后续独立迁移完整
重建表并验证循环 FK、append-only trigger、active reservation 和 payload counter 后，才把物理
列收紧为 `NOT NULL`。

## 5. HTTP 错误契约

v15 延续 authentication/authorization/resource 错误边界，并增加成员管理和 account audit 合约。
普通登录失败继续保持通用 `401 invalid_credentials`；setup token 无效、过期、已消费或已轮换统一
返回 `401 invalid_member_setup_token`，不泄露具体原因。当前没有 account picker。

- `401 authentication_required`：没有 session，或身份/session 已失效。
- `401 invalid_credentials`：登录失败；用户名不存在、密码错误、User disabled 必须不可区分。
- `403 permission_denied`：已认证且属于该 account，但缺少 capability，例如 member 审批。
- `404 *_not_found`：对象不存在、跨 account 或没有该 account membership；不得泄露存在性。
- `409 membership_revision_conflict`：成员管理 optimistic concurrency 冲突。
- `409 last_account_owner`：试图禁用或降级最后一个 active owner。
- `409 member_already_exists`：成员身份或用户名已存在。
- `409 member_setup_not_pending`：成员已完成 setup，不能再使用 setup 流程。
- `409 audit_policy_revision_conflict`：audit policy revision 已变化。
- `409 audit_checkpoint_conflict`：archive checkpoint revision 或前缀不匹配。
- `409 idempotency_conflict`：相同完整 scope/key 对应不同请求。
- `507 audit_storage_exhausted`：legal hold/archive 约束下普通可审计 mutation 已无安全容量。
- `507 audit_export_too_large`：完整 NDJSON export 超过响应上限；不得返回截断的 `200`。

auth、setup token、成员管理和 audit 响应统一 `Cache-Control: no-store`。v15 的 setup、成员管理与
audit mutation 不宣称 HTTP 幂等 receipt；携带 `Idempotency-Key` 会明确返回 `400
idempotency_not_supported`。创建响应丢失时，owner 先刷新成员列表，再对仍为 setup-pending 的
成员轮换 token；revision mutation 遇到 `409` 后刷新再决定是否重试。

## 6. Bootstrap audit retention（schema v12）

当前未配置实例每次启动都会签发新 bootstrap token。`bootstrap_tokens` 默认最多 1,024 行，
却禁止删除；第 1,025 次未配置启动会在监听端口开放前失败。rotation 与真正 consume 又共用
`used_at`，无法区分终止原因。

v12 先独立修复这个 system-scope 问题，不改任何 Session/Run ledger 或 receipt：

- 每个 token lifecycle 增加单调 `sequence`、`terminal_at` 和 `terminal_reason`；
- reason 为 `superseded`、`consumed`、`expired` 或迁移专用 `legacy_unknown`；
- 任意时刻最多一个 live token，live token 永不被压缩；
- `ZEUS_MAX_BOOTSTRAP_AUDIT_ROWS` 表示保留的详细 lifecycle 窗口，默认 1,024、hard ceiling
  65,536；
- rotation 在同一事务中终止旧 token，按 sequence 每批最多 64 行压缩最老 terminal 前缀，
  再签发新 token；任一步失败全部回滚；
- 被移除的 canonical rows 链入 singleton rollup：`through_sequence + SHA-256 digest +
updated_at`。rollup 永久保留且只能单调前进；详细窗口因此有界，同时新启动不会因历史行数
  达上限而锁死。

该 digest 是数据库内的历史压缩 commitment，不是外部可信锚。它能约束正常实现的前缀压缩，
但不能检测拥有 SQLite 任意写权限的人把 digest 与 trigger 一并替换；文档、API 和验收不得把它
描述成独立的防篡改证明。

v12 的 digest 采用固定 v1 编码，不能依赖 SQLite JSON 或平台字节序：初始值是 64 个 ASCII
`0`；每行按 sequence 处理，计算
`SHA256("zeus.bootstrap-audit-rollup.v1\0" || previous_digest_ascii || sequence_i64_be || fields)`。
fields 依次为 token hash、created_at、expires_at、terminal_at、terminal_reason；每个字段编码为
`length_u64_be || utf8_bytes`，结果保存为 lowercase hex。修改编码必须升级 domain/version。

## 7. Account security audit（schema v15）

account audit 只记录已实现的安全与管理状态变化，不把每次读取都写入 SQLite，也不允许未认证失败
请求无限放大持久写。当前 action 精确限定为 `member.created`、
`member.setup_token_rotated`、`member.setup_completed`、`member.disabled`、
`member.enabled`、`member.role_changed`、`audit.policy_updated` 与
`audit.archive_checkpointed`。owner 创建、session revoke-all、密码重置、provider policy、
approval/dispatch revoke 和 purge 审计属于后续范围，当前版本不得声称已经覆盖。

每条事件固定 `account_id`、可空的 `actor_user_id`、action、outcome、target、occurred_at 和有界
metadata。actor 退出后历史不改写。登录失败继续先受内存 rate limit 约束；若加入持久审计，必须
使用有界聚合，不能每个攻击请求写一行。

v15 本地版本先采用 count-bounded 详细窗口和永久 account 摘要链；详细窗口、account/global
hard ceiling、reserved revocation capacity 和 compaction batch 都必须是显式配置。legal hold
阻止详细行 purge；若 hold 使普通 audit admission 达到 ceiling，普通可审计 mutation fail closed
为 `507 audit_storage_exhausted`，readiness 降级。progress reserve 只用于 active→disabled、
active owner→member、audit policy update 与 archive checkpoint；member create、token rotate、
setup、enable 和 member→owner 使用 ordinary lane。即使有预留也不能承诺无限写入，响应必须暴露
需要 export/release-hold 的运维状态。

365 天详细保留是共享部署目标，不是 SQLite-only v15 的无条件保证。对外声明该期限前必须接入
有容量证明的外部归档，并验证 legal hold、归档故障和恢复；account 摘要链也不是独立防篡改锚。
owner-only audit list 使用 keyset page，不允许全表加载。NDJSON export 在发送 `200` 前遍历稳定
分页、校验事件序列与 rollup，并受 96 MiB 响应上限约束；首行是带 schema/version、rollup、
snapshot head 与事件计数的 manifest，后续每行才是事件。超限明确失败，不能把截断的 `200`
误当完整归档。更大的历史应分页读取或接入外部归档。

Session/Run ledger、receipt、turn、reply/dispatch job 不在本阶段做 retention。直接删除它们会
破坏连续 sequence、SSE cursor、FK 和 exactly-once replay。未来若压缩 ledger，必须先加入
`retained_from_sequence`、可信 snapshot/archive anchor、低于 floor 的
`410 history_compacted`，以及永久 idempotency tombstone；任何情况下都不能重新执行已过期的
副作用命令。

## 8. 实施切片

### v12：Bootstrap Audit Retention（已实现）

- 明确 token lifecycle 原因；
- 有界详细窗口与单调 rollup；
- 证明超过 1,024 次 rotation 仍可启动；
- ledger、receipt、member gate 零变化。

### v13：Account Membership Foundation（已实现）

- 新增 `accounts`、`account_memberships`；
- 创建 `acc_local`，回填 Incident/Session/Run/runtime identity account scope；
- 只给既有唯一 owner 建 membership；旧 member 不自动授权；
- member-owned/cross-owner legacy state 或无法证明的 actor/scope 使 migration 整体回滚；
- bootstrap 在原事务内创建 owner membership；
- 以 nullable FK + 完整回填 + non-NULL/immutable trigger 落地 account_id；
- 新增 account 一致性 FK/trigger、revision/identity trigger、点查询与 deep-integrity 校验；
- API 仍拒绝 member。

v13 采用双轨过渡，只新增/回填 immutable account scope；v14 随后重建 account-scoped
auth/receipt/job/reservation 与一致性 trigger，通过 migration postflight 与 deep integrity 后切换
代码，并删除旧 owner 授权 trigger/index。creator 列的物理改名仍可在后续兼容迁移中完成。

### v14：Account-scoped Durable Authorization（已实现）

- 引入 `AuthzContext`；
- membership role 取代 `users.role` 成为唯一 capability 权威；
- auth session、receipt、job、reservation、cursor 与 capacity 改为 account scope；
- worker claim 复核 membership revision/capability；
- 无 actor 业务入口收窄；
- API 仍拒绝 member，先跑完整迁移与撤权测试。

### v15：Member Lifecycle 与 Account Audit（已实现）

- owner 创建 member 并返回一次性 setup token；
- member 设置密码、登录、读写 Account Session；
- member approval 返回 `403`，owner 可以审批；
- disable member 后 SSE 关闭；只有 disable 事务先于 claim 提交的排队工作保证在外部调用前
  被拒绝，已 in-flight 工作必须在响应中列出；
- owner-only audit list/export、count-bounded local retention、legal hold，以及 owner 声明式外部
  归档 checkpoint 状态；当前版本不包含外部传输服务；
- member 登录 gate 已在上述 storage/runtime/API 约束和回归测试落地后移除。

## 9. 验收状态与后续门槛

schema v15 当前已完成的证据：

- `cargo test --workspace --all-targets --all-features` 按项目既有口径共 342 个测试通过，其中
  storage 174、runtime 33、API library 51、API main/config 6，并包含子进程数据库锁与 active-SSE
  SIGTERM 合约；`cargo fmt --all -- --check`、workspace all-target/all-feature clippy 与
  `git diff --check` 通过；
- v14→v15 会按当前配置写入 audit detail target；已有 v15 policy 超过后来降低的硬上限时启动
  fail closed，且不改写 schema/policy。migration failure、缺失 index/trigger、legal hold、archive
  checkpoint、ordinary/progress capacity 和 hash-chain corruption 均有确定性测试；
- member setup/login、Session read/write/reply、approval/audit/admin `403`、disable 后 cookie/SSE
  撤销、claim 前 revision/capability 复核与 in-flight 边界都有 storage/runtime/API 回归；
- Web 28 个 Node 测试、Svelte autofixer/check、lint 和 production build 通过；真实浏览器已验证
  New Session、消息回复、Settings、Members、Audit 与 dark mode，控制台无 warning/error；
- `zeus-operation-acceptance` 保留历史 v11→v12→v13→v14 named volume，当前 v15 `up/verify` 与
  保留卷 `restart-verify` 通过，`configured=false` 保持不变；API 为 2 CPU/1 GiB，记录的
  `memory.peak=99,479,552`、Zeus RSS 10,252 KiB、`pids.current=7`，OOM/kill 为 0；
- fresh `zeus-audit-acceptance` 以 detail 2、每 account ceiling 8、progress reserve 2 实测 owner
  bootstrap、member setup/reply、audit 403、checkpoint、legal-hold 507、三次额外 create 后容量拒绝、
  disable reserve、session revocation、完整 NDJSON manifest 与 release-hold readiness 恢复；保留卷
  restart 后 `configured=true`，`memory.peak=43,433,984`、Zeus RSS 10,340 KiB，OOM/kill 为 0。

provider 配置、tool policy、approval 与 connector dispatch 仍保持 owner-only。Apple
`pids.max=max`，上述证据不是 Linux PID-limit/OOM authoritative acceptance。

single-node trusted ingress 的主机契约已实现 canonical HTTPS origin、trusted proxy CIDR、严格
client IP 和强制 Secure Cookie；共享网络部署仍须独立证明真实 TLS/proxy 配置、listener 网络
隔离、per-account provider secret/计费隔离与 Linux PID/OOM gate。membership 或主机测试本身
都不等于可以直接暴露到公网。

Linux PID/OOM gate 的独立 release-runtime Compose、normal/low-memory verifier 和 CI 证据契约
已经落地，详见 `docs/linux-container-acceptance.zh-CN.md`；当前主机没有 Docker CLI，真实 Linux
job 尚未运行，因此仍不得声明该 gate 已通过。single-node trusted ingress 与该部署 gate 相互
独立；两者都不能直接放开多 account 或多 API 副本。
