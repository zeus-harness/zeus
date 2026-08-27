# Account Membership 与审计保留设计

状态：v12 Bootstrap Audit Retention 与 schema v13 Account Membership Foundation 均已实现。
主机 Rust/Web 全量门禁通过；Apple `zeus-operation-acceptance` 先保留历史 v11→v12 证据，随后又在
同一 named volume 上完成 v12→v13 原地迁移及保留卷重启验证。v14-v15 仍待实施。本文不表示
member 已可登录，也不授权共享网络部署。

当前实现基线是 schema v13。产品仍是单实例、单 owner；所有业务 HTTP/SSE 都拒绝 `member`。

## 1. 为什么不能直接开放 member

当前 `owner_user_id` 同时承担三种不同职责：

1. Session/Run 的资源所属作用域；
2. 发起命令、reply 或 approval 的 actor 身份；
3. receipt、队列和容量限制的 scope key。

这三种职责在单 owner 模式下恰好相同，在 account 内协作时不再相同。现有实现还存在有意的
角色差异：Session/reply storage 接受 active `member`，Run review/dispatch 只接受 active
`owner`，而 API 在最外层拒绝所有 member。仅删除 API 的 owner 检查会得到一个半授权系统：
member 可以创建 Session 和触发 provider，却不能稳定读取或审批相连的 Run。

因此实施必须遵守：

- 先建立 account scope，再开放 member；
- account ID 与 actor user ID 永远分列；
- worker 在 provider/connector 调用前重新验证 membership 与 capability；
- foreign account 与无 membership 的对象继续统一返回 `404`；
- member gate 在全部迁移和验收完成前保持关闭。

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

当前 v13 的 `owner_user_id` 仍是访问控制权威。只有 v14 完成授权切换后，它才不再参与访问控制，
并只作为 legacy creator 来源，最终明确命名为 `created_by_user_id`。历史事件 payload 不重写。

v11 允许通过 storage 构造 member-owned Session，因此 configured migration 不能无条件把所有
数据并入 `acc_local`。v13 迁移在写入任何 account 字段前证明：所有 Session/Run owner 都等于
唯一旧 owner；receipt、reply/dispatch job 与 reservation actor/scope 都能追溯到该 owner；同一
Incident 不跨旧 owner。任一条件不成立，migration 整体回滚并停在 v12，不自动给旧 member
membership，也不扩大旧 owner 的可见范围。无法证明归属的旧 member auth session 在 v14 必须
撤销，不能猜测绑定到 `acc_local`。

## 3. 统一授权上下文

本节描述待实施的 v14 授权目标，不是当前 v13 已开放的 API/storage 行为。

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
当前 v13 及 v14-v15 设计只支持一个 `acc_local`，不提供 account picker 或多 account runtime。
未来若增加 account 切换，一个登录 session 仍只能绑定一个 account，切换必须轮换 session
token，避免请求头临时选 tenant 带来的 confused-deputy 风险。

首版权限矩阵：

| Capability | owner | member |
| --- | :---: | :---: |
| Account 内 Session/Run 读取 | ✓ | ✓ |
| 创建 Session、发送 turn、resume | ✓ | ✓ |
| 调用 reply provider | ✓ | ✓ |
| approval、connector dispatch | ✓ | — |
| 成员管理、Account/provider 设置 | ✓ | — |
| 安全审计读取与导出 | ✓ | — |

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

当前 v13 过渡期仍保留 `users.role`，并要求全局唯一旧 owner 与 `acc_local` owner membership 完全
一致；API member gate 继续读取旧边界。v14 必须把 membership role 变成 account capability 的
唯一权威，删除或停止使用 `users.role`、`users_single_owner_idx` 和所有 `StoredUserRole`
授权分支。`AuthPrincipal`、API 返回 role、Run/reply/dispatch 检查全部改读当前 membership；
旧授权点归零前不能开放 member。

## 4. 数据与幂等作用域

以下 account-scoped receipt、capacity 与 cursor 也是 v14 目标；当前 v13 仍使用既有 owner/actor
scope，不得据此开放 member。

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

Account scope 清单还包括 member setup/invitation token、provider/connector 配置与 secret
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

以下新增错误是 v14-v15 目标。当前 v13 的 member 登录仍保持通用 `401 invalid_credentials`，
没有 account picker 或成员管理 HTTP API。

- `401 authentication_required`：没有 session，或身份/session 已失效。
- `401 invalid_credentials`：登录失败；用户名不存在、密码错误、User disabled 必须不可区分。
- `403 permission_denied`：已认证且属于该 account，但缺少 capability，例如 member 审批。
- `404 *_not_found`：对象不存在、跨 account 或没有该 account membership；不得泄露存在性。
- `409 membership_revision_conflict`：成员管理 optimistic concurrency 冲突。
- `409 last_account_owner`：试图禁用或降级最后一个 active owner。
- `409 idempotency_conflict`：相同完整 scope/key 对应不同请求。

auth、setup token、成员管理和 audit 响应统一 `Cache-Control: no-store`。member gate 未开放时，
member 登录仍保持现有通用 `401 invalid_credentials`。

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

## 7. Account security audit（后续 schema）

account audit 只记录安全与管理状态变化，不把每次读取都写入 SQLite，也不允许未认证失败请求
无限放大持久写：

- owner/member 创建、setup、disable、角色变化；
- auth session revoke-all、密码重置；
- Account/provider policy 变化；
- approval、dispatch 授权撤销；
- retention/legal-hold 变化和每次 archive/purge。

每条事件固定 `account_id`、可空的 `actor_user_id`、action、outcome、target、occurred_at 和有界
metadata。actor 退出后历史不改写。登录失败继续先受内存 rate limit 约束；若加入持久审计，必须
使用有界聚合，不能每个攻击请求写一行。

v15 本地版本先采用 count-bounded 详细窗口和永久 account 摘要链；详细窗口、account/global
hard ceiling、reserved revocation capacity 和 compaction batch 都必须是显式配置。legal hold
阻止详细行 purge；若 hold 使普通 audit admission 达到 ceiling，普通可审计 mutation fail closed
为 `507 audit_storage_exhausted`，readiness 降级，disable/revoke 与既有工作的 settlement 使用预留
进度容量。即使有预留也不能承诺无限写入，响应必须暴露需要 export/release-hold 的运维状态。

365 天详细保留是共享部署目标，不是 SQLite-only v15 的无条件保证。对外声明该期限前必须接入
有容量证明的外部归档，并验证 legal hold、归档故障和恢复；account 摘要链也不是独立防篡改锚。
owner-only audit list/export 使用 keyset page，不允许全表加载。

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

v13 已采用双轨过渡：只新增/回填 immutable account scope，现有 `owner_user_id` 授权和 trigger
继续工作。v14 先重建 account-scoped receipt/job/reservation 与一致性 trigger，通过 deep
integrity 后切换代码，最后删除旧 owner 授权 trigger/index 并把 creator 列明确改名。

### v14：Account-scoped Durable Authorization（待实施）

- 引入 `AuthzContext`；
- membership role 取代 `users.role` 成为唯一 capability 权威；
- auth session、receipt、job、reservation、cursor 与 capacity 改为 account scope；
- worker claim 复核 membership revision/capability；
- 无 actor 业务入口收窄；
- API 仍拒绝 member，先跑完整迁移与撤权测试。

### v15：Member Lifecycle 与 Account Audit（待实施）

- owner 创建 member 并返回一次性 setup token；
- member 设置密码、登录、读写 Account Session；
- member approval 返回 `403`，owner 可以审批；
- disable member 后 SSE 关闭；只有 disable 事务先于 claim 提交的排队工作保证在外部调用前
  被拒绝，已 in-flight 工作必须在响应中列出；
- owner-only audit list/export、count-bounded local retention、legal hold 与外部归档接口；
- 全部验收后才移除 member 登录 gate。

## 9. 验收状态与后续门槛

schema v13 已完成的证据：

- `cargo test --workspace --all-targets` 共 289 个测试通过，其中 storage 139、runtime 28、API
  library 44、API main/config 4，其余 crates 与 graceful-shutdown 合约也通过；
- `cargo fmt --all -- --check` 与 workspace all-target clippy 通过；
- fresh 及既有 v1/v5/v8/v12 数据迁移覆盖 account 回填，member-owned history、外键破坏或无法
  证明的 owner/actor/scope 会使 v12→v13 整体回滚，不留下部分 account schema；
- `acc_local`、唯一旧 owner membership、bootstrap 原子建 membership、account/revision/last-owner
  trigger、root scope immutability 与 deep-integrity corruption 都有确定性 storage 测试；
- Bootstrap Audit Retention 的 v11→v12 reason 迁移、rotation/open 多批压缩、摘要连续性与非法
  删除测试继续通过，未因 v13 改写 ledger 或 receipt；
- Web 25 个 Node 测试及 check、lint、production build 全部通过；
- Apple current-image `zeus-operation-acceptance` 保留 schema v12 named volume，原地迁移到 v13，
  `restart-verify` 后仍通过；入口为 `127.0.0.1:18089`，API 限制为 2 CPU/1 GiB，采集到的
  `memory.events` 为 `oom=0`、`oom_kill=0`。

v14-v15 仍须完成并重新验收：

- Account A 的 actor 对 Account B 的 REST、SSE、cursor、receipt 一律得到 `404`；
- membership revision 变化后旧 cookie、SSE 与在变更后 claim 的 job 全部失效；
- member 能调用配置好的 reply provider 完成 Session 对话；provider 配置、tool policy、approval
  与 connector dispatch 保持 owner-only；
- 同 account 两个 actor 的同名 idempotency key 互不 replay；
- account audit、member setup/disable、legal hold、归档与 retention failure injection 达到本文约束；
- 全部门禁通过后才移除 member 登录/API gate。当前 v13 不得描述为多租户授权已经完成。

共享网络部署还必须另行完成 TLS/canonical origin、trusted proxy、Secure cookie、per-account
provider secret/计费隔离与 Linux Docker PID/OOM gate；membership 完成本身不等于可以暴露到
公网。
