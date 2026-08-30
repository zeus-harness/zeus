# Zeus 0.1.0 研究记录

## 目的

这份记录服务于 Zeus 0.1.0。它固定源码阅读的版本，避免把不同提交混在一起。

下面的提交是研究锚点，不是 Zeus 的依赖。没有写入的源码，不会因为出现在这里就进入仓库。

## 固定提交

| 项目 | 固定提交 | 关注点 | 结论 |
| --- | --- | --- | --- |
| DeepSeek Harness | `cd5ef8148158c3a752a658978873241fdf8e2bbc` | Agent loop、Session、能力扩展点 | 学习执行链和 append-only Session 事件；用 Rust 重写，不逐包翻译。 |
| Pi | `6c87d9a026677b601e8278030dcf1ad97fe0bd86` | Harness 接口和适配边界 | Pi 部分接口 HarnessNotImplemented。它们只算边界，不算 Zeus 已有能力。 |
| Symphony | `8001b52e3062495a16e520e4ceaf8f9de868c4d0` | 长任务和 Agent 编排 | 只取任务生命周期的思路；状态仍由 Zeus 自己的领域模型负责。 |
| Astonish | `98b9a33b7771e45dd00afe32d554eeddccaec583` | Agent 与工具的组合方式 | 只作设计对照；不把外部运行时状态当作 Zeus 事实。 |
| Windmill | `7a0c81d7222f3e7bb971c3cb9baeb82f153ba749` | 工作流和工具边界 | Windmill 混合许可证只学习不复制。不得带入代码、依赖、片段或生成物。 |
| Codex | `4ee04c0aa5833ac39b1763f6ea44c7bc777c83dd` | Agent 任务、工具调用和恢复边界 | 只比较任务编排和工具约束；授权和审计由 Zeus 控制。 |
| PGMQ | `c41b93adc4a93914339bde0ec3792311191f9e73` | 队列 claim、重试和可见性边界 | 只学习队列语义。Zeus 0.1.0 不接入 PGMQ 扩展。 |
| Rauthy | `e2367289847e0db252eb3f5aa1a2ceee87deb3e3` | 原生身份、联合登录和 OIDC Provider | 学习安全状态和故障恢复语义。Zeus 不复制源码，也不依赖 Rauthy 内部模块。 |

DeepSeek Harness 和 Pi 的提交已用独立临时检出复核。复核目录不进入 Zeus 仓库。

## DeepSeek Harness 源码结论

复核提交：[`cd5ef814`](https://github.com/deepseek-ai/DeepSeek-Harness/tree/cd5ef8148158c3a752a658978873241fdf8e2bbc)

| 源码位置 | 看到的约束 | Zeus 的处理 |
| --- | --- | --- |
| `packages/core/session/src/index.ts` | Session 是事件源。`append` 先提交事件，再通知观察者。模型消息由事件派生。 | `session_events` 保存模型可见历史。正文不从 Run 快照反推。 |
| `packages/core/session/src/repair.ts` | 崩溃恢复会为悬空 ToolCall 追加确定性的合成 ToolResult，并区分 `TOOL_NOT_STARTED` 与 `TOOL_OUTCOME_UNKNOWN`。 | Zeus 保留“未开始”和“结果未知”两个失败语义。只有前者可按策略重试；后者先查外部状态或交给人工。 |
| `packages/core/agent-loop/src/agent.ts` | Loop 明确记录 turn/step 边界；每次模型请求都从 Session Log 重建。 | `zeus-core` 负责状态规则；Runtime 从持久事件构造上下文。进程内对象不充当恢复依据。 |
| `packages/core/agent/src/inbox.ts` | `next-step` 和 `next-turn` 队列本身也写入 Session Event，重启后可投影恢复。 | steering 写入当前 Session，在工具边界消费；follow-up 持久化后创建后续 Run。 |
| `packages/core/agent-loop/src/tool-calls.ts` | Tool 可并行执行，但结果按模型调用顺序提交。取消会停止补充新调用，并给未开始的调用补合成结果。 | Tool Pipeline 可并发执行安全调用；Session Event 按 call 顺序收口。取消不能留下无结果调用。 |
| `vendor/cordis/src/service.ts`、`context.ts`、`fiber.ts` | 插件资源跟随 Context/Fiber 生命周期注册和释放。作用域负责清理监听器与副作用。 | Capability Adapter 使用显式 `start/stop` 生命周期和作用域资源，不把 Cordis 运行时移植进 Rust。 |

不采用的部分：

- `packages/shell/*`、本地文件系统、PTY、Code Runtime 和动态本机 Profile。
- 进程内 Session Store 作为系统事实源。
- 为迁就 TypeScript 包边界而拆分 Rust crate。

## Pi 源码结论

复核提交：[`6c87d9a0`](https://github.com/earendil-works/pi/tree/6c87d9a026677b601e8278030dcf1ad97fe0bd86)

| 源码位置 | 看到的约束 | Zeus 的处理 |
| --- | --- | --- |
| `packages/agent/src/agent-loop.ts` | 模型流、Tool 批次、steering 和 follow-up 分层。steering 在下一次模型调用前注入；follow-up 在 Agent 原本将停止时进入外层循环。 | 保留两种队列语义。Zeus 的 follow-up 创建新 Run，便于独立租约、审计和预算。 |
| `packages/agent/src/agent.ts` | steering/follow-up 各有队列与 `all`、`one-at-a-time` 消费模式。 | 初版固定单条有序消费。确有批处理需求后再开放模式配置。 |
| `packages/coding-agent/src/core/usage-totals.ts` | prompt、completion、cache read、cache write 和成本分别累计。 | `run_events` 与 usage ledger 分列记录 provider 原始用量，不只保存 total token。 |
| `packages/agent/docs/harness.md` | 新 Harness 规范使用 write-once Entry、可变 Register、append-only Usage，外部副作用明确不承诺 exactly-once。 | Zeus 用 Session Event、Run 状态和 ToolCall/Intent 分开承载这些职责；外部调用依赖幂等键与结果对账。 |
| `packages/agent/src/harness/reducer.ts` | Reducer 会拒绝重复工具调用、非连续 Attempt、结果 ID 冲突和不完整 Deferred Handle。 | 把这些条件写成 `zeus-core` 状态不变量和数据库约束，恢复时拒绝矛盾记录。 |
| `packages/agent/src/harness/agent-harness.ts` | API 面已经定义，`prompt`、`resume`、`steer`、`followUp`、hooks、events 等关键路径仍抛 `HarnessNotImplemented`。 | 只把文档与类型当设计输入。Zeus 的 OpenAPI 占位端点明确返回 `501`，实现完成前不标成可用。 |

不采用的部分：

- 面向单机 Coding Agent 的 shell、文件修改和本地 Session 后端。
- Session 单写进程假设。Zeus 使用 PostgreSQL lease 和 fence 支持多个 API 副本。
- Pi Harness 文档里尚未落地的接口行为。

## Rauthy 源码结论

复核提交：[`e2367289`](https://github.com/sebadob/rauthy/tree/e2367289847e0db252eb3f5aa1a2ceee87deb3e3)

| 源码位置 | 看到的约束 | Zeus 的处理 |
| --- | --- | --- |
| `src/api_types/src/sessions.rs`、`src/middlewares/src/principal.rs`、`csrf_protection.rs` | Session 有显式状态、过期时间和最后活动时间。Cookie 请求经过 CSRF 与浏览器安全头检查。 | `web_sessions` 保存认证方法、空闲/绝对过期和 CSRF 摘要。Cookie 写请求同时校验 Origin、双提交 CSRF 和数据库摘要。 |
| `src/common/src/password_hasher.rs`、`src/bin/src/init_static_vars.rs` | Argon2 工作通过有界 channel 限制并发，避免哈希请求把内存吃满。 | `zeus-identity::PasswordExecutor` 固定最多四个活跃哈希，并设置有界等待队列。队列满返回 `429`。 |
| `src/service/src/oidc/auth_providers/login_finish.rs`、`src/data/src/entity/auth_providers.rs` | 普通联合登录和账号绑定走不同分支。未绑定的同邮箱账号默认拒绝，显式 link cookie 才允许绑定。 | Zeus 返回 `account_link_required`。用户登录后创建短期绑定意图。邮箱相同不会触发自动合并。 |
| `src/service/src/oidc/validation.rs`、`src/data/src/entity/refresh_tokens.rs` | Refresh Token 在签发替代 Token 前原子 claim。重放触发同组 Token 撤销。 | Zeus 用 PostgreSQL 单次 claim Refresh Token，并按 `family_id` 撤销整个 Family。 |
| `src/data/src/entity/jwk.rs`、`src/schedulers/src/jwks.rs` | 私钥加密入库。轮换后继续发布旧公钥，再按保留期清理。 | Zeus 存储 envelope-encrypted 3072-bit RSA 私钥。新密钥接管签名，旧公钥保留七天。 |
| `src/data/src/entity/email_jobs.rs`、`src/schedulers/src/email_jobs.rs` | 邮件任务保存进度。调度器可以找回超时或中断的任务。 | `email_outbox` 使用 lease、fence、attempt 和可用时间。API 副本中断后，其他 `IdentityMaintenance` 可继续投递。 |

不采用的部分：

- `users.auth_provider_id` 和 `users.federation_uid` 的单上游绑定结构。Zeus 使用独立的多值 `federated_identities`。
- Hiqlite、cache-first 查询路径和 Rauthy 的数据库抽象。
- Password Grant、Device Flow、动态 Client 注册、SCIM 和 Rauthy 扩展协议。
- 将上游 Group 或全局角色直接映射成租户授权。
- Rauthy 的源码、crate、内部 API、迁移和前端组件。

## 采用的方向

- Agent 运行分成 Run、Turn、Step 和 ToolCall。
- Session Event 是模型历史、界面时间线和回放的事实源。
- 模型可见的消息和工具事件必须写入 append-only Session Event。
- Capability 有明确的 schema、scope、策略、租户和审计信息。
- 外部副作用先创建唯一 ExecutionIntent，再处理 lease、发送和结果。
- 业务状态、执行事实和派生视图分开。派生视图可以重建。
- 版本进入 Run 后固定。新配置只影响新 Run。
- 租户边界来自认证上下文。请求正文不能扩大权限。

## 映射到 Zeus 0.1.0

| 参考约束 | Zeus 落点 | 当前状态 |
| --- | --- | --- |
| append-only Session | `session_events`、append-only trigger、`validate_tool_pairs` | Schema 和纯函数已实现；Runtime 写入链待实现。 |
| ToolCall 必须闭合 | `tool_calls`、Session ToolResult、取消合成结果 | Schema 和配对校验已实现；取消路径待实现。 |
| steering/follow-up 分流 | Session Inbox Event 与后续 Run | 领域语义已固定；API 和 Runtime 待实现。 |
| usage 分项记账 | `run_events` 与 provider usage payload | Schema 已具备；模型适配器待实现。 |
| 生命周期清理 | API shutdown token、Supervisor drain、Capability lifecycle | Supervisor 最多等待 60 秒；Capability lifecycle 待实现。 |
| 可恢复执行 | PostgreSQL claim、lease、fence、attempt | SQL 函数和 Supervisor 骨架已实现；心跳和故障注入待实现。 |

这些方向来自 0.1.0 计划，也参考了上表的固定提交。参考不等于复制。

## Zeus 的明确边界

- `apps/zeus-api` 负责 HTTP、数据库、OIDC、模型、Capability、调度和运行时 IO。
- `crates/zeus-core` 只放无 IO 的领域类型、状态机和策略。
- `ExecutionSupervisor` 运行在 `zeus-api` 内，不创建 `zeus-worker`。
- 本地 shell/fs/profile 不进入 Zeus。Zeus 不提供任意 shell、用户代码执行或服务器文件系统工具。
- 当前不使用 Redis、NATS、PGMQ 扩展、pgvector 或对象存储。
- Windmill 混合许可证只学习不复制。Zeus 不复制其实现。
- Pi 部分接口 HarnessNotImplemented，不得被文档或适配层伪装成已实现接口。

## 不把研究写成承诺

源码阅读只能说明设计参考，不能说明 Zeus 已实现或已通过验收。
实现前仍要验证跨租户、提示注入、Capability 越权、密钥处理、lease、Webhook、审计和资源上限。
没有测试、运行或故障注入证据时，标记为“未验证”。
