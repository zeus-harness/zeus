# Zeus 0.1.0 威胁模型

## 范围

本模型覆盖 Zeus 0.1.0 的 Web/API、OIDC 身份、PostgreSQL、Agent Runtime、Capability、Webhook 和审计事件。
`zeus-api` 是主要运行边界。`zeus-core` 不做 IO。

本版本不提供任意 shell、用户代码执行或服务器文件系统工具。本地 shell/fs/profile 不属于信任边界，也不应成为可调用 Capability。

## 资产和信任边界

资产包括：

- Organization、Workspace、成员、Agent、Session、Run 和业务数据。
- Prompt、模型输出、Tool 输入输出和审计元数据。
- SecretRef、短期凭据、Webhook 密钥和 Capability 授权。
- Session Event、执行意图、lease、审批和幂等记录。

主要边界如下：

```text
用户 / Webhook / 外部内容
          -> HTTP / OIDC / 签名验证
          -> zeus-api
          -> zeus-core 状态机与策略
          -> PostgreSQL RLS / append-only Event
          -> 模型、受控 Capability 或企业系统
```

攻击者可以是另一租户的用户、被攻破的 Agent 或模型、恶意 Webhook、过期 Worker、恶意 Capability，或试图复用连接和凭据的进程。

## 威胁与控制

| 威胁 | 攻击方式 | 0.1.0 控制 |
| --- | --- | --- |
| 跨租户 | 伪造 tenant、Organization、Workspace 或资源 ID；复用带残留上下文的连接。 | tenant 和资源 scope 只从认证上下文取得；请求正文不可信；租户表启用并强制 RLS；外键带租户边界；缺失或不匹配的上下文直接拒绝。 |
| 提示注入 | 日志、Webhook、经验或模型输出要求跳过策略、泄漏数据或调用高风险工具。 | 外部内容标成不可信；Experience 注入使用边界转义并记录实际版本；系统指令、策略和用户内容分开；模型文本不能授权；Tool schema、Capability、审批和输出检查在模型外执行。 |
| Capability 越权 | 模型或客户端改 resource、scope、SecretRef、工具参数或租户。 | Capability 使用显式 scope、版本、输入输出 Schema 和权限；外部 `$ref` 被拒绝；服务端重新解析资源和身份；高风险动作需要策略或审批；`zeus-core` 状态机拒绝越界转移。 |
| 密钥泄漏 | Secret 进入 Prompt、Event、日志、Trace、错误、响应或长期凭据。 | 只传 SecretRef；在 API 执行边界按需解析；原始密钥没有读取接口；日志、事件和错误做字段白名单与脱敏；凭据使用短期、最小范围。 |
| 过期 lease | 旧 Worker 在 lease 到期或被接管后继续写入或发送。 | claim 使用短事务和 `FOR UPDATE SKIP LOCKED`；每次写入检查 owner、lease expiry 和 fencing token；旧 token 拒绝；外部调用不放在数据库事务中；不确定结果进入对账或人工处理。 |
| Webhook 重放 | 重放合法请求，重复创建 WorkItem 或推进状态。 | 0.1.0 的 B/C/D 只开放 Webhook 配置，不开放公网 delivery 路由。E 开放入口前必须实现版本化 HMAC、时间窗、原始请求摘要和 delivery id 幂等。 |
| 审计篡改 | 修改、删除或伪造已发生的 Session Event 和状态事实。 | Event 只追加；sequence 和 event id 唯一且单调；应用路径禁止 UPDATE/DELETE；修正追加新事件；状态变更、actor、correlation 和 causation 都留痕；派生视图不能反写事实。 |
| Child Run 越权 | 子流程扩大 Token、运行时间、Capability 或审批权限；父进程重启后丢失等待关系。 | 子 Run 使用独立 Session 和持久关系；预算、Capability 和审批只能收窄；深度最多 8；父子唤醒、取消和结果配对由 PostgreSQL 事件恢复。 |
| 资源耗尽 | 大请求、大事件、无限分页、并发 Tool、Child Run、长模型调用或恶意重试占满服务。 | HTTP body 限制为 8MiB；附件限制为 5MiB/25MiB；限制页大小、Run 并发、Child 深度、Token、运行时间、模型重试和 claim 数量。租户级速率与存储配额仍需生产数据。 |

还要覆盖两类相关风险：

- 外部 Capability 的 SSRF、跨租户调用和凭据滥用。只允许声明过的目标、身份和网络出口。
- 通用 Kubernetes 清单仍允许未限定目的地的 TCP 443。生产 overlay 或 egress gateway 必须按 Provider、OIDC、KMS 和遥测目的地收窄。
- 发送后丢失结果。不能把 `UnknownOutcome` 当作失败重试，也不能伪造成功事件。

## 安全不变量

- 默认拒绝。显式授权才放行，显式拒绝优先。
- tenant、Organization、Workspace、actor 和 resource scope 不接受客户端自报。
- 状态变化先经过 `zeus-core`，再由 API 写入 PostgreSQL 和 Session Event。
- 模型不能改变 Capability、策略、审批、lease 或审计结果。
- Session Event 不原地修改。审计和模型历史不能从可变快照推断。
- Secret 不进入模型、日志、事件、错误链或客户端响应。
- 外部副作用必须有唯一 ExecutionIntent、幂等键和可解释的最终状态。

## 验证要求

合并前至少有以下负面测试：

- 两个 Organization 使用相同资源 ID 时互不可见。
- 恶意 Prompt、Webhook 字段和模型输出不能触发越权 Tool。
- 改写 Capability 参数、scope、SecretRef 或租户时无副作用。
- 过期 lease、旧 fencing token 和重复 claim 都不能写入或发送。
- 同一 Webhook delivery 重放不创建第二个 Case 或 Event。
- Event 的 UPDATE、DELETE、跳号和跨租户引用都失败。
- 大请求、高并发、长调用和恶意重试会被限流、超时或拒绝。

没有相应的测试和运行证据，不标记为已关闭。
