# 企业 Agent 工作流首版

## 2026-10-01 交付范围

保留现有 Rust 核心、组织/Workspace 权限、内嵌 Supervisor、隔离代码环境和 append-only 事件。此前组织群聊能调用 Agent，但目标只存在于源消息中；终态不等于问题解决，模型配置恢复时可能改变。本次补齐一个可操作、可验证的垂直切片：

`组织群消息 → 显式调用 Agent → 持久 WorkItem + 首 Run → 工具审批等待 → 拒绝/批准/恢复 → 新 Run 或按意见再处理 → Owner 接受最新结果 → 验证报告 → 归档`

已有调用、审批、租约释放和 fence 恢复机制继续使用。没有通过聊天连接或常驻沙箱保存等待状态。新增工作项记录目标，每个 Run 记录一次尝试，归档另有不可修改的人工证据记录。

## 操作与验收

1. 在 `/organizations/:organizationId/im` 的组织群添加当前 Workspace 已发布的 Agent，在一条人类消息下「交给 Agent」。勾选创建持久工作项并确认以本人 Workspace 权限执行、向群分享结果。
2. 展开「Agent 调用与审批」，进入运行或「跟踪工作项与验收」。工具请求由服务端判断真实决策者资格，聊天中的同意不授予权限。
3. 审批等待期间刷新页面或重建 Runtime，待审批仍保存在 PostgreSQL。拒绝保留失败记录；有关联目标的失败运行可创建一次幂等重试。重复点击同一来源的重试不会创建多份 Run。
4. 成功后核对输出、测试与具体业务证据。需要修改时保存 `needs_changes` 意见，再按意见重新处理，保留原成功结果和新尝试关联。
5. Workspace Owner 接受最新成功根 Run 的结果。改变目标会使旧验收失效，尚有未结束 Run、最新 Run 失败、旧结果或非 Owner 验收不能作为归档依据。
6. Owner 填写问题解决验证报告并确认目标达成，然后归档。归档与审计、结果写入在同一事务完成；报告包含所选 Run、验收、Workflow 版本、目标 revision、真实归档人和时间。归档后拒绝目标修改和新增 Run。普通既有工作项完成操作保留；聊天创建的目标必须经过验证归档。

网络中断不清空验证报告；相同验收/revision 的提交有稳定幂等 key，响应丢失可重放已完成结果。内容改变却沿用相同 key 会冲突。412 保留报告并要求核对更新状态。页面禁用并发提交，服务端独立去重和校验，不能依赖按钮实现授权。

## API 与迁移

- 调用请求可带 `create_work_item: true`，响应 `{ id, work_item_id }`；省略此参数维持旧行为。调用事务从数据库读取源消息，拒绝客户端替换正文、Actor、Workspace 或 Workflow。
- `GET /api/v1/workspaces/:workspaceId/work-items/:id/archive`：有权成员读取归档记录，尚未归档返回 404。
- `POST` 同一路径：`If-Match: "revision-N"`、`Idempotency-Key`、`{ review_id, resolution_summary }`，创建返回 201。真实当前 Workspace Owner 校验、租户 RLS、验收版本和最新根 Run 校验均在服务端执行；平台支持身份与服务账号不能归档。
- `0043_work_item_archival.sql` 增加封闭状态、强制 RLS 的追加归档记录，以及归档/新 Run 之间的工作项行锁。HTTP 与 Runtime 的插入均经过同一封闭检查。
- `0044_run_model_configuration_bindings.sql` 对每个 Run 保存组织模型、供应商 ID/revision 和有效配置 SHA-256；不保存密钥或原始配置。恢复时不匹配会在模型或工具 IO 前停止，重试新建绑定。当前配置不可用时不会悄悄回退到其他模型。模型管理仍归 Organization，Workspace 只引用已发布版本。

新库先 bootstrap 角色，再迁移；部署升级先停止旧 API/Supervisor，迁移成功后启动匹配版本。0044 对历史 Run 只能记录升级时的配置绑定，不能重建历史实际配置；这不是历史配置可复现性证明。后续如需持续保留每个历史模型配置正文，应建立专门的无密钥版本目录。

## 可执行验证

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
pnpm check
pnpm test
pnpm build
scripts/container e2e test-db
pnpm exec playwright test scripts/e2e/browser/work-item-lifecycle.spec.mts
```

PostgreSQL runner 为每组创建并删除独立临时数据库，先 bootstrap、后迁移，不把 API/Supervisor 指向测试库。`work_item_lifecycle_postgres.rs` 使用真实 HTTP handlers、zeus_http 和强制 RLS，外部成功结果显式模拟；覆盖并发同源调用、幂等冲突、多次 Run、失败不能归档、旧验收/目标变更、Owner/支持身份限制、封闭和跨 Workspace 隔离。`runtime_postgres.rs` 覆盖真实审批等待/拒绝/重新领取、租约/fence、未知副作用不重放、临时 Git 仓库与模拟沙箱，并验证配置改变在两次 Runtime 重建中均停止。

新增浏览器用真实生产 Svelte SSR、独立 Chromium 和本地模拟 API：聊天建目标 → 审批页面刷新 → 拒绝 → 重试 → 批准 → 接受 → 归档连接中断/412/重复提交 → 刷新核对证据，检查桌面与移动宽度。随机回环端口，不读取凭据，不接管其他应用窗口。此浏览器测试验证 UI，真实权限、状态机与去重由隔离 PostgreSQL 测试交叉验证。

## 尚未实现的完整业务链

- Slack/Lark webhook 签名校验、自然 @、事件重投收件箱和外部回复；当前入口是平台内组织群的显式调用。
- 远端 PR review/merge 成功证据、随后 tag/deploy 的步骤依赖与适配器。发送请求不构成成功证据；本次未推送、合并、打 tag 或部署。
- 独立 SQL 修改工单、具体脚本摘要/版本审批及事务执行后的验证收据。现有通用工具审批/未知结果停止机制不能代替 SQL/deploy 的业务去重协议，这些副作用仍未接入。
- 全量业务阶段 DAG 和跨适配器恢复/补偿。当前复用已有单个 Workflow 执行与 Run 状态机，不宣称完成整条代码到发布链路。
- 真实模型及生产形态多租户隔离验收。现有容器/本地沙箱抽象的边界未扩大，未给 Agent 宿主 root；共享内核不是生产级强隔离证明。H/I5 外部门禁继续 `active`，确定性模型和模拟结果不能关闭外部门禁。

DeepSeek Harness 参考仓库尚未由用户确认，本次没有猜测来源或据此重写工程。已有大量未提交修改保留；首版测试通过代表当前组合工作树可执行，不代表这些既有改动全属于本次交付。
