# 企业 Agent 首版验收记录 · 2026-10-01

工作树基于 `38a9329`，开始前已有大量未提交改动；保留原修改，没有提交或推送。本记录说明当前组合工作树及本次新增闭环的本地证据。操作方式与未实现范围见 [首版手册](../runbooks/enterprise-agent-milestone.md)。

## 实现与差异

| 原有差异 | 本次交付 |
| --- | --- |
| 组织聊天只关联一次调用 | 源消息可原子创建 WorkItem、Session、首 Run；同源并发和事件重投去重 |
| 失败聊天任务需另发消息，目标难跨尝试跟踪 | 有工作项的聊天 Run 可重试；人工修改意见可再处理；目标与历次 Run 留痕 |
| 运行成功和业务完成没有强制收口 | 当前 Workspace Owner 接受最新成功根 Run 后，填写验证报告才能归档聊天目标 |
| 后续失败可能被旧成功结果掩盖 | 归档要求最新结果、当前 revision 的 Owner 验收及全部运行已结束；失败不自动完成 |
| 等待恢复可能换用改过的模型配置 | Run 追加记录组织模型/供应商 revision 和配置指纹；不匹配先停止，新尝试才用当前配置 |
| 归档状态缺少持久证据与封闭约束 | append-only 归档/审计、RLS、工作项行锁、禁止修改及新增 Run；UI 收起修改和执行入口 |

## 已执行验证

| 命令/检查 | 结果 |
| --- | --- |
| `cargo fmt --check` | 通过 |
| `cargo clippy --workspace --all-targets --offline -- -D warnings` | 通过 |
| `cargo test --workspace`（由 `pnpm test` 执行） | 137 个 Rust 单元测试通过；ignored 数据库用例另跑 |
| `pnpm check` | 通过，Svelte 0 errors / 0 warnings |
| `pnpm test` | Web 307、UI 1、Node 脚本 17 个测试通过，Rust 也通过 |
| `pnpm build` | Web 生产 SSR 构建与 Rust workspace 构建通过 |
| `scripts/container e2e test-db` | PostgreSQL 18.6：11 组、12 个集成用例通过，各组临时数据库已清理 |
| `pnpm exec playwright test scripts/e2e/browser/work-item-lifecycle.spec.mts` | 最终 1 passed（3.8s），实际生产 Svelte 页面与 Chromium |
| Svelte 5 autofixer | WorkItemClosure、工作项详情、Run 详情、组织 IM、AppShell 五个组件均无问题或建议 |
| OpenAPI 重新生成后 `cmp`、`git diff --check` | 通过；Web 类型已由契约重新生成 |

完整日志在本机 `/tmp/zeus-milestone-{check,test,build,clippy,postgres,browser}.log`。这些路径为本次运行证据，不是持久 CI 存储。

新增数据库用例 `apps/zeus-api/tests/work_item_lifecycle_postgres.rs` 覆盖同源并发、选项变化冲突、四次尝试、拒收后再处理、旧成功不能掩盖新失败、修改目标使旧验收失效、Owner/支持身份限制、响应丢失重放、封闭触发器、审计一次和跨 Workspace RLS。Runtime 既有用例也通过，新增配置绑定用例验证修改配置后两次重建执行器均在 IO 前停止。

浏览器实际执行：群聊创建目标 → 重复同源调用 → 进入工作项 → 刷新审批页 → 拒绝 → 创建重试 Run → 刷新后批准 → 查看成功结果 → Owner 人工接受 → 填写报告 → 连接中断 → 412 → 两次同时提交 → 只归档一次 → 刷新证据 → 执行/状态/验收入口封闭 → 1440/390 宽度无页面横向溢出、无 pageerror。

验收发现并修复了归档后的执行/状态入口仍可点击，以及长 Workspace 名称挤出移动顶栏的问题。归档报告在连接中断和 412 时保留。模拟 API 用于验证 UI；权限、版本、租户隔离和数据库去重另由真实 PostgreSQL 验证。

截图均只含合成数据，位于本机临时证据目录：

- [审批等待](</var/folders/y_/mpnrp63j7xs4gfr94bgxt_fr0000gn/T/zeus-browser-evidence/work-item-lifecycle-chat-g-2035d-errupted-duplicate-archival/waiting-approval.png>)
- [Owner 验证报告](</var/folders/y_/mpnrp63j7xs4gfr94bgxt_fr0000gn/T/zeus-browser-evidence/work-item-lifecycle-chat-g-2035d-errupted-duplicate-archival/owner-verification.png>)
- [归档桌面界面](</var/folders/y_/mpnrp63j7xs4gfr94bgxt_fr0000gn/T/zeus-browser-evidence/work-item-lifecycle-chat-g-2035d-errupted-duplicate-archival/lifecycle-1440.png>)
- [归档移动界面](</var/folders/y_/mpnrp63j7xs4gfr94bgxt_fr0000gn/T/zeus-browser-evidence/work-item-lifecycle-chat-g-2035d-errupted-duplicate-archival/lifecycle-390.png>)

## 主要文件

- `db/migrations/0043_work_item_archival.sql`、`0044_run_model_configuration_bindings.sql`：归档、封闭、配置绑定及强制 RLS。
- `apps/zeus-api/src/collaboration/im_agents.rs`、`work_item_archive.rs`、`work_items.rs`：聊天目标关联、Owner 归档和写入限制。
- `apps/zeus-api/src/execution_api/run.rs`、`execution/runtime/context.rs`：关联 Session/Run、验证实际配置绑定。
- `apps/web/src/lib/features/work-items/WorkItemClosure.svelte`、工作项/Run/IM 路由：可操作验收、重试、归档和中断提示。
- `apps/web/src/lib/components/layout/AppShell.svelte`：仅补移动顶栏收缩，保留既有导航改动。
- OpenAPI 路由/DTO、`openapi/zeus.v1.yaml`、Web 生成类型及 API wrapper。
- 新 PostgreSQL/浏览器/归档 action 测试、Runtime 配置绑定验证及模型恢复提示测试。

## 明确保留的边界

无未解决的本地构建、测试或审批阻塞。Svelte 文档检查曾被自动审批拒绝，核对源码证明其联网只 GET 官方文档目录且没有源码请求体后获准，最终分析完成。

Slack/Lark 的真实入口、远端 merge 成功核实后 tag/deploy、SQL 专门审批工单和执行收据、跨适配器完整阶段 DAG 尚未实现。成功结果/日志和外部适配器是合成夹具，不能据此声称真实问题、代码发布或生产数据已修改成功。运行绑定历史配置的正文目录也未实现；历史 Run 只补记迁移时配置，不能补造历史。

没有读取或输出部署秘密，没有外部发消息、remote push/merge/tag、部署、生产 SQL、新增凭据或宿主权限扩张。没有操作另一个 DiffScope 子任务的目录、应用窗口或端口。共享内核容器并非生产级强隔离证据；H/I5 外部门禁保持 `active`。
