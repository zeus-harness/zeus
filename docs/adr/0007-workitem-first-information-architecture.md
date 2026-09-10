# ADR 0007：WorkItem-first 信息架构与 Web 组件边界

状态：Accepted（J0 文档基线，Zeus `0.1.0`）

## Context

Workspace 同时展示 WorkItem、Run 和 Approval。用户需要从一条工作进入 Agent 执行、事件时间线和人工审批。当前 Web 已有 `/work-items`、`/work-items/{work_item_id}`、`/runs`、`/runs/{run_id}` 和 `/approvals` 路径。外部书签、通知链接和协作记录已经引用这些路径。

页面结构还要保持已有模块边界。`apps/web` 持有业务页面和 SvelteKit 服务端代码。`packages/ui` 持有共享视觉组件和 shadcn-svelte 基础组件。把业务状态放进共享包会扩大依赖面，把基础控件复制到业务目录会产生行为差异。

## Decision

### WorkItem-first 信息架构

- WorkItem 是 Workspace 工作入口。列表进入详情，详情启动 Agent，Run 详情展示执行事实，Approval 展示需要人工决定的动作。
- `/` 作为 Workspace 工作台，汇总 WorkItem 队列、活动 Run 和待审批项。它提供入口，不替代 WorkItem 详情。
- `/work-items` 是主要工作队列。`/work-items/{work_item_id}` 是状态、输入、附件、外部引用和 Agent 启动中心。
- `/runs`、`/runs/{run_id}` 和 `/approvals` 保留一级导航。它们服务于筛选、值班、审阅和直接链接；记录仍链接回 WorkItem。

### URL 兼容

- 保留 `/`、`/work-items`、`/work-items/{work_item_id}`、`/runs`、`/runs/{run_id}` 和 `/approvals`。
- 保留现有 `status`、`cursor` 查询参数。`/work-items?create=1` 打开创建 Sheet。新增 UI 不删除未知查询参数。
- Web URL 不增加 Workspace 段。当前 Workspace 继续来自 Session 和 Workspace context。
- 服务端 API 继续使用 `/api/v1` 和 `/api/v1/workspaces/{workspace_id}/...`。J0 不通过改路由或改 OpenAPI 表达信息架构。
- 页面移动、标题变化或导航排序不能使已有深链接失效。需要破坏兼容时，另开 ADR 并提供迁移与验证。

### 组件归属

- `apps/web` 保存路由页面、SvelteKit `load`/`action`、WorkItem/Run/Approval 业务组件、权限判断、API 编排和状态映射。
- `packages/ui` 保存跨业务复用的 Button、Card、Table、Badge、Separator 以及 shadcn-svelte 基础组件。组件固定在 `packages/ui/src/lib/components/ui`。
- `packages/ui` 不依赖 WorkItem、Run、Approval 领域规则。`apps/web` 不复制基础组件实现。
- 视觉基线由 `packages/ui` 导出。当前 shadcn-svelte 配置使用 `lyra`、neutral base color 和 Phosphor 图标，Web 不另建一套基础控件或 token。本 ADR 不创建品牌系统。

### 事实与交互边界

- WorkItem 更新使用 `revision` 和 `If-Match`。冲突保留用户草稿，读取最新版本后再合并。
- WorkItem 启动 Run 使用 `/api/v1/workspaces/{workspace_id}/work-items/{work_item_id}/runs`，带 `Idempotency-Key`。成功结果包含绑定 Session 和 queued Run。
- Run Timeline 读取持久化 Run Event、Session Event、Tool Call、Approval、usage、Experience 注入和 Child Run。SSE 通过 `Last-Event-ID` 续传，客户端按事件 ID 去重。
- Approval 通过现有 approve/reject POST 写入。服务端响应和追加事件决定 UI 状态。断线、重复决定和过期请求都不能触发盲目重放。
- J0 只固定文档和结构边界。J1-J4 的代码、测试、响应式和运行验收按实现计划推进。

## Consequences

- 用户从 WorkItem 看到目标、执行和审批的关联。Run 和 Approval 的值班入口仍可直接使用。
- 旧链接继续命中同一业务对象。信息架构调整不需要同时迁移浏览器书签和外部通知。
- 业务规则集中在 `apps/web`，共享包保持可复用。部分页面会保留少量业务编排代码。
- Run、Session Event 和 Approval 的服务端事实优先于客户端缓存。断线恢复需要快照、事件 ID 和去重处理。
- J0 文档完成不改变 H 或 I5 的门禁状态。外部 KMS、SMTP、真实企业 IdP、OpenID Conformance、生产 PostgreSQL 权限和生产规格压力数据仍需独立验收。
