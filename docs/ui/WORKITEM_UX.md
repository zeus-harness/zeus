# WorkItem-first UX 基线

状态：J0 文档基线

版本：Zeus `0.1.0`

协议：`/api/v1`

本文件定义 Workspace 工作台、WorkItem 详情、Agent 启动、Run 时间线和审批的 Web 结构。线框图只表达信息层级与动作位置。J0 文档验收不代表 J1-J4、H 或 I5 已完成。

线框图：

- [Workspace 工作台](./workspace-workbench.svg)
- [WorkItem 详情与 Agent 启动](./workitem-detail-agent-launch.svg)
- [Run 时间线与审批](./run-timeline-approvals.svg)

## 信息架构与 URL

WorkItem 是 Workspace 内的工作入口。用户从列表进入详情，从详情启动 Run，从 Run 查看事件、工具调用和审批。Run 与 Approval 保留独立入口，服务筛选、值班和直接链接。

浏览器 URL 保持现有路径。当前 Workspace 由 Session 和 Workspace context 决定，浏览器路径不增加新的 Workspace 段。

| 页面 | URL | 交互约束 |
| --- | --- | --- |
| Workspace 工作台 | `/` | 汇总当前 Workspace 的 WorkItem、活动 Run 和待审批项。保留现有概览入口。 |
| WorkItem 列表 | `/work-items` | 保留 `status`、`cursor` 查询参数。`?create=1` 打开创建 Sheet。列表只显示 API 返回的记录。 |
| WorkItem 详情 | `/work-items/{work_item_id}` | 详情、状态更新、附件、外部引用和启动 Agent 都从这里进入。 |
| Run 列表 | `/runs` | 保留已有列表入口。支持从 WorkItem 回到相关 Run。 |
| Run 详情 | `/runs/{run_id}` | 显示 Timeline、Trace、Session Event、Tool Call、Usage 和 Approval。 |
| Approval 队列 | `/approvals` | 保留 `status` 筛选。每条审批链接回 Run 和 WorkItem。 |

页面继续调用 `/api/v1/workspaces/{workspace_id}/...`。不通过重命名路径或迁移旧链接表达 WorkItem-first。已有书签、邮件链接和表单返回地址保持可用。未知查询参数不被无故丢弃。

## 布局

布局以 `packages/ui` 的导出为准。当前组件使用 shadcn-svelte `lyra`、neutral token、Phosphor 图标和 JetBrains Mono 字体资源。状态不能只靠颜色表达。图标配文字和可访问名称。线框采用灰度，不定义品牌色、Logo 或新设计 token。

### 桌面

断点：`>= 1280px`。

- 顶部保留 Workspace 导航、当前 Workspace 和新建 WorkItem 动作。
- 工作台使用“WorkItem 队列 + Workspace 快捷动作”两列。队列占主要宽度，右侧显示活动 Run、待审批和刷新动作。
- WorkItem 详情使用“内容 + 动作栏”两列。标题、状态、描述、Input、Output、附件和外部引用在主列。状态更新和“启动 Agent”在动作栏。
- Run 详情使用“事件时间线 + 详情检查栏”两列。时间线按 `sequence` 展示持久化事件。检查栏显示当前工具调用、审批、usage 和关联 WorkItem。
- 表格保留标题、状态、负责人、更新时间等关键列。长 ID 使用可复制的等宽文本并允许换行。

### 平板

断点：`768px–1279px`。

- 顶部导航允许横向滚动。当前 Workspace 和主动作保持可见。
- 工作台、WorkItem 详情、Run 详情从两列切成上下两块。主内容先出现，筛选、动作栏和检查栏随后出现。
- Agent 启动面板使用右侧抽屉或居中面板。面板宽度不遮挡标题，关闭动作始终可见。
- 审批操作保持同一张卡片。批准和拒绝按钮不因换行而失去上下文。

### 移动

断点：`< 768px`。

- 使用单列布局。顶部导航横向滚动，页面不横向溢出。
- WorkItem 表格转换为可点击卡片。标题、状态、更新时间和待办标记保留；ID 放入详情。
- WorkItem 详情的“启动 Agent”作为主动作。启动面板全屏或底部抽屉显示，关闭后回到原滚动位置。
- Run Timeline 的事件卡片垂直排列。Tool Call、Approval、Session Event 使用折叠面板减少首屏高度。
- 审批按钮纵向排列并至少保留 `44px` 触控高度。固定动作栏不遮挡正文和键盘焦点。
- 输入区、错误说明和提交结果紧跟对应动作。旋转屏幕后保留草稿和当前事件位置。

## 主要动作

动作都显示当前对象、目标和结果。提交期间锁定重复点击。服务端响应是状态事实，UI 不先把失败动作标记为成功。

| 位置 | 动作 | 结果 |
| --- | --- | --- |
| 工作台 | 新建 WorkItem | 打开 `/work-items?create=1` 的创建 Sheet，提交后进入详情。创建请求带 `Idempotency-Key`。 |
| 工作台 | 筛选或打开 WorkItem | 只更新当前列表视图，打开 `/work-items/{work_item_id}`。保留 `status` 和 `cursor`。 |
| WorkItem 详情 | 更新状态或可变字段 | 发送当前 `revision`，使用 `If-Match`。成功后更新详情和 revision。 |
| WorkItem 详情 | 启动 Agent | 选择必需的 `workflow_id`，填写可选 `message` 和 `input`，调用 `start_work_item_run`。成功返回绑定 Session 和 queued Run，再打开 `/runs/{run_id}`。 |
| Run 详情 | 取消或重试 | 取消调用现有 cancel 动作。重试创建新的 Run。旧 Run 的事件保持可见。 |
| Run / Approval | 查看审批请求 | 展示 Capability、Tool Call、原因、脱敏输入、决定人和过期时间。链接回 WorkItem。 |
| Approval | 批准或拒绝 | 调用对应 approve/reject POST，可带 `reason`。收到服务端成功响应和事件后再更新状态。 |

启动 Agent 使用唯一的 `Idempotency-Key`。网络错误不能直接重复发送未知结果的非幂等请求。UI 提供“检查当前 Run”和“重试请求”两个分开的动作；重试前先读取服务端事实。

## 状态与反馈

每个页面都能表达以下状态。状态文本、可操作动作和当前对象同时出现。

| 状态 | 触发 | 页面反馈 | 后续动作 |
| --- | --- | --- | --- |
| 空 | API 成功但列表、Run 或审批没有记录 | 显示“当前没有 WorkItem”“当前没有 Run”或“没有待处理审批”。不填充 mock 数据。 | WorkItem 列表提供“创建 WorkItem”。Run 空状态回到 WorkItem。审批空状态提供刷新和筛选。 |
| 加载 | 首次读取、翻页、打开详情或恢复连接 | 保留标题和操作位置，使用与内容等高的骨架。表单草稿不清空。 | 读操作允许继续加载；同一动作只允许一个提交中请求。 |
| 失败 | API 返回 `application/problem+json`、解析失败或请求超时 | 显示稳定错误码可读文案和安全的 request id。隐藏 SQL、堆栈、Authorization、Cookie、模型密钥和连接密钥。 | GET 提供“重试”。写操作保留输入。未知结果先读取对象状态，不盲目重放。 |
| 断线 | Run SSE 关闭、网络切换或心跳超时 | Timeline 标为“连接断开”和“数据截至某事件”。已显示事件保留，未确认的事件不补猜。 | 提供“重新连接”。HTTP 仍可用时可读取详情；审批提交按 POST 响应判断，不依赖 SSE 乐观更新。 |
| 冲突 | WorkItem `revision` 过期、`If-Match` 不匹配或动作返回 `409` | 显示服务端最新版本、用户草稿和冲突字段。保持编辑内容，不覆盖其他人的更新。 | “读取最新版本”后由用户合并，再提交新的 revision。审批已被别人处理时显示处理人和当前状态。 |
| 无权限 | 未登录、Session 过期、Workspace 不可见或角色不能执行动作 | `401` 引导重新认证；`403` 显示当前动作需要的权限；`404` 不泄露对象存在性。隐藏或禁用无权按钮，并保留可读数据的安全范围。 | 重新认证、切换 Workspace 或联系 Workspace 管理员。禁止通过失败重试探测资源。 |

加载、失败和断线状态都不改变服务端事实。状态徽标同时显示文字。无障碍文本使用 `aria-live` 报告连接、提交和审批结果，焦点回到触发动作或错误说明。

## SSE 续传

Run 详情使用快照加事件流。SSE 只负责读取变化，审批和其他写操作继续走 HTTP POST。

1. 页面读取 `/api/v1/workspaces/{workspace_id}/runs/{run_id}` 和 `/trace`，建立可渲染快照。
2. 页面打开 `/api/v1/workspaces/{workspace_id}/runs/{run_id}/events/stream`。每次接受事件后记录服务端 `id` 和 `sequence`，不记录凭据。
3. 连接关闭后保留当前已接受的 `id`。重连请求带 `Last-Event-ID`，服务端从该事件之后续传。
4. 重放事件按 `id` 去重，并按 `sequence` 排序。重复事件不重复展示。sequence 出现缺口时暂停增量渲染，读取 `/events` 或 `/trace`，再合并快照。
5. 收到终态事件后保留完整 Timeline 和连接时间。页面可继续查看事件、usage 和审批，不持续重连。
6. 重连使用有界退避。用户可以手动重连。持续失败显示失败原因和“读取最新状态”动作。

恢复过程中不把旧状态写回服务端。SSE 事件、日志和前端错误信息不包含 Authorization、Cookie、原始密钥或完整 OIDC claims。

## 审批交互

审批卡片在 WorkItem 详情的 Run 区域、Run Timeline 和 `/approvals` 队列保持同一信息顺序：

1. 显示当前 Run、Tool Call、Capability、风险级别、请求原因、最小必要输入摘要、过期时间和需要的 Workspace 角色。
2. 用户点击“批准”或“拒绝”后打开确认区。确认区重复显示目标和动作，拒绝理由可选；高风险请求要求用户明确点击确认。
3. 提交时锁定两个按钮，显示提交中状态。按钮恢复由 HTTP 结果决定。
4. 批准调用 `/api/v1/workspaces/{workspace_id}/approvals/{approval_id}/approve`。拒绝调用对应 `/reject`。请求体可带 `reason`。
5. 收到成功响应后重新读取审批和 Run，或等待对应事件后合并。服务端事件落库前不显示“已批准”或“已拒绝”。
6. 收到 `409`、过期或已处理响应时，读取最新记录，显示处理结果，不再次提交。SSE 断线不改变这条规则。
7. 没有审批权限时显示请求摘要和当前状态，不显示可提交按钮。移动端按钮全宽排列，仍显示请求目标。

审批理由、Tool 输入和事件展示遵守脱敏策略。UI 不提供原始密钥读取入口。

## 组件边界与视觉约束

- 路由 load、form action、WorkItem/Run/Approval 业务卡片、状态映射和权限判断留在 `apps/web`。
- 通用 Button、Card、Table、Badge、Separator 和后续基础组件留在 `packages/ui/src/lib/components/ui`。
- `packages/ui` 的构建、导出、组件目录和 token 是 Web 的基础 UI 契约。当前配置使用 `lyra`、`neutral`、`phosphor` 和 JetBrains Mono 字体资源。不在 `apps/web` 复制基础组件，不在 `packages/ui` 放 WorkItem 业务规则。
- Web 继续使用 SvelteKit 5、Svelte 5 runes 和当前 Workspace SSR context。页面状态不存入模块全局变量。
- API 类型仍由 `openapi/zeus.v1.yaml` 生成到 `apps/web/src/lib/api`。本 J0 文档不改 Rust、TypeScript、Svelte、package、lock 或 OpenAPI 文件。

## J0 交付边界

J0 只交付信息架构、线框、交互规则和验收口径：

- 三张灰度 SVG 线框位于 `docs/ui/`。
- 本文件覆盖三种 viewport、主要动作、六类状态、SSE 续传和审批交互。
- WorkItem-first、URL 兼容和组件归属由 `docs/adr/0007-workitem-first-information-architecture.md` 固定。
- J1-J4 的实现与运行验收单独记录在 `docs/IMPLEMENTATION_PLAN.md`。H 与 I5 外部门禁继续保持 `active`。
