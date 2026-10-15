# 多天流程与代码执行：现状、测试和设计边界

日期：2026-09-18。本文记录分阶段交付。0035 实现可复用 Workflow 的执行/等待时间策略；0036 增加受控仓库导入、Run 独立 worktree 和持久检查点；0037 接入受审批的 Alpine 脚本沙箱。文末前两阶段的验证记录保留其当时的边界。

## 0037：Alpine 隔离执行接入

`builtin.sandbox_exec` 接收 `{ "script": "…" }`。Workflow 新版本同时绑定已有 `code_repository` 和 `execution_environment: "sha256:<64 位小写十六进制>"`，Web 的代码仓库配置区可填写。定义可复用；每个 Run、每个租约 fence 使用独立 worktree，执行容器只收到普通文件副本，不挂载 API 代码卷或 `.git`。

执行器始终要求现有 Approval 人工批准，不能通过把 Capability 标记为 low risk、关闭 approval_required 或宣称支持幂等来跳过。执行前、执行中每两秒、接收结果后重新检查 Run 租约/fence、取消、业务期限、组织 active、Capability 启用/未归档、审批状态。等待审批时持久保存并释放 worktree 和执行槽位；恢复后从已确认检查点继续。脚本返回后先保存代码检查点，再保存工具结果。未知结果不会自动重跑。

隔离服务是 API 调用的执行适配器，无数据库、调度器或模型密钥。Apple container 使用专用 Linux VM，外层启动器只保留建立隔离所需的 SYS_ADMIN、SETUID、SETGID、CHOWN、DAC_READ_SEARCH；不能把该服务当普通宿主机进程运行。实际脚本以 UID/GID 10001、无 capabilities、no-new-privs 执行，使用独立 user/PID/network/mount/IPC/UTS/cgroup namespaces、只读 Alpine rootfs 和 seccomp。默认完全断网，不注入平台密钥。Git、Node/npm/pnpm、Python/pip、Rust/Cargo、C/C++ 编译工具已预装。

固定限制：每任务 1 CPU、512 MiB 内存、禁用 swap、128 PIDs；工作目录与 `/tmp` 共用 64 MiB tmpfs；输入/输出文件各最多 32 MiB、4096 项；日志 64 KiB；脚本 16 KiB；单次执行最多 300 秒，同时最多 2 个任务。API 每两秒续约，10 秒失联停止整个 cgroup；超时、取消、输出超限也停止整个进程树。退出后才采集文件，拒绝符号链接、硬链接和特殊文件。根 `.git` 不导出，平台 Git 元数据始终不可见。

### 本地启用

1. `scripts/container build sandbox` 构建镜像。宿主机从 Alpine 官方 HTTPS 源下载 APK 和索引，容器内 apk 解析依赖并验证包签名；没有关闭签名验证。包缓存位于被忽略的 `.zeus/sandbox-apk-cache`。
2. 在私有 `.zeus/local.env` 设置 `ZEUS_CODE_STORAGE_ENABLED=true`、`ZEUS_SANDBOX_ENABLED=true`。不要手工粘贴 token 到命令或聊天。
3. 构建匹配的 API/Web，使用 `scripts/container up api` 执行 bootstrap、迁移及启动。脚本生成并持久保存沙箱 token（0600），沙箱仅监听私有容器网络；启动输出显示可配置的镜像 digest。
4. `up api` 会同步更新已运行的 Web/网关；全新环境统一使用 `scripts/container up all`，无需逐个重复启动依赖。日常环境为 3000，E2E 独立使用 3100。
5. 打开 Workspace 设置 → 工具，点击“启用隔离脚本”。首次注册要求 Organization Owner，Workspace 启用仍单独验证 Owner 权限；强制审批无法在此关闭。随后在 Workflow 工具列表选中它，绑定已导入仓库/commit 和刚才的 digest，保存发布新版本。默认工具 timeout 为 60 秒；API 配置可提高到 300 秒。对应工具定义为 executor_key=`builtin.sandbox_exec`，输入 Schema 如下。


```json
{"type":"object","properties":{"script":{"type":"string","minLength":1,"maxLength":16384}},"required":["script"],"additionalProperties":false}
```

代码和作业防重记录分别保存在 `zeus-local-code`、`zeus-local-sandbox-state` 命名卷；E2E 使用独立前缀。删除作业防重卷会丢失历史拒绝重跑记录，不能将清空它作为重试方式。镜像 digest 不匹配时执行失败；当前只运行一个环境版本，升级镜像后旧 Workflow 不会静默切换，需保留旧环境或发布新版本。`toolchain-packages.txt` 记录具体软件包版本。

### 可重复验证

- `PYTHONDONTWRITEBYTECODE=1 python3 apps/zeus-api/sandbox/test_broker.py`：路径、文件类型、重复输入和镜像绑定边界。
- `scripts/container e2e test-sandbox`：专用 Linux VM 的 11 项实际执行测试，覆盖工具链、文件回传、非 root/只读/断网/seccomp、资源耗尽、失联/超时/取消、并发目录隔离、输出限制、重复执行拒绝和任务资源清理。需要先构建 sandbox 镜像；测试临时开放回环 18090，结束删除测试容器，保留防重状态卷。
- `scripts/container e2e test-db`：独立 PostgreSQL 下待审批不调用适配器，批准后恢复执行，工具结果和文件检查点持久化，再次创建 worktree 可读到修改。适配器响应在此测试中是确定性 fixture；真实 Linux 隔离由上一项单独验证。
- `pnpm check`、`pnpm test`、`pnpm build`、`cargo fmt --check`、`cargo clippy --workspace --all-targets -- -D warnings`。

2026-09-18 本地结果：Web 245 项、Rust 135 项单元测试、9 组隔离 PostgreSQL 目标、4 项适配器边界测试及 11 项真实 Linux 测试通过；类型检查、构建、Clippy、fmt 和 Svelte autofixer 通过。Linux 测试结束无遗留任务目录或 cgroups。

3000 已更新 API/Web、应用 0037、启用私网沙箱和持久状态卷，`/health/ready` 返回 ready。使用已授权账号登录/MFA 后，在默认验收 Workspace 的工具页完成“启用隔离脚本”，列表显示 enabled=true、approval_required=true。当前 Workspace 尚无模型和已发布 Agent，未宣称完成真实模型脚本流程。启动就绪探测通过私网 HTTP 进行，避免 container exec 与 cgroups 初始化竞争；已有代码卷直接复用，避免重复挂载正在使用的虚拟磁盘。

### 当前边界

- 当前为本地受控脚本接入，尚不提供私有仓库凭据、联网安装依赖、密钥注入、推送/发布或多环境调度；离线脚本需使用预装工具及仓库已有依赖。Alpine 使用 musl，不能保证所有 glibc 二进制兼容。
- 超时/取消/失联的输出文件不回传，保持此前已确认检查点；执行中断后的同一 tool call 不重跑。进程本身不做内存快照。
- 返回给模型的脚本输出有体积限制，但不会自动识别用户仓库中的所有秘密。不要把真实密钥或敏感客户数据导入代码仓库。
- 后端 HTTP 使用专用网络和 token；跨主机部署还需 TLS、访问控制、配额/状态卷保留策略、镜像供应链管理和独立安全验收。当前并非任意公网多租户代码执行服务。
- 真实 72 小时 soak、整机重启、完整权限撤销组合及生产攻击面验收仍未完成。

## 0035/0036 阶段结论（历史记录）

- 单次 Run 的执行预算上限仍为 86400 秒。新建 Workflow 版本默认采用 active 时间策略，允许跨天等待，默认单次等待 7 天、流程总期限 30 天；旧版本继续采用原墙钟时间语义。
- `RunPlan::remaining_runtime` 对新策略读取 Run 的累计执行毫秒数与当前执行段；等待审批/子任务及排队不消耗执行预算。租约中断最多计入原租约到期时间，接管后重新开始执行段。旧版本仍从首次 `started_at` 计算墙钟时间。
- Supervisor 通过 PostgreSQL 租约、心跳和 fence 防止过期执行者提交结果。浏览器 SSE 只是观察通道，不拥有执行生命周期。
- 领取条件包括 queued 和租约过期的 running；等待不占用执行槽位。Supervisor 每 5 秒运行有界的期限维护，超期等待/业务期限通过已有取消路径收尾并级联子 Run；运行中的任务接收取消请求，失联执行者租约到期后由维护恢复取消。审批决定接口也检查期限，不能利用维护间隔批准过期操作。
- 工具配置单次调用最多 3600 秒。普通本地执行器只实现 builtin.echo 和 builtin.work_item_read，子 Run 另有处理路径。Git 仅供部署管理员登记来源和 Runtime 内部检查点使用；没有任意 shell、用户代码或服务器文件系统工具。
- 已处于 running 且没有幂等键的工具恢复时会报告 capability_outcome_unknown；这保护了重复副作用边界，但并不构成外部脚本 exactly-once 保证。
- 会话上下文目前读取整个 Session 事件历史；Trace 查询也有固定数量上限。多天日志、工具输出和模型上下文需要分页、摘要和体积预算，不能无限追加到每轮提示中。

代码依据：`apps/zeus-api/src/execution/runtime/{types,context,tools,execution}.rs`、`apps/zeus-api/src/execution/supervisor.rs`、`apps/zeus-api/src/control_plane/{agents,integrations}.rs`、`db/migrations/{0002_control_plane,0017_child_runs,0029_tenant_state_execution_guard}.sql`。

## 0035：可复用版本与独立 Run

- Workflow 版本保存 `time_policy`：`runtime_clock=active`、`wait_timeout_seconds`、`business_timeout_seconds`。后两项为 1..31536000 的整数。Web 配置页可设置，版本列表区分旧版总时限和新版执行预算。
- 创建 Run 时从同租户 Workflow 版本复制策略并计算总截止时间；重试接管与审批恢复不会修改模板、重置预算或刷新期限。用户主动创建新的重试 Run 仍是独立运行，拥有新期限。
- 数据库触发器统一累计运行段，在等待时清空执行段，固定 Run 的策略快照。审批、结束执行和过期维护按 Run → Approval 的顺序加锁。快速审批不会丢失唤醒。
- 超期取消追加 `run.deadline_exceeded`，原因为 `wait_timeout` 或 `business_deadline_exceeded`；工具结果和子任务使用现有取消收尾。维护发现到期后通过取消路径收尾；执行器先检测到总期限时返回 failed / business_deadline_exceeded，执行预算耗尽为 failed / run_timeout。
- Run API/详情页展示 `deadline_at` 和 `wait_expires_at`。截止时间是 UTC RFC3339。
- 回归包含旧版三天后超时、新版三天日历跨度保留执行预算、同一版本多个独立 Run、等待释放租约、恢复保持累计预算、快速审批、重复收尾及取消后执行节点失联。
- 这些仍是加速时间和确定性测试，未执行真实 72 小时耐久运行。当前持久检查点仍为模型/工具事件；没有文件系统快照或任意脚本恢复能力。

升级时先构建匹配的 API/Web，停止旧 API，使用 migration owner 执行 0035，再启动新 API/Web。新 API 依赖新列和维护函数，不能先启动新 API 后迁移。不要改写已发布版本来启用新时间语义，应保存并发布新版本；已有 Run 保持原语义。

后续阶段仍按“代码环境与检查点 → 隔离作业后端 → 会话中的作业/审批 → 故障注入与耐久运行”推进；本次不改变 AGENTS.md 对宿主机 shell 和用户代码执行的禁止。

## 本轮可重复验证

`apps/zeus-api/tests/runtime_postgres.rs` 新增加速场景，复用真实 PostgreSQL 和确定性本地模型服务：

1. 原运行完成，新增首次启动时间在三天前的 Run。
2. 旧节点领取，模拟租约已过期三天；新节点重新领取。
3. 断言 attempt 与 fence 增加，旧节点心跳与完成提交均被拒绝。
4. 用新节点执行器恢复，断言得到 run_timeout，首次启动时间未重置。
5. 新节点提交超时，数据库最终状态为 failed / run_timeout。

`control_plane/agents.rs` 中的配置校验测试增加 24 小时可接受、3 天被拒绝的边界。

运行方式：`scripts/container e2e test-db`。每组用独立临时库，自动清理；不得把日常 API 指向这些库。另运行 `cargo test -p zeus-api workflow_limits_are_rejected_before_database_work` 和 `cargo fmt --check`。

本轮结果：9 组隔离 PostgreSQL 测试目标全部通过，临时库已清理；24 小时/3 天配置边界测试、`cargo fmt --check` 、workspace 全目标 Clippy（`-D warnings`）以及 `cargo test --workspace` 均通过。

这是时间戳前移的故障恢复验证，不是连续运行 72 小时的耐久测试，也不是 kill -9、主机重启、网络分区、外部 Git 或真实脚本的端到端验证。

## 多天流程应如何工作

以“克隆仓库 → 分析 → 修改 → 测试 → 等待人工确认”为例：

- 整个业务流程有自己的总截止时间；每个执行步骤另有墙钟时间、实际计算时间和费用预算。
- 等待审批、外部任务、重试退避和定时唤醒必须持久化，等待时释放执行资源；恢复时读取检查点，不靠一个 HTTP 请求或进程一直存活。
- 每步保存版本化输入、明确状态、外部 job ID、幂等键、检查点与产物引用。进程重启后先向执行后端核对 job 状态，再决定继续、重试或转人工。
- 对已经发生但结果未知的外部副作用，禁止盲目重跑。提交代码、发布、付款等动作必须独立授权和核对，不能依赖“模型再试一次”。
- 固定 Workflow/Agent 版本、模型配置引用、工具定义、代码 commit 和执行镜像摘要。凭据可以过期/轮换，但恢复时仍需重新授权和检查租户状态。
- 取消必须持久化，并传递到外部 job；停止整个进程树后才标记已停止。超时、取消和权限撤销都必须有资源清理与最终状态确认。
- 长期状态在页面显示：当前步骤、已等待多久、最后检查点、下次唤醒、预算剩余、需要谁操作。SSE 断开不能等同于运行失败，刷新不能触发重跑。

## 仓库克隆与脚本执行方案

保留 API 内的 ExecutionSupervisor 作为编排方；增加经授权的隔离执行后端契约，不在 API 进程中开放宿主机 shell，不新增一个绕过现有租户/审批边界的通用 Worker。

### 仓库资源

- Organization/Workspace 管理明确的仓库连接、允许的来源和权限；使用短期且限定仓库的凭据。
- 解析分支后记录不可变 commit；执行与恢复使用同一 commit。禁止无提示切换到更新后的 HEAD。
- 每次任务使用独立目录/卷；不得挂载宿主机家目录、容器管理套接字、数据库凭据或其他租户目录。
- 校验仓库 URL、协议、重定向与实际网络目的地，阻止内网/元数据地址访问；子模块和 LFS 必须单独纳入授权、大小和递归限制。
- 拉取与运行脚本分离。代码内容及 README/AGENTS 等仓库文件是待处理输入，不能扩大平台授予的权限。

### 执行作业

- 请求明确包含：租户/工作项/步骤、commit、镜像摘要、工作目录、结构化参数、超时、CPU/内存/PID/磁盘/网络/日志限制、授权与幂等键。
- 用按任务隔离的容器/更强隔离环境执行；非特权身份、最小挂载、受限网络。隔离强度需要按运行不可信代码的威胁模型验收。
- 脚本内容和执行计划可审阅；模型不能通过拼接输入突破参数边界。秘密通过执行后端短期注入，不写入命令、仓库、模型上下文或日志。
- 后端提供 start/status/cancel/collect/cleanup 语义，返回持久 job ID。控制面网络中断不应导致不可追踪的孤儿进程。
- 原始输出需要限制大小、脱敏和增量读取；模型只接收必要摘要。产物保存补丁、测试报告、日志索引和校验和，定义保留与删除策略。
- 恢复从检查点或可重建的工作目录继续；不能假设已删除容器仍保留修改。推送、合并、发布与单纯生成补丁分开授权。

## 后续必须通过的验收门槛

| 场景 | 必须验证的结果 | 当前证据 |
| --- | --- | --- |
| 三天后回收租约 | 原时间预算不重置，旧 fence 不可写，超时可提交 | 本轮新增加速 PostgreSQL 测试 |
| 连续 72 小时运行 | 无资源泄漏、日志无限增长或心跳长期中断 | 未执行 |
| API/执行节点被 kill、滚动发布 | 接管且不重复产生副作用 | 未执行真实进程故障注入 |
| PostgreSQL/执行后端网络分区 | 旧执行者停止，新节点核对外部 job 后恢复 | 未执行 |
| 等待审批 48 小时 | 到期、批准、拒绝、撤销权限均有确定终态 | 已有预算保持、期限与自动收尾的加速验证；真实 48 小时及权限撤销组合仍待验收 |
| 重复通知/重复 start | 不重复执行同一副作用 | Git/脚本后端未实现 |
| 恶意仓库/脚本 | 隔离跨租户、内网、凭据、子进程、磁盘耗尽与日志攻击 | 未实现与未测试 |
| 取消长脚本 | 整个进程树停止，外部 job 可确认，产物策略明确 | 未实现与未测试 |
| 执行中凭据过期/组织暂停 | 停止或转人工，无越权恢复 | 执行后端场景未测试 |
| 百万事件与大型产物 | 页面分页、断线续读、上下文预算有效 | 未执行规模验收 |

实施进度：0035 已交付执行/等待时间语义和事件恢复；0036 增加代码目录检查点；接下来实现仓库连接管理和隔离作业契约，再接入受审阅脚本，最后做故障注入和 72 小时 soak。执行预算上限仍为 86400 秒。


## 0036：受控仓库与代码检查点

Workflow 版本可选保存 `code_repository: {repository_id, commit}`。commit 必须是完整的 40 位小写 SHA-1；不接受分支。每次 Run 和租约 fence 都使用新的 detached worktree；等待审批/子任务或完成前，先保存 Git commit 和仅追加的数据库检查点，再移除该工作目录。恢复读取本 Run 的最新检查点，不修改 Workflow 模板。Trace 返回最近 100 条记录，运行详情默认折叠展示。

部署管理员在受信任环境使用 `zeus-api import-code-repository --root /var/lib/zeus-code --organization-id <ORG_UUID> --workspace-id <WORKSPACE_UUID> --repository-id <REPOSITORY_UUID> --source <ABSOLUTE_LOCAL_REPOSITORY_OR_HTTPS_URL>` 登记仓库。CLI 不验证数据库成员关系，必须仅由已授权部署管理员调用。HTTPS 不支持 URL 内凭据、query、fragment、重定向或交互认证；此入口不向 Web/模型开放。私有仓库凭据管理另行实现。

服务设置 `ZEUS_CODE_STORAGE_ROOT` 为持久目录；必须与导入使用同一个存储，目录仅运行用户可访问。Apple container 可在 `.zeus/local.env` 设置 `ZEUS_CODE_STORAGE_ENABLED=true` 后通过 `scripts/container up api` 启用；使用独立 `zeus-local-code` 命名卷（E2E 为 `zeus-e2e-code`），重建 API 和 reset-db 均不删除代码卷。导入在相同卷中以 UID 10001 运行 CLI。备份必须同时包含 PostgreSQL 和代码卷；多节点必须共享该持久目录，否则缺失仓库的节点会拒绝执行。

当前约束：

- worktree 只隔离代码目录，不是安全沙箱；尚无读写代码或执行脚本的模型工具，不把 `.git` 或共享仓库暴露给不可信脚本。
- 单个展开版本/检查点最多 32 MiB、4096 项，拒绝符号链接和子模块；不自动获取 LFS。Git add 遵守忽略规则，忽略的构建产物不在检查点中。
- Git 子进程使用固定参数、清空继承环境、禁用 hooks/交互凭据，并限制时间与输出；取消时终止其进程组。
- 受信任管理员导入尚无 Git pack 大小配额和网络目的地防护，不可作为公共用户仓库导入 API。
- 失败、强杀、超时的执行目录及未提交数据库的 Git checkpoint refs 可能保留；自动回收和全卷配额尚未实现。正常挂起释放进程/执行槽位/工作目录，数据库和持久 Git 状态仍占用存储。
- Git 与 PostgreSQL 不是一个事务；只有数据库确认的检查点可用于恢复。过期 fence、取消或失效租约无法写入检查点。

验证包含独立 Run 文件隔离、删除工作目录后恢复、符号链接/大文件/元数据重定向拒绝、取消进程组，以及 PostgreSQL 下执行器保存与恢复、旧 fence/失效租约拒绝和检查点不可修改。仍不是真实脚本隔离、主机故障或 72 小时耐久验收。


本阶段本地验证：`pnpm check`、`pnpm test`、`pnpm build`、`cargo fmt --check`、`cargo clippy --workspace --all-targets -- -D warnings` 通过；Web 240 项、Rust 132 项单元测试通过；9 组独立 PostgreSQL 测试目标通过，含检查点 RLS/租约/恢复断言，临时数据库已清理。两处 Svelte 组件 autofixer 无问题。

3000 本地部署已应用本阶段迁移并启用 `zeus-local-code` 持久卷（0700，UID/GID 10001），API/Web 镜像已更新，`/health/ready` 返回 ready，登录后的 Workflow 页面可正常访问。最终 Linux 镜像已用仅含测试 README 的临时仓库完成 CLI 导入，测试容器/仓库已清理。当前测试 Workspace 无可用模型及已发布 Agent，本次未进行真实模型全流程。为避免本机构建容器内的软件源 DNS 依赖，本地 API 运行基础镜像改为官方 `buildpack-deps:bookworm-scm`，其中预装 Git/procps；这增加了本地镜像体积。
