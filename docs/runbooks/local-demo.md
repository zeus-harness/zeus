# 本机首版演示

## 已启动的环境

入口为 `http://127.0.0.1:3100`。API/Web、Mailpit 和确定性模型只在 `zeus-e2e` 私有容器网络内访问，Gateway 只发布宿主机回环端口；数据库复用独立 E2E volume。日常 `3000` 环境没有重启、迁移或账号修改。

本轮完成当前源码的 API/Web/Gateway/模型夹具镜像构建，bootstrap 后迁移到 0044。真实 Rust API、PostgreSQL、Supervisor、模型夹具和浏览器共同通过一次「等待审批 → 批准 → 成功 → Owner 接受 → 验证报告 → 归档 → 刷新封闭状态」验收，不只是 HTTP readiness。

已有 E2E 模板使用旧版总耗时预算。新增独立 `[本地演示] 持久审批流程`，保留原 Echo-only 工具及审批策略，执行预算仍为 120 秒，审批等待/业务期限为 24 小时。旧版本没有改写，旧演示尝试取消留痕，新尝试仍关联同一目标。

当前待体验目标及运行 ID 保存在 `.zeus/demo-state.json`，只包含非敏感引用与期限，不包含密码、TOTP、Cookie 或 Token。

## 最短体验路径

1. 使用已打开的独立 Chromium 演示窗口。它复用现有 E2E 账号完成正常登录和 MFA，凭据不会显示或导出。
2. 刷新工作项页面，点击最新 Run 的「处理工具审批」或「查看时间线」，批准纯合成回显。
3. 查看运行结果，返回关联工作项，选择「接受结果」，填写验收原因并确认核对。
4. 在「验证与归档」填写仅针对演示流程的验证报告，确认目标达成后归档。

演示组织当前没有第二个人类成员，脚本不会为填充群聊而创建/邀请身份。因此当前体验从工作项开始；聊天入口与去重已有首版验收记录，群聊演示需已有合适成员后再配置。

## 重新进入与维护

在仓库根目录、已配置 Node 24.18.0/pnpm 10.33.0 的终端使用：

```bash
node scripts/e2e/demo.mjs open
scripts/container e2e status all
```

`open` 打开独立临时浏览器上下文，正常使用已有账号，不创建账号、密码、API Token 或其他长期凭据；不保存浏览器 storageState。关闭这个窗口会结束该浏览器启动器，容器服务继续运行。

待体验任务已结束或过期时，可重新准备合成目标并完成浏览器验证：

```bash
node scripts/e2e/demo.mjs verify
node scripts/e2e/demo.mjs open
```

`verify` 要求现有隔离账号、TOTP、模型供应商凭据和 Workflow 已存在；缺失会停止，不调用 Setup、不新增身份或凭据。仅核对 Secret metadata；通过正式 API 维护本地模型夹具地址、独立演示 Workflow 和合成工作项。模拟模型地址严格限定在现有 `192.168.64.*` E2E 网络，不调用真实模型。

服务由 Apple `container` 的 detached 容器保持，Mac 和 container 服务需保持运行。按需停止演示（保留 volume 和数据）：

```bash
scripts/container e2e down all
```

再次启动当前镜像用 `scripts/container e2e up all`。不要运行 reset-db；不需要更改日常账号、密码、MFA 或平台安全设置。

## 本轮证据与边界

- `/tmp/zeus-demo-build.log`：当前源码镜像构建。
- `/tmp/zeus-demo-start.log`：隔离服务启动、迁移及 readiness。
- `/tmp/zeus-demo-verify.log`：真实浏览器闭环成功及待体验链接。
- `/tmp/zeus-demo-refresh.log`：持久审批版本、新 Run 与等待期限。
- `/tmp/zeus-demo-browser/actual-waiting-approval.png`、`actual-archived.png`、`actual-user-ready.png`：仅含合成数据的页面证据。

环境短暂断连时启动和验证实际已完成；通过日志、状态文件、容器健康和进程检查确认，没有重复执行不确定结果的调用。现有日常服务及 DiffScope 没有被操作。

没有公网部署、源码转移、新购资源、外部群消息、remote push/merge/tag、真实部署或生产 SQL。演示结果证明平台链路可操作，不能代替真实模型、业务修复、远端发布或生产隔离验收。H/I5 继续保持 `active`。

界面简化复验：`node scripts/e2e/demo.mjs ui`。此模式复用现有隔离身份及回显流程，不新增凭据；通过浏览器在 1440px/390px 发起合成任务，验证拒绝、再次处理、批准中断恢复、人工验收与归档。截图及不含秘密的 ID 证据保存在 `/tmp/zeus-ui-simplification/`。当前日常入口是 Workspace 工作台，主要动作是“发起任务”；运行/工作流在高级工具，成员/Agent 会话配置默认折叠。详见 `docs/ui/TASK_WORKSPACE_SIMPLIFICATION_20261001.md`。
