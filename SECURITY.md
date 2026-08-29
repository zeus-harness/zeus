# Security Policy

## 报告安全问题

请通过仓库维护者提供的私有渠道报告。不要在公开 Issue 中提交漏洞细节、Token、客户数据或复现凭据。

报告应包含影响范围、触发条件、最小复现和建议修复。所有密钥使用 `<REDACTED>` 代替。

## 项目安全边界

- Zeus 初版不执行用户代码，不提供 shell 或服务器文件系统工具。
- 企业 Capability 必须在服务端注册，并通过租户策略和审批检查。
- PostgreSQL RLS 和应用 RBAC 同时保护租户数据。
- Session、Run、审批和审计事件采用追加写入。
- 原始连接密钥没有读取 API。
- 日志不得记录 Authorization、Cookie、OIDC Secret 或模型密钥。

`.zeus/local.env` 只用于本机开发，权限必须是 `0600`。不要提交该目录，
不要把文件内容贴进 Issue、日志或聊天。

`container inspect` 会显示容器环境变量。检查本地 PostgreSQL 时只运行
`scripts/container/postgres-status`，不要粘贴原始 inspect 输出。

详细威胁模型见 `docs/THREAT_MODEL.md`。
