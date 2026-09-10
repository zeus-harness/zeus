# ADR 0006：HTTP 与 Runtime 使用固定数据库角色

状态：Accepted（Zeus 0.1.0）

## Context

RLS 只有在真实服务连接受限时才有效。只在测试 SQL 中执行 `SET ROLE`，但让 API 长期使用 migration owner，会绕过隔离目标。

HTTP 和 Runtime 的权限也不同。HTTP 需要租户行隔离和控制面写入。Runtime 需要跨租户领取 Run，但只能访问执行所需的表和 security-definer 函数。

## Decision

- Migration 使用数据库 owner，不进入请求处理或 Run 执行。
- HTTP SQLx 连接在 startup packet 中设置 `role=zeus_http` 和 `row_security=on`。
- Runtime SQLx 连接设置 `role=zeus_runtime`。该角色带 `BYPASSRLS`，SQL 仍必须携带 Organization 和 Workspace。
- 服务进程在无法切换角色时启动失败，不回退到登录账号权限。
- `zeus_http` 不能直接读取 OIDC transaction、HTTP idempotency 或 run usage 表，也不能直接写 Session/Run Event。
- 受保护读写通过最小范围的 `zeus_private` security-definer 函数完成。
- `scripts/db/bootstrap-roles.sql` 创建固定的 NOLOGIN 角色。生产登录账号和密码由部署平台创建，并只授予所需的 `SET ROLE` 能力。

## Consequences

- 本地、测试和云端使用同一套 RLS 与函数权限边界。
- API 代码中的漏租户条件仍会被 HTTP RLS 拦截。Runtime SQL 不受 RLS 兜底，必须保留显式租户条件和 fence 校验。
- 新数据库要先创建角色，再运行 migration。缺少角色会让权限迁移失败，部署会停止。
- 登录账号配置错误会直接暴露为启动错误，不会静默扩大权限。
