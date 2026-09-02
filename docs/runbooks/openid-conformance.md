# OpenID conformance

状态：`external_not_run`

截至 2026-08-30，仓库只完成本地协议测试和 Apple `container` 冒烟。没有 OpenID Foundation Conformance Suite 的运行记录，也没有 OpenID Certified 结论。

官方入口：

- [OpenID Connect OP 测试说明](https://openid.net/certification/connect_op_testing/)
- [OpenID Conformance Suite](https://openid.net/certification/about-conformance-suite/)
- [OpenID Connect OP Logout 测试说明](https://openid.net/certification/connect_op_logout_testing/)

## 目标计划

| 计划 | Zeus 范围 | 当前状态 |
| --- | --- | --- |
| OpenID Connect Core Basic OP | Authorization Code、ID Token、UserInfo、静态 Client | 待外部运行 |
| OpenID Connect Config OP | Discovery 和 JWKS | 待外部运行 |
| RP-Initiated Logout OP | `end_session_endpoint`、ID Token Hint、回跳 URI | 待外部运行 |
| OAuth Authorization Server 安全测试 | S256 PKCE、Code 单次使用、Redirect URI、Refresh 轮换和重放 | 待外部运行 |

Zeus 不支持 Dynamic Client Registration。按官方静态 Client 流程准备三个测试 Client：两个 `client_secret_basic`，一个 `client_secret_post`。Redirect URI 精确登记为 Suite 给出的 callback。Public Client 另建一组，使用 `none` 和 S256 PKCE。

## 运行前检查

- 使用独立测试 Organization、用户和邮箱。
- 部署到可被 Suite 访问的 HTTPS 地址。
- `ZEUS_PUBLIC_URL` 与 Discovery 的 `issuer` 完全一致。
- 数据库时钟、Pod 时钟和 TLS 证书正常。
- 注册 Suite 给出的 Redirect URI 和 Post Logout Redirect URI。
- 关闭测试 Client 的企业副作用 Capability。
- 日志与 Trace 不记录 Code、Token、Cookie、Client Secret 或 Authorization Header。

## 本地前置门禁

```bash
cargo test -p zeus-api oidc
cargo test -p zeus-api --test oidc_provider_postgres -- --ignored
curl --fail --silent https://zeus-test.example.com/.well-known/openid-configuration | jq .
curl --fail --silent https://zeus-test.example.com/oauth2/jwks.json | jq .
```

这些命令只做实现检查。它们不能替代 Foundation Suite。

## 证据

每次运行保存：

- Suite 版本或托管环境、计划名和运行 URL。
- Zeus Git commit、镜像 digest、迁移版本和 `ZEUS_PUBLIC_URL`。
- 每个测试的最终状态。
- Suite 导出的日志包和人工截图。
- `REVIEW`、`WARNING`、`SKIPPED` 的解释。
- 修复提交和复测链接。

证据目录放在受控发布系统，不提交包含 Token、Cookie、Client Secret、用户资料或测试会话的原始包。

## 上线判断

Basic OP、Config OP、Authorization Code、PKCE、Refresh Token 和 RP-Initiated Logout 的目标用例没有 `FAILED` 或 `INTERRUPTED`，才满足本项目的外部上线条件。官方认证申请和本项目上线判断分开记录。
