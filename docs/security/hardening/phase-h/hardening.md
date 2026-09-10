# Security Hardening Review: Zeus Phase H

## Evidence Basis

我检查了当前密钥加载、加密接口、Runtime、Kubernetes 和 OpenTelemetry 边界。证据集合记录在 [`context.md`](context.md)。这次工作没有安全扫描或生产集群结果，结论只覆盖源码和部署清单能支持的事实。

## Constraints

Zeus 0.1.0 还没有选定云厂商、KMS、工作负载身份或 egress gateway。我们需要保留 Provider、OIDC 和遥测 HTTPS，同时保证 Secret 不进入环境变量、日志、事件或 Trace。容量和 KMS 配额目前没有生产测量值。

## Opportunity Portfolio

| Opportunity | Evidence | Options | Recommendation | Proposal |
| --- | --- | --- | --- | --- |
| 绑定密钥交付和网络出口权限 | key 文件加载、`EnvelopeCipher`、Kubernetes Secret 与宽泛 HTTPS egress（`E002`–`E004`、`E007`） | KMS 支持的文件挂载；应用直连 KMS envelope | 0.1.0 采用文件挂载方案；云环境选定后再评估直连 KMS | [完整提案](proposals/bind-secret-and-egress-authority.md) |

## Recommendation Summary

我建议 0.1.0 使用 KMS 支持的 Secret driver，把源 key 只挂给 staging init container，再写入 API 使用的内存卷普通 `0400` 文件。egress gateway 维护 Provider、OIDC、KMS 和遥测目的地。仓库已经提供严格文件读取和默认拒绝 NetworkPolicy，云 overlay 与真实策略验证仍需平台团队完成。

应用直连 KMS 能减少长驻主密钥，但它会改变同步加密接口、数据库 envelope 格式和可用性依赖。等云厂商、KMS SLO、配额和延迟预算有实测数据后，这个方案会更容易做出可靠判断。

## Next Decisions

- 选定云 KMS、工作负载身份、Secret driver 和 egress gateway。
- 定义 Organization 到 KMS key 或 encryption context 的映射。
- 在生产形态集群执行密钥轮换、KMS 拒绝、出口拒绝和 200 Run 容量测试。
