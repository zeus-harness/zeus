# 生产形态验收

H/I5 状态：`active`。本清单准备执行顺序和证据要求，不代表生产放行。

## 先固定验收对象

部署负责人记录 commit、API/Web 镜像 digest、Schema 版本、集群规格、数据库规格、模型配置 revision 和验收窗口。仅使用合成租户和账号，不在记录中保存凭据、客户输入或连接 URI。云资源费用、模型费用和影响范围应在开始外部执行前确定。

当前仓库的本地回归可先运行：

```bash
pnpm check
pnpm test
pnpm build
scripts/container e2e build all
scripts/container e2e down api
scripts/container e2e smoke
pnpm e2e:pilot
pnpm test:browser
scripts/container e2e test-db
```

数据库测试为每组创建临时库，API 不得连接这些库。3100 E2E 与 3000 日常环境独立。上述成功只能填写“本地证据”，不能填写下表的外部通过状态。

## 外部执行顺序

| 顺序 | 负责人 | 执行动作与通过条件 | 证据位置 | 当前外部状态 |
| --- | --- | --- | --- | --- |
| 1 | 部署/数据库负责人 | 核对 migration owner、HTTP、Runtime 登录的实际 grant chain；运行跨 Organization/Workspace 拒绝测试、Grant 撤销与 Suspend 执行阻断 | 脱敏角色授权结果、拒绝测试记录、镜像和 Schema 版本 | 未执行 |
| 2 | 部署/安全负责人 | 验证 KMS、工作负载身份、Secret 挂载与出口策略；确认应用无法绕过限制，轮换后新调用可用 | [KMS 方案](../security/hardening/phase-h/hardening.md)、部署 overlay、轮换结果 | 未执行 |
| 3 | 数据库/身份负责人 | 从备份恢复并完成恢复后的身份失效；记录实测 RPO/RTO、恢复点及验证时间 | [备份恢复](backup-restore.md)，脱敏恢复演练记录 | 未执行 |
| 4 | 身份负责人 | 联调真实企业 IdP、受控 SMTP、签名轮换和下游 JWKS 缓存；运行 OpenID Foundation Suite | [Conformance](openid-conformance.md)、[IdP 故障](oidc-outage.md)、[SMTP 故障](smtp-outage.md)、[签名轮换](signing-key-rotation.md) | 未执行 |
| 5 | 性能/部署负责人 | 执行 1000 Session、100 Workspace、200 并发 Run、1800 秒容量窗口及生产规格身份压力；按现有手册阈值判断，验证 HPA 和连接池 | [容量](capacity-test.md)、[身份压力](identity-load-test.md)，RSS/重启/延迟/队列/数据库连接曲线 | 未执行 |
| 6 | 运行时/业务负责人 | 演练模型故障、租约积压和进程退出恢复；验证未知工具结果、审批、取消及试点质量 | [模型故障](provider-outage.md)、[租约积压](lease-backlog.md)、[需求试点](requirements-pilot.md) | 未执行 |

每项记录执行时间、环境、预期、实际、通过/失败、证据链接及负责人。失败项附修复或回退动作，不以“已有脚本”代替实跑结果。外部条件缺失时保持未执行。

## 升级和放行

`0026`/`0030`/`0031` 不允许旧 API 与新 Schema 混跑。升级前关闭入口，停止旧 API/Supervisor 并阻止 HPA 拉起旧副本；备份后由 migration owner 迁移，再启动匹配版本，检查 readiness、登录、租户隔离和合成 Run 后恢复入口。

Schema 升级后不能只回滚旧镜像。恢复流程遵循备份手册，并处理旧 Session、Refresh Family 和其他凭据状态。只有外部清单证据齐备、失败项处理完成且部署负责人确认，才可重新评估 H/I5 状态。
