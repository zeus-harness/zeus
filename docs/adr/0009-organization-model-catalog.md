# ADR 0009：组织模型目录与 Agent 模型选择

状态：接受，2026-09-12。

## 决策

Organization Owner 管理模型供应商、密钥和模型目录。一个供应商连接可对应多个模型配置，每个配置保存模型 ID、API 地址及调用参数。当前执行协议仍是 OpenAI-compatible，多供应商不等于已实现其他厂商的原生协议。

组织内所有 Workspace 可读取可用模型目录。Workspace Builder/Owner 在 Agent 版本中选择模型，不配置供应商凭据。Workflow 继承并持久化 Agent 版本的模型选择，不提供覆盖入口。修改 Agent 模型需要保存新 Agent 版本及新 Workflow 版本。

Organization 模型写入使用 Organization 权限；Workspace 角色及 Workspace Service Account 不获此权限。普通 Workspace 工具连接仍按原范围隔离。模型、供应商和密钥通过 Organization RLS 和复合外键约束，Runtime 仍检查 Run、Agent、Workflow 的 Workspace 边界。

## 升级与兼容

`0031` 将模型配置及其供应商/密钥上移到 Organization，保留主键、密文和加密 AAD，不合并不同 Workspace 的供应商。重名资源添加 ID 后缀。已存在的 Agent/Workflow 版本和 Run 不改写；旧 Agent 版本未选模型时，旧客户端仍可在 Workflow 请求中显式指定组织模型。新的界面要求在 Agent 版本选择。

旧 API 与新 Schema 不兼容。先停止旧 API/Supervisor，再执行 migration，之后启动匹配版本并验证。迁移失败事务回滚；成功后不只回滚旧 API 镜像。

## 影响

供应商密钥轮换与模型配置修改影响组织内引用它的全部 Workspace，包括后续恢复的运行。编辑继续保留未修改参数并使用 revision 检查；需隔离变更时创建新模型配置。启用供应商意味着授权组织内 Workspace 使用该服务，部署方需确认数据出口策略。密钥始终没有原文读取接口。
