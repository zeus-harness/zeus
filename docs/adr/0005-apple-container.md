# ADR 0005：macOS 使用 Apple `container`

状态：Accepted（Zeus 0.1.0）

## Context

开发机是 macOS。项目本地环境使用 Apple `container`，不依赖 Docker Compose。PostgreSQL 18.6 仍是本地权威数据库。

本地环境要能启动 API、Supervisor 和数据库，也要让秘密不落到命令行、日志或宽权限文件。Apple `container` 是开发和验收工具，不是生产部署结论。

## Decision

- 本地容器生命周期使用 Apple `container`。脚本不假设 Docker Compose 存在。
- API 与 `ExecutionSupervisor` 使用同一个 `zeus-api` 运行边界；PostgreSQL 放在私有容器网络中，只有明确的 API 路径访问。
- 本地密码由 `scripts/container/init-env` 生成到 `.zeus/local.env`，权限固定为 `0600`。脚本和日志不打印密码、Token、Cookie 或 Authorization。
- 容器只暴露本地或私有网络入口。不要把开发 API 直接暴露到公网。
- 数据卷、镜像和网络只由带有 Zeus 标识的脚本管理。清理操作必须先解析精确目标，不删除工作区或宿主机的宽目录。
- Apple `container` 结果只证明 macOS 本地路径。Linux 容器、cgroup、OOM、PID 和生产恢复要走独立验收。
- 这个 ADR 不增加 shell、fs、profile 或用户代码执行能力。容器不是给 Agent 使用的沙箱接口。

## Consequences

- 新成员可以在统一的 macOS 工具链上启动 0.1.0 本地环境。
- 容器与 API 的边界更容易复现。秘密文件权限和日志要求也有固定位置。
- Apple `container` 与 Linux runtime 可能有资源和网络差异。不能用本地绿灯替代 Linux 或生产门禁。
- 数据卷会保留状态，迁移和清理必须有明确命令与验证。未知目标不执行删除。
- 若未来改用 Docker、Kubernetes 或其他部署形态，需要重新记录资源、网络、密钥和恢复语义。
