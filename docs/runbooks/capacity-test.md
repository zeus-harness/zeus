# Capacity test

## 目标

这套驱动验证 1,000 个用户、100 个 Workspace、200 个并发 Run 持续 30 分钟时的队列和终态行为。

运行必须放在隔离的性能环境。数据库、模型 Provider、OIDC 和 OpenTelemetry 要使用接近生产的配置。不要对客户 Workspace 运行。

## 准备身份文件

在集群外生成 1,000 个测试用户并完成 OIDC 登录。每个用户保存一个尚未过期的 Zeus Session Cookie。把身份映射写入不进 Git 的 JSON 文件：

```json
{
  "baseUrl": "https://zeus-load.example.com",
  "actors": [
    {
      "id": "load-user-0001",
      "workspaceId": "00000000-0000-7000-8000-000000000001",
      "workflowVersionId": "00000000-0000-7000-8000-000000000002",
      "auth": {
        "type": "cookie",
        "value": "zeus_session=YOUR_SESSION_TOKEN_HERE"
      }
    }
  ]
}
```

文件至少包含 1,000 个唯一 `id` 和 100 个唯一 `workspaceId`。测试 Workflow 要使用容量测试专用 Provider，输出短且稳定，不得触发企业副作用。

```bash
chmod 0600 /secure/path/zeus-capacity.json
```

驱动拒绝符号链接、组可读文件、公开文件、带凭据的 Base URL 和明文 HTTP。`--allow-http` 只供隔离的本机环境。

## 运行

```bash
node scripts/load/capacity.mjs \
  --config /secure/path/zeus-capacity.json \
  --concurrency 200 \
  --duration-seconds 1800
```

驱动为每次迭代创建独立 Session 和 Run。200 个并发槽位在 Run 到达终态后继续提交下一次迭代。身份按槽位轮换。输出只包含计数、延迟和稳定错误码，不输出 Cookie、Bearer Token、Prompt 或模型结果。

本机冒烟可使用小样本：

```bash
node scripts/load/capacity.mjs \
  --config /secure/path/zeus-capacity-local.json \
  --concurrency 4 \
  --duration-seconds 60 \
  --allow-smaller \
  --allow-http
```

## 通过条件

- 200 个并发 Run 持续提交 30 分钟。
- 每个已提交 Run 只有一个持久终态。
- 没有请求失败或等待超时。
- 有空闲执行容量时，`created_at` 到 `started_at` 的 p95 小于 2 秒。
- `zeus_queue_depth` 能在压力下降后回到基线。
- 数据库、API Pod 和 Collector 没有 OOM、连接池耗尽或持续错误。

驱动对前四项做机器判定并用退出码 `2` 表示不通过。队列回落和资源状态需要结合 Prometheus、Trace 和 PostgreSQL 指标确认。

## 留存证据

保存驱动 JSON 汇总、测试窗口、镜像 digest、迁移版本、HPA 事件、Pod 重启记录、数据库指标和 Provider 限流记录。身份文件不进入报告。测试结束后撤销测试 Session 和 Service Account。
