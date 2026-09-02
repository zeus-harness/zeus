# Identity load test

这套驱动验证密码哈希并发上限、PostgreSQL 登录限流、API 存活和认证指标。默认发送 200 次合成无效登录，并发数是 100。

只在隔离环境运行。测试会触发 IP 级限流。不要对生产入口、客户账号或公司邮箱域名运行。

## 运行

本机 Apple `container`：

```bash
scripts/container up all
pnpm load:identity -- \
  --base-url http://127.0.0.1:3000 \
  --allow-http \
  --concurrency 100 \
  --requests 200
```

集群环境使用 HTTPS：

```bash
pnpm load:identity -- \
  --base-url https://zeus-load.example.com \
  --concurrency 100 \
  --requests 200
```

驱动生成 `example.invalid` 地址。它不读取账号文件，不携带 Cookie，不打印请求邮箱、密码或响应正文。

## 判定

退出码 `0` 表示：

- 每个登录返回 `401` 或 `429`。
- 没有网络失败和异常状态码。
- 压力结束后 `/health/ready` 仍返回成功。
- `zeus_identity_password_failures_total` 有增长。
- `zeus_identity_throttled_total` 有增长。

退出码 `2` 表示验收失败。退出码 `1` 表示配置、网络或指标读取失败。

同时观察：

```bash
curl --fail --silent https://zeus-load.example.com/metrics \
  | rg 'zeus_identity_|zeus_http_inflight_requests'

kubectl -n zeus top pod -l app=zeus-api
kubectl -n zeus get pod -l app=zeus-api -o wide
```

100 个并发请求不能造成 Pod OOM、数据库连接池持续耗尽或 readiness 失败。记录镜像 digest、数据库规格、API 副本数、连接池大小、测试摘要和 Pod 重启次数。

## 邮件租约恢复

在专用空数据库运行：

```bash
psql "$ZEUS_TEST_DATABASE_URL" \
  --no-psqlrc \
  --set=ON_ERROR_STOP=1 \
  --file scripts/db/identity-maintenance-smoke.sql
```

脚本在事务中模拟邮件租约过期、第二节点接管和旧 fence 提交。成功后回滚，不保留邮件。数据库里已有待发邮件时脚本会拒绝运行。

## 留存

保留 JSON 摘要和聚合指标截图。不要保留请求抓包、Cookie、数据库 URI、SMTP URL 或 `.zeus/local.env` 内容。
