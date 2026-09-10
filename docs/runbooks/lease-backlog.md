# Lease and queue backlog

Zeus 的每个 API Pod 都运行一个内嵌 Supervisor。不要创建或启动独立执行进程。
租约过期后，其他 API Pod 会重新 claim Run。当前基线是 60 秒租约、1 秒轮询。

## 先看事实

```bash
kubectl -n zeus get deployment,pod,hpa,pdb -o wide
kubectl -n zeus logs deployment/zeus-api --since=15m \
  | rg 'run claim failed|heartbeat failed|lease or fence|database' \
  | tail -n 80
```

日志只在受控频道查看。不要把完整日志复制到工单。

使用有只读运维权限的数据库连接检查队列。不要使用 `zeus_http` 或 `zeus_runtime` 做运维查询：

```bash
psql "$ZEUS_OPERATOR_DATABASE_URL" --no-psqlrc --csv --set=ON_ERROR_STOP=1 <<'SQL'
select status, count(*)
from runs
group by status
order by status;

select
  count(*) filter (
    where status = 'queued'
      and available_at <= now()
      and cancel_requested_at is null
  ) as ready_queue,
  count(*) filter (
    where status = 'running'
      and lease_expires_at < now()
      and cancel_requested_at is null
  ) as expired_leases,
  max(now() - available_at) filter (
    where status = 'queued'
      and available_at <= now()
      and cancel_requested_at is null
  ) as oldest_ready_age
from runs;

select lease_owner, count(*) as running_runs
from runs
where status = 'running'
group by lease_owner
order by running_runs desc;
SQL
```

## 处理顺序

1. `health/ready` 失败时先查 PostgreSQL、Secret 注入和 egress。不要先重启所有 Pod。
2. `expired_leases` 增长时，确认至少一个 API Pod Ready，再等待一个租约周期加轮询时间。
3. 确认队列下降后停止操作。不要直接 UPDATE `runs`、`run_attempts` 或 fence。
4. 所有 Pod 都不 Ready 时，逐个查看 `describe pod`、容器退出原因和数据库连接数。
5. 数据库连接或模型供应商达到上限时，先暂停产生新 Run 的上游。API 副本数乘以每 Pod 的并发和连接池上限，必须小于外部容量。
6. 需要临时扩容时调整 `zeus-api` Deployment，并观察 PostgreSQL 与供应商延迟。不要把 API 拆成独立执行进程。
7. 只有在指标适配器已安装、指标已有数据时，才应用 `deploy/kubernetes/zeus-hpa-custom-metrics.yaml`。应用前后都检查 `kubectl -n zeus describe hpa zeus-api`。

## 验证恢复

终端 1 保持端口转发：

```bash
kubectl -n zeus port-forward service/zeus-api 18080:8080
```

终端 2 执行检查：

```bash
curl --fail --silent http://127.0.0.1:18080/health/ready >/dev/null
curl --fail --silent http://127.0.0.1:18080/metrics | sed -n '1,40p'
```

再次执行队列查询。`ready_queue` 和 `expired_leases` 应下降；不要只看 Pod 数量。

## 本机验证

```bash
scripts/container up postgres
set -a
source .zeus/local.env
set +a
scripts/db/queue-concurrency
psql "$DATABASE_URL" --no-psqlrc --set=ON_ERROR_STOP=1 --file=scripts/db/queue-smoke.sql
```

本机只能验证 claim、`FOR UPDATE SKIP LOCKED`、lease 和 fence 语义。

## 真实集群验证

必须在真实集群验证多副本 claim、Pod 被终止后的租约恢复、PDB、60 秒退出窗口、HPA 行为、NetworkPolicy 和托管 PostgreSQL 连接上限。
