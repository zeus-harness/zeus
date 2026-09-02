# Model provider outage

Zeus 把模型网络错误分成稳定错误码。超时、429、5xx、传输失败和流中断可在同一 Run 内重试两次。
4xx 配置错误、无效响应和取消不会自动重试。

## 判断

```bash
kubectl -n zeus get deployment,pod,hpa -o wide
kubectl -n zeus logs deployment/zeus-api --since=15m \
  | rg 'model_|provider|run claim failed|heartbeat failed' \
  | tail -n 100
```

日志不应包含 Authorization、模型 key、Cookie 或完整 provider 响应。发现时停止转发日志。

用只读运维连接查看错误码，不读连接密文：

```bash
psql "$ZEUS_OPERATOR_DATABASE_URL" --no-psqlrc --csv --set=ON_ERROR_STOP=1 <<'SQL'
select coalesce(error_code, '<none>') as error_code,
       status,
       count(*) as runs,
       max(updated_at) as last_seen
from runs
where updated_at >= now() - interval '1 hour'
group by error_code, status
order by last_seen desc;

select event_type, count(*) as events
from run_events
where occurred_at >= now() - interval '1 hour'
group by event_type
order by events desc;
SQL
```

从批准的网络位置做 provider 状态或合成请求。不要把真实 key 放进命令行、脚本或工单。

## 处理

1. 先确认是 provider-wide outage、区域网络故障、429 限流，还是单个 Model Profile 配置错误。
2. provider-wide outage 时暂停产生新 Run 的上游。不要重启所有 API；重启不会修复外部服务。
3. 让已经领取的 Run 按现有策略完成两次短重试。不要直接 UPDATE `runs` 标记成功或失败。
4. 429 持续时降低上游流量或并发，并观察数据库连接、队列年龄和 provider 配额。
5. `model_request_rejected`、`invalid_model_configuration` 或 `invalid_model_response` 出现时，修正 URL、模型名、连接配置或 Secret。通过控制面轮换 Secret，不直接改数据库。
6. 不要因为 provider outage 关闭内嵌 Supervisor。只有数据库或租约故障才走 lease runbook。
7. provider 恢复后运行一个低成本 canary Run，确认成功、usage、Session Event 和 Run Event 都闭合，再恢复上游。

## 本机验证

```bash
cargo test -p zeus-api model
cargo test -p zeus-api runtime
```

本机测试只能验证错误分类、重试分支和事件收口。它不证明供应商可用。

## 真实集群和云服务验证

必须在真实集群验证 provider DNS/HTTPS egress、Secret 注入、Pod 退出后的 lease 恢复、队列积压、并发上限和 HPA CPU 行为。
必须在真实供应商服务验证 429、5xx、超时、流中断、凭据轮换、区域恢复和 canary Run。
