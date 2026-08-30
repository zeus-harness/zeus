# SMTP outage

邮件故障不会停止原生登录和已有 Session。注册验证、密码找回和邀请会停在 `email_outbox`，IdentityMaintenance 按租约和 fence 重试。

SMTP 在接收邮件后断开连接时，Zeus 无法判断投递结果。后续重试可能产生重复邮件。验证、找回和邀请 Token 都按单次使用处理，邮件模板要允许用户忽略旧邮件。

## 判断

```bash
kubectl -n zeus logs deployment/zeus-api --since=15m \
  | rg 'identity email|SMTP' \
  | tail -n 80

kubectl -n zeus port-forward service/zeus-api 18080:8080
curl --fail --silent http://127.0.0.1:18080/metrics \
  | rg 'zeus_identity_email_|zeus_identity_operational_metrics_up'
```

用只读运维连接查看聚合状态。不要读取收件地址、密文或 Provider 响应：

```sql
select status, count(*) as messages, min(created_at) as oldest
from email_outbox
where status in ('queued', 'sending', 'failed')
group by status
order by status;
```

`zeus_identity_operational_metrics_up` 为 `0` 时，邮件积压 Gauge 可能已经过期。先修复数据库观测，再依据积压值操作。

## 处理

1. 核对 SMTP DNS、TLS、认证方式、来源地址和服务商状态。不要把 SMTP URL 或凭据放进命令行和日志。
2. SMTP 全局不可用时保留 API Pod。IdentityMaintenance 会释放失败租约并按退避时间重新排队。
3. 不要把 `sending` 直接改成 `sent`。租约到期后由下一次 claim 恢复。
4. 不要批量复制 `email_outbox` 行。未知投递结果允许重复邮件，不能伪造成功状态。
5. 达到十次尝试后，邮件进入 `failed`。修复 SMTP 后，通过对应的重新发送 API 创建新 Token 和新邮件。
6. 恢复后观察 backlog 和最老邮件年龄下降。使用测试账号完成验证、找回和邀请各一次。

## 本机演练

```bash
scripts/container up all
scripts/container down mailpit
```

用测试账号请求一封验证或找回邮件，确认 backlog 增长且日志只含错误类别。再启动 Mailpit：

```bash
scripts/container up mailpit
scripts/container logs api -n 100
```

等待退避窗口后，从 `http://127.0.0.1:3000/mailpit/` 确认邮件到达。演练记录不保存邮件 Token。

## 告警

- `zeus_identity_operational_metrics_up == 0` 持续 2 分钟。
- `zeus_identity_email_oldest_pending_age_seconds > 300` 持续 5 分钟。
- backlog 持续增长 10 分钟。
- `failed` 邮件数量增长。
