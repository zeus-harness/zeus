# Federated identity provider outage

先区分三类故障：Zeus 到 IdP 不通、IdP 返回错误、Zeus 自己的数据库或入口不通。
不要为了恢复登录关闭 JWT 校验、PKCE、issuer 校验或 group mapping。

## 判断

```bash
kubectl -n zeus get pod -l app=zeus-api
kubectl -n zeus logs deployment/zeus-api --since=15m \
  | rg 'OIDC|discovery|exchange|UserInfo' \
  | tail -n 80
```

先检查 API：

终端 1 保持端口转发：

```bash
kubectl -n zeus port-forward service/zeus-api 18080:8080
```

终端 2 执行检查：

```bash
curl --fail --silent http://127.0.0.1:18080/health/ready >/dev/null
curl --fail --silent http://127.0.0.1:18080/metrics \
  | rg 'zeus_federated_provider_errors_total|zeus_identity_operational_metrics_up'
```

数据库只读检查 provider 状态和未完成登录事务。不读 `encrypted_client_secret`：

```bash
psql "$ZEUS_OPERATOR_DATABASE_URL" --no-psqlrc --csv --set=ON_ERROR_STOP=1 <<'SQL'
select id, organization_id, slug, issuer_url, enabled, updated_at
from federated_identity_providers
order by updated_at desc;

select count(*) as active_login_transactions
from federated_login_transactions
where consumed_at is null
  and expires_at > now();
SQL
```

从批准的网络位置做 discovery 探测。只丢弃响应体：

```bash
OIDC_ISSUER_URL='<OIDC_ISSUER_URL>'
curl --fail --silent --show-error --max-time 5 \
  "${OIDC_ISSUER_URL%/}/.well-known/openid-configuration" >/dev/null
```

同时查看 IdP 状态页、区域 DNS、证书和 JWKS 轮换告警。不要使用真实 client secret 做临时 curl。

## 处理

1. API 或 PostgreSQL 不健康时，按应用和数据库故障处理。不要把它标成 IdP outage。
2. discovery、授权或 token exchange 失败时，保留现有 Web Session。现有 Session 只依赖 Zeus 数据库，在过期前可能继续工作；新登录可能失败。
3. 不要批量撤销 Session，不要删除 `federated_login_transactions`，不要复用旧 `state` 或 code。
4. IdP 恢复前暂停反复登录测试。每次测试都会产生新的状态记录。
5. 如果是 issuer、redirect URI 或 provider 配置错误，通过控制面修正。Client secret 只走写入接口；不要直接改数据库，也不要在日志中打印。
6. IdP 恢复后，用一个测试租户完成一次完整登录：discovery、授权回调、token、ID token、JWKS、UserInfo 和 group mapping。
7. 验证测试 Session 后再恢复用户入口，并记录受影响时段。

## 本机验证

```bash
cargo test -p zeus-api oidc
```

这只验证 URL、issuer、return-to 和 group claim 的本地规则，不验证真实 IdP。

## 真实集群和云服务验证

必须在真实集群验证 egress DNS/HTTPS、Ingress redirect URI、Pod 时钟、Secret 注入和滚动发布。
必须在真实企业 IdP 验证 discovery、授权码交换、JWKS 轮换、UserInfo、租户 group mapping 和恢复后的新登录。
