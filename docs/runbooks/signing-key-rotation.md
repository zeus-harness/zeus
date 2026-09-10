# OIDC signing-key rotation

Zeus 使用 3072-bit RSA 和 RS256。常规密钥 90 天后停止签发，旧公钥继续在 JWKS 保留 7 天。私钥以 envelope encryption 形式保存在 PostgreSQL。

## 日常检查

```bash
curl --fail --silent https://zeus.example.com/metrics \
  | rg 'zeus_oidc_signing_key_(present|age_seconds)|zeus_identity_operational_metrics_up'

curl --fail --silent https://zeus.example.com/oauth2/jwks.json \
  | jq '{key_count: (.keys | length), kids: [.keys[].kid]}'
```

`zeus_oidc_signing_key_present` 必须为 `1`。密钥年龄达到 85 天时告警。到 90 天仍未出现新 `kid` 时停止发布并检查维护日志、数据库和 envelope key。

数据库检查只读公开元数据：

```sql
select key_id, algorithm, key_use, activates_at, rotates_at, public_expires_at, created_at
from oidc_signing_keys
order by created_at desc;
```

不要查询 `encrypted_private_key`、`private_key_nonce` 或 envelope key。

## 常规提前轮换

使用 migration owner 连接调用固定函数：

```sql
select zeus_private.request_oidc_signing_key_rotation('scheduled');
```

函数只缩短当前签名窗口并写入 `security_events`。它不读取私钥。滚动一个 API Pod 会立即运行密钥维护：

```bash
kubectl -n zeus rollout restart deployment/zeus-api
kubectl -n zeus rollout status deployment/zeus-api --timeout=10m
```

检查 JWKS 同时出现新旧 `kid`。用测试 Client 完成 Authorization Code、Token、Refresh 和 UserInfo。7 天后确认旧 `kid` 消失。

## 私钥疑似泄漏

1. 暂停 `/oauth2/authorize` 和 `/oauth2/token` 的外部流量，保留健康检查和运维入口。
2. 保存 key id、发现时间和相关审计事件。不要复制私钥密文。
3. 使用 migration owner 调用：

   ```sql
   select zeus_private.request_oidc_signing_key_rotation('compromise');
   ```

4. 滚动 API，确认新 key 生成。`compromise` 会让旧公钥在约一秒后退出 Zeus JWKS，不保留七天重叠。
5. 撤销受影响的 Web Session、Refresh Token Family 和 OIDC Grant。通知下游清理 JWKS 缓存。
6. 轮换 envelope key 和数据库凭据时按独立变更执行。不要用临时本地 key 启动生产 Pod。
7. 用干净 Client 重新验证签名、`iss`、`aud`、`typ`、`kid`、`exp` 和 `nbf`。

旧公钥可能仍在下游缓存中。事故处理完成条件必须包含下游缓存失效证据。

## 压力验证

忽略式 PostgreSQL 集成测试会同时发起 32 个密钥安装请求，要求 advisory lock 只留下一个当前 key，并保留一个旧公钥：

```bash
ZEUS_TEST_DATABASE_URL="DATABASE_URL_HERE" \
ZEUS_TEST_ENVELOPE_KEY="ENVELOPE_KEY_HERE" \
cargo test -p zeus-api \
  --test oidc_provider_postgres \
  -- --ignored --exact oidc_provider_supports_public_confidential_and_refresh_replay_protection
```

只在专用空数据库运行。测试会改写该数据库中的签名 key 元数据。
