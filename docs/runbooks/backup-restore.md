# Backup and restore

范围是 PostgreSQL 数据和 envelope key。数据库备份不包含解密密钥。

本机由 `.zeus/local.env` 提供 `ZEUS_LOCAL_MASTER_KEY`。Kubernetes 基线通过 `ZEUS_ENVELOPE_KEY_FILE` 读取 init container 暂存到内存卷的普通 `0400` 文件。生产环境要由工作负载身份和 KMS 支持的 Secret driver 提供源 Secret；云资源仍需环境 overlay。密钥变化后滚动 API Pod。
部署契约如下：

- 托管 PostgreSQL：`<MANAGED_POSTGRES_PROVIDER>`、备份 ID 或时间点。
- KMS：`<KMS_PROVIDER>`、`<KMS_KEY_REFERENCE>`。
- Secret 注入器：向 `zeus-runtime` 提供受限 HTTP `database-url`、`runtime-database-url`、`envelope-key`、`envelope-key-id`。
- Migration 注入器：只向 `zeus-migration` 提供 owner `database-url`。API Pod 不能读取该 Secret。
- 密码策略：`zeus-password-policy/weak-passwords.txt` 要和恢复前版本一致，并通过发布系统校验来源和条目数。

不要把数据库 URI、密钥明文或 Secret 输出到终端记录、工单或日志。

## 发现问题

1. 记录 RPO、RTO 和故障时间。
2. 保存当前部署版本、迁移状态和备份时间。
3. 选择隔离的恢复目标。先不要覆盖源数据库。
4. 对比备份中的 `key_id` 与 Secret 注入的 `envelope-key-id`。

## 本机验证

使用本地 Apple `container` PostgreSQL 做一次可恢复性检查：

```bash
scripts/container up postgres
set -a
source .zeus/local.env
set +a
umask 077
backup_file="/private/tmp/zeus-$(date -u +%Y%m%dT%H%M%SZ).dump"
pg_dump --format=custom --no-owner --file="$backup_file" "$DATABASE_URL"
chmod 0600 "$backup_file"
pg_restore --list "$backup_file" >/dev/null

restore_db="zeus_restore_check"
createdb --maintenance-db="$DATABASE_URL" "$restore_db"
restore_url="${DATABASE_URL%/*}/${restore_db}"
pg_restore --clean --if-exists --exit-on-error --no-owner --dbname="$restore_url" "$backup_file"
DATABASE_URL="$restore_url" cargo run --quiet -p zeus-api -- db migrate
DATABASE_URL="$restore_url" scripts/db/check-schema
dropdb --maintenance-db="$DATABASE_URL" "$restore_db"
```

检查失败时保留错误信息，不保留数据库 URI。测试备份放入加密目录，并按本机保留策略清理。

## 身份状态回滚风险

PITR 会把数据库恢复到过去。恢复点之后发生的以下动作可能丢失：

- Session、Refresh Token、Consent、Service Account 和 OIDC Client 撤销。
- 邮箱验证、密码重置、恢复码、邀请、Authorization Code 和登录事务消费。
- 密码、TOTP、Provider Secret、Client Secret、Connection Secret 和成员角色变更。
- 签名密钥轮换和安全事件。

拿到可解密的备份不代表可以直接恢复流量。恢复期间保持入口关闭，并停止 Supervisor 领取 Run。等待至少 5 分钟，让恢复前签发的 Access Token 超过最长有效期。

0.1.0 没有自动重建恢复缺口的凭据撤销历史。生产环境必须保留数据库之外的安全事件和凭据变更记录。记录完整时只处理受影响对象；记录不完整时执行全量身份失效，并安排所有原生用户重置密码、重新配置 TOTP。完成这件事前不能开放原生登录。

## 真实集群和云服务

1. 进入维护窗口。通过 WAF、Load Balancer 或独立 Ingress overlay 关闭公网入口。暂停 Webhook、Schedule 和产生新 Run 的上游。
2. 删除 HPA，再停止 Web 和 API：

   ```bash
   kubectl -n zeus delete hpa zeus-api zeus-web --ignore-not-found
   kubectl -n zeus scale deployment/zeus-api deployment/zeus-web --replicas=0
   kubectl -n zeus wait --for=delete pod -l app=zeus-api --timeout=180s
   kubectl -n zeus wait --for=delete pod -l app=zeus-web --timeout=180s
   ```

3. 用 `<MANAGED_POSTGRES_PROVIDER>` 的快照或 PITR 接口恢复到隔离目标。供应商命令只写在变更记录中，不写入仓库。
4. 让 Secret 注入器指向恢复目标，并恢复备份对应的 `envelope-key`。密钥不可用时停止。不能生成新 key 代替旧 key。
5. 只运行恢复版本对应的 Migration Job。保持公网入口关闭，API 先以 Supervisor 禁用的隔离配置启动：

   ```bash
   kubectl -n zeus delete job zeus-migrate --ignore-not-found
   kubectl apply -f <RESTORE_MIGRATION_OVERLAY>
   kubectl -n zeus wait --for=condition=complete job/zeus-migrate --timeout=900s
   kubectl apply -f <RESTORE_API_NO_SUPERVISOR_OVERLAY>
   kubectl -n zeus rollout status deployment/zeus-api --timeout=10m
   ```

6. 用 migration owner 连接执行下面的事务。它撤销恢复库中的短期身份状态，不读取或输出凭据：

   ```sql
   begin;

   update web_sessions
   set revoked_at = coalesce(revoked_at, now())
   where revoked_at is null;

   update oidc_refresh_token_families
   set status = 'revoked',
       revoked_at = coalesce(revoked_at, now()),
       revoke_reason = coalesce(revoke_reason, 'database_restore'),
       updated_at = now()
   where status <> 'revoked';

   update oidc_refresh_tokens
   set revoked_at = coalesce(revoked_at, now())
   where consumed_at is null and revoked_at is null;

   update email_verification_tokens
   set consumed_at = now()
   where consumed_at is null;

   update password_reset_tokens
   set consumed_at = now()
   where consumed_at is null;

   update user_recovery_codes
   set used_at = now()
   where used_at is null;

   update organization_invitations
   set status = 'revoked', revoked_at = now(), updated_at = now()
   where status = 'pending';

   update oidc_authorization_transactions
   set denied_at = now()
   where consumed_at is null and denied_at is null;

   update oidc_authorization_codes
   set consumed_at = now()
   where consumed_at is null;

   update oidc_consents
   set revoked_at = coalesce(revoked_at, now())
   where revoked_at is null;

   select zeus_private.request_oidc_signing_key_rotation('restore');

   insert into security_events (event_type, outcome, metadata)
   values (
     'identity.restore_credentials_invalidated',
     'success',
     jsonb_build_object('scope', 'short_lived_identity_state')
   );

   commit;
   ```

7. 对照外部安全事件和变更记录，找出恢复缺口内修改过的用户密码、TOTP、Service Account、OIDC Client、企业 IdP 和 Connection Secret。逐项撤销或轮换。无法准确对账时：

   - 撤销所有 Service Account。
   - 撤销并重建所有 OIDC Client。
   - 要求所有原生用户重置密码并重新配置 TOTP。
   - 轮换所有企业 IdP、SMTP、模型和 Capability 凭据。
   - 保持 Schedule、Webhook 和 Supervisor 关闭，直到 Connection Secret 完成轮换。

8. 滚动一个隔离 API Pod。确认新签名 key 已生成，JWKS 只包含预期的新旧 key。验证 `/health/ready`、聚合身份指标、Session 拒绝、Refresh 拒绝和新登录。
9. 启动 Web，用测试 Organization 验证注册、验证邮件、密码登录、MFA、联合登录、Authorization Code、Refresh 和 UserInfo。此时入口仍保持关闭。
10. 恢复标准 API/Web 清单和 HPA。开启 Supervisor 后跑一个无企业副作用的低风险 Run。检查数据库、事件、加密 Secret 和 lease。
11. 开放公网入口和上游。记录实际 RPO、RTO、恢复点、丢失窗口、失效数量、轮换范围和复核人。

必须在真实集群验证 Pod 停止、网络策略、Secret 注入、Migration Job、签名 key 轮换和滚动恢复。
必须在真实云服务验证快照/PITR、托管 PostgreSQL 连接、KMS 解密、外部审计保留和权限。
托管 PostgreSQL 的公网地址不匹配核心清单的私有 5432 egress。先通过环境 overlay 或 egress gateway 加入明确 CIDR，再恢复流量。
