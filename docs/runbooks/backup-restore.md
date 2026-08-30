# Backup and restore

范围是 PostgreSQL 数据和 envelope key。数据库备份不包含解密密钥。

本机由 `.zeus/local.env` 提供 `ZEUS_LOCAL_MASTER_KEY`。Kubernetes 基线通过 `ZEUS_ENVELOPE_KEY_FILE` 读取 init container 暂存到内存卷的普通 `0400` 文件。生产环境要由工作负载身份和 KMS 支持的 Secret driver 提供源 Secret；云资源仍需环境 overlay。密钥变化后滚动 API Pod。
部署契约如下：

- 托管 PostgreSQL：`<MANAGED_POSTGRES_PROVIDER>`、备份 ID 或时间点。
- KMS：`<KMS_PROVIDER>`、`<KMS_KEY_REFERENCE>`。
- Secret 注入器：向 `zeus-runtime` 提供 `database-url`、`runtime-database-url`、`envelope-key`、`envelope-key-id`。

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

## 真实集群和云服务

1. 进入维护窗口。暂停入口流量和产生新 Run 的上游。
2. 删除 HPA，避免它把 API 副本数恢复到最小值；再停止 Web 和 API：

   ```bash
   kubectl -n zeus delete hpa zeus-api zeus-web --ignore-not-found
   kubectl -n zeus scale deployment/zeus-api deployment/zeus-web --replicas=0
   kubectl -n zeus wait --for=delete pod -l app=zeus-api --timeout=180s
   kubectl -n zeus wait --for=delete pod -l app=zeus-web --timeout=180s
   ```

3. 用 `<MANAGED_POSTGRES_PROVIDER>` 的快照或 PITR 接口恢复到隔离目标。供应商命令只写在变更记录中，不写入本仓库。
4. 让 Secret 注入器指向恢复目标，并恢复同一版本的 `envelope-key`。密钥不可用时停止，不要生成新 key 代替旧 key。
5. 恢复应用清单和 Migration Job：

   ```bash
   kubectl -n zeus delete job zeus-migrate --ignore-not-found
   kubectl apply -f deploy/kubernetes/zeus.yaml
   kubectl -n zeus wait --for=condition=complete job/zeus-migrate --timeout=900s
   kubectl -n zeus rollout status deployment/zeus-api --timeout=10m
   kubectl -n zeus rollout status deployment/zeus-web --timeout=10m
   ```

6. 先请求 `/health/ready`，再用一个低风险租户 Run 验证读写、事件和加密 Secret。
7. 恢复 HPA、入口流量和上游。记录实际 RPO、RTO 和丢失的时间段。

必须在真实集群验证 Pod 停止、网络策略、Secret 注入、Migration Job 和滚动恢复。
必须在真实云服务验证快照/PITR、托管 PostgreSQL 连接、KMS 解密和权限。
托管 PostgreSQL 的公网地址不匹配核心清单的私有 5432 egress；先通过环境 overlay 或 egress gateway 加入明确 CIDR，再恢复流量。
