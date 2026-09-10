# Implementation Plan: KMS-backed mounted key with controlled egress

## Selected Design And Constraints

Zeus 0.1.0 keeps local AES-256-GCM and receives its production key through a KMS-backed, workload-identity-authorized file mount. HTTPS leaves through an approved egress policy. The repository stays cloud-neutral, so vendor resource names belong in an environment overlay.

The evidence collection digest is `7df75df17894d2d5a71b26d2e8568417e24e346b8e9184a52342221becfb8385`.

## Source Revision And Drift Check

The base revision is `2765f44f65b197fb544150e31b5fbd0037193814`. The 0.1.0 rebuild is uncommitted, so source drift is present. Before applying a cloud overlay, recompute the evidence inventory and review changes to `AppConfig`, `EnvelopeCipher`, Kubernetes volumes and egress rules.

## Affected Components

- `apps/zeus-api/src/config.rs`
- `apps/zeus-api/src/crypto.rs`
- `deploy/kubernetes/zeus.yaml`
- cloud environment overlay owned by the platform team
- `docs/runbooks/backup-restore.md`
- `docs/runbooks/provider-outage.md`
- `docs/runbooks/capacity-test.md`

## Ordered Work Packages

1. Keep the repository key seam. `ZEUS_ENVELOPE_KEY_FILE` remains exclusive with inline key variables. The loader keeps regular-file, size and Unix permission checks.
2. Select the cloud KMS, Secret driver, workload identity and egress gateway. Record their versions and support windows.
3. Add an environment overlay that binds only the `zeus-api` service identity to the KMS-backed source. Mount that source only into the staging init container and copy it into the existing memory-backed regular `0400` file.
4. Replace broad TCP 443 access at the gateway with explicit Provider, OIDC, KMS and telemetry destinations. Keep Kubernetes default-deny as a second layer.
5. Add rotation and denial alerts. Correlate them with `request_id`, `run_id`, queue depth and Provider errors without recording secret values.
6. Canary one API Pod, verify existing and new envelopes, then roll by zone. Run the capacity and failure exercises before promotion.

## Compatibility And Migration

The mounted value uses the existing 32-byte hex or URL-safe base64 format. Existing ciphertext, nonce and key id remain unchanged. The first cloud rollout must present the same key and key id as the source environment. A later rotation may introduce a new id only with a retained reader or an explicit re-encryption procedure.

No database migration is required for this option.

## Tactical Protections During Migration

- Keep the old Secret source available for rollback, but mount only one source into the staging init container for each Pod revision.
- Keep non-root, read-only root filesystem, dropped capabilities and disabled ServiceAccount token automount.
- Keep the API body limit, RLS, RBAC, audit events and secret-safe tracing.
- Run gateway policy in audit mode before enforcement and reject unowned wildcard destinations.

## Tests And Security Validation

- Configuration unit tests cover missing, conflicting, symlinked, oversized, empty and wide-permission files.
- Cluster tests prove Pod identity, volume mode, unrelated-Pod denial and denied destination behavior.
- Rotation tests read old envelopes, write a new test envelope, restart the Pod and read both again.
- Failure tests cover driver denial, KMS denial, gateway denial, DNS failure and Collector outage.
- Cross-tenant tests confirm that key delivery does not bypass Zeus RLS or encryption AAD checks.

## Performance And Resource Benchmarks

Run `scripts/load/capacity.mjs` with 1,000 user Sessions, 100 Workspaces and 200 concurrent Runs for 1,800 seconds. Compare the same workload before and after gateway enforcement. Record queue-wait p50/p95/p99, Run latency, Provider latency, gateway latency, API RSS, Collector drops, database connections and KMS or driver calls.

The release gate requires one terminal state per submitted Run and queue-wait p95 below 2 seconds while spare execution capacity exists. Set a separate acceptable gateway delta only after baseline measurements exist.

## Rollout And Rollback

Roll one canary Pod with the driver-managed source and let the init container create the final key file. Verify readiness, secret reads and outbound destinations. Expand one zone at a time and retain at least two ready API Pods through the rollout. A rollback restores the previous source and gateway route while keeping the key id stable. Key changes always roll Pods. Active Runs recover through PostgreSQL leases if a Pod is replaced.

## Acceptance Criteria

- Production key values do not appear in environment variables, manifests, logs, events, traces or API responses.
- Only the Zeus workload identity can retrieve the key; only `zeus-api` Pods can read the mounted file.
- Unapproved HTTPS destinations are denied and observable.
- Existing encrypted records remain readable across canary, rollout, restart and rollback.
- Rotation and outage procedures are executed with recorded evidence.
- The 30-minute 200-Run capacity gate passes in the production-shaped environment.

## Open Decisions

- Cloud, KMS, Secret driver, identity system and egress gateway.
- Key scope and rotation interval.
- Gateway destination ownership and emergency-change process.
- Key retirement and historical-envelope handling.
