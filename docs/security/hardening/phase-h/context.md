# Phase H security hardening evidence

本次评审基于 Zeus 当前源码和部署基线，未执行漏洞扫描。源码基准提交为 `2765f44f65b197fb544150e31b5fbd0037193814`。工作区包含 0.1.0 重建内容，因此 `sourceDrift` 记为 `present`。

集合摘要算法：对下表八个文件分别计算 SHA-256，把完整的 `hash path` 行按字节排序，再对结果计算 SHA-256。集合摘要为 `7df75df17894d2d5a71b26d2e8568417e24e346b8e9184a52342221becfb8385`。

| Evidence | 文件 | 标题 | SHA-256 |
| --- | --- | --- | --- |
| `E001` | `SECURITY.md` | Zeus 安全边界 | `a6dbe52466dbdbf42244119f92e86f51ea97e1fac36952aadc64d0749e8a6ccd` |
| `E002` | `docs/THREAT_MODEL.md` | Secret 与 Capability 威胁模型 | `c029e27401412122309f991fd51c4fad0b42e842e88f0e750393365a048cc1b2` |
| `E003` | `apps/zeus-api/src/config.rs` | envelope key 文件加载规则 | `9366c2a177eae81f465b21bc16f50aec99c7f96e684738dd57ea534df5766e34` |
| `E004` | `apps/zeus-api/src/crypto.rs` | `EnvelopeCipher` 与本地 AES-256-GCM | `6aa125b49a4b25ecc94c068058caa63f082f5bdaa0e66d898034a9895a6e54a2` |
| `E005` | `apps/zeus-api/src/http.rs` | HTTP 边界、请求上限和指标 | `0a225e1703db6b91ae17c896cbdb6f9819d3cbf07bdf5421f756669868376393` |
| `E006` | `apps/zeus-api/src/runtime.rs` | Provider 与 Capability 执行边界 | `70ca89721e4811ef2552485725898ae8df05093be3d21809426ccfa1ab79cb1b` |
| `E007` | `deploy/kubernetes/zeus.yaml` | Kubernetes Pod、Secret 和网络策略 | `ee5f594f953d62594215bc4c681cc5951c1d003117247d167fc4cbb177e26bbe` |
| `E008` | `deploy/otel/otel-collector.yaml` | OpenTelemetry Collector 边界 | `bca65ddccf75f7cfcb50b6b39f30cdd34e0890d64c5f2762a147fc515afce62f` |

本地静态检查能确认配置拒绝符号链接和宽权限 key 文件，也能确认非 root init container 把 Secret 源暂存为内存卷普通 `0400` 文件，Pod 使用只读根文件系统和默认拒绝网络策略。它无法确认云 KMS、Secret CSI、集群 egress gateway、NetworkPolicy CNI 或工作负载身份的实际行为。
