# Linux Docker release-runtime 验收

## 1. 状态与边界

本文件定义 SQLite Operation Capacity 与容器资源约束阶段最后一项外部门禁：在 Linux Docker
Engine、cgroup v2 和 release runtime 镜像上，验证 Zeus 的 CPU、memory、swap、PID、OOM、重启
恢复与并发拒绝行为。

该门禁只覆盖一个 `acc_local`、一个 API/worker、一个本地 SQLite named volume，以及同源的 Web
和 gateway。它不声明以下能力已经完成：

- 公网或共享网络入口；
- TLS、canonical public origin 或 trusted proxy；
- 多 account、多 API 副本、NFS/共享 SQLite；
- Restate、MinIO、PostgreSQL 或 tool sandbox 的生产接入；
- 外部 audit 归档传输与 365 天容量证明。

当前 macOS 开发机没有 Docker CLI，因此只能完成文件、脚本和 CI 的静态验证。只有受控 Linux
runner 的实际证据满足本文件全部条件后，才能把 Linux PID/OOM 门禁标记为通过。

## 2. 验收拓扑

Linux 验收必须使用独立 Compose 文件，不能复用 `compose.yaml` 的 `full` profile。后者运行
`cargo-watch`、Vite、源码 bind mount 和编译缓存，其资源值包含开发构建余量，不是 release
runtime 或 OOM 基准。

验收栈只包含：

- `zeus`：`infra/docker/rust.Dockerfile` 的 `runtime` target；
- `web`：`infra/docker/web.Dockerfile` 的 `runtime` target；
- `gateway`：`infra/docker/caddy.Dockerfile`；
- 一个只供 API 使用的 named volume；
- gateway 的唯一 loopback published port。

API 与 Web 不发布宿主端口，不挂 Docker socket，不使用 host network，不取得额外 capability。
验收容器必须使用 `restart: "no"`，否则 OOM 或崩溃后的自动重启会掩盖失败。

## 3. 固定资源 profile

所有 memory profile 都令 `memswap_limit == mem_limit`。Docker 在 Linux 上应把它落实为
`memory.swap.max=0`，即容器没有额外 swap 余量。

| Profile    | Service |  CPU |  Memory | PID |
| ---------- | ------- | ---: | ------: | --: |
| normal     | API     |  2.0 |   1 GiB | 128 |
| normal     | Web     |  1.0 | 512 MiB | 128 |
| normal     | gateway | 0.50 | 128 MiB |  64 |
| low-memory | API     |  1.0 | 256 MiB |  64 |
| low-memory | Web     | 0.50 | 256 MiB |  64 |
| low-memory | gateway | 0.25 |  64 MiB |  32 |

这些值是验收契约，不是按某次运行结果回填的软目标。若 low-memory 失败，先保留资源、cgroup、
响应分类和日志证据；不得为了得到绿色结果静默调高限制。
`normal` 与 `low-memory` 不接受偏离表格或压力矩阵的 resource/pressure override；偏离即配置失败，
不能仍以标准 profile 名义产出权威证据。Operation Capacity 固定为 `2/1/1 ms`（最大并发、
progress reserve、acquire timeout），build toolchain 固定为 Rust `1.97.1`、Node `24.18.0`、pnpm
`10.33.0`；这些值不继承 runner 的同名环境变量。

## 4. 启动前门禁

验收脚本必须先证明：

1. Docker Server 的 OS type 是 `linux`；
2. 使用 cgroup v2，`cpu`、`memory`、`pids` controller 可用；
3. Docker Compose 能解析独立验收文件；
4. project 名是脚本生成或调用方明确提供的唯一 `zeus-linux-acceptance-*` 名称；
5. 清理只作用于该 project 的 Compose-labeled container、network 和 volume；
6. debug overlay、privileged、host network、Docker socket 和额外 capability 均未进入 resolved
   config；
7. Git worktree 干净，build context 中的 ignored runtime artifact 已由 `.dockerignore` 排除；三个
   image 都带有与当前 `HEAD` commit、tree 和 service role 精确一致的 label。复用镜像时同样验证
   这些 label，而不是只验证 tag 存在；Compose 使用 `/dev/null` 作为显式 env file，避免隐式加载
   gitignored `.env` 改写 interpolation。

token、cookie 和密码只能写入 `umask 077` 的临时目录，不进入命令 trace、容器环境、上传日志或
证据包。API 启动日志中的 owner setup token只允许在进程内提取并立即消费，不能打印到 CI
输出。脚本入口必须主动关闭继承或 `bash -x` 打开的 xtrace；setup token、owner password、cookie
value 与 CSRF token 都要登记到最终证据扫描，且不能作为外部命令参数传递。扫描失败时必须删除
位于 artifact 路径下的原证据包并令门禁失败，不能把含秘密的 failed bundle 交给 always-upload。

## 5. 配置与 cgroup 一致性

对 API、Web、gateway 都必须同时核对 Docker inspect 和容器内 cgroup，而不是只相信 Compose
源文件：

- `NanoCpus` 与 profile CPU 一致；
- `Memory` 与 profile memory 一致；
- `MemorySwap == Memory`；
- `PidsLimit` 与 profile PID 一致且不是 `0` 或 `-1`；
- `RestartPolicy.Name == "no"`、`RestartCount == 0`、`OOMKilled == false`；
- root filesystem 为 read-only；
- runtime user 非 root；
- `CapDrop` 包含 `ALL`，并启用 `no-new-privileges`；
- `cpu.max`、`memory.max`、`memory.swap.max`、`pids.max` 与 inspect 一致；
- API 的 SQLite volume 是唯一可写持久路径。

## 6. 功能与持久化验收

normal 和 low-memory 都必须在 fresh volume 上完成：

1. Web、API readiness 与 gateway 路由可用；
2. anonymous auth status 是未配置、未认证；
3. protected overview 返回 `401`；
4. 安全消费 fresh owner setup token并创建 owner；
5. 两路并发无效登录都按认证合约拒绝，用于实际覆盖两个 Argon2 worker；
6. 创建 Session、提交一个 turn，并等待 durable local-fallback reply 到连续 sequence 4；
7. 停止并重建容器但保留 named volume；
8. 重启后 `configured=true`，原 auth session、Session、turn 和 reply 仍可读取；
9. 重启后的 readiness、inspect 与 cgroup 约束仍全部成立。

启动与 readiness 会检查 exact schema v16、migration、trigger/index、foreign key、ledger 和容量
完整性。当前 runtime 镜像不携带 SQLite CLI；在增加受支持的离线数据库检查命令前，不把容器外
临时安装 `sqlite3` 的结果当作本门禁前提。

## 7. Operation Capacity 压力

| Profile    | Requests | Concurrency |
| ---------- | -------: | ----------: |
| normal     |   10,000 |          64 |
| low-memory |    3,000 |          32 |

压力目标是 `/health/ready`。每个请求只允许：

- `200`；或
- `503` 且 problem code 精确为 `sqlite_operation_capacity_exceeded`。

通过条件：

- transport error 为 0；
- 非预期 HTTP/status/body 为 0；
- `200` 至少一个；
- 合约正确的 capacity `503` 至少一个；
- 分类总数等于请求总数；
- 压力结束后 readiness 在有界时间内恢复为 `200`。

吞吐量只记录，不设为跨 runner 的硬阈值。
每个 worker 在请求间固定 pacing `100 ms`，保留原并发度和请求总数，同时给三服务 cgroup
time-series 留出可重复的观测窗口；证据必须记录该 pacing。

## 8. OOM、PID 与时间序列

对 API、Web、gateway 三个服务，都要在 fresh baseline、功能流量后、pressure 前/中/后和
restart 新 cgroup 上采集：

- `memory.current`、`memory.peak`；
- `memory.events` 的 `oom` 与 `oom_kill`；
- `pids.current`、`pids.max`、`pids.events max`；
- `cpu.stat` 的 usage 与 throttling；
- Docker state、restart count 和单次 `docker stats` 快照。

Zeus 栈通过条件：

- fresh baseline 与 restart baseline 的 `oom`、`oom_kill`、`pids.events max`、
  `memory.swap.current` 全部为 `0`；
- 从 fresh 到 pressure 前、从 pressure 前到 recovery 后、从 restart baseline 到 restart final，
  每个服务的 `oom`、`oom_kill` 和 `pids.events max` 都不增长；
- 所有采样点的 `memory.swap.current` 都为 `0`；
- 没有容器退出或自动重启；
- 压力后 readiness 恢复；
- 采样文件带 service、phase、container ID、cgroup CPU/memory/PID 字段和 `docker stats`，并包含
  每个服务至少两个 pressure 运行期样本，而不只是结束快照；首次采样前还必须确认 pressure
  进程已启动、尚未发布完成标记且仍存活。

当前门禁不运行 disposable OOM/PID 负向控制，所以它证明 Zeus 三服务在声明的 Linux cgroup v2
envelope 内没有触发限制，但不单独校准 runner 对故意越界容器的 OOM kill/EAGAIN 行为。以后若
加入负向控制，它必须使用独立、无网络、无 Zeus volume 的容器，并与 Zeus 证据分开；负向控制
失败不得伤害或重启 Zeus 栈。

## 9. 证据包

每个 profile 独立保存：

- 干净 source 的 commit SHA/tree、带 source/role label 的 image ID、runner/kernel、
  Docker/Compose、cgroup 版本；
- resolved Compose config；
- 脱敏后的 container inspect；
- 三服务 fresh/functional/pressure/restart resource time-series 与 counter assertion；
- pressure 请求分类、开始/结束时间与持续毫秒数；
- restart 前后 auth/Session 验证结果；
- outcome、清理结果和完整 `run.log`；
- logging 停止、secret scan 和 outcome 固定后生成的 SHA-256 manifest；manifest 覆盖包内除
  `SHA256SUMS` 自身外的所有稳定文件。

证据包不得包含 setup token、密码、cookie、CSRF token、provider key 或完整 API 日志。
Docker inventory/query、project ownership、Compose teardown、删除后复查、outcome 写入或 manifest
生成任一失败，都必须把最终 exit/outcome 翻转为失败；不得把清理/证据失败吞掉后返回成功。

## 10. 命令与完成条件

本地或受控 Linux runner 的权威入口为：

```sh
scripts/linux-container-acceptance.sh config
scripts/linux-container-acceptance.sh run
```

CI 应分别执行 normal 与 low-memory profile，并在成功或失败时都上传脱敏证据、再清理唯一验收
project。仅有 Compose 静态解析、镜像 build 或 Apple `container` 结果，都不能替代 Linux live
gate。

`Trusted Single-Node Ingress` 的主机代码已独立落地：canonical HTTPS origin、可信代理 CIDR、
严格单跳 client IP、强制 Secure Cookie 和同源公网入口。这里的 Linux live gate 仍是独立的部署
验收项，不能由主机单元/路由测试替代；多 account 和多 API 副本继续属于更后的控制面与分布式
权威阶段。
