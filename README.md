# Zeus Harness

Zeus Harness is an early Rust and SvelteKit vertical slice toward an auditable
agent runtime. The current Alpha+ slice demonstrates a durable conversation
Session attached to an incident Run, independent ordered Session and Run event
streams, a guarded approval flow, local owner authentication, and recovery
through SQLite. A user message, Agent turn, and first immutable model job
commit atomically; only the server-side Agent workers may append assistant
output, admit a server-resolved tool call, or close the turn. Its web
interface deliberately follows the compact, conversation-first shape of
DeepSeek Harness rather than a dense operations dashboard.

An approval records authorization only. The default `production-guarded`
profile has no RDS executor: approving the illustrated change is durably
recorded, then settles as `not_dispatched / executor_unavailable` without a
production side effect. An explicit `local-development` profile provides a
path-constrained marker executor and can additionally register rooted,
read-only workspace discovery, literal text search, bounded whole-file and
line-range reading, plus approval-gated exact text replacement, line insertion,
and create-new-only file tools for testing a useful complete Agent loop. Restate,
MinIO, the networkless tool sandbox, and optional PostgreSQL are development
topology for later milestones; they are not application state authorities.

Alpha+ supports one local `acc_local` account with owner and member roles.
Schema v14 made durable membership the sole capability authority for
authentication, REST/SSE access, receipts, reply/dispatch work, and worker
claim. Schema v15 adds owner-managed member setup/disable, immediate revision
revocation, bounded account security audit, legal hold, and archive
checkpoints. Members can use ordinary Session/Run and reply paths; approval,
connector dispatch, member administration, and audit administration remain
owner-only. Keep the service loopback/private-network only, and do not expose
it as a shared or Internet-facing deployment.

The staged account/membership and audit-retention design is documented in
[`docs/account-membership-audit-retention.zh-CN.md`](docs/account-membership-audit-retention.zh-CN.md).
Its v12-v15 storage, authorization, member-lifecycle, and local-audit slices
are implemented. It also documents the deployment gates that remain outside
this local collaboration milestone.

## Prerequisites

- Rust `1.97.1`
- Node.js `24.18.0` and pnpm `10.33.0`
- Docker Engine/Desktop with Docker Compose v2 for Compose modes
- Apple `container` with its service running, plus `curl`, `jq`, and `rsync`,
  for the Apple container mode

Copy the local defaults before using Compose. The Apple helper does not use
this file:

```sh
cp .env.example .env
```

The checked-in values are development-only. Do not reuse the MinIO or optional
PostgreSQL credentials outside an isolated workstation.

## Local development modes

### Fast mode: applications on the host

The API creates and migrates `.zeus/zeus.db`, seeds the demo only when the
database is empty, and reuses the same state after a restart:

```sh
ZEUS_DATABASE_PATH=.zeus/zeus.db \
ZEUS_LISTEN_ADDR=127.0.0.1:8081 \
ZEUS_DEMO_PROFILE=production-guarded \
cargo run -p zeus-api

ZEUS_API_URL=http://127.0.0.1:8081 \
pnpm --filter web dev --host 127.0.0.1 --port 3000
```

On every startup while a database is still unconfigured, the API rotates the
owner setup token, invalidates the previous token, and prints the new bearer
once to that process's terminal. Open the Web UI, enter the current token, and
choose a username plus a password of at least 12 characters. After owner setup,
later restarts preserve the owner and no longer print a setup token.

With no model configuration, the durable Agent model worker returns an explicit
non-model local message. Configure an OpenAI-compatible Chat Completions
provider by setting all three variables together:

```sh
ZEUS_LLM_ENDPOINT=https://provider.example/v1/chat/completions
ZEUS_LLM_MODEL=your-model
ZEUS_LLM_API_KEY=your-secret
```

Partial provider configuration fails startup. The endpoint and key are never
writable through the browser Settings API.

Each accepted turn builds the initial provider request from exactly one stable
system message, the newest complete, flushed user/assistant pairs that existed
at the submitted `expected_sequence`, the new user message, and one final
durable `context` message. The system
prompt identity, revision, and domain-separated content digest are part of the
canonical secret-free deployment manifest; its exact content is the first
message in the durable request. The prompt and governed context share the 64 KiB
initial UTF-8 content budget with at most 26 prior pairs and the current user
message. That initial shape uses at most 55 of the Agent's 64-message budget,
reserving eight messages for four sequential assistant tool calls and their
results. The fixed loop also permits at most eight model steps, one pending
approval, 16 KiB of arguments per call, 64 KiB per known result, and 128 KiB of
known results for the turn. Retries reuse the originally admitted request
rather than rebuilding it from newer Session state. A current user message that
cannot fit beside the fixed prompt is rejected with `413
agent_request_too_large` before any turn or job is written.

SQLite logical-capacity defaults can be reduced for local tests or raised only
up to the compiled hard ceiling. Explicit values must be non-empty unsigned
decimal integers; zero, non-UTF-8, actor values above their account value,
account values above their global value,
per-ledger event-payload byte limits above the global byte limit, and values
above the hard ceiling fail startup.

| Environment variable                               |               Default |          Hard ceiling |
| -------------------------------------------------- | --------------------: | --------------------: |
| `ZEUS_MAX_SESSIONS_PER_ACTOR`                      |                 1,000 |                10,000 |
| `ZEUS_MAX_SESSIONS_PER_ACCOUNT`                    |                10,000 |               100,000 |
| `ZEUS_MAX_SESSIONS_GLOBAL`                         |                10,000 |               100,000 |
| `ZEUS_MAX_OPEN_TURNS_PER_ACTOR`                    |                    32 |                   128 |
| `ZEUS_MAX_OPEN_TURNS_PER_ACCOUNT`                  |                    64 |                   512 |
| `ZEUS_MAX_OPEN_TURNS_GLOBAL`                       |                    64 |                   512 |
| `ZEUS_MAX_ACTIVE_REPLY_JOBS_PER_ACTOR`             |                    32 |                   128 |
| `ZEUS_MAX_ACTIVE_REPLY_JOBS_PER_ACCOUNT`           |                    64 |                   512 |
| `ZEUS_MAX_ACTIVE_REPLY_JOBS_GLOBAL`                |                    64 |                   512 |
| `ZEUS_MAX_ACTIVE_DISPATCH_JOBS_PER_ACTOR`          |                    16 |                    64 |
| `ZEUS_MAX_ACTIVE_DISPATCH_JOBS_PER_ACCOUNT`        |                    32 |                   256 |
| `ZEUS_MAX_ACTIVE_DISPATCH_JOBS_GLOBAL`             |                    32 |                   256 |
| `ZEUS_MAX_AUTH_SESSIONS_PER_USER`                  |                    32 |                   128 |
| `ZEUS_MAX_AUTH_SESSIONS_GLOBAL`                    |                   256 |                 4,096 |
| `ZEUS_MAX_SESSION_EVENT_SLOTS_PER_SESSION`         |                10,000 |               100,000 |
| `ZEUS_MAX_RUN_EVENT_SLOTS_PER_RUN`                 |                50,000 |               500,000 |
| `ZEUS_MAX_SESSION_EVENT_PAYLOAD_BYTES_PER_SESSION` |   64 MiB (67,108,864) | 256 MiB (268,435,456) |
| `ZEUS_MAX_RUN_EVENT_PAYLOAD_BYTES_PER_RUN`         | 256 MiB (268,435,456) | 1 GiB (1,073,741,824) |
| `ZEUS_MAX_EVENT_PAYLOAD_BYTES_GLOBAL`              | 1 GiB (1,073,741,824) | 2 GiB (2,147,483,648) |
| `ZEUS_MAX_BOOTSTRAP_AUDIT_ROWS`                    |                 1,024 |                65,536 |

The legacy `*_PER_SCOPE` names are accepted only when their corresponding
`*_PER_ACTOR` name is absent. Setting both names fails startup. If a
`*_PER_ACCOUNT` value is absent it inherits the effective configured global
value, so reducing a global limit cannot accidentally leave an invalid account
default above it.

Event-slot limits cover the current durable ledger head plus slots reserved for
accepted work to reach a terminal state. Event-payload byte limits similarly
cover the UTF-8 byte length of serialized `session_events.payload_json` and
`run_events.payload_json` plus outstanding finalization reservations. They do
not cover other rows, indexes, SQLite page overhead, the database file, WAL, or
free-disk capacity.

`ZEUS_MAX_BOOTSTRAP_AUDIT_ROWS` is the detailed token-lifecycle window, not an
admission limit that can permanently block owner setup. Schema v12 terminates
each token as `superseded`, `consumed`, `expired`, or migration-only
`legacy_unknown`; terminal prefixes are folded in deterministic batches of at
most 64 into a monotonic SHA-256 rollup before their detail rows are removed.
The live token is never compacted. The rollup is a database-local history
commitment, not an external tamper-proof anchor.

The implemented and locally verified SQLite Physical Capacity Slice uses these
configuration limits:

| Environment variable                  |               Default | Hard ceiling | Purpose                                 |
| ------------------------------------- | --------------------: | -----------: | --------------------------------------- |
| `ZEUS_SQLITE_MAX_MAIN_BYTES`          | 4 GiB (4,294,967,296) |       32 GiB | Main database page budget               |
| `ZEUS_SQLITE_WAL_TARGET_BYTES`        |   16 MiB (16,777,216) |      256 MiB | WAL autocheckpoint/reset target         |
| `ZEUS_SQLITE_MIN_FREE_BYTES`          | 256 MiB (268,435,456) |        8 GiB | Minimum filesystem headroom             |
| `ZEUS_SQLITE_ADMISSION_RESERVE_BYTES` | 512 MiB (536,870,912) |        8 GiB | Admission filesystem headroom watermark |

Startup rejects invalid configuration unless
`WAL target < admission reserve < max main`; it must also use checked arithmetic
so `min free + admission reserve` cannot overflow. `max main` is translated to
SQLite `max_page_count` and limits pages in the main database only. The WAL
target drives autocheckpoint and journal reset; it is not an absolute hard cap
on the size of an active WAL. Filesystem free space comes from `statvfs`, whose
result has an unavoidable TOCTOU window, so that check is an admission signal,
not a durable disk reservation. The logical event-payload quotas above remain
independent and continue to protect ledger payload growth.

Every file-backed connection reapplies and verifies the safety and physical
PRAGMAs, including `max_page_count`, `wal_autocheckpoint`,
`journal_size_limit`, the bounded cache, and disabled `mmap`. Ordinary
`Admission` requires the main file to remain below the configured headroom
watermark, the active WAL to be at or below its target, and filesystem free
space to cover `min free + admission reserve`. `ReservedProgress` and
`Finalization` preserve already accepted work: they still enforce the main-file
maximum and minimum free space, but do not pretend that the WAL target is a hard
cap. The admission headroom is one watermark, not a reserve accumulated once
per request or active job.

Business operations rejected by the physical gate return a redacted
`507 physical_storage_exhausted` with `Cache-Control: no-store`; the public
`/health/ready` endpoint reports the same watermark as a redacted `503` with
`Cache-Control: no-store`. Readiness performs only schema/PRAGMA metadata and
physical-watermark checks. Startup performs the deep business, ledger, foreign-
key and SQLite integrity checks plus a truncating WAL checkpoint before the
listener is exposed. Operators and tests can request the same deep integrity
check, without the startup checkpoint, explicitly through
`SqliteStore::verify_integrity`; it is not run for every health probe.

SQLite blocking work also has a bounded operation gate:

| Environment variable                       |  Default | Hard ceiling |
| ------------------------------------------ | -------: | -----------: |
| `ZEUS_SQLITE_MAX_CONCURRENT_OPERATIONS`    |        8 |           32 |
| `ZEUS_SQLITE_RESERVED_PROGRESS_OPERATIONS` |        1 |            8 |
| `ZEUS_SQLITE_OPERATION_ACQUIRE_TIMEOUT_MS` | 1,000 ms |     5,000 ms |

With the defaults, ordinary reads and admission commands share seven general
slots. Their general-lane acquisition uses `try_acquire`, so saturation fails
fast instead of forming an unbounded waiter queue. Durable progress may use all
eight total slots and waits only for the configured bounded timeout. The total
and in-memory connection gates share one deadline instead of each receiving a
fresh timeout budget. Ordinary in-memory waiters stay outside the connection
FIFO, so an accepted durable-progress waiter receives the next connection.
Reply and dispatch claim, the point reads needed by those workers, completion,
recovery, and explicit manual-flush finalization use this progress class. An
in-memory store has an additional single-connection async gate before work
enters Tokio's blocking pool.

The acquired permits move into `spawn_blocking` and remain held across file
connection open/drop, SQLite busy waits, and the complete transaction. Aborting
the async caller does not return capacity while its blocking closure is still
running. Provider and connector calls happen outside SQLite transactions and do
not hold an operation permit while awaiting an external system. Saturated
business requests return `503 sqlite_operation_capacity_exceeded`,
`Retry-After: 1`, and `Cache-Control: no-store`. `/health/live` never opens
SQLite; `/health/ready` returns a redacted `503` when it cannot enter the
operation gate. Internal reply/dispatch progress retries only this transient
capacity error with a fixed bounded delay, retaining an already-produced
provider/connector result until its idempotent finalization commits. Repeated
worker wakeups are coalesced into at most one running worker and one pending
drain cycle instead of spawning mutex waiters without a bound.

To exercise the local connectors, use a separate database and explicit fixed
roots. The marker caller cannot choose a path. `workspace_list_directory`
lists at most 64 sorted entries from one canonical relative directory.
`workspace_find_paths` finds at most 32 regular files using a relative glob;
`*`, `?`, and character classes stay within one path component while `**`
matches complete path components. Its deterministic traversal is bounded by
directory, file, entry, depth, and result limits.
`workspace_search_text` searches literal text deterministically below one such
directory, retaining at most 32 matches while bounding directories, files,
depth, per-file bytes, and total bytes; it skips `.git`, `.svelte-kit`, `.zeus`,
`node_modules`, `target`, and `dist`. `workspace_read_file` reads at most 8 KiB
from one canonical relative UTF-8 regular file. `workspace_read_lines` reads an
inclusive range of at most 200 lines from a UTF-8 regular file of at most 64
KiB and rejects a selected range larger than 8 KiB instead of clipping it.
`workspace_replace_text`
atomically replaces exactly one unique occurrence in an existing UTF-8 regular
file of at most 64 KiB, preserves file permissions, and requires owner approval
for its exact persisted arguments. `workspace_insert_text` inserts at an exact
logical line boundary (`after_line=0` means the beginning), preserves file
permissions, atomically rejects a changed target, limits inserted text to 4
KiB and the result to 64 KiB, and requires owner approval. A final newline
defines a trailing empty logical line consistently for line reads and inserts.
`workspace_create_file` creates one UTF-8
file of at most 12 KiB below an existing directory, publishes it atomically,
never overwrites an existing path, and also requires owner approval for the
exact persisted arguments. Same-process mutation retries replay a bounded
recent receipt; a changed target or reused call ID with a different tool or
arguments fails closed. All workspace tools reject traversal and never follow
symlinks. None of these connectors can invoke a host command:

```sh
ZEUS_DATABASE_PATH=.zeus/local-development.db \
ZEUS_LISTEN_ADDR=127.0.0.1:8081 \
ZEUS_DEMO_PROFILE=local-development \
ZEUS_LOCAL_MARKER_ROOT=.zeus/local-markers \
ZEUS_LOCAL_WORKSPACE_ROOT=. \
cargo run -p zeus-api
```

Approve `APR-DEV-1` in the Web UI. A successful result creates exactly one
server-named JSON marker below `.zeus/local-markers`; rejecting creates none.
Do not point both profiles at the same database—the profile and primary
Session/Run identity check fails closed when they disagree.

The current vertical slice does not need external infrastructure. To inspect
the future Restate and MinIO topology separately, run:

```sh
docker compose --profile infra up -d
```

Infrastructure management ports bind only to `127.0.0.1`:

| Service          | Address                 |
| ---------------- | ----------------------- |
| Restate ingress  | `http://127.0.0.1:8080` |
| Restate admin/UI | `http://127.0.0.1:9070` |
| MinIO API        | `http://127.0.0.1:9000` |
| MinIO console    | `http://127.0.0.1:9001` |

PostgreSQL is an optional, non-authoritative adapter target:

```sh
docker compose --profile postgres up -d postgres
```

### Docker Compose full mode: applications and infrastructure

```sh
docker compose --profile full up --build
```

Open `http://127.0.0.1:8088`. Caddy is the only application entry point in
this mode. The API stores SQLite files under `/var/lib/zeus` in the dedicated
`zeus_data` named volume. Rust uses `cargo-watch`, Vite uses HMR, the repository
is bind mounted, and dependency/build caches use separate named volumes.

Compose statically wires CPU, memory, and PID ceilings for the API, Web, and
gateway through `ZEUS_COMPOSE_{API,WEB,GATEWAY}_{CPUS,MEMORY,PIDS_LIMIT}`.
The checked-in API defaults are 4 CPUs, 4 GiB, and 512 PIDs because `full` runs
the `cargo-watch` development image and may compile Rust. These limits are a
developer-machine safety boundary, not a production runtime capacity or OOM
benchmark.

Host fast mode and full container mode intentionally use different databases.
They do not mirror state. Compose project names also scope volumes, so two
different `COMPOSE_PROJECT_NAME` values produce isolated Zeus stores.

The containerized local executor is opt-in and should use an isolated Compose
project/database:

```sh
COMPOSE_PROJECT_NAME=zeus-local \
ZEUS_DEMO_PROFILE=local-development \
ZEUS_DATABASE_PATH=/var/lib/zeus/local-development.db \
docker compose --profile full up --build
```

Its marker root defaults to `/var/lib/zeus/local-markers` inside the dedicated
`zeus_data` volume. The normal Compose defaults remain `production-guarded`.

### Linux Docker release-runtime acceptance

The authoritative Linux resource gate uses the independent
`compose.linux-acceptance.yaml`, not the development `full` profile. It builds
the API and Web `runtime` targets plus the checked-in Caddy image, publishes
only a dynamic loopback gateway port, and creates a one-run SQLite volume and
two internal networks. Every service has an exact CPU, memory, no-swap, and PID
ceiling together with a read-only root, all capabilities dropped,
`no-new-privileges`, a non-root runtime user, and `restart: "no"`.

On a Linux Docker Engine with cgroup v2:

```sh
scripts/linux-container-acceptance.sh config
scripts/linux-container-acceptance.sh run
```

The live verifier safely consumes a fresh owner token, checks two concurrent
Argon2 paths, settles a durable local-fallback turn, runs bounded readiness
pressure, samples all three services before/during/after it, and recreates the
stack while retaining its SQLite volume. Fresh and restarted cgroups must begin
with zero OOM/OOM-kill/PID-max/swap counters. It rejects any response other than
`200` or a `503` carrying `sqlite_operation_capacity_exceeded`, and fails if any
service records OOM/PID exhaustion, transport errors, an unexpected restart, or
resource drift. The fixed normal profile is API/Web/gateway at
2/1/0.5 CPUs, 1 GiB/512 MiB/128 MiB, and 128/128/64 PIDs; CI reuses the same
source-bound images for the fixed 1/0.5/0.25 CPU, 256/256/64 MiB, and 64/64/32
PID low-memory profile. Both disable container swap.

The generated evidence is written under `.zeus-linux-acceptance/` without
bootstrap tokens, passwords, cookies, CSRF tokens, provider keys, or complete
API logs. Authoritative runs require a clean worktree, validate commit/tree/role
image labels, fail closed on teardown or evidence finalization errors, and hash
the stable bundle including `run.log`. The current gate does not run a
disposable OOM/PID negative-control container; its result is evidence that the
Zeus services stayed inside their enforced cgroup v2 envelopes, not a separate
calibration of deliberate runner limit violations. See
[`docs/linux-container-acceptance.zh-CN.md`](docs/linux-container-acceptance.zh-CN.md)
for the exact contract. This workstation has no Docker CLI, so the automation
is statically checked here but the Linux live gate remains pending until its
CI or controlled-run evidence passes.

### Apple container mode: runtime images on macOS

The Apple helper builds the same non-root API and Web runtime stages, then runs
only API, Web, and gateway containers. It does not start the Compose-only
Restate, MinIO, PostgreSQL, debug, or sandbox services:

```sh
scripts/apple-container.sh build
scripts/apple-container.sh up
scripts/apple-container.sh verify
scripts/apple-container.sh restart-verify
```

Use `status`, `logs api|web|gateway`, and `down` for routine operation. The
defaults are:

- project `zeus-alpha`;
- gateway publish target `http://127.0.0.1:18088`; API and Web remain private
  to the project network, so Caddy is the only application entry point;
- containers `zeus-alpha-api`, `zeus-alpha-web`, and
  `zeus-alpha-gateway`, network `zeus-alpha-net`, and persistent volume
  `zeus-alpha-data` mounted at `/var/lib/zeus`;
- the `production-guarded` profile. This helper does not enable the local
  marker executor.

The release API VM defaults to two CPUs and 1 GiB and can be changed with
`ZEUS_CONTAINER_API_CPUS` and `ZEUS_CONTAINER_API_MEMORY`; the helper verifies
the effective values reported by `container inspect`. Run
`scripts/apple-container.sh resources` for a read-only snapshot of inspect,
cgroup v2 CPU/memory/swap/PID counters, selected `/proc/meminfo`, process RSS/
high-water marks, and `smaps_rollup`. Apple `container` 1.0 exposes no
per-container PID-limit option, so the reported `pids.max` is evidence about
that running VM, not a configured guarantee.

Every resource managed by the helper carries
`dev.zeus-harness.managed=true` and a matching
`dev.zeus-harness.project` label. Name collisions with foreign or unlabeled
resources fail closed. `down` removes only owned containers and the owned
network; it retains the data volume. Reset requires the exact volume name:

```sh
ZEUS_CONTAINER_CONFIRM_RESET=zeus-alpha-data \
scripts/apple-container.sh reset
```

When `ZEUS_CONTAINER_PROJECT` changes, the confirmation value must change to
that project's `${project}-data` volume as well.

`verify` and `restart-verify` prefer the gateway's current container IP and
fall back to the published loopback URL. `status` prints both. This keeps the
stack usable on Apple Container releases affected by the reported
[localhost forwarding reset](https://github.com/apple/container/issues/1702):
open the printed `gateway direct URL` when the published URL is unavailable.
All local probes bypass proxy environment variables and have bounded connect
and response timeouts.

`verify` checks the Web/API/gateway paths, the public auth status contract, and
that an anonymous request cannot reach the protected overview. Because the
helper does not retain an owner's password, `restart-verify` checks that the
configured/unconfigured owner state survives named-volume recreation; the
authenticated ledger and reply flow are covered by host and storage tests.

For image builds, the helper copies a filtered context to a physical path under
the repository and removes it afterward. This avoids Apple's reported
[empty temporary build context](https://github.com/apple/container/issues/2037)
while the upstream [symlink-prefix fix](https://github.com/apple/container/pull/2124)
is unresolved. The helper uses BuildKit cache mounts and never copies `.git`,
local databases, dependencies, or build output into that context.

### Debug mode

The debug overlay is deliberately separate because it grants `SYS_PTRACE` and
uses an unconfined seccomp profile for the Rust container:

```sh
docker compose -f compose.yaml -f compose.debug.yaml --profile debug up --build
```

- Rust `gdbserver`: `127.0.0.1:2345`; the API waits for a debugger.
- Node inspector: `127.0.0.1:9229`.
- Direct debug endpoints: Rust `127.0.0.1:8081`, Web `127.0.0.1:3000`.

These permissions and ports are absent from `infra` and `full`. Published debug
ports still bind only to loopback.

### Sandbox profile

The initial sandbox profile supplies a networkless, read-only Alpine shell with
all Linux capabilities dropped. It is a development security envelope, not a
working Zeus tool executor:

```sh
docker compose --profile sandbox run --rm --no-deps tool-sandbox sh
```

It has no Docker socket, no network, a 64 MiB `noexec` temporary filesystem,
and bounded memory, CPU, and PID resources.

## Persistence contract

- Session and Run each have their own contiguous sequence and append-only
  ledger. Their sequence numbers order replay within that ledger only and must
  not be compared with each other or used as idempotency keys.
- Authenticated Session creation writes the owner, projection,
  `session_created` event, and actor-scoped response receipt in one
  `BEGIN IMMEDIATE` transaction.
- Starting a turn requires the expected Session sequence. It atomically creates
  the open turn, appends `user_message`, advances the Session to `running`,
  stores the actor-scoped response receipt, creates the durable Agent state,
  binds that Agent to one canonical, secret-free deployment manifest, and
  enqueues its first immutable model job.
  That work contains a bounded provider request whose first and only system
  message is the exact manifest-bound prompt, followed by complete historical
  turns through the submitted sequence and the new user message; interrupted
  or otherwise unflushed turns never enter model context.
- The deployment manifest fixes the profile, environment, provider/model
  identity, policy revision, workflow limits, prompt ID/revision/content digest,
  and exact versioned tool contracts used for the turn. The prompt content is
  not copied into the secret-free manifest; it is persisted in the immutable
  model request so the provider-visible input is reconstructable. Admission,
  claim, tool continuation, and deep-integrity verification all require one
  first-position system message whose content matches the manifest digest, and
  the complete typed transcript/message/content envelope must be executable.
  Model requests derive their visible tool list from that same manifest.
  Invalid prompt or tool authority at admission rejects and rolls back the
  complete command. Before already queued model or tool work can reach an
  external provider/executor, a durable `prepared` claim compares the persisted
  digest and binding with the current runtime without authorizing external I/O.
  The same worker can recover that exact claim after a transient storage error;
  an expired prepared claim advances to a new generation while the operation
  remains queued. Missing, corrupted, promptless, or drifted queued authority
  settles durably as `deployment_unavailable` with zero external calls.
- The model worker atomically advances the exact prepared claim and its
  RunEpoch/workflow fact/job to `started` before calling a provider.
  Final text atomically stores the assistant message, appends
  `assistant_message` and `turn_flushed`, and returns the Session to `ready`.
  A tool proposal is matched against the server registry and current policy;
  one immutable call is either queued, held for owner approval, or recorded as
  a known policy-denied result before the next model step.
- The tool worker rechecks the persisted descriptor, policy revision,
  authority, and approval after its `started` checkpoint. A known connector
  result and the next immutable model request commit in one transaction. The
  continuation preserves the exact persisted prompt and transcript instead of
  resolving current prompt content or rebuilding model input. If the bounded
  continuation cannot be represented, the known result remains known and the
  Agent fails as `continuation_unavailable`; it is never rewritten as
  `outcome_unknown`.
- Queued Agent jobs survive restart and remain claimable. Startup expires
  prepared-only claims without writing `outcome_unknown`, because they never
  authorized external I/O. A model or tool already marked `started` moves to
  `needs_attention` exactly once and is never automatically replayed because
  the external call may have taken effect.
  Other open turns follow the same interruption/resume contract.
- Session commands do not change the Run ledger or wake the dispatch worker.
  Session and Run are joined by durable ownership, not by sharing an event
  sequence or transaction stream.
- Run projection, versioned event payload, and the first Run command response
  are written in one SQLite transaction.
- Reusing an idempotency key with the same command input replays the stored
  response; reusing it with different input is a conflict. Session
  `expected_sequence` and Run head compare-and-swap arbitrate different keys
  racing on the same resource.
- Every production Session/Run read, command, event replay, and receipt lookup
  is actor-scoped in the same SQLite query or transaction. Authorization runs
  before receipt replay, and a missing or unowned resource has the same 404
  surface.
- Approval is bound to one call ID, argument digest, policy revision, sandbox,
  and `allow_once` scope. Approve atomically appends the decision and enqueues
  that exact immutable dispatch job; reject enqueues nothing. Before any new
  job is admitted, storage also reloads the durable requested call and bound
  runtime identity in the same transaction. A mismatched policy, tool contract,
  argument object, digest, or sandbox therefore cannot occupy the queue head or
  its terminal reservation.
- A worker commits `ToolDispatchStarted` before invoking a connector. A queued
  job can resume after restart; a started job without a durable result becomes
  `outcome_unknown` and is never retried automatically.
- The legacy reply worker observes the queued head without mutation, then
  retains that exact job ID while retrying its atomic `started` transition.
  An ambiguous database acknowledgement can therefore replay only the same
  start; it cannot skip to another reply or cause a second provider call.
- Reply and dispatch claims revalidate the approving actor's current status,
  role, and resource ownership. Revoked work is durably rejected with
  `authorization_revoked` evidence before any provider or connector can see
  it; the Run or Session moves to `needs_attention`.
- Events become visible to live subscribers only after the transaction commits.
  Process-local broadcast is a latency hint; SSE also polls the durable ledger
  every two seconds from its last sequence cursor so a missed hint cannot leave
  the stream permanently behind. Authenticated streams revalidate the login
  session on each wake/poll and close after logout, expiry, or disablement.
- Unknown event kinds or payload versions fail closed during recovery.
- SQLite runs with foreign keys, a busy timeout, WAL for file databases, and
  full synchronous durability.
- A file-backed database acquires an OS-level exclusive lease on the adjacent
  `.zeus.lock` sidecar before migration and holds it until the final store
  clone drops. A competing Zeus process fails startup before recovery.
- SIGINT or SIGTERM first starts graceful HTTP draining, then closes any
  remaining long-lived SSE connection after five seconds. This bound ensures
  every store clone and the SQLite lease are released during container stop.
- Schema v4 adds durable Sessions and their ledger. Schema v5 adds local users,
  auth sessions, owner references, bootstrap credentials, and preferences;
  v6 migrates command receipts to actor scopes; v7 adds the forward-only reply
  queue; v8 binds each dispatch to its approving actor and adds owner-consistency
  triggers plus a durable authorization-revoked terminal state. Schema v9 adds
  typed, immutable Run-event lookup projections, point-query indexes, contiguous
  Run-event insertion enforcement, and fixed 64-row startup-recovery batches.
  Schema v10 adds owner/global row and active-work admission limits, durable
  Session-turn and dispatch event-slot reservations, bounded expired-auth-session
  cleanup, and readiness checks for reservation ownership and lifecycle. Schema
  v11 adds exact Session/Run/global logical event-payload byte counters and
  conservative terminal byte reservations, with migration backfill and trigger-
  enforced accounting over the stored UTF-8 JSON. Schema v12 gives bootstrap
  credentials ordered lifecycle reasons and a bounded detailed audit window;
  rotation and startup compaction preserve a monotonic digest rollup and no
  longer brick an unconfigured instance when detailed history reaches its cap.
  Schema v13 adds the deterministic `acc_local` account, enrolls only the
  existing active owner as revision-1 membership, and backfills immutable
  account scope onto Incident, Session, Run, and runtime identity. Ambiguous
  legacy owner/actor/scope or broken foreign-key state aborts v12-to-v13
  migration before partial account state can commit. Schema v14 rebuilds login
  sessions, receipts, reply/dispatch jobs, and finalization reservations around
  `(account, actor, membership revision)` authority. It removes legacy owner
  checks from authorization, scopes cursors and active-work capacity by account
  and actor, and revalidates both dispatch subjects before worker claim. The
  product-level member login gate remains closed in v14. Schema v15 adds
  one-time member setup tokens, revisioned lifecycle transitions, account audit
  state, and the final capability-gated member surface. Schema v16 adds the
  partial Session-event index used to read only the newest complete reply
  context pairs at an immutable ledger boundary. Schema v17 adds the
  Session-native Agent state, model jobs, sequential tool calls, approval
  receipts, fixed loop limits, and bounded terminal-event replay indexes.
  Schema v18 binds every known tool completion to its exact next-request JSON,
  including the distinction between SQL `NULL` and model-visible JSON `null`,
  so continuation replay cannot silently change after a restart. Schema v19
  stores immutable canonical deployment manifests and binds every newly
  admitted Agent turn to one digest; pre-v19 terminal history remains readable,
  while legacy queued work fails closed at claim instead of running under an
  unproven deployment. Schema v20 adds immutable RunEpoch authority and an
  Agent-local hash-chained execution-fact ledger. Schema v21 adds append-only,
  generation-ordered prepared/start claims for model and tool operations;
  prepared claims are safely recoverable, while started claims are released
  only by a durable terminal result or conservative restart recovery. Schema
  v22 binds every new Agent to an immutable account-scoped knowledge corpus,
  deterministic selection snapshot, canonical context, initial model job, and
  execution-origin fact. The exact pre-v22 Agent set is sealed during migration
  by a domain-separated count+digest commitment; unbound legacy work remains
  readable but cannot execute. Schema v23 adds an owner-governed, revisioned
  account knowledge catalog, immutable ingestion receipts, and a bounded active
  corpus projection consumed by every newly admitted owner or member Agent.
  Schema v24 adds an owner-governed account Agent prompt with immutable
  content-addressed revisions, CAS/idempotency receipts, bounded history, and
  account audit. Revision zero preserves the exact original built-in prompt and
  manifest revision `1`; the first custom revision binds manifest revision `2`.
  Existing Agents retain their immutable manifest/request. Queued work whose
  governed prompt is no longer active fails closed before provider or tool I/O.
  Existing Runs and events are decoded, validated, and migrated in place without
  rewriting their payloads. Runtime identity still binds profile, environment,
  primary Session and Run, policy ID, and policy revision; a mismatch fails
  startup.

Dynamic knowledge remains separate from the governed prompt contract. Knowledge
v1 validates immutable entry revisions, ranks them with a fixed integer/tokenizer
contract, drops whole entries at a 16 KiB context boundary, and emits a canonical
digest-bearing selection snapshot. Schema v22 persists the exact corpus,
snapshot, canonical context, Agent/job binding, and execution admission digests;
replay never reselects from live state. The provider contract carries the
context as a distinct durable `context` role, mapped to a separate `user`
message only at the OpenAI-compatible wire boundary. Schema v23 exposes the
account catalog through an owner-only ingestion API. Revision zero is an
implicit empty corpus; after the first committed replacement, Agent admission
selects from the active durable revision and still persists the exact corpus and
selection snapshot, so later catalog updates cannot rewrite an existing turn.
Schema v24 governs the system prompt independently from knowledge. New Agent
admission reads the active prompt, binds only its ID/revision/content digest in
the secret-free manifest, and persists the exact content in the immutable model
request. Prompt changes never rewrite an existing Agent or its transcript.

SQLite is the authoritative store for this local single-instance Alpha. Do not
place it on NFS or share one database volume between multiple Zeus replicas.
Competing local processes fail closed; coordinated multi-instance ownership and
PostgreSQL are later milestones.

When upgrading from a build that predates the `.zeus.lock` lease, stop every old
Zeus process before starting the new binary. The lease is advisory for Zeus
processes and does not prevent an unrelated program from opening SQLite
directly.

## HTTP contract

- `GET /health/live` and `GET /health/ready` are public. The remaining public
  surface is limited to `GET /api/v1/auth/status`, first-owner
  `POST /api/v1/auth/bootstrap`, `POST /api/v1/auth/login`, and one-time
  `POST /api/v1/auth/member-setup` (with `/api/auth/member-setup` as a
  compatibility alias).
- Bootstrap and login require an exact same-origin `Origin`/`Host` pair. A
  successful bootstrap or login issues an opaque `HttpOnly; SameSite=Strict`
  login cookie plus a separate CSRF cookie. When the browser-facing origin is
  HTTPS, the operator must set `ZEUS_COOKIE_SECURE=true`; then both cookies are
  emitted with `Secure`.
- Bootstrap, login, and member setup are charged before Argon2 work against bounded, in-memory
  fixed-window limits. Login defaults to 60 attempts globally, 10 per direct
  peer IP, and 5 per canonical account per minute; bootstrap defaults to 10
  globally and 3 per direct peer IP; member setup defaults to 30 globally and
  5 per direct peer IP. Zeus ignores `Forwarded` and
  `X-Forwarded-For` unless a future explicit trusted-proxy contract is added.
  Rejection is a generic `429` with `Retry-After` and `Cache-Control: no-store`.
- Every business REST/SSE route requires an active durable account membership.
  Protected state changes additionally require `X-CSRF-Token` to match the
  login and an exact same-origin request. Members may read and write Account
  Session/Run state and use the reply provider; approval/dispatch, member
  administration, and account-audit routes require owner capability. Actor
  isolation, SQLite physical headroom, bounded bootstrap/account audit
  retention, durable authorization, and member revision revocation are
  enforced below HTTP.
- An owner creates a member through `POST /api/v1/members`; the plaintext setup
  token appears only in that response, expires after 24 hours, and is stored by
  Zeus only as a domain-separated SHA-256 digest. The single-use
  `POST /api/v1/auth/member-setup` endpoint consumes it while setting the
  password and issuing the login session. Member lifecycle and audit
  administration are owner-only and return `Cache-Control: no-store`.
- Active Run/Session SSE connections revalidate durable account authority at
  most two seconds apart and close after disable, role revision, or session
  revocation. Middleware is only an entry filter: storage and worker claim
  transactions still revalidate account, actor, revision, and capability.
- Owner-only `GET/POST /api/v1/members`, `PATCH /api/v1/members/{user_id}`,
  and `POST /api/v1/members/{user_id}/setup-token` provide bounded keyset
  listing, optimistic membership revisions, last-owner protection, token
  rotation, and a response listing work already claimed before disable.
- Owner-only `GET /api/v1/audit/events`, `GET /api/v1/audit/export`,
  `GET/PUT /api/v1/audit/policy`, and
  `POST /api/v1/audit/archive/checkpoint` expose bounded account audit state.
  The NDJSON export is fully collected and validated before its `200` response
  and fails above 96 MiB; a checkpoint is an operator assertion, not proof that
  an external archive exists.
- Owner-only `GET/PUT /api/v1/knowledge/catalog` reads or atomically replaces
  the active account corpus. `PUT` accepts `expected_revision` and validated
  immutable `entries`, requires a canonical `Idempotency-Key`, and returns the
  committed catalog revision plus `replayed`. Stale revision returns
  `409 knowledge_catalog_revision_conflict`; the same key with different input
  returns the normal idempotency conflict. Ordinary members cannot administer
  the catalog, but their newly admitted Agents read its active corpus.
- Owner-only `GET /api/v1/knowledge/catalog/revisions` returns newest-first
  bounded revision summaries using an exclusive `before_revision` boundary;
  `GET /api/v1/knowledge/catalog/revisions/{revision}` returns the exact
  immutable corpus, including the implicit empty revision `0`. Recovery never
  rewrites history: read the desired historical corpus, then submit its
  `entries` through the existing CAS `PUT` to create a new catalog revision.
  Both history routes send `Cache-Control: no-store`.
- Owner-only `GET/PUT /api/v1/agent/prompt` reads or atomically replaces the
  active account Agent system prompt. `PUT` requires `expected_revision` and a
  canonical `Idempotency-Key`; content is non-empty, control-safe, and capped at
  16 KiB. Stale CAS returns `409 agent_prompt_revision_conflict`. Responses use
  `Cache-Control: no-store`; ordinary members cannot administer the prompt, but
  their new Agents use the current owner-governed revision.
- Owner-only `GET /api/v1/agent/prompt/revisions` returns newest-first bounded
  revision metadata, and `GET /api/v1/agent/prompt/revisions/{revision}` returns
  the exact content, including built-in revision `0`. Recovery reads the desired
  historical content and submits it through the existing CAS `PUT`, creating a
  new head instead of rewriting immutable history.
- `GET /api/v1/me/settings` returns the current safe preferences.
  `PATCH /api/v1/me/settings` accepts `theme`, optional allowlisted
  `preferred_model`, and `expected_revision`. Provider endpoints and API keys
  are server-only configuration and never cross this API.
- `GET /api/v1/overview` returns `primary_session_id`, the current profile's
  primary Run, and the latest 128 Run events with opaque backward-pagination
  metadata. Older Run history remains available through Run detail.
- `GET /api/v1/sessions` lists Session summaries in stable
  `updated_at DESC, id ASC` order. `limit` defaults to 50 and is capped at 100;
  the response body remains a bare JSON array, while `X-Zeus-Next-Cursor`
  carries the opaque continuation cursor when another page exists.
  `POST /api/v1/sessions` creates one from `{"id":...,"title":...}` and
  returns `201` for both the first committed response and an idempotent replay.
- `GET /api/v1/sessions/{session_id}` returns its current summary plus bounded,
  independently pageable tails of attached Run IDs, turns, and ordered Session
  events. Run-ID and turn pages default to 50 and are capped at 100; event pages
  default to 128 and are capped at 256. The optional `pagination` object returns
  scoped opaque `next_before` cursors and `has_more` for each collection.
- `GET /api/v1/sessions/{session_id}/turns/{turn_id}` performs one
  actor-scoped point lookup. The Web client uses it to settle a durable retry
  identity when that turn is older than the bounded detail tail.
- `POST /api/v1/sessions/{session_id}/turns` accepts
  `{"turn_id":...,"user_message":...,"expected_sequence":...}`, atomically
  persists the user turn and durable Agent entry job, and returns `202`. The
  server-side workers later commit either the assistant reply, a pending tool
  approval, or an explicit interrupted/needs-attention event through Session
  SSE.
- `GET /api/v1/sessions/{session_id}/turns/{turn_id}/agent` returns the
  actor-scoped durable Agent state, deployment-manifest digest, and ordered
  tool calls.
- `GET /api/v1/sessions/{session_id}/turns/{turn_id}/agent/explain` returns the
  actor-scoped persisted and current secret-free manifests plus a deterministic
  JSON-pointer diff. It explicitly marks pre-v19 unbound history and whether
  the current runtime can execute the exact persisted deployment.
- `GET /api/v1/sessions/{session_id}/turns/{turn_id}/agent/knowledge/explain`
  returns the exact persisted selection snapshot and its binding, corpus,
  query, snapshot, and context digests with `Cache-Control: no-store`. It does
  not return unselected account-corpus entries; frozen pre-v22 history is
  reported as `legacy_unbound` with no fabricated context.
- `POST /api/v1/sessions/{session_id}/turns/{turn_id}/approvals/{call_id}/decision`
  lets an owner approve the exact persisted call or reject it as a structured
  model-visible result. The decision is idempotent and never accepts a
  client-supplied continuation transcript.
- Browsers cannot submit assistant content. The legacy
  `POST /api/v1/sessions/{session_id}/turns/{turn_id}/flush` route exists only
  in a private `#[cfg(test)]` contract router that bootstraps a real test owner;
  it is absent from the production server.
- `POST /api/v1/sessions/{session_id}/resume` accepts
  `{"expected_sequence":...}` and only resumes a Session in
  `needs_attention`.
- `GET /api/v1/sessions/{session_id}/events?after={sequence}` streams
  `session.event` SSE from the independent Session ledger.
- `GET /api/v1/runs/{run_id}` returns one Run projection plus a bounded ordered
  event tail. `events_limit` defaults to 128 and is capped at 256;
  `events_before` accepts the resource-scoped opaque cursor returned in
  `pagination.events`.
- `GET /api/v1/runs/{run_id}/events?after={sequence}` streams Run SSE. For both
  feeds, `Last-Event-ID` takes precedence over the query cursor when present.
  Run and Session streams share a limit of 64 open connections globally and 4
  per authenticated actor; the lease remains held until the response body is
  closed. Initial replay, broadcast reconciliation, lag recovery, and durable
  polling read at most 128 events per SQL `LIMIT + 1` page, then continue
  cooperatively without moving the cursor past an event actually sent. A
  malformed, duplicate, or out-of-range cursor returns `400`; an authenticated
  cursor ahead of the durable head returns `409`, while masked resources remain
  `404`.
- `POST /api/v1/runs/{run_id}/approvals/{approval_id}/decision` accepts
  `{"decision":"approve|reject","note":...}` and requires an
  `Idempotency-Key` header. Approval identity comes from the path, not a caller-
  selected tool payload.
- Session creation, turn start, resume, and approval-decision commands require
  exactly one canonical `Idempotency-Key`: 1–128 ASCII graphic bytes, with no
  trimming or reinterpretation. Authentication/logout and optimistic settings
  updates use their own replay/concurrency rules. Member setup/admin and audit
  mutations do not implement HTTP idempotency receipts and explicitly reject
  `Idempotency-Key` as `400 idempotency_not_supported`. A lost member-create
  response is recovered by listing the pending member and rotating its setup
  token. Malformed input returns 400,
  oversized JSON returns 413, a wrong content type returns 415, schema mismatch
  or unknown fields return 422, and capacity/rate rejection returns 429.
  Knowledge catalog replacement is the exception among owner administration
  commands: it has its own durable idempotency receipt. Durable capacity
  problems use `storage_quota_exceeded`,
  `reply_queue_capacity_exceeded`, `dispatch_queue_capacity_exceeded`, or
  `auth_session_capacity_exceeded` with `Cache-Control: no-store`; reply and
  dispatch queue responses also return `Retry-After: 2`.
  Missing or unowned resources return 404; unauthenticated requests return 401;
  CSRF/origin rejection returns 403; duplicate identity, idempotency conflict,
  invalid state, or sequence conflict returns 409 as
  `application/problem+json`. Member and audit conflicts use
  `member_already_exists`, `member_setup_not_pending`,
  `audit_policy_revision_conflict`, or `audit_checkpoint_conflict` as
  applicable. Audit ordinary-capacity exhaustion returns
  `507 audit_storage_exhausted` and never commits the partially audited
  mutation; a complete export that would exceed the response bound returns
  `507 audit_export_too_large` instead of a truncated `200`.
- Internal execution-invariant failures return a stable, redacted
  `500 runtime_unavailable`. Storage, policy-build, connector-configuration, or
  registry unavailability returns a redacted `503 runtime_unavailable`.
  Internal details remain in server logs.

Current schema v24 retains durable Run attachment during migration and demo
seeding, but Alpha+ does not expose a public attach-Run HTTP route.

The application boundary now caps auth JSON at 8 KiB, command JSON at 512 KiB,
and knowledge-catalog JSON at 2 MiB plus 4 KiB of request-envelope headroom.
Agent-prompt JSON is capped at 100 KiB so escaped JSON can still represent the
full validated 16 KiB decoded prompt; the larger transport cap does not enlarge
the stored or model-visible prompt limit.
Newly created Session and turn IDs are capped at 128 UTF-8 bytes;
Session titles at 256 bytes; user and assistant messages at 64 KiB; and review
notes at 8 KiB. A typed reply response is capped at 512 KiB; provider, model,
finish-reason, failure-code, and tool digest/code fields are capped at 128
bytes; reply/tool diagnostics at 4 KiB; compact tool output and dispatch
argument JSON at 64 KiB. Agent tool arguments use the stricter 16 KiB reserved
loop budget. Provider and executor over-limit results settle once
as fixed, bounded durable failures; the rejected payload is never copied into
the ledger or job result.
New Session event IDs are ledger-local and bounded. Historical v8 durable IDs
remain addressable so the stricter write envelope does not strand existing
data. Shared validation runs before command fingerprinting or receipt lookup at
the relevant API/runtime/storage entry points. Event feeds use bounded pages;
approval, dispatch, reply completion, attachment checks, and startup recovery
use typed point queries or fixed 64-row batches. Production Session list/detail,
Run detail, and overview reads now use indexed `LIMIT + 1` keyset pages inside
actor-authorized SQLite snapshots; no production HTTP read loads a complete
ledger or collection. Current schema v24 retains bounded Session, open-turn,
active reply/dispatch, auth-session, bootstrap-audit, event-slot, and logical
event-payload-byte admission. Exact idempotent replay is checked before capacity,
while accepted work consumes its reserved terminal slots and payload bytes
without ordinary admission. Parent-ledger and global counters are charged by
SQLite triggers from the exact stored UTF-8 `payload_json`; migration backfills
existing bytes and conservatively reserves active work so historical databases
can still drain even when they exceed a newly configured limit. Expired auth
sessions and sessions bound to missing, disabled, suspended, or stale-revision
authority are deleted in deterministic batches of at most 64 on startup and
before session creation. Append-only ledgers, receipts, jobs, and turns are not
silently pruned. Bootstrap-token and account-audit details follow their explicit
bounded rollup policies; account audit additionally supports legal hold and an
owner-recorded external archive checkpoint. The locally verified Physical Capacity Slice
now gates the main DB, active-WAL target, and filesystem headroom, subject to
the documented WAL and `statvfs` limitations. Bounded SQLite operation
concurrency is also implemented. Schema v15 builds on account-scoped
receipt/job/auth/cursor/capacity authorization with one-time member setup,
revisioned lifecycle transitions, SSE revocation, dual-subject worker claims,
and count-bounded account audit. Shared-network and multi-tenant deployment is
still out of scope.
The earlier Operation Capacity Apple readiness-pressure scenario and historical
schema-v14 retained-volume migration/restart passed as separate gates; the v14
image did not rerun that pressure workload. Current v15 retained-volume and
fresh small-capacity Apple acceptance also passed; authoritative Linux Docker
PID/OOM and adversarial low-memory acceptance remain separate deployment gates.

## Container images

The Rust and Web Dockerfiles are shared by Docker Compose and Apple
`container`. They contain `dev`, `debug`, builder, and non-root `runtime`
stages:

```sh
docker build -f infra/docker/rust.Dockerfile --target runtime -t zeus-api:local .
docker build -f infra/docker/web.Dockerfile --target runtime -t zeus-web:local .
```

The Rust runtime creates `/var/lib/zeus` for its non-root user. The Web runtime
serves SvelteKit's Node adapter output from `apps/web/build`.

## Operations

Inspect resolved configuration without starting anything:

```sh
docker compose --profile full config
docker compose -f compose.yaml -f compose.debug.yaml --profile debug config
```

Stop containers while retaining all named volumes, including `zeus_data`:

```sh
docker compose --profile full down
```

To reset host fast-mode state, first stop the API and remove only these files:

```sh
rm -f .zeus/zeus.db .zeus/zeus.db-wal .zeus/zeus.db-shm
```

Compose state lives in named volumes and needs a separately scoped reset.
Do not use `docker compose down -v` as a Zeus reset: it also deletes unrelated
Restate, MinIO, cache, and optional PostgreSQL volumes. Resolve the active
Compose project name and delete only its logical `zeus_data` volume while the
API is stopped.

Do not copy only a live `zeus.db` file for backup: WAL state may still contain
committed data. Use SQLite's backup/checkpoint facilities.

## Verification status

Current Alpha+ plus Actor Boundary Foundation, API Resource Envelope, Terminal
Payload Envelope, Bounded Event Feed, Point-query Durable Context, Bounded Read
Models, SQLite Capacity Slice 2, the SQLite Physical Capacity Slice, and the
SQLite Operation Capacity Slice, Bootstrap Audit Retention, schema v13 Account
Membership Foundation, schema v14 Account-scoped Durable Authorization, and
schema v15 Member Lifecycle / Account Audit, schema v16 Session Reply Context
Index, schema v17 Durable Session Agent Loop, schema v18 exact tool-completion
replay, schema v19 deployment-manifest binding, schema v20 execution-ledger,
schema v21 prepared claims, schema v22 durable knowledge-context binding, and
schema v23 account knowledge catalog ingestion, and schema v24 account Agent
prompt governance:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-targets --locked`: 565 tests passed
  under the existing project counting convention, including 18 connector tests,
  8 deployment tests, 29 knowledge tests, 248 storage tests, 48 runtime tests,
  71 API library tests, 6 API main/config
  tests, and the real
  child-process database lease and active-SSE SIGTERM checks, authentication,
  actor-scoped REST/SSE/receipt isolation, authorization-revoked queue claims,
  body/field/idempotency boundaries, atomic login limits, SSE lease capacity,
  bounded `LIMIT + 1` event pages and cooperative multi-page replay, durable
  reply provenance, typed v9 point lookups, a 16-way same-key review race,
  fixed-batch restart recovery, bounded 50/50/1 Session-list traversal,
  independent Session/Run history tails, actor/resource-scoped cursors, an
  old-turn point lookup for durable retry recovery, concurrent claim, and
  provider `outcome_unknown` semantics. Capacity coverage includes exact-limit
  and limit-plus-one admission, terminal event-slot and logical payload-byte
  reservation lifecycles, UTF-8 migration backfill, counter-integrity and
  `INSERT OR REPLACE` hardening, startup seed idempotency, over-limit legacy
  migration/recovery, bounded unusable-auth cleanup, fail-closed environment
  parsing, typed reply/tool
  payload envelopes, canonical dispatch admission, and one-shot oversized
  provider/executor settlement without persisting the rejected payload.
  Operation-capacity coverage proves the seven-slot ordinary lane, fail-fast
  general admission, one-deadline progress waiting, progress priority at the
  single-connection in-memory gate, cancellation and partial-permit cleanup,
  permit retention after caller abort, internal capacity-only retry, bounded
  worker wake coalescing, progress-waiter cancellation notification,
  provider/connector panic settlement as `outcome_unknown`, progress under
  general saturation, and the stable API `503` mapping contract.
  Bootstrap-audit coverage includes v11 migration with explicit unknown
  reasons, canonical digest vectors, multi-batch rotation and startup
  compaction, current-v12 limit reduction, wall-clock rollback, pre-write
  physical gating, trigger rollback, and deep-integrity corruption detection.
  Account-foundation and durable-authorization coverage includes
  fresh/v1/v5/v8/v12/v13 migration, the
  deterministic local account and owner membership, bootstrap atomicity,
  revision/identity/last-owner triggers, immutable root scope, deep-integrity
  corruption, account/actor cursor and receipt isolation, three-tier capacity,
  stale-session relogin, dual-subject dispatch, worker claim revocation, and
  fail-closed rollback without a partial v13 or v14 schema.
  Agent-loop coverage includes direct final replies, tool approval/rejection,
  policy denial, deterministic call identity, strict provider transcripts,
  the fixed 8-model-step/4-tool-call limits, 16 KiB arguments, 64 KiB individual
  results and 128 KiB aggregate results, scalar/array result replay, exact
  persistence retry without external re-execution, unavailable-continuation
  settlement, transient claim recovery without a lost worker wake, bounded
  terminal replay queries, one-shot restart settlement of started work,
  canonical secret-free manifests, actor-scoped explainability, exact
  provider-visible tools, completion replay binding, and fail-closed
  provider/tool/policy/profile drift, prepared-claim exact recovery and expiry,
  one RunEpoch per external start, no replay of started work, and exact replay
  or conflict detection for a committed dispatch terminal acknowledgement. The
  rooted workspace connectors additionally cover traversal, symlink, UTF-8,
  regular-file, 8 KiB file and 64-entry directory rejection, deterministic
  directory ordering, bounded path-glob and literal search, plus automatic
  find-to-read and search-to-read-to-model continuations through the real Agent
  worker chain. The exact text
  replacement path covers unique-match enforcement, atomic permission-preserving
  publication, bounded idempotent replay/conflict, deletion, size rejection,
  owner approval before the first byte changes, and exact result continuation.
- `pnpm --filter web test`: 28 tests passed for CSRF headers, stable command
  identity, deep-page active-Session restore, Session-list cursor encoding and
  deduplication, bounded-tail retry reconciliation and Session-switch race
  guards, primary-Run identity, Session event merging, and theme behavior.
- `pnpm --filter web check`: zero errors and zero warnings.
- `pnpm --filter web lint` and `pnpm --filter web build`: passed; the Node
  adapter production artifact was generated.
- Svelte autofixer reported no issues or suggestions for the changed login,
  sidebar, settings, header, timeline, and page components.

Live Alpha+ acceptance on the host covered first-owner setup, login/logout,
real Session creation and selection, refresh restore, dark mode, and a
server-side local-fallback reply delivered through the durable worker/SSE path.
The final API replay at `127.0.0.1:8081` committed a user message at sequence 2,
an `assistant_message` carrying `local-fallback/non_model_fallback` provenance
at sequence 3, and `turn_flushed` at sequence 4. Settings revision and revoked
session rejection were also verified. The page at `127.0.0.1:3001` had no
browser console errors.

Actor Boundary Foundation was additionally live-smoked against an isolated
schema-v8 database at `127.0.0.1:18081`: unauthenticated access returned `401`,
owner bootstrap returned `200`, Session creation returned `201`, turn enqueue
returned `202`, and the durable reply settled at sequence 4. Restarting the API
against the same database preserved the login, flushed turn, assistant
provenance, and ordered event ledger; an unknown or masked Session returned the
same `404` surface. Cross-owner transfer, receipt collision, revocation, and
live-SSE closure are covered by the automated actor-isolation tests.

API Resource Envelope was live-smoked through a real TCP listener at
`127.0.0.1:18082`, proving production `ConnectInfo` injection. An 8,193-byte
auth body returned `413`; an unknown request field returned `422` without
creating a Session; duplicate `Idempotency-Key` headers returned `400` without
creating a Session; and a valid create/turn request still settled through the
durable worker to sequence 4 with local-fallback provenance. Rate-window and
SSE body-drop behavior are covered by deterministic automated tests.

Apple `container` remains a supported local debug path. Commit `af29089` was
built and accepted without replacing the pre-existing `zeus-alpha` stack. The
isolated `zeus-operation-acceptance` stack uses its own images, network, named
volume, and port `18089`; `build`, `up`, `verify`, and volume-retaining
`restart-verify` all passed. It remains available locally for inspection.

The schema-v12 image from commit `cdaa211` was then rebuilt on that same
isolated project while retaining its schema-v11 named volume. The first
`up/verify` completed the v11-to-v12 migration. A second volume-retaining
`restart-verify` rebuilt the containers and network and passed API, Web,
gateway, authentication-status, anonymous-boundary, and `configured=false`
state-consistency checks across the retained-volume restart. Historical
schema-v12 readiness required the exact schema, so this also verified reopening
the v11-to-v12 migrated volume.

The schema-v13 image was subsequently rebuilt in the same
`zeus-operation-acceptance` project while retaining that now-v12 named volume.
It completed the in-place v12-to-v13 migration, and volume-retaining
`restart-verify` passed again.

The historical schema-v14 image was then built from this worktree on the same
isolated project while retaining the now-v13 volume. `up` completed the
v13-to-v14 migration; `verify` and volume-retaining `restart-verify` passed API,
Web, gateway, auth-status, anonymous-boundary, and `configured=false` state
consistency checks. At that point the API effective limit was 2 CPUs/1 GiB; its
post-restart snapshot reported
`memory.current=79,466,496`, `memory.peak=98,201,600`, Zeus RSS 9,824 KiB,
`pids.current=6`, and `memory.events` `oom=0`/`oom_kill=0`. Apple `container`
still reports `pids.max=max`, so this is not a PID-limit guarantee.

The current schema-v15 images then retained the now-v14 volume in the same
`zeus-operation-acceptance` project. `up`, `verify`, and volume-retaining
`restart-verify` passed the v14-to-v15 migration, a second reopen, Web/API/
gateway routes, the anonymous boundary, and `configured=false` recovery at
`http://127.0.0.1:18089`. The API remained limited to 2 CPUs/1 GiB; the recorded
snapshot was `memory.current=80,617,472`, `memory.peak=99,479,552`, Zeus RSS
10,252 KiB, `pids.current=7`, and zero OOM/OOM-kill events.

A separate fresh `zeus-audit-acceptance` project at
`http://127.0.0.1:18090` used a two-row detail target, eight-row per-account
ceiling, and two-row progress reserve. Live API acceptance covered owner
bootstrap, one-time member setup/login, a member Session reply settled through
the durable local fallback, member audit `403`, archive checkpoint, legal-hold
`507`, ordinary-capacity exhaustion after three additional creates, member
disable through progress reserve, session revocation, complete NDJSON manifest,
hold release, and readiness recovery. Browser acceptance clicked New Session,
sent a message through event sequence 4, opened Settings/Members/Audit, applied
dark mode, and found no console warning or error. Volume-retaining
`restart-verify` preserved `configured=true`; afterward the API reported
`memory.current=24,735,744`, `memory.peak=43,433,984`, Zeus RSS 10,340 KiB,
`pids.current=7`, and zero OOM/OOM-kill events. The VM had no swap and still
reported `pids.max=max`.

The earlier Operation Capacity readiness-pressure image was verified at 2
CPUs/1 GiB. A 30,000-request `/health/ready` run at concurrency 128 completed
in 4.493 seconds (about 6,677 requests/second): 2,670 responses were `200`,
27,330 were the expected
fail-fast `503`, and there were no transport errors. A second 10,000-request
run at concurrency 64 returned 414 `200` and 9,586 `503`; every `503` carried
`sqlite_operation_capacity_exceeded`. During and after pressure, cgroup memory
peak remained 97,595,392 bytes (about 93 MiB), Zeus RSS remained around 23 MiB,
and `memory.events` reported zero `oom`/`oom_kill`. CPU throttling confirmed the
2-CPU quota was active. Apple `container` 1.0 still exposes no per-container
PID limit (`pids.max=max`), and the VM had no swap. This is historical Apple
acceptance for the stated Operation Capacity readiness-pressure scenario, not
evidence that the v14 image reran it, and not authoritative Linux Docker
PID/OOM or adversarial low-memory acceptance.

The isolated Linux release-runtime Compose, verifier, normal/low-memory CI
matrix, and evidence contract are now checked in. This machine currently has
Apple `container` but no Docker CLI, so these new files are statically verified
but their authoritative Linux live result remains pending. The development
Compose configuration remains separate and is not used as that resource gate.
