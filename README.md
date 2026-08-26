# Zeus Harness

Zeus Harness is an early Rust and SvelteKit vertical slice toward an auditable
agent runtime. The current Alpha slice demonstrates a durable conversation
Session attached to an incident Run, independent ordered Session and Run event
streams, a guarded approval flow, and local recovery through SQLite. Messages
are persisted as durable turns with an explicit `session/flush` barrier. Its web
interface deliberately follows the compact, conversation-first shape of
DeepSeek Harness rather than a dense operations dashboard.

An approval records authorization only. The default `production-guarded`
profile has no RDS executor: approving the illustrated change is durably
recorded, then settles as `not_dispatched / executor_unavailable` without a
production side effect. An explicit `local-development` profile provides one
real, path-constrained marker executor for testing the complete loop. Restate,
MinIO, the networkless tool sandbox, and optional PostgreSQL are development
topology for later milestones; they are not application state authorities.

This Alpha has no user authentication or tenant isolation. Keep its HTTP/SSE
endpoints on an isolated workstation; do not expose the host, Compose, or Apple
Container addresses through a public or shared-network reverse proxy.

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

To exercise the only executable Alpha connector, use a separate database and
an explicit fixed root. The caller supplies marker text only; it cannot choose
a path or invoke a host command:

```sh
ZEUS_DATABASE_PATH=.zeus/local-development.db \
ZEUS_LISTEN_ADDR=127.0.0.1:8081 \
ZEUS_DEMO_PROFILE=local-development \
ZEUS_LOCAL_MARKER_ROOT=.zeus/local-markers \
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
- Session creation writes the projection, `session_created` event, and first
  response receipt in one `BEGIN IMMEDIATE` transaction.
- Starting a turn requires the expected Session sequence. It atomically creates
  the open turn, appends `user_message`, advances the Session to `running`, and
  stores the first response receipt.
- Flushing the active turn also uses Session sequence compare-and-swap. One
  transaction stores an optional assistant message, closes the turn, appends
  `turn_flushed`, returns the Session to `ready`, stores the response receipt,
  and returns `ack.durability_sequence` for the committed barrier.
- A Session left with an open turn at process restart is atomically marked
  `interrupted`; Zeus appends `turn_interrupted` and moves the Session to
  `needs_attention`. Recovery never manufactures a flush acknowledgement. An
  idempotent, sequence-checked resume command must return it to `ready` before
  another turn starts.
- Session commands do not change the Run ledger or wake the dispatch worker.
  Session and Run are joined by durable ownership, not by sharing an event
  sequence or transaction stream.
- Run projection, versioned event payload, and the first Run command response
  are written in one SQLite transaction.
- Reusing an idempotency key with the same command input replays the stored
  response; reusing it with different input is a conflict. Session
  `expected_sequence` and Run head compare-and-swap arbitrate different keys
  racing on the same resource.
- Approval is bound to one call ID, argument digest, policy revision, sandbox,
  and `allow_once` scope. Approve atomically appends the decision and enqueues
  that exact immutable dispatch job; reject enqueues nothing.
- A worker commits `ToolDispatchStarted` before invoking a connector. A queued
  job can resume after restart; a started job without a durable result becomes
  `outcome_unknown` and is never retried automatically.
- Events become visible to live subscribers only after the transaction commits.
  Process-local broadcast is a latency hint; SSE also polls the durable ledger
  every two seconds from its last sequence cursor so a missed hint cannot leave
  the stream permanently behind.
- Unknown event kinds or payload versions fail closed during recovery.
- SQLite runs with foreign keys, a busy timeout, WAL for file databases, and
  full synchronous durability.
- A file-backed database acquires an OS-level exclusive lease on the adjacent
  `.zeus.lock` sidecar before migration and holds it until the final store
  clone drops. A competing Zeus process fails startup before recovery.
- SIGINT or SIGTERM first starts graceful HTTP draining, then closes any
  remaining long-lived SSE connection after five seconds. This bound ensures
  every store clone and the SQLite lease are released during container stop.
- Schema v4 adds durable Sessions, Session-to-Run ownership, turns, Session
  events, command receipts, and an immutable `primary_session_id`. Each pre-v4
  Run is attached to a generated `session-{run_id}` without rewriting or
  discarding its Run events. Runtime identity binds profile, environment,
  primary Session and Run, policy ID, and policy revision; a mismatch fails
  startup.

SQLite is the authoritative store for this local single-instance Alpha. Do not
place it on NFS or share one database volume between multiple Zeus replicas.
Competing local processes fail closed; coordinated multi-instance ownership and
PostgreSQL are later milestones.

When upgrading from a build that predates the `.zeus.lock` lease, stop every old
Zeus process before starting the new binary. The lease is advisory for Zeus
processes and does not prevent an unrelated program from opening SQLite
directly.

## HTTP contract

- `GET /api/v1/overview` returns `primary_session_id`, the current profile's
  primary Run, and its complete recent Run ledger.
- `GET /api/v1/sessions` lists Session summaries. `POST /api/v1/sessions`
  creates one from `{"id":...,"title":...}` and returns `201` for both the
  first committed response and an idempotent replay.
- `GET /api/v1/sessions/{session_id}` returns its summary, attached Run IDs,
  turns, and ordered Session events.
- `POST /api/v1/sessions/{session_id}/turns` accepts
  `{"turn_id":...,"user_message":...,"expected_sequence":...}`.
- `POST /api/v1/sessions/{session_id}/turns/{turn_id}/flush` accepts the same
  `turn_id`, optional `assistant_message`, and `expected_sequence`. Path and
  body IDs must match; success returns `ack.durability_sequence`.
- `POST /api/v1/sessions/{session_id}/resume` accepts
  `{"expected_sequence":...}` and only resumes a Session in
  `needs_attention`.
- `GET /api/v1/sessions/{session_id}/events?after={sequence}` streams
  `session.event` SSE from the independent Session ledger.
- `GET /api/v1/runs/{run_id}` returns one run projection plus ordered events.
- `GET /api/v1/runs/{run_id}/events?after={sequence}` streams Run SSE. For both
  feeds, `Last-Event-ID` takes precedence over the query cursor when present.
- `POST /api/v1/runs/{run_id}/approvals/{approval_id}/decision` accepts
  `{"decision":"approve|reject","note":...}` and requires an
  `Idempotency-Key` header. Approval identity comes from the path, not a caller-
  selected tool payload.
- Every POST requires a non-empty `Idempotency-Key`. Invalid input returns 400;
  missing resources return 404; duplicate identity, idempotency conflict,
  invalid state, or sequence conflict returns 409 as
  `application/problem+json`.
- Internal execution-invariant failures return a stable, redacted
  `500 runtime_unavailable`. Storage, policy-build, connector-configuration, or
  registry unavailability returns a redacted `503 runtime_unavailable`.
  Internal details remain in server logs.

Schema v4 supports durable Run attachment during migration and demo seeding,
but Alpha does not expose a public attach-Run HTTP route.

Session identifiers, titles, and messages currently have canonical/non-empty
validation but no explicit per-field byte quota, and detail routes return the
complete local ledger without pagination. Add quotas, retention, and cursor
pagination before any shared-network or multi-tenant deployment.

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

Current automated host verification:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace --all-targets` (99 tests, including real
  child-process database-lock and active-SSE SIGTERM checks plus out-of-order
  Run broadcast reconciliation)
- `pnpm --filter web test` (10 tests covering stable and rebased command
  identity, lost-response retries, persisted-attempt validation and ownership,
  Session event merging, and cross-ledger timeline ordering)
- `pnpm --filter web check`, `lint`, and `build`

Earlier live host acceptance retained for the Run and connector path:

- Svelte autofixer on all eight Web components: no issues or suggestions
- real production-profile HTTP/SSE: approval event `9`, checkpoint `10`, and
  `not_dispatched / executor_unavailable` result `11`; a process stop/start
  preserved all 11 events, and the same key replay added no event `12`
- real local-development HTTP: allow-once advanced through sequence `7` to
  `succeeded`, created one marker, and an idempotent replay still left one file
- simulated restart after a committed checkpoint but before connector execution:
  durable `outcome_unknown`, `needs_attention`, attempt count `1`, and no marker
- schema v1/v3 to v4 live migration preserved the Run ledger; Session
  start/flush advanced `2 → 3 → 5`, returned durability acknowledgement `5`,
  replayed the same command without another event, and left the Run unchanged
- a forced process death with an open turn recovered exactly one
  `turn_interrupted`, moved the Session to `needs_attention`, and required an
  idempotent explicit resume; no fabricated flush acknowledgement was emitted
- SIGTERM with live Run and Session SSE connections exited at the five-second
  bound, closed both streams, released `.zeus.lock`, and left SQLite integrity
  `ok`
- browser verification at `127.0.0.1:3001`: Live API data, explicit queued /
  running / not-dispatched labels, persisted Session messages in one compact
  timeline, `Saved through session event 7` in the single composer, and no
  console warnings or errors; terminal unavailable state remains amber, not
  success green

Apple `container` acceptance passed on macOS `26.6.2` with CLI `1.0.0`: all
three runtime images built, `up` reached healthy API/Web/gateway routes,
`verify` replayed both Run and Session SSE feeds, and a real Session turn
committed through durability sequence `5`. `restart-verify` deleted and
recreated all three containers and their network while retaining
`zeus-alpha-data`; the same Run, Session, turn, and every pre-restart event
remained present. This machine intermittently exhibited Apple localhost
forwarder resets (a later rebuild reported the published URL healthy), so
acceptance deliberately used the helper's stable direct gateway probe. The
script reports current loopback reachability instead of inferring it from an
earlier successful check.

The Compose and Docker configuration has been statically inspected. The machine
used for this implementation did not have Docker, Podman, Colima, nerdctl, or
Finch installed, so image pulls, builds, container health checks, named-volume
restart recovery, and end-to-end Compose startup remain unverified until run on
a machine with Docker Compose v2.
