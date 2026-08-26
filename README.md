# Zeus Harness

Zeus Harness is an early Rust and SvelteKit vertical slice toward an auditable
agent runtime. The current Alpha+ slice demonstrates a durable conversation
Session attached to an incident Run, independent ordered Session and Run event
streams, a guarded approval flow, local owner authentication, and recovery
through SQLite. A user message and its reply job commit atomically; only the
server-side worker may append assistant output and close the turn. Its web
interface deliberately follows the compact, conversation-first shape of
DeepSeek Harness rather than a dense operations dashboard.

An approval records authorization only. The default `production-guarded`
profile has no RDS executor: approving the illustrated change is durably
recorded, then settles as `not_dispatched / executor_unavailable` without a
production side effect. An explicit `local-development` profile provides one
real, path-constrained marker executor for testing the complete loop. Restate,
MinIO, the networkless tool sandbox, and optional PostgreSQL are development
topology for later milestones; they are not application state authorities.

Alpha+ supports exactly one local owner. A future `member` role is reserved in
the schema but cannot authenticate through this build; multi-user resource
isolation is not enabled yet. Keep the service loopback/private-network only,
and do not expose it as a shared or Internet-facing deployment.

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

With no model configuration, the durable reply worker returns an explicit
non-model local message. Configure an OpenAI-compatible Chat Completions
provider by setting all three variables together:

```sh
ZEUS_LLM_ENDPOINT=https://provider.example/v1/chat/completions
ZEUS_LLM_MODEL=your-model
ZEUS_LLM_API_KEY=your-secret
```

Partial provider configuration fails startup. The endpoint and key are never
writable through the browser Settings API.

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
  stores the actor-scoped response receipt, and enqueues immutable reply work.
- The worker commits a `started` checkpoint before calling a provider. Success
  atomically stores the assistant message, appends `assistant_message` and
  `turn_flushed`, marks the job succeeded, and returns the Session to `ready`.
  Provider failure appends `turn_interrupted`, marks the job failed, and moves
  the Session to `needs_attention` without fabricating assistant content.
- Queued replies survive restart and remain claimable. A reply already marked
  `started` becomes `outcome_unknown` exactly once and is never automatically
  replayed, because the provider call may have incurred an external effect.
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
  that exact immutable dispatch job; reject enqueues nothing.
- A worker commits `ToolDispatchStarted` before invoking a connector. A queued
  job can resume after restart; a started job without a durable result becomes
  `outcome_unknown` and is never retried automatically.
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
  triggers plus a durable authorization-revoked terminal state. Existing Runs
  and events are migrated in place without rewriting history. Runtime identity
  still binds profile, environment, primary Session and Run, policy ID, and
  policy revision; a mismatch fails startup.

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
  `POST /api/v1/auth/bootstrap`, and `POST /api/v1/auth/login`.
- Bootstrap and login require an exact same-origin `Origin`/`Host` pair. A
  successful bootstrap or login issues an opaque `HttpOnly; SameSite=Strict`
  login cookie plus a separate CSRF cookie. When the browser-facing origin is
  HTTPS, the operator must set `ZEUS_COOKIE_SECURE=true`; then both cookies are
  emitted with `Secure`.
- Every business REST/SSE route requires the active local owner. Protected
  state changes additionally require `X-CSRF-Token` to match the login and an
  exact same-origin request. Alpha+ deliberately rejects the schema-reserved
  `member` role. Actor isolation is now present, but member access remains
  blocked until quotas, pagination, SSE limits, and login rate limiting land.
- `GET /api/v1/me/settings` returns the current safe preferences.
  `PATCH /api/v1/me/settings` accepts `theme`, optional allowlisted
  `preferred_model`, and `expected_revision`. Provider endpoints and API keys
  are server-only configuration and never cross this API.
- `GET /api/v1/overview` returns `primary_session_id`, the current profile's
  primary Run, and its complete recent Run ledger.
- `GET /api/v1/sessions` lists Session summaries. `POST /api/v1/sessions`
  creates one from `{"id":...,"title":...}` and returns `201` for both the
  first committed response and an idempotent replay.
- `GET /api/v1/sessions/{session_id}` returns its summary, attached Run IDs,
  turns, and ordered Session events.
- `POST /api/v1/sessions/{session_id}/turns` accepts
  `{"turn_id":...,"user_message":...,"expected_sequence":...}`, atomically
  persists the user turn and a durable reply job, and returns `202`. The
  server-side worker later commits either the assistant reply or an explicit
  interrupted/needs-attention event through Session SSE.
- Browsers cannot submit assistant content. The legacy
  `POST /api/v1/sessions/{session_id}/turns/{turn_id}/flush` route exists only
  in a private `#[cfg(test)]` contract router that bootstraps a real test owner;
  it is absent from the production server.
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
- Session creation, turn start, resume, and approval-decision commands require
  a non-empty `Idempotency-Key`. Authentication/logout and optimistic settings
  updates use their own replay/concurrency rules. Invalid input returns 400;
  missing or unowned resources return 404; unauthenticated requests return
  401; CSRF/origin rejection returns 403; duplicate identity, idempotency
  conflict, invalid state, or sequence conflict returns 409 as
  `application/problem+json`.
- Internal execution-invariant failures return a stable, redacted
  `500 runtime_unavailable`. Storage, policy-build, connector-configuration, or
  registry unavailability returns a redacted `503 runtime_unavailable`.
  Internal details remain in server logs.

Schema v8 retains durable Run attachment during migration and demo seeding,
but Alpha+ does not expose a public attach-Run HTTP route.

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

Current Alpha+ plus Actor Boundary Foundation host verification:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace --all-targets`: 145 tests passed, including the real
  child-process database lease and active-SSE SIGTERM checks, authentication,
  actor-scoped REST/SSE/receipt isolation, authorization-revoked queue claims,
  durable reply provenance, concurrent claim, restart recovery, and provider
  `outcome_unknown` semantics.
- `pnpm --filter web test`: 19 tests passed for CSRF headers, stable command
  identity, active-Session restore, Session event merging, and theme behavior.
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

Apple `container` remains a supported local debug path. `bash -n` passes for
the helper, and the pre-existing labeled API/Web/gateway containers plus
`zeus-alpha-data` volume remained healthy and untouched during this change.
The Alpha+ image rebuild on this machine stalled while updating the crates.io
index inside BuildKit and was interrupted before any running container was
replaced. Therefore the new image, `verify`, and named-volume `restart-verify`
are not yet claimed as current Alpha+ acceptance. The earlier Alpha baseline
container acceptance belongs to commit `9a89706`; the committed Alpha+ host
baseline is `4fede62`, whose replacement container image is still unverified.

Docker Compose configuration remains available for environments with Docker
Compose v2; this machine currently has Apple `container` but no Docker CLI, so
Compose startup is statically configured rather than live-verified here.
