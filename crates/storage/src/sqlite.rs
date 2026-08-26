use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use chrono::{SecondsFormat, Utc};
use fs2::FileExt;
use protocol::{
    ApprovalScope, ApprovalStatus, AttachRunRequest, AttachRunResponse, CreateSessionRequest,
    CreateSessionResponse, EventType, FlushSessionRequest, FlushSessionResponse, IncidentStatus,
    IncidentSummary, ResumeSessionRequest, ResumeSessionResponse, ReviewDecision, ReviewResponse,
    RunEvent, RunEventData, RunStatus, RunSummary, SandboxProfile, SessionDetail, SessionEvent,
    SessionEventData, SessionFlushAck, SessionStatus, SessionSummary, SessionTurn,
    SessionTurnStatus, Severity, StartTurnRequest, StartTurnResponse, ToolCallStatus, ToolEffect,
    ToolOutcome,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use crate::{
    ClaimOutcome, CommitOutcome, DispatchCompleteCommit, DispatchJob, DispatchJobSpec,
    DispatchRecoveryCommit, DispatchStartCommit, DispatchStatus, ReviewCommit, ReviewReceipt,
    RunSnapshot, RuntimeIdentity, StorageError, StoredRun,
};

const CURRENT_SCHEMA_VERSION: i64 = 4;
const EVENT_PAYLOAD_VERSION_V1: i64 = 1;
const EVENT_PAYLOAD_VERSION_V2: i64 = 2;
const SESSION_EVENT_PAYLOAD_VERSION_V1: i64 = 1;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const MIGRATION_0001: &str = include_str!("../migrations/0001_init.sql");
const MIGRATION_0002: &str = include_str!("../migrations/0002_tool_execution.sql");
const MIGRATION_0003: &str = include_str!("../migrations/0003_runtime_identity.sql");
const MIGRATION_0004: &str = include_str!("../migrations/0004_sessions.sql");

#[derive(Clone)]
pub struct SqliteStore {
    backend: Backend,
}

#[derive(Clone)]
enum Backend {
    File(Arc<FileBackend>),
    Memory(Arc<Mutex<Connection>>),
}

struct FileBackend {
    path: PathBuf,
    // Dropping the final backend clone releases the process-wide lease.
    _lock_file: File,
}

impl SqliteStore {
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref().to_path_buf();
        if path == Path::new(":memory:") {
            let connection = tokio::task::spawn_blocking(move || {
                let mut connection = Connection::open_in_memory()?;
                configure_connection(&connection, false)?;
                migrate(&mut connection)?;
                Ok::<_, StorageError>(connection)
            })
            .await??;
            Ok(Self {
                backend: Backend::Memory(Arc::new(Mutex::new(connection))),
            })
        } else {
            let backend = tokio::task::spawn_blocking(move || {
                let path = normalized_file_path(&path)?;
                let lock_file = acquire_database_lock(&path)?;
                let mut connection = open_file_connection(&path)?;
                migrate(&mut connection)?;
                Ok::<_, StorageError>(FileBackend {
                    path,
                    _lock_file: lock_file,
                })
            })
            .await??;
            Ok(Self {
                backend: Backend::File(Arc::new(backend)),
            })
        }
    }

    /// Binds this database to one immutable runtime profile and policy.
    ///
    /// An empty database is initialized directly. A database upgraded from an
    /// earlier schema is adopted only when its sole run and every persisted
    /// policy-bearing record agree with the requested identity.
    pub async fn bind_runtime_identity(
        &self,
        identity: RuntimeIdentity,
    ) -> Result<(), StorageError> {
        self.with_connection(move |connection| bind_runtime_identity(connection, identity))
            .await
    }

    /// Seeds the database only when it has no runs. Existing state is never
    /// overwritten, including after a process restart.
    pub async fn seed_if_empty(
        &self,
        snapshot: RunSnapshot,
        events: Vec<RunEvent>,
    ) -> Result<bool, StorageError> {
        self.with_connection(move |connection| seed_if_empty(connection, snapshot, events))
            .await
    }

    /// Creates (or completes) the durable demo-session attachment.
    ///
    /// This startup seed is naturally idempotent: an already-attached run is
    /// left untouched. If the session exists but the run is not yet owned, a
    /// `run_attached` event is appended under the session sequence CAS.
    pub async fn seed_demo_session(
        &self,
        session_id: &str,
        title: &str,
        run_id: &str,
    ) -> Result<bool, StorageError> {
        let session_id = normalized_session_value(session_id, "session ID")?.to_owned();
        let title = normalized_session_value(title, "session title")?.to_owned();
        let run_id = normalized_session_value(run_id, "run ID")?.to_owned();
        self.with_connection(move |connection| {
            seed_demo_session(connection, &session_id, &title, &run_id)
        })
        .await
    }

    pub async fn list_sessions(&self) -> Result<Vec<SessionSummary>, StorageError> {
        self.with_connection(query_session_summaries).await
    }

    pub async fn get_session(&self, session_id: &str) -> Result<SessionDetail, StorageError> {
        let session_id = normalized_session_value(session_id, "session ID")?.to_owned();
        self.with_connection(move |connection| query_session_detail(connection, &session_id))
            .await
    }

    pub async fn session_events_after(
        &self,
        session_id: &str,
        after: u64,
    ) -> Result<Vec<SessionEvent>, StorageError> {
        let session_id = normalized_session_value(session_id, "session ID")?.to_owned();
        self.with_connection(move |connection| {
            query_session_events_after(connection, &session_id, after)
        })
        .await
    }

    pub async fn create_session(
        &self,
        request: CreateSessionRequest,
        idempotency_key: &str,
    ) -> Result<CreateSessionResponse, StorageError> {
        let key = normalized_key(idempotency_key)?.to_owned();
        self.with_connection(move |connection| create_session(connection, request, &key))
            .await
    }

    pub async fn attach_run(
        &self,
        session_id: &str,
        request: AttachRunRequest,
        idempotency_key: &str,
    ) -> Result<AttachRunResponse, StorageError> {
        let session_id = normalized_session_value(session_id, "session ID")?.to_owned();
        let key = normalized_key(idempotency_key)?.to_owned();
        self.with_connection(move |connection| attach_run(connection, &session_id, request, &key))
            .await
    }

    pub async fn start_turn(
        &self,
        session_id: &str,
        request: StartTurnRequest,
        idempotency_key: &str,
    ) -> Result<StartTurnResponse, StorageError> {
        let session_id = normalized_session_value(session_id, "session ID")?.to_owned();
        let key = normalized_key(idempotency_key)?.to_owned();
        self.with_connection(move |connection| start_turn(connection, &session_id, request, &key))
            .await
    }

    pub async fn flush_turn(
        &self,
        session_id: &str,
        request: FlushSessionRequest,
        idempotency_key: &str,
    ) -> Result<FlushSessionResponse, StorageError> {
        let session_id = normalized_session_value(session_id, "session ID")?.to_owned();
        let key = normalized_key(idempotency_key)?.to_owned();
        self.with_connection(move |connection| {
            flush_turn(connection, &session_id, request, &key, false)
        })
        .await
    }

    pub async fn resume_session(
        &self,
        session_id: &str,
        request: ResumeSessionRequest,
        idempotency_key: &str,
    ) -> Result<ResumeSessionResponse, StorageError> {
        let session_id = normalized_session_value(session_id, "session ID")?.to_owned();
        let key = normalized_key(idempotency_key)?.to_owned();
        self.with_connection(move |connection| {
            resume_session(connection, &session_id, request, &key)
        })
        .await
    }

    /// Closes every turn left open by a previous process. Recovery only
    /// appends `turn_interrupted`; it never manufactures a flush acknowledgement.
    pub async fn recover_open_turns(&self) -> Result<Vec<SessionEvent>, StorageError> {
        self.with_connection(recover_open_turns).await
    }

    pub async fn readiness(&self) -> Result<(), StorageError> {
        let expects_wal = matches!(self.backend, Backend::File(_));
        self.with_connection(move |connection| readiness(connection, expects_wal))
            .await
    }

    pub async fn snapshot(&self, run_id: &str) -> Result<RunSnapshot, StorageError> {
        let run_id = run_id.to_owned();
        self.with_connection(move |connection| load_snapshot(connection, &run_id))
            .await
    }

    pub async fn load_run(&self, run_id: &str) -> Result<StoredRun, StorageError> {
        let run_id = run_id.to_owned();
        self.with_connection(move |connection| load_run(connection, &run_id))
            .await
    }

    pub async fn events_after(
        &self,
        run_id: &str,
        after: u64,
    ) -> Result<Vec<RunEvent>, StorageError> {
        let run_id = run_id.to_owned();
        self.with_connection(move |connection| events_after(connection, &run_id, after))
            .await
    }

    pub async fn review_receipt(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<ReviewReceipt>, StorageError> {
        let idempotency_key = normalized_key(idempotency_key)?.to_owned();
        self.with_connection(move |connection| load_review_receipt(connection, &idempotency_key))
            .await
    }

    /// Atomically advances the run projection, appends the v1 event payload,
    /// and records the idempotency receipt. Business transition validation is
    /// intentionally owned by the runtime/kernel before this call.
    pub async fn commit_review(&self, commit: ReviewCommit) -> Result<CommitOutcome, StorageError> {
        self.with_connection(move |connection| commit_review(connection, commit, false))
            .await
    }

    /// Returns a queued job without mutating it. Callers use this to build the
    /// projection/event supplied to [`Self::claim_next_dispatch`].
    pub async fn peek_next_dispatch(&self) -> Result<Option<DispatchJob>, StorageError> {
        self.with_connection(peek_next_dispatch).await
    }

    pub async fn dispatch_job(&self, call_id: &str) -> Result<Option<DispatchJob>, StorageError> {
        let call_id = normalized_identifier(call_id, "call ID")?.to_owned();
        self.with_connection(move |connection| query_dispatch_job(connection, &call_id))
            .await
    }

    pub async fn started_dispatches(&self) -> Result<Vec<DispatchJob>, StorageError> {
        self.with_connection(query_started_dispatches).await
    }

    /// Atomically claims the current queue head, appends the caller-computed
    /// dispatch-started event, and advances the run projection. No connector
    /// code runs while this transaction is open.
    pub async fn claim_next_dispatch(
        &self,
        commit: DispatchStartCommit,
    ) -> Result<ClaimOutcome, StorageError> {
        self.with_connection(move |connection| claim_next_dispatch(connection, commit, false))
            .await
    }

    /// Atomically records a connector result, appends its v2 event, and
    /// advances the run projection.
    pub async fn complete_dispatch(
        &self,
        commit: DispatchCompleteCommit,
    ) -> Result<DispatchJob, StorageError> {
        self.with_connection(move |connection| complete_dispatch(connection, commit, false))
            .await
    }

    /// Converts one previously-started call into a terminal
    /// `outcome_unknown` record. This method only writes recovery evidence; it
    /// never claims or executes a queued call.
    pub async fn recover_started(
        &self,
        commit: DispatchRecoveryCommit,
    ) -> Result<DispatchJob, StorageError> {
        self.with_connection(move |connection| recover_started(connection, commit))
            .await
    }

    #[cfg(test)]
    pub(crate) async fn commit_review_with_failure(
        &self,
        commit: ReviewCommit,
    ) -> Result<CommitOutcome, StorageError> {
        self.with_connection(move |connection| commit_review(connection, commit, true))
            .await
    }

    #[cfg(test)]
    pub(crate) async fn claim_next_dispatch_with_failure(
        &self,
        commit: DispatchStartCommit,
    ) -> Result<ClaimOutcome, StorageError> {
        self.with_connection(move |connection| claim_next_dispatch(connection, commit, true))
            .await
    }

    #[cfg(test)]
    pub(crate) async fn complete_dispatch_with_failure(
        &self,
        commit: DispatchCompleteCommit,
    ) -> Result<DispatchJob, StorageError> {
        self.with_connection(move |connection| complete_dispatch(connection, commit, true))
            .await
    }

    #[cfg(test)]
    pub(crate) async fn flush_turn_with_failure(
        &self,
        session_id: &str,
        request: FlushSessionRequest,
        idempotency_key: &str,
    ) -> Result<FlushSessionResponse, StorageError> {
        let session_id = normalized_session_value(session_id, "session ID")?.to_owned();
        let key = normalized_key(idempotency_key)?.to_owned();
        self.with_connection(move |connection| {
            flush_turn(connection, &session_id, request, &key, true)
        })
        .await
    }

    async fn with_connection<T, F>(&self, operation: F) -> Result<T, StorageError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, StorageError> + Send + 'static,
    {
        match &self.backend {
            Backend::File(backend) => {
                let backend = Arc::clone(backend);
                tokio::task::spawn_blocking(move || {
                    let mut connection = open_file_connection(&backend.path)?;
                    operation(&mut connection)
                })
                .await?
            }
            Backend::Memory(connection) => {
                let connection = Arc::clone(connection);
                tokio::task::spawn_blocking(move || {
                    let mut connection = connection.lock().map_err(|_| {
                        StorageError::CorruptData("in-memory SQLite lock was poisoned".into())
                    })?;
                    operation(&mut connection)
                })
                .await?
            }
        }
    }
}

fn normalized_file_path(path: &Path) -> Result<PathBuf, StorageError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let file_name = absolute.file_name().ok_or_else(|| {
        StorageError::CorruptData(format!(
            "SQLite database path `{}` has no file name",
            path.display()
        ))
    })?;
    let parent = absolute.parent().ok_or_else(|| {
        StorageError::CorruptData(format!(
            "SQLite database path `{}` has no parent directory",
            path.display()
        ))
    })?;
    fs::create_dir_all(parent)?;
    let canonical_parent = fs::canonicalize(parent)?;
    let candidate = canonical_parent.join(file_name);
    match fs::canonicalize(&candidate) {
        Ok(canonical) => Ok(canonical),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(candidate),
        Err(error) => Err(error.into()),
    }
}

fn acquire_database_lock(path: &Path) -> Result<File, StorageError> {
    let mut lock_name = path
        .file_name()
        .map(OsString::from)
        .ok_or_else(|| StorageError::CorruptData("SQLite database path has no file name".into()))?;
    lock_name.push(".zeus.lock");
    let lock_path = path.with_file_name(lock_name);
    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    match FileExt::try_lock_exclusive(&lock_file) {
        Ok(()) => Ok(lock_file),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            Err(StorageError::DatabaseLocked(path.display().to_string()))
        }
        Err(error) => Err(error.into()),
    }
}

fn open_file_connection(path: &Path) -> Result<Connection, StorageError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let connection = Connection::open(path)?;
    configure_connection(&connection, true)?;
    Ok(connection)
}

fn configure_connection(connection: &Connection, enable_wal: bool) -> Result<(), StorageError> {
    connection.busy_timeout(BUSY_TIMEOUT)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    if enable_wal {
        connection.pragma_update(None, "journal_mode", "WAL")?;
    }
    connection.pragma_update(None, "synchronous", "FULL")?;

    let journal_mode: String =
        connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    let expected_journal = if enable_wal { "wal" } else { "memory" };
    if !journal_mode.eq_ignore_ascii_case(expected_journal) {
        return Err(StorageError::CorruptData(format!(
            "expected {expected_journal} journal mode, found `{journal_mode}`"
        )));
    }
    Ok(())
}

fn migrate(connection: &mut Connection) -> Result<(), StorageError> {
    connection.execute_batch(
        r#"CREATE TABLE IF NOT EXISTS schema_migrations (
               version INTEGER PRIMARY KEY,
               applied_at TEXT NOT NULL
           ) STRICT;"#,
    )?;

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (current, migration_count): (i64, i64) = transaction.query_row(
        "SELECT COALESCE(MAX(version), 0), COUNT(*) FROM schema_migrations",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if current > CURRENT_SCHEMA_VERSION {
        return Err(StorageError::UnsupportedSchemaVersion {
            found: current,
            supported: CURRENT_SCHEMA_VERSION,
        });
    }
    if migration_count != current {
        return Err(StorageError::CorruptData(
            "schema migration history is not contiguous from version 1".into(),
        ));
    }
    if current < 1 {
        transaction.execute_batch(MIGRATION_0001)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![1, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    if current < 2 {
        transaction.execute_batch(MIGRATION_0002)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![2, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    if current < 3 {
        transaction.execute_batch(MIGRATION_0003)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![3, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    if current < 4 {
        transaction.execute_batch(MIGRATION_0004)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![4, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    transaction.commit()?;
    Ok(())
}

fn readiness(connection: &mut Connection, expects_wal: bool) -> Result<(), StorageError> {
    let version: i64 = connection.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        [],
        |row| row.get(0),
    )?;
    if version != CURRENT_SCHEMA_VERSION {
        return Err(StorageError::UnsupportedSchemaVersion {
            found: version,
            supported: CURRENT_SCHEMA_VERSION,
        });
    }

    let foreign_keys: i64 =
        connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    let synchronous: i64 = connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
    let busy_timeout: i64 =
        connection.pragma_query_value(None, "busy_timeout", |row| row.get(0))?;
    let journal_mode: String =
        connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    let expected_journal = if expects_wal { "wal" } else { "memory" };
    if foreign_keys != 1
        || synchronous != 2
        || busy_timeout != BUSY_TIMEOUT.as_millis() as i64
        || !journal_mode.eq_ignore_ascii_case(expected_journal)
    {
        return Err(StorageError::CorruptData(
            "SQLite safety pragmas are not active".into(),
        ));
    }

    let table_count: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM sqlite_schema
           WHERE type = 'table' AND name IN (
               'schema_migrations', 'incidents', 'runs', 'run_events', 'idempotency_receipts',
               'dispatch_jobs', 'runtime_identity', 'sessions', 'session_runs',
               'session_turns', 'session_events', 'session_command_receipts'
           )"#,
        [],
        |row| row.get(0),
    )?;
    if table_count != 12 {
        return Err(StorageError::CorruptData(
            "one or more required tables are missing".into(),
        ));
    }

    let execution_status_columns: i64 = connection.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('runs') WHERE name = 'execution_status'",
        [],
        |row| row.get(0),
    )?;
    if execution_status_columns != 1 {
        return Err(StorageError::CorruptData(
            "runs.execution_status is missing".into(),
        ));
    }

    let primary_session_columns: i64 = connection.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('runtime_identity') WHERE name = 'primary_session_id'",
        [],
        |row| row.get(0),
    )?;
    if primary_session_columns != 1 {
        return Err(StorageError::CorruptData(
            "runtime_identity.primary_session_id is missing".into(),
        ));
    }

    let trigger_count: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM sqlite_schema
           WHERE type = 'trigger' AND name IN (
               'run_events_reject_update',
               'run_events_reject_delete',
               'dispatch_jobs_reject_input_update',
               'dispatch_jobs_enforce_forward_transition',
               'dispatch_jobs_reject_delete',
               'runtime_identity_reject_update',
               'runtime_identity_reject_delete',
               'session_events_require_next_sequence',
               'session_events_reject_update',
               'session_events_reject_delete',
               'session_runs_reject_update',
               'session_runs_reject_delete',
               'session_turns_reject_input_update',
               'session_turns_enforce_terminal_transition',
               'session_turns_reject_delete',
               'session_command_receipts_reject_update',
               'session_command_receipts_reject_delete'
           )"#,
        [],
        |row| row.get(0),
    )?;
    if trigger_count != 17 {
        return Err(StorageError::CorruptData(
            "one or more durability triggers are missing".into(),
        ));
    }

    let quick_check: String =
        connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if quick_check != "ok" {
        return Err(StorageError::CorruptData(format!(
            "SQLite quick_check failed: {quick_check}"
        )));
    }
    let foreign_key_violation = connection
        .query_row(
            "SELECT 1 FROM pragma_foreign_key_check LIMIT 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    if foreign_key_violation.is_some() {
        return Err(StorageError::CorruptData(
            "SQLite foreign_key_check failed".into(),
        ));
    }
    Ok(())
}

fn bind_runtime_identity(
    connection: &mut Connection,
    identity: RuntimeIdentity,
) -> Result<(), StorageError> {
    validate_runtime_identity(&identity)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let stored = transaction
        .query_row(
            r#"SELECT profile, environment, primary_session_id, primary_run_id,
                      policy_id, policy_revision
               FROM runtime_identity WHERE singleton = 1"#,
            [],
            |row| {
                Ok(RuntimeIdentity {
                    profile: row.get(0)?,
                    environment: row.get(1)?,
                    primary_session_id: row.get(2)?,
                    primary_run_id: row.get(3)?,
                    policy_id: row.get(4)?,
                    policy_revision: row.get(5)?,
                })
            },
        )
        .optional()?;

    if let Some(stored) = stored {
        if stored != identity {
            return Err(identity_mismatch(&identity, identity_label(&stored)));
        }
        transaction.commit()?;
        return Ok(());
    }

    validate_legacy_runtime_identity(&transaction, &identity)?;
    transaction.execute(
        r#"INSERT INTO runtime_identity(
               singleton, profile, environment, primary_session_id, primary_run_id,
               policy_id, policy_revision, bound_at
           ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
        params![
            identity.profile,
            identity.environment,
            identity.primary_session_id,
            identity.primary_run_id,
            identity.policy_id,
            identity.policy_revision,
            Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        ],
    )?;
    transaction.commit()?;
    Ok(())
}

fn validate_runtime_identity(identity: &RuntimeIdentity) -> Result<(), StorageError> {
    if !matches!(
        identity.profile.as_str(),
        "production-guarded" | "local-development"
    ) {
        return Err(StorageError::CorruptData(format!(
            "unsupported runtime profile identity `{}`",
            identity.profile
        )));
    }
    for (label, value) in [
        ("profile", identity.profile.as_str()),
        ("environment", identity.environment.as_str()),
        ("primary session ID", identity.primary_session_id.as_str()),
        ("primary run ID", identity.primary_run_id.as_str()),
        ("policy ID", identity.policy_id.as_str()),
        ("policy revision", identity.policy_revision.as_str()),
    ] {
        if value.is_empty() || value.trim() != value {
            return Err(StorageError::CorruptData(format!(
                "runtime identity {label} must be non-empty and canonical"
            )));
        }
    }
    Ok(())
}

fn validate_legacy_runtime_identity(
    transaction: &rusqlite::Transaction<'_>,
    identity: &RuntimeIdentity,
) -> Result<(), StorageError> {
    let run_count: i64 =
        transaction.query_row("SELECT COUNT(*) FROM runs", [], |row| row.get(0))?;
    if run_count == 0 {
        let state_rows: i64 = transaction.query_row(
            r#"SELECT
                 (SELECT COUNT(*) FROM incidents) +
                 (SELECT COUNT(*) FROM run_events) +
                 (SELECT COUNT(*) FROM idempotency_receipts) +
                 (SELECT COUNT(*) FROM dispatch_jobs) +
                 (SELECT COUNT(*) FROM sessions) +
                 (SELECT COUNT(*) FROM session_runs) +
                 (SELECT COUNT(*) FROM session_turns) +
                 (SELECT COUNT(*) FROM session_events) +
                 (SELECT COUNT(*) FROM session_command_receipts)"#,
            [],
            |row| row.get(0),
        )?;
        if state_rows != 0 {
            return Err(StorageError::CorruptData(
                "cannot bind a database with orphaned runtime state".into(),
            ));
        }
        return Ok(());
    }

    let primary_environment = transaction
        .query_row(
            "SELECT environment FROM runs WHERE id = ?1",
            [&identity.primary_run_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let Some(primary_environment) = primary_environment else {
        return Err(identity_mismatch(
            identity,
            format!("database with {run_count} runs but no configured primary run"),
        ));
    };
    if primary_environment != identity.environment {
        return Err(identity_mismatch(
            identity,
            format!(
                "primary run {} in environment {primary_environment}",
                identity.primary_run_id
            ),
        ));
    }

    let existing_owner = transaction
        .query_row(
            "SELECT session_id FROM session_runs WHERE run_id = ?1",
            [&identity.primary_run_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(existing_owner) = existing_owner
        && existing_owner != identity.primary_session_id
    {
        return Err(identity_mismatch(
            identity,
            format!(
                "primary run {} owned by session {existing_owner}",
                identity.primary_run_id
            ),
        ));
    }

    let mismatched_job = transaction
        .query_row(
            r#"SELECT policy_id, policy_revision FROM dispatch_jobs
               WHERE run_id = ?1 AND (policy_id <> ?2 OR policy_revision <> ?3) LIMIT 1"#,
            params![
                identity.primary_run_id,
                identity.policy_id,
                identity.policy_revision
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    if let Some((policy_id, policy_revision)) = mismatched_job {
        return Err(identity_mismatch(
            identity,
            format!("dispatch policy {policy_id}@{policy_revision}"),
        ));
    }

    let mut statement = transaction.prepare(
        r#"SELECT payload_json FROM run_events
           WHERE run_id = ?1 AND payload_version IN (?2, ?3) ORDER BY sequence"#,
    )?;
    let payloads = statement
        .query_map(
            params![
                identity.primary_run_id,
                EVENT_PAYLOAD_VERSION_V1,
                EVENT_PAYLOAD_VERSION_V2
            ],
            |row| row.get::<_, String>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    for payload in payloads {
        let event: RunEvent = serde_json::from_str(&payload)?;
        if let Some(RunEventData::ToolPolicyDecided {
            policy_revision, ..
        }) = event.data
            && policy_revision != identity.policy_revision
        {
            return Err(identity_mismatch(
                identity,
                format!("event policy revision {policy_revision}"),
            ));
        }
        if let Some(policy_revision) = event.approval.and_then(|approval| approval.policy_revision)
            && policy_revision != identity.policy_revision
        {
            return Err(identity_mismatch(
                identity,
                format!("approval policy revision {policy_revision}"),
            ));
        }
    }
    Ok(())
}

fn identity_mismatch(identity: &RuntimeIdentity, found: String) -> StorageError {
    StorageError::RuntimeIdentityMismatch {
        expected: identity_label(identity),
        found,
    }
}

fn identity_label(identity: &RuntimeIdentity) -> String {
    format!(
        "{} session {} / run {} in {} using {}@{}",
        identity.profile,
        identity.primary_session_id,
        identity.primary_run_id,
        identity.environment,
        identity.policy_id,
        identity.policy_revision
    )
}

fn seed_if_empty(
    connection: &mut Connection,
    snapshot: RunSnapshot,
    events: Vec<RunEvent>,
) -> Result<bool, StorageError> {
    validate_seed(&snapshot, &events)?;
    let metrics_json = serde_json::to_string(&snapshot.metrics)?;
    let evidence_json = serde_json::to_string(&snapshot.evidence)?;
    let tool_policy_json = snapshot
        .tool_policy
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;
    let duration_seconds = u64_to_i64(snapshot.run.duration_seconds, "duration_seconds")?;
    let sequence = u64_to_i64(snapshot.run.sequence, "run sequence")?;

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let run_count: i64 =
        transaction.query_row("SELECT COUNT(*) FROM runs", [], |row| row.get(0))?;
    if run_count != 0 {
        transaction.commit()?;
        return Ok(false);
    }

    transaction.execute(
        r#"INSERT INTO incidents(
               id, title, severity, status, service, region, user_impact, since
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
        params![
            snapshot.incident.id,
            snapshot.incident.title,
            severity_to_db(&snapshot.incident.severity),
            incident_status_to_db(&snapshot.incident.status),
            snapshot.incident.service,
            snapshot.incident.region,
            snapshot.incident.user_impact,
            snapshot.incident.since,
        ],
    )?;
    transaction.execute(
        r#"INSERT INTO runs(
               id, incident_id, status, environment, started_at, duration_seconds, agent,
               sequence, projection_sequence, metrics_json, evidence_json, tool_policy_json,
               execution_status
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9, ?10, ?11, ?12)"#,
        params![
            snapshot.run.id,
            snapshot.incident.id,
            legacy_run_status_to_db(&snapshot.run.status),
            snapshot.run.environment,
            snapshot.run.started_at,
            duration_seconds,
            snapshot.run.agent,
            sequence,
            metrics_json,
            evidence_json,
            tool_policy_json,
            execution_status_to_db(&snapshot.run.status),
        ],
    )?;
    for event in &events {
        if event.data.is_some() {
            insert_event_v2(&transaction, &snapshot.run.id, event)?;
        } else {
            insert_event_v1(&transaction, &snapshot.run.id, event)?;
        }
    }
    transaction.commit()?;
    Ok(true)
}

fn seed_demo_session(
    connection: &mut Connection,
    session_id: &str,
    title: &str,
    run_id: &str,
) -> Result<bool, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let run_exists = transaction
        .query_row("SELECT 1 FROM runs WHERE id = ?1", [run_id], |row| {
            row.get::<_, i64>(0)
        })
        .optional()?;
    if run_exists.is_none() {
        return Err(StorageError::RunNotFound(run_id.to_owned()));
    }

    let owner = transaction
        .query_row(
            "SELECT session_id FROM session_runs WHERE run_id = ?1",
            [run_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(owner) = owner {
        if owner != session_id {
            return Err(StorageError::RunAlreadyAttached {
                run_id: run_id.to_owned(),
                session_id: owner,
            });
        }
        transaction.commit()?;
        return Ok(false);
    }

    let mut summary = query_session_summary_optional(&transaction, session_id)?;
    if summary.is_none() {
        let timestamp = now();
        transaction.execute(
            r#"INSERT INTO sessions(
                   id, title, status, created_at, updated_at, sequence,
                   projection_sequence, active_turn_id
               ) VALUES (?1, ?2, 'ready', ?3, ?3, 0, 0, NULL)"#,
            params![session_id, title, timestamp],
        )?;
        let event = build_session_event(
            session_id,
            1,
            &timestamp,
            SessionEventData::SessionCreated {
                title: title.to_owned(),
            },
        );
        insert_session_event(&transaction, session_id, &event)?;
        update_session_projection(
            &transaction,
            session_id,
            0,
            SessionStatus::Ready,
            None,
            1,
            &timestamp,
        )?;
        summary = Some(query_session_summary(&transaction, session_id)?);
    }

    let summary = summary.ok_or_else(|| {
        StorageError::CorruptData("session seed did not create or load its projection".into())
    })?;
    let timestamp = now();
    transaction.execute(
        r#"INSERT INTO session_runs(session_id, run_id, attached_at)
           VALUES (?1, ?2, ?3)"#,
        params![session_id, run_id, timestamp],
    )?;
    let sequence = summary
        .sequence
        .checked_add(1)
        .ok_or(StorageError::IntegerOutOfRange("session sequence"))?;
    let event = build_session_event(
        session_id,
        sequence,
        &timestamp,
        SessionEventData::RunAttached {
            run_id: run_id.to_owned(),
        },
    );
    insert_session_event(&transaction, session_id, &event)?;
    update_session_projection(
        &transaction,
        session_id,
        summary.sequence,
        summary.status,
        summary.active_turn_id.as_deref(),
        sequence,
        &timestamp,
    )?;
    transaction.commit()?;
    Ok(true)
}

fn query_session_summaries(
    connection: &mut Connection,
) -> Result<Vec<SessionSummary>, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let mut statement = transaction.prepare(
        r#"SELECT id, title, status, created_at, updated_at, sequence,
                  projection_sequence, active_turn_id
           FROM sessions ORDER BY updated_at DESC, id"#,
    )?;
    let rows = statement
        .query_map([], decode_session_summary_row)?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    let summaries = rows
        .into_iter()
        .map(StoredSessionSummaryRow::decode)
        .collect::<Result<Vec<_>, _>>()?;
    transaction.commit()?;
    Ok(summaries)
}

fn query_session_detail(
    connection: &mut Connection,
    session_id: &str,
) -> Result<SessionDetail, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let session = query_session_summary(&transaction, session_id)?;

    let mut run_statement = transaction.prepare(
        r#"SELECT run_id FROM session_runs
           WHERE session_id = ?1 ORDER BY attached_at, run_id"#,
    )?;
    let run_ids = run_statement
        .query_map([session_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(run_statement);

    let turns = query_session_turns(&transaction, session_id)?;
    let events = query_session_events(&transaction, session_id, 0)?;
    let event_head = events.last().map_or(0, |event| event.sequence);
    if event_head != session.sequence {
        return Err(StorageError::CorruptData(format!(
            "session head {} does not match event head {event_head}",
            session.sequence
        )));
    }
    validate_session_turn_projection(&session, &turns)?;
    transaction.commit()?;
    Ok(SessionDetail {
        session,
        run_ids,
        turns,
        events,
    })
}

fn query_session_events_after(
    connection: &mut Connection,
    session_id: &str,
    after: u64,
) -> Result<Vec<SessionEvent>, StorageError> {
    let after = u64_to_i64(after, "session event cursor")?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    query_session_summary(&transaction, session_id)?;
    let events = query_session_events(&transaction, session_id, after)?;
    transaction.commit()?;
    Ok(events)
}

fn create_session(
    connection: &mut Connection,
    request: CreateSessionRequest,
    idempotency_key: &str,
) -> Result<CreateSessionResponse, StorageError> {
    let fingerprint = session_command_fingerprint(None, &request)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(mut response) = load_session_command_receipt::<CreateSessionResponse>(
        &transaction,
        idempotency_key,
        "create_session",
        &fingerprint,
    )? {
        response.replayed = true;
        transaction.commit()?;
        return Ok(response);
    }

    normalized_session_value(&request.id, "session ID")?;
    normalized_session_value(&request.title, "session title")?;
    if query_session_summary_optional(&transaction, &request.id)?.is_some() {
        return Err(StorageError::SessionAlreadyExists(request.id));
    }
    let timestamp = now();
    transaction.execute(
        r#"INSERT INTO sessions(
               id, title, status, created_at, updated_at, sequence,
               projection_sequence, active_turn_id
           ) VALUES (?1, ?2, 'ready', ?3, ?3, 0, 0, NULL)"#,
        params![request.id, request.title, timestamp],
    )?;
    let event = build_session_event(
        &request.id,
        1,
        &timestamp,
        SessionEventData::SessionCreated {
            title: request.title.clone(),
        },
    );
    insert_session_event(&transaction, &request.id, &event)?;
    update_session_projection(
        &transaction,
        &request.id,
        0,
        SessionStatus::Ready,
        None,
        1,
        &timestamp,
    )?;
    let response = CreateSessionResponse {
        session: query_session_summary(&transaction, &request.id)?,
        event,
        replayed: false,
    };
    insert_session_command_receipt(
        &transaction,
        idempotency_key,
        "create_session",
        &fingerprint,
        &response,
        &request.id,
        response.event.sequence,
    )?;
    transaction.commit()?;
    Ok(response)
}

fn attach_run(
    connection: &mut Connection,
    session_id: &str,
    request: AttachRunRequest,
    idempotency_key: &str,
) -> Result<AttachRunResponse, StorageError> {
    let fingerprint = session_command_fingerprint(Some(session_id), &request)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(mut response) = load_session_command_receipt::<AttachRunResponse>(
        &transaction,
        idempotency_key,
        "attach_run",
        &fingerprint,
    )? {
        response.replayed = true;
        transaction.commit()?;
        return Ok(response);
    }

    normalized_session_value(&request.run_id, "run ID")?;
    let summary = query_session_summary(&transaction, session_id)?;
    require_session_sequence(&summary, request.expected_sequence)?;
    let run_exists = transaction
        .query_row(
            "SELECT 1 FROM runs WHERE id = ?1",
            [&request.run_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    if run_exists.is_none() {
        return Err(StorageError::RunNotFound(request.run_id));
    }
    if let Some(owner) = transaction
        .query_row(
            "SELECT session_id FROM session_runs WHERE run_id = ?1",
            [&request.run_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
    {
        return Err(StorageError::RunAlreadyAttached {
            run_id: request.run_id,
            session_id: owner,
        });
    }

    let timestamp = now();
    transaction.execute(
        "INSERT INTO session_runs(session_id, run_id, attached_at) VALUES (?1, ?2, ?3)",
        params![session_id, request.run_id, timestamp],
    )?;
    let sequence = next_session_sequence(summary.sequence)?;
    let event = build_session_event(
        session_id,
        sequence,
        &timestamp,
        SessionEventData::RunAttached {
            run_id: request.run_id.clone(),
        },
    );
    insert_session_event(&transaction, session_id, &event)?;
    update_session_projection(
        &transaction,
        session_id,
        summary.sequence,
        summary.status,
        summary.active_turn_id.as_deref(),
        sequence,
        &timestamp,
    )?;
    let response = AttachRunResponse {
        session: query_session_summary(&transaction, session_id)?,
        event,
        replayed: false,
    };
    insert_session_command_receipt(
        &transaction,
        idempotency_key,
        "attach_run",
        &fingerprint,
        &response,
        session_id,
        response.event.sequence,
    )?;
    transaction.commit()?;
    Ok(response)
}

fn start_turn(
    connection: &mut Connection,
    session_id: &str,
    request: StartTurnRequest,
    idempotency_key: &str,
) -> Result<StartTurnResponse, StorageError> {
    let fingerprint = session_command_fingerprint(Some(session_id), &request)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(mut response) = load_session_command_receipt::<StartTurnResponse>(
        &transaction,
        idempotency_key,
        "start_turn",
        &fingerprint,
    )? {
        response.replayed = true;
        transaction.commit()?;
        return Ok(response);
    }

    normalized_session_value(&request.turn_id, "turn ID")?;
    validate_message(&request.user_message, "user message")?;
    let summary = query_session_summary(&transaction, session_id)?;
    require_session_sequence(&summary, request.expected_sequence)?;
    if summary.status != SessionStatus::Ready || summary.active_turn_id.is_some() {
        return Err(StorageError::InvalidSessionTransition(format!(
            "session `{session_id}` must be ready before starting a turn"
        )));
    }
    let turn_exists = transaction
        .query_row(
            "SELECT 1 FROM session_turns WHERE id = ?1",
            [&request.turn_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    if turn_exists.is_some() {
        return Err(StorageError::InvalidSessionTransition(format!(
            "turn `{}` already exists",
            request.turn_id
        )));
    }
    let ordinal: i64 = transaction.query_row(
        "SELECT COALESCE(MAX(ordinal), 0) + 1 FROM session_turns WHERE session_id = ?1",
        [session_id],
        |row| row.get(0),
    )?;
    let timestamp = now();
    transaction.execute(
        r#"INSERT INTO session_turns(
               id, session_id, ordinal, status, user_message, assistant_message,
               started_at, completed_at
           ) VALUES (?1, ?2, ?3, 'open', ?4, NULL, ?5, NULL)"#,
        params![
            request.turn_id,
            session_id,
            ordinal,
            request.user_message,
            timestamp
        ],
    )?;
    let sequence = next_session_sequence(summary.sequence)?;
    let event = build_session_event(
        session_id,
        sequence,
        &timestamp,
        SessionEventData::UserMessage {
            turn_id: request.turn_id.clone(),
            content: request.user_message.clone(),
        },
    );
    insert_session_event(&transaction, session_id, &event)?;
    update_session_projection(
        &transaction,
        session_id,
        summary.sequence,
        SessionStatus::Running,
        Some(&request.turn_id),
        sequence,
        &timestamp,
    )?;
    let response = StartTurnResponse {
        session: query_session_summary(&transaction, session_id)?,
        turn: query_session_turn(&transaction, session_id, &request.turn_id)?,
        event,
        replayed: false,
    };
    insert_session_command_receipt(
        &transaction,
        idempotency_key,
        "start_turn",
        &fingerprint,
        &response,
        session_id,
        response.event.sequence,
    )?;
    transaction.commit()?;
    Ok(response)
}

fn flush_turn(
    connection: &mut Connection,
    session_id: &str,
    request: FlushSessionRequest,
    idempotency_key: &str,
    fail_before_flush_event: bool,
) -> Result<FlushSessionResponse, StorageError> {
    let fingerprint = session_command_fingerprint(Some(session_id), &request)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(mut response) = load_session_command_receipt::<FlushSessionResponse>(
        &transaction,
        idempotency_key,
        "flush_turn",
        &fingerprint,
    )? {
        response.replayed = true;
        transaction.commit()?;
        return Ok(response);
    }

    normalized_session_value(&request.turn_id, "turn ID")?;
    if let Some(message) = &request.assistant_message {
        validate_message(message, "assistant message")?;
    }
    let mut summary = query_session_summary(&transaction, session_id)?;
    require_session_sequence(&summary, request.expected_sequence)?;
    if summary.status != SessionStatus::Running
        || summary.active_turn_id.as_deref() != Some(request.turn_id.as_str())
    {
        return Err(StorageError::InvalidSessionTransition(format!(
            "turn `{}` is not the active turn for session `{session_id}`",
            request.turn_id
        )));
    }
    let turn = query_session_turn(&transaction, session_id, &request.turn_id)?;
    if turn.status != SessionTurnStatus::Open {
        return Err(StorageError::InvalidSessionTransition(format!(
            "turn `{}` is not open",
            request.turn_id
        )));
    }

    let timestamp = now();
    let mut events = Vec::with_capacity(if request.assistant_message.is_some() {
        2
    } else {
        1
    });
    if let Some(message) = &request.assistant_message {
        let sequence = next_session_sequence(summary.sequence)?;
        let event = build_session_event(
            session_id,
            sequence,
            &timestamp,
            SessionEventData::AssistantMessage {
                turn_id: request.turn_id.clone(),
                content: message.clone(),
            },
        );
        insert_session_event(&transaction, session_id, &event)?;
        update_session_projection(
            &transaction,
            session_id,
            summary.sequence,
            SessionStatus::Running,
            Some(&request.turn_id),
            sequence,
            &timestamp,
        )?;
        summary.sequence = sequence;
        summary.updated_at.clone_from(&timestamp);
        events.push(event);
    }

    let changed = transaction.execute(
        r#"UPDATE session_turns
           SET status = 'flushed', assistant_message = ?1, completed_at = ?2
           WHERE session_id = ?3 AND id = ?4 AND status = 'open'"#,
        params![
            request.assistant_message,
            timestamp,
            session_id,
            request.turn_id
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }

    #[cfg(test)]
    if fail_before_flush_event {
        return Err(StorageError::InjectedFailure);
    }
    #[cfg(not(test))]
    let _ = fail_before_flush_event;

    let flush_sequence = next_session_sequence(summary.sequence)?;
    let flush_event = build_session_event(
        session_id,
        flush_sequence,
        &timestamp,
        SessionEventData::TurnFlushed {
            turn_id: request.turn_id.clone(),
        },
    );
    insert_session_event(&transaction, session_id, &flush_event)?;
    update_session_projection(
        &transaction,
        session_id,
        summary.sequence,
        SessionStatus::Ready,
        None,
        flush_sequence,
        &timestamp,
    )?;
    events.push(flush_event);

    let response = FlushSessionResponse {
        session: query_session_summary(&transaction, session_id)?,
        turn: query_session_turn(&transaction, session_id, &request.turn_id)?,
        events,
        ack: SessionFlushAck {
            session_id: session_id.to_owned(),
            turn_id: request.turn_id.clone(),
            durability_sequence: flush_sequence,
        },
        replayed: false,
    };
    insert_session_command_receipt(
        &transaction,
        idempotency_key,
        "flush_turn",
        &fingerprint,
        &response,
        session_id,
        flush_sequence,
    )?;
    transaction.commit()?;
    Ok(response)
}

fn resume_session(
    connection: &mut Connection,
    session_id: &str,
    request: ResumeSessionRequest,
    idempotency_key: &str,
) -> Result<ResumeSessionResponse, StorageError> {
    let fingerprint = session_command_fingerprint(Some(session_id), &request)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(mut response) = load_session_command_receipt::<ResumeSessionResponse>(
        &transaction,
        idempotency_key,
        "resume_session",
        &fingerprint,
    )? {
        response.replayed = true;
        transaction.commit()?;
        return Ok(response);
    }

    let summary = query_session_summary(&transaction, session_id)?;
    require_session_sequence(&summary, request.expected_sequence)?;
    if summary.status != SessionStatus::NeedsAttention || summary.active_turn_id.is_some() {
        return Err(StorageError::InvalidSessionTransition(format!(
            "session `{session_id}` is not awaiting an explicit resume"
        )));
    }
    let timestamp = now();
    let sequence = next_session_sequence(summary.sequence)?;
    let event = build_session_event(
        session_id,
        sequence,
        &timestamp,
        SessionEventData::SessionResumed {
            from_status: summary.status.clone(),
        },
    );
    insert_session_event(&transaction, session_id, &event)?;
    update_session_projection(
        &transaction,
        session_id,
        summary.sequence,
        SessionStatus::Ready,
        None,
        sequence,
        &timestamp,
    )?;
    let response = ResumeSessionResponse {
        session: query_session_summary(&transaction, session_id)?,
        event,
        replayed: false,
    };
    insert_session_command_receipt(
        &transaction,
        idempotency_key,
        "resume_session",
        &fingerprint,
        &response,
        session_id,
        response.event.sequence,
    )?;
    transaction.commit()?;
    Ok(response)
}

fn recover_open_turns(connection: &mut Connection) -> Result<Vec<SessionEvent>, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut statement = transaction.prepare(
        r#"SELECT session_id, id FROM session_turns
           WHERE status = 'open' ORDER BY session_id, ordinal"#,
    )?;
    let open_turns = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);

    let mut recovered = Vec::with_capacity(open_turns.len());
    for (session_id, turn_id) in open_turns {
        let summary = query_session_summary(&transaction, &session_id)?;
        if summary.status != SessionStatus::Running
            || summary.active_turn_id.as_deref() != Some(turn_id.as_str())
        {
            return Err(StorageError::CorruptData(format!(
                "open turn `{turn_id}` disagrees with session `{session_id}` projection"
            )));
        }
        let timestamp = now();
        let changed = transaction.execute(
            r#"UPDATE session_turns
               SET status = 'interrupted', completed_at = ?1
               WHERE session_id = ?2 AND id = ?3 AND status = 'open'"#,
            params![timestamp, session_id, turn_id],
        )?;
        if changed != 1 {
            return Err(StorageError::ConcurrentModification);
        }
        let sequence = next_session_sequence(summary.sequence)?;
        let event = build_session_event(
            &session_id,
            sequence,
            &timestamp,
            SessionEventData::TurnInterrupted {
                turn_id: turn_id.clone(),
                reason: "process restarted before session/flush committed".into(),
            },
        );
        insert_session_event(&transaction, &session_id, &event)?;
        update_session_projection(
            &transaction,
            &session_id,
            summary.sequence,
            SessionStatus::NeedsAttention,
            None,
            sequence,
            &timestamp,
        )?;
        recovered.push(event);
    }
    transaction.commit()?;
    Ok(recovered)
}

fn query_session_summary(
    connection: &Connection,
    session_id: &str,
) -> Result<SessionSummary, StorageError> {
    query_session_summary_optional(connection, session_id)?
        .ok_or_else(|| StorageError::SessionNotFound(session_id.to_owned()))
}

fn query_session_summary_optional(
    connection: &Connection,
    session_id: &str,
) -> Result<Option<SessionSummary>, StorageError> {
    let row = connection
        .query_row(
            r#"SELECT id, title, status, created_at, updated_at, sequence,
                      projection_sequence, active_turn_id
               FROM sessions WHERE id = ?1"#,
            [session_id],
            decode_session_summary_row,
        )
        .optional()?;
    row.map(StoredSessionSummaryRow::decode).transpose()
}

fn decode_session_summary_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<StoredSessionSummaryRow> {
    Ok(StoredSessionSummaryRow {
        id: row.get(0)?,
        title: row.get(1)?,
        status: row.get(2)?,
        created_at: row.get(3)?,
        updated_at: row.get(4)?,
        sequence: row.get(5)?,
        projection_sequence: row.get(6)?,
        active_turn_id: row.get(7)?,
    })
}

fn query_session_turns(
    connection: &Connection,
    session_id: &str,
) -> Result<Vec<SessionTurn>, StorageError> {
    let mut statement = connection.prepare(
        r#"SELECT id, session_id, ordinal, status, user_message, assistant_message,
                  started_at, completed_at
           FROM session_turns WHERE session_id = ?1 ORDER BY ordinal"#,
    )?;
    let rows = statement
        .query_map([session_id], decode_session_turn_row)?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter().map(StoredSessionTurnRow::decode).collect()
}

fn query_session_turn(
    connection: &Connection,
    session_id: &str,
    turn_id: &str,
) -> Result<SessionTurn, StorageError> {
    let row = connection
        .query_row(
            r#"SELECT id, session_id, ordinal, status, user_message, assistant_message,
                      started_at, completed_at
               FROM session_turns WHERE session_id = ?1 AND id = ?2"#,
            params![session_id, turn_id],
            decode_session_turn_row,
        )
        .optional()?;
    row.ok_or_else(|| StorageError::SessionTurnNotFound(turn_id.to_owned()))?
        .decode()
}

fn decode_session_turn_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredSessionTurnRow> {
    Ok(StoredSessionTurnRow {
        id: row.get(0)?,
        session_id: row.get(1)?,
        ordinal: row.get(2)?,
        status: row.get(3)?,
        user_message: row.get(4)?,
        assistant_message: row.get(5)?,
        started_at: row.get(6)?,
        completed_at: row.get(7)?,
    })
}

fn query_session_events(
    connection: &Connection,
    session_id: &str,
    after: i64,
) -> Result<Vec<SessionEvent>, StorageError> {
    let mut statement = connection.prepare(
        r#"SELECT sequence, event_id, event_kind, payload_version, payload_json,
                  turn_id, created_at
           FROM session_events
           WHERE session_id = ?1 AND sequence > ?2 ORDER BY sequence"#,
    )?;
    let mut rows = statement.query(params![session_id, after])?;
    let mut events = Vec::new();
    let mut expected = after.checked_add(1);
    while let Some(row) = rows.next()? {
        let stored = StoredSessionEventRow {
            sequence: row.get(0)?,
            event_id: row.get(1)?,
            event_kind: row.get(2)?,
            payload_version: row.get(3)?,
            payload_json: row.get(4)?,
            turn_id: row.get(5)?,
            created_at: row.get(6)?,
        };
        if let Some(expected_sequence) = expected
            && stored.sequence != expected_sequence
        {
            return Err(StorageError::CorruptData(format!(
                "session event sequence gap: expected {expected_sequence}, found {}",
                stored.sequence
            )));
        }
        expected = stored.sequence.checked_add(1);
        events.push(stored.decode()?);
    }
    Ok(events)
}

fn insert_session_event(
    connection: &Connection,
    session_id: &str,
    event: &SessionEvent,
) -> Result<(), StorageError> {
    let sequence = u64_to_i64(event.sequence, "session event sequence")?;
    connection.execute(
        r#"INSERT INTO session_events(
               session_id, sequence, event_id, event_kind, payload_version,
               payload_json, turn_id, created_at
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
        params![
            session_id,
            sequence,
            event.id,
            session_event_kind(&event.data),
            SESSION_EVENT_PAYLOAD_VERSION_V1,
            serde_json::to_string(event)?,
            session_event_turn_id(&event.data),
            event.at,
        ],
    )?;
    Ok(())
}

fn build_session_event(
    session_id: &str,
    sequence: u64,
    at: &str,
    data: SessionEventData,
) -> SessionEvent {
    SessionEvent {
        sequence,
        id: format!("{session_id}:event:{sequence}"),
        at: at.to_owned(),
        data,
    }
}

#[allow(clippy::too_many_arguments)]
fn update_session_projection(
    connection: &Connection,
    session_id: &str,
    expected_sequence: u64,
    status: SessionStatus,
    active_turn_id: Option<&str>,
    new_sequence: u64,
    updated_at: &str,
) -> Result<(), StorageError> {
    if new_sequence != next_session_sequence(expected_sequence)? {
        return Err(StorageError::InvalidSessionTransition(
            "session projection must advance exactly one sequence".into(),
        ));
    }
    let changed = connection.execute(
        r#"UPDATE sessions
           SET status = ?1, updated_at = ?2, sequence = ?3,
               projection_sequence = ?3, active_turn_id = ?4
           WHERE id = ?5 AND sequence = ?6 AND projection_sequence = ?6"#,
        params![
            session_status_to_db(&status),
            updated_at,
            u64_to_i64(new_sequence, "session sequence")?,
            active_turn_id,
            session_id,
            u64_to_i64(expected_sequence, "expected session sequence")?,
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    Ok(())
}

fn validate_session_turn_projection(
    session: &SessionSummary,
    turns: &[SessionTurn],
) -> Result<(), StorageError> {
    let open_turns = turns
        .iter()
        .filter(|turn| turn.status == SessionTurnStatus::Open)
        .collect::<Vec<_>>();
    match (&session.status, session.active_turn_id.as_deref()) {
        (SessionStatus::Running, Some(active_turn_id))
            if open_turns.len() == 1 && open_turns[0].id == active_turn_id =>
        {
            Ok(())
        }
        (SessionStatus::Ready | SessionStatus::NeedsAttention, None) if open_turns.is_empty() => {
            Ok(())
        }
        _ => Err(StorageError::CorruptData(format!(
            "session `{}` status/active turn projection is inconsistent",
            session.id
        ))),
    }
}

fn session_command_fingerprint<T: Serialize>(
    session_id: Option<&str>,
    request: &T,
) -> Result<String, StorageError> {
    let request = serde_json::to_value(request)?;
    Ok(serde_json::to_string(&json!({
        "session_id": session_id,
        "request": request,
    }))?)
}

fn load_session_command_receipt<T: DeserializeOwned>(
    connection: &Connection,
    idempotency_key: &str,
    operation: &str,
    request_fingerprint: &str,
) -> Result<Option<T>, StorageError> {
    let stored = connection
        .query_row(
            r#"SELECT operation, request_fingerprint, response_json
               FROM session_command_receipts WHERE idempotency_key = ?1"#,
            [idempotency_key],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((stored_operation, stored_fingerprint, response_json)) = stored else {
        return Ok(None);
    };
    if stored_operation != operation || stored_fingerprint != request_fingerprint {
        return Err(StorageError::IdempotencyConflict);
    }
    let value: Value = serde_json::from_str(&response_json)?;
    if value.get("replayed") != Some(&Value::Bool(false)) {
        return Err(StorageError::CorruptData(
            "stored session command receipt must contain the original response".into(),
        ));
    }
    Ok(Some(serde_json::from_value(value)?))
}

#[allow(clippy::too_many_arguments)]
fn insert_session_command_receipt<T: Serialize>(
    connection: &Connection,
    idempotency_key: &str,
    operation: &str,
    request_fingerprint: &str,
    response: &T,
    session_id: &str,
    event_sequence: u64,
) -> Result<(), StorageError> {
    connection.execute(
        r#"INSERT INTO session_command_receipts(
               idempotency_key, operation, request_fingerprint, response_json,
               session_id, event_sequence, created_at
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
        params![
            idempotency_key,
            operation,
            request_fingerprint,
            serde_json::to_string(response)?,
            session_id,
            u64_to_i64(event_sequence, "session receipt event sequence")?,
            now(),
        ],
    )?;
    Ok(())
}

fn require_session_sequence(
    summary: &SessionSummary,
    expected_sequence: u64,
) -> Result<(), StorageError> {
    if summary.sequence != expected_sequence {
        Err(StorageError::ConcurrentModification)
    } else {
        Ok(())
    }
}

fn next_session_sequence(sequence: u64) -> Result<u64, StorageError> {
    sequence
        .checked_add(1)
        .ok_or(StorageError::IntegerOutOfRange("session sequence"))
}

fn normalized_session_value<'a>(
    value: &'a str,
    field: &'static str,
) -> Result<&'a str, StorageError> {
    if value.is_empty() || value.trim() != value {
        Err(StorageError::InvalidSessionTransition(format!(
            "{field} must be non-empty and canonical"
        )))
    } else {
        Ok(value)
    }
}

fn validate_message(value: &str, field: &'static str) -> Result<(), StorageError> {
    if value.trim().is_empty() {
        Err(StorageError::InvalidSessionTransition(format!(
            "{field} cannot be empty"
        )))
    } else {
        Ok(())
    }
}

fn load_snapshot(connection: &mut Connection, run_id: &str) -> Result<RunSnapshot, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let snapshot = query_snapshot(&transaction, run_id)?;
    transaction.commit()?;
    Ok(snapshot)
}

fn load_run(connection: &mut Connection, run_id: &str) -> Result<StoredRun, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let snapshot = query_snapshot(&transaction, run_id)?;
    let events = query_events(&transaction, run_id, 0)?;
    let event_head = events.last().map_or(0, |event| event.sequence);
    if event_head != snapshot.run.sequence {
        return Err(StorageError::CorruptData(format!(
            "run head {} does not match event head {event_head}",
            snapshot.run.sequence
        )));
    }
    transaction.commit()?;
    Ok(StoredRun { snapshot, events })
}

fn query_snapshot(connection: &Connection, run_id: &str) -> Result<RunSnapshot, StorageError> {
    let row = connection
        .query_row(
            r#"SELECT
                   i.id, i.title, i.severity, i.status, i.service, i.region, i.user_impact, i.since,
                   r.id, r.status, r.environment, r.started_at, r.duration_seconds, r.agent,
                   r.sequence, r.projection_sequence, r.metrics_json, r.evidence_json,
                   r.tool_policy_json, r.execution_status
               FROM runs r JOIN incidents i ON i.id = r.incident_id
               WHERE r.id = ?1"#,
            [run_id],
            |row| {
                Ok(StoredSnapshotRow {
                    incident_id: row.get(0)?,
                    incident_title: row.get(1)?,
                    incident_severity: row.get(2)?,
                    incident_status: row.get(3)?,
                    service: row.get(4)?,
                    region: row.get(5)?,
                    user_impact: row.get(6)?,
                    since: row.get(7)?,
                    run_id: row.get(8)?,
                    run_status: row.get(9)?,
                    environment: row.get(10)?,
                    started_at: row.get(11)?,
                    duration_seconds: row.get(12)?,
                    agent: row.get(13)?,
                    sequence: row.get(14)?,
                    projection_sequence: row.get(15)?,
                    metrics_json: row.get(16)?,
                    evidence_json: row.get(17)?,
                    tool_policy_json: row.get(18)?,
                    execution_status: row.get(19)?,
                })
            },
        )
        .optional()?
        .ok_or_else(|| StorageError::RunNotFound(run_id.to_owned()))?;
    row.decode()
}

fn events_after(
    connection: &mut Connection,
    run_id: &str,
    after: u64,
) -> Result<Vec<RunEvent>, StorageError> {
    let after = u64_to_i64(after, "event cursor")?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let run_exists = transaction
        .query_row("SELECT 1 FROM runs WHERE id = ?1", [run_id], |row| {
            row.get::<_, i64>(0)
        })
        .optional()?;
    if run_exists.is_none() {
        return Err(StorageError::RunNotFound(run_id.to_owned()));
    }
    let events = query_events(&transaction, run_id, after)?;
    transaction.commit()?;
    Ok(events)
}

fn query_events(
    connection: &Connection,
    run_id: &str,
    after: i64,
) -> Result<Vec<RunEvent>, StorageError> {
    let mut statement = connection.prepare(
        r#"SELECT sequence, event_id, event_kind, payload_version, payload_json
           FROM run_events WHERE run_id = ?1 AND sequence > ?2 ORDER BY sequence"#,
    )?;
    let mut rows = statement.query(params![run_id, after])?;
    let mut events = Vec::new();
    let mut expected = after.checked_add(1);
    while let Some(row) = rows.next()? {
        let stored = StoredEventRow {
            sequence: row.get(0)?,
            event_id: row.get(1)?,
            event_kind: row.get(2)?,
            payload_version: row.get(3)?,
            payload_json: row.get(4)?,
        };
        if let Some(expected_sequence) = expected
            && stored.sequence != expected_sequence
        {
            return Err(StorageError::CorruptData(format!(
                "event sequence gap: expected {expected_sequence}, found {}",
                stored.sequence
            )));
        }
        expected = stored.sequence.checked_add(1);
        events.push(stored.decode()?);
    }
    Ok(events)
}

fn load_review_receipt(
    connection: &Connection,
    idempotency_key: &str,
) -> Result<Option<ReviewReceipt>, StorageError> {
    let stored = connection
        .query_row(
            r#"SELECT operation, request_fingerprint, response_json, run_id, event_sequence
               FROM idempotency_receipts WHERE idempotency_key = ?1"#,
            [idempotency_key],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((operation, request_fingerprint, response_json, run_id, event_sequence)) = stored
    else {
        return Ok(None);
    };
    if operation != "review" {
        return Err(StorageError::IdempotencyConflict);
    }
    validate_fingerprint(&request_fingerprint)?;
    let response: ReviewResponse = serde_json::from_str(&response_json)?;
    if response.replayed {
        return Err(StorageError::CorruptData(
            "stored review receipt must contain the original response".into(),
        ));
    }
    if response.run.id != run_id
        || u64_to_i64(response.run.sequence, "receipt run sequence")? != event_sequence
        || u64_to_i64(response.event.sequence, "receipt event sequence")? != event_sequence
    {
        return Err(StorageError::CorruptData(
            "review receipt identity does not match its stored run/event reference".into(),
        ));
    }
    Ok(Some(ReviewReceipt {
        request_fingerprint,
        response,
    }))
}

fn commit_review(
    connection: &mut Connection,
    commit: ReviewCommit,
    fail_after_event: bool,
) -> Result<CommitOutcome, StorageError> {
    validate_commit(&commit)?;
    let key = normalized_key(&commit.idempotency_key)?.to_owned();
    let new_sequence = u64_to_i64(commit.snapshot.run.sequence, "run sequence")?;
    let response_json = serde_json::to_string(&commit.response)?;

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(receipt) = load_review_receipt(&transaction, &key)? {
        if receipt.request_fingerprint != commit.request_fingerprint {
            return Err(StorageError::IdempotencyConflict);
        }
        transaction.commit()?;
        return Ok(CommitOutcome::Replayed(Box::new(receipt)));
    }

    update_projection(&transaction, &commit.snapshot, commit.expected_sequence)?;

    if commit.event.data.is_some() {
        insert_event_v2(&transaction, &commit.snapshot.run.id, &commit.event)?;
    } else {
        insert_event_v1(&transaction, &commit.snapshot.run.id, &commit.event)?;
    }

    transaction.execute(
        r#"INSERT INTO idempotency_receipts(
               idempotency_key, operation, request_fingerprint, response_json, run_id,
               event_sequence, created_at
           ) VALUES (?1, 'review', ?2, ?3, ?4, ?5, ?6)"#,
        params![
            key,
            commit.request_fingerprint,
            response_json,
            commit.snapshot.run.id,
            new_sequence,
            Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        ],
    )?;

    if let Some(dispatch) = &commit.dispatch {
        insert_dispatch_job(
            &transaction,
            &commit.snapshot.run.id,
            new_sequence,
            dispatch,
        )?;
    }

    #[cfg(test)]
    if fail_after_event {
        return Err(StorageError::InjectedFailure);
    }
    #[cfg(not(test))]
    let _ = fail_after_event;

    transaction.commit()?;
    Ok(CommitOutcome::Committed)
}

fn peek_next_dispatch(connection: &mut Connection) -> Result<Option<DispatchJob>, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let call_id = transaction
        .query_row(
            r#"SELECT call_id FROM dispatch_jobs
               WHERE status = 'queued'
               ORDER BY queued_at, call_id
               LIMIT 1"#,
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let job = call_id
        .map(|call_id| query_dispatch_job(&transaction, &call_id))
        .transpose()
        .map(Option::flatten)?;
    transaction.commit()?;
    Ok(job)
}

fn query_started_dispatches(connection: &mut Connection) -> Result<Vec<DispatchJob>, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let mut statement = transaction.prepare(
        r#"SELECT call_id FROM dispatch_jobs
           WHERE status = 'started'
           ORDER BY started_at, call_id"#,
    )?;
    let call_ids = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    let jobs = call_ids
        .iter()
        .map(|call_id| {
            query_dispatch_job(&transaction, call_id)?.ok_or_else(|| {
                StorageError::CorruptData(format!(
                    "started dispatch `{call_id}` disappeared during one read"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    transaction.commit()?;
    Ok(jobs)
}

fn query_dispatch_job(
    connection: &Connection,
    call_id: &str,
) -> Result<Option<DispatchJob>, StorageError> {
    connection
        .query_row(
            r#"SELECT
                   call_id, run_id, approval_id, approval_event_sequence,
                   tool_name, tool_version, effect, args_json, args_digest,
                   policy_id, policy_revision, sandbox_profile, status, attempt,
                   result_json, queued_at, started_at, finished_at,
                   start_event_sequence, result_event_sequence
               FROM dispatch_jobs WHERE call_id = ?1"#,
            [call_id],
            |row| {
                Ok(StoredDispatchRow {
                    call_id: row.get(0)?,
                    run_id: row.get(1)?,
                    approval_id: row.get(2)?,
                    approval_event_sequence: row.get(3)?,
                    tool_name: row.get(4)?,
                    tool_version: row.get(5)?,
                    effect: row.get(6)?,
                    args_json: row.get(7)?,
                    args_digest: row.get(8)?,
                    policy_id: row.get(9)?,
                    policy_revision: row.get(10)?,
                    sandbox_profile: row.get(11)?,
                    status: row.get(12)?,
                    attempt: row.get(13)?,
                    result_json: row.get(14)?,
                    queued_at: row.get(15)?,
                    started_at: row.get(16)?,
                    finished_at: row.get(17)?,
                    start_event_sequence: row.get(18)?,
                    result_event_sequence: row.get(19)?,
                })
            },
        )
        .optional()?
        .map(StoredDispatchRow::decode)
        .transpose()
}

fn claim_next_dispatch(
    connection: &mut Connection,
    commit: DispatchStartCommit,
    inject_failure: bool,
) -> Result<ClaimOutcome, StorageError> {
    validate_dispatch_transition(
        &commit.call_id,
        commit.expected_sequence,
        &commit.snapshot,
        &commit.event,
    )?;
    if execution_status_to_db(&commit.snapshot.run.status) != "running" {
        return Err(StorageError::InvalidDispatchTransition(
            "claim projection must have running execution status".into(),
        ));
    }

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let queue_head = transaction
        .query_row(
            r#"SELECT call_id FROM dispatch_jobs
               WHERE status = 'queued'
               ORDER BY queued_at, call_id
               LIMIT 1"#,
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if queue_head.as_deref() != Some(commit.call_id.as_str()) {
        transaction.commit()?;
        return Ok(ClaimOutcome::NotAvailable);
    }

    let job = query_dispatch_job(&transaction, &commit.call_id)?
        .ok_or_else(|| StorageError::DispatchJobNotFound(commit.call_id.clone()))?;
    if job.status != DispatchStatus::Queued || job.run_id != commit.snapshot.run.id {
        return Err(StorageError::InvalidDispatchTransition(
            "queue head does not match the supplied run projection".into(),
        ));
    }
    match commit.event.data.as_ref() {
        Some(RunEventData::ToolDispatchStarted {
            call_id,
            sandbox_profile,
            status: ToolCallStatus::Running,
            ..
        }) if call_id == &job.call_id && sandbox_profile == &job.sandbox_profile => {}
        _ => {
            return Err(StorageError::InvalidDispatchTransition(
                "claim requires matching v2 tool_dispatch_started data".into(),
            ));
        }
    }

    update_projection(&transaction, &commit.snapshot, commit.expected_sequence)?;
    insert_event_v2(&transaction, &job.run_id, &commit.event)?;
    let changed = transaction.execute(
        r#"UPDATE dispatch_jobs SET
               status = 'started',
               attempt = attempt + 1,
               started_at = ?1,
               start_event_sequence = ?2
           WHERE call_id = ?3 AND status = 'queued' AND attempt = 0"#,
        params![
            now(),
            u64_to_i64(commit.event.sequence, "dispatch start event sequence")?,
            commit.call_id,
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }

    #[cfg(test)]
    if inject_failure {
        return Err(StorageError::InjectedFailure);
    }
    #[cfg(not(test))]
    let _ = inject_failure;

    let claimed = query_dispatch_job(&transaction, &job.call_id)?.ok_or_else(|| {
        StorageError::CorruptData("claimed dispatch disappeared before commit".into())
    })?;
    transaction.commit()?;
    Ok(ClaimOutcome::Claimed(Box::new(claimed)))
}

fn complete_dispatch(
    connection: &mut Connection,
    commit: DispatchCompleteCommit,
    inject_failure: bool,
) -> Result<DispatchJob, StorageError> {
    validate_dispatch_transition(
        &commit.call_id,
        commit.expected_sequence,
        &commit.snapshot,
        &commit.event,
    )?;
    validate_completion_status(&commit.snapshot.run.status)?;

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let job = query_dispatch_job(&transaction, &commit.call_id)?
        .ok_or_else(|| StorageError::DispatchJobNotFound(commit.call_id.clone()))?;
    if job.status != DispatchStatus::Started || job.run_id != commit.snapshot.run.id {
        return Err(StorageError::InvalidDispatchTransition(
            "only the matching started dispatch may be completed".into(),
        ));
    }
    match commit.event.data.as_ref() {
        Some(RunEventData::ToolResult {
            call_id,
            outcome,
            status,
        }) if call_id == &job.call_id
            && status == &outcome.call_status()
            && serde_json::to_value(outcome)? == commit.result_json => {}
        _ => {
            return Err(StorageError::InvalidDispatchTransition(
                "completion requires matching v2 tool_result data".into(),
            ));
        }
    }

    update_projection(&transaction, &commit.snapshot, commit.expected_sequence)?;
    insert_event_v2(&transaction, &job.run_id, &commit.event)?;
    let result_json = serde_json::to_string(&commit.result_json)?;
    let changed = transaction.execute(
        r#"UPDATE dispatch_jobs SET
               status = 'finished',
               result_json = ?1,
               finished_at = ?2,
               result_event_sequence = ?3
           WHERE call_id = ?4 AND status = 'started' AND result_json IS NULL"#,
        params![
            result_json,
            now(),
            u64_to_i64(commit.event.sequence, "dispatch result event sequence")?,
            commit.call_id,
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }

    #[cfg(test)]
    if inject_failure {
        return Err(StorageError::InjectedFailure);
    }
    #[cfg(not(test))]
    let _ = inject_failure;

    let completed = query_dispatch_job(&transaction, &job.call_id)?.ok_or_else(|| {
        StorageError::CorruptData("completed dispatch disappeared before commit".into())
    })?;
    transaction.commit()?;
    Ok(completed)
}

fn recover_started(
    connection: &mut Connection,
    commit: DispatchRecoveryCommit,
) -> Result<DispatchJob, StorageError> {
    validate_dispatch_transition(
        &commit.call_id,
        commit.expected_sequence,
        &commit.snapshot,
        &commit.event,
    )?;
    if execution_status_to_db(&commit.snapshot.run.status) != "needs_attention" {
        return Err(StorageError::InvalidDispatchTransition(
            "started-call recovery must set needs_attention".into(),
        ));
    }
    let outcome: ToolOutcome = serde_json::from_value(commit.result_json.clone())?;
    if !matches!(outcome, ToolOutcome::OutcomeUnknown { .. }) {
        return Err(StorageError::InvalidDispatchTransition(
            "started-call recovery result must declare outcome_unknown".into(),
        ));
    }

    complete_dispatch(
        connection,
        DispatchCompleteCommit {
            call_id: commit.call_id,
            expected_sequence: commit.expected_sequence,
            snapshot: commit.snapshot,
            event: commit.event,
            result_json: commit.result_json,
        },
        false,
    )
}

fn insert_dispatch_job(
    connection: &Connection,
    run_id: &str,
    approval_event_sequence: i64,
    job: &DispatchJobSpec,
) -> Result<(), StorageError> {
    connection.execute(
        r#"INSERT INTO dispatch_jobs(
               call_id, run_id, approval_id, approval_event_sequence,
               tool_name, tool_version, effect, args_json, args_digest,
               policy_id, policy_revision, sandbox_profile, status, attempt, queued_at
           ) VALUES (
               ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'queued', 0, ?13
           )"#,
        params![
            job.call_id,
            run_id,
            job.approval_id,
            approval_event_sequence,
            job.tool_name,
            job.tool_version,
            tool_effect_to_db(&job.effect),
            serde_json::to_string(&job.args_json)?,
            job.args_digest,
            job.policy_id,
            job.policy_revision,
            sandbox_profile_to_db(&job.sandbox_profile),
            now(),
        ],
    )?;
    Ok(())
}

fn update_projection(
    connection: &Connection,
    snapshot: &RunSnapshot,
    expected_sequence: u64,
) -> Result<(), StorageError> {
    let expected_next = expected_sequence
        .checked_add(1)
        .ok_or(StorageError::IntegerOutOfRange("expected run sequence"))?;
    if snapshot.run.sequence != expected_next {
        return Err(StorageError::InvalidDispatchTransition(
            "projection must advance exactly one event".into(),
        ));
    }

    let current = connection
        .query_row(
            "SELECT sequence, incident_id FROM runs WHERE id = ?1",
            [&snapshot.run.id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .ok_or_else(|| StorageError::RunNotFound(snapshot.run.id.clone()))?;
    if current.0 != u64_to_i64(expected_sequence, "expected run sequence")? {
        return Err(StorageError::ConcurrentModification);
    }
    if current.1 != snapshot.incident.id {
        return Err(StorageError::CorruptData(
            "projection references a different incident".into(),
        ));
    }

    let changed = connection.execute(
        r#"UPDATE runs SET
               status = ?1,
               execution_status = ?2,
               environment = ?3,
               started_at = ?4,
               duration_seconds = ?5,
               agent = ?6,
               sequence = ?7,
               projection_sequence = ?7,
               metrics_json = ?8,
               evidence_json = ?9,
               tool_policy_json = ?10
           WHERE id = ?11 AND sequence = ?12"#,
        params![
            legacy_run_status_to_db(&snapshot.run.status),
            execution_status_to_db(&snapshot.run.status),
            snapshot.run.environment,
            snapshot.run.started_at,
            u64_to_i64(snapshot.run.duration_seconds, "duration_seconds")?,
            snapshot.run.agent,
            u64_to_i64(snapshot.run.sequence, "run sequence")?,
            serde_json::to_string(&snapshot.metrics)?,
            serde_json::to_string(&snapshot.evidence)?,
            snapshot
                .tool_policy
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?,
            snapshot.run.id,
            u64_to_i64(expected_sequence, "expected run sequence")?,
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    Ok(())
}

fn insert_event_v1(
    connection: &Connection,
    run_id: &str,
    event: &RunEvent,
) -> Result<(), StorageError> {
    insert_event(connection, run_id, event, EVENT_PAYLOAD_VERSION_V1)
}

fn insert_event_v2(
    connection: &Connection,
    run_id: &str,
    event: &RunEvent,
) -> Result<(), StorageError> {
    insert_event(connection, run_id, event, EVENT_PAYLOAD_VERSION_V2)
}

fn insert_event(
    connection: &Connection,
    run_id: &str,
    event: &RunEvent,
    payload_version: i64,
) -> Result<(), StorageError> {
    let sequence = u64_to_i64(event.sequence, "event sequence")?;
    connection.execute(
        r#"INSERT INTO run_events(
               run_id, sequence, event_id, event_kind, payload_version, payload_json
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)"#,
        params![
            run_id,
            sequence,
            event.id,
            event_kind(&event.event_type),
            payload_version,
            serde_json::to_string(event)?,
        ],
    )?;
    Ok(())
}

fn validate_seed(snapshot: &RunSnapshot, events: &[RunEvent]) -> Result<(), StorageError> {
    if snapshot.incident.id.is_empty() || snapshot.run.id.is_empty() {
        return Err(StorageError::CorruptData("seed IDs cannot be empty".into()));
    }
    let mut expected = 1_u64;
    for event in events {
        if event.sequence != expected {
            return Err(StorageError::CorruptData(format!(
                "seed event sequence gap: expected {expected}, found {}",
                event.sequence
            )));
        }
        if event.id.is_empty() {
            return Err(StorageError::CorruptData(
                "seed event ID cannot be empty".into(),
            ));
        }
        event_kind(&event.event_type);
        expected = expected
            .checked_add(1)
            .ok_or(StorageError::IntegerOutOfRange("seed event sequence"))?;
    }
    let event_head = events.last().map_or(0, |event| event.sequence);
    if event_head != snapshot.run.sequence {
        return Err(StorageError::CorruptData(format!(
            "run head {} does not match seeded event head {event_head}",
            snapshot.run.sequence
        )));
    }
    Ok(())
}

fn validate_commit(commit: &ReviewCommit) -> Result<(), StorageError> {
    validate_fingerprint(&commit.request_fingerprint)?;
    let expected_next = commit
        .expected_sequence
        .checked_add(1)
        .ok_or(StorageError::IntegerOutOfRange("expected run sequence"))?;
    if commit.snapshot.run.id.is_empty()
        || commit.event.id.is_empty()
        || commit.event.sequence != expected_next
        || commit.snapshot.run.sequence != expected_next
        || commit.response.run != commit.snapshot.run
        || commit.response.event != commit.event
        || commit.response.replayed
    {
        return Err(StorageError::CorruptData(
            "review commit fields do not describe one next event and projection".into(),
        ));
    }
    event_kind(&commit.event.event_type);
    if let Some(dispatch) = &commit.dispatch {
        validate_dispatch_spec(dispatch)?;
        if execution_status_to_db(&commit.snapshot.run.status) != "queued" {
            return Err(StorageError::InvalidDispatchTransition(
                "approval with a dispatch must produce a queued run".into(),
            ));
        }
        let approval = commit.event.approval.as_ref().ok_or_else(|| {
            StorageError::InvalidDispatchTransition(
                "dispatch enqueue requires an approval decision event".into(),
            )
        })?;
        if commit.event.event_type != EventType::Approval
            || approval.status != ApprovalStatus::Approved
            || approval.id != dispatch.approval_id
            || approval.call_id.as_deref() != Some(dispatch.call_id.as_str())
            || approval.tool != dispatch.tool_name
            || approval.policy_revision.as_deref() != Some(dispatch.policy_revision.as_str())
            || approval.arguments_digest.as_deref() != Some(dispatch.args_digest.as_str())
            || approval.sandbox_profile.as_ref() != Some(&dispatch.sandbox_profile)
            || approval.scope != Some(ApprovalScope::AllowOnce)
        {
            return Err(StorageError::InvalidDispatchTransition(
                "dispatch must reference the approved event and approval ID".into(),
            ));
        }
        match commit.event.data.as_ref() {
            Some(RunEventData::ApprovalDecided {
                approval_id,
                call_id,
                decision: ReviewDecision::Approve,
                status: ToolCallStatus::Queued,
            }) if approval_id == &dispatch.approval_id && call_id == &dispatch.call_id => {}
            _ => {
                return Err(StorageError::InvalidDispatchTransition(
                    "dispatch enqueue requires matching v2 approval_decided data".into(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_dispatch_spec(job: &DispatchJobSpec) -> Result<(), StorageError> {
    for (value, field) in [
        (&job.call_id, "call ID"),
        (&job.approval_id, "approval ID"),
        (&job.tool_name, "tool name"),
        (&job.tool_version, "tool version"),
        (&job.args_digest, "argument digest"),
        (&job.policy_id, "policy ID"),
        (&job.policy_revision, "policy revision"),
    ] {
        normalized_identifier(value, field)?;
    }
    if !job.args_json.is_object() {
        return Err(StorageError::InvalidDispatchTransition(
            "tool arguments must be a JSON object".into(),
        ));
    }
    Ok(())
}

fn validate_dispatch_transition(
    call_id: &str,
    expected_sequence: u64,
    snapshot: &RunSnapshot,
    event: &RunEvent,
) -> Result<(), StorageError> {
    normalized_identifier(call_id, "call ID")?;
    normalized_identifier(&event.id, "event ID")?;
    let expected_next = expected_sequence
        .checked_add(1)
        .ok_or(StorageError::IntegerOutOfRange("expected run sequence"))?;
    if snapshot.run.sequence != expected_next || event.sequence != expected_next {
        return Err(StorageError::InvalidDispatchTransition(
            "dispatch transition must append exactly one event and projection".into(),
        ));
    }
    if let Some(stored_call_id) = event.metadata.get("call_id")
        && stored_call_id.as_str() != Some(call_id)
    {
        return Err(StorageError::InvalidDispatchTransition(
            "dispatch event call_id metadata does not match the job".into(),
        ));
    }
    event_kind(&event.event_type);
    Ok(())
}

fn validate_completion_status(status: &RunStatus) -> Result<(), StorageError> {
    if matches!(
        execution_status_to_db(status),
        "waiting_for_approval" | "queued"
    ) {
        return Err(StorageError::InvalidDispatchTransition(
            "a completed dispatch cannot leave the run waiting or queued".into(),
        ));
    }
    Ok(())
}

fn validate_fingerprint(fingerprint: &str) -> Result<(), StorageError> {
    let value: Value = serde_json::from_str(fingerprint)?;
    if !value.is_object() {
        return Err(StorageError::CorruptData(
            "review request fingerprint must be a JSON object".into(),
        ));
    }
    Ok(())
}

fn normalized_key(key: &str) -> Result<&str, StorageError> {
    let key = key.trim();
    if key.is_empty() {
        Err(StorageError::EmptyIdempotencyKey)
    } else {
        Ok(key)
    }
}

fn normalized_identifier<'a>(value: &'a str, field: &'static str) -> Result<&'a str, StorageError> {
    let value = value.trim();
    if value.is_empty() {
        Err(StorageError::InvalidDispatchTransition(format!(
            "{field} cannot be empty"
        )))
    } else {
        Ok(value)
    }
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn u64_to_i64(value: u64, field: &'static str) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::IntegerOutOfRange(field))
}

fn i64_to_u64(value: i64, field: &'static str) -> Result<u64, StorageError> {
    u64::try_from(value).map_err(|_| StorageError::IntegerOutOfRange(field))
}

fn severity_to_db(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    }
}

fn severity_from_db(value: &str) -> Result<Severity, StorageError> {
    match value {
        "critical" => Ok(Severity::Critical),
        "high" => Ok(Severity::High),
        "medium" => Ok(Severity::Medium),
        "low" => Ok(Severity::Low),
        other => Err(StorageError::CorruptData(format!(
            "unknown incident severity `{other}`"
        ))),
    }
}

fn incident_status_to_db(status: &IncidentStatus) -> &'static str {
    match status {
        IncidentStatus::Investigating => "investigating",
        IncidentStatus::Mitigating => "mitigating",
        IncidentStatus::Resolved => "resolved",
    }
}

fn incident_status_from_db(value: &str) -> Result<IncidentStatus, StorageError> {
    match value {
        "investigating" => Ok(IncidentStatus::Investigating),
        "mitigating" => Ok(IncidentStatus::Mitigating),
        "resolved" => Ok(IncidentStatus::Resolved),
        other => Err(StorageError::CorruptData(format!(
            "unknown incident status `{other}`"
        ))),
    }
}

fn legacy_run_status_to_db(status: &RunStatus) -> &'static str {
    match status {
        RunStatus::WaitingForApproval => "waiting_for_approval",
        RunStatus::Queued
        | RunStatus::Running
        | RunStatus::Blocked
        | RunStatus::NeedsAttention
        | RunStatus::Active => "active",
        RunStatus::Succeeded => "succeeded",
        RunStatus::Failed => "failed",
        RunStatus::Cancelled => "cancelled",
    }
}

fn execution_status_to_db(status: &RunStatus) -> &'static str {
    match status {
        RunStatus::WaitingForApproval => "waiting_for_approval",
        RunStatus::Queued => "queued",
        RunStatus::Running => "running",
        RunStatus::Blocked => "blocked",
        RunStatus::NeedsAttention | RunStatus::Active => "needs_attention",
        RunStatus::Succeeded => "succeeded",
        RunStatus::Failed => "failed",
        RunStatus::Cancelled => "cancelled",
    }
}

fn execution_status_from_db(value: &str) -> Result<RunStatus, StorageError> {
    match value {
        "waiting_for_approval" => Ok(RunStatus::WaitingForApproval),
        "queued" => Ok(RunStatus::Queued),
        "running" => Ok(RunStatus::Running),
        "blocked" => Ok(RunStatus::Blocked),
        "needs_attention" => Ok(RunStatus::NeedsAttention),
        "succeeded" => Ok(RunStatus::Succeeded),
        "failed" => Ok(RunStatus::Failed),
        "cancelled" => Ok(RunStatus::Cancelled),
        other => Err(StorageError::CorruptData(format!(
            "unknown execution status `{other}`"
        ))),
    }
}

fn tool_effect_to_db(effect: &ToolEffect) -> &'static str {
    match effect {
        ToolEffect::ReadOnly => "read_only",
        ToolEffect::LocalWrite => "local_write",
        ToolEffect::ProductionWrite => "production_write",
        ToolEffect::Destructive => "destructive",
    }
}

fn tool_effect_from_db(value: &str) -> Result<ToolEffect, StorageError> {
    match value {
        "read_only" => Ok(ToolEffect::ReadOnly),
        "local_write" => Ok(ToolEffect::LocalWrite),
        "production_write" => Ok(ToolEffect::ProductionWrite),
        "destructive" => Ok(ToolEffect::Destructive),
        other => Err(StorageError::CorruptData(format!(
            "unknown tool effect `{other}`"
        ))),
    }
}

fn sandbox_profile_to_db(profile: &SandboxProfile) -> &'static str {
    match profile {
        SandboxProfile::ReadOnly => "read_only",
        SandboxProfile::WorkspaceWrite => "workspace_write",
        SandboxProfile::IsolatedContainer => "isolated_container",
        SandboxProfile::ProductionGuarded => "production_guarded",
    }
}

fn sandbox_profile_from_db(value: &str) -> Result<SandboxProfile, StorageError> {
    match value {
        "read_only" => Ok(SandboxProfile::ReadOnly),
        "workspace_write" => Ok(SandboxProfile::WorkspaceWrite),
        "isolated_container" => Ok(SandboxProfile::IsolatedContainer),
        "production_guarded" => Ok(SandboxProfile::ProductionGuarded),
        other => Err(StorageError::CorruptData(format!(
            "unknown sandbox profile `{other}`"
        ))),
    }
}

fn session_status_to_db(status: &SessionStatus) -> &'static str {
    match status {
        SessionStatus::Ready => "ready",
        SessionStatus::Running => "running",
        SessionStatus::NeedsAttention => "needs_attention",
    }
}

fn session_status_from_db(value: &str) -> Result<SessionStatus, StorageError> {
    match value {
        "ready" => Ok(SessionStatus::Ready),
        "running" => Ok(SessionStatus::Running),
        "needs_attention" => Ok(SessionStatus::NeedsAttention),
        other => Err(StorageError::CorruptData(format!(
            "unknown session status `{other}`"
        ))),
    }
}

fn session_turn_status_from_db(value: &str) -> Result<SessionTurnStatus, StorageError> {
    match value {
        "open" => Ok(SessionTurnStatus::Open),
        "flushed" => Ok(SessionTurnStatus::Flushed),
        "interrupted" => Ok(SessionTurnStatus::Interrupted),
        other => Err(StorageError::CorruptData(format!(
            "unknown session turn status `{other}`"
        ))),
    }
}

fn session_event_kind(data: &SessionEventData) -> &'static str {
    match data {
        SessionEventData::SessionCreated { .. } => "session_created",
        SessionEventData::RunAttached { .. } => "run_attached",
        SessionEventData::SessionResumed { .. } => "session_resumed",
        SessionEventData::UserMessage { .. } => "user_message",
        SessionEventData::AssistantMessage { .. } => "assistant_message",
        SessionEventData::TurnFlushed { .. } => "turn_flushed",
        SessionEventData::TurnInterrupted { .. } => "turn_interrupted",
    }
}

fn session_event_turn_id(data: &SessionEventData) -> Option<&str> {
    match data {
        SessionEventData::UserMessage { turn_id, .. }
        | SessionEventData::AssistantMessage { turn_id, .. }
        | SessionEventData::TurnFlushed { turn_id }
        | SessionEventData::TurnInterrupted { turn_id, .. } => Some(turn_id),
        SessionEventData::SessionCreated { .. }
        | SessionEventData::RunAttached { .. }
        | SessionEventData::SessionResumed { .. } => None,
    }
}

fn event_kind(event_type: &EventType) -> &'static str {
    match event_type {
        EventType::System => "system",
        EventType::User => "user",
        EventType::Reasoning => "reasoning",
        EventType::Step => "step",
        EventType::ToolCall => "tool_call",
        EventType::Evidence => "evidence",
        EventType::Approval => "approval",
    }
}

fn event_type_from_kind(kind: &str) -> Result<EventType, StorageError> {
    match kind {
        "system" => Ok(EventType::System),
        "user" => Ok(EventType::User),
        "reasoning" => Ok(EventType::Reasoning),
        "step" => Ok(EventType::Step),
        "tool_call" => Ok(EventType::ToolCall),
        "evidence" => Ok(EventType::Evidence),
        "approval" => Ok(EventType::Approval),
        other => Err(StorageError::UnsupportedEventKind(other.to_owned())),
    }
}

struct StoredSessionSummaryRow {
    id: String,
    title: String,
    status: String,
    created_at: String,
    updated_at: String,
    sequence: i64,
    projection_sequence: i64,
    active_turn_id: Option<String>,
}

impl StoredSessionSummaryRow {
    fn decode(self) -> Result<SessionSummary, StorageError> {
        if self.sequence != self.projection_sequence {
            return Err(StorageError::CorruptData(format!(
                "session projection sequence {} does not match head {}",
                self.projection_sequence, self.sequence
            )));
        }
        let status = session_status_from_db(&self.status)?;
        if matches!(status, SessionStatus::Running) != self.active_turn_id.is_some() {
            return Err(StorageError::CorruptData(format!(
                "session `{}` status disagrees with active turn",
                self.id
            )));
        }
        Ok(SessionSummary {
            id: self.id,
            title: self.title,
            status,
            created_at: self.created_at,
            updated_at: self.updated_at,
            sequence: i64_to_u64(self.sequence, "session sequence")?,
            active_turn_id: self.active_turn_id,
        })
    }
}

struct StoredSessionTurnRow {
    id: String,
    session_id: String,
    ordinal: i64,
    status: String,
    user_message: String,
    assistant_message: Option<String>,
    started_at: String,
    completed_at: Option<String>,
}

impl StoredSessionTurnRow {
    fn decode(self) -> Result<SessionTurn, StorageError> {
        let status = session_turn_status_from_db(&self.status)?;
        let timestamps_are_valid = match status {
            SessionTurnStatus::Open => {
                self.assistant_message.is_none() && self.completed_at.is_none()
            }
            SessionTurnStatus::Flushed => self.completed_at.is_some(),
            SessionTurnStatus::Interrupted => {
                self.assistant_message.is_none() && self.completed_at.is_some()
            }
        };
        if !timestamps_are_valid {
            return Err(StorageError::CorruptData(format!(
                "turn `{}` status disagrees with its durable result",
                self.id
            )));
        }
        Ok(SessionTurn {
            id: self.id,
            session_id: self.session_id,
            ordinal: i64_to_u64(self.ordinal, "session turn ordinal")?,
            status,
            user_message: self.user_message,
            assistant_message: self.assistant_message,
            started_at: self.started_at,
            completed_at: self.completed_at,
        })
    }
}

struct StoredSessionEventRow {
    sequence: i64,
    event_id: String,
    event_kind: String,
    payload_version: i64,
    payload_json: String,
    turn_id: Option<String>,
    created_at: String,
}

impl StoredSessionEventRow {
    fn decode(self) -> Result<SessionEvent, StorageError> {
        if self.payload_version != SESSION_EVENT_PAYLOAD_VERSION_V1 {
            return Err(StorageError::UnsupportedPayloadVersion {
                event_kind: self.event_kind,
                version: self.payload_version,
            });
        }
        let event: SessionEvent = serde_json::from_str(&self.payload_json)?;
        if u64_to_i64(event.sequence, "session event sequence")? != self.sequence
            || event.id != self.event_id
            || event.at != self.created_at
            || session_event_kind(&event.data) != self.event_kind
            || session_event_turn_id(&event.data) != self.turn_id.as_deref()
        {
            return Err(StorageError::CorruptData(format!(
                "stored session event {} does not match its envelope",
                self.event_id
            )));
        }
        Ok(event)
    }
}

struct StoredSnapshotRow {
    incident_id: String,
    incident_title: String,
    incident_severity: String,
    incident_status: String,
    service: String,
    region: String,
    user_impact: String,
    since: String,
    run_id: String,
    run_status: String,
    environment: String,
    started_at: String,
    duration_seconds: i64,
    agent: String,
    sequence: i64,
    projection_sequence: i64,
    metrics_json: String,
    evidence_json: String,
    tool_policy_json: Option<String>,
    execution_status: String,
}

impl StoredSnapshotRow {
    fn decode(self) -> Result<RunSnapshot, StorageError> {
        if self.projection_sequence != self.sequence {
            return Err(StorageError::CorruptData(format!(
                "projection sequence {} does not match run head {}",
                self.projection_sequence, self.sequence
            )));
        }
        let status = execution_status_from_db(&self.execution_status)?;
        if legacy_run_status_to_db(&status) != self.run_status {
            return Err(StorageError::CorruptData(format!(
                "legacy run status `{}` disagrees with execution status `{}`",
                self.run_status, self.execution_status
            )));
        }
        Ok(RunSnapshot {
            incident: IncidentSummary {
                id: self.incident_id,
                title: self.incident_title,
                severity: severity_from_db(&self.incident_severity)?,
                status: incident_status_from_db(&self.incident_status)?,
                service: self.service,
                region: self.region,
                user_impact: self.user_impact,
                since: self.since,
            },
            run: RunSummary {
                id: self.run_id,
                status,
                environment: self.environment,
                started_at: self.started_at,
                duration_seconds: i64_to_u64(self.duration_seconds, "duration_seconds")?,
                agent: self.agent,
                sequence: i64_to_u64(self.sequence, "run sequence")?,
            },
            metrics: serde_json::from_str(&self.metrics_json)?,
            evidence: serde_json::from_str(&self.evidence_json)?,
            tool_policy: self
                .tool_policy_json
                .map(|value| serde_json::from_str(&value))
                .transpose()?,
        })
    }
}

struct StoredDispatchRow {
    call_id: String,
    run_id: String,
    approval_id: String,
    approval_event_sequence: i64,
    tool_name: String,
    tool_version: String,
    effect: String,
    args_json: String,
    args_digest: String,
    policy_id: String,
    policy_revision: String,
    sandbox_profile: String,
    status: String,
    attempt: i64,
    result_json: Option<String>,
    queued_at: String,
    started_at: Option<String>,
    finished_at: Option<String>,
    start_event_sequence: Option<i64>,
    result_event_sequence: Option<i64>,
}

impl StoredDispatchRow {
    fn decode(self) -> Result<DispatchJob, StorageError> {
        let status = match self.status.as_str() {
            "queued" => DispatchStatus::Queued,
            "started" => DispatchStatus::Started,
            "finished" => DispatchStatus::Finished,
            other => {
                return Err(StorageError::CorruptData(format!(
                    "unknown dispatch status `{other}`"
                )));
            }
        };
        Ok(DispatchJob {
            call_id: self.call_id,
            run_id: self.run_id,
            approval_id: self.approval_id,
            approval_event_sequence: i64_to_u64(
                self.approval_event_sequence,
                "approval event sequence",
            )?,
            tool_name: self.tool_name,
            tool_version: self.tool_version,
            effect: tool_effect_from_db(&self.effect)?,
            args_json: serde_json::from_str(&self.args_json)?,
            args_digest: self.args_digest,
            policy_id: self.policy_id,
            policy_revision: self.policy_revision,
            sandbox_profile: sandbox_profile_from_db(&self.sandbox_profile)?,
            status,
            attempt: u32::try_from(self.attempt)
                .map_err(|_| StorageError::IntegerOutOfRange("dispatch attempt"))?,
            result_json: self
                .result_json
                .map(|value| serde_json::from_str(&value))
                .transpose()?,
            queued_at: self.queued_at,
            started_at: self.started_at,
            finished_at: self.finished_at,
            start_event_sequence: self
                .start_event_sequence
                .map(|value| i64_to_u64(value, "dispatch start event sequence"))
                .transpose()?,
            result_event_sequence: self
                .result_event_sequence
                .map(|value| i64_to_u64(value, "dispatch result event sequence"))
                .transpose()?,
        })
    }
}

struct StoredEventRow {
    sequence: i64,
    event_id: String,
    event_kind: String,
    payload_version: i64,
    payload_json: String,
}

impl StoredEventRow {
    fn decode(self) -> Result<RunEvent, StorageError> {
        let expected_type = event_type_from_kind(&self.event_kind)?;
        if !matches!(
            self.payload_version,
            EVENT_PAYLOAD_VERSION_V1 | EVENT_PAYLOAD_VERSION_V2
        ) {
            return Err(StorageError::UnsupportedPayloadVersion {
                event_kind: self.event_kind,
                version: self.payload_version,
            });
        }
        let event: RunEvent = serde_json::from_str(&self.payload_json)?;
        match self.payload_version {
            EVENT_PAYLOAD_VERSION_V1 if event.data.is_none() => {}
            EVENT_PAYLOAD_VERSION_V1 => {
                return Err(StorageError::CorruptData(format!(
                    "v1 event at sequence {} contains v2 typed data",
                    self.sequence
                )));
            }
            EVENT_PAYLOAD_VERSION_V2 if event.data.is_some() => {}
            EVENT_PAYLOAD_VERSION_V2 => {
                return Err(StorageError::CorruptData(format!(
                    "v2 event at sequence {} is missing typed data",
                    self.sequence
                )));
            }
            _ => unreachable!("payload version was checked before decoding"),
        }
        if u64_to_i64(event.sequence, "event sequence")? != self.sequence
            || event.id != self.event_id
            || event.event_type != expected_type
        {
            return Err(StorageError::CorruptData(format!(
                "event row and v1 payload disagree at sequence {}",
                self.sequence
            )));
        }
        Ok(event)
    }
}
