use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use chrono::{SecondsFormat, Utc};
use fs2::FileExt;
use protocol::{
    ApprovalScope, ApprovalStatus, AssistantReplyProvenance, AttachRunRequest, AttachRunResponse,
    CreateSessionRequest, CreateSessionResponse, EVENT_PAGE_MAX_LIMIT, EventType,
    FlushSessionRequest, FlushSessionResponse, IncidentStatus, IncidentSummary,
    NotDispatchedReason, ResourceEnvelopeError, ResumeSessionRequest, ResumeSessionResponse,
    ReviewDecision, ReviewResponse, RunEvent, RunEventData, RunEventPage, RunStatus, RunSummary,
    SandboxProfile, SessionDetail, SessionEvent, SessionEventData, SessionEventPage,
    SessionFlushAck, SessionStatus, SessionSummary, SessionTurn, SessionTurnStatus, Severity,
    StartTurnRequest, StartTurnResponse, ToolCallStatus, ToolEffect, ToolOutcome,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use crate::{
    AuthPrincipal, AuthSessionCommit, BootstrapOwnerCommit, ClaimOutcome, CommitOutcome,
    DispatchCompleteCommit, DispatchContext, DispatchJob, DispatchJobSpec, DispatchRecoveryCommit,
    DispatchRejection, DispatchStartCommit, DispatchStatus, RecoveredSessionTurn,
    ReplyClaimOutcome, ReplyCompletion, ReplyFailureCommit, ReplyJob, ReplyJobEnqueueResponse,
    ReplyJobSpec, ReplyJobStatus, ReplyOutcomeUnknownCommit, ReplySuccessCommit, ReviewCommit,
    ReviewContext, ReviewReceipt, RunSnapshot, RuntimeIdentity, StorageError, StoredCredential,
    StoredPreferences, StoredRun, StoredUser, StoredUserRole, StoredUserStatus,
};

const CURRENT_SCHEMA_VERSION: i64 = 9;
const EVENT_PAYLOAD_VERSION_V1: i64 = 1;
const EVENT_PAYLOAD_VERSION_V2: i64 = 2;
const SESSION_EVENT_PAYLOAD_VERSION_V1: i64 = 1;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const MIGRATION_0001: &str = include_str!("../migrations/0001_init.sql");
const MIGRATION_0002: &str = include_str!("../migrations/0002_tool_execution.sql");
const MIGRATION_0003: &str = include_str!("../migrations/0003_runtime_identity.sql");
const MIGRATION_0004: &str = include_str!("../migrations/0004_sessions.sql");
const MIGRATION_0005: &str = include_str!("../migrations/0005_accounts.sql");
const MIGRATION_0006: &str = include_str!("../migrations/0006_actor_receipts.sql");
const MIGRATION_0007: &str = include_str!("../migrations/0007_reply_jobs.sql");
const MIGRATION_0008: &str = include_str!("../migrations/0008_actor_boundaries.sql");
const MIGRATION_0009: &str = include_str!("../migrations/0009_point_queries.sql");
const RECOVERY_BATCH_LIMIT: i64 = 64;

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
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let title = title.to_owned();
        let run_id = validated_durable_reference(run_id, "run ID")?.to_owned();
        self.with_connection(move |connection| {
            seed_demo_session(connection, &session_id, &title, &run_id)
        })
        .await
    }

    /// System/test-only unscoped read. Authenticated paths must use
    /// [`Self::list_sessions_for_actor`].
    pub async fn list_sessions(&self) -> Result<Vec<SessionSummary>, StorageError> {
        self.with_connection(query_session_summaries).await
    }

    pub async fn list_sessions_for_actor(
        &self,
        actor_user_id: &str,
    ) -> Result<Vec<SessionSummary>, StorageError> {
        let actor_user_id =
            normalized_account_value(actor_user_id, "session actor user ID", 128)?.to_owned();
        self.with_connection(move |connection| {
            query_session_summaries_for_actor(connection, &actor_user_id)
        })
        .await
    }

    /// System/test-only unscoped read. Authenticated paths must use
    /// [`Self::get_session_for_actor`].
    pub async fn get_session(&self, session_id: &str) -> Result<SessionDetail, StorageError> {
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        self.with_connection(move |connection| query_session_detail(connection, &session_id))
            .await
    }

    pub async fn get_session_for_actor(
        &self,
        actor_user_id: &str,
        session_id: &str,
    ) -> Result<SessionDetail, StorageError> {
        let actor_user_id =
            normalized_account_value(actor_user_id, "session actor user ID", 128)?.to_owned();
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        self.with_connection(move |connection| {
            query_session_detail_for_actor(connection, &actor_user_id, &session_id)
        })
        .await
    }

    /// Returns one projection after checking its durable event tail in the
    /// same read transaction. Unlike session detail, this never loads turns,
    /// attachments, or the complete event ledger.
    pub async fn session_summary(&self, session_id: &str) -> Result<SessionSummary, StorageError> {
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        self.with_connection(move |connection| {
            query_consistent_session_summary(connection, &session_id)
        })
        .await
    }

    pub async fn session_summary_for_actor(
        &self,
        actor_user_id: &str,
        session_id: &str,
    ) -> Result<SessionSummary, StorageError> {
        let actor_user_id =
            normalized_account_value(actor_user_id, "session actor user ID", 128)?.to_owned();
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        self.with_connection(move |connection| {
            query_consistent_session_summary_for_actor(connection, &actor_user_id, &session_id)
        })
        .await
    }

    /// Checks one immutable attachment without loading Session detail.
    pub async fn session_has_run(
        &self,
        session_id: &str,
        run_id: &str,
    ) -> Result<bool, StorageError> {
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let run_id = validated_durable_reference(run_id, "run ID")?.to_owned();
        self.with_connection(move |connection| {
            query_session_has_run(connection, &session_id, &run_id)
        })
        .await
    }

    /// System/test-only unscoped read. Authenticated paths must use
    /// [`Self::session_events_after_for_actor`].
    pub async fn session_events_after(
        &self,
        session_id: &str,
        after: u64,
    ) -> Result<Vec<SessionEvent>, StorageError> {
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        self.with_connection(move |connection| {
            query_session_events_after(connection, &session_id, after)
        })
        .await
    }

    pub async fn session_events_after_for_actor(
        &self,
        actor_user_id: &str,
        session_id: &str,
        after: u64,
    ) -> Result<Vec<SessionEvent>, StorageError> {
        let actor_user_id =
            normalized_account_value(actor_user_id, "session actor user ID", 128)?.to_owned();
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        self.with_connection(move |connection| {
            query_session_events_after_for_actor(connection, &actor_user_id, &session_id, after)
        })
        .await
    }

    /// System/test-only bounded read. Authenticated paths must use
    /// [`Self::session_event_page_for_actor`].
    pub async fn session_event_page(
        &self,
        session_id: &str,
        after: u64,
        limit: usize,
    ) -> Result<SessionEventPage, StorageError> {
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        self.with_connection(move |connection| {
            query_session_event_page(connection, &session_id, after, limit)
        })
        .await
    }

    /// Returns a bounded Session ledger page after authorizing the actor in
    /// the same read transaction that observes the durable head and events.
    pub async fn session_event_page_for_actor(
        &self,
        actor_user_id: &str,
        session_id: &str,
        after: u64,
        limit: usize,
    ) -> Result<SessionEventPage, StorageError> {
        let actor_user_id =
            normalized_account_value(actor_user_id, "session actor user ID", 128)?.to_owned();
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        self.with_connection(move |connection| {
            query_session_event_page_for_actor(
                connection,
                &actor_user_id,
                &session_id,
                after,
                limit,
            )
        })
        .await
    }

    /// System/test-only legacy write. Authenticated paths must use
    /// [`Self::create_session_for_actor`].
    pub async fn create_session(
        &self,
        request: CreateSessionRequest,
        idempotency_key: &str,
    ) -> Result<CreateSessionResponse, StorageError> {
        let key = normalized_key(idempotency_key)?.to_owned();
        self.with_connection(move |connection| create_session(connection, request, &key, None))
            .await
    }

    /// Creates a session owned by the authenticated actor and stores the
    /// idempotency receipt in that actor's scope.
    pub async fn create_session_for_actor(
        &self,
        actor_user_id: &str,
        request: CreateSessionRequest,
        idempotency_key: &str,
    ) -> Result<CreateSessionResponse, StorageError> {
        let actor_user_id =
            normalized_account_value(actor_user_id, "session actor user ID", 128)?.to_owned();
        let key = normalized_key(idempotency_key)?.to_owned();
        self.with_connection(move |connection| {
            create_session(connection, request, &key, Some(&actor_user_id))
        })
        .await
    }

    /// System/test-only legacy write. Authenticated paths must use
    /// [`Self::attach_run_for_actor`].
    pub async fn attach_run(
        &self,
        session_id: &str,
        request: AttachRunRequest,
        idempotency_key: &str,
    ) -> Result<AttachRunResponse, StorageError> {
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let key = normalized_key(idempotency_key)?.to_owned();
        self.with_connection(move |connection| {
            attach_run(connection, &session_id, request, &key, None)
        })
        .await
    }

    pub async fn attach_run_for_actor(
        &self,
        actor_user_id: &str,
        session_id: &str,
        request: AttachRunRequest,
        idempotency_key: &str,
    ) -> Result<AttachRunResponse, StorageError> {
        let actor_user_id =
            normalized_account_value(actor_user_id, "session actor user ID", 128)?.to_owned();
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let key = normalized_key(idempotency_key)?.to_owned();
        self.with_connection(move |connection| {
            attach_run(connection, &session_id, request, &key, Some(&actor_user_id))
        })
        .await
    }

    /// System/test-only legacy write. Authenticated paths must use
    /// [`Self::start_turn_for_actor`].
    pub async fn start_turn(
        &self,
        session_id: &str,
        request: StartTurnRequest,
        idempotency_key: &str,
    ) -> Result<StartTurnResponse, StorageError> {
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let key = normalized_key(idempotency_key)?.to_owned();
        self.with_connection(move |connection| {
            start_turn(connection, &session_id, request, &key, None, None, false)
                .map(|(response, _)| response)
        })
        .await
    }

    pub async fn start_turn_for_actor(
        &self,
        actor_user_id: &str,
        session_id: &str,
        request: StartTurnRequest,
        idempotency_key: &str,
    ) -> Result<StartTurnResponse, StorageError> {
        let actor_user_id =
            normalized_account_value(actor_user_id, "session actor user ID", 128)?.to_owned();
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let key = normalized_key(idempotency_key)?.to_owned();
        self.with_connection(move |connection| {
            start_turn(
                connection,
                &session_id,
                request,
                &key,
                Some(&actor_user_id),
                None,
                false,
            )
            .map(|(response, _)| response)
        })
        .await
    }

    /// Atomically persists the user turn and its provider work item.
    ///
    /// Replaying the same idempotency key returns the original turn and queue
    /// record. Changing either the turn request or immutable job input is an
    /// idempotency conflict.
    /// System/test-only legacy write. Authenticated paths must use
    /// [`Self::start_turn_and_enqueue_reply_for_actor`].
    pub async fn start_turn_and_enqueue_reply(
        &self,
        session_id: &str,
        request: StartTurnRequest,
        idempotency_key: &str,
        job: ReplyJobSpec,
    ) -> Result<ReplyJobEnqueueResponse, StorageError> {
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let key = normalized_key(idempotency_key)?.to_owned();
        let actor_user_id = job.actor_user_id.clone();
        self.with_connection(move |connection| {
            start_turn(
                connection,
                &session_id,
                request,
                &key,
                Some(&actor_user_id),
                Some(job),
                false,
            )
            .and_then(|(start, job)| {
                job.map(|job| ReplyJobEnqueueResponse { start, job })
                    .ok_or_else(|| {
                        StorageError::CorruptData(
                            "reply enqueue committed without a queue record".into(),
                        )
                    })
            })
        })
        .await
    }

    pub async fn start_turn_and_enqueue_reply_for_actor(
        &self,
        actor_user_id: &str,
        session_id: &str,
        request: StartTurnRequest,
        idempotency_key: &str,
        job: ReplyJobSpec,
    ) -> Result<ReplyJobEnqueueResponse, StorageError> {
        let actor_user_id =
            normalized_account_value(actor_user_id, "session actor user ID", 128)?.to_owned();
        if job.actor_user_id != actor_user_id {
            return Err(StorageError::SessionNotFound(session_id.to_owned()));
        }
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let key = normalized_key(idempotency_key)?.to_owned();
        self.with_connection(move |connection| {
            start_turn(
                connection,
                &session_id,
                request,
                &key,
                Some(&actor_user_id),
                Some(job),
                false,
            )
            .and_then(|(start, job)| {
                job.map(|job| ReplyJobEnqueueResponse { start, job })
                    .ok_or_else(|| {
                        StorageError::CorruptData(
                            "reply enqueue committed without a queue record".into(),
                        )
                    })
            })
        })
        .await
    }

    pub async fn reply_job(&self, job_id: &str) -> Result<Option<ReplyJob>, StorageError> {
        let job_id = normalized_reply_value(job_id, "reply job ID")?.to_owned();
        self.with_connection(move |connection| query_reply_job_optional(connection, &job_id))
            .await
    }

    /// Claims at most one queued reply. The committed `started` transition is
    /// the authorization boundary for provider execution.
    pub async fn claim_next_reply(&self) -> Result<ReplyClaimOutcome, StorageError> {
        self.with_connection(claim_next_reply).await
    }

    /// Commits provider output, assistant/flush ledger events, and the ready
    /// session projection in one transaction.
    pub async fn complete_reply_success(
        &self,
        commit: ReplySuccessCommit,
    ) -> Result<ReplyCompletion, StorageError> {
        self.with_connection(move |connection| complete_reply_success(connection, commit, false))
            .await
    }

    /// Commits a terminal provider failure together with interruption evidence.
    pub async fn complete_reply_failure(
        &self,
        commit: ReplyFailureCommit,
    ) -> Result<ReplyCompletion, StorageError> {
        self.with_connection(move |connection| complete_reply_failure(connection, commit))
            .await
    }

    /// Commits an indeterminate provider outcome together with interruption
    /// evidence. This terminal state must never be retried automatically.
    pub async fn complete_reply_outcome_unknown(
        &self,
        commit: ReplyOutcomeUnknownCommit,
    ) -> Result<ReplyCompletion, StorageError> {
        self.with_connection(move |connection| complete_reply_outcome_unknown(connection, commit))
            .await
    }

    /// Converts one bounded batch of replies durably claimed by a previous
    /// process into `outcome_unknown`. Queued work remains claimable.
    pub async fn recover_started_replies(&self) -> Result<Vec<ReplyCompletion>, StorageError> {
        self.with_connection(recover_started_replies).await
    }

    /// System/test-only legacy write. Authenticated paths must use
    /// [`Self::flush_turn_for_actor`].
    pub async fn flush_turn(
        &self,
        session_id: &str,
        request: FlushSessionRequest,
        idempotency_key: &str,
    ) -> Result<FlushSessionResponse, StorageError> {
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let key = normalized_key(idempotency_key)?.to_owned();
        self.with_connection(move |connection| {
            flush_turn(connection, &session_id, request, &key, None, false)
        })
        .await
    }

    pub async fn flush_turn_for_actor(
        &self,
        actor_user_id: &str,
        session_id: &str,
        request: FlushSessionRequest,
        idempotency_key: &str,
    ) -> Result<FlushSessionResponse, StorageError> {
        let actor_user_id =
            normalized_account_value(actor_user_id, "session actor user ID", 128)?.to_owned();
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let key = normalized_key(idempotency_key)?.to_owned();
        self.with_connection(move |connection| {
            flush_turn(
                connection,
                &session_id,
                request,
                &key,
                Some(&actor_user_id),
                false,
            )
        })
        .await
    }

    /// System/test-only legacy write. Authenticated paths must use
    /// [`Self::resume_session_for_actor`].
    pub async fn resume_session(
        &self,
        session_id: &str,
        request: ResumeSessionRequest,
        idempotency_key: &str,
    ) -> Result<ResumeSessionResponse, StorageError> {
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let key = normalized_key(idempotency_key)?.to_owned();
        self.with_connection(move |connection| {
            resume_session(connection, &session_id, request, &key, None)
        })
        .await
    }

    pub async fn resume_session_for_actor(
        &self,
        actor_user_id: &str,
        session_id: &str,
        request: ResumeSessionRequest,
        idempotency_key: &str,
    ) -> Result<ResumeSessionResponse, StorageError> {
        let actor_user_id =
            normalized_account_value(actor_user_id, "session actor user ID", 128)?.to_owned();
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let key = normalized_key(idempotency_key)?.to_owned();
        self.with_connection(move |connection| {
            resume_session(connection, &session_id, request, &key, Some(&actor_user_id))
        })
        .await
    }

    /// Closes one bounded batch of turns left open by a previous process.
    /// Recovery only appends `turn_interrupted`; it never manufactures a flush
    /// acknowledgement.
    pub async fn recover_open_turns(&self) -> Result<Vec<RecoveredSessionTurn>, StorageError> {
        self.with_connection(recover_open_turns).await
    }

    pub async fn has_users(&self) -> Result<bool, StorageError> {
        self.with_connection(|connection| {
            Ok(
                connection.query_row("SELECT EXISTS(SELECT 1 FROM users)", [], |row| {
                    row.get::<_, i64>(0)
                })? != 0,
            )
        })
        .await
    }

    /// Replaces any previously printed, unused bootstrap token.
    ///
    /// The raw token is never persisted. Rotating at startup guarantees an
    /// operator cannot be permanently locked out after losing terminal output.
    pub async fn replace_bootstrap_token(
        &self,
        token_hash: &str,
        expires_at: &str,
    ) -> Result<(), StorageError> {
        let token_hash = normalized_token_hash(token_hash, "bootstrap token hash")?.to_owned();
        let expires_at = normalized_timestamp(expires_at, "bootstrap token expiry")?.to_owned();
        self.with_connection(move |connection| {
            replace_bootstrap_token(connection, &token_hash, &expires_at)
        })
        .await
    }

    /// Atomically creates the first owner, consumes the bootstrap token, claims
    /// every legacy Alpha resource/receipt, and creates the first login session.
    pub async fn bootstrap_owner(
        &self,
        commit: BootstrapOwnerCommit,
    ) -> Result<(StoredUser, StoredPreferences), StorageError> {
        self.with_connection(move |connection| bootstrap_owner(connection, commit))
            .await
    }

    pub async fn credential_for_username(
        &self,
        username: &str,
    ) -> Result<Option<StoredCredential>, StorageError> {
        let username = normalized_account_value(username, "username", 64)?.to_owned();
        self.with_connection(move |connection| query_credential(connection, &username))
            .await
    }

    pub async fn create_auth_session(
        &self,
        commit: AuthSessionCommit,
    ) -> Result<AuthPrincipal, StorageError> {
        self.with_connection(move |connection| create_auth_session(connection, commit))
            .await
    }

    pub async fn authenticate(
        &self,
        session_token_hash: &str,
    ) -> Result<Option<AuthPrincipal>, StorageError> {
        let session_token_hash =
            normalized_token_hash(session_token_hash, "session token hash")?.to_owned();
        self.with_connection(move |connection| {
            query_auth_principal(connection, &session_token_hash, &now())
        })
        .await
    }

    pub async fn revoke_auth_session(
        &self,
        session_token_hash: &str,
    ) -> Result<bool, StorageError> {
        let session_token_hash =
            normalized_token_hash(session_token_hash, "session token hash")?.to_owned();
        self.with_connection(move |connection| {
            Ok(connection.execute(
                "DELETE FROM auth_sessions WHERE token_hash = ?1",
                [&session_token_hash],
            )? == 1)
        })
        .await
    }

    pub async fn preferences(&self, user_id: &str) -> Result<StoredPreferences, StorageError> {
        let user_id = normalized_account_value(user_id, "user ID", 128)?.to_owned();
        self.with_connection(move |connection| query_preferences(connection, &user_id))
            .await
    }

    pub async fn update_preferences(
        &self,
        user_id: &str,
        expected_revision: u64,
        theme: &str,
        preferred_model: Option<&str>,
    ) -> Result<StoredPreferences, StorageError> {
        let user_id = normalized_account_value(user_id, "user ID", 128)?.to_owned();
        let theme = normalized_theme(theme)?.to_owned();
        let preferred_model = preferred_model
            .map(|model| normalized_account_value(model, "preferred model", 128).map(str::to_owned))
            .transpose()?;
        self.with_connection(move |connection| {
            update_preferences(
                connection,
                &user_id,
                expected_revision,
                &theme,
                preferred_model.as_deref(),
            )
        })
        .await
    }

    pub async fn readiness(&self) -> Result<(), StorageError> {
        let expects_wal = matches!(self.backend, Backend::File(_));
        self.with_connection(move |connection| readiness(connection, expects_wal))
            .await
    }

    /// System/test-only unscoped read. Authenticated paths must use
    /// [`Self::snapshot_for_actor`].
    pub async fn snapshot(&self, run_id: &str) -> Result<RunSnapshot, StorageError> {
        let run_id = validated_durable_reference(run_id, "run ID")?.to_owned();
        self.with_connection(move |connection| load_snapshot(connection, &run_id))
            .await
    }

    pub async fn snapshot_for_actor(
        &self,
        actor_user_id: &str,
        run_id: &str,
    ) -> Result<RunSnapshot, StorageError> {
        let actor_user_id =
            normalized_account_value(actor_user_id, "run actor user ID", 128)?.to_owned();
        let run_id = validated_durable_reference(run_id, "run ID")?.to_owned();
        self.with_connection(move |connection| {
            load_snapshot_for_actor(connection, &actor_user_id, &run_id)
        })
        .await
    }

    /// Returns one Run projection after decoding and matching only its durable
    /// event tail. Internal execution paths use this instead of loading the
    /// complete ledger.
    pub async fn consistent_snapshot(&self, run_id: &str) -> Result<RunSnapshot, StorageError> {
        let run_id = validated_durable_reference(run_id, "run ID")?.to_owned();
        self.with_connection(move |connection| query_consistent_snapshot(connection, &run_id))
            .await
    }

    pub async fn consistent_snapshot_for_actor(
        &self,
        actor_user_id: &str,
        run_id: &str,
    ) -> Result<RunSnapshot, StorageError> {
        let actor_user_id =
            normalized_account_value(actor_user_id, "run actor user ID", 128)?.to_owned();
        let run_id = validated_durable_reference(run_id, "run ID")?.to_owned();
        self.with_connection(move |connection| {
            query_consistent_snapshot_for_actor(connection, &actor_user_id, &run_id)
        })
        .await
    }

    pub async fn review_context(
        &self,
        run_id: &str,
        approval_id: &str,
    ) -> Result<ReviewContext, StorageError> {
        let run_id = validated_durable_reference(run_id, "run ID")?.to_owned();
        let approval_id = validated_durable_reference(approval_id, "approval ID")?.to_owned();
        self.with_connection(move |connection| {
            query_review_context(connection, &run_id, &approval_id)
        })
        .await
    }

    pub async fn review_context_for_actor(
        &self,
        actor_user_id: &str,
        run_id: &str,
        approval_id: &str,
    ) -> Result<ReviewContext, StorageError> {
        let actor_user_id =
            normalized_account_value(actor_user_id, "review actor user ID", 128)?.to_owned();
        let run_id = validated_durable_reference(run_id, "run ID")?.to_owned();
        let approval_id = validated_durable_reference(approval_id, "approval ID")?.to_owned();
        self.with_connection(move |connection| {
            query_review_context_for_actor(connection, &actor_user_id, &run_id, &approval_id)
        })
        .await
    }

    pub async fn dispatch_context(
        &self,
        job: &DispatchJob,
    ) -> Result<DispatchContext, StorageError> {
        let run_id = validated_durable_reference(&job.run_id, "run ID")?.to_owned();
        let call_id = validated_durable_reference(&job.call_id, "call ID")?.to_owned();
        let approval_id = validated_durable_reference(&job.approval_id, "approval ID")?.to_owned();
        let approval_event_sequence = job.approval_event_sequence;
        self.with_connection(move |connection| {
            query_dispatch_context(
                connection,
                &run_id,
                approval_event_sequence,
                &call_id,
                &approval_id,
            )
        })
        .await
    }

    /// System/test-only unscoped read. Authenticated paths must use
    /// [`Self::load_run_for_actor`].
    pub async fn load_run(&self, run_id: &str) -> Result<StoredRun, StorageError> {
        let run_id = validated_durable_reference(run_id, "run ID")?.to_owned();
        self.with_connection(move |connection| load_run(connection, &run_id))
            .await
    }

    pub async fn load_run_for_actor(
        &self,
        actor_user_id: &str,
        run_id: &str,
    ) -> Result<StoredRun, StorageError> {
        let actor_user_id =
            normalized_account_value(actor_user_id, "run actor user ID", 128)?.to_owned();
        let run_id = validated_durable_reference(run_id, "run ID")?.to_owned();
        self.with_connection(move |connection| {
            load_run_for_actor(connection, &actor_user_id, &run_id)
        })
        .await
    }

    /// System/test-only unscoped read. Authenticated paths must use
    /// [`Self::events_after_for_actor`].
    pub async fn events_after(
        &self,
        run_id: &str,
        after: u64,
    ) -> Result<Vec<RunEvent>, StorageError> {
        let run_id = validated_durable_reference(run_id, "run ID")?.to_owned();
        self.with_connection(move |connection| events_after(connection, &run_id, after))
            .await
    }

    pub async fn events_after_for_actor(
        &self,
        actor_user_id: &str,
        run_id: &str,
        after: u64,
    ) -> Result<Vec<RunEvent>, StorageError> {
        let actor_user_id =
            normalized_account_value(actor_user_id, "run actor user ID", 128)?.to_owned();
        let run_id = validated_durable_reference(run_id, "run ID")?.to_owned();
        self.with_connection(move |connection| {
            events_after_for_actor(connection, &actor_user_id, &run_id, after)
        })
        .await
    }

    /// System/test-only bounded read. Authenticated paths must use
    /// [`Self::run_event_page_for_actor`].
    pub async fn run_event_page(
        &self,
        run_id: &str,
        after: u64,
        limit: usize,
    ) -> Result<RunEventPage, StorageError> {
        let run_id = validated_durable_reference(run_id, "run ID")?.to_owned();
        self.with_connection(move |connection| {
            query_run_event_page(connection, &run_id, after, limit)
        })
        .await
    }

    /// Returns a bounded Run ledger page after authorizing the actor in the
    /// same read transaction that observes the durable head and events.
    pub async fn run_event_page_for_actor(
        &self,
        actor_user_id: &str,
        run_id: &str,
        after: u64,
        limit: usize,
    ) -> Result<RunEventPage, StorageError> {
        let actor_user_id =
            normalized_account_value(actor_user_id, "run actor user ID", 128)?.to_owned();
        let run_id = validated_durable_reference(run_id, "run ID")?.to_owned();
        self.with_connection(move |connection| {
            query_run_event_page_for_actor(connection, &actor_user_id, &run_id, after, limit)
        })
        .await
    }

    /// System/test-only legacy receipt lookup. Authenticated paths must use
    /// [`Self::review_receipt_for_actor`].
    pub async fn review_receipt(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<ReviewReceipt>, StorageError> {
        let idempotency_key = normalized_key(idempotency_key)?.to_owned();
        self.with_connection(move |connection| load_review_receipt(connection, &idempotency_key))
            .await
    }

    pub async fn review_receipt_for_actor(
        &self,
        actor_user_id: &str,
        run_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<ReviewReceipt>, StorageError> {
        let actor_user_id =
            normalized_account_value(actor_user_id, "review actor user ID", 128)?.to_owned();
        let run_id = validated_durable_reference(run_id, "run ID")?.to_owned();
        let idempotency_key = normalized_key(idempotency_key)?.to_owned();
        self.with_connection(move |connection| {
            load_review_receipt_for_actor(connection, &actor_user_id, &run_id, &idempotency_key)
        })
        .await
    }

    /// Atomically advances the run projection, appends the v1 event payload,
    /// and records the idempotency receipt. Business transition validation is
    /// intentionally owned by the runtime/kernel before this call.
    /// System/test-only legacy write. Authenticated paths must use
    /// [`Self::commit_review_for_actor`].
    pub async fn commit_review(&self, commit: ReviewCommit) -> Result<CommitOutcome, StorageError> {
        self.with_connection(move |connection| commit_review(connection, commit, None, false))
            .await
    }

    pub async fn commit_review_for_actor(
        &self,
        actor_user_id: &str,
        commit: ReviewCommit,
    ) -> Result<CommitOutcome, StorageError> {
        let actor_user_id =
            normalized_account_value(actor_user_id, "review actor user ID", 128)?.to_owned();
        self.with_connection(move |connection| {
            commit_review(connection, commit, Some(&actor_user_id), false)
        })
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

    /// Returns one bounded startup-recovery batch ordered by durable start.
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
        self.with_connection(move |connection| commit_review(connection, commit, None, true))
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
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let key = normalized_key(idempotency_key)?.to_owned();
        self.with_connection(move |connection| {
            flush_turn(connection, &session_id, request, &key, None, true)
        })
        .await
    }

    #[cfg(test)]
    pub(crate) async fn start_turn_and_enqueue_reply_with_failure(
        &self,
        session_id: &str,
        request: StartTurnRequest,
        idempotency_key: &str,
        job: ReplyJobSpec,
    ) -> Result<ReplyJobEnqueueResponse, StorageError> {
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let key = normalized_key(idempotency_key)?.to_owned();
        let actor_user_id = job.actor_user_id.clone();
        self.with_connection(move |connection| {
            start_turn(
                connection,
                &session_id,
                request,
                &key,
                Some(&actor_user_id),
                Some(job),
                true,
            )
            .and_then(|(start, job)| {
                job.map(|job| ReplyJobEnqueueResponse { start, job })
                    .ok_or_else(|| {
                        StorageError::CorruptData(
                            "reply enqueue committed without a queue record".into(),
                        )
                    })
            })
        })
        .await
    }

    #[cfg(test)]
    pub(crate) async fn complete_reply_success_with_failure(
        &self,
        commit: ReplySuccessCommit,
    ) -> Result<ReplyCompletion, StorageError> {
        self.with_connection(move |connection| complete_reply_success(connection, commit, true))
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
    if current < 5 {
        transaction.execute_batch(MIGRATION_0005)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![5, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    if current < 6 {
        transaction.execute_batch(MIGRATION_0006)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![6, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    if current < 7 {
        transaction.execute_batch(MIGRATION_0007)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![7, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    if current < 8 {
        transaction.execute_batch(MIGRATION_0008)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![8, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    if current < 9 {
        // Existing rows are decoded by Rust before their immutable lookup
        // projections are populated. This avoids making SQLite JSON-path
        // behavior part of the durable event contract.
        transaction.execute_batch("DROP TRIGGER run_events_reject_update;")?;
        transaction.execute_batch(MIGRATION_0009)?;
        backfill_run_event_lookups(&transaction)?;
        transaction.execute_batch(
            r#"CREATE INDEX run_events_approval_lookup_idx
                   ON run_events(run_id, approval_id, sequence DESC, approval_status)
                   WHERE approval_id IS NOT NULL;
               CREATE INDEX run_events_tool_call_lookup_idx
                   ON run_events(run_id, data_kind, call_id, sequence)
                   WHERE data_kind = 'tool_call_requested' AND call_id IS NOT NULL;
               CREATE INDEX run_events_policy_revision_idx
                   ON run_events(run_id, policy_revision)
                   WHERE policy_revision IS NOT NULL;
               CREATE INDEX session_runs_session_attached_idx
                   ON session_runs(session_id, attached_at, run_id);
               CREATE INDEX reply_jobs_started_idx
                   ON reply_jobs(status, started_at, id);
               CREATE INDEX dispatch_jobs_started_idx
                   ON dispatch_jobs(status, started_at, call_id);
               CREATE INDEX session_turns_open_recovery_idx
                   ON session_turns(status, session_id, ordinal, id);

               CREATE TRIGGER run_events_reject_update
               BEFORE UPDATE ON run_events
               BEGIN
                   SELECT RAISE(ABORT, 'run_events are append-only');
               END;

               CREATE TRIGGER run_events_require_next_sequence
               BEFORE INSERT ON run_events
               WHEN NEW.sequence <> COALESCE((
                   SELECT MAX(sequence) + 1
                   FROM run_events
                   WHERE run_id = NEW.run_id
               ), 1)
               BEGIN
                   SELECT RAISE(ABORT, 'run event sequence must be contiguous');
               END;"#,
        )?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![9, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    transaction.commit()?;
    Ok(())
}

fn backfill_run_event_lookups(connection: &Connection) -> Result<(), StorageError> {
    let mut cursor: Option<(String, i64)> = None;
    loop {
        let rows = if let Some((run_id, sequence)) = cursor.as_ref() {
            let mut statement = connection.prepare(
                r#"SELECT run_id, sequence, event_id, event_kind, payload_version, payload_json
                   FROM run_events
                   WHERE (run_id, sequence) > (?1, ?2)
                   ORDER BY run_id, sequence
                   LIMIT 128"#,
            )?;
            statement
                .query_map(params![run_id, sequence], decode_migration_event_row)?
                .collect::<Result<Vec<_>, _>>()?
        } else {
            let mut statement = connection.prepare(
                r#"SELECT run_id, sequence, event_id, event_kind, payload_version, payload_json
                   FROM run_events
                   ORDER BY run_id, sequence
                   LIMIT 128"#,
            )?;
            statement
                .query_map([], decode_migration_event_row)?
                .collect::<Result<Vec<_>, _>>()?
        };
        if rows.is_empty() {
            validate_migrated_run_ledgers(connection)?;
            return Ok(());
        }

        for (run_id, stored) in &rows {
            let event = stored.decode_payload()?;
            let lookup = RunEventLookup::from_event(&event)?;
            let changed = connection.execute(
                r#"UPDATE run_events
                   SET data_kind = ?1, call_id = ?2, approval_id = ?3,
                       approval_status = ?4, policy_revision = ?5
                   WHERE run_id = ?6 AND sequence = ?7"#,
                params![
                    lookup.data_kind,
                    lookup.call_id,
                    lookup.approval_id,
                    lookup.approval_status,
                    lookup.policy_revision,
                    run_id,
                    stored.sequence,
                ],
            )?;
            if changed != 1 {
                return Err(StorageError::CorruptData(format!(
                    "run event {run_id}/{} disappeared during lookup migration",
                    stored.sequence
                )));
            }
        }
        let (run_id, stored) = rows.last().expect("non-empty migration batch");
        cursor = Some((run_id.clone(), stored.sequence));
    }
}

fn decode_migration_event_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<(String, StoredEventRow)> {
    Ok((
        row.get(0)?,
        StoredEventRow {
            sequence: row.get(1)?,
            event_id: row.get(2)?,
            event_kind: row.get(3)?,
            payload_version: row.get(4)?,
            payload_json: row.get(5)?,
            data_kind: None,
            call_id: None,
            approval_id: None,
            approval_status: None,
            policy_revision: None,
        },
    ))
}

fn validate_migrated_run_ledgers(connection: &Connection) -> Result<(), StorageError> {
    let invalid = connection
        .query_row(
            r#"SELECT r.id, r.sequence, r.projection_sequence,
                      COUNT(e.sequence), COALESCE(MIN(e.sequence), 0),
                      COALESCE(MAX(e.sequence), 0)
               FROM runs r
               LEFT JOIN run_events e ON e.run_id = r.id
               GROUP BY r.id
               HAVING r.sequence <> r.projection_sequence
                   OR COUNT(e.sequence) <> r.sequence
                   OR (r.sequence = 0 AND COALESCE(MAX(e.sequence), 0) <> 0)
                   OR (r.sequence > 0 AND (
                       COALESCE(MIN(e.sequence), 0) <> 1
                       OR COALESCE(MAX(e.sequence), 0) <> r.sequence
                   ))
               LIMIT 1"#,
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?;
    if let Some((run_id, sequence, projection, count, first, last)) = invalid {
        return Err(StorageError::CorruptData(format!(
            "run `{run_id}` ledger is not contiguous with its projection: head={sequence}, projection={projection}, count={count}, first={first}, last={last}"
        )));
    }
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
               'session_turns', 'session_events', 'session_command_receipts',
               'users', 'auth_sessions', 'bootstrap_tokens', 'user_preferences',
               'reply_jobs'
           )"#,
        [],
        |row| row.get(0),
    )?;
    if table_count != 17 {
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

    let dispatch_authorization_columns: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM pragma_table_info('dispatch_jobs')
           WHERE name IN ('approving_actor_user_id', 'authorization_error_json')"#,
        [],
        |row| row.get(0),
    )?;
    if dispatch_authorization_columns != 2 {
        return Err(StorageError::CorruptData(
            "dispatch authorization columns are missing".into(),
        ));
    }

    let event_lookup_columns: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM pragma_table_info('run_events')
           WHERE name IN (
               'data_kind', 'call_id', 'approval_id', 'approval_status', 'policy_revision'
           )"#,
        [],
        |row| row.get(0),
    )?;
    if event_lookup_columns != 5 {
        return Err(StorageError::CorruptData(
            "run event lookup projection columns are missing".into(),
        ));
    }

    let point_query_indexes: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM sqlite_schema
           WHERE type = 'index' AND name IN (
               'run_events_approval_lookup_idx',
               'run_events_tool_call_lookup_idx',
               'run_events_policy_revision_idx',
               'session_runs_session_attached_idx',
               'reply_jobs_started_idx',
               'dispatch_jobs_started_idx',
               'session_turns_open_recovery_idx'
           )"#,
        [],
        |row| row.get(0),
    )?;
    if point_query_indexes != 7 {
        return Err(StorageError::CorruptData(
            "one or more point-query indexes are missing".into(),
        ));
    }

    let trigger_count: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM sqlite_schema
           WHERE type = 'trigger' AND name IN (
               'run_events_reject_update',
               'run_events_reject_delete',
               'run_events_require_next_sequence',
               'dispatch_jobs_reject_input_update',
               'dispatch_jobs_enforce_forward_transition',
               'dispatch_jobs_reject_delete',
               'dispatch_jobs_require_actor_on_insert',
               'dispatch_jobs_require_owner_on_legacy_claim',
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
               'session_command_receipts_reject_delete',
               'idempotency_receipts_reject_update',
               'idempotency_receipts_reject_delete',
               'users_reject_identity_update',
               'users_reject_delete_with_history',
               'auth_sessions_reject_update',
               'bootstrap_tokens_enforce_single_use',
               'bootstrap_tokens_reject_delete',
               'user_preferences_enforce_revision',
               'sessions_owner_is_write_once',
               'runs_owner_is_write_once',
               'reply_jobs_reject_input_update',
               'reply_jobs_enforce_forward_transition',
               'reply_jobs_reject_delete',
               'session_runs_require_same_owner',
               'reply_jobs_require_session_owner',
               'session_receipts_require_session_owner_on_insert',
               'session_receipts_require_session_owner_on_claim',
               'run_receipts_require_run_owner_on_insert',
               'run_receipts_require_run_owner_on_claim'
           )"#,
        [],
        |row| row.get(0),
    )?;
    if trigger_count != 39 {
        return Err(StorageError::CorruptData(
            "one or more durability triggers are missing".into(),
        ));
    }

    let actor_boundary_violation: i64 = connection.query_row(
        r#"SELECT EXISTS(
               SELECT 1
               FROM session_runs sr
               JOIN sessions s ON s.id = sr.session_id
               JOIN runs r ON r.id = sr.run_id
               WHERE s.owner_user_id IS NOT r.owner_user_id
               UNION ALL
               SELECT 1
               FROM reply_jobs j
               JOIN sessions s ON s.id = j.session_id
               WHERE j.actor_user_id IS NOT s.owner_user_id
               UNION ALL
               SELECT 1
               FROM session_command_receipts receipt
               JOIN sessions s ON s.id = receipt.session_id
               WHERE receipt.actor_scope <> '__legacy__'
                 AND receipt.actor_scope IS NOT s.owner_user_id
               UNION ALL
               SELECT 1
               FROM idempotency_receipts receipt
               JOIN runs r ON r.id = receipt.run_id
               WHERE receipt.actor_scope <> '__legacy__'
                 AND receipt.actor_scope IS NOT r.owner_user_id
               UNION ALL
               SELECT 1
               FROM dispatch_jobs job
               JOIN runs r ON r.id = job.run_id
               WHERE job.approving_actor_user_id IS NOT NULL
                 AND job.approving_actor_user_id IS NOT r.owner_user_id
           )"#,
        [],
        |row| row.get(0),
    )?;
    if actor_boundary_violation != 0 {
        return Err(StorageError::CorruptData(
            "one or more durable records cross an actor ownership boundary".into(),
        ));
    }
    let (user_count, owner_count): (i64, i64) = connection.query_row(
        r#"SELECT COUNT(*),
                  COALESCE(SUM(CASE WHEN role = 'owner' THEN 1 ELSE 0 END), 0)
           FROM users"#,
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if user_count != 0 && owner_count != 1 {
        return Err(StorageError::CorruptData(
            "configured database must contain exactly one owner".into(),
        ));
    }
    let configured_legacy_boundary: i64 = connection.query_row(
        r#"SELECT EXISTS(SELECT 1 FROM users)
           AND EXISTS(
               SELECT 1 FROM sessions WHERE owner_user_id IS NULL
               UNION ALL
               SELECT 1 FROM runs WHERE owner_user_id IS NULL
               UNION ALL
               SELECT 1 FROM session_command_receipts WHERE actor_scope = '__legacy__'
               UNION ALL
               SELECT 1 FROM idempotency_receipts WHERE actor_scope = '__legacy__'
               UNION ALL
               SELECT 1 FROM dispatch_jobs WHERE approving_actor_user_id IS NULL
           )"#,
        [],
        |row| row.get(0),
    )?;
    if configured_legacy_boundary != 0 {
        return Err(StorageError::CorruptData(
            "configured database still contains unclaimed legacy actor state".into(),
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

fn replace_bootstrap_token(
    connection: &mut Connection,
    token_hash: &str,
    expires_at: &str,
) -> Result<(), StorageError> {
    let timestamp = now();
    if expires_at <= timestamp.as_str() {
        return Err(StorageError::InvalidAccountData(
            "bootstrap token expiry must be in the future".into(),
        ));
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let configured: i64 =
        transaction.query_row("SELECT EXISTS(SELECT 1 FROM users)", [], |row| row.get(0))?;
    if configured != 0 {
        return Err(StorageError::AccountAlreadyConfigured);
    }
    transaction.execute(
        "UPDATE bootstrap_tokens SET used_at = ?1 WHERE used_at IS NULL",
        [&timestamp],
    )?;
    transaction.execute(
        r#"INSERT INTO bootstrap_tokens(token_hash, created_at, expires_at, used_at)
           VALUES (?1, ?2, ?3, NULL)"#,
        params![token_hash, timestamp, expires_at],
    )?;
    transaction.commit()?;
    Ok(())
}

fn bootstrap_owner(
    connection: &mut Connection,
    commit: BootstrapOwnerCommit,
) -> Result<(StoredUser, StoredPreferences), StorageError> {
    let bootstrap_token_hash =
        normalized_token_hash(&commit.bootstrap_token_hash, "bootstrap token hash")?;
    let user_id = normalized_account_value(&commit.user_id, "user ID", 128)?;
    let username = normalized_account_value(&commit.username, "username", 64)?;
    let password_hash = normalized_password_hash(&commit.password_hash)?;
    let session_token_hash =
        normalized_token_hash(&commit.session_token_hash, "session token hash")?;
    let csrf_hash = normalized_token_hash(&commit.csrf_hash, "CSRF token hash")?;
    let session_expires_at = normalized_timestamp(&commit.session_expires_at, "session expiry")?;
    let timestamp = now();
    if session_expires_at <= timestamp.as_str() {
        return Err(StorageError::InvalidAccountData(
            "session expiry must be in the future".into(),
        ));
    }

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let configured: i64 =
        transaction.query_row("SELECT EXISTS(SELECT 1 FROM users)", [], |row| row.get(0))?;
    if configured != 0 {
        return Err(StorageError::AccountAlreadyConfigured);
    }
    let bootstrap_expiry = transaction
        .query_row(
            r#"SELECT expires_at FROM bootstrap_tokens
               WHERE token_hash = ?1 AND used_at IS NULL"#,
            [bootstrap_token_hash],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if bootstrap_expiry
        .as_deref()
        .is_none_or(|expiry| expiry <= timestamp.as_str())
    {
        return Err(StorageError::InvalidBootstrapToken);
    }

    transaction.execute(
        r#"INSERT INTO users(
               id, username, role, status, password_hash, created_at, updated_at
           ) VALUES (?1, ?2, 'owner', 'active', ?3, ?4, ?4)"#,
        params![user_id, username, password_hash, timestamp],
    )?;
    transaction.execute(
        r#"INSERT INTO user_preferences(
               user_id, theme, preferred_model, revision, updated_at
           ) VALUES (?1, 'system', NULL, 1, ?2)"#,
        params![user_id, timestamp],
    )?;

    transaction.execute(
        "UPDATE sessions SET owner_user_id = ?1 WHERE owner_user_id IS NULL",
        [user_id],
    )?;
    transaction.execute(
        "UPDATE runs SET owner_user_id = ?1 WHERE owner_user_id IS NULL",
        [user_id],
    )?;
    transaction.execute(
        "UPDATE session_command_receipts SET actor_scope = ?1 WHERE actor_scope = '__legacy__'",
        [user_id],
    )?;
    transaction.execute(
        "UPDATE idempotency_receipts SET actor_scope = ?1 WHERE actor_scope = '__legacy__'",
        [user_id],
    )?;
    transaction.execute(
        r#"UPDATE dispatch_jobs
           SET approving_actor_user_id = ?1
           WHERE approving_actor_user_id IS NULL"#,
        [user_id],
    )?;

    let consumed = transaction.execute(
        r#"UPDATE bootstrap_tokens SET used_at = ?1
           WHERE token_hash = ?2 AND used_at IS NULL"#,
        params![timestamp, bootstrap_token_hash],
    )?;
    if consumed != 1 {
        return Err(StorageError::InvalidBootstrapToken);
    }
    insert_auth_session(
        &transaction,
        user_id,
        session_token_hash,
        csrf_hash,
        session_expires_at,
        &timestamp,
    )?;

    let user = query_user(&transaction, user_id)?;
    let preferences = query_preferences(&transaction, user_id)?;
    transaction.commit()?;
    Ok((user, preferences))
}

fn query_credential(
    connection: &Connection,
    username: &str,
) -> Result<Option<StoredCredential>, StorageError> {
    let row = connection
        .query_row(
            r#"SELECT id, username, role, status, password_hash, created_at, updated_at
               FROM users WHERE username = ?1 COLLATE NOCASE"#,
            [username],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(id, username, role, status, password_hash, created_at, updated_at)| {
            Ok(StoredCredential {
                user: decode_user(id, username, role, status, created_at, updated_at)?,
                password_hash,
            })
        },
    )
    .transpose()
}

fn create_auth_session(
    connection: &mut Connection,
    commit: AuthSessionCommit,
) -> Result<AuthPrincipal, StorageError> {
    let user_id = normalized_account_value(&commit.user_id, "user ID", 128)?;
    let token_hash = normalized_token_hash(&commit.session_token_hash, "session token hash")?;
    let csrf_hash = normalized_token_hash(&commit.csrf_hash, "CSRF token hash")?;
    let expires_at = normalized_timestamp(&commit.expires_at, "session expiry")?;
    let timestamp = now();
    if expires_at <= timestamp.as_str() {
        return Err(StorageError::InvalidAccountData(
            "session expiry must be in the future".into(),
        ));
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let user = query_user(&transaction, user_id)?;
    if user.status != StoredUserStatus::Active {
        return Err(StorageError::UserDisabled(user_id.to_owned()));
    }
    insert_auth_session(
        &transaction,
        user_id,
        token_hash,
        csrf_hash,
        expires_at,
        &timestamp,
    )?;
    transaction.commit()?;
    Ok(AuthPrincipal {
        user,
        csrf_hash: csrf_hash.to_owned(),
        expires_at: expires_at.to_owned(),
    })
}

fn insert_auth_session(
    connection: &Connection,
    user_id: &str,
    token_hash: &str,
    csrf_hash: &str,
    expires_at: &str,
    timestamp: &str,
) -> Result<(), StorageError> {
    connection.execute(
        r#"INSERT INTO auth_sessions(
               token_hash, user_id, csrf_hash, created_at, expires_at, last_seen_at
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?4)"#,
        params![token_hash, user_id, csrf_hash, timestamp, expires_at],
    )?;
    Ok(())
}

fn query_auth_principal(
    connection: &Connection,
    token_hash: &str,
    timestamp: &str,
) -> Result<Option<AuthPrincipal>, StorageError> {
    let row = connection
        .query_row(
            r#"SELECT u.id, u.username, u.role, u.status, u.created_at, u.updated_at,
                      a.csrf_hash, a.expires_at
               FROM auth_sessions a
               JOIN users u ON u.id = a.user_id
               WHERE a.token_hash = ?1 AND a.expires_at > ?2 AND u.status = 'active'"#,
            params![token_hash, timestamp],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(id, username, role, status, created_at, updated_at, csrf_hash, expires_at)| {
            Ok(AuthPrincipal {
                user: decode_user(id, username, role, status, created_at, updated_at)?,
                csrf_hash,
                expires_at,
            })
        },
    )
    .transpose()
}

fn query_user(connection: &Connection, user_id: &str) -> Result<StoredUser, StorageError> {
    let row = connection
        .query_row(
            r#"SELECT id, username, role, status, created_at, updated_at
               FROM users WHERE id = ?1"#,
            [user_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()?;
    let Some((id, username, role, status, created_at, updated_at)) = row else {
        return Err(StorageError::UserNotFound(user_id.to_owned()));
    };
    decode_user(id, username, role, status, created_at, updated_at)
}

fn decode_user(
    id: String,
    username: String,
    role: String,
    status: String,
    created_at: String,
    updated_at: String,
) -> Result<StoredUser, StorageError> {
    let role = match role.as_str() {
        "owner" => StoredUserRole::Owner,
        "member" => StoredUserRole::Member,
        other => {
            return Err(StorageError::CorruptData(format!(
                "unsupported stored user role `{other}`"
            )));
        }
    };
    let status = match status.as_str() {
        "active" => StoredUserStatus::Active,
        "disabled" => StoredUserStatus::Disabled,
        other => {
            return Err(StorageError::CorruptData(format!(
                "unsupported stored user status `{other}`"
            )));
        }
    };
    Ok(StoredUser {
        id,
        username,
        role,
        status,
        created_at,
        updated_at,
    })
}

fn query_preferences(
    connection: &Connection,
    user_id: &str,
) -> Result<StoredPreferences, StorageError> {
    let row = connection
        .query_row(
            r#"SELECT user_id, theme, preferred_model, revision, updated_at
               FROM user_preferences WHERE user_id = ?1"#,
            [user_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((user_id, theme, preferred_model, revision, updated_at)) = row else {
        return Err(StorageError::UserNotFound(user_id.to_owned()));
    };
    normalized_theme(&theme)?;
    Ok(StoredPreferences {
        user_id,
        theme,
        preferred_model,
        revision: i64_to_u64(revision, "preference revision")?,
        updated_at,
    })
}

fn update_preferences(
    connection: &mut Connection,
    user_id: &str,
    expected_revision: u64,
    theme: &str,
    preferred_model: Option<&str>,
) -> Result<StoredPreferences, StorageError> {
    let expected_revision = u64_to_i64(expected_revision, "expected preference revision")?;
    let timestamp = now();
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let changed = transaction.execute(
        r#"UPDATE user_preferences
           SET theme = ?1, preferred_model = ?2, revision = revision + 1, updated_at = ?3
           WHERE user_id = ?4 AND revision = ?5"#,
        params![
            theme,
            preferred_model,
            timestamp,
            user_id,
            expected_revision
        ],
    )?;
    if changed != 1 {
        if transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM user_preferences WHERE user_id = ?1)",
            [user_id],
            |row| row.get::<_, i64>(0),
        )? == 0
        {
            return Err(StorageError::UserNotFound(user_id.to_owned()));
        }
        return Err(StorageError::ConcurrentModification);
    }
    let preferences = query_preferences(&transaction, user_id)?;
    transaction.commit()?;
    Ok(preferences)
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

    let mismatched_event_policy = transaction
        .query_row(
            r#"SELECT policy_revision FROM run_events
               WHERE run_id = ?1
                 AND policy_revision IS NOT NULL
                 AND policy_revision <> ?2
               LIMIT 1"#,
            params![identity.primary_run_id, identity.policy_revision],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(policy_revision) = mismatched_event_policy {
        return Err(identity_mismatch(
            identity,
            format!("event policy revision {policy_revision}"),
        ));
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
    validated_durable_reference(session_id, "session ID")?;
    validated_durable_reference(run_id, "run ID")?;
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
        validated_new_session_id(session_id, "session ID")?;
        validated_new_session_title(title, "session title")?;
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

fn query_session_summaries_for_actor(
    connection: &mut Connection,
    actor_user_id: &str,
) -> Result<Vec<SessionSummary>, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_active_user(&transaction, actor_user_id)?;
    let mut statement = transaction.prepare(
        r#"SELECT id, title, status, created_at, updated_at, sequence,
                  projection_sequence, active_turn_id
           FROM sessions
           WHERE owner_user_id = ?1
           ORDER BY updated_at DESC, id"#,
    )?;
    let rows = statement
        .query_map([actor_user_id], decode_session_summary_row)?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    let summaries = rows
        .into_iter()
        .map(StoredSessionSummaryRow::decode)
        .collect::<Result<Vec<_>, _>>()?;
    transaction.commit()?;
    Ok(summaries)
}

fn query_consistent_session_summary(
    connection: &mut Connection,
    session_id: &str,
) -> Result<SessionSummary, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let summary = query_session_summary(&transaction, session_id)?;
    validate_session_event_tail(&transaction, &summary)?;
    transaction.commit()?;
    Ok(summary)
}

fn query_consistent_session_summary_for_actor(
    connection: &mut Connection,
    actor_user_id: &str,
    session_id: &str,
) -> Result<SessionSummary, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_active_session_actor(&transaction, session_id, actor_user_id)?;
    let summary = query_session_summary(&transaction, session_id)?;
    validate_session_event_tail(&transaction, &summary)?;
    transaction.commit()?;
    Ok(summary)
}

fn query_session_has_run(
    connection: &mut Connection,
    session_id: &str,
    run_id: &str,
) -> Result<bool, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let summary = query_session_summary(&transaction, session_id)?;
    validate_session_event_tail(&transaction, &summary)?;
    let attached = transaction.query_row(
        r#"SELECT EXISTS(
               SELECT 1 FROM session_runs
               WHERE session_id = ?1 AND run_id = ?2
           )"#,
        params![session_id, run_id],
        |row| row.get::<_, i64>(0),
    )? != 0;
    transaction.commit()?;
    Ok(attached)
}

fn validate_session_event_tail(
    connection: &Connection,
    summary: &SessionSummary,
) -> Result<(), StorageError> {
    let tail = connection
        .query_row(
            r#"SELECT sequence, event_id, event_kind, payload_version, payload_json,
                      turn_id, created_at
               FROM session_events
               WHERE session_id = ?1
               ORDER BY sequence DESC LIMIT 1"#,
            [&summary.id],
            |row| {
                Ok(StoredSessionEventRow {
                    sequence: row.get(0)?,
                    event_id: row.get(1)?,
                    event_kind: row.get(2)?,
                    payload_version: row.get(3)?,
                    payload_json: row.get(4)?,
                    turn_id: row.get(5)?,
                    created_at: row.get(6)?,
                })
            },
        )
        .optional()?;
    let tail_sequence = tail.as_ref().map_or(0, |event| event.sequence);
    if i64_to_u64(tail_sequence, "session event tail")? != summary.sequence {
        return Err(StorageError::CorruptData(format!(
            "session head {} does not match event tail {tail_sequence}",
            summary.sequence
        )));
    }
    if let Some(tail) = tail {
        tail.decode()?;
    }
    Ok(())
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

fn query_session_detail_for_actor(
    connection: &mut Connection,
    actor_user_id: &str,
    session_id: &str,
) -> Result<SessionDetail, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_active_session_actor(&transaction, session_id, actor_user_id)?;
    let session = query_session_summary(&transaction, session_id)?;

    let mut run_statement = transaction.prepare(
        r#"SELECT sr.run_id
           FROM session_runs sr
           JOIN runs r ON r.id = sr.run_id
           WHERE sr.session_id = ?1 AND r.owner_user_id = ?2
           ORDER BY sr.attached_at, sr.run_id"#,
    )?;
    let run_ids = run_statement
        .query_map(params![session_id, actor_user_id], |row| {
            row.get::<_, String>(0)
        })?
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

fn query_session_events_after_for_actor(
    connection: &mut Connection,
    actor_user_id: &str,
    session_id: &str,
    after: u64,
) -> Result<Vec<SessionEvent>, StorageError> {
    let after = u64_to_i64(after, "session event cursor")?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_active_session_actor(&transaction, session_id, actor_user_id)?;
    let events = query_session_events(&transaction, session_id, after)?;
    transaction.commit()?;
    Ok(events)
}

fn query_session_event_page(
    connection: &mut Connection,
    session_id: &str,
    after: u64,
    limit: usize,
) -> Result<SessionEventPage, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let head_sequence = query_session_summary(&transaction, session_id)?.sequence;
    let (after_sql, fetch_limit) = validated_event_page_request(after, limit)?;
    reject_cursor_beyond_head(after, head_sequence)?;
    let page = query_session_events_page(
        &transaction,
        session_id,
        after,
        after_sql,
        limit,
        fetch_limit,
        head_sequence,
    )?;
    transaction.commit()?;
    Ok(page)
}

fn query_session_event_page_for_actor(
    connection: &mut Connection,
    actor_user_id: &str,
    session_id: &str,
    after: u64,
    limit: usize,
) -> Result<SessionEventPage, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_active_session_actor(&transaction, session_id, actor_user_id)?;
    let head_sequence = query_session_summary(&transaction, session_id)?.sequence;
    let (after_sql, fetch_limit) = validated_event_page_request(after, limit)?;
    reject_cursor_beyond_head(after, head_sequence)?;
    let page = query_session_events_page(
        &transaction,
        session_id,
        after,
        after_sql,
        limit,
        fetch_limit,
        head_sequence,
    )?;
    transaction.commit()?;
    Ok(page)
}

fn create_session(
    connection: &mut Connection,
    request: CreateSessionRequest,
    idempotency_key: &str,
    actor_user_id: Option<&str>,
) -> Result<CreateSessionResponse, StorageError> {
    normalized_key(idempotency_key)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(actor_user_id) = actor_user_id {
        require_active_user(&transaction, actor_user_id)?;
    }
    validate_create_session_request(&request)?;
    let fingerprint = session_command_fingerprint(None, &request)?;
    let stored_response = match actor_user_id {
        Some(actor_user_id) => load_session_command_receipt_for_actor::<CreateSessionResponse>(
            &transaction,
            actor_user_id,
            idempotency_key,
            "create_session",
            &fingerprint,
        )?,
        None => load_session_command_receipt::<CreateSessionResponse>(
            &transaction,
            idempotency_key,
            "create_session",
            &fingerprint,
        )?,
    };
    if let Some(mut response) = stored_response {
        response.replayed = true;
        transaction.commit()?;
        return Ok(response);
    }
    if query_session_summary_optional(&transaction, &request.id)?.is_some() {
        return Err(StorageError::SessionAlreadyExists(request.id));
    }
    let timestamp = now();
    transaction.execute(
        r#"INSERT INTO sessions(
               id, title, status, created_at, updated_at, sequence,
               projection_sequence, active_turn_id, owner_user_id
           ) VALUES (?1, ?2, 'ready', ?3, ?3, 0, 0, NULL, ?4)"#,
        params![request.id, request.title, timestamp, actor_user_id],
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
    if let Some(actor_user_id) = actor_user_id {
        insert_session_command_receipt_for_actor(
            &transaction,
            actor_user_id,
            idempotency_key,
            "create_session",
            &fingerprint,
            &response,
            &request.id,
            response.event.sequence,
        )?;
    } else {
        insert_session_command_receipt(
            &transaction,
            idempotency_key,
            "create_session",
            &fingerprint,
            &response,
            &request.id,
            response.event.sequence,
        )?;
    }
    transaction.commit()?;
    Ok(response)
}

fn attach_run(
    connection: &mut Connection,
    session_id: &str,
    request: AttachRunRequest,
    idempotency_key: &str,
    actor_user_id: Option<&str>,
) -> Result<AttachRunResponse, StorageError> {
    validated_durable_reference(session_id, "session ID")?;
    normalized_key(idempotency_key)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(actor_user_id) = actor_user_id {
        require_active_session_actor(&transaction, session_id, actor_user_id)?;
    }
    validated_durable_reference(&request.run_id, "run ID")?;
    let fingerprint = session_command_fingerprint(Some(session_id), &request)?;
    let stored_response = match actor_user_id {
        Some(actor_user_id) => load_session_command_receipt_for_actor::<AttachRunResponse>(
            &transaction,
            actor_user_id,
            idempotency_key,
            "attach_run",
            &fingerprint,
        )?,
        None => load_session_command_receipt::<AttachRunResponse>(
            &transaction,
            idempotency_key,
            "attach_run",
            &fingerprint,
        )?,
    };
    if let Some(mut response) = stored_response {
        response.replayed = true;
        transaction.commit()?;
        return Ok(response);
    }
    let summary = query_session_summary(&transaction, session_id)?;
    require_session_sequence(&summary, request.expected_sequence)?;
    let run_exists = match actor_user_id {
        Some(actor_user_id) => transaction
            .query_row(
                "SELECT 1 FROM runs WHERE id = ?1 AND owner_user_id = ?2",
                params![request.run_id, actor_user_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?,
        None => transaction
            .query_row(
                "SELECT 1 FROM runs WHERE id = ?1",
                [&request.run_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?,
    };
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
    if let Some(actor_user_id) = actor_user_id {
        insert_session_command_receipt_for_actor(
            &transaction,
            actor_user_id,
            idempotency_key,
            "attach_run",
            &fingerprint,
            &response,
            session_id,
            response.event.sequence,
        )?;
    } else {
        insert_session_command_receipt(
            &transaction,
            idempotency_key,
            "attach_run",
            &fingerprint,
            &response,
            session_id,
            response.event.sequence,
        )?;
    }
    transaction.commit()?;
    Ok(response)
}

fn start_turn(
    connection: &mut Connection,
    session_id: &str,
    request: StartTurnRequest,
    idempotency_key: &str,
    actor_user_id: Option<&str>,
    reply_job: Option<ReplyJobSpec>,
    fail_after_enqueue: bool,
) -> Result<(StartTurnResponse, Option<ReplyJob>), StorageError> {
    validated_durable_reference(session_id, "session ID")?;
    normalized_key(idempotency_key)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(actor_user_id) = actor_user_id {
        require_active_session_actor(&transaction, session_id, actor_user_id)?;
    }
    validate_start_turn_request(&request)?;
    if let Some(job) = &reply_job {
        validate_reply_job_spec(job)?;
        if actor_user_id != Some(job.actor_user_id.as_str()) {
            return Err(StorageError::SessionNotFound(session_id.to_owned()));
        }
    }
    let fingerprint = match &reply_job {
        Some(job) => reply_start_fingerprint(session_id, &request, job)?,
        None => session_command_fingerprint(Some(session_id), &request)?,
    };
    let stored_response = match actor_user_id {
        Some(actor_user_id) => load_session_command_receipt_for_actor::<StartTurnResponse>(
            &transaction,
            actor_user_id,
            idempotency_key,
            "start_turn",
            &fingerprint,
        )?,
        None => load_session_command_receipt::<StartTurnResponse>(
            &transaction,
            idempotency_key,
            "start_turn",
            &fingerprint,
        )?,
    };
    if let Some(mut response) = stored_response {
        response.replayed = true;
        let stored_job = match &reply_job {
            Some(spec) => {
                let job = query_reply_job_for_turn(&transaction, session_id, &request.turn_id)?;
                require_reply_job_matches_spec(&job, spec)?;
                Some(job)
            }
            None => None,
        };
        transaction.commit()?;
        return Ok((response, stored_job));
    }
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
    let stored_job = if let Some(job) = reply_job {
        insert_reply_job(&transaction, session_id, &request.turn_id, &job, &timestamp)?;
        Some(query_reply_job(&transaction, &job.id)?)
    } else {
        None
    };

    #[cfg(test)]
    if fail_after_enqueue {
        return Err(StorageError::InjectedFailure);
    }
    #[cfg(not(test))]
    let _ = fail_after_enqueue;

    let response = StartTurnResponse {
        session: query_session_summary(&transaction, session_id)?,
        turn: query_session_turn(&transaction, session_id, &request.turn_id)?,
        event,
        replayed: false,
    };
    if let Some(actor_user_id) = actor_user_id {
        insert_session_command_receipt_for_actor(
            &transaction,
            actor_user_id,
            idempotency_key,
            "start_turn",
            &fingerprint,
            &response,
            session_id,
            response.event.sequence,
        )?;
    } else {
        insert_session_command_receipt(
            &transaction,
            idempotency_key,
            "start_turn",
            &fingerprint,
            &response,
            session_id,
            response.event.sequence,
        )?;
    }
    transaction.commit()?;
    Ok((response, stored_job))
}

fn insert_reply_job(
    connection: &Connection,
    session_id: &str,
    turn_id: &str,
    job: &ReplyJobSpec,
    queued_at: &str,
) -> Result<(), StorageError> {
    connection.execute(
        r#"INSERT INTO reply_jobs(
               id, actor_user_id, session_id, turn_id, provider_name, model_name,
               status, attempt, request_json, response_json, error_json,
               completion_fingerprint, assistant_event_sequence,
               terminal_event_sequence, queued_at, started_at, finished_at
           ) VALUES (
               ?1, ?2, ?3, ?4, ?5, ?6, 'queued', 0, ?7, NULL, NULL,
               NULL, NULL, NULL, ?8, NULL, NULL
           )"#,
        params![
            job.id,
            job.actor_user_id,
            session_id,
            turn_id,
            job.provider_name,
            job.model_name,
            serde_json::to_string(&job.request_json)?,
            queued_at,
        ],
    )?;
    Ok(())
}

fn claim_next_reply(connection: &mut Connection) -> Result<ReplyClaimOutcome, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let job_id = transaction
        .query_row(
            r#"SELECT id FROM reply_jobs
               WHERE status = 'queued' ORDER BY queued_at, id LIMIT 1"#,
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let Some(job_id) = job_id else {
        transaction.commit()?;
        return Ok(ReplyClaimOutcome::NotAvailable);
    };

    let job = query_reply_job(&transaction, &job_id)?;
    let summary = require_open_reply_turn(&transaction, &job)?;
    let changed = transaction.execute(
        r#"UPDATE reply_jobs
           SET status = 'started', attempt = 1, started_at = ?1
           WHERE id = ?2 AND status = 'queued' AND attempt = 0"#,
        params![now(), job_id],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    if !reply_actor_is_authorized(&transaction, &job)? {
        let error_json = json!({
            "code": "authorization_revoked",
            "message": "the reply actor is no longer authorized for this session"
        });
        let fingerprint = serde_json::to_string(&json!({
            "kind": "failed",
            "job_id": job.id,
            "expected_sequence": summary.sequence,
            "error_json": error_json,
        }))?;
        let completion = interrupt_reply_job(
            &transaction,
            job,
            summary.sequence,
            ReplyJobStatus::Failed,
            &error_json,
            &fingerprint,
            "reply authorization was revoked before provider execution",
        )?;
        transaction.commit()?;
        return Ok(ReplyClaimOutcome::Rejected(Box::new(completion)));
    }
    let claimed = query_reply_job(&transaction, &job_id)?;
    transaction.commit()?;
    Ok(ReplyClaimOutcome::Claimed(Box::new(claimed)))
}

fn reply_actor_is_authorized(
    connection: &Connection,
    job: &ReplyJob,
) -> Result<bool, StorageError> {
    let authorized: i64 = connection.query_row(
        r#"SELECT EXISTS(
               SELECT 1
               FROM sessions s
               JOIN users u ON u.id = ?1
               WHERE s.id = ?2
                 AND s.owner_user_id = u.id
                 AND u.status = 'active'
                 AND u.role IN ('owner', 'member')
           )"#,
        params![job.actor_user_id, job.session_id],
        |row| row.get(0),
    )?;
    Ok(authorized != 0)
}

fn complete_reply_success(
    connection: &mut Connection,
    commit: ReplySuccessCommit,
    fail_before_flush_event: bool,
) -> Result<ReplyCompletion, StorageError> {
    normalized_reply_value(&commit.job_id, "reply job ID")?;
    validate_message(&commit.assistant_message, "assistant message")?;
    validate_reply_provenance(&commit.provenance)?;
    let fingerprint = reply_completion_fingerprint("succeeded", &commit)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let job = query_reply_job(&transaction, &commit.job_id)?;
    require_reply_provenance_matches_job(&job, &commit.provenance)?;
    if job.status != ReplyJobStatus::Started {
        let replay =
            replay_reply_completion(&transaction, job, ReplyJobStatus::Succeeded, &fingerprint)?;
        transaction.commit()?;
        return Ok(replay);
    }

    let mut summary = require_open_reply_turn(&transaction, &job)?;
    require_session_sequence(&summary, commit.expected_sequence)?;
    let timestamp = now();
    let assistant_sequence = next_session_sequence(summary.sequence)?;
    let assistant_event = build_session_event(
        &job.session_id,
        assistant_sequence,
        &timestamp,
        SessionEventData::AssistantMessage {
            turn_id: job.turn_id.clone(),
            content: commit.assistant_message.clone(),
            provenance: Some(commit.provenance.clone()),
        },
    );
    insert_session_event(&transaction, &job.session_id, &assistant_event)?;
    update_session_projection(
        &transaction,
        &job.session_id,
        summary.sequence,
        SessionStatus::Running,
        Some(&job.turn_id),
        assistant_sequence,
        &timestamp,
    )?;
    summary.sequence = assistant_sequence;
    summary.updated_at.clone_from(&timestamp);

    let changed = transaction.execute(
        r#"UPDATE session_turns
           SET status = 'flushed', assistant_message = ?1, completed_at = ?2
           WHERE session_id = ?3 AND id = ?4 AND status = 'open'"#,
        params![
            commit.assistant_message,
            timestamp,
            job.session_id,
            job.turn_id
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

    let terminal_sequence = next_session_sequence(summary.sequence)?;
    let flush_event = build_session_event(
        &job.session_id,
        terminal_sequence,
        &timestamp,
        SessionEventData::TurnFlushed {
            turn_id: job.turn_id.clone(),
        },
    );
    insert_session_event(&transaction, &job.session_id, &flush_event)?;
    update_session_projection(
        &transaction,
        &job.session_id,
        summary.sequence,
        SessionStatus::Ready,
        None,
        terminal_sequence,
        &timestamp,
    )?;

    let changed = transaction.execute(
        r#"UPDATE reply_jobs
           SET status = 'succeeded', response_json = ?1,
               completion_fingerprint = ?2, assistant_event_sequence = ?3,
               terminal_event_sequence = ?4, finished_at = ?5
           WHERE id = ?6 AND status = 'started' AND attempt = 1"#,
        params![
            serde_json::to_string(&commit.response_json)?,
            fingerprint,
            u64_to_i64(assistant_sequence, "assistant reply event sequence")?,
            u64_to_i64(terminal_sequence, "reply terminal event sequence")?,
            timestamp,
            job.id,
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    let completion = query_reply_completion(&transaction, &job.id, false)?;
    transaction.commit()?;
    Ok(completion)
}

fn complete_reply_failure(
    connection: &mut Connection,
    commit: ReplyFailureCommit,
) -> Result<ReplyCompletion, StorageError> {
    normalized_reply_value(&commit.job_id, "reply job ID")?;
    let fingerprint = reply_completion_fingerprint("failed", &commit)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let job = query_reply_job(&transaction, &commit.job_id)?;
    if job.status != ReplyJobStatus::Started {
        let replay =
            replay_reply_completion(&transaction, job, ReplyJobStatus::Failed, &fingerprint)?;
        transaction.commit()?;
        return Ok(replay);
    }
    let completion = interrupt_reply_job(
        &transaction,
        job,
        commit.expected_sequence,
        ReplyJobStatus::Failed,
        &commit.error_json,
        &fingerprint,
        "assistant reply provider failed",
    )?;
    transaction.commit()?;
    Ok(completion)
}

fn complete_reply_outcome_unknown(
    connection: &mut Connection,
    commit: ReplyOutcomeUnknownCommit,
) -> Result<ReplyCompletion, StorageError> {
    normalized_reply_value(&commit.job_id, "reply job ID")?;
    let fingerprint = reply_completion_fingerprint("outcome_unknown", &commit)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let job = query_reply_job(&transaction, &commit.job_id)?;
    if job.status != ReplyJobStatus::Started {
        let replay = replay_reply_completion(
            &transaction,
            job,
            ReplyJobStatus::OutcomeUnknown,
            &fingerprint,
        )?;
        transaction.commit()?;
        return Ok(replay);
    }
    let completion = interrupt_reply_job(
        &transaction,
        job,
        commit.expected_sequence,
        ReplyJobStatus::OutcomeUnknown,
        &commit.error_json,
        &fingerprint,
        "assistant reply provider outcome is unknown",
    )?;
    transaction.commit()?;
    Ok(completion)
}

fn recover_started_replies(
    connection: &mut Connection,
) -> Result<Vec<ReplyCompletion>, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut statement = transaction.prepare(
        r#"SELECT id FROM reply_jobs
           WHERE status = 'started' ORDER BY started_at, id LIMIT ?1"#,
    )?;
    let job_ids = statement
        .query_map([RECOVERY_BATCH_LIMIT], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);

    let mut recovered = Vec::with_capacity(job_ids.len());
    for job_id in job_ids {
        let job = query_reply_job(&transaction, &job_id)?;
        let summary = require_open_reply_turn(&transaction, &job)?;
        let error_json = json!({
            "code": "process_restarted",
            "message": "reply execution was started but no durable result was committed"
        });
        let fingerprint = serde_json::to_string(&json!({
            "kind": "outcome_unknown",
            "job_id": job.id,
            "expected_sequence": summary.sequence,
            "error_json": error_json,
        }))?;
        recovered.push(interrupt_reply_job(
            &transaction,
            job,
            summary.sequence,
            ReplyJobStatus::OutcomeUnknown,
            &error_json,
            &fingerprint,
            "process restarted after reply execution was claimed",
        )?);
    }
    transaction.commit()?;
    Ok(recovered)
}

#[allow(clippy::too_many_arguments)]
fn interrupt_reply_job(
    connection: &Connection,
    job: ReplyJob,
    expected_sequence: u64,
    terminal_status: ReplyJobStatus,
    error_json: &Value,
    fingerprint: &str,
    reason: &str,
) -> Result<ReplyCompletion, StorageError> {
    if !matches!(
        terminal_status,
        ReplyJobStatus::Failed | ReplyJobStatus::OutcomeUnknown
    ) {
        return Err(StorageError::InvalidReplyTransition(
            "an interrupted reply must end as failed or outcome_unknown".into(),
        ));
    }
    let summary = require_open_reply_turn(connection, &job)?;
    require_session_sequence(&summary, expected_sequence)?;
    let timestamp = now();
    let changed = connection.execute(
        r#"UPDATE session_turns
           SET status = 'interrupted', completed_at = ?1
           WHERE session_id = ?2 AND id = ?3 AND status = 'open'"#,
        params![timestamp, job.session_id, job.turn_id],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }

    let terminal_sequence = next_session_sequence(summary.sequence)?;
    let event = build_session_event(
        &job.session_id,
        terminal_sequence,
        &timestamp,
        SessionEventData::TurnInterrupted {
            turn_id: job.turn_id.clone(),
            reason: reason.to_owned(),
        },
    );
    insert_session_event(connection, &job.session_id, &event)?;
    update_session_projection(
        connection,
        &job.session_id,
        summary.sequence,
        SessionStatus::NeedsAttention,
        None,
        terminal_sequence,
        &timestamp,
    )?;
    let changed = connection.execute(
        r#"UPDATE reply_jobs
           SET status = ?1, error_json = ?2, completion_fingerprint = ?3,
               terminal_event_sequence = ?4, finished_at = ?5
           WHERE id = ?6 AND status = 'started' AND attempt = 1"#,
        params![
            reply_status_to_db(&terminal_status),
            serde_json::to_string(error_json)?,
            fingerprint,
            u64_to_i64(terminal_sequence, "reply terminal event sequence")?,
            timestamp,
            job.id,
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    query_reply_completion(connection, &job.id, false)
}

fn replay_reply_completion(
    connection: &Connection,
    job: ReplyJob,
    expected_status: ReplyJobStatus,
    expected_fingerprint: &str,
) -> Result<ReplyCompletion, StorageError> {
    if job.status != expected_status {
        return Err(StorageError::InvalidReplyTransition(format!(
            "reply job `{}` is already {:?}",
            job.id, job.status
        )));
    }
    let stored_fingerprint = query_reply_completion_fingerprint(connection, &job.id)?;
    if stored_fingerprint.as_deref() != Some(expected_fingerprint) {
        return Err(StorageError::IdempotencyConflict);
    }
    query_reply_completion(connection, &job.id, true)
}

fn flush_turn(
    connection: &mut Connection,
    session_id: &str,
    request: FlushSessionRequest,
    idempotency_key: &str,
    actor_user_id: Option<&str>,
    fail_before_flush_event: bool,
) -> Result<FlushSessionResponse, StorageError> {
    validated_durable_reference(session_id, "session ID")?;
    normalized_key(idempotency_key)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(actor_user_id) = actor_user_id {
        require_active_session_actor(&transaction, session_id, actor_user_id)?;
    }
    validated_durable_reference(&request.turn_id, "turn ID")?;
    if let Some(message) = &request.assistant_message {
        validate_message(message, "assistant message")?;
    }
    let fingerprint = session_command_fingerprint(Some(session_id), &request)?;
    let stored_response = match actor_user_id {
        Some(actor_user_id) => load_session_command_receipt_for_actor::<FlushSessionResponse>(
            &transaction,
            actor_user_id,
            idempotency_key,
            "flush_turn",
            &fingerprint,
        )?,
        None => load_session_command_receipt::<FlushSessionResponse>(
            &transaction,
            idempotency_key,
            "flush_turn",
            &fingerprint,
        )?,
    };
    if let Some(mut response) = stored_response {
        response.replayed = true;
        transaction.commit()?;
        return Ok(response);
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
                provenance: None,
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
    if let Some(actor_user_id) = actor_user_id {
        insert_session_command_receipt_for_actor(
            &transaction,
            actor_user_id,
            idempotency_key,
            "flush_turn",
            &fingerprint,
            &response,
            session_id,
            flush_sequence,
        )?;
    } else {
        insert_session_command_receipt(
            &transaction,
            idempotency_key,
            "flush_turn",
            &fingerprint,
            &response,
            session_id,
            flush_sequence,
        )?;
    }
    transaction.commit()?;
    Ok(response)
}

fn resume_session(
    connection: &mut Connection,
    session_id: &str,
    request: ResumeSessionRequest,
    idempotency_key: &str,
    actor_user_id: Option<&str>,
) -> Result<ResumeSessionResponse, StorageError> {
    validated_durable_reference(session_id, "session ID")?;
    normalized_key(idempotency_key)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(actor_user_id) = actor_user_id {
        require_active_session_actor(&transaction, session_id, actor_user_id)?;
    }
    let fingerprint = session_command_fingerprint(Some(session_id), &request)?;
    let stored_response = match actor_user_id {
        Some(actor_user_id) => load_session_command_receipt_for_actor::<ResumeSessionResponse>(
            &transaction,
            actor_user_id,
            idempotency_key,
            "resume_session",
            &fingerprint,
        )?,
        None => load_session_command_receipt::<ResumeSessionResponse>(
            &transaction,
            idempotency_key,
            "resume_session",
            &fingerprint,
        )?,
    };
    if let Some(mut response) = stored_response {
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
    if let Some(actor_user_id) = actor_user_id {
        insert_session_command_receipt_for_actor(
            &transaction,
            actor_user_id,
            idempotency_key,
            "resume_session",
            &fingerprint,
            &response,
            session_id,
            response.event.sequence,
        )?;
    } else {
        insert_session_command_receipt(
            &transaction,
            idempotency_key,
            "resume_session",
            &fingerprint,
            &response,
            session_id,
            response.event.sequence,
        )?;
    }
    transaction.commit()?;
    Ok(response)
}

fn recover_open_turns(
    connection: &mut Connection,
) -> Result<Vec<RecoveredSessionTurn>, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut statement = transaction.prepare(
        r#"SELECT t.session_id, t.id FROM session_turns t
           WHERE t.status = 'open'
             AND NOT EXISTS (
                 SELECT 1 FROM reply_jobs j
                 WHERE j.session_id = t.session_id AND j.turn_id = t.id
                   AND j.status IN ('queued', 'started')
             )
           ORDER BY t.session_id, t.ordinal LIMIT ?1"#,
    )?;
    let open_turns = statement
        .query_map([RECOVERY_BATCH_LIMIT], |row| {
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
        recovered.push(RecoveredSessionTurn { session_id, event });
    }
    transaction.commit()?;
    Ok(recovered)
}

fn query_reply_job_optional(
    connection: &Connection,
    job_id: &str,
) -> Result<Option<ReplyJob>, StorageError> {
    connection
        .query_row(
            r#"SELECT id, actor_user_id, session_id, turn_id, provider_name, model_name,
                      status, attempt, request_json, response_json, error_json,
                      queued_at, started_at, finished_at, completion_fingerprint,
                      assistant_event_sequence, terminal_event_sequence
               FROM reply_jobs WHERE id = ?1"#,
            [job_id],
            decode_reply_job_row,
        )
        .optional()?
        .map(StoredReplyJobRow::decode)
        .transpose()
}

fn query_reply_job(connection: &Connection, job_id: &str) -> Result<ReplyJob, StorageError> {
    query_reply_job_optional(connection, job_id)?
        .ok_or_else(|| StorageError::ReplyJobNotFound(job_id.to_owned()))
}

fn query_reply_job_for_turn(
    connection: &Connection,
    session_id: &str,
    turn_id: &str,
) -> Result<ReplyJob, StorageError> {
    connection
        .query_row(
            r#"SELECT id, actor_user_id, session_id, turn_id, provider_name, model_name,
                      status, attempt, request_json, response_json, error_json,
                      queued_at, started_at, finished_at, completion_fingerprint,
                      assistant_event_sequence, terminal_event_sequence
               FROM reply_jobs WHERE session_id = ?1 AND turn_id = ?2"#,
            params![session_id, turn_id],
            decode_reply_job_row,
        )
        .optional()?
        .ok_or_else(|| {
            StorageError::CorruptData(format!(
                "reply-backed turn `{turn_id}` in session `{session_id}` has no queue record"
            ))
        })?
        .decode()
}

fn decode_reply_job_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredReplyJobRow> {
    Ok(StoredReplyJobRow {
        id: row.get(0)?,
        actor_user_id: row.get(1)?,
        session_id: row.get(2)?,
        turn_id: row.get(3)?,
        provider_name: row.get(4)?,
        model_name: row.get(5)?,
        status: row.get(6)?,
        attempt: row.get(7)?,
        request_json: row.get(8)?,
        response_json: row.get(9)?,
        error_json: row.get(10)?,
        queued_at: row.get(11)?,
        started_at: row.get(12)?,
        finished_at: row.get(13)?,
        completion_fingerprint: row.get(14)?,
        assistant_event_sequence: row.get(15)?,
        terminal_event_sequence: row.get(16)?,
    })
}

fn query_reply_completion_fingerprint(
    connection: &Connection,
    job_id: &str,
) -> Result<Option<String>, StorageError> {
    connection
        .query_row(
            "SELECT completion_fingerprint FROM reply_jobs WHERE id = ?1",
            [job_id],
            |row| row.get(0),
        )
        .optional()?
        .ok_or_else(|| StorageError::ReplyJobNotFound(job_id.to_owned()))
}

fn query_reply_completion(
    connection: &Connection,
    job_id: &str,
    replayed: bool,
) -> Result<ReplyCompletion, StorageError> {
    let job = query_reply_job(connection, job_id)?;
    let terminal_sequence = job.terminal_event_sequence.ok_or_else(|| {
        StorageError::CorruptData(format!(
            "terminal reply job `{job_id}` has no terminal event sequence"
        ))
    })?;
    let terminal_event = query_session_event(connection, &job.session_id, terminal_sequence)?;
    let mut events = Vec::with_capacity(if job.status == ReplyJobStatus::Succeeded {
        2
    } else {
        1
    });
    match job.status {
        ReplyJobStatus::Succeeded => {
            let assistant_sequence = job.assistant_event_sequence.ok_or_else(|| {
                StorageError::CorruptData(format!(
                    "succeeded reply job `{job_id}` has no assistant event sequence"
                ))
            })?;
            let assistant_event =
                query_session_event(connection, &job.session_id, assistant_sequence)?;
            if !matches!(
                &assistant_event.data,
                SessionEventData::AssistantMessage { turn_id, .. } if turn_id == &job.turn_id
            ) || !matches!(
                &terminal_event.data,
                SessionEventData::TurnFlushed { turn_id } if turn_id == &job.turn_id
            ) {
                return Err(StorageError::CorruptData(format!(
                    "succeeded reply job `{job_id}` points at incompatible ledger events"
                )));
            }
            events.push(assistant_event);
            events.push(terminal_event);
        }
        ReplyJobStatus::Failed | ReplyJobStatus::OutcomeUnknown => {
            if !matches!(
                &terminal_event.data,
                SessionEventData::TurnInterrupted { turn_id, .. } if turn_id == &job.turn_id
            ) {
                return Err(StorageError::CorruptData(format!(
                    "interrupted reply job `{job_id}` points at an incompatible ledger event"
                )));
            }
            events.push(terminal_event);
        }
        ReplyJobStatus::Queued | ReplyJobStatus::Started => {
            return Err(StorageError::InvalidReplyTransition(format!(
                "reply job `{job_id}` is not terminal"
            )));
        }
    }
    Ok(ReplyCompletion {
        session: query_session_summary(connection, &job.session_id)?,
        turn: query_session_turn(connection, &job.session_id, &job.turn_id)?,
        job,
        events,
        replayed,
    })
}

fn query_session_event(
    connection: &Connection,
    session_id: &str,
    sequence: u64,
) -> Result<SessionEvent, StorageError> {
    let sequence = u64_to_i64(sequence, "session event sequence")?;
    connection
        .query_row(
            r#"SELECT sequence, event_id, event_kind, payload_version, payload_json,
                      turn_id, created_at
               FROM session_events WHERE session_id = ?1 AND sequence = ?2"#,
            params![session_id, sequence],
            |row| {
                Ok(StoredSessionEventRow {
                    sequence: row.get(0)?,
                    event_id: row.get(1)?,
                    event_kind: row.get(2)?,
                    payload_version: row.get(3)?,
                    payload_json: row.get(4)?,
                    turn_id: row.get(5)?,
                    created_at: row.get(6)?,
                })
            },
        )
        .optional()?
        .ok_or_else(|| {
            StorageError::CorruptData(format!(
                "session `{session_id}` has no event at sequence {sequence}"
            ))
        })?
        .decode()
}

fn require_open_reply_turn(
    connection: &Connection,
    job: &ReplyJob,
) -> Result<SessionSummary, StorageError> {
    let summary = query_session_summary(connection, &job.session_id)?;
    if summary.status != SessionStatus::Running
        || summary.active_turn_id.as_deref() != Some(job.turn_id.as_str())
    {
        return Err(StorageError::CorruptData(format!(
            "reply job `{}` disagrees with session `{}` projection",
            job.id, job.session_id
        )));
    }
    let turn = query_session_turn(connection, &job.session_id, &job.turn_id)?;
    if turn.status != SessionTurnStatus::Open {
        return Err(StorageError::CorruptData(format!(
            "reply job `{}` targets a non-open turn",
            job.id
        )));
    }
    Ok(summary)
}

fn require_reply_job_matches_spec(job: &ReplyJob, spec: &ReplyJobSpec) -> Result<(), StorageError> {
    if job.id != spec.id
        || job.actor_user_id != spec.actor_user_id
        || job.provider_name != spec.provider_name
        || job.model_name != spec.model_name
        || job.request_json != spec.request_json
    {
        return Err(StorageError::IdempotencyConflict);
    }
    Ok(())
}

fn require_reply_provenance_matches_job(
    job: &ReplyJob,
    provenance: &AssistantReplyProvenance,
) -> Result<(), StorageError> {
    if job.provider_name != provenance.provider_id || job.model_name != provenance.model {
        return Err(StorageError::InvalidReplyTransition(format!(
            "reply provenance does not match immutable job `{}` configuration",
            job.id
        )));
    }
    Ok(())
}

fn require_active_session_actor(
    connection: &Connection,
    session_id: &str,
    actor_user_id: &str,
) -> Result<(), StorageError> {
    let authorized = connection.query_row(
        r#"SELECT EXISTS(
                   SELECT 1
                   FROM sessions s
                   JOIN users u ON u.id = s.owner_user_id
                   WHERE s.id = ?1 AND u.id = ?2 AND u.status = 'active'
               )"#,
        params![session_id, actor_user_id],
        |row| row.get::<_, i64>(0),
    )?;
    if authorized == 0 {
        return Err(StorageError::SessionNotFound(session_id.to_owned()));
    }
    Ok(())
}

fn require_active_run_owner(
    connection: &Connection,
    run_id: &str,
    actor_user_id: &str,
) -> Result<(), StorageError> {
    let authorized = connection.query_row(
        r#"SELECT EXISTS(
                   SELECT 1
                   FROM runs r
                   JOIN users u ON u.id = r.owner_user_id
                   WHERE r.id = ?1
                     AND u.id = ?2
                     AND u.role = 'owner'
                     AND u.status = 'active'
               )"#,
        params![run_id, actor_user_id],
        |row| row.get::<_, i64>(0),
    )?;
    if authorized == 0 {
        return Err(StorageError::RunNotFound(run_id.to_owned()));
    }
    Ok(())
}

fn require_active_user(connection: &Connection, actor_user_id: &str) -> Result<(), StorageError> {
    let status = connection
        .query_row(
            "SELECT status FROM users WHERE id = ?1",
            [actor_user_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| StorageError::UserNotFound(actor_user_id.to_owned()))?;
    if status != "active" {
        return Err(StorageError::UserDisabled(actor_user_id.to_owned()));
    }
    Ok(())
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

#[allow(clippy::too_many_arguments)]
fn query_session_events_page(
    connection: &Connection,
    session_id: &str,
    after: u64,
    after_sql: i64,
    limit: usize,
    fetch_limit: i64,
    head_sequence: u64,
) -> Result<SessionEventPage, StorageError> {
    let mut statement = connection.prepare(
        r#"SELECT sequence, event_id, event_kind, payload_version, payload_json,
                  turn_id, created_at
           FROM session_events
           WHERE session_id = ?1 AND sequence > ?2
           ORDER BY sequence LIMIT ?3"#,
    )?;
    let mut rows = statement.query(params![session_id, after_sql, fetch_limit])?;
    let mut events = Vec::with_capacity(limit.saturating_add(1));
    let mut expected = after_sql.checked_add(1);
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
    finish_session_event_page(events, after, limit, head_sequence)
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
    _session_id: &str,
    sequence: u64,
    at: &str,
    data: SessionEventData,
) -> SessionEvent {
    SessionEvent {
        sequence,
        // Session event IDs are unique only within their ledger. Keeping the
        // parent ID out of this value prevents a valid 128-byte Session ID
        // from producing an oversized child resource ID.
        id: format!("sev-{sequence}"),
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

fn reply_start_fingerprint(
    session_id: &str,
    request: &StartTurnRequest,
    job: &ReplyJobSpec,
) -> Result<String, StorageError> {
    Ok(serde_json::to_string(&json!({
        "session_id": session_id,
        "request": request,
        "reply_job": job,
    }))?)
}

fn reply_completion_fingerprint<T: Serialize>(
    kind: &str,
    commit: &T,
) -> Result<String, StorageError> {
    Ok(serde_json::to_string(&json!({
        "kind": kind,
        "commit": commit,
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
               FROM session_command_receipts
               WHERE actor_scope = '__legacy__' AND operation = ?1
                 AND idempotency_key = ?2"#,
            params![operation, idempotency_key],
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

fn load_session_command_receipt_for_actor<T: DeserializeOwned>(
    connection: &Connection,
    actor_scope: &str,
    idempotency_key: &str,
    operation: &str,
    request_fingerprint: &str,
) -> Result<Option<T>, StorageError> {
    let stored = connection
        .query_row(
            r#"SELECT request_fingerprint, response_json
               FROM session_command_receipts
               WHERE actor_scope = ?1 AND operation = ?2 AND idempotency_key = ?3"#,
            params![actor_scope, operation, idempotency_key],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((stored_fingerprint, response_json)) = stored else {
        return Ok(None);
    };
    if stored_fingerprint != request_fingerprint {
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

#[allow(clippy::too_many_arguments)]
fn insert_session_command_receipt_for_actor<T: Serialize>(
    connection: &Connection,
    actor_scope: &str,
    idempotency_key: &str,
    operation: &str,
    request_fingerprint: &str,
    response: &T,
    session_id: &str,
    event_sequence: u64,
) -> Result<(), StorageError> {
    connection.execute(
        r#"INSERT INTO session_command_receipts(
               actor_scope, idempotency_key, operation, request_fingerprint,
               response_json, session_id, event_sequence, created_at
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
        params![
            actor_scope,
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

fn validated_new_session_id<'a>(
    value: &'a str,
    field: &'static str,
) -> Result<&'a str, StorageError> {
    protocol::validate_session_id(value)
        .map_err(|error| invalid_resource_envelope(field, error))?;
    Ok(value)
}

fn validated_new_turn_id<'a>(value: &'a str, field: &'static str) -> Result<&'a str, StorageError> {
    protocol::validate_turn_id(value).map_err(|error| invalid_resource_envelope(field, error))?;
    Ok(value)
}

fn validated_new_session_title<'a>(
    value: &'a str,
    field: &'static str,
) -> Result<&'a str, StorageError> {
    protocol::validate_session_title(value)
        .map_err(|error| invalid_resource_envelope(field, error))?;
    Ok(value)
}

fn validate_create_session_request(request: &CreateSessionRequest) -> Result<(), StorageError> {
    validated_new_session_id(&request.id, "session ID")?;
    validated_new_session_title(&request.title, "session title")?;
    Ok(())
}

fn validate_start_turn_request(request: &StartTurnRequest) -> Result<(), StorageError> {
    validated_new_turn_id(&request.turn_id, "turn ID")?;
    protocol::validate_user_message(&request.user_message)
        .map_err(|error| invalid_resource_envelope("user message", error))?;
    Ok(())
}

fn validated_durable_reference<'a>(
    value: &'a str,
    field: &'static str,
) -> Result<&'a str, StorageError> {
    if value.is_empty() || value.trim() != value {
        Err(StorageError::InvalidResourceEnvelope(format!(
            "{field} must be non-empty and canonical"
        )))
    } else {
        Ok(value)
    }
}

fn validate_review_note_value(value: &str, field: &'static str) -> Result<(), StorageError> {
    protocol::validate_review_note(value).map_err(|error| invalid_resource_envelope(field, error))
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

fn invalid_resource_envelope(field: &'static str, error: ResourceEnvelopeError) -> StorageError {
    StorageError::InvalidResourceEnvelope(format!("{field} {error}"))
}

fn validate_reply_job_spec(job: &ReplyJobSpec) -> Result<(), StorageError> {
    normalized_reply_value(&job.id, "reply job ID")?;
    normalized_account_value(&job.actor_user_id, "reply actor user ID", 128)?;
    normalized_reply_value(&job.provider_name, "reply provider name")?;
    if let Some(model_name) = &job.model_name {
        normalized_reply_value(model_name, "reply model name")?;
    }
    Ok(())
}

fn validate_reply_provenance(provenance: &AssistantReplyProvenance) -> Result<(), StorageError> {
    normalized_reply_value(&provenance.provider_id, "assistant reply provider ID")?;
    if let Some(model) = &provenance.model {
        normalized_reply_value(model, "assistant reply model")?;
    }
    Ok(())
}

fn normalized_reply_value<'a>(
    value: &'a str,
    field: &'static str,
) -> Result<&'a str, StorageError> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        Err(StorageError::InvalidReplyTransition(format!(
            "{field} must be non-empty, canonical, and control-free"
        )))
    } else {
        Ok(value)
    }
}

fn query_consistent_snapshot(
    connection: &mut Connection,
    run_id: &str,
) -> Result<RunSnapshot, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let snapshot = query_snapshot(&transaction, run_id)?;
    validate_run_event_tail(&transaction, &snapshot)?;
    transaction.commit()?;
    Ok(snapshot)
}

fn query_consistent_snapshot_for_actor(
    connection: &mut Connection,
    actor_user_id: &str,
    run_id: &str,
) -> Result<RunSnapshot, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_active_run_owner(&transaction, run_id, actor_user_id)?;
    let snapshot = query_snapshot(&transaction, run_id)?;
    validate_run_event_tail(&transaction, &snapshot)?;
    transaction.commit()?;
    Ok(snapshot)
}

fn query_review_context(
    connection: &mut Connection,
    run_id: &str,
    approval_id: &str,
) -> Result<ReviewContext, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let context = query_review_context_in_transaction(&transaction, run_id, approval_id)?;
    transaction.commit()?;
    Ok(context)
}

fn query_review_context_for_actor(
    connection: &mut Connection,
    actor_user_id: &str,
    run_id: &str,
    approval_id: &str,
) -> Result<ReviewContext, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    // Authorization deliberately precedes every lookup that could reveal
    // whether an approval or call exists.
    require_active_run_owner(&transaction, run_id, actor_user_id)?;
    let context = query_review_context_in_transaction(&transaction, run_id, approval_id)?;
    transaction.commit()?;
    Ok(context)
}

fn query_review_context_in_transaction(
    connection: &Connection,
    run_id: &str,
    approval_id: &str,
) -> Result<ReviewContext, StorageError> {
    let snapshot = query_snapshot(connection, run_id)?;
    validate_run_event_tail(connection, &snapshot)?;
    let approval_with_sequence = query_pending_approval(connection, run_id, approval_id)?;
    let requested_call_with_sequence = approval_with_sequence
        .as_ref()
        .and_then(|(_, approval)| approval.call_id.as_deref())
        .map(|call_id| query_requested_call(connection, run_id, call_id))
        .transpose()?
        .flatten();
    if let (Some((approval_sequence, _)), Some((call_sequence, _))) =
        (&approval_with_sequence, &requested_call_with_sequence)
        && call_sequence >= approval_sequence
    {
        return Err(StorageError::CorruptData(format!(
            "approval `{approval_id}` precedes its requested tool call"
        )));
    }
    Ok(ReviewContext {
        snapshot,
        approval_event_sequence: approval_with_sequence
            .as_ref()
            .map(|(sequence, _)| *sequence),
        approval: approval_with_sequence.map(|(_, approval)| approval),
        requested_call_event_sequence: requested_call_with_sequence
            .as_ref()
            .map(|(sequence, _)| *sequence),
        requested_call: requested_call_with_sequence.map(|(_, call)| call),
    })
}

fn query_dispatch_context(
    connection: &mut Connection,
    run_id: &str,
    approval_event_sequence: u64,
    call_id: &str,
    approval_id: &str,
) -> Result<DispatchContext, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let snapshot = query_snapshot(&transaction, run_id)?;
    validate_run_event_tail(&transaction, &snapshot)?;
    let approval_event = query_run_event_at(
        &transaction,
        run_id,
        u64_to_i64(approval_event_sequence, "approval event sequence")?,
    )?;
    validate_dispatch_approval_event(&approval_event, approval_id, call_id)?;
    let requested_call_with_sequence = query_requested_call(&transaction, run_id, call_id)?;
    if let Some((call_sequence, _)) = &requested_call_with_sequence
        && *call_sequence >= approval_event_sequence
    {
        return Err(StorageError::CorruptData(format!(
            "dispatch approval `{approval_id}` precedes its requested tool call"
        )));
    }
    transaction.commit()?;
    Ok(DispatchContext {
        snapshot,
        approval_event,
        requested_call_event_sequence: requested_call_with_sequence
            .as_ref()
            .map(|(sequence, _)| *sequence),
        requested_call: requested_call_with_sequence.map(|(_, call)| call),
    })
}

fn validate_run_event_tail(
    connection: &Connection,
    snapshot: &RunSnapshot,
) -> Result<(), StorageError> {
    let tail = connection
        .query_row(
            r#"SELECT sequence, event_id, event_kind, payload_version, payload_json,
                      data_kind, call_id, approval_id, approval_status, policy_revision
               FROM run_events
               WHERE run_id = ?1
               ORDER BY sequence DESC LIMIT 1"#,
            [&snapshot.run.id],
            decode_stored_event_row,
        )
        .optional()?;
    let tail_sequence = tail.as_ref().map_or(0, |event| event.sequence);
    if i64_to_u64(tail_sequence, "run event tail")? != snapshot.run.sequence {
        return Err(StorageError::CorruptData(format!(
            "run head {} does not match event tail {tail_sequence}",
            snapshot.run.sequence
        )));
    }
    if let Some(tail) = tail {
        tail.decode()?;
    }
    Ok(())
}

fn query_pending_approval(
    connection: &Connection,
    run_id: &str,
    approval_id: &str,
) -> Result<Option<(u64, protocol::Approval)>, StorageError> {
    let mut statement = connection.prepare(
        r#"SELECT sequence, event_id, event_kind, payload_version, payload_json,
                  data_kind, call_id, approval_id, approval_status, policy_revision
           FROM run_events
           WHERE run_id = ?1 AND approval_id = ?2
           ORDER BY sequence DESC LIMIT 3"#,
    )?;
    let rows = statement
        .query_map(params![run_id, approval_id], decode_stored_event_row)?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() > 2 {
        return Err(StorageError::CorruptData(format!(
            "approval `{approval_id}` is reused by more than one request/decision pair in run `{run_id}`"
        )));
    }

    let mut pending = None;
    let mut terminal = None;
    for row in rows {
        let sequence = i64_to_u64(row.sequence, "approval event sequence")?;
        let event = row.decode()?;
        let Some(approval) = event.approval else {
            return Err(StorageError::CorruptData(format!(
                "approval lookup `{approval_id}` resolved to an event without approval data"
            )));
        };
        if approval.id != approval_id {
            return Err(StorageError::CorruptData(format!(
                "approval lookup `{approval_id}` resolved to `{}`",
                approval.id
            )));
        }
        if event.event_type != EventType::Approval {
            return Err(StorageError::CorruptData(format!(
                "approval lookup `{approval_id}` resolved to a non-approval event"
            )));
        }

        match &approval.status {
            ApprovalStatus::Pending => {
                match event.data {
                    Some(RunEventData::ApprovalRequested {
                        approval_id: data_approval_id,
                        call_id,
                        scope,
                        status: ToolCallStatus::WaitingForApproval,
                    }) if data_approval_id == approval.id
                        && approval.call_id.as_deref() == Some(call_id.as_str())
                        && approval.scope.as_ref() == Some(&scope) => {}
                    None => {}
                    _ => {
                        return Err(StorageError::CorruptData(format!(
                            "pending approval `{approval_id}` has inconsistent typed request data"
                        )));
                    }
                }
                if pending.replace((sequence, approval)).is_some() {
                    return Err(StorageError::CorruptData(format!(
                        "approval `{approval_id}` has multiple pending request events"
                    )));
                }
            }
            ApprovalStatus::Approved | ApprovalStatus::Rejected => {
                let typed_decision_matches = match (&approval.status, event.data) {
                    (
                        ApprovalStatus::Approved,
                        Some(RunEventData::ApprovalDecided {
                            approval_id: data_approval_id,
                            call_id,
                            decision: ReviewDecision::Approve,
                            status: ToolCallStatus::Queued,
                        }),
                    ) => {
                        data_approval_id == approval.id
                            && approval.call_id.as_deref() == Some(call_id.as_str())
                    }
                    (
                        ApprovalStatus::Rejected,
                        Some(RunEventData::ApprovalDecided {
                            approval_id: data_approval_id,
                            call_id,
                            decision: ReviewDecision::Reject,
                            status: ToolCallStatus::NotDispatched,
                        }),
                    ) => {
                        data_approval_id == approval.id
                            && approval.call_id.as_deref() == Some(call_id.as_str())
                    }
                    (_, None) => true,
                    _ => false,
                };
                if !typed_decision_matches {
                    return Err(StorageError::CorruptData(format!(
                        "terminal approval `{approval_id}` has inconsistent typed decision data"
                    )));
                }
                if terminal.replace((sequence, approval)).is_some() {
                    return Err(StorageError::CorruptData(format!(
                        "approval `{approval_id}` has multiple terminal decisions"
                    )));
                }
            }
        }
    }
    if let Some((terminal_sequence, terminal)) = terminal {
        let Some((pending_sequence, pending)) = pending else {
            return Err(StorageError::CorruptData(format!(
                "terminal approval `{approval_id}` has no durable request"
            )));
        };
        if pending_sequence >= terminal_sequence {
            return Err(StorageError::CorruptData(format!(
                "approval `{approval_id}` decision does not follow its durable request"
            )));
        }
        if let (Some(request_call), Some(decision_call)) =
            (pending.call_id.as_deref(), terminal.call_id.as_deref())
            && request_call != decision_call
        {
            return Err(StorageError::CorruptData(format!(
                "approval `{approval_id}` request and decision target different calls"
            )));
        }
        Ok(None)
    } else {
        Ok(pending)
    }
}

fn query_requested_call(
    connection: &Connection,
    run_id: &str,
    call_id: &str,
) -> Result<Option<(u64, protocol::ToolCall)>, StorageError> {
    let mut statement = connection.prepare(
        r#"SELECT sequence, event_id, event_kind, payload_version, payload_json,
                  data_kind, call_id, approval_id, approval_status, policy_revision
           FROM run_events
           WHERE run_id = ?1
             AND data_kind = 'tool_call_requested'
             AND call_id = ?2
           ORDER BY sequence LIMIT 2"#,
    )?;
    let rows = statement
        .query_map(params![run_id, call_id], decode_stored_event_row)?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() > 1 {
        return Err(StorageError::CorruptData(format!(
            "tool call `{call_id}` has multiple request events in run `{run_id}`"
        )));
    }
    rows.into_iter()
        .next()
        .map(|row| {
            let sequence = i64_to_u64(row.sequence, "requested call event sequence")?;
            let event = row.decode()?;
            match (event.event_type, event.data) {
                (
                    EventType::ToolCall,
                    Some(RunEventData::ToolCallRequested {
                        call,
                        status: ToolCallStatus::Requested,
                    }),
                ) if call.call_id == call_id => Ok((sequence, call)),
                _ => Err(StorageError::CorruptData(format!(
                    "tool call lookup `{call_id}` resolved to an incompatible event"
                ))),
            }
        })
        .transpose()
}

fn validate_dispatch_approval_event(
    event: &RunEvent,
    approval_id: &str,
    call_id: &str,
) -> Result<(), StorageError> {
    let approval = event
        .approval
        .as_ref()
        .filter(|approval| {
            approval.id == approval_id
                && approval.status == ApprovalStatus::Approved
                && approval.call_id.as_deref() == Some(call_id)
        })
        .ok_or_else(|| {
            StorageError::CorruptData(
                "dispatch approval event is not bound to the queued approval/call".into(),
            )
        })?;
    if event.event_type != EventType::Approval {
        return Err(StorageError::CorruptData(
            "dispatch approval binding is not an approval event".into(),
        ));
    }
    match event.data.as_ref() {
        Some(RunEventData::ApprovalDecided {
            approval_id: data_approval_id,
            call_id: data_call_id,
            decision: ReviewDecision::Approve,
            status: ToolCallStatus::Queued,
        }) if data_approval_id == approval_id
            && data_call_id == call_id
            && approval.scope == Some(ApprovalScope::AllowOnce) =>
        {
            Ok(())
        }
        // v1 dispatch history predates typed event data. StoredEventRow has
        // already proven that `None` is legal only for a v1 payload.
        None => Ok(()),
        _ => Err(StorageError::CorruptData(
            "dispatch approval event has inconsistent typed decision data".into(),
        )),
    }
}

fn query_run_event_at(
    connection: &Connection,
    run_id: &str,
    sequence: i64,
) -> Result<RunEvent, StorageError> {
    connection
        .query_row(
            r#"SELECT sequence, event_id, event_kind, payload_version, payload_json,
                      data_kind, call_id, approval_id, approval_status, policy_revision
               FROM run_events
               WHERE run_id = ?1 AND sequence = ?2"#,
            params![run_id, sequence],
            decode_stored_event_row,
        )
        .optional()?
        .ok_or_else(|| {
            StorageError::CorruptData(format!(
                "run `{run_id}` has no event at sequence {sequence}"
            ))
        })?
        .decode()
}

fn decode_stored_event_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredEventRow> {
    Ok(StoredEventRow {
        sequence: row.get(0)?,
        event_id: row.get(1)?,
        event_kind: row.get(2)?,
        payload_version: row.get(3)?,
        payload_json: row.get(4)?,
        data_kind: row.get(5)?,
        call_id: row.get(6)?,
        approval_id: row.get(7)?,
        approval_status: row.get(8)?,
        policy_revision: row.get(9)?,
    })
}

fn load_snapshot(connection: &mut Connection, run_id: &str) -> Result<RunSnapshot, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let snapshot = query_snapshot(&transaction, run_id)?;
    transaction.commit()?;
    Ok(snapshot)
}

fn load_snapshot_for_actor(
    connection: &mut Connection,
    actor_user_id: &str,
    run_id: &str,
) -> Result<RunSnapshot, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_active_run_owner(&transaction, run_id, actor_user_id)?;
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

fn load_run_for_actor(
    connection: &mut Connection,
    actor_user_id: &str,
    run_id: &str,
) -> Result<StoredRun, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_active_run_owner(&transaction, run_id, actor_user_id)?;
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

fn events_after_for_actor(
    connection: &mut Connection,
    actor_user_id: &str,
    run_id: &str,
    after: u64,
) -> Result<Vec<RunEvent>, StorageError> {
    let after = u64_to_i64(after, "event cursor")?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_active_run_owner(&transaction, run_id, actor_user_id)?;
    let events = query_events(&transaction, run_id, after)?;
    transaction.commit()?;
    Ok(events)
}

fn query_run_event_page(
    connection: &mut Connection,
    run_id: &str,
    after: u64,
    limit: usize,
) -> Result<RunEventPage, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let head_sequence = query_run_head(&transaction, run_id)?;
    let (after_sql, fetch_limit) = validated_event_page_request(after, limit)?;
    reject_cursor_beyond_head(after, head_sequence)?;
    let page = query_run_events_page(
        &transaction,
        run_id,
        after,
        after_sql,
        limit,
        fetch_limit,
        head_sequence,
    )?;
    transaction.commit()?;
    Ok(page)
}

fn query_run_event_page_for_actor(
    connection: &mut Connection,
    actor_user_id: &str,
    run_id: &str,
    after: u64,
    limit: usize,
) -> Result<RunEventPage, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_active_run_owner(&transaction, run_id, actor_user_id)?;
    let head_sequence = query_run_head(&transaction, run_id)?;
    let (after_sql, fetch_limit) = validated_event_page_request(after, limit)?;
    reject_cursor_beyond_head(after, head_sequence)?;
    let page = query_run_events_page(
        &transaction,
        run_id,
        after,
        after_sql,
        limit,
        fetch_limit,
        head_sequence,
    )?;
    transaction.commit()?;
    Ok(page)
}

fn query_run_head(connection: &Connection, run_id: &str) -> Result<u64, StorageError> {
    let (head, projection_sequence) = connection
        .query_row(
            "SELECT sequence, projection_sequence FROM runs WHERE id = ?1",
            [run_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?
        .ok_or_else(|| StorageError::RunNotFound(run_id.to_owned()))?;
    if projection_sequence != head {
        return Err(StorageError::CorruptData(format!(
            "projection sequence {projection_sequence} does not match run head {head}"
        )));
    }
    i64_to_u64(head, "run sequence")
}

fn query_events(
    connection: &Connection,
    run_id: &str,
    after: i64,
) -> Result<Vec<RunEvent>, StorageError> {
    let mut statement = connection.prepare(
        r#"SELECT sequence, event_id, event_kind, payload_version, payload_json,
                  data_kind, call_id, approval_id, approval_status, policy_revision
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
            data_kind: row.get(5)?,
            call_id: row.get(6)?,
            approval_id: row.get(7)?,
            approval_status: row.get(8)?,
            policy_revision: row.get(9)?,
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

#[allow(clippy::too_many_arguments)]
fn query_run_events_page(
    connection: &Connection,
    run_id: &str,
    after: u64,
    after_sql: i64,
    limit: usize,
    fetch_limit: i64,
    head_sequence: u64,
) -> Result<RunEventPage, StorageError> {
    let mut statement = connection.prepare(
        r#"SELECT sequence, event_id, event_kind, payload_version, payload_json,
                  data_kind, call_id, approval_id, approval_status, policy_revision
           FROM run_events
           WHERE run_id = ?1 AND sequence > ?2
           ORDER BY sequence LIMIT ?3"#,
    )?;
    let mut rows = statement.query(params![run_id, after_sql, fetch_limit])?;
    let mut events = Vec::with_capacity(limit.saturating_add(1));
    let mut expected = after_sql.checked_add(1);
    while let Some(row) = rows.next()? {
        let stored = StoredEventRow {
            sequence: row.get(0)?,
            event_id: row.get(1)?,
            event_kind: row.get(2)?,
            payload_version: row.get(3)?,
            payload_json: row.get(4)?,
            data_kind: row.get(5)?,
            call_id: row.get(6)?,
            approval_id: row.get(7)?,
            approval_status: row.get(8)?,
            policy_revision: row.get(9)?,
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
    finish_run_event_page(events, after, limit, head_sequence)
}

fn load_review_receipt(
    connection: &Connection,
    idempotency_key: &str,
) -> Result<Option<ReviewReceipt>, StorageError> {
    let stored = connection
        .query_row(
            r#"SELECT operation, request_fingerprint, response_json, run_id, event_sequence
               FROM idempotency_receipts
               WHERE actor_scope = '__legacy__'
                 AND operation = 'review'
                 AND idempotency_key = ?1"#,
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
    validate_stored_review_fingerprint(&request_fingerprint)?;
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

fn load_review_receipt_for_actor(
    connection: &mut Connection,
    actor_user_id: &str,
    run_id: &str,
    idempotency_key: &str,
) -> Result<Option<ReviewReceipt>, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_active_run_owner(&transaction, run_id, actor_user_id)?;
    let stored = transaction
        .query_row(
            r#"SELECT request_fingerprint, response_json, run_id, event_sequence
               FROM idempotency_receipts
               WHERE actor_scope = ?1
                 AND operation = 'review'
                 AND idempotency_key = ?2"#,
            params![actor_user_id, idempotency_key],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    let receipt = stored
        .map(
            |(request_fingerprint, response_json, stored_run_id, event_sequence)| {
                if stored_run_id != run_id {
                    return Err(StorageError::IdempotencyConflict);
                }
                decode_review_receipt(
                    request_fingerprint,
                    response_json,
                    stored_run_id,
                    event_sequence,
                )
            },
        )
        .transpose()?;
    transaction.commit()?;
    Ok(receipt)
}

fn load_review_receipt_for_actor_in_transaction(
    connection: &Connection,
    actor_user_id: &str,
    run_id: &str,
    idempotency_key: &str,
) -> Result<Option<ReviewReceipt>, StorageError> {
    let stored = connection
        .query_row(
            r#"SELECT request_fingerprint, response_json, run_id, event_sequence
               FROM idempotency_receipts
               WHERE actor_scope = ?1
                 AND operation = 'review'
                 AND idempotency_key = ?2"#,
            params![actor_user_id, idempotency_key],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    stored
        .map(
            |(request_fingerprint, response_json, stored_run_id, event_sequence)| {
                if stored_run_id != run_id {
                    return Err(StorageError::IdempotencyConflict);
                }
                decode_review_receipt(
                    request_fingerprint,
                    response_json,
                    stored_run_id,
                    event_sequence,
                )
            },
        )
        .transpose()
}

fn decode_review_receipt(
    request_fingerprint: String,
    response_json: String,
    run_id: String,
    event_sequence: i64,
) -> Result<ReviewReceipt, StorageError> {
    validate_stored_review_fingerprint(&request_fingerprint)?;
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
    Ok(ReviewReceipt {
        request_fingerprint,
        response,
    })
}

fn commit_review(
    connection: &mut Connection,
    commit: ReviewCommit,
    actor_user_id: Option<&str>,
    fail_after_event: bool,
) -> Result<CommitOutcome, StorageError> {
    validated_durable_reference(&commit.snapshot.run.id, "run ID")?;
    let key = normalized_key(&commit.idempotency_key)?.to_owned();
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(actor_user_id) = actor_user_id {
        require_active_run_owner(&transaction, &commit.snapshot.run.id, actor_user_id)?;
        if commit
            .dispatch
            .as_ref()
            .is_some_and(|dispatch| dispatch.approving_actor_user_id != actor_user_id)
        {
            return Err(StorageError::RunNotFound(commit.snapshot.run.id.clone()));
        }
    }
    validate_commit(&commit)?;
    let new_sequence = u64_to_i64(commit.snapshot.run.sequence, "run sequence")?;
    let response_json = serde_json::to_string(&commit.response)?;
    let stored_receipt = match actor_user_id {
        Some(actor_user_id) => load_review_receipt_for_actor_in_transaction(
            &transaction,
            actor_user_id,
            &commit.snapshot.run.id,
            &key,
        )?,
        None => load_review_receipt(&transaction, &key)?,
    };
    if let Some(receipt) = stored_receipt {
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
               actor_scope, idempotency_key, operation, request_fingerprint,
               response_json, run_id, event_sequence, created_at
           ) VALUES (?1, ?2, 'review', ?3, ?4, ?5, ?6, ?7)"#,
        params![
            actor_user_id.unwrap_or("__legacy__"),
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
           ORDER BY started_at, call_id LIMIT ?1"#,
    )?;
    let call_ids = statement
        .query_map([RECOVERY_BATCH_LIMIT], |row| row.get::<_, String>(0))?
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
                   approving_actor_user_id, tool_name, tool_version, effect, args_json, args_digest,
                   policy_id, policy_revision, sandbox_profile, status, attempt,
                   result_json, authorization_error_json, queued_at, started_at, finished_at,
                   start_event_sequence, result_event_sequence
               FROM dispatch_jobs WHERE call_id = ?1"#,
            [call_id],
            |row| {
                Ok(StoredDispatchRow {
                    call_id: row.get(0)?,
                    run_id: row.get(1)?,
                    approval_id: row.get(2)?,
                    approval_event_sequence: row.get(3)?,
                    approving_actor_user_id: row.get(4)?,
                    tool_name: row.get(5)?,
                    tool_version: row.get(6)?,
                    effect: row.get(7)?,
                    args_json: row.get(8)?,
                    args_digest: row.get(9)?,
                    policy_id: row.get(10)?,
                    policy_revision: row.get(11)?,
                    sandbox_profile: row.get(12)?,
                    status: row.get(13)?,
                    attempt: row.get(14)?,
                    result_json: row.get(15)?,
                    authorization_error_json: row.get(16)?,
                    queued_at: row.get(17)?,
                    started_at: row.get(18)?,
                    finished_at: row.get(19)?,
                    start_event_sequence: row.get(20)?,
                    result_event_sequence: row.get(21)?,
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
    normalized_identifier(&commit.call_id, "call ID")?;

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
    if let Some(reason) = dispatch_authorization_failure(&transaction, &job)? {
        let rejection = reject_dispatch_authorization(&transaction, job, reason)?;
        transaction.commit()?;
        return Ok(ClaimOutcome::Rejected(Box::new(rejection)));
    }

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

fn dispatch_authorization_failure(
    connection: &Connection,
    job: &DispatchJob,
) -> Result<Option<&'static str>, StorageError> {
    let Some(actor_user_id) = job.approving_actor_user_id.as_deref() else {
        return Ok(Some("missing_approving_actor"));
    };
    let actor = connection
        .query_row(
            "SELECT role, status FROM users WHERE id = ?1",
            [actor_user_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((role, status)) = actor else {
        return Ok(Some("approving_actor_missing"));
    };
    if status != "active" {
        return Ok(Some("approving_actor_disabled"));
    }
    if role != "owner" {
        return Ok(Some("approving_actor_role_changed"));
    }
    let owns_run: i64 = connection.query_row(
        r#"SELECT EXISTS(
               SELECT 1 FROM runs
               WHERE id = ?1 AND owner_user_id = ?2
           )"#,
        params![job.run_id, actor_user_id],
        |row| row.get(0),
    )?;
    if owns_run == 0 {
        return Ok(Some("approving_actor_no_longer_owns_run"));
    }
    Ok(None)
}

fn reject_dispatch_authorization(
    connection: &Connection,
    job: DispatchJob,
    reason: &'static str,
) -> Result<DispatchRejection, StorageError> {
    if job.status != DispatchStatus::Queued {
        return Err(StorageError::InvalidDispatchTransition(
            "only a queued dispatch may be authorization-rejected".into(),
        ));
    }
    let mut snapshot = query_snapshot(connection, &job.run_id)?;
    validate_run_event_tail(connection, &snapshot)?;
    if snapshot.run.status != RunStatus::Queued {
        return Err(StorageError::InvalidDispatchTransition(
            "authorization rejection requires a queued run projection".into(),
        ));
    }
    if snapshot.run.sequence != job.approval_event_sequence {
        return Err(StorageError::CorruptData(
            "queued dispatch approval is not the current run event head".into(),
        ));
    }
    let approval_event = query_run_event_at(
        connection,
        &job.run_id,
        u64_to_i64(job.approval_event_sequence, "approval event sequence")?,
    )?;
    validate_dispatch_approval_event(&approval_event, &job.approval_id, &job.call_id)?;
    let (call_sequence, call) = query_requested_call(connection, &job.run_id, &job.call_id)?
        .ok_or_else(|| {
            StorageError::CorruptData("queued dispatch has no requested-call event".into())
        })?;
    if call_sequence >= job.approval_event_sequence {
        return Err(StorageError::CorruptData(
            "queued dispatch approval precedes its requested tool call".into(),
        ));
    }
    validate_dispatch_job_binding(&job, &snapshot, &approval_event, &call)?;
    let expected_sequence = snapshot.run.sequence;
    let next_sequence = expected_sequence
        .checked_add(1)
        .ok_or(StorageError::IntegerOutOfRange("run sequence"))?;
    let previous = approval_event;
    let timestamp = now();
    let summary =
        "The approving actor is no longer authorized; connector execution was not attempted.";
    let outcome = ToolOutcome::NotDispatched {
        reason: NotDispatchedReason::AuthorizationRevoked,
        summary: summary.into(),
    };
    let event = RunEvent {
        sequence: next_sequence,
        id: format!("evt-{next_sequence:06}"),
        turn: previous.turn,
        step: previous.step.saturating_add(1),
        event_type: EventType::ToolCall,
        title: "Tool was not dispatched".into(),
        at: timestamp.clone(),
        summary: Some(summary.into()),
        content: None,
        metadata: BTreeMap::from([
            ("durable".into(), json!(true)),
            ("executor_invoked".into(), json!(false)),
            ("authorization_rechecked".into(), json!(true)),
        ]),
        approval: None,
        data: Some(RunEventData::ToolResult {
            call_id: job.call_id.clone(),
            outcome: outcome.clone(),
            status: ToolCallStatus::NotDispatched,
        }),
    };
    snapshot.run.status = RunStatus::NeedsAttention;
    snapshot.run.sequence = next_sequence;
    update_projection(connection, &snapshot, expected_sequence)?;
    insert_event_v2(connection, &job.run_id, &event)?;

    let result_json = serde_json::to_string(&serde_json::to_value(&outcome)?)?;
    let authorization_error_json = serde_json::to_string(&json!({
        "code": "authorization_revoked",
        "reason": reason,
        "executor_invoked": false
    }))?;
    let changed = connection.execute(
        r#"UPDATE dispatch_jobs SET
               status = 'rejected',
               result_json = ?1,
               authorization_error_json = ?2,
               finished_at = ?3,
               result_event_sequence = ?4
           WHERE call_id = ?5 AND status = 'queued' AND attempt = 0"#,
        params![
            result_json,
            authorization_error_json,
            timestamp,
            u64_to_i64(next_sequence, "dispatch rejection event sequence")?,
            job.call_id,
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    let rejected = query_dispatch_job(connection, &job.call_id)?.ok_or_else(|| {
        StorageError::CorruptData("rejected dispatch disappeared before commit".into())
    })?;
    Ok(DispatchRejection {
        job: rejected,
        event,
    })
}

fn validate_dispatch_job_binding(
    job: &DispatchJob,
    snapshot: &RunSnapshot,
    approval_event: &RunEvent,
    call: &protocol::ToolCall,
) -> Result<(), StorageError> {
    let approval = approval_event.approval.as_ref().ok_or_else(|| {
        StorageError::CorruptData("dispatch approval event has no approval binding".into())
    })?;
    let matches = job.run_id == snapshot.run.id
        && job.tool_name == call.tool
        && job.tool_version == call.tool_version
        && job.effect == call.effect
        && job.args_json == call.arguments
        && job.args_digest == call.arguments_digest
        && job.sandbox_profile == call.sandbox_profile
        && approval.id == job.approval_id
        && approval.call_id.as_deref() == Some(job.call_id.as_str())
        && approval.policy_revision.as_deref() == Some(job.policy_revision.as_str())
        && approval.arguments_digest.as_deref() == Some(job.args_digest.as_str())
        && approval.sandbox_profile.as_ref() == Some(&job.sandbox_profile);
    if !matches {
        return Err(StorageError::CorruptData(
            "dispatch job, approval, and requested call do not have one exact binding".into(),
        ));
    }
    Ok(())
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
               approving_actor_user_id, tool_name, tool_version, effect, args_json, args_digest,
               policy_id, policy_revision, sandbox_profile, status, attempt, queued_at
           ) VALUES (
               ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
               'queued', 0, ?14
           )"#,
        params![
            job.call_id,
            run_id,
            job.approval_id,
            approval_event_sequence,
            job.approving_actor_user_id,
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
    let lookup = RunEventLookup::from_event(event)?;
    connection.execute(
        r#"INSERT INTO run_events(
               run_id, sequence, event_id, event_kind, payload_version, payload_json,
               data_kind, call_id, approval_id, approval_status, policy_revision
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"#,
        params![
            run_id,
            sequence,
            event.id,
            event_kind(&event.event_type),
            payload_version,
            serde_json::to_string(event)?,
            lookup.data_kind,
            lookup.call_id,
            lookup.approval_id,
            lookup.approval_status,
            lookup.policy_revision,
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
    validate_new_review_fingerprint(&commit.request_fingerprint, commit.event.content.as_deref())?;
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
    validated_durable_reference(&job.call_id, "call ID")?;
    validated_durable_reference(&job.approval_id, "approval ID")?;
    for (value, field) in [
        (&job.approving_actor_user_id, "approving actor user ID"),
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

fn validate_stored_review_fingerprint(fingerprint: &str) -> Result<(), StorageError> {
    let value: Value = serde_json::from_str(fingerprint)?;
    if !value.is_object() {
        return Err(StorageError::CorruptData(
            "review request fingerprint must be a JSON object".into(),
        ));
    }
    Ok(())
}

fn validate_new_review_fingerprint(
    fingerprint: &str,
    event_content: Option<&str>,
) -> Result<(), StorageError> {
    let value: Value = serde_json::from_str(fingerprint)?;
    let object = value.as_object().ok_or_else(|| {
        StorageError::CorruptData("review request fingerprint must be a JSON object".into())
    })?;
    for (field, label) in [("run_id", "run ID"), ("approval_id", "approval ID")] {
        if let Some(value) = object.get(field) {
            let value = value.as_str().ok_or_else(|| {
                StorageError::CorruptData(format!(
                    "review request fingerprint {field} must be a string"
                ))
            })?;
            validated_durable_reference(value, label)?;
        }
    }
    if let Some(value) = object.get("note") {
        let fingerprint_note = if value.is_null() {
            None
        } else {
            let note = value.as_str().ok_or_else(|| {
                StorageError::CorruptData(
                    "review request fingerprint note must be a string or null".into(),
                )
            })?;
            validate_review_note_value(note, "review note")?;
            Some(note)
        };
        if fingerprint_note != event_content {
            return Err(StorageError::CorruptData(
                "review request fingerprint note does not match event content".into(),
            ));
        }
    }
    Ok(())
}

fn normalized_key(key: &str) -> Result<&str, StorageError> {
    match protocol::validate_idempotency_key(key) {
        Ok(()) => Ok(key),
        Err(ResourceEnvelopeError::Empty) => Err(StorageError::EmptyIdempotencyKey),
        Err(error) => Err(invalid_resource_envelope("idempotency key", error)),
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

fn normalized_account_value<'a>(
    value: &'a str,
    field: &'static str,
    max_bytes: usize,
) -> Result<&'a str, StorageError> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > max_bytes
        || value.chars().any(char::is_control)
    {
        return Err(StorageError::InvalidAccountData(format!(
            "{field} must be canonical, control-free, and at most {max_bytes} bytes"
        )));
    }
    Ok(value)
}

fn normalized_token_hash<'a>(value: &'a str, field: &'static str) -> Result<&'a str, StorageError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(StorageError::InvalidAccountData(format!(
            "{field} must be a lowercase SHA-256 hex digest"
        )));
    }
    Ok(value)
}

fn normalized_password_hash(value: &str) -> Result<&str, StorageError> {
    if !value.starts_with("$argon2id$") || value.len() > 1024 || value.chars().any(char::is_control)
    {
        return Err(StorageError::InvalidAccountData(
            "password hash must be a bounded Argon2id PHC string".into(),
        ));
    }
    Ok(value)
}

fn normalized_timestamp<'a>(value: &'a str, field: &'static str) -> Result<&'a str, StorageError> {
    chrono::DateTime::parse_from_rfc3339(value).map_err(|_| {
        StorageError::InvalidAccountData(format!("{field} must be an RFC 3339 timestamp"))
    })?;
    Ok(value)
}

fn normalized_theme(value: &str) -> Result<&str, StorageError> {
    if matches!(value, "system" | "light" | "dark") {
        Ok(value)
    } else {
        Err(StorageError::InvalidAccountData(format!(
            "unsupported theme `{value}`"
        )))
    }
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn validated_event_page_request(after: u64, limit: usize) -> Result<(i64, i64), StorageError> {
    if limit == 0 || limit > EVENT_PAGE_MAX_LIMIT {
        return Err(StorageError::InvalidEventPageLimit {
            limit,
            max: EVENT_PAGE_MAX_LIMIT,
        });
    }
    let after_sql =
        i64::try_from(after).map_err(|_| StorageError::EventCursorOutOfRange { after })?;
    let fetch_limit = i64::try_from(limit + 1)
        .expect("the bounded event page limit is always representable by SQLite");
    Ok((after_sql, fetch_limit))
}

fn reject_cursor_beyond_head(after: u64, head_sequence: u64) -> Result<(), StorageError> {
    if after > head_sequence {
        Err(StorageError::EventCursorBeyondHead {
            after,
            head_sequence,
        })
    } else {
        Ok(())
    }
}

fn finish_run_event_page(
    mut items: Vec<RunEvent>,
    after: u64,
    limit: usize,
    head_sequence: u64,
) -> Result<RunEventPage, StorageError> {
    if items.len() > limit + 1 {
        return Err(StorageError::CorruptData(
            "bounded run event query exceeded its SQL limit".into(),
        ));
    }
    let has_more = items.len() == limit + 1;
    let sentinel = has_more.then(|| items.pop().expect("limit is at least one"));
    let observed_tail = items.last().map_or(after, |event| event.sequence);
    if let Some(sentinel) = sentinel
        && sentinel.sequence > head_sequence
    {
        return Err(StorageError::CorruptData(format!(
            "run event {} is beyond durable head {head_sequence}",
            sentinel.sequence
        )));
    }
    if !has_more && observed_tail != head_sequence {
        return Err(StorageError::CorruptData(format!(
            "run page ended at {observed_tail}, before durable head {head_sequence}"
        )));
    }
    Ok(RunEventPage {
        next_after: has_more.then_some(observed_tail),
        items,
        head_sequence,
        has_more,
    })
}

fn finish_session_event_page(
    mut items: Vec<SessionEvent>,
    after: u64,
    limit: usize,
    head_sequence: u64,
) -> Result<SessionEventPage, StorageError> {
    if items.len() > limit + 1 {
        return Err(StorageError::CorruptData(
            "bounded session event query exceeded its SQL limit".into(),
        ));
    }
    let has_more = items.len() == limit + 1;
    let sentinel = has_more.then(|| items.pop().expect("limit is at least one"));
    let observed_tail = items.last().map_or(after, |event| event.sequence);
    if let Some(sentinel) = sentinel
        && sentinel.sequence > head_sequence
    {
        return Err(StorageError::CorruptData(format!(
            "session event {} is beyond durable head {head_sequence}",
            sentinel.sequence
        )));
    }
    if !has_more && observed_tail != head_sequence {
        return Err(StorageError::CorruptData(format!(
            "session page ended at {observed_tail}, before durable head {head_sequence}"
        )));
    }
    Ok(SessionEventPage {
        next_after: has_more.then_some(observed_tail),
        items,
        head_sequence,
        has_more,
    })
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

fn reply_status_to_db(status: &ReplyJobStatus) -> &'static str {
    match status {
        ReplyJobStatus::Queued => "queued",
        ReplyJobStatus::Started => "started",
        ReplyJobStatus::Succeeded => "succeeded",
        ReplyJobStatus::Failed => "failed",
        ReplyJobStatus::OutcomeUnknown => "outcome_unknown",
    }
}

fn reply_status_from_db(value: &str) -> Result<ReplyJobStatus, StorageError> {
    match value {
        "queued" => Ok(ReplyJobStatus::Queued),
        "started" => Ok(ReplyJobStatus::Started),
        "succeeded" => Ok(ReplyJobStatus::Succeeded),
        "failed" => Ok(ReplyJobStatus::Failed),
        "outcome_unknown" => Ok(ReplyJobStatus::OutcomeUnknown),
        other => Err(StorageError::CorruptData(format!(
            "unknown reply job status `{other}`"
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
                event_kind: self.event_kind.clone(),
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

struct StoredReplyJobRow {
    id: String,
    actor_user_id: String,
    session_id: String,
    turn_id: String,
    provider_name: String,
    model_name: Option<String>,
    status: String,
    attempt: i64,
    request_json: String,
    response_json: Option<String>,
    error_json: Option<String>,
    queued_at: String,
    started_at: Option<String>,
    finished_at: Option<String>,
    completion_fingerprint: Option<String>,
    assistant_event_sequence: Option<i64>,
    terminal_event_sequence: Option<i64>,
}

impl StoredReplyJobRow {
    fn decode(self) -> Result<ReplyJob, StorageError> {
        let status = reply_status_from_db(&self.status)?;
        let attempt = u32::try_from(self.attempt)
            .map_err(|_| StorageError::IntegerOutOfRange("reply job attempt"))?;
        let assistant_event_sequence = self
            .assistant_event_sequence
            .map(|value| i64_to_u64(value, "assistant reply event sequence"))
            .transpose()?;
        let terminal_event_sequence = self
            .terminal_event_sequence
            .map(|value| i64_to_u64(value, "reply terminal event sequence"))
            .transpose()?;
        let shape_is_valid = match status {
            ReplyJobStatus::Queued => {
                attempt == 0
                    && self.response_json.is_none()
                    && self.error_json.is_none()
                    && self.completion_fingerprint.is_none()
                    && self.started_at.is_none()
                    && self.finished_at.is_none()
                    && assistant_event_sequence.is_none()
                    && terminal_event_sequence.is_none()
            }
            ReplyJobStatus::Started => {
                attempt == 1
                    && self.response_json.is_none()
                    && self.error_json.is_none()
                    && self.completion_fingerprint.is_none()
                    && self.started_at.is_some()
                    && self.finished_at.is_none()
                    && assistant_event_sequence.is_none()
                    && terminal_event_sequence.is_none()
            }
            ReplyJobStatus::Succeeded => {
                attempt == 1
                    && self.response_json.is_some()
                    && self.error_json.is_none()
                    && self.completion_fingerprint.is_some()
                    && self.started_at.is_some()
                    && self.finished_at.is_some()
                    && assistant_event_sequence.is_some()
                    && terminal_event_sequence
                        == assistant_event_sequence.and_then(|sequence| sequence.checked_add(1))
            }
            ReplyJobStatus::Failed | ReplyJobStatus::OutcomeUnknown => {
                attempt == 1
                    && self.response_json.is_none()
                    && self.error_json.is_some()
                    && self.completion_fingerprint.is_some()
                    && self.started_at.is_some()
                    && self.finished_at.is_some()
                    && assistant_event_sequence.is_none()
                    && terminal_event_sequence.is_some()
            }
        };
        if !shape_is_valid {
            return Err(StorageError::CorruptData(format!(
                "reply job `{}` status disagrees with its durable fields",
                self.id
            )));
        }
        if let Some(fingerprint) = &self.completion_fingerprint {
            let value: Value = serde_json::from_str(fingerprint)?;
            if !value.is_object() {
                return Err(StorageError::CorruptData(format!(
                    "reply job `{}` has a non-object completion fingerprint",
                    self.id
                )));
            }
        }
        Ok(ReplyJob {
            id: self.id,
            actor_user_id: self.actor_user_id,
            session_id: self.session_id,
            turn_id: self.turn_id,
            provider_name: self.provider_name,
            model_name: self.model_name,
            status,
            attempt,
            request_json: serde_json::from_str(&self.request_json)?,
            response_json: self
                .response_json
                .map(|value| serde_json::from_str(&value))
                .transpose()?,
            error_json: self
                .error_json
                .map(|value| serde_json::from_str(&value))
                .transpose()?,
            queued_at: self.queued_at,
            started_at: self.started_at,
            finished_at: self.finished_at,
            assistant_event_sequence,
            terminal_event_sequence,
        })
    }
}

struct StoredDispatchRow {
    call_id: String,
    run_id: String,
    approval_id: String,
    approval_event_sequence: i64,
    approving_actor_user_id: Option<String>,
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
    authorization_error_json: Option<String>,
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
            "rejected" => DispatchStatus::Rejected,
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
            approving_actor_user_id: self.approving_actor_user_id,
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
            authorization_error_json: self
                .authorization_error_json
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
    data_kind: Option<String>,
    call_id: Option<String>,
    approval_id: Option<String>,
    approval_status: Option<String>,
    policy_revision: Option<String>,
}

impl StoredEventRow {
    fn decode_payload(&self) -> Result<RunEvent, StorageError> {
        let expected_type = event_type_from_kind(&self.event_kind)?;
        if !matches!(
            self.payload_version,
            EVENT_PAYLOAD_VERSION_V1 | EVENT_PAYLOAD_VERSION_V2
        ) {
            return Err(StorageError::UnsupportedPayloadVersion {
                event_kind: self.event_kind.clone(),
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

    fn decode(self) -> Result<RunEvent, StorageError> {
        let event = self.decode_payload()?;
        let lookup = RunEventLookup::from_event(&event)?;
        if self.data_kind.as_deref() != lookup.data_kind
            || self.call_id.as_deref() != lookup.call_id
            || self.approval_id.as_deref() != lookup.approval_id
            || self.approval_status.as_deref() != lookup.approval_status
            || self.policy_revision.as_deref() != lookup.policy_revision
        {
            return Err(StorageError::CorruptData(format!(
                "run event lookup projection disagrees with payload at sequence {}",
                self.sequence
            )));
        }
        Ok(event)
    }
}

struct RunEventLookup<'a> {
    data_kind: Option<&'static str>,
    call_id: Option<&'a str>,
    approval_id: Option<&'a str>,
    approval_status: Option<&'static str>,
    policy_revision: Option<&'a str>,
}

impl<'a> RunEventLookup<'a> {
    fn from_event(event: &'a RunEvent) -> Result<Self, StorageError> {
        let (data_kind, call_id) = match event.data.as_ref() {
            Some(RunEventData::ToolCallRequested { call, .. }) => {
                (Some("tool_call_requested"), Some(call.call_id.as_str()))
            }
            Some(RunEventData::ToolPolicyDecided { call_id, .. }) => {
                (Some("tool_policy_decided"), Some(call_id.as_str()))
            }
            Some(RunEventData::ApprovalRequested { call_id, .. }) => {
                (Some("approval_requested"), Some(call_id.as_str()))
            }
            Some(RunEventData::ApprovalDecided { call_id, .. }) => {
                (Some("approval_decided"), Some(call_id.as_str()))
            }
            Some(RunEventData::ToolDispatchStarted { call_id, .. }) => {
                (Some("tool_dispatch_started"), Some(call_id.as_str()))
            }
            Some(RunEventData::ToolResult { call_id, .. }) => {
                (Some("tool_result"), Some(call_id.as_str()))
            }
            None => (None, None),
        };
        let approval_status = event
            .approval
            .as_ref()
            .map(|approval| match approval.status {
                ApprovalStatus::Pending => "pending",
                ApprovalStatus::Approved => "approved",
                ApprovalStatus::Rejected => "rejected",
            });
        let approval_policy_revision = event
            .approval
            .as_ref()
            .and_then(|approval| approval.policy_revision.as_deref());
        let decision_policy_revision = match event.data.as_ref() {
            Some(RunEventData::ToolPolicyDecided {
                policy_revision, ..
            }) => Some(policy_revision.as_str()),
            _ => None,
        };
        if let (Some(approval), Some(decision)) =
            (approval_policy_revision, decision_policy_revision)
            && approval != decision
        {
            return Err(StorageError::CorruptData(format!(
                "run event {} contains conflicting policy revisions",
                event.sequence
            )));
        }
        Ok(Self {
            data_kind,
            call_id,
            approval_id: event.approval.as_ref().map(|approval| approval.id.as_str()),
            approval_status,
            policy_revision: approval_policy_revision.or(decision_policy_revision),
        })
    }
}
