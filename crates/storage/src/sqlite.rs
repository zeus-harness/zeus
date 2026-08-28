use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use authz::{AccountCapability, membership_allows};
use chrono::{SecondsFormat, Utc};
use fs2::{FileExt, available_space};
use protocol::{
    ApprovalScope, ApprovalStatus, AssistantReplyProvenance, AttachRunRequest, AttachRunResponse,
    COLLECTION_PAGE_MAX_LIMIT, CreateSessionRequest, CreateSessionResponse, EVENT_PAGE_MAX_LIMIT,
    EnqueueSessionFollowupRequest, EnqueueSessionFollowupResponse, EventType, FlushSessionRequest,
    FlushSessionResponse, IncidentStatus, IncidentSummary, NotDispatchedReason, ReadPageInfo,
    ResourceEnvelopeError, ResumeSessionRequest, ResumeSessionResponse, ReviewDecision,
    ReviewResponse, RunEvent, RunEventData, RunEventPage, RunStatus, RunSummary, SandboxProfile,
    SessionDetail, SessionDetailPagination, SessionEvent, SessionEventData, SessionEventPage,
    SessionFlushAck, SessionFlushBarrier, SessionFlushBarrierStatus, SessionFollowup,
    SessionFollowupStatus, SessionStatus, SessionSummary, SessionTurn, SessionTurnStatus, Severity,
    StartTurnRequest, StartTurnResponse, ToolCallStatus, ToolEffect, ToolOutcome,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::cursor;
mod agent;
mod compaction;
mod execution;
mod provider;
use crate::operation::{OperationClass, OperationLimiter};
use crate::{
    AccountAuditArchiveState, AccountAuditCheckpointCommit, AccountAuditEvent, AccountAuditPage,
    AccountAuditPolicy, AccountAuditRollup, AccountAuditState, AccountId,
    AccountReplyProviderCommit, AccountReplyProviderState, AccountReplyProviderUpdateResult,
    AgentGoalRoundSpec, AgentModelJob, AgentPromptCommit, AgentPromptRevisionPage,
    AgentPromptState, AgentPromptUpdateResult, AgentTurn, AgentTurnEnqueueResponse,
    AgentTurnReceiptProbe, AgentTurnSpec, AuthPrincipal, AuthSessionCommit, AuthSessionId,
    AuthzContext, BootstrapOwnerCommit, BoundedRunRead, ClaimOutcome, CommitOutcome,
    CreateAccountCommit, CreateAccountResult, CreateMemberCommit, CreateMemberResult,
    DispatchCompleteCommit, DispatchContext, DispatchJob, DispatchJobSpec, DispatchRecoveryCommit,
    DispatchRejection, DispatchStartCommit, DispatchStatus, InFlightWorkSummary,
    KnowledgeCatalogCommit, KnowledgeCatalogRevisionPage, KnowledgeCatalogState,
    KnowledgeCatalogUpdateResult, MEMBER_SETUP_TOKEN_TTL_SECONDS, MemberSetupCommit,
    MemberSetupResult, MemberTransitionResult, MembershipRevision, MembershipRole,
    RecoveredSessionTurn, ReplyClaimOutcome, ReplyCompletion, ReplyFailureCommit, ReplyJob,
    ReplyJobEnqueueResponse, ReplyJobSpec, ReplyJobStatus, ReplyOutcomeUnknownCommit,
    ReplySuccessCommit, ReviewCommit, ReviewContext, ReviewReceipt, RotateMemberSetupTokenCommit,
    RotateMemberSetupTokenResult, RunSnapshot, RuntimeIdentity, SessionCompactionClaimOutcome,
    SessionCompactionFailureCommit, SessionCompactionJob, SessionCompactionSuccessCommit,
    SessionContextCheckpoint, SessionFollowupCandidate, SessionSummaryPage, SqliteOperationLimits,
    SqlitePhysicalLimits, StorageError, StorageLimits, StoredAccount, StoredAccountStatus,
    StoredCredential, StoredMember, StoredMemberPage, StoredMembershipStatus, StoredPreferences,
    StoredRun, StoredUser, StoredUserRole, StoredUserStatus, SwitchAuthSessionCommit,
    SwitchAuthSessionResult, TransitionMemberCommit, UpdateAccountAuditPolicyCommit,
};

const CURRENT_SCHEMA_VERSION: i64 = 32;
const LOCAL_ACCOUNT_ID: &str = "acc_local";
const MAX_ACCOUNTS_PER_USER: i64 = 16;
const MAX_ACCOUNTS_GLOBAL: i64 = 64;
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
const MIGRATION_0010: &str = include_str!("../migrations/0010_capacity.sql");
const MIGRATION_0011: &str = include_str!("../migrations/0011_event_payload_bytes.sql");
const MIGRATION_0012: &str = include_str!("../migrations/0012_bootstrap_audit_retention.sql");
const MIGRATION_0013: &str = include_str!("../migrations/0013_account_membership_foundation.sql");
const MIGRATION_0014: &str =
    include_str!("../migrations/0014_account_scoped_durable_authorization.sql");
const MIGRATION_0015: &str = include_str!("../migrations/0015_member_lifecycle_account_audit.sql");
const MIGRATION_0016: &str = include_str!("../migrations/0016_session_reply_context_index.sql");
const MIGRATION_0017: &str = include_str!("../migrations/0017_session_agent_loop.sql");
const MIGRATION_0018: &str = include_str!("../migrations/0018_agent_tool_completion_replay.sql");
const MIGRATION_0019: &str = include_str!("../migrations/0019_agent_deployment_manifest.sql");
const MIGRATION_0020: &str = include_str!("../migrations/0020_agent_execution_ledger.sql");
const MIGRATION_0021: &str = include_str!("../migrations/0021_agent_operation_claims.sql");
const MIGRATION_0022: &str = include_str!("../migrations/0022_agent_knowledge_context.sql");
const MIGRATION_0023: &str = include_str!("../migrations/0023_account_knowledge_catalog.sql");
const MIGRATION_0024: &str = include_str!("../migrations/0024_account_agent_prompt.sql");
const MIGRATION_0025: &str = include_str!("../migrations/0025_session_context_compaction.sql");
const MIGRATION_0026: &str = include_str!("../migrations/0026_account_reply_provider.sql");
const MIGRATION_0027: &str = include_str!("../migrations/0027_agent_safe_cancellation.sql");
const MIGRATION_0028: &str = include_str!("../migrations/0028_agent_todo_snapshots.sql");
const MIGRATION_0029: &str = include_str!("../migrations/0029_session_agent_goals.sql");
const MIGRATION_0030: &str = include_str!("../migrations/0030_agent_goal_rounds.sql");
const MIGRATION_0031: &str = include_str!("../migrations/0031_session_followups.sql");
const MIGRATION_0032: &str = include_str!("../migrations/0032_agent_model_output_chunks.sql");
const MIGRATION_0022_TRIGGER_NAMES: &[&str] = &[
    "knowledge_corpus_revisions_reject_update",
    "knowledge_corpus_revisions_reject_delete",
    "agent_knowledge_contexts_reject_update",
    "agent_knowledge_contexts_reject_delete",
    "agent_knowledge_legacy_boundary_reject_insert",
    "agent_knowledge_legacy_boundary_reject_update",
    "agent_knowledge_legacy_boundary_reject_delete",
    "agent_knowledge_legacy_agents_reject_insert",
    "agent_knowledge_legacy_agents_reject_update",
    "agent_knowledge_legacy_agents_reject_delete",
    "agent_turns_require_knowledge_context",
    "agent_turns_reject_identity_update",
    "agent_model_jobs_require_current_step",
    "agent_model_jobs_reject_input_update",
];
const MIGRATION_0023_TRIGGER_NAMES: &[&str] = &[
    "account_knowledge_catalogs_require_current_owner",
    "account_knowledge_catalogs_enforce_revision",
    "account_knowledge_catalogs_reject_delete",
    "knowledge_catalog_receipts_require_current_owner",
    "knowledge_catalog_receipts_reject_update",
    "knowledge_catalog_receipts_reject_delete",
];
const MIGRATION_0024_TRIGGER_NAMES: &[&str] = &[
    "agent_prompt_revisions_reject_update",
    "agent_prompt_revisions_reject_delete",
    "account_agent_prompt_configs_require_current_owner",
    "account_agent_prompt_configs_enforce_revision",
    "account_agent_prompt_configs_reject_delete",
    "agent_prompt_config_receipts_require_current_owner",
    "agent_prompt_config_receipts_reject_update",
    "agent_prompt_config_receipts_reject_delete",
];
const MIGRATION_0025_TRIGGER_NAMES: &[&str] = &[
    "session_compaction_jobs_validate_insert",
    "session_compaction_jobs_reject_identity_update",
    "session_compaction_jobs_enforce_transition",
    "session_compaction_jobs_reject_delete",
];
const MIGRATION_0026_TRIGGER_NAMES: &[&str] = &[
    "account_reply_provider_configs_require_current_owner",
    "account_reply_provider_configs_enforce_revision",
    "account_reply_provider_configs_reject_delete",
    "account_reply_provider_receipts_require_current_owner",
    "account_reply_provider_receipts_reject_update",
    "account_reply_provider_receipts_reject_delete",
];
const MIGRATION_0027_TRIGGER_NAMES: &[&str] = &["agent_tool_calls_enforce_forward_transition"];
const MIGRATION_0028_TRIGGER_NAMES: &[&str] = &[
    "agent_todo_snapshots_validate_insert",
    "agent_todo_snapshots_reject_update",
    "agent_todo_snapshots_reject_delete",
    "agent_tool_calls_bind_todo_snapshot",
];
const MIGRATION_0029_TRIGGER_NAMES: &[&str] = &[
    "agent_goal_snapshots_reject_update",
    "agent_goal_snapshots_reject_delete",
    "agent_tool_calls_bind_goal_snapshot",
];
const MIGRATION_0030_TRIGGER_NAMES: &[&str] = &[
    "agent_goal_rounds_validate_insert",
    "agent_goal_rounds_reject_update",
    "agent_goal_rounds_reject_delete",
    "agent_goal_snapshots_validate_insert",
];
const MIGRATION_0031_TRIGGER_NAMES: &[&str] = &[
    "session_followups_validate_insert",
    "session_followups_enforce_transition",
    "session_followups_reject_delete",
    "session_followup_receipts_require_authority",
    "session_followup_receipts_reject_update",
    "session_followup_receipts_reject_delete",
];
const MIGRATION_0032_TRIGGER_NAMES: &[&str] = &[
    "agent_model_output_chunks_validate_insert",
    "agent_model_output_chunks_reject_update",
    "agent_model_output_chunks_reject_delete",
];
const RECOVERY_BATCH_LIMIT: i64 = 64;
const AUTH_SESSION_CLEANUP_BATCH_LIMIT: i64 = 64;
const BOOTSTRAP_AUDIT_ROLLUP_BATCH_LIMIT: i64 = 64;
const BOOTSTRAP_AUDIT_ZERO_DIGEST: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const ACCOUNT_AUDIT_ZERO_DIGEST: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const ACCOUNT_AUDIT_EVENT_DOMAIN: &[u8] = b"zeus.account-audit-event.v1\0";
const ACCOUNT_AUDIT_ROLLUP_DOMAIN: &[u8] = b"zeus.account-audit-rollup.v1\0";
const ACCOUNT_AUDIT_PAGE_MAX_LIMIT: usize = 256;
const ACCOUNT_MEMBER_PAGE_MAX_LIMIT: usize = 100;
const ACCOUNT_AUDIT_METADATA_MAX_BYTES: usize = 8 * 1024;
// A syntactically valid Argon2id record with a 16-byte salt and a deliberately
// unissued all-zero 32-byte output. No setup path accepts this sentinel as a
// new credential; pending members stay non-loginable while parsing remains
// indistinguishable from a normal supported record.
const PENDING_MEMBER_PASSWORD_HASH: &str = concat!(
    "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
);
const REPLY_JOB_ID_MAX_BYTES: usize = 384;
const REPLY_REQUEST_JSON_MAX_BYTES: usize = 512 * 1024;
const REPLY_RESPONSE_JSON_MAX_BYTES: usize = 512 * 1024;
const REPLY_ERROR_JSON_MAX_BYTES: usize = 32 * 1024;
const REPLY_AUTHORIZATION_REVOKED_REASON: &str =
    "reply authorization was revoked before provider execution";
const SESSION_FOLLOWUP_AUTHORIZATION_REVOKED_REASON: &str =
    "follow-up authorization was revoked before Agent admission";
const SESSION_FOLLOWUP_QUEUE_MAX: i64 = 32;
const DISPATCH_CALL_ID_MAX_BYTES: usize = 160;
const DISPATCH_IDENTIFIER_MAX_BYTES: usize = 128;
const DISPATCH_TOOL_NAME_MAX_BYTES: usize = 96;
const DISPATCH_TOOL_VERSION_MAX_BYTES: usize = 64;
const DISPATCH_ARGS_JSON_MAX_BYTES: usize = 64 * 1024;
const SESSION_FINALIZATION_BASE_BYTES: i64 = 512 * 1024;
const SESSION_FINALIZATION_TURN_ID_MULTIPLIER: i64 = 12;
const SESSION_FINALIZATION_PROVIDER_MULTIPLIER: i64 = 6;
const DISPATCH_QUEUED_FINALIZATION_BASE_BYTES: i64 = 96 * 1024;
const DISPATCH_QUEUED_CALL_ID_MULTIPLIER: i64 = 12;
const DISPATCH_TERMINAL_FINALIZATION_BASE_BYTES: i64 = 64 * 1024;
const DISPATCH_TERMINAL_CALL_ID_MULTIPLIER: i64 = 6;

#[derive(Debug)]
struct EncodedEventPayload {
    json: String,
    bytes: i64,
}

#[derive(Clone, Copy, Debug)]
struct EventCapacityRequest {
    new_event_slots: usize,
    new_event_payload_bytes: i64,
    new_reserved_slots: usize,
    new_reserved_payload_bytes: i64,
}

impl EventCapacityRequest {
    fn events(new_event_slots: usize, new_event_payload_bytes: i64) -> Self {
        Self {
            new_event_slots,
            new_event_payload_bytes,
            new_reserved_slots: 0,
            new_reserved_payload_bytes: 0,
        }
    }
}

#[derive(Clone)]
pub struct SqliteStore {
    backend: Backend,
    limits: StorageLimits,
    physical_limits: SqlitePhysicalLimits,
    operation_limits: SqliteOperationLimits,
    operation_limiter: Arc<OperationLimiter>,
}

#[derive(Clone)]
enum Backend {
    File(Arc<FileBackend>),
    Memory(Arc<Mutex<Connection>>),
}

struct FileBackend {
    path: PathBuf,
    physical_limits: SqlitePhysicalLimits,
    // Dropping the final backend clone releases the process-wide lease.
    _lock_file: File,
}

impl SqliteStore {
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        Self::open_with_limits_and_physical_and_operations(
            path,
            StorageLimits::default(),
            SqlitePhysicalLimits::default(),
            SqliteOperationLimits::default(),
        )
        .await
    }

    pub async fn open_with_limits(
        path: impl AsRef<Path>,
        limits: StorageLimits,
    ) -> Result<Self, StorageError> {
        Self::open_with_limits_and_physical_and_operations(
            path,
            limits,
            SqlitePhysicalLimits::default(),
            SqliteOperationLimits::default(),
        )
        .await
    }

    pub async fn open_with_limits_and_physical(
        path: impl AsRef<Path>,
        limits: StorageLimits,
        physical_limits: SqlitePhysicalLimits,
    ) -> Result<Self, StorageError> {
        Self::open_with_limits_and_physical_and_operations(
            path,
            limits,
            physical_limits,
            SqliteOperationLimits::default(),
        )
        .await
    }

    /// Opens a store with explicit logical, physical, and blocking-operation
    /// capacity policy. Existing constructors retain the supported defaults.
    pub async fn open_with_limits_and_physical_and_operations(
        path: impl AsRef<Path>,
        limits: StorageLimits,
        physical_limits: SqlitePhysicalLimits,
        operation_limits: SqliteOperationLimits,
    ) -> Result<Self, StorageError> {
        limits.validate()?;
        physical_limits.validate()?;
        operation_limits.validate()?;
        let operation_limiter = Arc::new(OperationLimiter::new(&operation_limits));
        let path = path.as_ref().to_path_buf();
        if path == Path::new(":memory:") {
            let migration_limits = limits.clone();
            let permits = operation_limiter
                .acquire(OperationClass::General, true)
                .await?;
            #[cfg(test)]
            let task_limiter = Arc::clone(&operation_limiter);
            let connection = tokio::task::spawn_blocking(move || {
                #[cfg(test)]
                let _task_guard = task_limiter.blocking_task_guard();
                let result = (|| {
                    let mut connection = Connection::open_in_memory()?;
                    configure_connection(&connection, false, None)?;
                    migrate(&mut connection, &migration_limits)?;
                    cleanup_unusable_auth_sessions(&mut connection, &now())?;
                    deep_readiness(&connection, false, None)?;
                    Ok::<_, StorageError>(connection)
                })();
                drop(permits);
                result
            })
            .await??;
            Ok(Self {
                backend: Backend::Memory(Arc::new(Mutex::new(connection))),
                limits,
                physical_limits,
                operation_limits,
                operation_limiter,
            })
        } else {
            let backend_physical_limits = physical_limits.clone();
            let migration_limits = limits.clone();
            let permits = operation_limiter
                .acquire(OperationClass::General, false)
                .await?;
            #[cfg(test)]
            let task_limiter = Arc::clone(&operation_limiter);
            let backend = tokio::task::spawn_blocking(move || {
                #[cfg(test)]
                let _task_guard = task_limiter.blocking_task_guard();
                let result = (|| {
                    let path = normalized_file_path(&path)?;
                    let lock_file = acquire_database_lock(&path)?;
                    let mut connection = open_file_connection(&path, &backend_physical_limits)?;
                    let schema_version = current_schema_version(&connection)?;
                    let bootstrap_audit_compaction_required = schema_version
                        == CURRENT_SCHEMA_VERSION
                        && bootstrap_audit_retention_required(&connection, &migration_limits)?;
                    if schema_version < CURRENT_SCHEMA_VERSION
                        || bootstrap_audit_compaction_required
                    {
                        require_physical_capacity(
                            &connection,
                            &path,
                            &backend_physical_limits,
                            PhysicalCapacityGate::Migration,
                        )?;
                    }
                    migrate(&mut connection, &migration_limits)?;
                    require_physical_capacity(
                        &connection,
                        &path,
                        &backend_physical_limits,
                        PhysicalCapacityGate::Finalization,
                    )?;
                    cleanup_unusable_auth_sessions(&mut connection, &now())?;
                    checkpoint_wal(&connection)?;
                    deep_readiness(&connection, true, Some(&backend_physical_limits))?;
                    Ok::<_, StorageError>(FileBackend {
                        path,
                        physical_limits: backend_physical_limits,
                        _lock_file: lock_file,
                    })
                })();
                drop(permits);
                result
            })
            .await??;
            Ok(Self {
                backend: Backend::File(Arc::new(backend)),
                limits,
                physical_limits,
                operation_limits,
                operation_limiter,
            })
        }
    }

    pub fn limits(&self) -> &StorageLimits {
        &self.limits
    }

    pub fn physical_limits(&self) -> &SqlitePhysicalLimits {
        &self.physical_limits
    }

    pub fn operation_limits(&self) -> &SqliteOperationLimits {
        &self.operation_limits
    }

    #[cfg(test)]
    pub(crate) async fn physical_pragma_snapshot(
        &self,
    ) -> Result<(u64, u64, u64, i64, i64), StorageError> {
        self.with_connection(|connection| {
            Ok((
                pragma_positive_u64(connection, "max_page_count")?,
                pragma_positive_u64(connection, "wal_autocheckpoint")?,
                pragma_non_negative_u64(connection, "journal_size_limit")?,
                connection.pragma_query_value(None, "cache_size", |row| row.get(0))?,
                connection.pragma_query_value(None, "mmap_size", |row| row.get(0))?,
            ))
        })
        .await
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
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            bind_runtime_identity(connection, identity, &physical_limits)
        })
        .await
    }

    /// Seeds the database only when it has no runs. Existing state is never
    /// overwritten, including after a process restart.
    pub async fn seed_if_empty(
        &self,
        snapshot: RunSnapshot,
        events: Vec<RunEvent>,
    ) -> Result<bool, StorageError> {
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            seed_if_empty(connection, snapshot, events, &limits, &physical_limits)
        })
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
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            seed_demo_session(
                connection,
                &session_id,
                &title,
                &run_id,
                &limits,
                &physical_limits,
            )
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
        context: &AuthzContext,
    ) -> Result<Vec<SessionSummary>, StorageError> {
        let context = validated_authz_context(context)?;
        self.with_connection(move |connection| {
            query_session_summaries_for_actor(connection, &context)
        })
        .await
    }

    /// Returns one actor-scoped keyset page while keeping the public JSON body
    /// compatible with the historical bare Session-summary array.
    pub async fn session_summary_page_for_actor(
        &self,
        context: &AuthzContext,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<SessionSummaryPage, StorageError> {
        let context = validated_authz_context(context)?;
        let cursor = cursor.map(str::to_owned);
        self.with_connection(move |connection| {
            query_session_summary_page_for_actor(connection, &context, cursor.as_deref(), limit)
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
        context: &AuthzContext,
        session_id: &str,
    ) -> Result<SessionDetail, StorageError> {
        let context = validated_authz_context(context)?;
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        self.with_connection(move |connection| {
            query_session_detail_for_actor(connection, &context, &session_id)
        })
        .await
    }

    /// Returns bounded latest-first history slices, normalized back to the
    /// ascending collection order used by the original Session detail shape.
    /// Authorization, projection checks, and every page are read from one
    /// SQLite snapshot.
    #[allow(clippy::too_many_arguments)]
    pub async fn session_detail_page_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        run_ids_before: Option<&str>,
        run_ids_limit: usize,
        turns_before: Option<&str>,
        turns_limit: usize,
        events_before: Option<&str>,
        events_limit: usize,
    ) -> Result<SessionDetail, StorageError> {
        let context = validated_authz_context(context)?;
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let run_ids_before = run_ids_before.map(str::to_owned);
        let turns_before = turns_before.map(str::to_owned);
        let events_before = events_before.map(str::to_owned);
        self.with_connection(move |connection| {
            query_session_detail_page_for_actor(
                connection,
                &context,
                &session_id,
                run_ids_before.as_deref(),
                run_ids_limit,
                turns_before.as_deref(),
                turns_limit,
                events_before.as_deref(),
                events_limit,
            )
        })
        .await
    }

    /// Returns one durable Session turn after authorizing its parent Session.
    /// The parent authorization and point lookup share one SQLite snapshot so
    /// an unknown turn cannot reveal a foreign Session.
    pub async fn session_turn_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        turn_id: &str,
    ) -> Result<SessionTurn, StorageError> {
        let context = validated_authz_context(context)?;
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        // Durable references intentionally have no new-write byte ceiling so
        // pre-envelope turn IDs remain addressable.
        let turn_id = turn_id.to_owned();
        self.with_connection(move |connection| {
            query_session_turn_for_actor(connection, &context, &session_id, &turn_id)
        })
        .await
    }

    /// Returns the newest complete conversation turns visible at an immutable
    /// Session ledger boundary.
    ///
    /// `through_sequence` is the caller's pre-command `expected_sequence`.
    /// Reading against that historical boundary lets an idempotent retry
    /// rebuild the exact same provider request after the original turn has
    /// already advanced the live Session head.
    pub async fn session_reply_turns_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        through_sequence: u64,
        limit: usize,
    ) -> Result<Vec<SessionTurn>, StorageError> {
        let context = validated_authz_context(context)?;
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        self.with_connection(move |connection| {
            query_session_reply_turns_for_actor(
                connection,
                &context,
                &session_id,
                through_sequence,
                limit,
            )
        })
        .await
    }

    /// Returns only complete turns strictly after a succeeded compaction source
    /// boundary and at or before the caller's immutable pre-command boundary.
    pub async fn session_reply_turns_after_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        after_sequence: u64,
        through_sequence: u64,
        limit: usize,
    ) -> Result<Vec<SessionTurn>, StorageError> {
        let context = validated_authz_context(context)?;
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        self.with_connection(move |connection| {
            query_session_reply_turns_after_for_actor(
                connection,
                &context,
                &session_id,
                after_sequence,
                through_sequence,
                limit,
            )
        })
        .await
    }

    /// Worker-only bounded history read. The caller supplies a durable account
    /// binding; Goal-round admission later rechecks the captured membership in
    /// the same write transaction.
    pub async fn session_reply_turns_after_for_runtime(
        &self,
        account_id: &AccountId,
        session_id: &str,
        after_sequence: u64,
        through_sequence: u64,
        limit: usize,
    ) -> Result<Vec<SessionTurn>, StorageError> {
        let account_id = account_id.clone();
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        self.with_connection(move |connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
            require_session_account(&transaction, &session_id, &account_id)?;
            let session = query_session_summary(&transaction, &session_id)?;
            validate_session_event_tail(&transaction, &session)?;
            validate_active_turn_projection(&transaction, &session)?;
            if after_sequence > through_sequence || through_sequence > session.sequence {
                return Err(StorageError::ConcurrentModification);
            }
            let turns = query_session_reply_turns_after(
                &transaction,
                &session_id,
                after_sequence,
                through_sequence,
                limit,
            )?;
            transaction.commit()?;
            Ok(turns)
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

    /// Durable-worker point read that may use the reserved progress lane.
    /// Public/API summary reads must continue to use [`Self::session_summary`]
    /// or the actor-scoped general-admission variant.
    pub async fn session_summary_for_progress(
        &self,
        session_id: &str,
    ) -> Result<SessionSummary, StorageError> {
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        self.with_progress_connection(move |connection| {
            query_consistent_session_summary(connection, &session_id)
        })
        .await
    }

    pub async fn session_summary_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
    ) -> Result<SessionSummary, StorageError> {
        let context = validated_authz_context(context)?;
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        self.with_connection(move |connection| {
            query_consistent_session_summary_for_actor(connection, &context, &session_id)
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
        context: &AuthzContext,
        session_id: &str,
        after: u64,
    ) -> Result<Vec<SessionEvent>, StorageError> {
        let context = validated_authz_context(context)?;
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        self.with_connection(move |connection| {
            query_session_events_after_for_actor(connection, &context, &session_id, after)
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
        context: &AuthzContext,
        session_id: &str,
        after: u64,
        limit: usize,
    ) -> Result<SessionEventPage, StorageError> {
        let context = validated_authz_context(context)?;
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        self.with_connection(move |connection| {
            query_session_event_page_for_actor(connection, &context, &session_id, after, limit)
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
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            create_session(connection, request, &key, None, &limits, &physical_limits)
        })
        .await
    }

    /// Creates a session owned by the authenticated actor and stores the
    /// idempotency receipt in that actor's scope.
    pub async fn create_session_for_actor(
        &self,
        context: &AuthzContext,
        request: CreateSessionRequest,
        idempotency_key: &str,
    ) -> Result<CreateSessionResponse, StorageError> {
        let context = validated_authz_context(context)?;
        let key = normalized_key(idempotency_key)?.to_owned();
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            create_session(
                connection,
                request,
                &key,
                Some(&context),
                &limits,
                &physical_limits,
            )
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
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            attach_run(
                connection,
                &session_id,
                request,
                &key,
                None,
                &limits,
                &physical_limits,
            )
        })
        .await
    }

    pub async fn attach_run_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        request: AttachRunRequest,
        idempotency_key: &str,
    ) -> Result<AttachRunResponse, StorageError> {
        let context = validated_authz_context(context)?;
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let key = normalized_key(idempotency_key)?.to_owned();
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            attach_run(
                connection,
                &session_id,
                request,
                &key,
                Some(&context),
                &limits,
                &physical_limits,
            )
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
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            start_turn(
                connection,
                &session_id,
                request,
                &key,
                StartTurnOptions {
                    authz: None,
                    reply_job: None,
                    agent_turn: None,
                    goal_round: None,
                    followup: None,
                    limits: &limits,
                    physical_limits: &physical_limits,
                    fail_after_enqueue: false,
                },
            )
            .map(|outcome| outcome.start)
        })
        .await
    }

    pub async fn start_turn_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        request: StartTurnRequest,
        idempotency_key: &str,
    ) -> Result<StartTurnResponse, StorageError> {
        let context = validated_authz_context(context)?;
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let key = normalized_key(idempotency_key)?.to_owned();
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            start_turn(
                connection,
                &session_id,
                request,
                &key,
                StartTurnOptions {
                    authz: Some(&context),
                    reply_job: None,
                    agent_turn: None,
                    goal_round: None,
                    followup: None,
                    limits: &limits,
                    physical_limits: &physical_limits,
                    fail_after_enqueue: false,
                },
            )
            .map(|outcome| outcome.start)
        })
        .await
    }

    /// Atomically persists the user turn and its provider work item.
    ///
    /// Replaying the same idempotency key returns the original turn and queue
    /// record. Changing the client turn request or stable provider/job identity
    /// is an idempotency conflict; regenerated server context never replaces
    /// the first durable `request_json`.
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
        let context = job.authz.clone();
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            start_turn(
                connection,
                &session_id,
                request,
                &key,
                StartTurnOptions {
                    authz: Some(&context),
                    reply_job: Some(job),
                    agent_turn: None,
                    goal_round: None,
                    followup: None,
                    limits: &limits,
                    physical_limits: &physical_limits,
                    fail_after_enqueue: false,
                },
            )
            .and_then(|outcome| {
                outcome
                    .reply_job
                    .map(|job| ReplyJobEnqueueResponse {
                        start: outcome.start,
                        job,
                    })
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
        context: &AuthzContext,
        session_id: &str,
        request: StartTurnRequest,
        idempotency_key: &str,
        job: ReplyJobSpec,
    ) -> Result<ReplyJobEnqueueResponse, StorageError> {
        let context = validated_authz_context(context)?;
        if job.authz != context {
            return Err(StorageError::SessionNotFound(session_id.to_owned()));
        }
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let key = normalized_key(idempotency_key)?.to_owned();
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            start_turn(
                connection,
                &session_id,
                request,
                &key,
                StartTurnOptions {
                    authz: Some(&context),
                    reply_job: Some(job),
                    agent_turn: None,
                    goal_round: None,
                    followup: None,
                    limits: &limits,
                    physical_limits: &physical_limits,
                    fail_after_enqueue: false,
                },
            )
            .and_then(|outcome| {
                outcome
                    .reply_job
                    .map(|job| ReplyJobEnqueueResponse {
                        start: outcome.start,
                        job,
                    })
                    .ok_or_else(|| {
                        StorageError::CorruptData(
                            "reply enqueue committed without a queue record".into(),
                        )
                    })
            })
        })
        .await
    }

    /// Resolve an exact Agent start replay before rebuilding server-derived
    /// history, knowledge selection, or provider request bytes.
    pub async fn agent_start_receipt_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        request: &StartTurnRequest,
        idempotency_key: &str,
        probe: &AgentTurnReceiptProbe,
    ) -> Result<Option<AgentTurnEnqueueResponse>, StorageError> {
        let context = validated_authz_context(context)?;
        if probe.authz != context {
            return Err(StorageError::SessionNotFound(session_id.to_owned()));
        }
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let key = normalized_key(idempotency_key)?.to_owned();
        let request = request.clone();
        let probe = probe.clone();
        self.with_connection(move |connection| {
            load_agent_start_receipt_for_actor(
                connection,
                &context,
                &session_id,
                &request,
                &key,
                &probe,
            )
        })
        .await
    }

    /// Atomically persists a user turn, its Session-native agent state, and
    /// the immutable first model request. Provider execution cannot begin
    /// until the model job is claimed and its `started` checkpoint commits.
    pub async fn start_turn_and_enqueue_agent_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        request: StartTurnRequest,
        idempotency_key: &str,
        agent: AgentTurnSpec,
    ) -> Result<AgentTurnEnqueueResponse, StorageError> {
        let context = validated_authz_context(context)?;
        if agent.authz != context {
            return Err(StorageError::SessionNotFound(session_id.to_owned()));
        }
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let key = normalized_key(idempotency_key)?.to_owned();
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            start_turn(
                connection,
                &session_id,
                request,
                &key,
                StartTurnOptions {
                    authz: Some(&context),
                    reply_job: None,
                    agent_turn: Some(agent),
                    goal_round: None,
                    followup: None,
                    limits: &limits,
                    physical_limits: &physical_limits,
                    fail_after_enqueue: false,
                },
            )
            .and_then(|outcome| {
                outcome
                    .agent_work
                    .map(|(agent, job)| AgentTurnEnqueueResponse {
                        start: outcome.start,
                        agent,
                        job,
                    })
                    .ok_or_else(|| {
                        StorageError::CorruptData(
                            "agent enqueue committed without durable work".into(),
                        )
                    })
            })
        })
        .await
    }

    /// Atomically admits one process-authorized Goal round as a real Session
    /// turn and Agent. The stored membership revision is revalidated without
    /// depending on the browser login session that originally armed the Goal.
    pub async fn start_goal_round_and_enqueue_agent(
        &self,
        session_id: &str,
        request: StartTurnRequest,
        idempotency_key: &str,
        agent: AgentTurnSpec,
        goal_round: AgentGoalRoundSpec,
    ) -> Result<AgentTurnEnqueueResponse, StorageError> {
        let context = validated_authz_context(&agent.authz)?;
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let key = normalized_key(idempotency_key)?.to_owned();
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            start_turn(
                connection,
                &session_id,
                request,
                &key,
                StartTurnOptions {
                    authz: Some(&context),
                    reply_job: None,
                    agent_turn: Some(agent),
                    goal_round: Some(goal_round),
                    followup: None,
                    limits: &limits,
                    physical_limits: &physical_limits,
                    fail_after_enqueue: false,
                },
            )
            .and_then(|outcome| {
                outcome
                    .agent_work
                    .map(|(agent, job)| AgentTurnEnqueueResponse {
                        start: outcome.start,
                        agent,
                        job,
                    })
                    .ok_or_else(|| {
                        StorageError::CorruptData(
                            "Goal round admission committed without durable Agent work".into(),
                        )
                    })
            })
        })
        .await
    }

    /// Durably enqueue one ordinary user follow-up without changing the
    /// Session event sequence. The inbox itself is the acknowledgement.
    pub async fn enqueue_session_followup_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        request: EnqueueSessionFollowupRequest,
        idempotency_key: &str,
    ) -> Result<EnqueueSessionFollowupResponse, StorageError> {
        let context = validated_authz_context(context)?;
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let key = normalized_key(idempotency_key)?.to_owned();
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            enqueue_session_followup(
                connection,
                &context,
                &session_id,
                request,
                &key,
                &limits,
                &physical_limits,
            )
        })
        .await
    }

    pub async fn session_followups_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
    ) -> Result<Vec<SessionFollowup>, StorageError> {
        let context = validated_authz_context(context)?;
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        self.with_connection(move |connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
            require_current_authority(&transaction, &context, AccountCapability::Read)?;
            require_active_session_actor(&transaction, &session_id, &context)?;
            let items = query_session_followups(&transaction, &session_id)?;
            transaction.commit()?;
            Ok(items)
        })
        .await
    }

    /// Captures the exact active turn and follow-up prefix admitted before a
    /// Session flush barrier. SQLite commits are already synchronous; this
    /// snapshot gives the caller a stable boundary to wait through without
    /// later work extending the wait forever.
    pub async fn capture_session_flush_barrier_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
    ) -> Result<SessionFlushBarrier, StorageError> {
        let context = validated_authz_context(context)?;
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        self.with_connection(move |connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
            require_current_authority(&transaction, &context, AccountCapability::Read)?;
            require_active_session_actor(&transaction, &session_id, &context)?;
            let barrier = capture_session_flush_barrier(&transaction, &session_id)?;
            transaction.commit()?;
            Ok(barrier)
        })
        .await
    }

    /// Revalidates authority and observes one previously captured barrier.
    /// The immutable boundary, rather than the Session's current head, decides
    /// which work must settle.
    pub async fn observe_session_flush_barrier_for_actor(
        &self,
        context: &AuthzContext,
        barrier: SessionFlushBarrier,
    ) -> Result<SessionFlushBarrier, StorageError> {
        let context = validated_authz_context(context)?;
        let session_id = validated_durable_reference(&barrier.session_id, "session ID")?.to_owned();
        if let Some(turn_id) = barrier.active_turn_id.as_deref() {
            validated_durable_reference(turn_id, "turn ID")?;
        }
        self.with_connection(move |connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
            require_current_authority(&transaction, &context, AccountCapability::Read)?;
            require_active_session_actor(&transaction, &session_id, &context)?;
            let observed = observe_session_flush_barrier(&transaction, barrier)?;
            transaction.commit()?;
            Ok(observed)
        })
        .await
    }

    /// Returns the oldest executable follow-up. Revoked authority is
    /// terminalized in FIFO order so it cannot poison the queue forever.
    pub async fn next_session_followup_candidate(
        &self,
    ) -> Result<Option<SessionFollowupCandidate>, StorageError> {
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            query_next_session_followup_candidate(connection, &physical_limits)
        })
        .await
    }

    /// Converts the exact first queued follow-up into a normal Session turn
    /// and immutable initial Agent model job in one SQLite transaction.
    pub async fn start_followup_and_enqueue_agent(
        &self,
        candidate: SessionFollowupCandidate,
        agent: AgentTurnSpec,
    ) -> Result<AgentTurnEnqueueResponse, StorageError> {
        let context = validated_authz_context(&candidate.authz)?;
        if agent.authz != context {
            return Err(StorageError::SessionNotFound(candidate.session.id.clone()));
        }
        let session_id =
            validated_durable_reference(&candidate.session.id, "session ID")?.to_owned();
        let followup = candidate.followup;
        let request = StartTurnRequest {
            turn_id: followup.turn_id.clone(),
            user_message: followup.user_message.clone(),
            expected_sequence: candidate.session.sequence,
        };
        let key = format!("followup-{}", followup.turn_id);
        normalized_key(&key)?;
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            start_turn(
                connection,
                &session_id,
                request,
                &key,
                StartTurnOptions {
                    authz: Some(&context),
                    reply_job: None,
                    agent_turn: Some(agent),
                    goal_round: None,
                    followup: Some(followup),
                    limits: &limits,
                    physical_limits: &physical_limits,
                    fail_after_enqueue: false,
                },
            )
            .and_then(|outcome| {
                outcome
                    .agent_work
                    .map(|(agent, job)| AgentTurnEnqueueResponse {
                        start: outcome.start,
                        agent,
                        job,
                    })
                    .ok_or_else(|| {
                        StorageError::CorruptData(
                            "follow-up admission committed without durable Agent work".into(),
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

    /// Atomically revalidates the current login authority and returns the job
    /// only when it belongs to the same account. Foreign jobs are concealed as
    /// absent from the same SQLite snapshot.
    pub async fn reply_job_for_actor(
        &self,
        context: &AuthzContext,
        job_id: &str,
    ) -> Result<Option<ReplyJob>, StorageError> {
        let context = validated_authz_context(context)?;
        let job_id = normalized_reply_value(job_id, "reply job ID")?.to_owned();
        self.with_connection(move |connection| {
            query_reply_job_for_actor(connection, &context, &job_id)
        })
        .await
    }

    /// Claims at most one queued reply. The committed `started` transition is
    /// the authorization boundary for provider execution.
    ///
    /// This compatibility operation deliberately does not replay a committed
    /// start. Production workers that retry transient storage errors must use
    /// [`Self::peek_next_reply`] and [`Self::start_observed_reply`] so the
    /// exact job ID remains fixed across an ambiguous commit acknowledgement.
    pub async fn claim_next_reply(&self) -> Result<ReplyClaimOutcome, StorageError> {
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            claim_next_reply(connection, &physical_limits)
        })
        .await
    }

    /// Observes the stable head of the queued reply set without changing any
    /// durable state. A worker retains this job ID while it retries the exact
    /// start operation.
    pub async fn peek_next_reply(&self) -> Result<Option<ReplyJob>, StorageError> {
        self.with_progress_connection(|connection| peek_next_reply(connection))
            .await
    }

    /// Starts the exact reply previously returned by [`Self::peek_next_reply`].
    ///
    /// A `started` record is returned again only to resolve an ambiguous
    /// acknowledgement in the same in-memory execution context. Once this
    /// method returns `Claimed`, that context must invoke provider I/O at most
    /// once and must never call this method again for the job.
    pub async fn start_observed_reply(
        &self,
        job_id: &str,
    ) -> Result<ReplyClaimOutcome, StorageError> {
        let job_id = normalized_reply_value(job_id, "reply job ID")?.to_owned();
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            start_observed_reply(connection, &job_id, &physical_limits)
        })
        .await
    }

    /// Commits provider output, assistant/flush ledger events, and the ready
    /// session projection in one transaction.
    pub async fn complete_reply_success(
        &self,
        commit: ReplySuccessCommit,
    ) -> Result<ReplyCompletion, StorageError> {
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            complete_reply_success(connection, commit, &physical_limits, false)
        })
        .await
    }

    /// Commits a terminal provider failure together with interruption evidence.
    pub async fn complete_reply_failure(
        &self,
        commit: ReplyFailureCommit,
    ) -> Result<ReplyCompletion, StorageError> {
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            complete_reply_failure(connection, commit, &physical_limits)
        })
        .await
    }

    /// Commits an indeterminate provider outcome together with interruption
    /// evidence. This terminal state must never be retried automatically.
    pub async fn complete_reply_outcome_unknown(
        &self,
        commit: ReplyOutcomeUnknownCommit,
    ) -> Result<ReplyCompletion, StorageError> {
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            complete_reply_outcome_unknown(connection, commit, &physical_limits)
        })
        .await
    }

    /// Converts one bounded batch of replies durably claimed by a previous
    /// process into `outcome_unknown`. Queued work remains claimable.
    pub async fn recover_started_replies(&self) -> Result<Vec<ReplyCompletion>, StorageError> {
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            recover_started_replies(connection, &physical_limits)
        })
        .await
    }

    /// Observe the stable head of the durable Session-compaction queue.
    pub async fn peek_next_session_compaction(
        &self,
    ) -> Result<Option<SessionCompactionJob>, StorageError> {
        self.with_progress_connection(|connection| compaction::peek_next(connection))
            .await
    }

    /// Commit the exact `started` checkpoint for one observed compaction job.
    pub async fn start_observed_session_compaction(
        &self,
        job_id: &str,
    ) -> Result<SessionCompactionClaimOutcome, StorageError> {
        let job_id = normalized_reply_value(job_id, "Session compaction job ID")?.to_owned();
        self.with_progress_connection(move |connection| {
            compaction::start_observed(connection, &job_id)
        })
        .await
    }

    /// Persist a validated model summary as the latest immutable checkpoint.
    pub async fn complete_session_compaction_success(
        &self,
        commit: SessionCompactionSuccessCommit,
    ) -> Result<SessionCompactionJob, StorageError> {
        self.with_progress_connection(move |connection| {
            compaction::complete_success(connection, commit)
        })
        .await
    }

    /// Terminalize a known failure or indeterminate post-start provider result.
    pub async fn complete_session_compaction_failure(
        &self,
        commit: SessionCompactionFailureCommit,
    ) -> Result<SessionCompactionJob, StorageError> {
        self.with_progress_connection(move |connection| {
            compaction::complete_failure(connection, commit)
        })
        .await
    }

    /// Convert one bounded batch of process-orphaned started compactions to
    /// `outcome_unknown`; queued jobs remain safe to execute.
    pub async fn recover_started_session_compactions(
        &self,
    ) -> Result<Vec<SessionCompactionJob>, StorageError> {
        self.with_progress_connection(compaction::recover_started)
            .await
    }

    /// Return the latest succeeded checkpoint visible at an authenticated
    /// historical Session boundary.
    pub async fn session_context_checkpoint_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        through_sequence: u64,
    ) -> Result<Option<SessionContextCheckpoint>, StorageError> {
        let context = validated_authz_context(context)?;
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        self.with_connection(move |connection| {
            compaction::checkpoint_for_actor(connection, &context, &session_id, through_sequence)
        })
        .await
    }

    pub async fn session_context_checkpoint_for_runtime(
        &self,
        account_id: &AccountId,
        session_id: &str,
        through_sequence: u64,
    ) -> Result<Option<SessionContextCheckpoint>, StorageError> {
        let account_id = account_id.clone();
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        self.with_connection(move |connection| {
            require_session_account(connection, &session_id, &account_id)?;
            let session = query_session_summary(connection, &session_id)?;
            if through_sequence > session.sequence {
                return Err(StorageError::ConcurrentModification);
            }
            compaction::latest_checkpoint(connection, &session_id, through_sequence)
        })
        .await
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
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            flush_turn(
                connection,
                &session_id,
                request,
                &key,
                None,
                &physical_limits,
                false,
            )
        })
        .await
    }

    pub async fn flush_turn_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        request: FlushSessionRequest,
        idempotency_key: &str,
    ) -> Result<FlushSessionResponse, StorageError> {
        let context = validated_authz_context(context)?;
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let key = normalized_key(idempotency_key)?.to_owned();
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            flush_turn(
                connection,
                &session_id,
                request,
                &key,
                Some(&context),
                &physical_limits,
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
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            resume_session(
                connection,
                &session_id,
                request,
                &key,
                None,
                &limits,
                &physical_limits,
            )
        })
        .await
    }

    pub async fn resume_session_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        request: ResumeSessionRequest,
        idempotency_key: &str,
    ) -> Result<ResumeSessionResponse, StorageError> {
        let context = validated_authz_context(context)?;
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let key = normalized_key(idempotency_key)?.to_owned();
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            resume_session(
                connection,
                &session_id,
                request,
                &key,
                Some(&context),
                &limits,
                &physical_limits,
            )
        })
        .await
    }

    /// Closes one bounded batch of turns left open by a previous process.
    /// Recovery only appends `turn_interrupted`; it never manufactures a flush
    /// acknowledgement.
    pub async fn recover_open_turns(&self) -> Result<Vec<RecoveredSessionTurn>, StorageError> {
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            recover_open_turns(connection, &physical_limits)
        })
        .await
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
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            replace_bootstrap_token(
                connection,
                &token_hash,
                &expires_at,
                &limits,
                &physical_limits,
            )
        })
        .await
    }

    /// Atomically creates the first owner, consumes the bootstrap token, claims
    /// every legacy Alpha resource/receipt, and creates the first login session.
    pub async fn bootstrap_owner(
        &self,
        commit: BootstrapOwnerCommit,
    ) -> Result<(StoredUser, StoredPreferences), StorageError> {
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            bootstrap_owner(connection, commit, &limits, &physical_limits)
        })
        .await
    }

    pub async fn credential_for_username(
        &self,
        username: &str,
    ) -> Result<Option<StoredCredential>, StorageError> {
        self.credential_for_username_in_account(username, &AccountId::local())
            .await
    }

    pub async fn credential_for_username_in_account(
        &self,
        username: &str,
        account_id: &AccountId,
    ) -> Result<Option<StoredCredential>, StorageError> {
        let username = normalized_account_value(username, "username", 64)?.to_owned();
        let account_id = account_id.clone();
        self.with_connection(move |connection| {
            query_credential(connection, &username, account_id.as_str())
        })
        .await
    }

    pub async fn accounts_for_user(
        &self,
        context: &AuthzContext,
    ) -> Result<Vec<StoredAccount>, StorageError> {
        let context = validated_authz_context(context)?;
        self.with_connection(move |connection| {
            require_current_authority(connection, &context, AccountCapability::Read)?;
            query_accounts_for_user(connection, &context.user_id)
        })
        .await
    }

    pub async fn create_account(
        &self,
        context: &AuthzContext,
        commit: CreateAccountCommit,
    ) -> Result<CreateAccountResult, StorageError> {
        let context = validated_authz_context(context)?;
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            create_account(connection, &context, commit, &limits, &physical_limits)
        })
        .await
    }

    pub async fn create_auth_session(
        &self,
        commit: AuthSessionCommit,
    ) -> Result<AuthPrincipal, StorageError> {
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            create_auth_session(connection, commit, &limits, &physical_limits)
        })
        .await
    }

    pub async fn switch_auth_session(
        &self,
        commit: SwitchAuthSessionCommit,
    ) -> Result<SwitchAuthSessionResult, StorageError> {
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            switch_auth_session(connection, commit, &limits, &physical_limits)
        })
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
        context: &AuthzContext,
        session_token_hash: &str,
    ) -> Result<bool, StorageError> {
        let context = validated_authz_context(context)?;
        let session_token_hash =
            normalized_token_hash(session_token_hash, "session token hash")?.to_owned();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            require_current_authority(connection, &context, AccountCapability::Read)?;
            require_connection_physical_capacity(
                connection,
                &physical_limits,
                PhysicalCapacityGate::Finalization,
            )?;
            Ok(connection.execute(
                "DELETE FROM auth_sessions WHERE id = ?1 AND token_hash = ?2",
                params![context.auth_session_id.as_str(), session_token_hash],
            )? == 1)
        })
        .await
    }

    pub async fn preferences(
        &self,
        context: &AuthzContext,
    ) -> Result<StoredPreferences, StorageError> {
        let context = validated_authz_context(context)?;
        self.with_connection(move |connection| {
            require_current_authority(connection, &context, AccountCapability::Read)?;
            query_preferences(connection, &context.user_id)
        })
        .await
    }

    pub async fn update_preferences(
        &self,
        context: &AuthzContext,
        expected_revision: u64,
        theme: &str,
        preferred_model: Option<&str>,
    ) -> Result<StoredPreferences, StorageError> {
        let context = validated_authz_context(context)?;
        let theme = normalized_theme(theme)?.to_owned();
        let preferred_model = preferred_model
            .map(|model| normalized_account_value(model, "preferred model", 128).map(str::to_owned))
            .transpose()?;
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            update_preferences(
                connection,
                &context,
                expected_revision,
                &theme,
                preferred_model.as_deref(),
                &physical_limits,
            )
        })
        .await
    }

    pub async fn knowledge_catalog_for_admin(
        &self,
        context: &AuthzContext,
    ) -> Result<KnowledgeCatalogState, StorageError> {
        let context = validated_authz_context(context)?;
        self.with_connection(move |connection| {
            agent::query_account_knowledge_catalog_for_admin(connection, &context)
        })
        .await
    }

    pub async fn active_knowledge_corpus_for_actor(
        &self,
        context: &AuthzContext,
    ) -> Result<knowledge::CorpusRevisionEnvelope, StorageError> {
        let context = validated_authz_context(context)?;
        self.with_connection(move |connection| {
            agent::query_active_knowledge_corpus_for_actor(connection, &context)
        })
        .await
    }

    pub async fn active_knowledge_corpus_for_runtime(
        &self,
        account_id: &AccountId,
    ) -> Result<knowledge::CorpusRevisionEnvelope, StorageError> {
        let account_id = account_id.clone();
        self.with_connection(move |connection| {
            agent::query_active_knowledge_corpus_for_runtime(connection, &account_id)
        })
        .await
    }

    pub async fn knowledge_catalog_revision_for_admin(
        &self,
        context: &AuthzContext,
        revision: u64,
    ) -> Result<KnowledgeCatalogState, StorageError> {
        let context = validated_authz_context(context)?;
        self.with_connection(move |connection| {
            agent::query_account_knowledge_catalog_revision_for_admin(
                connection, &context, revision,
            )
        })
        .await
    }

    pub async fn knowledge_catalog_revisions_for_admin(
        &self,
        context: &AuthzContext,
        before_revision: Option<u64>,
        limit: usize,
    ) -> Result<KnowledgeCatalogRevisionPage, StorageError> {
        let context = validated_authz_context(context)?;
        self.with_connection(move |connection| {
            agent::query_account_knowledge_catalog_revisions_for_admin(
                connection,
                &context,
                before_revision,
                limit,
            )
        })
        .await
    }

    pub async fn replace_knowledge_catalog(
        &self,
        context: &AuthzContext,
        commit: KnowledgeCatalogCommit,
    ) -> Result<KnowledgeCatalogUpdateResult, StorageError> {
        let context = validated_authz_context(context)?;
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            agent::replace_account_knowledge_catalog(
                connection,
                &context,
                commit,
                &limits,
                &physical_limits,
            )
        })
        .await
    }

    pub async fn agent_prompt_for_admin(
        &self,
        context: &AuthzContext,
    ) -> Result<AgentPromptState, StorageError> {
        let context = validated_authz_context(context)?;
        self.with_connection(move |connection| {
            agent::query_account_agent_prompt_for_admin(connection, &context)
        })
        .await
    }

    pub async fn agent_prompt_revision_for_admin(
        &self,
        context: &AuthzContext,
        revision: u64,
    ) -> Result<AgentPromptState, StorageError> {
        let context = validated_authz_context(context)?;
        self.with_connection(move |connection| {
            agent::query_account_agent_prompt_revision_for_admin(connection, &context, revision)
        })
        .await
    }

    pub async fn agent_prompt_revisions_for_admin(
        &self,
        context: &AuthzContext,
        before_revision: Option<u64>,
        limit: usize,
    ) -> Result<AgentPromptRevisionPage, StorageError> {
        let context = validated_authz_context(context)?;
        self.with_connection(move |connection| {
            agent::query_account_agent_prompt_revisions_for_admin(
                connection,
                &context,
                before_revision,
                limit,
            )
        })
        .await
    }

    pub async fn active_agent_prompt_for_actor(
        &self,
        context: &AuthzContext,
    ) -> Result<AgentPromptState, StorageError> {
        let context = validated_authz_context(context)?;
        self.with_connection(move |connection| {
            agent::query_active_agent_prompt_for_actor(connection, &context)
        })
        .await
    }

    /// Trusted runtime read used to resolve the manifest checked again inside
    /// Agent admission/claim transactions. It intentionally has no actor
    /// parameter and must not be exposed directly as an HTTP authorization
    /// boundary.
    pub async fn active_agent_prompt_for_runtime(
        &self,
        account_id: &AccountId,
    ) -> Result<AgentPromptState, StorageError> {
        let account_id = account_id.clone();
        self.with_connection(move |connection| {
            agent::query_account_agent_prompt(connection, account_id.as_str())
        })
        .await
    }

    pub async fn replace_agent_prompt(
        &self,
        context: &AuthzContext,
        commit: AgentPromptCommit,
    ) -> Result<AgentPromptUpdateResult, StorageError> {
        let context = validated_authz_context(context)?;
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            agent::replace_account_agent_prompt(
                connection,
                &context,
                commit,
                &limits,
                &physical_limits,
            )
        })
        .await
    }

    /// Resolve the effective account provider after checking Reply authority.
    /// `startup_default` is used only for the implicit revision-zero state.
    pub async fn reply_provider_for_actor(
        &self,
        context: &AuthzContext,
        startup_default: AccountReplyProviderState,
    ) -> Result<AccountReplyProviderState, StorageError> {
        let context = validated_authz_context(context)?;
        provider::validate_startup_default(&context.account_id, &startup_default)?;
        self.with_connection(move |connection| {
            provider::query_account_reply_provider_for_actor(connection, &context, startup_default)
        })
        .await
    }

    /// Resolve provider selection for trusted worker manifest construction.
    pub async fn reply_provider_for_runtime(
        &self,
        account_id: &AccountId,
        startup_default: AccountReplyProviderState,
    ) -> Result<AccountReplyProviderState, StorageError> {
        provider::validate_startup_default(account_id, &startup_default)?;
        let account_id = account_id.clone();
        self.with_connection(move |connection| {
            provider::query_account_reply_provider(connection, &account_id, startup_default)
        })
        .await
    }

    pub async fn replace_reply_provider(
        &self,
        context: &AuthzContext,
        commit: AccountReplyProviderCommit,
    ) -> Result<AccountReplyProviderUpdateResult, StorageError> {
        let context = validated_authz_context(context)?;
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            provider::replace_account_reply_provider(
                connection,
                &context,
                commit,
                &limits,
                &physical_limits,
            )
        })
        .await
    }

    pub async fn get_member(
        &self,
        context: &AuthzContext,
        user_id: &str,
    ) -> Result<StoredMember, StorageError> {
        let context = validated_authz_context(context)?;
        let user_id = normalized_account_value(user_id, "member user ID", 128)?.to_owned();
        self.with_connection(move |connection| {
            query_member_for_admin(connection, &context, &user_id)
        })
        .await
    }

    pub async fn list_members(
        &self,
        context: &AuthzContext,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<StoredMemberPage, StorageError> {
        let context = validated_authz_context(context)?;
        let cursor = cursor.map(str::to_owned);
        self.with_connection(move |connection| {
            query_member_page(connection, &context, cursor.as_deref(), limit)
        })
        .await
    }

    pub async fn create_member(
        &self,
        context: &AuthzContext,
        commit: CreateMemberCommit,
    ) -> Result<CreateMemberResult, StorageError> {
        let context = validated_authz_context(context)?;
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            create_member(connection, &context, commit, &limits, &physical_limits)
        })
        .await
    }

    pub async fn rotate_member_setup_token(
        &self,
        context: &AuthzContext,
        commit: RotateMemberSetupTokenCommit,
    ) -> Result<RotateMemberSetupTokenResult, StorageError> {
        let context = validated_authz_context(context)?;
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            rotate_member_setup_token(connection, &context, commit, &limits, &physical_limits)
        })
        .await
    }

    pub async fn complete_member_setup(
        &self,
        commit: MemberSetupCommit,
    ) -> Result<MemberSetupResult, StorageError> {
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            complete_member_setup(connection, commit, &limits, &physical_limits)
        })
        .await
    }

    pub async fn transition_member(
        &self,
        context: &AuthzContext,
        commit: TransitionMemberCommit,
    ) -> Result<MemberTransitionResult, StorageError> {
        let context = validated_authz_context(context)?;
        let use_progress = commit.expected_status == StoredMembershipStatus::Active
            && commit.role == MembershipRole::Member
            && (commit.status == StoredMembershipStatus::Disabled
                || commit.expected_role == MembershipRole::Owner);
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        let operation = move |connection: &mut Connection| {
            transition_member(connection, &context, commit, &limits, &physical_limits)
        };
        if use_progress {
            self.with_progress_connection(operation).await
        } else {
            self.with_connection(operation).await
        }
    }

    pub async fn account_audit_state(
        &self,
        context: &AuthzContext,
    ) -> Result<AccountAuditState, StorageError> {
        let context = validated_authz_context(context)?;
        let limits = self.limits.clone();
        self.with_connection(move |connection| {
            require_current_authority(connection, &context, AccountCapability::AuditRead)?;
            query_account_audit_state(connection, context.account_id.as_str(), &limits)
        })
        .await
    }

    pub async fn list_account_audit_events(
        &self,
        context: &AuthzContext,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<AccountAuditPage, StorageError> {
        let context = validated_authz_context(context)?;
        let cursor = cursor.map(str::to_owned);
        let limits = self.limits.clone();
        self.with_connection(move |connection| {
            query_account_audit_page(connection, &context, cursor.as_deref(), limit, &limits)
        })
        .await
    }

    pub async fn update_account_audit_policy(
        &self,
        context: &AuthzContext,
        commit: UpdateAccountAuditPolicyCommit,
    ) -> Result<AccountAuditState, StorageError> {
        let context = validated_authz_context(context)?;
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            update_account_audit_policy(connection, &context, commit, &limits, &physical_limits)
        })
        .await
    }

    pub async fn checkpoint_account_audit_archive(
        &self,
        context: &AuthzContext,
        commit: AccountAuditCheckpointCommit,
    ) -> Result<AccountAuditState, StorageError> {
        let context = validated_authz_context(context)?;
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            checkpoint_account_audit_archive(
                connection,
                &context,
                commit,
                &limits,
                &physical_limits,
            )
        })
        .await
    }

    pub async fn readiness(&self) -> Result<(), StorageError> {
        let expects_wal = matches!(self.backend, Backend::File(_));
        let physical_limits = self.physical_limits.clone();
        let limits = self.limits.clone();
        self.with_connection(move |connection| {
            readiness(
                connection,
                expects_wal,
                expects_wal.then_some(&physical_limits),
                true,
                false,
                Some(&limits),
            )
        })
        .await
    }

    /// Runs the expensive business, ledger, FK, and SQLite integrity checks.
    /// The public readiness endpoint intentionally uses [`Self::readiness`]
    /// instead so probes remain independent of historical ledger size.
    pub async fn verify_integrity(&self) -> Result<(), StorageError> {
        let expects_wal = matches!(self.backend, Backend::File(_));
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
            deep_readiness(
                &transaction,
                expects_wal,
                expects_wal.then_some(&physical_limits),
            )?;
            transaction.commit()?;
            Ok(())
        })
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
        context: &AuthzContext,
        run_id: &str,
    ) -> Result<RunSnapshot, StorageError> {
        let context = validated_authz_context(context)?;
        let run_id = validated_durable_reference(run_id, "run ID")?.to_owned();
        self.with_connection(move |connection| {
            load_snapshot_for_actor(connection, &context, &run_id)
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

    /// Durable-worker projection point read that may use reserved operation
    /// capacity. Public/API reads remain on general admission.
    pub async fn consistent_snapshot_for_progress(
        &self,
        run_id: &str,
    ) -> Result<RunSnapshot, StorageError> {
        let run_id = validated_durable_reference(run_id, "run ID")?.to_owned();
        self.with_progress_connection(move |connection| {
            query_consistent_snapshot(connection, &run_id)
        })
        .await
    }

    pub async fn consistent_snapshot_for_actor(
        &self,
        context: &AuthzContext,
        run_id: &str,
    ) -> Result<RunSnapshot, StorageError> {
        let context = validated_authz_context(context)?;
        let run_id = validated_durable_reference(run_id, "run ID")?.to_owned();
        self.with_connection(move |connection| {
            query_consistent_snapshot_for_actor(connection, &context, &run_id)
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
        context: &AuthzContext,
        run_id: &str,
        approval_id: &str,
    ) -> Result<ReviewContext, StorageError> {
        let context = validated_authz_context(context)?;
        let run_id = validated_durable_reference(run_id, "run ID")?.to_owned();
        let approval_id = validated_durable_reference(approval_id, "approval ID")?.to_owned();
        self.with_connection(move |connection| {
            query_review_context_for_actor(connection, &context, &run_id, &approval_id)
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
        self.with_progress_connection(move |connection| {
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
        context: &AuthzContext,
        run_id: &str,
    ) -> Result<StoredRun, StorageError> {
        let context = validated_authz_context(context)?;
        let run_id = validated_durable_reference(run_id, "run ID")?.to_owned();
        self.with_connection(move |connection| load_run_for_actor(connection, &context, &run_id))
            .await
    }

    /// Returns one actor-scoped Run projection and one bounded event-history
    /// tail from the same SQLite read transaction.
    pub async fn bounded_run_for_actor(
        &self,
        context: &AuthzContext,
        run_id: &str,
        events_before: Option<&str>,
        events_limit: usize,
    ) -> Result<BoundedRunRead, StorageError> {
        let context = validated_authz_context(context)?;
        let run_id = validated_durable_reference(run_id, "run ID")?.to_owned();
        let events_before = events_before.map(str::to_owned);
        self.with_connection(move |connection| {
            query_bounded_run_for_actor(
                connection,
                &context,
                &run_id,
                events_before.as_deref(),
                events_limit,
            )
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
        context: &AuthzContext,
        run_id: &str,
        after: u64,
    ) -> Result<Vec<RunEvent>, StorageError> {
        let context = validated_authz_context(context)?;
        let run_id = validated_durable_reference(run_id, "run ID")?.to_owned();
        self.with_connection(move |connection| {
            events_after_for_actor(connection, &context, &run_id, after)
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
        context: &AuthzContext,
        run_id: &str,
        after: u64,
        limit: usize,
    ) -> Result<RunEventPage, StorageError> {
        let context = validated_authz_context(context)?;
        let run_id = validated_durable_reference(run_id, "run ID")?.to_owned();
        self.with_connection(move |connection| {
            query_run_event_page_for_actor(connection, &context, &run_id, after, limit)
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
        context: &AuthzContext,
        run_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<ReviewReceipt>, StorageError> {
        let context = validated_authz_context(context)?;
        let run_id = validated_durable_reference(run_id, "run ID")?.to_owned();
        let idempotency_key = normalized_key(idempotency_key)?.to_owned();
        self.with_connection(move |connection| {
            load_review_receipt_for_actor(connection, &context, &run_id, &idempotency_key)
        })
        .await
    }

    /// Atomically advances the run projection, appends the v1 event payload,
    /// and records the idempotency receipt. Business transition validation is
    /// intentionally owned by the runtime/kernel before this call.
    /// System/test-only legacy write. Authenticated paths must use
    /// [`Self::commit_review_for_actor`].
    pub async fn commit_review(&self, commit: ReviewCommit) -> Result<CommitOutcome, StorageError> {
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            commit_review(connection, commit, None, &limits, &physical_limits, false)
        })
        .await
    }

    pub async fn commit_review_for_actor(
        &self,
        context: &AuthzContext,
        commit: ReviewCommit,
    ) -> Result<CommitOutcome, StorageError> {
        let context = validated_authz_context(context)?;
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            commit_review(
                connection,
                commit,
                Some(&context),
                &limits,
                &physical_limits,
                false,
            )
        })
        .await
    }

    /// Returns a queued job without mutating it. Callers use this to build the
    /// projection/event supplied to [`Self::claim_next_dispatch`].
    pub async fn peek_next_dispatch(&self) -> Result<Option<DispatchJob>, StorageError> {
        self.with_progress_connection(peek_next_dispatch).await
    }

    pub async fn dispatch_job(&self, call_id: &str) -> Result<Option<DispatchJob>, StorageError> {
        let call_id = normalized_identifier(call_id, "call ID")?.to_owned();
        self.with_connection(move |connection| query_dispatch_job(connection, &call_id))
            .await
    }

    /// Returns one bounded startup-recovery batch ordered by durable start.
    pub async fn started_dispatches(&self) -> Result<Vec<DispatchJob>, StorageError> {
        self.with_progress_connection(query_started_dispatches)
            .await
    }

    /// Atomically claims the current queue head, appends the caller-computed
    /// dispatch-started event, and advances the run projection. No connector
    /// code runs while this transaction is open.
    pub async fn claim_next_dispatch(
        &self,
        commit: DispatchStartCommit,
    ) -> Result<ClaimOutcome, StorageError> {
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            claim_next_dispatch(connection, commit, &physical_limits, false)
        })
        .await
    }

    /// Atomically records a connector result, appends its v2 event, and
    /// advances the run projection.
    pub async fn complete_dispatch(
        &self,
        commit: DispatchCompleteCommit,
    ) -> Result<DispatchJob, StorageError> {
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            complete_dispatch(connection, commit, &physical_limits, false)
        })
        .await
    }

    /// Converts one previously-started call into a terminal
    /// `outcome_unknown` record. This method only writes recovery evidence; it
    /// never claims or executes a queued call.
    pub async fn recover_started(
        &self,
        commit: DispatchRecoveryCommit,
    ) -> Result<DispatchJob, StorageError> {
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            recover_started(connection, commit, &physical_limits)
        })
        .await
    }

    #[cfg(test)]
    pub(crate) async fn commit_review_with_failure(
        &self,
        context: &AuthzContext,
        commit: ReviewCommit,
    ) -> Result<CommitOutcome, StorageError> {
        let context = validated_authz_context(context)?;
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            commit_review(
                connection,
                commit,
                Some(&context),
                &limits,
                &physical_limits,
                true,
            )
        })
        .await
    }

    #[cfg(test)]
    pub(crate) async fn claim_next_dispatch_with_failure(
        &self,
        commit: DispatchStartCommit,
    ) -> Result<ClaimOutcome, StorageError> {
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            claim_next_dispatch(connection, commit, &physical_limits, true)
        })
        .await
    }

    #[cfg(test)]
    pub(crate) async fn complete_dispatch_with_failure(
        &self,
        commit: DispatchCompleteCommit,
    ) -> Result<DispatchJob, StorageError> {
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            complete_dispatch(connection, commit, &physical_limits, true)
        })
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
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            flush_turn(
                connection,
                &session_id,
                request,
                &key,
                None,
                &physical_limits,
                true,
            )
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
        let context = job.authz.clone();
        let limits = self.limits.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_connection(move |connection| {
            start_turn(
                connection,
                &session_id,
                request,
                &key,
                StartTurnOptions {
                    authz: Some(&context),
                    reply_job: Some(job),
                    agent_turn: None,
                    goal_round: None,
                    followup: None,
                    limits: &limits,
                    physical_limits: &physical_limits,
                    fail_after_enqueue: true,
                },
            )
            .and_then(|outcome| {
                outcome
                    .reply_job
                    .map(|job| ReplyJobEnqueueResponse {
                        start: outcome.start,
                        job,
                    })
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
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            complete_reply_success(connection, commit, &physical_limits, true)
        })
        .await
    }

    async fn with_connection<T, F>(&self, operation: F) -> Result<T, StorageError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, StorageError> + Send + 'static,
    {
        self.with_connection_class(OperationClass::General, operation)
            .await
    }

    async fn with_progress_connection<T, F>(&self, operation: F) -> Result<T, StorageError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, StorageError> + Send + 'static,
    {
        self.with_connection_class(OperationClass::DurableProgress, operation)
            .await
    }

    async fn with_connection_class<T, F>(
        &self,
        class: OperationClass,
        operation: F,
    ) -> Result<T, StorageError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, StorageError> + Send + 'static,
    {
        let is_memory = matches!(self.backend, Backend::Memory(_));
        let permits = self.operation_limiter.acquire(class, is_memory).await?;
        #[cfg(test)]
        let task_limiter = Arc::clone(&self.operation_limiter);
        match &self.backend {
            Backend::File(backend) => {
                let backend = Arc::clone(backend);
                tokio::task::spawn_blocking(move || {
                    #[cfg(test)]
                    let _task_guard = task_limiter.blocking_task_guard();
                    let result = (|| {
                        let mut connection =
                            open_file_connection(&backend.path, &backend.physical_limits)?;
                        operation(&mut connection)
                    })();
                    // The connection (including any busy wait or transaction)
                    // is dropped by the inner scope before operation capacity
                    // is returned. Aborting the async caller does not cancel
                    // this blocking closure or release its permits early.
                    drop(permits);
                    result
                })
                .await?
            }
            Backend::Memory(connection) => {
                let connection = Arc::clone(connection);
                tokio::task::spawn_blocking(move || {
                    #[cfg(test)]
                    let _task_guard = task_limiter.blocking_task_guard();
                    let result = (|| {
                        let mut connection = connection.lock().map_err(|_| {
                            StorageError::CorruptData("in-memory SQLite lock was poisoned".into())
                        })?;
                        operation(&mut connection)
                    })();
                    drop(permits);
                    result
                })
                .await?
            }
        }
    }

    #[cfg(test)]
    pub(crate) async fn test_general_operation<T, F>(&self, operation: F) -> Result<T, StorageError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, StorageError> + Send + 'static,
    {
        self.with_connection(operation).await
    }

    #[cfg(test)]
    pub(crate) async fn test_progress_operation<T, F>(
        &self,
        operation: F,
    ) -> Result<T, StorageError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, StorageError> + Send + 'static,
    {
        self.with_progress_connection(operation).await
    }

    #[cfg(test)]
    pub(crate) fn operation_test_snapshot(&self) -> (usize, usize) {
        self.operation_limiter.test_snapshot()
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

fn open_file_connection(
    path: &Path,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<Connection, StorageError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let connection = Connection::open(path)?;
    configure_connection(&connection, true, Some(physical_limits))?;
    Ok(connection)
}

fn configure_connection(
    connection: &Connection,
    enable_wal: bool,
    physical_limits: Option<&SqlitePhysicalLimits>,
) -> Result<(), StorageError> {
    connection.busy_timeout(BUSY_TIMEOUT)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    if enable_wal {
        connection.pragma_update(None, "journal_mode", "WAL")?;
    }
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "cache_size", -2048_i64)?;
    connection.pragma_update(None, "mmap_size", 0_i64)?;

    if let Some(physical_limits) = physical_limits {
        configure_physical_pragmas(connection, physical_limits)?;
    }

    let journal_mode: String =
        connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    let encoding: String = connection.pragma_query_value(None, "encoding", |row| row.get(0))?;
    let expected_journal = if enable_wal { "wal" } else { "memory" };
    if !journal_mode.eq_ignore_ascii_case(expected_journal) {
        return Err(StorageError::CorruptData(format!(
            "expected {expected_journal} journal mode, found `{journal_mode}`"
        )));
    }
    if !encoding.eq_ignore_ascii_case("UTF-8") {
        return Err(StorageError::CorruptData(format!(
            "expected UTF-8 database encoding, found `{encoding}`"
        )));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PhysicalCapacityGate {
    Migration,
    Admission,
    ReservedProgress,
    Finalization,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PhysicalCapacitySnapshot {
    main_bytes: u64,
    wal_bytes: u64,
    available_bytes: u64,
}

fn configure_physical_pragmas(
    connection: &Connection,
    limits: &SqlitePhysicalLimits,
) -> Result<(), StorageError> {
    let page_size = pragma_positive_u64(connection, "page_size")?;
    let page_count = pragma_non_negative_u64(connection, "page_count")?;
    let max_page_count = limits.max_main_bytes / page_size;
    if max_page_count == 0 || page_count > max_page_count {
        return Err(StorageError::PhysicalStorageExhausted);
    }
    let max_page_count = i64::try_from(max_page_count)
        .map_err(|_| StorageError::IntegerOutOfRange("SQLite max page count"))?;
    connection.pragma_update(None, "max_page_count", max_page_count)?;
    let configured_max_page_count = pragma_positive_u64(connection, "max_page_count")?;
    if configured_max_page_count != max_page_count as u64 {
        return Err(StorageError::CorruptData(format!(
            "expected SQLite max_page_count {max_page_count}, found {configured_max_page_count}"
        )));
    }

    const WAL_HEADER_BYTES: u64 = 32;
    const WAL_FRAME_HEADER_BYTES: u64 = 24;
    let frame_bytes = page_size
        .checked_add(WAL_FRAME_HEADER_BYTES)
        .ok_or(StorageError::IntegerOutOfRange("SQLite WAL frame size"))?;
    let wal_autocheckpoint = limits
        .wal_target_bytes
        .saturating_sub(WAL_HEADER_BYTES)
        .checked_div(frame_bytes)
        .unwrap_or(0)
        .max(1);
    let wal_autocheckpoint = i64::try_from(wal_autocheckpoint)
        .map_err(|_| StorageError::IntegerOutOfRange("SQLite WAL autocheckpoint"))?;
    let journal_size_limit = i64::try_from(limits.wal_target_bytes)
        .map_err(|_| StorageError::IntegerOutOfRange("SQLite journal size limit"))?;
    connection.pragma_update(None, "wal_autocheckpoint", wal_autocheckpoint)?;
    connection.pragma_update(None, "journal_size_limit", journal_size_limit)?;

    let configured_autocheckpoint = pragma_positive_u64(connection, "wal_autocheckpoint")?;
    let configured_journal_limit = pragma_non_negative_u64(connection, "journal_size_limit")?;
    if configured_autocheckpoint != wal_autocheckpoint as u64
        || configured_journal_limit != limits.wal_target_bytes
    {
        return Err(StorageError::CorruptData(
            "SQLite physical-capacity pragmas are not active".into(),
        ));
    }
    Ok(())
}

fn verify_physical_pragmas(
    connection: &Connection,
    limits: &SqlitePhysicalLimits,
) -> Result<(), StorageError> {
    let page_size = pragma_positive_u64(connection, "page_size")?;
    let expected_max_page_count = limits.max_main_bytes / page_size;
    const WAL_HEADER_BYTES: u64 = 32;
    const WAL_FRAME_HEADER_BYTES: u64 = 24;
    let frame_bytes = page_size
        .checked_add(WAL_FRAME_HEADER_BYTES)
        .ok_or(StorageError::IntegerOutOfRange("SQLite WAL frame size"))?;
    let expected_autocheckpoint = limits
        .wal_target_bytes
        .saturating_sub(WAL_HEADER_BYTES)
        .checked_div(frame_bytes)
        .unwrap_or(0)
        .max(1);
    let actual_max_page_count = pragma_positive_u64(connection, "max_page_count")?;
    let actual_autocheckpoint = pragma_positive_u64(connection, "wal_autocheckpoint")?;
    let actual_journal_limit = pragma_non_negative_u64(connection, "journal_size_limit")?;
    if actual_max_page_count != expected_max_page_count
        || actual_autocheckpoint != expected_autocheckpoint
        || actual_journal_limit != limits.wal_target_bytes
    {
        return Err(StorageError::CorruptData(
            "SQLite physical-capacity pragmas are not active".into(),
        ));
    }
    Ok(())
}

fn pragma_positive_u64(connection: &Connection, pragma: &'static str) -> Result<u64, StorageError> {
    let value = pragma_non_negative_u64(connection, pragma)?;
    if value == 0 {
        return Err(StorageError::CorruptData(format!(
            "SQLite PRAGMA {pragma} must be positive"
        )));
    }
    Ok(value)
}

fn pragma_non_negative_u64(
    connection: &Connection,
    pragma: &'static str,
) -> Result<u64, StorageError> {
    let value: i64 = connection.pragma_query_value(None, pragma, |row| row.get(0))?;
    u64::try_from(value).map_err(|_| {
        StorageError::CorruptData(format!("SQLite PRAGMA {pragma} cannot be negative"))
    })
}

fn current_schema_version(connection: &Connection) -> Result<i64, StorageError> {
    let has_migrations: i64 = connection.query_row(
        r#"SELECT EXISTS(
               SELECT 1 FROM sqlite_schema
               WHERE type = 'table' AND name = 'schema_migrations'
           )"#,
        [],
        |row| row.get(0),
    )?;
    if has_migrations == 0 {
        return Ok(0);
    }
    Ok(connection.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        [],
        |row| row.get(0),
    )?)
}

fn checkpoint_wal(connection: &Connection) -> Result<(), StorageError> {
    let (busy, _, _): (i64, i64, i64) =
        connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
    if busy != 0 {
        return Err(StorageError::CorruptData(
            "SQLite WAL checkpoint could not complete during exclusive startup".into(),
        ));
    }
    Ok(())
}

fn require_physical_capacity(
    connection: &Connection,
    database_path: &Path,
    limits: &SqlitePhysicalLimits,
    gate: PhysicalCapacityGate,
) -> Result<(), StorageError> {
    let snapshot = physical_capacity_snapshot(connection, database_path)?;
    evaluate_physical_capacity(snapshot, limits, gate)
}

fn require_connection_physical_capacity(
    connection: &Connection,
    limits: &SqlitePhysicalLimits,
    gate: PhysicalCapacityGate,
) -> Result<(), StorageError> {
    let Some(path) = connection.path() else {
        return Ok(());
    };
    if path.is_empty() || path == ":memory:" {
        return Ok(());
    }
    require_physical_capacity(connection, Path::new(path), limits, gate)
}

fn physical_capacity_snapshot(
    connection: &Connection,
    database_path: &Path,
) -> Result<PhysicalCapacitySnapshot, StorageError> {
    let page_size = pragma_positive_u64(connection, "page_size")?;
    let page_count = pragma_non_negative_u64(connection, "page_count")?;
    let page_bytes = page_size
        .checked_mul(page_count)
        .ok_or(StorageError::IntegerOutOfRange(
            "SQLite main database bytes",
        ))?;
    let main_bytes = file_size_or_zero(database_path)?.max(page_bytes);
    let wal_bytes = file_size_or_zero(&sqlite_sidecar_path(database_path, "-wal"))?;
    let parent = database_path.parent().ok_or_else(|| {
        StorageError::CorruptData("SQLite database path has no parent directory".into())
    })?;
    Ok(PhysicalCapacitySnapshot {
        main_bytes,
        wal_bytes,
        available_bytes: available_space(parent)?,
    })
}

fn sqlite_sidecar_path(database_path: &Path, suffix: &str) -> PathBuf {
    let mut file_name = database_path
        .file_name()
        .map(OsString::from)
        .unwrap_or_default();
    file_name.push(suffix);
    database_path.with_file_name(file_name)
}

fn file_size_or_zero(path: &Path) -> Result<u64, StorageError> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error.into()),
    }
}

fn evaluate_physical_capacity(
    snapshot: PhysicalCapacitySnapshot,
    limits: &SqlitePhysicalLimits,
    gate: PhysicalCapacityGate,
) -> Result<(), StorageError> {
    if snapshot.main_bytes > limits.max_main_bytes {
        return Err(StorageError::PhysicalStorageExhausted);
    }
    match gate {
        PhysicalCapacityGate::Migration => {
            let main_admission_ceiling = limits
                .max_main_bytes
                .checked_sub(limits.admission_reserve_bytes)
                .ok_or(StorageError::PhysicalStorageExhausted)?;
            let required_available = limits
                .min_free_bytes
                .checked_add(limits.admission_reserve_bytes)
                .and_then(|headroom| headroom.checked_add(snapshot.main_bytes))
                .ok_or(StorageError::PhysicalStorageExhausted)?;
            if snapshot.main_bytes > main_admission_ceiling
                || snapshot.wal_bytes > limits.wal_target_bytes
                || snapshot.available_bytes < required_available
            {
                return Err(StorageError::PhysicalStorageExhausted);
            }
        }
        PhysicalCapacityGate::Admission => {
            let main_admission_ceiling = limits
                .max_main_bytes
                .checked_sub(limits.admission_reserve_bytes)
                .ok_or(StorageError::PhysicalStorageExhausted)?;
            let required_available = limits
                .min_free_bytes
                .checked_add(limits.admission_reserve_bytes)
                .ok_or(StorageError::PhysicalStorageExhausted)?;
            if snapshot.main_bytes > main_admission_ceiling
                || snapshot.wal_bytes > limits.wal_target_bytes
                || snapshot.available_bytes < required_available
            {
                return Err(StorageError::PhysicalStorageExhausted);
            }
        }
        PhysicalCapacityGate::ReservedProgress | PhysicalCapacityGate::Finalization => {
            if snapshot.available_bytes < limits.min_free_bytes {
                return Err(StorageError::PhysicalStorageExhausted);
            }
        }
    }
    Ok(())
}

fn validate_account_foundation_migration(connection: &Connection) -> Result<(), StorageError> {
    let foreign_key_violation = connection
        .query_row(
            r#"SELECT "table" FROM pragma_foreign_key_check LIMIT 1"#,
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(table) = foreign_key_violation {
        return Err(StorageError::CorruptData(format!(
            "schema v13 account migration cannot prove local ownership: foreign key violation in `{table}`"
        )));
    }

    let (user_count, owner_count, active_owner_count): (i64, i64, i64) = connection.query_row(
        r#"SELECT COUNT(*),
                      COALESCE(SUM(CASE WHEN role = 'owner' THEN 1 ELSE 0 END), 0),
                      COALESCE(SUM(CASE
                          WHEN role = 'owner' AND status = 'active' THEN 1 ELSE 0
                      END), 0)
               FROM users"#,
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;

    if user_count == 0 {
        let violation = connection
            .query_row(
                r#"SELECT boundary
                   FROM (
                       SELECT 1 AS priority, 'an unconfigured session already has an owner' AS boundary
                       WHERE EXISTS(SELECT 1 FROM sessions WHERE owner_user_id IS NOT NULL)
                       UNION ALL
                       SELECT 2, 'an unconfigured run already has an owner'
                       WHERE EXISTS(SELECT 1 FROM runs WHERE owner_user_id IS NOT NULL)
                       UNION ALL
                       SELECT 3, 'an unconfigured reply job has an actor'
                       WHERE EXISTS(SELECT 1 FROM reply_jobs)
                       UNION ALL
                       SELECT 4, 'an unconfigured database contains an auth session'
                       WHERE EXISTS(SELECT 1 FROM auth_sessions)
                       UNION ALL
                       SELECT 5, 'an unconfigured database contains user preferences'
                       WHERE EXISTS(SELECT 1 FROM user_preferences)
                       UNION ALL
                       SELECT 6, 'an unconfigured session receipt is not in legacy scope'
                       WHERE EXISTS(
                           SELECT 1 FROM session_command_receipts
                           WHERE actor_scope <> '__legacy__'
                       )
                       UNION ALL
                       SELECT 7, 'an unconfigured run receipt is not in legacy scope'
                       WHERE EXISTS(
                           SELECT 1 FROM idempotency_receipts
                           WHERE actor_scope <> '__legacy__'
                       )
                       UNION ALL
                       SELECT 8, 'an unconfigured dispatch job has an approving actor'
                       WHERE EXISTS(
                           SELECT 1 FROM dispatch_jobs
                           WHERE approving_actor_user_id IS NOT NULL
                       )
                       UNION ALL
                       SELECT 9, 'an unconfigured finalization reservation is not in legacy scope'
                       WHERE EXISTS(
                           SELECT 1 FROM finalization_reservations
                           WHERE scope_id <> '__legacy__'
                       )
                   )
                   ORDER BY priority
                   LIMIT 1"#,
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(boundary) = violation {
            return Err(StorageError::CorruptData(format!(
                "schema v13 account migration cannot prove local ownership: {boundary}"
            )));
        }
        return Ok(());
    }

    if owner_count != 1 || active_owner_count != 1 {
        return Err(StorageError::CorruptData(
            "schema v13 account migration requires exactly one active legacy owner".into(),
        ));
    }
    let owner_user_id: String = connection.query_row(
        "SELECT id FROM users WHERE role = 'owner' AND status = 'active'",
        [],
        |row| row.get(0),
    )?;
    let violation = connection
        .query_row(
            r#"SELECT boundary
               FROM (
                   SELECT 1 AS priority, 'a configured session is not owned by the legacy owner' AS boundary
                   WHERE EXISTS(
                       SELECT 1 FROM sessions WHERE owner_user_id IS NOT ?1
                   )
                   UNION ALL
                   SELECT 2, 'a configured run is not owned by the legacy owner'
                   WHERE EXISTS(
                       SELECT 1 FROM runs WHERE owner_user_id IS NOT ?1
                   )
                   UNION ALL
                   SELECT 3, 'a session-to-run binding crosses a legacy owner boundary'
                   WHERE EXISTS(
                       SELECT 1
                       FROM session_runs binding
                       JOIN sessions session ON session.id = binding.session_id
                       JOIN runs run ON run.id = binding.run_id
                       WHERE session.owner_user_id IS NOT run.owner_user_id
                   )
                   UNION ALL
                   SELECT 4, 'an incident contains runs from different legacy owners'
                   WHERE EXISTS(
                       SELECT 1
                       FROM runs first
                       JOIN runs second
                         ON second.incident_id = first.incident_id
                        AND second.id > first.id
                       WHERE first.owner_user_id IS NOT second.owner_user_id
                   )
                   UNION ALL
                   SELECT 5, 'a reply job actor is not the legacy owner'
                   WHERE EXISTS(
                       SELECT 1 FROM reply_jobs WHERE actor_user_id IS NOT ?1
                   )
                   UNION ALL
                   SELECT 6, 'a session receipt actor scope is not the legacy owner'
                   WHERE EXISTS(
                       SELECT 1 FROM session_command_receipts WHERE actor_scope IS NOT ?1
                   )
                   UNION ALL
                   SELECT 7, 'a run receipt actor scope is not the legacy owner'
                   WHERE EXISTS(
                       SELECT 1 FROM idempotency_receipts WHERE actor_scope IS NOT ?1
                   )
                   UNION ALL
                   SELECT 8, 'a dispatch approving actor is not the legacy owner'
                   WHERE EXISTS(
                       SELECT 1 FROM dispatch_jobs
                       WHERE approving_actor_user_id IS NOT ?1
                   )
                   UNION ALL
                   SELECT 9, 'a finalization reservation scope is not the legacy owner'
                   WHERE EXISTS(
                       SELECT 1 FROM finalization_reservations WHERE scope_id IS NOT ?1
                   )
                   UNION ALL
                   SELECT 10, 'the runtime identity does not resolve to the legacy owner resources'
                   WHERE EXISTS(
                       SELECT 1
                       FROM runtime_identity identity
                       WHERE NOT EXISTS(
                                 SELECT 1
                                 FROM sessions session
                                 WHERE session.id = identity.primary_session_id
                                   AND session.owner_user_id IS ?1
                             )
                          OR NOT EXISTS(
                                 SELECT 1
                                 FROM runs run
                                 WHERE run.id = identity.primary_run_id
                                   AND run.owner_user_id IS ?1
                             )
                          OR NOT EXISTS(
                                 SELECT 1
                                 FROM session_runs binding
                                 WHERE binding.session_id = identity.primary_session_id
                                   AND binding.run_id = identity.primary_run_id
                             )
                   )
               )
               ORDER BY priority
               LIMIT 1"#,
            [&owner_user_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(boundary) = violation {
        return Err(StorageError::CorruptData(format!(
            "schema v13 account migration cannot prove local ownership: {boundary}"
        )));
    }
    Ok(())
}

fn migrate(connection: &mut Connection, limits: &StorageLimits) -> Result<(), StorageError> {
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
    if current < 10 {
        transaction.execute_batch(MIGRATION_0010)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![10, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    if current < 11 {
        transaction.execute_batch(MIGRATION_0011)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![11, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    if current < 12 {
        transaction.execute_batch(MIGRATION_0012)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![12, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    if current < 13 {
        validate_account_foundation_migration(&transaction)?;
        transaction.execute_batch(MIGRATION_0013)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![13, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    if current < 14 {
        let v14_snapshot = capture_v14_migration_snapshot(&transaction)?;
        transaction.execute_batch(MIGRATION_0014)?;
        validate_v14_migration_postflight(&transaction, &v14_snapshot)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![14, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    if current < 15 {
        transaction.execute_batch(MIGRATION_0015)?;
        let detail_rows = capacity_limit(limits.account_audit_detail_rows)?;
        let applied_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        transaction.execute(
            r#"INSERT INTO account_audit_policies(
                   account_id, detail_rows, legal_hold, archive_required, revision, updated_at
               )
               SELECT id, ?1, 0, 0, 1, ?2 FROM accounts"#,
            params![detail_rows, applied_at],
        )?;
        validate_v15_migration_postflight(&transaction)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![15, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    if current < 16 {
        transaction.execute_batch(MIGRATION_0016)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![16, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    if current < 17 {
        transaction.execute_batch(MIGRATION_0017)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![17, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    if current < 18 {
        transaction.execute_batch(MIGRATION_0018)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![18, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    if current < 19 {
        transaction.execute_batch(MIGRATION_0019)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![19, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    if current < 20 {
        transaction.execute_batch(MIGRATION_0020)?;
        let applied_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        execution::backfill_legacy_execution_ledgers(&transaction, &applied_at)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![20, applied_at],
        )?;
    }
    if current < 21 {
        transaction.execute_batch(MIGRATION_0021)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![21, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    if current < 22 {
        transaction.execute_batch(MIGRATION_0022)?;
        agent::seal_legacy_agent_knowledge_boundary(&transaction)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![22, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    if current < 23 {
        transaction.execute_batch(MIGRATION_0023)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![23, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    if current < 24 {
        transaction.execute_batch(MIGRATION_0024)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![24, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    if current < 25 {
        transaction.execute_batch(MIGRATION_0025)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![25, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    if current < 26 {
        transaction.execute_batch(MIGRATION_0026)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![26, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    if current < 27 {
        transaction.execute_batch(MIGRATION_0027)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![27, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    if current < 28 {
        transaction.execute_batch(MIGRATION_0028)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![28, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    if current < 29 {
        transaction.execute_batch(MIGRATION_0029)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![29, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    if current < 30 {
        transaction.execute_batch(MIGRATION_0030)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![30, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    if current < 31 {
        transaction.execute_batch(MIGRATION_0031)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![31, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    if current < 32 {
        transaction.execute_batch(MIGRATION_0032)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![32, Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)],
        )?;
    }
    // The execution verifier now understands the v22 knowledge binding. Run
    // it only after every missing schema step has been installed so upgrades
    // from v19 and older never query a column that does not exist yet. This
    // remains inside the migration transaction, so a corrupt legacy ledger
    // still rolls the entire upgrade back.
    if current < CURRENT_SCHEMA_VERSION {
        agent::verify_agent_knowledge_context_integrity(&transaction)?;
        agent::verify_account_knowledge_catalog_integrity(&transaction)?;
        agent::verify_account_agent_prompt_integrity(&transaction)?;
        agent::verify_agent_todo_integrity(&transaction)?;
        agent::verify_agent_goal_integrity(&transaction)?;
        agent::verify_agent_goal_round_integrity(&transaction)?;
        verify_session_followup_integrity(&transaction)?;
        agent::verify_agent_model_output_integrity(&transaction)?;
        provider::verify_account_reply_provider_integrity(&transaction)?;
        execution::verify_agent_execution_integrity(&transaction)?;
    }
    validate_configured_account_audit_policies(&transaction, limits)?;
    compact_existing_bootstrap_audit_to_capacity(&transaction, &now(), limits)?;
    transaction.commit()?;
    Ok(())
}

fn validate_configured_account_audit_policies(
    connection: &Connection,
    limits: &StorageLimits,
) -> Result<(), StorageError> {
    let configured_limit = capacity_limit(limits.account_audit_detail_rows)?;
    let exceeding_policy = connection
        .query_row(
            r#"SELECT account_id, detail_rows
               FROM account_audit_policies
               WHERE detail_rows > ?1
               ORDER BY account_id
               LIMIT 1"#,
            [configured_limit],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    if let Some((account_id, detail_rows)) = exceeding_policy {
        return Err(StorageError::AccountAuditPolicyExceedsConfiguredLimit {
            account_id,
            detail_rows,
            configured_limit,
        });
    }
    Ok(())
}

fn validate_v15_migration_postflight(connection: &Connection) -> Result<(), StorageError> {
    let account_count: i64 =
        connection.query_row("SELECT COUNT(*) FROM accounts", [], |row| row.get(0))?;
    for (table, count) in [
        (
            "account_audit_rollups",
            table_row_count_query(connection, "SELECT COUNT(*) FROM account_audit_rollups")?,
        ),
        (
            "account_audit_policies",
            table_row_count_query(connection, "SELECT COUNT(*) FROM account_audit_policies")?,
        ),
        (
            "account_audit_archive_state",
            table_row_count_query(
                connection,
                "SELECT COUNT(*) FROM account_audit_archive_state",
            )?,
        ),
    ] {
        if count != account_count {
            return Err(StorageError::CorruptData(format!(
                "schema v15 migration did not create one {table} row per account"
            )));
        }
    }

    let schema_object_count: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM sqlite_schema
           WHERE name IN (
               'member_setup_tokens', 'account_audit_rollups',
               'account_audit_policies', 'account_audit_archive_state',
               'account_audit_events', 'member_setup_tokens_expiry_idx',
               'account_audit_events_hash_idx', 'account_audit_events_time_idx',
               'member_setup_tokens_require_pending_member',
               'member_setup_tokens_reject_update',
               'account_audit_events_require_chain',
               'account_audit_events_reject_update',
               'account_audit_events_require_rollup_before_delete',
               'account_audit_rollups_enforce_forward_update',
               'account_audit_rollups_reject_delete',
               'account_audit_policies_enforce_revision',
               'account_audit_policies_reject_delete',
               'account_audit_archive_state_enforce_revision',
               'account_audit_archive_state_reject_delete'
           )"#,
        [],
        |row| row.get(0),
    )?;
    if schema_object_count != 19 {
        return Err(StorageError::CorruptData(
            "schema v15 member lifecycle/audit objects are incomplete".into(),
        ));
    }

    if connection
        .query_row(
            "SELECT 1 FROM pragma_foreign_key_check LIMIT 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some()
    {
        return Err(StorageError::CorruptData(
            "schema v15 migration introduced a foreign-key violation".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct V14MigrationSnapshot {
    session_receipts: i64,
    run_receipts: i64,
    reply_jobs: i64,
    dispatch_jobs: i64,
    reservations: i64,
    retained_auth_sessions: i64,
    configured: bool,
}

fn capture_v14_migration_snapshot(
    connection: &Connection,
) -> Result<V14MigrationSnapshot, StorageError> {
    Ok(V14MigrationSnapshot {
        session_receipts: table_row_count(connection, "session_command_receipts")?,
        run_receipts: table_row_count(connection, "idempotency_receipts")?,
        reply_jobs: table_row_count(connection, "reply_jobs")?,
        dispatch_jobs: table_row_count(connection, "dispatch_jobs")?,
        reservations: table_row_count(connection, "finalization_reservations")?,
        retained_auth_sessions: connection.query_row(
            r#"SELECT COUNT(*)
               FROM auth_sessions session
               JOIN users user
                 ON user.id = session.user_id AND user.status = 'active'
               JOIN account_memberships membership
                 ON membership.user_id = session.user_id
                AND membership.account_id = ?1
                AND membership.status = 'active'
                AND membership.role = 'owner'
               JOIN accounts account
                 ON account.id = membership.account_id
                AND account.status = 'active'"#,
            [LOCAL_ACCOUNT_ID],
            |row| row.get(0),
        )?,
        configured: connection.query_row("SELECT EXISTS(SELECT 1 FROM users)", [], |row| {
            row.get::<_, i64>(0)
        })? != 0,
    })
}

fn table_row_count(connection: &Connection, table: &'static str) -> Result<i64, StorageError> {
    let sql = match table {
        "session_command_receipts" => "SELECT COUNT(*) FROM session_command_receipts",
        "idempotency_receipts" => "SELECT COUNT(*) FROM idempotency_receipts",
        "reply_jobs" => "SELECT COUNT(*) FROM reply_jobs",
        "dispatch_jobs" => "SELECT COUNT(*) FROM dispatch_jobs",
        "finalization_reservations" => "SELECT COUNT(*) FROM finalization_reservations",
        _ => {
            return Err(StorageError::CorruptData(
                "unsupported v14 migration count target".into(),
            ));
        }
    };
    Ok(connection.query_row(sql, [], |row| row.get(0))?)
}

fn validate_v14_migration_postflight(
    connection: &Connection,
    before: &V14MigrationSnapshot,
) -> Result<(), StorageError> {
    let after = V14MigrationSnapshot {
        session_receipts: table_row_count(connection, "session_command_receipts")?,
        run_receipts: table_row_count(connection, "idempotency_receipts")?,
        reply_jobs: table_row_count(connection, "reply_jobs")?,
        dispatch_jobs: table_row_count(connection, "dispatch_jobs")?,
        reservations: table_row_count(connection, "finalization_reservations")?,
        retained_auth_sessions: table_row_count_query(
            connection,
            "SELECT COUNT(*) FROM auth_sessions",
        )?,
        configured: before.configured,
    };
    if after != *before {
        return Err(StorageError::CorruptData(format!(
            "schema v14 migration did not preserve its proven durable row set: before={before:?}, after={after:?}"
        )));
    }

    let authority_root_violation: i64 = connection.query_row(
        r#"SELECT CASE
               WHEN (SELECT COUNT(*) FROM accounts) <> 1
                 OR NOT EXISTS (
                     SELECT 1 FROM accounts
                     WHERE id = ?1 AND status = 'active'
                 )
               THEN 1
               WHEN ?2 = 1 AND (
                   SELECT COUNT(*)
                   FROM account_memberships membership
                   JOIN users user ON user.id = membership.user_id
                   WHERE membership.account_id = ?1
                     AND membership.role = 'owner'
                     AND membership.status = 'active'
                     AND user.status = 'active'
               ) <> 1
               THEN 1
               WHEN ?2 = 0 AND (
                   EXISTS(SELECT 1 FROM users)
                   OR EXISTS(SELECT 1 FROM account_memberships)
               )
               THEN 1
               ELSE 0
           END"#,
        params![LOCAL_ACCOUNT_ID, i64::from(before.configured)],
        |row| row.get(0),
    )?;
    if authority_root_violation != 0 {
        return Err(StorageError::CorruptData(
            "schema v14 migration did not preserve a valid active account owner root".into(),
        ));
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
            "schema v14 migration introduced a foreign-key violation".into(),
        ));
    }

    let authorization_columns: i64 = connection.query_row(
        r#"SELECT
               (SELECT COUNT(*) FROM pragma_table_info('auth_sessions')
                WHERE name IN ('id', 'account_id', 'user_id', 'membership_revision'))
             + (SELECT COUNT(*) FROM pragma_table_info('session_command_receipts')
                WHERE name IN ('account_id', 'actor_user_id'))
             + (SELECT COUNT(*) FROM pragma_table_info('idempotency_receipts')
                WHERE name IN ('account_id', 'actor_user_id'))
             + (SELECT COUNT(*) FROM pragma_table_info('reply_jobs')
                WHERE name IN ('account_id', 'actor_user_id', 'actor_membership_revision'))
             + (SELECT COUNT(*) FROM pragma_table_info('dispatch_jobs')
                WHERE name IN ('account_id', 'initiating_actor_user_id',
                               'initiating_membership_revision', 'approving_actor_user_id',
                               'approving_membership_revision'))
             + (SELECT COUNT(*) FROM pragma_table_info('finalization_reservations')
                WHERE name IN ('account_id', 'actor_user_id'))"#,
        [],
        |row| row.get(0),
    )?;
    if authorization_columns != 18 {
        return Err(StorageError::CorruptData(
            "schema v14 durable authorization columns are incomplete".into(),
        ));
    }

    let index_count: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM sqlite_schema
           WHERE type = 'index' AND name IN (
               'auth_sessions_user_idx', 'auth_sessions_expiry_idx',
               'session_command_receipts_actor_key_idx',
               'session_command_receipts_prebootstrap_key_idx',
               'idempotency_receipts_actor_key_idx',
               'idempotency_receipts_prebootstrap_key_idx',
               'reply_jobs_ready_idx', 'reply_jobs_actor_idx',
               'reply_jobs_account_idx', 'reply_jobs_started_idx',
               'dispatch_jobs_ready_idx', 'dispatch_jobs_run_idx',
               'dispatch_jobs_actor_idx', 'dispatch_jobs_initiator_idx',
               'dispatch_jobs_account_idx', 'dispatch_jobs_started_idx',
               'finalization_reservations_turn_idx',
               'finalization_reservations_dispatch_idx',
               'finalization_reservations_actor_active_idx',
               'finalization_reservations_account_active_idx',
               'finalization_reservations_kind_active_idx'
           )"#,
        [],
        |row| row.get(0),
    )?;
    if index_count != 21 {
        return Err(StorageError::CorruptData(
            "schema v14 durable authorization indexes are incomplete".into(),
        ));
    }

    let trigger_count: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM sqlite_schema
           WHERE type = 'trigger' AND name IN (
               'auth_sessions_reject_duplicate_insert',
               'auth_sessions_require_current_membership',
               'auth_sessions_reject_update',
               'session_command_receipts_require_authority',
               'session_command_receipts_reject_update',
               'session_command_receipts_reject_delete',
               'idempotency_receipts_require_authority',
               'idempotency_receipts_reject_update',
               'idempotency_receipts_reject_delete',
               'reply_jobs_require_authority',
               'reply_jobs_reject_input_update',
               'reply_jobs_enforce_forward_transition',
               'reply_jobs_reject_delete',
               'dispatch_jobs_require_authority',
               'dispatch_jobs_reject_input_update',
               'dispatch_jobs_enforce_forward_transition',
               'dispatch_jobs_reject_delete',
               'finalization_reservations_require_authority',
               'finalization_reservations_require_event_payload_capacity_on_insert',
               'finalization_reservations_enforce_update',
               'finalization_reservations_reject_live_delete'
           )"#,
        [],
        |row| row.get(0),
    )?;
    if trigger_count != 21 {
        return Err(StorageError::CorruptData(
            "schema v14 durable authorization triggers are incomplete".into(),
        ));
    }

    let legacy_schema_objects: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM sqlite_schema
           WHERE name IN (
               'auth_sessions_v13', 'session_command_receipts_v13',
               'idempotency_receipts_v13', 'reply_jobs_v13',
               'dispatch_jobs_v13', 'finalization_reservations_v13',
               'users_single_owner_idx', 'session_runs_require_same_owner'
           )"#,
        [],
        |row| row.get(0),
    )?;
    if legacy_schema_objects != 0 {
        return Err(StorageError::CorruptData(
            "schema v14 migration left a legacy authorization object behind".into(),
        ));
    }

    let actor_state_violation: i64 = if before.configured {
        connection.query_row(
            r#"SELECT EXISTS(
                   SELECT 1 FROM session_command_receipts WHERE actor_user_id IS NULL
                   UNION ALL SELECT 1 FROM idempotency_receipts WHERE actor_user_id IS NULL
                   UNION ALL SELECT 1 FROM dispatch_jobs
                       WHERE initiating_actor_user_id IS NULL
                          OR initiating_membership_revision IS NULL
                          OR approving_actor_user_id IS NULL
                          OR approving_membership_revision IS NULL
                   UNION ALL SELECT 1 FROM finalization_reservations
                       WHERE actor_user_id IS NULL
               )"#,
            [],
            |row| row.get(0),
        )?
    } else {
        connection.query_row(
            r#"SELECT EXISTS(
                   SELECT 1 FROM auth_sessions
                   UNION ALL SELECT 1 FROM reply_jobs
                   UNION ALL SELECT 1 FROM session_command_receipts
                       WHERE actor_user_id IS NOT NULL
                   UNION ALL SELECT 1 FROM idempotency_receipts
                       WHERE actor_user_id IS NOT NULL
                   UNION ALL SELECT 1 FROM dispatch_jobs
                       WHERE initiating_actor_user_id IS NOT NULL
                          OR initiating_membership_revision IS NOT NULL
                          OR approving_actor_user_id IS NOT NULL
                          OR approving_membership_revision IS NOT NULL
                   UNION ALL SELECT 1 FROM finalization_reservations
                       WHERE actor_user_id IS NOT NULL
               )"#,
            [],
            |row| row.get(0),
        )?
    };
    if actor_state_violation != 0 {
        return Err(StorageError::CorruptData(
            "schema v14 migration produced an invalid configured/bootstrap actor state".into(),
        ));
    }

    let migrated_auth_violation: i64 = connection.query_row(
        r#"SELECT EXISTS(
               SELECT 1
               FROM auth_sessions session
               LEFT JOIN accounts account ON account.id = session.account_id
               LEFT JOIN users user ON user.id = session.user_id
               LEFT JOIN account_memberships membership
                 ON membership.account_id = session.account_id
                AND membership.user_id = session.user_id
               WHERE account.status IS NOT 'active'
                  OR user.status IS NOT 'active'
                  OR membership.role IS NOT 'owner'
                  OR membership.status IS NOT 'active'
                  OR membership.revision IS NOT session.membership_revision
           )"#,
        [],
        |row| row.get(0),
    )?;
    if migrated_auth_violation != 0 {
        return Err(StorageError::CorruptData(
            "schema v14 migration retained an unproven authentication authority".into(),
        ));
    }
    Ok(())
}

fn table_row_count_query(connection: &Connection, sql: &str) -> Result<i64, StorageError> {
    Ok(connection.query_row(sql, [], |row| row.get(0))?)
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

fn migration_trigger_definition<'a>(
    migration: &'a str,
    name: &str,
) -> Result<&'a str, StorageError> {
    let marker = format!("CREATE TRIGGER {name}\n");
    let start = migration.find(&marker).ok_or_else(|| {
        StorageError::CorruptData(format!(
            "the authoritative migration is missing trigger `{name}`"
        ))
    })?;
    let trigger = &migration[start..];
    let end = trigger.find("\nEND;").ok_or_else(|| {
        StorageError::CorruptData(format!(
            "the authoritative migration trigger `{name}` is unterminated"
        ))
    })? + "\nEND;".len();
    Ok(&trigger[..end])
}

fn normalized_schema_sql(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_end_matches(';')
        .to_owned()
}

fn verify_migration_trigger_definitions(
    connection: &Connection,
    migration: &str,
    names: &[&str],
) -> Result<(), StorageError> {
    for name in names {
        let expected = migration_trigger_definition(migration, name)?;
        let expected = normalized_schema_sql(expected);
        let stored = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
                [name],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if stored.as_deref().map(normalized_schema_sql).as_deref() != Some(expected.as_str()) {
            return Err(StorageError::CorruptData(format!(
                "durability trigger `{name}` differs from the authoritative migration"
            )));
        }
    }
    Ok(())
}

fn readiness(
    connection: &Connection,
    expects_wal: bool,
    physical_limits: Option<&SqlitePhysicalLimits>,
    require_admission: bool,
    deep_invariants: bool,
    audit_admission_limits: Option<&StorageLimits>,
) -> Result<(), StorageError> {
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
    let cache_size: i64 = connection.pragma_query_value(None, "cache_size", |row| row.get(0))?;
    let mmap_size: i64 = if expects_wal {
        connection.pragma_query_value(None, "mmap_size", |row| row.get(0))?
    } else {
        0
    };
    let journal_mode: String =
        connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    let encoding: String = connection.pragma_query_value(None, "encoding", |row| row.get(0))?;
    let expected_journal = if expects_wal { "wal" } else { "memory" };
    if foreign_keys != 1
        || synchronous != 2
        || busy_timeout != BUSY_TIMEOUT.as_millis() as i64
        || cache_size != -2048
        || mmap_size != 0
        || !journal_mode.eq_ignore_ascii_case(expected_journal)
        || !encoding.eq_ignore_ascii_case("UTF-8")
    {
        return Err(StorageError::CorruptData(
            "SQLite safety pragmas are not active".into(),
        ));
    }
    if let Some(physical_limits) = physical_limits {
        verify_physical_pragmas(connection, physical_limits)?;
        if require_admission {
            require_connection_physical_capacity(
                connection,
                physical_limits,
                PhysicalCapacityGate::Admission,
            )?;
        }
    }

    let table_count: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM sqlite_schema
           WHERE type = 'table' AND name IN (
               'schema_migrations', 'incidents', 'runs', 'run_events', 'idempotency_receipts',
               'dispatch_jobs', 'runtime_identity', 'sessions', 'session_runs',
               'session_turns', 'session_events', 'session_command_receipts',
               'users', 'auth_sessions', 'bootstrap_tokens', 'user_preferences',
               'reply_jobs', 'finalization_reservations', 'event_payload_usage',
               'bootstrap_audit_rollup', 'accounts', 'account_memberships',
               'member_setup_tokens', 'account_audit_rollups',
               'account_audit_policies', 'account_audit_archive_state',
               'account_audit_events', 'agent_turns', 'agent_model_jobs',
               'agent_tool_calls', 'agent_review_receipts',
               'agent_deployment_manifests', 'agent_run_epochs',
               'agent_execution_events', 'agent_execution_heads',
               'agent_operation_claims', 'knowledge_corpus_revisions',
               'agent_knowledge_contexts', 'agent_knowledge_legacy_boundary',
               'agent_knowledge_legacy_agents', 'account_knowledge_catalogs',
               'knowledge_catalog_receipts', 'session_compaction_jobs',
               'agent_todo_snapshots'
           )"#,
        [],
        |row| row.get(0),
    )?;
    if table_count != 44 {
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

    let account_scope_columns: i64 = connection.query_row(
        r#"SELECT
               (SELECT COUNT(*) FROM pragma_table_info('incidents') WHERE name = 'account_id')
             + (SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name = 'account_id')
             + (SELECT COUNT(*) FROM pragma_table_info('runs') WHERE name = 'account_id')
             + (SELECT COUNT(*) FROM pragma_table_info('runtime_identity')
                WHERE name = 'account_id')"#,
        [],
        |row| row.get(0),
    )?;
    if account_scope_columns != 4 {
        return Err(StorageError::CorruptData(
            "account scope columns are missing".into(),
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

    let agent_tool_completion_columns: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM pragma_table_info('agent_tool_calls')
           WHERE name = 'completion_next_request_json'"#,
        [],
        |row| row.get(0),
    )?;
    if agent_tool_completion_columns != 1 {
        return Err(StorageError::CorruptData(
            "Agent tool completion replay column is missing".into(),
        ));
    }

    let agent_todo_columns: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM pragma_table_info('agent_todo_snapshots')
           WHERE name IN (
               'account_id', 'session_id', 'turn_id', 'agent_id', 'revision',
               'call_id', 'todos_json', 'digest', 'item_count', 'pending_count',
               'in_progress_count', 'completed_count', 'created_at'
           )"#,
        [],
        |row| row.get(0),
    )?;
    if agent_todo_columns != 13 {
        return Err(StorageError::CorruptData(
            "Agent todo snapshot schema is missing".into(),
        ));
    }

    let agent_output_columns: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM pragma_table_info('agent_model_output_chunks')
           WHERE name IN (
               'account_id', 'actor_user_id', 'actor_membership_revision',
               'session_id', 'turn_id', 'agent_id', 'job_id', 'step',
               'sequence', 'ordinal', 'content', 'cumulative_bytes', 'created_at'
           )"#,
        [],
        |row| row.get(0),
    )?;
    if agent_output_columns != 13 {
        return Err(StorageError::CorruptData(
            "Agent model output chunk schema is missing".into(),
        ));
    }

    let agent_deployment_manifest_columns: i64 = connection.query_row(
        r#"SELECT COUNT(*)
           FROM pragma_table_info('agent_deployment_manifests')
           WHERE name IN ('digest', 'schema_version', 'envelope_json', 'created_at')"#,
        [],
        |row| row.get(0),
    )?;
    let agent_manifest_binding_columns: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM pragma_table_info('agent_turns')
           WHERE name = 'deployment_manifest_digest'"#,
        [],
        |row| row.get(0),
    )?;
    if agent_deployment_manifest_columns != 4 || agent_manifest_binding_columns != 1 {
        return Err(StorageError::CorruptData(
            "Agent deployment manifest schema is missing".into(),
        ));
    }

    let agent_knowledge_columns: i64 = connection.query_row(
        r#"SELECT
               (SELECT COUNT(*) FROM pragma_table_info('knowledge_corpus_revisions')
                WHERE name IN (
                    'account_id', 'digest', 'schema_version', 'entry_count',
                    'aggregate_entry_bytes', 'envelope_json', 'created_at'
                ))
             + (SELECT COUNT(*) FROM pragma_table_info('agent_knowledge_contexts')
                WHERE name IN (
                    'digest', 'schema_version', 'account_id', 'actor_user_id',
                    'actor_membership_revision', 'session_id', 'turn_id',
                    'agent_id', 'initial_model_job_id', 'corpus_digest',
                    'snapshot_digest', 'query_digest', 'context_digest',
                    'context_bytes', 'canonical_context', 'snapshot_envelope_json',
                    'binding_json', 'created_at'
                ))
             + (SELECT COUNT(*) FROM pragma_table_info('agent_turns')
                WHERE name = 'knowledge_context_digest')
             + (SELECT COUNT(*) FROM pragma_table_info('agent_model_jobs')
                WHERE name = 'knowledge_context_digest')
             + (SELECT COUNT(*) FROM pragma_table_info('agent_knowledge_legacy_boundary')
                WHERE name IN (
                    'singleton', 'schema_version', 'agent_count', 'set_digest'
                ))
             + (SELECT COUNT(*) FROM pragma_table_info('agent_knowledge_legacy_agents')
                WHERE name IN (
                    'agent_id', 'initial_model_job_id',
                    'execution_origin_fact_digest'
                ))"#,
        [],
        |row| row.get(0),
    )?;
    if agent_knowledge_columns != 34 {
        return Err(StorageError::CorruptData(
            "Agent knowledge context schema is missing".into(),
        ));
    }

    let knowledge_catalog_columns: i64 = connection.query_row(
        r#"SELECT
               (SELECT COUNT(*) FROM pragma_table_info('account_knowledge_catalogs')
                WHERE name IN (
                    'account_id', 'revision', 'active_corpus_digest',
                    'updated_by_user_id', 'updated_by_membership_revision', 'updated_at'
                ))
             + (SELECT COUNT(*) FROM pragma_table_info('knowledge_catalog_receipts')
                WHERE name IN (
                    'account_id', 'actor_user_id', 'actor_membership_revision',
                    'idempotency_key', 'request_fingerprint', 'catalog_revision',
                    'corpus_digest', 'created_at'
                ))"#,
        [],
        |row| row.get(0),
    )?;
    if knowledge_catalog_columns != 14 {
        return Err(StorageError::CorruptData(
            "account knowledge catalog schema is missing".into(),
        ));
    }

    let agent_prompt_columns: i64 = connection.query_row(
        r#"SELECT
               (SELECT COUNT(*) FROM pragma_table_info('agent_prompt_revisions')
                WHERE name IN (
                    'account_id', 'digest', 'content_bytes', 'content', 'created_at'
                ))
             + (SELECT COUNT(*) FROM pragma_table_info('account_agent_prompt_configs')
                WHERE name IN (
                    'account_id', 'revision', 'active_prompt_digest',
                    'updated_by_user_id', 'updated_by_membership_revision', 'updated_at'
                ))
             + (SELECT COUNT(*) FROM pragma_table_info('agent_prompt_config_receipts')
                WHERE name IN (
                    'account_id', 'actor_user_id', 'actor_membership_revision',
                    'idempotency_key', 'request_fingerprint', 'prompt_revision',
                    'prompt_digest', 'created_at'
                ))"#,
        [],
        |row| row.get(0),
    )?;
    if agent_prompt_columns != 19 {
        return Err(StorageError::CorruptData(
            "account Agent prompt schema is missing".into(),
        ));
    }

    let account_reply_provider_columns: i64 = connection.query_row(
        r#"SELECT
               (SELECT COUNT(*) FROM pragma_table_info('account_reply_provider_configs')
                WHERE name IN (
                    'account_id', 'revision', 'provider_id', 'model', 'reply_kind',
                    'updated_by_user_id', 'updated_by_membership_revision', 'updated_at'
                ))
             + (SELECT COUNT(*) FROM pragma_table_info('account_reply_provider_receipts')
                WHERE name IN (
                    'account_id', 'actor_user_id', 'actor_membership_revision',
                    'idempotency_key', 'request_fingerprint', 'provider_revision',
                    'provider_id', 'model', 'reply_kind', 'created_at'
                ))"#,
        [],
        |row| row.get(0),
    )?;
    if account_reply_provider_columns != 18 {
        return Err(StorageError::CorruptData(
            "account reply provider schema is missing".into(),
        ));
    }

    let agent_execution_columns: i64 = connection.query_row(
        r#"SELECT
               (SELECT COUNT(*) FROM pragma_table_info('agent_run_epochs')
                WHERE name IN (
                    'digest', 'agent_id', 'workflow_revision', 'operation_kind',
                    'model_job_id', 'tool_call_id', 'bound_manifest_digest',
                    'observed_manifest_digest', 'input_digest', 'envelope_json'
                ))
             + (SELECT COUNT(*) FROM pragma_table_info('agent_execution_events')
                WHERE name IN (
                    'agent_id', 'sequence', 'fact_digest', 'previous_fact_digest',
                    'fact_kind', 'agent_revision', 'epoch_digest', 'envelope_json'
                ))
             + (SELECT COUNT(*) FROM pragma_table_info('agent_execution_heads')
                WHERE name IN (
                    'agent_id', 'head_sequence', 'projected_agent_revision',
                    'history_origin', 'history_complete', 'head_hash',
                    'committed_payload_bytes'
                ))"#,
        [],
        |row| row.get(0),
    )?;
    if agent_execution_columns != 25 {
        return Err(StorageError::CorruptData(
            "Agent execution ledger schema is missing".into(),
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

    let event_payload_accounting_columns: i64 = connection.query_row(
        r#"SELECT
               (SELECT COUNT(*) FROM pragma_table_info('sessions')
                WHERE name = 'event_payload_bytes')
             + (SELECT COUNT(*) FROM pragma_table_info('runs')
                WHERE name = 'event_payload_bytes')
             + (SELECT COUNT(*) FROM pragma_table_info('finalization_reservations')
                WHERE name = 'remaining_event_payload_bytes')"#,
        [],
        |row| row.get(0),
    )?;
    if event_payload_accounting_columns != 3 {
        return Err(StorageError::CorruptData(
            "event payload accounting columns are missing".into(),
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
               'session_turns_open_recovery_idx',
               'finalization_reservations_turn_idx',
               'finalization_reservations_dispatch_idx',
               'finalization_reservations_actor_active_idx',
               'finalization_reservations_account_active_idx',
               'finalization_reservations_kind_active_idx',
               'session_command_receipts_actor_key_idx',
               'session_command_receipts_prebootstrap_key_idx',
               'idempotency_receipts_actor_key_idx',
               'idempotency_receipts_prebootstrap_key_idx',
               'reply_jobs_ready_idx',
               'reply_jobs_actor_idx',
               'reply_jobs_account_idx',
               'dispatch_jobs_ready_idx',
               'dispatch_jobs_run_idx',
               'dispatch_jobs_actor_idx',
               'dispatch_jobs_initiator_idx',
               'dispatch_jobs_account_idx',
               'auth_sessions_user_idx',
               'auth_sessions_expiry_idx',
               'bootstrap_tokens_one_live_idx',
               'bootstrap_tokens_terminal_sequence_idx',
               'account_memberships_user_idx',
               'account_memberships_active_owner_idx',
               'incidents_account_id_idx',
               'sessions_account_id_idx',
               'sessions_account_updated_idx',
               'runs_account_id_idx',
               'runs_account_started_idx',
               'runs_account_incident_idx',
               'member_setup_tokens_expiry_idx',
               'account_audit_events_hash_idx',
               'account_audit_events_time_idx',
               'session_events_reply_context_idx',
               'session_events_turn_kind_idx',
               'agent_turns_account_status_idx',
               'agent_turns_recovery_idx',
               'agent_model_jobs_ready_idx',
               'agent_model_jobs_started_idx',
               'agent_model_jobs_one_live_idx',
               'agent_tool_calls_ready_idx',
               'agent_tool_calls_started_idx',
               'agent_tool_calls_one_live_idx',
               'agent_turns_deployment_manifest_idx',
               'agent_run_epochs_model_job_idx',
               'agent_run_epochs_tool_call_idx',
               'agent_run_epochs_agent_revision_idx',
               'agent_run_epochs_agent_created_idx',
               'agent_execution_events_digest_idx',
               'agent_execution_events_epoch_idx',
               'agent_execution_events_operation_idx',
               'agent_operation_claims_one_active_idx',
               'agent_operation_claims_one_prepared_holder_idx',
               'agent_operation_claims_prepared_expiry_idx',
               'knowledge_corpus_revisions_account_created_idx',
               'agent_knowledge_contexts_account_created_idx',
               'agent_knowledge_contexts_corpus_idx',
               'agent_turns_knowledge_context_idx',
               'agent_model_jobs_knowledge_context_idx',
               'agent_tool_calls_one_per_model_step_idx',
               'account_knowledge_catalogs_active_corpus_idx',
               'knowledge_catalog_receipts_corpus_idx',
               'agent_prompt_revisions_account_created_idx',
               'account_agent_prompt_configs_active_prompt_idx',
               'agent_prompt_config_receipts_digest_idx',
               'account_reply_provider_configs_provider_idx',
               'account_reply_provider_receipts_provider_idx',
               'session_followups_ready_idx',
               'session_followups_actor_capacity_idx',
               'agent_model_output_chunks_turn_page_idx',
               'agent_model_output_chunks_job_idx'
           )"#,
        [],
        |row| row.get(0),
    )?;
    if point_query_indexes != 77 {
        return Err(StorageError::CorruptData(
            "one or more point-query indexes are missing".into(),
        ));
    }
    let one_tool_call_per_model_step_index: i64 = connection.query_row(
        r#"SELECT EXISTS(
               SELECT 1
               FROM pragma_index_list('agent_tool_calls') AS index_list
               WHERE index_list.name = 'agent_tool_calls_one_per_model_step_idx'
                 AND index_list."unique" = 1
                 AND index_list.partial = 0
                 AND (SELECT COUNT(*)
                      FROM pragma_index_info('agent_tool_calls_one_per_model_step_idx')) = 2
                 AND (SELECT name
                      FROM pragma_index_info('agent_tool_calls_one_per_model_step_idx')
                      WHERE seqno = 0) = 'agent_id'
                 AND (SELECT name
                      FROM pragma_index_info('agent_tool_calls_one_per_model_step_idx')
                      WHERE seqno = 1) = 'model_step'
           )"#,
        [],
        |row| row.get(0),
    )?;
    if one_tool_call_per_model_step_index != 1 {
        return Err(StorageError::CorruptData(
            "Agent tool-call model-step uniqueness is not enforced".into(),
        ));
    }

    let trigger_count: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM sqlite_schema
           WHERE type = 'trigger' AND name IN (
               'account_memberships_enforce_revision',
               'account_memberships_preserve_last_active_owner',
               'account_memberships_reject_delete',
               'account_memberships_reject_duplicate_insert',
               'accounts_reject_delete',
               'accounts_reject_duplicate_insert',
               'accounts_reject_identity_update',
               'auth_sessions_reject_duplicate_insert',
               'auth_sessions_reject_update',
               'auth_sessions_require_current_membership',
               'bootstrap_audit_rollup_enforce_update',
               'bootstrap_audit_rollup_reject_delete',
               'bootstrap_tokens_enforce_terminal_transition',
               'bootstrap_tokens_reject_uncommitted_delete',
               'bootstrap_tokens_require_next_sequence',
               'dispatch_jobs_enforce_forward_transition',
               'dispatch_jobs_reject_delete',
               'dispatch_jobs_reject_input_update',
               'dispatch_jobs_require_authority',
               'event_payload_usage_enforce_monotonic_update',
               'event_payload_usage_reject_delete',
               'event_payload_usage_reject_duplicate_insert',
               'finalization_reservations_enforce_update',
               'finalization_reservations_reject_live_delete',
               'finalization_reservations_require_authority',
               'finalization_reservations_require_event_payload_capacity_on_insert',
               'idempotency_receipts_reject_delete',
               'idempotency_receipts_reject_update',
               'idempotency_receipts_require_authority',
               'incidents_account_is_immutable',
               'incidents_require_account_on_insert',
               'member_setup_tokens_require_pending_member',
               'member_setup_tokens_reject_update',
               'account_audit_events_require_chain',
               'account_audit_events_reject_update',
               'account_audit_events_require_rollup_before_delete',
               'account_audit_rollups_enforce_forward_update',
               'account_audit_rollups_reject_delete',
               'account_audit_policies_enforce_revision',
               'account_audit_policies_reject_delete',
               'account_audit_archive_state_enforce_revision',
               'account_audit_archive_state_reject_delete',
               'reply_jobs_enforce_forward_transition',
               'reply_jobs_reject_delete',
               'reply_jobs_reject_input_update',
               'reply_jobs_require_authority',
               'run_events_charge_payload_bytes',
               'run_events_reject_delete',
               'run_events_reject_update',
               'run_events_require_next_sequence',
               'runs_account_is_immutable',
               'runs_event_payload_bytes_reject_rollback',
               'runs_require_account_on_insert',
               'runs_require_incident_account_on_update',
               'runtime_identity_reject_delete',
               'runtime_identity_reject_update',
               'runtime_identity_require_account_on_insert',
               'session_command_receipts_reject_delete',
               'session_command_receipts_reject_update',
               'session_command_receipts_require_authority',
               'session_events_charge_payload_bytes',
               'session_events_reject_delete',
               'session_events_reject_update',
               'session_events_require_next_sequence',
               'session_runs_reject_delete',
               'session_runs_reject_update',
               'session_runs_require_same_account',
               'session_turns_enforce_terminal_transition',
               'session_turns_reject_delete',
               'session_turns_reject_input_update',
               'sessions_account_is_immutable',
               'sessions_event_payload_bytes_reject_rollback',
               'sessions_owner_is_write_once',
               'sessions_require_account_on_insert',
               'runs_owner_is_write_once',
               'user_preferences_enforce_revision',
               'users_reject_delete_with_history',
               'users_reject_identity_update',
               'agent_turns_reject_identity_update',
               'agent_turns_require_current_authority',
               'agent_turns_enforce_forward_revision',
               'agent_turns_reject_delete',
               'agent_model_jobs_require_current_step',
               'agent_model_jobs_reject_input_update',
               'agent_model_jobs_enforce_forward_transition',
               'agent_model_jobs_reject_delete',
               'agent_tool_calls_require_current_call',
               'agent_tool_calls_enforce_forward_transition',
               'agent_tool_calls_reject_input_update',
               'agent_tool_calls_freeze_review_binding',
               'agent_tool_calls_require_completion_next_request',
               'agent_tool_calls_freeze_completion_next_request',
               'agent_model_jobs_bind_tool_completion_request',
               'agent_tool_calls_reject_delete',
               'agent_review_receipts_require_current_owner',
               'agent_review_receipts_reject_update',
               'agent_review_receipts_reject_delete',
               'agent_deployment_manifests_reject_update',
               'agent_deployment_manifests_reject_delete',
               'agent_turns_require_deployment_manifest',
               'agent_run_epochs_require_release_binding',
               'agent_run_epochs_reject_update',
               'agent_run_epochs_reject_delete',
               'agent_execution_events_reject_update',
               'agent_execution_events_reject_delete',
               'agent_execution_events_require_next_sequence',
               'agent_execution_events_require_chain',
               'agent_execution_events_require_epoch_binding',
               'agent_execution_heads_require_origin',
               'agent_execution_heads_enforce_forward_update',
               'agent_execution_heads_reject_delete',
               'agent_operation_claims_require_operation_binding',
               'agent_operation_claims_require_next_generation',
               'agent_operation_claims_reject_identity_update',
               'agent_operation_claims_enforce_forward_transition',
               'agent_operation_claims_reject_delete',
               'knowledge_corpus_revisions_reject_update',
               'knowledge_corpus_revisions_reject_delete',
               'agent_knowledge_contexts_reject_update',
               'agent_knowledge_contexts_reject_delete',
               'agent_knowledge_legacy_boundary_reject_insert',
               'agent_knowledge_legacy_boundary_reject_update',
               'agent_knowledge_legacy_boundary_reject_delete',
               'agent_knowledge_legacy_agents_reject_insert',
               'agent_knowledge_legacy_agents_reject_update',
               'agent_knowledge_legacy_agents_reject_delete',
               'agent_turns_require_knowledge_context',
               'account_knowledge_catalogs_require_current_owner',
               'account_knowledge_catalogs_enforce_revision',
               'account_knowledge_catalogs_reject_delete',
               'knowledge_catalog_receipts_require_current_owner',
               'knowledge_catalog_receipts_reject_update',
               'knowledge_catalog_receipts_reject_delete',
               'agent_prompt_revisions_reject_update',
               'agent_prompt_revisions_reject_delete',
               'account_agent_prompt_configs_require_current_owner',
               'account_agent_prompt_configs_enforce_revision',
               'account_agent_prompt_configs_reject_delete',
               'agent_prompt_config_receipts_require_current_owner',
               'agent_prompt_config_receipts_reject_update',
               'agent_prompt_config_receipts_reject_delete',
               'account_reply_provider_configs_require_current_owner',
               'account_reply_provider_configs_enforce_revision',
               'account_reply_provider_configs_reject_delete',
               'account_reply_provider_receipts_require_current_owner',
               'account_reply_provider_receipts_reject_update',
               'account_reply_provider_receipts_reject_delete',
               'session_compaction_jobs_validate_insert',
               'session_compaction_jobs_reject_identity_update',
               'session_compaction_jobs_enforce_transition',
               'session_compaction_jobs_reject_delete',
               'agent_todo_snapshots_validate_insert',
               'agent_todo_snapshots_reject_update',
               'agent_todo_snapshots_reject_delete',
               'agent_tool_calls_bind_todo_snapshot',
               'agent_goal_snapshots_validate_insert',
               'agent_goal_snapshots_reject_update',
               'agent_goal_snapshots_reject_delete',
               'agent_tool_calls_bind_goal_snapshot',
               'agent_goal_rounds_validate_insert',
               'agent_goal_rounds_reject_update',
               'agent_goal_rounds_reject_delete',
               'session_followups_validate_insert',
               'session_followups_enforce_transition',
               'session_followups_reject_delete',
               'session_followup_receipts_require_authority',
               'session_followup_receipts_reject_update',
               'session_followup_receipts_reject_delete',
               'agent_model_output_chunks_validate_insert',
               'agent_model_output_chunks_reject_update',
               'agent_model_output_chunks_reject_delete',
               'schema_migrations_reject_update',
               'schema_migrations_reject_delete'
           )"#,
        [],
        |row| row.get(0),
    )?;
    if trigger_count != 173 {
        return Err(StorageError::CorruptData(
            "one or more durability triggers are missing".into(),
        ));
    }
    verify_migration_trigger_definitions(connection, MIGRATION_0022, MIGRATION_0022_TRIGGER_NAMES)?;
    verify_migration_trigger_definitions(connection, MIGRATION_0023, MIGRATION_0023_TRIGGER_NAMES)?;
    verify_migration_trigger_definitions(connection, MIGRATION_0024, MIGRATION_0024_TRIGGER_NAMES)?;
    verify_migration_trigger_definitions(connection, MIGRATION_0025, MIGRATION_0025_TRIGGER_NAMES)?;
    verify_migration_trigger_definitions(connection, MIGRATION_0026, MIGRATION_0026_TRIGGER_NAMES)?;
    verify_migration_trigger_definitions(connection, MIGRATION_0027, MIGRATION_0027_TRIGGER_NAMES)?;
    verify_migration_trigger_definitions(connection, MIGRATION_0028, MIGRATION_0028_TRIGGER_NAMES)?;
    verify_migration_trigger_definitions(connection, MIGRATION_0029, MIGRATION_0029_TRIGGER_NAMES)?;
    verify_migration_trigger_definitions(connection, MIGRATION_0030, MIGRATION_0030_TRIGGER_NAMES)?;
    verify_migration_trigger_definitions(connection, MIGRATION_0031, MIGRATION_0031_TRIGGER_NAMES)?;
    verify_migration_trigger_definitions(connection, MIGRATION_0032, MIGRATION_0032_TRIGGER_NAMES)?;
    verify_session_followup_integrity(connection)?;

    let agent_pending_call_fk: i64 = connection.query_row(
        r#"SELECT COUNT(*)
           FROM pragma_foreign_key_list('agent_turns') left_column
           JOIN pragma_foreign_key_list('agent_turns') right_column
             ON right_column.id = left_column.id
           WHERE left_column."table" = 'agent_tool_calls'
             AND left_column."from" = 'id' AND left_column."to" = 'agent_id'
             AND right_column."from" = 'pending_call_id'
             AND right_column."to" = 'call_id'"#,
        [],
        |row| row.get(0),
    )?;
    if agent_pending_call_fk != 1 {
        return Err(StorageError::CorruptData(
            "the Agent pending-call composite foreign key is missing".into(),
        ));
    }

    let agent_manifest_fk: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM pragma_foreign_key_list('agent_turns')
           WHERE "table" = 'agent_deployment_manifests'
             AND "from" = 'deployment_manifest_digest'
             AND "to" = 'digest'
             AND on_delete = 'RESTRICT'"#,
        [],
        |row| row.get(0),
    )?;
    if agent_manifest_fk != 1 {
        return Err(StorageError::CorruptData(
            "the Agent deployment manifest foreign key is missing".into(),
        ));
    }

    let agent_knowledge_binding_fks: i64 = connection.query_row(
        r#"SELECT
               (SELECT COUNT(*) FROM pragma_foreign_key_list('agent_turns')
                WHERE "table" = 'agent_knowledge_contexts'
                  AND "from" = 'knowledge_context_digest'
                  AND "to" = 'digest'
                  AND on_delete = 'RESTRICT')
             + (SELECT COUNT(*) FROM pragma_foreign_key_list('agent_model_jobs')
                WHERE "table" = 'agent_knowledge_contexts'
                  AND "from" = 'knowledge_context_digest'
                  AND "to" = 'digest'
                  AND on_delete = 'RESTRICT')"#,
        [],
        |row| row.get(0),
    )?;
    if agent_knowledge_binding_fks != 2 {
        return Err(StorageError::CorruptData(
            "one or more Agent knowledge binding foreign keys are missing".into(),
        ));
    }

    let agent_knowledge_direct_fks: i64 = connection.query_row(
        r#"SELECT
               (SELECT COUNT(*) FROM pragma_foreign_key_list('knowledge_corpus_revisions')
                WHERE "table" = 'accounts'
                  AND "from" = 'account_id' AND "to" = 'id'
                  AND on_delete = 'RESTRICT')
             + (SELECT COUNT(*) FROM pragma_foreign_key_list('agent_knowledge_contexts')
                WHERE "table" = 'accounts'
                  AND "from" = 'account_id' AND "to" = 'id'
                  AND on_delete = 'RESTRICT')
             + (SELECT COUNT(*) FROM pragma_foreign_key_list('agent_knowledge_contexts')
                WHERE "table" = 'users'
                  AND "from" = 'actor_user_id' AND "to" = 'id'
                  AND on_delete = 'RESTRICT')"#,
        [],
        |row| row.get(0),
    )?;
    if agent_knowledge_direct_fks != 3 {
        return Err(StorageError::CorruptData(
            "one or more Agent knowledge authority foreign keys are missing".into(),
        ));
    }

    let agent_knowledge_legacy_fks: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM pragma_foreign_key_list('agent_knowledge_legacy_agents')
           WHERE ("table" = 'agent_turns'
                  AND "from" = 'agent_id' AND "to" = 'id'
                  AND on_delete = 'RESTRICT')
              OR ("table" = 'agent_model_jobs'
                  AND "from" = 'initial_model_job_id' AND "to" = 'id'
                  AND on_delete = 'RESTRICT')"#,
        [],
        |row| row.get(0),
    )?;
    if agent_knowledge_legacy_fks != 2 {
        return Err(StorageError::CorruptData(
            "the frozen legacy Agent knowledge boundary foreign keys are missing".into(),
        ));
    }

    let agent_knowledge_composite_fks: i64 = connection.query_row(
        r#"SELECT
               (SELECT COUNT(*)
                FROM pragma_foreign_key_list('agent_knowledge_contexts') account_column
                JOIN pragma_foreign_key_list('agent_knowledge_contexts') digest_column
                  ON digest_column.id = account_column.id
                WHERE account_column."table" = 'knowledge_corpus_revisions'
                  AND account_column."from" = 'account_id'
                  AND account_column."to" = 'account_id'
                  AND digest_column."from" = 'corpus_digest'
                  AND digest_column."to" = 'digest'
                  AND account_column.on_delete = 'RESTRICT'
                  AND digest_column.on_delete = 'RESTRICT')
             + (SELECT COUNT(*)
                FROM pragma_foreign_key_list('agent_knowledge_contexts') account_column
                JOIN pragma_foreign_key_list('agent_knowledge_contexts') identity_column
                  ON identity_column.id = account_column.id
                WHERE account_column."table" = 'account_memberships'
                  AND account_column."from" = 'account_id'
                  AND account_column."to" = 'account_id'
                  AND identity_column."from" = 'actor_user_id'
                  AND identity_column."to" = 'user_id'
                  AND account_column.on_delete = 'RESTRICT'
                  AND identity_column.on_delete = 'RESTRICT')
             + (SELECT COUNT(*)
                FROM pragma_foreign_key_list('agent_knowledge_contexts') account_column
                JOIN pragma_foreign_key_list('agent_knowledge_contexts') identity_column
                  ON identity_column.id = account_column.id
                WHERE account_column."table" = 'sessions'
                  AND account_column."from" = 'account_id'
                  AND account_column."to" = 'account_id'
                  AND identity_column."from" = 'session_id'
                  AND identity_column."to" = 'id'
                  AND account_column.on_delete = 'RESTRICT'
                  AND identity_column.on_delete = 'RESTRICT')
             + (SELECT COUNT(*)
                FROM pragma_foreign_key_list('agent_knowledge_contexts') session_column
                JOIN pragma_foreign_key_list('agent_knowledge_contexts') turn_column
                  ON turn_column.id = session_column.id
                WHERE session_column."table" = 'session_turns'
                  AND session_column."from" = 'session_id'
                  AND session_column."to" = 'session_id'
                  AND turn_column."from" = 'turn_id'
                  AND turn_column."to" = 'id'
                  AND session_column.on_delete = 'RESTRICT'
                  AND turn_column.on_delete = 'RESTRICT')"#,
        [],
        |row| row.get(0),
    )?;
    if agent_knowledge_composite_fks != 4 {
        return Err(StorageError::CorruptData(
            "one or more Agent knowledge composite foreign keys are missing".into(),
        ));
    }

    let agent_operation_claim_fks: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM pragma_foreign_key_list('agent_operation_claims')
           WHERE ("table" = 'agent_model_jobs'
                  AND "from" = 'model_job_id' AND "to" = 'id'
                  AND on_delete = 'RESTRICT')
              OR ("table" = 'agent_tool_calls'
                  AND "from" = 'tool_call_id' AND "to" = 'call_id'
                  AND on_delete = 'RESTRICT')
              OR ("table" = 'agent_turns'
                  AND "from" = 'agent_id' AND "to" = 'id'
                  AND on_delete = 'RESTRICT')"#,
        [],
        |row| row.get(0),
    )?;
    if agent_operation_claim_fks != 3 {
        return Err(StorageError::CorruptData(
            "one or more Agent operation claim foreign keys are missing".into(),
        ));
    }

    let agent_todo_fks: i64 = connection.query_row(
        r#"SELECT COUNT(DISTINCT "table" || ':' || "from" || ':' || "to")
           FROM pragma_foreign_key_list('agent_todo_snapshots')
           WHERE ("table" = 'agent_turns' AND "from" = 'agent_id'
                  AND "to" = 'id' AND on_delete = 'RESTRICT')
              OR ("table" = 'agent_tool_calls' AND "from" = 'call_id'
                  AND "to" = 'call_id' AND on_delete = 'RESTRICT')"#,
        [],
        |row| row.get(0),
    )?;
    if agent_todo_fks != 2 {
        return Err(StorageError::CorruptData(
            "one or more Agent todo snapshot foreign keys are missing".into(),
        ));
    }

    let (account_rows, active_local_accounts): (i64, i64) = connection.query_row(
        r#"SELECT COUNT(*),
                  COALESCE(SUM(CASE
                      WHEN id = ?1 AND status = 'active' THEN 1 ELSE 0
                  END), 0)
           FROM accounts"#,
        [LOCAL_ACCOUNT_ID],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if !(1..=MAX_ACCOUNTS_GLOBAL).contains(&account_rows) || active_local_accounts != 1 {
        return Err(StorageError::CorruptData(
            "the bounded account set is empty, oversized, or missing its active local root".into(),
        ));
    }
    let oversized_user_account_set: i64 = connection.query_row(
        r#"SELECT EXISTS(
               SELECT 1 FROM account_memberships
               GROUP BY user_id HAVING COUNT(*) > ?1
           )"#,
        [MAX_ACCOUNTS_PER_USER],
        |row| row.get(0),
    )?;
    if oversized_user_account_set != 0 {
        return Err(StorageError::CorruptData(
            "one or more users exceed the durable account membership ceiling".into(),
        ));
    }

    verify_bootstrap_audit_state(connection, deep_invariants)?;
    verify_account_audit_state(connection, deep_invariants)?;
    if let Some(limits) = audit_admission_limits {
        require_account_audit_capacity_readiness(connection, limits)?;
    }

    if !deep_invariants {
        let (usage_rows, singleton, used_bytes): (i64, i64, i64) = connection.query_row(
            r#"SELECT COUNT(*), COALESCE(MAX(singleton), 0),
                      COALESCE(MAX(used_bytes), -1)
               FROM event_payload_usage"#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if usage_rows != 1 || singleton != 1 || used_bytes < 0 {
            return Err(StorageError::CorruptData(
                "the event payload usage singleton is inconsistent".into(),
            ));
        }
        return Ok(());
    }

    let account_boundary_violation: i64 = connection.query_row(
        r#"SELECT EXISTS(
               SELECT 1
               FROM incidents incident
               WHERE incident.account_id IS NULL
                  OR NOT EXISTS(
                      SELECT 1 FROM accounts account
                      WHERE account.id = incident.account_id
                  )
               UNION ALL
               SELECT 1
               FROM sessions session
               WHERE session.account_id IS NULL
                  OR NOT EXISTS(
                      SELECT 1 FROM accounts account
                      WHERE account.id = session.account_id
                  )
               UNION ALL
               SELECT 1
               FROM runs run
               WHERE run.account_id IS NULL
                  OR NOT EXISTS(
                      SELECT 1 FROM accounts account
                      WHERE account.id = run.account_id
                  )
               UNION ALL
               SELECT 1 FROM runtime_identity WHERE account_id IS NOT ?1
               UNION ALL
               SELECT 1
               FROM runs run
               JOIN incidents incident ON incident.id = run.incident_id
               WHERE run.account_id IS NOT incident.account_id
               UNION ALL
               SELECT 1
               FROM session_runs binding
               JOIN sessions session ON session.id = binding.session_id
               JOIN runs run ON run.id = binding.run_id
               WHERE session.account_id IS NOT run.account_id
               UNION ALL
               SELECT 1
               FROM runtime_identity identity
               JOIN sessions session ON session.id = identity.primary_session_id
               WHERE identity.account_id IS NOT session.account_id
               UNION ALL
               SELECT 1
               FROM runtime_identity identity
               JOIN runs run ON run.id = identity.primary_run_id
               WHERE identity.account_id IS NOT run.account_id
               UNION ALL
               SELECT 1
               FROM runtime_identity identity
               WHERE EXISTS(SELECT 1 FROM runs)
                 AND NOT EXISTS(
                     SELECT 1
                     FROM runs run
                     WHERE run.id = identity.primary_run_id
                       AND run.account_id IS identity.account_id
                 )
               UNION ALL
               SELECT 1
               FROM runtime_identity identity
               JOIN session_runs binding ON binding.run_id = identity.primary_run_id
               WHERE binding.session_id IS NOT identity.primary_session_id
               UNION ALL
               SELECT 1
               WHERE NOT EXISTS(SELECT 1 FROM users)
                 AND EXISTS(SELECT 1 FROM account_memberships)
               UNION ALL
               SELECT 1
               FROM accounts account
               WHERE account.status = 'active'
                 AND EXISTS(SELECT 1 FROM users)
                 AND NOT EXISTS(
                     SELECT 1
                     FROM account_memberships membership
                     JOIN users user ON user.id = membership.user_id
                     WHERE membership.account_id = account.id
                       AND membership.role = 'owner'
                       AND membership.status = 'active'
                       AND user.status = 'active'
                 )
           )"#,
        [LOCAL_ACCOUNT_ID],
        |row| row.get(0),
    )?;
    if account_boundary_violation != 0 {
        return Err(StorageError::CorruptData(
            "one or more durable records cross an account boundary".into(),
        ));
    }

    let event_payload_counter_violation: i64 = connection.query_row(
        r#"SELECT EXISTS(
               SELECT 1
               WHERE (SELECT COUNT(*) FROM event_payload_usage) <> 1
               UNION ALL
               SELECT 1
               FROM event_payload_usage usage
               WHERE usage.singleton <> 1
                  OR usage.used_bytes < 0
                  OR usage.used_bytes <> (
                      COALESCE((SELECT SUM(event_payload_bytes) FROM sessions), 0)
                      + COALESCE((SELECT SUM(event_payload_bytes) FROM runs), 0)
                  )
               UNION ALL
               SELECT 1 FROM sessions WHERE event_payload_bytes < 0
               UNION ALL
               SELECT 1 FROM runs WHERE event_payload_bytes < 0
           )"#,
        [],
        |row| row.get(0),
    )?;
    if event_payload_counter_violation != 0 {
        return Err(StorageError::CorruptData(
            "one or more event payload byte counters are inconsistent".into(),
        ));
    }

    let actor_boundary_violation: i64 = connection.query_row(
        r#"SELECT EXISTS(
               SELECT 1
               FROM reply_jobs j
               JOIN sessions s ON s.id = j.session_id
               WHERE j.account_id IS NOT s.account_id
               UNION ALL
               SELECT 1
               FROM session_command_receipts receipt
               JOIN sessions s ON s.id = receipt.session_id
               WHERE receipt.account_id IS NOT s.account_id
               UNION ALL
               SELECT 1
               FROM idempotency_receipts receipt
               JOIN runs r ON r.id = receipt.run_id
               WHERE receipt.account_id IS NOT r.account_id
               UNION ALL
               SELECT 1
               FROM dispatch_jobs job
               JOIN runs r ON r.id = job.run_id
               WHERE job.account_id IS NOT r.account_id
               UNION ALL
               SELECT 1
               FROM finalization_reservations reservation
               JOIN sessions s ON s.id = reservation.session_id
               WHERE reservation.kind = 'session_turn'
                 AND reservation.account_id IS NOT s.account_id
               UNION ALL
               SELECT 1
               FROM finalization_reservations reservation
               JOIN dispatch_jobs job
                 ON job.call_id = reservation.call_id
                AND job.run_id = reservation.run_id
               WHERE reservation.kind = 'dispatch'
                 AND (reservation.account_id IS NOT job.account_id
                      OR reservation.actor_user_id IS NOT COALESCE(
                          job.initiating_actor_user_id,
                          job.approving_actor_user_id
                      ))
               UNION ALL
               SELECT 1
               FROM agent_turns agent
               JOIN sessions session ON session.id = agent.session_id
               JOIN session_turns turn ON turn.id = agent.turn_id
               WHERE agent.account_id IS NOT session.account_id
                  OR turn.session_id IS NOT agent.session_id
               UNION ALL
               SELECT 1
               FROM agent_model_jobs job
               JOIN agent_turns agent ON agent.id = job.agent_id
               WHERE job.account_id IS NOT agent.account_id
                  OR job.actor_user_id IS NOT agent.actor_user_id
                  OR job.actor_membership_revision IS NOT agent.actor_membership_revision
                  OR job.session_id IS NOT agent.session_id
                  OR job.turn_id IS NOT agent.turn_id
                  OR job.provider_name IS NOT agent.provider_name
                  OR job.model_name IS NOT agent.model_name
                  OR job.knowledge_context_digest IS NOT agent.knowledge_context_digest
               UNION ALL
               SELECT 1
               FROM agent_knowledge_contexts context
               LEFT JOIN agent_turns agent
                 ON agent.id = context.agent_id
               LEFT JOIN agent_model_jobs initial_job
                 ON initial_job.id = context.initial_model_job_id
               WHERE agent.id IS NULL
                  OR initial_job.id IS NULL
                  OR agent.account_id IS NOT context.account_id
                  OR agent.actor_user_id IS NOT context.actor_user_id
                  OR agent.actor_membership_revision
                     IS NOT context.actor_membership_revision
                  OR agent.session_id IS NOT context.session_id
                  OR agent.turn_id IS NOT context.turn_id
                  OR agent.knowledge_context_digest IS NOT context.digest
                  OR agent.created_at IS NOT context.created_at
                  OR initial_job.agent_id IS NOT context.agent_id
                  OR initial_job.account_id IS NOT context.account_id
                  OR initial_job.actor_user_id IS NOT context.actor_user_id
                  OR initial_job.actor_membership_revision
                     IS NOT context.actor_membership_revision
                  OR initial_job.session_id IS NOT context.session_id
                  OR initial_job.turn_id IS NOT context.turn_id
                  OR initial_job.step <> 1
                  OR initial_job.knowledge_context_digest IS NOT context.digest
                  OR initial_job.queued_at IS NOT context.created_at
               UNION ALL
               SELECT 1
               FROM agent_tool_calls call
               JOIN agent_turns agent ON agent.id = call.agent_id
               WHERE call.account_id IS NOT agent.account_id
                  OR call.session_id IS NOT agent.session_id
                  OR call.turn_id IS NOT agent.turn_id
                  OR call.ordinal > agent.tool_calls
                  OR call.model_step > agent.model_steps
               UNION ALL
               SELECT 1
               FROM agent_review_receipts receipt
               JOIN agent_tool_calls call ON call.call_id = receipt.call_id
               WHERE receipt.account_id IS NOT call.account_id
                  OR receipt.actor_user_id IS NOT call.approving_actor_user_id
                  OR receipt.actor_membership_revision
                     IS NOT call.approving_membership_revision
               UNION ALL
               SELECT 1
               FROM agent_turns agent
               LEFT JOIN agent_tool_calls call
                 ON call.agent_id = agent.id AND call.call_id = agent.pending_call_id
               WHERE (agent.status = 'waiting_approval'
                      AND (call.status IS NULL OR call.status <> 'waiting_approval'))
                  OR (agent.status = 'tool_queued'
                      AND (call.status IS NULL OR call.status <> 'queued'))
                  OR (agent.status = 'tool_running'
                      AND (call.status IS NULL OR call.status <> 'started'))
           )"#,
        [],
        |row| row.get(0),
    )?;
    if actor_boundary_violation != 0 {
        return Err(StorageError::CorruptData(
            "one or more durable records cross an actor ownership boundary".into(),
        ));
    }

    let agent_operation_claim_violation: i64 = connection.query_row(
        r#"SELECT EXISTS(
               SELECT 1
               FROM agent_operation_claims claim
               LEFT JOIN agent_model_jobs model ON model.id = claim.model_job_id
               LEFT JOIN agent_tool_calls tool ON tool.call_id = claim.tool_call_id
               WHERE CASE claim.operation_kind
                   WHEN 'model' THEN claim.model_job_id IS NOT claim.operation_id
                       OR claim.tool_call_id IS NOT NULL
                       OR model.agent_id IS NOT claim.agent_id
                       OR (claim.phase = 'prepared' AND model.status <> 'queued')
                       OR (claim.phase = 'started' AND model.status <> 'started')
                   WHEN 'tool' THEN claim.model_job_id IS NOT NULL
                       OR claim.tool_call_id IS NOT claim.operation_id
                       OR tool.agent_id IS NOT claim.agent_id
                       OR (claim.phase = 'prepared' AND tool.status <> 'queued')
                       OR (claim.phase = 'started' AND tool.status <> 'started')
                   ELSE 1
               END
               UNION ALL
               SELECT 1
               FROM agent_operation_claims claim
               GROUP BY claim.operation_kind, claim.operation_id
               HAVING MIN(claim.generation) <> 1
                   OR MAX(claim.generation) <> COUNT(*)
                   OR SUM(claim.phase IN ('prepared', 'started')) > 1
               UNION ALL
               SELECT 1
               FROM agent_operation_claims claim
               WHERE NOT (
                   (claim.phase = 'prepared'
                    AND claim.started_at IS NULL AND claim.released_at IS NULL)
                   OR
                   (claim.phase = 'started'
                    AND claim.started_at IS NOT NULL AND claim.released_at IS NULL)
                   OR
                   (claim.phase = 'released' AND claim.released_at IS NOT NULL)
                   OR
                   (claim.phase = 'expired'
                    AND claim.started_at IS NULL AND claim.released_at IS NOT NULL)
               )
               UNION ALL
               SELECT 1
               FROM agent_model_jobs model
               WHERE model.status = 'started'
                 AND NOT EXISTS (
                     SELECT 1 FROM agent_operation_claims claim
                     WHERE claim.operation_kind = 'model'
                       AND claim.operation_id = model.id
                       AND claim.phase = 'started'
                 )
               UNION ALL
               SELECT 1
               FROM agent_tool_calls tool
               WHERE tool.status = 'started'
                 AND NOT EXISTS (
                     SELECT 1 FROM agent_operation_claims claim
                     WHERE claim.operation_kind = 'tool'
                       AND claim.operation_id = tool.call_id
                       AND claim.phase = 'started'
                 )
           )"#,
        [],
        |row| row.get(0),
    )?;
    if agent_operation_claim_violation != 0 {
        return Err(StorageError::CorruptData(
            "one or more Agent operation claims are inconsistent".into(),
        ));
    }

    let agent_tool_completion_binding_violation: i64 = connection.query_row(
        r#"SELECT EXISTS(
               SELECT 1
               FROM agent_tool_calls call
               LEFT JOIN agent_model_jobs next_job
                 ON next_job.agent_id = call.agent_id
                AND next_job.step = call.model_step + 1
               WHERE (
                   call.completion_next_request_json IS NOT NULL
                   AND (
                       call.status NOT IN (
                           'succeeded', 'failed', 'cancelled', 'not_dispatched'
                       )
                       OR call.policy_decision NOT IN ('allow', 'require_approval')
                       OR call.started_at IS NULL
                       OR call.finished_at IS NULL
                       OR call.result_json IS NULL
                       OR CASE
                           WHEN json_valid(call.completion_next_request_json) = 0 THEN 1
                           WHEN json_type(call.completion_next_request_json)
                                NOT IN ('object', 'null') THEN 1
                           ELSE 0
                       END = 1
                   )
               )
               OR (
                   call.status IN ('succeeded', 'failed', 'cancelled', 'not_dispatched')
                   AND call.policy_decision IN ('allow', 'require_approval')
                   AND call.started_at IS NOT NULL
                   AND next_job.id IS NOT NULL
                   AND CASE
                       WHEN call.completion_next_request_json IS NULL THEN 1
                       WHEN json_valid(call.completion_next_request_json) = 0 THEN 1
                       WHEN json_type(call.completion_next_request_json) <> 'object' THEN 1
                       WHEN call.completion_next_request_json IS NOT next_job.request_json THEN 1
                       ELSE 0
                   END = 1
               )
           )"#,
        [],
        |row| row.get(0),
    )?;
    if agent_tool_completion_binding_violation != 0 {
        return Err(StorageError::CorruptData(
            "one or more Agent tool completion replay bindings are inconsistent".into(),
        ));
    }
    agent::verify_agent_deployment_manifest_integrity(connection)?;
    agent::verify_agent_knowledge_context_integrity(connection)?;
    agent::verify_account_knowledge_catalog_integrity(connection)?;
    agent::verify_account_agent_prompt_integrity(connection)?;
    agent::verify_agent_todo_integrity(connection)?;
    agent::verify_agent_goal_integrity(connection)?;
    agent::verify_agent_goal_round_integrity(connection)?;
    agent::verify_agent_model_output_integrity(connection)?;
    provider::verify_account_reply_provider_integrity(connection)?;
    compaction::verify_integrity(connection)?;
    execution::verify_agent_execution_integrity(connection)?;
    let (user_count, ownerless_active_accounts): (i64, i64) = connection.query_row(
        r#"SELECT (SELECT COUNT(*) FROM users),
                  (SELECT COUNT(*) FROM accounts account
                   WHERE account.status = 'active'
                     AND NOT EXISTS(
                         SELECT 1
                         FROM account_memberships membership
                         JOIN users user ON user.id = membership.user_id
                         WHERE membership.account_id = account.id
                           AND membership.role = 'owner'
                           AND membership.status = 'active'
                           AND user.status = 'active'))"#,
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if user_count != 0 && ownerless_active_accounts != 0 {
        return Err(StorageError::CorruptData(
            "every active account in a configured database must retain an active owner".into(),
        ));
    }
    let configured_legacy_boundary: i64 = connection.query_row(
        r#"SELECT EXISTS(SELECT 1 FROM users)
           AND EXISTS(
               SELECT 1 FROM session_command_receipts WHERE actor_user_id IS NULL
               UNION ALL
               SELECT 1 FROM idempotency_receipts WHERE actor_user_id IS NULL
               UNION ALL
               SELECT 1 FROM dispatch_jobs
               WHERE approving_actor_user_id IS NULL
               UNION ALL
               SELECT 1 FROM finalization_reservations WHERE actor_user_id IS NULL
           )"#,
        [],
        |row| row.get(0),
    )?;
    if configured_legacy_boundary != 0 {
        return Err(StorageError::CorruptData(
            "configured database still contains unclaimed legacy actor state".into(),
        ));
    }

    let finalization_violation: i64 = connection.query_row(
        r#"WITH session_expected AS (
               SELECT
                   turn.session_id,
                   turn.id AS turn_id,
                   CASE
                       WHEN length(CAST(turn.id AS BLOB))
                            > ((9223372036854775807 - 524288) / 6) / 2
                       THEN 9223372036854775807
                       ELSE CASE
                           WHEN length(CAST(COALESCE(job.provider_name, agent.provider_name, '') AS BLOB))
                                > (9223372036854775807 - 524288) / 6
                                  - 2 * length(CAST(turn.id AS BLOB))
                           THEN 9223372036854775807
                           ELSE CASE
                               WHEN length(CAST(COALESCE(job.model_name, agent.model_name, '') AS BLOB))
                                    > (9223372036854775807 - 524288) / 6
                                      - 2 * length(CAST(turn.id AS BLOB))
                                      - length(CAST(COALESCE(job.provider_name, agent.provider_name, '') AS BLOB))
                               THEN 9223372036854775807
                               ELSE 524288 + 6 * (
                                   2 * length(CAST(turn.id AS BLOB))
                                   + length(CAST(COALESCE(job.provider_name, agent.provider_name, '') AS BLOB))
                                   + length(CAST(COALESCE(job.model_name, agent.model_name, '') AS BLOB))
                               )
                           END
                       END
                   END AS expected_bytes
               FROM session_turns turn
               LEFT JOIN reply_jobs job
                 ON job.session_id = turn.session_id
                AND job.turn_id = turn.id
               LEFT JOIN agent_turns agent
                 ON agent.session_id = turn.session_id
                AND agent.turn_id = turn.id
           ),
           dispatch_expected AS (
               SELECT
                   job.run_id,
                   job.call_id,
                   CASE job.status
                       WHEN 'queued' THEN CASE
                           WHEN length(CAST(job.call_id AS BLOB))
                                > (9223372036854775807 - 98304) / 12
                           THEN 9223372036854775807
                           ELSE 98304 + 12 * length(CAST(job.call_id AS BLOB))
                       END
                       WHEN 'started' THEN CASE
                           WHEN length(CAST(job.call_id AS BLOB))
                                > (9223372036854775807 - 65536) / 6
                           THEN 9223372036854775807
                           ELSE 65536 + 6 * length(CAST(job.call_id AS BLOB))
                       END
                   END AS expected_bytes
               FROM dispatch_jobs job
           )
           SELECT EXISTS(
               SELECT 1
               FROM session_turns t
               JOIN session_expected expected
                 ON expected.session_id = t.session_id
                AND expected.turn_id = t.id
               LEFT JOIN finalization_reservations reservation
                 ON reservation.kind = 'session_turn'
                AND reservation.session_id = t.session_id
                AND reservation.turn_id = t.id
               WHERE (t.status = 'open' AND (
                         reservation.remaining_event_slots IS NOT 2
                         OR reservation.remaining_event_payload_bytes
                            IS NOT expected.expected_bytes
                     ))
                  OR (t.status <> 'open' AND reservation.turn_id IS NOT NULL)
               UNION ALL
               SELECT 1
               FROM reply_jobs reply
               JOIN agent_turns agent
                 ON agent.session_id = reply.session_id
                AND agent.turn_id = reply.turn_id
               UNION ALL
               SELECT 1
               FROM dispatch_jobs job
               JOIN dispatch_expected expected
                 ON expected.run_id = job.run_id
                AND expected.call_id = job.call_id
               LEFT JOIN finalization_reservations reservation
                 ON reservation.kind = 'dispatch'
                AND reservation.run_id = job.run_id
                AND reservation.call_id = job.call_id
               WHERE (job.status = 'queued' AND (
                         reservation.remaining_event_slots IS NOT 2
                         OR reservation.remaining_event_payload_bytes
                            IS NOT expected.expected_bytes
                     ))
                  OR (job.status = 'started' AND (
                         reservation.remaining_event_slots IS NOT 1
                         OR reservation.remaining_event_payload_bytes
                            IS NOT expected.expected_bytes
                     ))
                  OR (job.status IN ('finished', 'rejected') AND reservation.call_id IS NOT NULL)
               UNION ALL
               SELECT 1
               FROM finalization_reservations
               WHERE remaining_event_slots <= 0
                  OR remaining_event_payload_bytes <= 0
                  OR reserved_bytes IS NOT NULL
           )"#,
        [],
        |row| row.get(0),
    )?;
    if finalization_violation != 0 {
        return Err(StorageError::CorruptData(
            "one or more durable finalization reservations are inconsistent".into(),
        ));
    }

    Ok(())
}

fn verify_bootstrap_audit_state(
    connection: &Connection,
    deep_invariants: bool,
) -> Result<(), StorageError> {
    let rollup_rows: i64 =
        connection.query_row("SELECT COUNT(*) FROM bootstrap_audit_rollup", [], |row| {
            row.get(0)
        })?;
    if rollup_rows != 1 {
        return Err(StorageError::CorruptData(
            "the bootstrap audit rollup singleton is missing or duplicated".into(),
        ));
    }
    let (singleton, through_sequence, digest): (i64, i64, String) = connection.query_row(
        r#"SELECT singleton, through_sequence, digest
           FROM bootstrap_audit_rollup"#,
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if singleton != 1
        || through_sequence < 0
        || !is_lower_hex_digest(&digest)
        || (through_sequence == 0 && digest != BOOTSTRAP_AUDIT_ZERO_DIGEST)
        || (through_sequence > 0 && digest == BOOTSTRAP_AUDIT_ZERO_DIGEST)
    {
        return Err(StorageError::CorruptData(
            "the bootstrap audit rollup is structurally inconsistent".into(),
        ));
    }

    let boundary_violation: i64 = connection.query_row(
        r#"SELECT EXISTS(
               SELECT 1 FROM bootstrap_tokens
               WHERE sequence <= ?1
               UNION ALL
               SELECT 1
               FROM bootstrap_tokens token
               WHERE token.terminal_at IS NULL
                 AND token.sequence <> (SELECT MAX(sequence) FROM bootstrap_tokens)
           )"#,
        [through_sequence],
        |row| row.get(0),
    )?;
    if boundary_violation != 0 {
        return Err(StorageError::CorruptData(
            "the bootstrap audit detailed window crosses its rollup boundary".into(),
        ));
    }

    if deep_invariants {
        let (count, first, last): (i64, i64, i64) = connection.query_row(
            r#"SELECT COUNT(*), COALESCE(MIN(sequence), 0), COALESCE(MAX(sequence), 0)
               FROM bootstrap_tokens"#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let expected_first = through_sequence
            .checked_add(1)
            .ok_or_else(|| StorageError::CorruptData("bootstrap audit sequence overflow".into()))?;
        let expected_count = last.checked_sub(through_sequence).ok_or_else(|| {
            StorageError::CorruptData("bootstrap audit sequence precedes its rollup".into())
        })?;
        if (count == 0 && (first != 0 || last != 0))
            || (count > 0 && (first != expected_first || count != expected_count))
        {
            return Err(StorageError::CorruptData(
                "the bootstrap audit detailed sequence is not contiguous with its rollup".into(),
            ));
        }
    }
    Ok(())
}

fn verify_account_audit_state(
    connection: &Connection,
    deep_invariants: bool,
) -> Result<(), StorageError> {
    let account_count: i64 =
        connection.query_row("SELECT COUNT(*) FROM accounts", [], |row| row.get(0))?;
    let singleton_counts: (i64, i64, i64) = connection.query_row(
        r#"SELECT
               (SELECT COUNT(*) FROM account_audit_rollups),
               (SELECT COUNT(*) FROM account_audit_policies),
               (SELECT COUNT(*) FROM account_audit_archive_state)"#,
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if singleton_counts != (account_count, account_count, account_count) {
        return Err(StorageError::CorruptData(
            "account audit singleton rows do not match the account set".into(),
        ));
    }

    let setup_token_violation: i64 = connection.query_row(
        r#"SELECT EXISTS(
               SELECT 1
               FROM member_setup_tokens token
               JOIN users user ON user.id = token.user_id
               JOIN accounts account ON account.id = token.account_id
               JOIN account_memberships membership
                 ON membership.account_id = token.account_id
                AND membership.user_id = token.user_id
               WHERE account.status <> 'active'
                  OR membership.role <> 'member'
                  OR membership.status <> 'active'
                  OR user.status <> 'disabled'
                  OR EXISTS (
                      SELECT 1 FROM user_preferences preference
                      WHERE preference.user_id = token.user_id
                  )
                  OR unixepoch(token.expires_at) - unixepoch(token.created_at) <> ?1
           )"#,
        [MEMBER_SETUP_TOKEN_TTL_SECONDS],
        |row| row.get(0),
    )?;
    if setup_token_violation != 0 {
        return Err(StorageError::CorruptData(
            "one or more member setup tokens cross their pending-member boundary".into(),
        ));
    }

    let global_rows: i64 =
        connection.query_row("SELECT COUNT(*) FROM account_audit_events", [], |row| {
            row.get(0)
        })?;
    if global_rows > capacity_limit(StorageLimits::HARD_CEILINGS.account_audit_rows_global)? {
        return Err(StorageError::CorruptData(
            "account audit detail exceeds the global hard ceiling".into(),
        ));
    }

    let mut account_statement = connection.prepare("SELECT id FROM accounts ORDER BY id")?;
    let account_ids = account_statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(account_statement);
    for account_id in account_ids {
        let (through_sequence, event_count, digest, last_event_hash): (i64, i64, String, String) =
            connection.query_row(
                r#"SELECT through_sequence, event_count, digest, last_event_hash
               FROM account_audit_rollups WHERE account_id = ?1"#,
                [&account_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )?;
        let (detail_rows, legal_hold, archive_required): (i64, i64, i64) = connection.query_row(
            r#"SELECT detail_rows, legal_hold, archive_required
                   FROM account_audit_policies WHERE account_id = ?1"#,
            [&account_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let (archive_through, archive_hash, archive_reference): (i64, String, Option<String>) =
            connection.query_row(
                r#"SELECT through_sequence, event_hash, archive_reference
               FROM account_audit_archive_state WHERE account_id = ?1"#,
                [&account_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
        if through_sequence < 0
            || through_sequence != event_count
            || !is_lower_hex_digest(&digest)
            || !is_lower_hex_digest(&last_event_hash)
            || (through_sequence == 0
                && (digest != ACCOUNT_AUDIT_ZERO_DIGEST
                    || last_event_hash != ACCOUNT_AUDIT_ZERO_DIGEST))
            || !(1..=capacity_limit(StorageLimits::HARD_CEILINGS.account_audit_detail_rows)?)
                .contains(&detail_rows)
            || !matches!(legal_hold, 0 | 1)
            || !matches!(archive_required, 0 | 1)
            || archive_through < 0
            || !is_lower_hex_digest(&archive_hash)
            || (archive_through == 0
                && (archive_hash != ACCOUNT_AUDIT_ZERO_DIGEST || archive_reference.is_some()))
            || (archive_through > 0 && archive_reference.is_none())
        {
            return Err(StorageError::CorruptData(format!(
                "account audit roots are structurally inconsistent for `{account_id}`"
            )));
        }

        let sql = format!(
            r#"{ACCOUNT_AUDIT_EVENT_SELECT}
               WHERE account_id = ?1 ORDER BY sequence"#
        );
        let mut event_statement = connection.prepare(&sql)?;
        let rows = event_statement
            .query_map([&account_id], decode_account_audit_event_row)?
            .collect::<Result<Vec<_>, _>>()?;
        drop(event_statement);
        if rows.len() > StorageLimits::HARD_CEILINGS.account_audit_rows_per_account {
            return Err(StorageError::CorruptData(format!(
                "account audit detail exceeds the account hard ceiling for `{account_id}`"
            )));
        }
        let mut expected_sequence = through_sequence
            .checked_add(1)
            .ok_or(StorageError::IntegerOutOfRange("account audit sequence"))?;
        let mut expected_previous_hash = last_event_hash.clone();
        for row in &rows {
            if row.sequence != expected_sequence
                || row.previous_hash != expected_previous_hash
                || row.account_id != account_id
            {
                return Err(StorageError::CorruptData(format!(
                    "account audit detailed chain is not contiguous for `{account_id}`"
                )));
            }
            let metadata: Value = serde_json::from_str(&row.metadata_json)?;
            if !metadata.is_object() {
                return Err(StorageError::CorruptData(format!(
                    "account audit metadata is not an object for `{account_id}`"
                )));
            }
            if deep_invariants {
                let expected_hash = account_audit_event_hash(
                    &row.previous_hash,
                    row.sequence,
                    &row.account_id,
                    row.actor_user_id.as_deref(),
                    &row.action,
                    &row.outcome,
                    &row.target_kind,
                    &row.target_id,
                    &row.metadata_json,
                    &row.occurred_at,
                )?;
                if row.event_hash != expected_hash {
                    return Err(StorageError::CorruptData(format!(
                        "account audit event hash is inconsistent for `{account_id}`"
                    )));
                }
            }
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or(StorageError::IntegerOutOfRange("account audit sequence"))?;
            expected_previous_hash.clone_from(&row.event_hash);
        }
        let tail_sequence = rows.last().map_or(through_sequence, |row| row.sequence);
        if archive_through > tail_sequence
            || (archive_required != 0 && archive_through < through_sequence)
        {
            return Err(StorageError::CorruptData(format!(
                "account audit archive checkpoint exceeds its durable chain for `{account_id}`"
            )));
        }
        if archive_through == through_sequence && archive_hash != last_event_hash {
            return Err(StorageError::CorruptData(format!(
                "account audit archive checkpoint does not match its rollup boundary for `{account_id}`"
            )));
        }
        if archive_through > through_sequence {
            let matching_hash = rows
                .iter()
                .find(|row| row.sequence == archive_through)
                .map(|row| row.event_hash.as_str());
            if matching_hash != Some(archive_hash.as_str()) {
                return Err(StorageError::CorruptData(format!(
                    "account audit archive checkpoint does not match its detailed event for `{account_id}`"
                )));
            }
        }
    }
    Ok(())
}

fn deep_readiness(
    connection: &Connection,
    expects_wal: bool,
    physical_limits: Option<&SqlitePhysicalLimits>,
) -> Result<(), StorageError> {
    readiness(connection, expects_wal, physical_limits, false, true, None)?;

    let exact_payload_counter_violation: i64 = connection.query_row(
        r#"SELECT EXISTS(
               SELECT 1
               FROM sessions session
               WHERE session.event_payload_bytes <> COALESCE((
                   SELECT SUM(length(CAST(event.payload_json AS BLOB)))
                   FROM session_events event
                   WHERE event.session_id = session.id
               ), 0)
               UNION ALL
               SELECT 1
               FROM runs run
               WHERE run.event_payload_bytes <> COALESCE((
                   SELECT SUM(length(CAST(event.payload_json AS BLOB)))
                   FROM run_events event
                   WHERE event.run_id = run.id
               ), 0)
           )"#,
        [],
        |row| row.get(0),
    )?;
    if exact_payload_counter_violation != 0 {
        return Err(StorageError::CorruptData(
            "one or more event payload byte counters are inconsistent".into(),
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

fn cleanup_unusable_auth_sessions(
    connection: &mut Connection,
    timestamp: &str,
) -> Result<usize, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let deleted = cleanup_unusable_auth_sessions_in_transaction(&transaction, timestamp, None)?;
    transaction.commit()?;
    Ok(deleted)
}

fn cleanup_unusable_auth_sessions_in_transaction(
    connection: &Connection,
    timestamp: &str,
    priority_user_id: Option<&str>,
) -> Result<usize, StorageError> {
    Ok(connection.execute(
        r#"DELETE FROM auth_sessions
           WHERE id IN (
               SELECT session.id
               FROM auth_sessions session
               LEFT JOIN users user ON user.id = session.user_id
               LEFT JOIN accounts account ON account.id = session.account_id
               LEFT JOIN account_memberships membership
                 ON membership.account_id = session.account_id
                AND membership.user_id = session.user_id
               WHERE session.expires_at <= ?1
                  OR user.id IS NULL
                  OR user.status <> 'active'
                  OR account.id IS NULL
                  OR account.status <> 'active'
                  OR membership.user_id IS NULL
                  OR membership.status <> 'active'
                  OR membership.revision <> session.membership_revision
               ORDER BY CASE
                            WHEN ?2 IS NOT NULL AND session.user_id = ?2 THEN 0
                            ELSE 1
                        END,
                        session.expires_at, session.id
               LIMIT ?3
           )"#,
        params![
            timestamp,
            priority_user_id,
            AUTH_SESSION_CLEANUP_BATCH_LIMIT
        ],
    )?)
}

fn capacity_limit(limit: usize) -> Result<i64, StorageError> {
    i64::try_from(limit).map_err(|_| StorageError::IntegerOutOfRange("storage capacity limit"))
}

fn require_bootstrap_audit_capacity(
    connection: &Connection,
    limits: &StorageLimits,
) -> Result<(), StorageError> {
    let limit = capacity_limit(limits.bootstrap_audit_rows)?;
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM (SELECT 1 FROM bootstrap_tokens LIMIT ?1)",
        [limit],
        |row| row.get(0),
    )?;
    if count >= limit {
        return Err(StorageError::StorageQuotaExceeded);
    }
    Ok(())
}

#[derive(Debug)]
struct BootstrapAuditTokenRow {
    sequence: i64,
    token_hash: String,
    created_at: String,
    expires_at: String,
    terminal_at: String,
    terminal_reason: String,
}

fn compact_bootstrap_audit_to_capacity(
    connection: &Connection,
    timestamp: &str,
    limits: &StorageLimits,
) -> Result<(), StorageError> {
    let limit = capacity_limit(limits.bootstrap_audit_rows)?;
    let target_count = limit.checked_sub(1).ok_or(StorageError::IntegerOutOfRange(
        "bootstrap audit live reservation",
    ))?;
    compact_bootstrap_audit_to_count(connection, timestamp, target_count)
}

fn compact_existing_bootstrap_audit_to_capacity(
    connection: &Connection,
    timestamp: &str,
    limits: &StorageLimits,
) -> Result<(), StorageError> {
    let target_count = capacity_limit(limits.bootstrap_audit_rows)?;
    compact_bootstrap_audit_to_count(connection, timestamp, target_count)
}

fn bootstrap_audit_retention_required(
    connection: &Connection,
    limits: &StorageLimits,
) -> Result<bool, StorageError> {
    let limit = capacity_limit(limits.bootstrap_audit_rows)?;
    let count: i64 = connection.query_row("SELECT COUNT(*) FROM bootstrap_tokens", [], |row| {
        row.get(0)
    })?;
    Ok(count > limit)
}

fn compact_bootstrap_audit_to_count(
    connection: &Connection,
    timestamp: &str,
    target_count: i64,
) -> Result<(), StorageError> {
    loop {
        let count: i64 =
            connection.query_row("SELECT COUNT(*) FROM bootstrap_tokens", [], |row| {
                row.get(0)
            })?;
        if count <= target_count {
            return Ok(());
        }
        let rows_to_remove = count
            .checked_sub(target_count)
            .ok_or(StorageError::IntegerOutOfRange(
                "bootstrap audit compaction batch",
            ))?
            .min(BOOTSTRAP_AUDIT_ROLLUP_BATCH_LIMIT);
        compact_bootstrap_audit_batch(connection, timestamp, rows_to_remove)?;
    }
}

fn compact_bootstrap_audit_batch(
    connection: &Connection,
    timestamp: &str,
    batch_limit: i64,
) -> Result<(), StorageError> {
    if !(1..=BOOTSTRAP_AUDIT_ROLLUP_BATCH_LIMIT).contains(&batch_limit) {
        return Err(StorageError::CorruptData(
            "bootstrap audit compaction batch is outside its supported bound".into(),
        ));
    }
    let (through_sequence, previous_digest): (i64, String) = connection.query_row(
        r#"SELECT through_sequence, digest
           FROM bootstrap_audit_rollup WHERE singleton = 1"#,
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if through_sequence < 0 || !is_lower_hex_digest(&previous_digest) {
        return Err(StorageError::CorruptData(
            "the bootstrap audit rollup is structurally inconsistent".into(),
        ));
    }

    let mut statement = connection.prepare(
        r#"SELECT sequence, token_hash, created_at, expires_at,
                  terminal_at, terminal_reason
           FROM bootstrap_tokens
           WHERE sequence > ?1
             AND terminal_at IS NOT NULL
             AND terminal_reason IS NOT NULL
           ORDER BY sequence
           LIMIT ?2"#,
    )?;
    let rows = statement
        .query_map(params![through_sequence, batch_limit], |row| {
            Ok(BootstrapAuditTokenRow {
                sequence: row.get(0)?,
                token_hash: row.get(1)?,
                created_at: row.get(2)?,
                expires_at: row.get(3)?,
                terminal_at: row.get(4)?,
                terminal_reason: row.get(5)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.is_empty() {
        return Err(StorageError::StorageQuotaExceeded);
    }
    for (index, row) in rows.iter().enumerate() {
        let expected =
            through_sequence
                .checked_add(i64::try_from(index + 1).map_err(|_| {
                    StorageError::IntegerOutOfRange("bootstrap audit sequence offset")
                })?)
                .ok_or(StorageError::IntegerOutOfRange("bootstrap audit sequence"))?;
        if row.sequence != expected {
            return Err(StorageError::CorruptData(
                "the bootstrap audit terminal prefix is not contiguous".into(),
            ));
        }
    }
    let new_through = rows
        .last()
        .expect("a non-empty bootstrap audit compaction batch has a tail")
        .sequence;
    let new_digest = bootstrap_audit_rollup_digest(&previous_digest, &rows)?;
    let changed = connection.execute(
        r#"UPDATE bootstrap_audit_rollup
           SET through_sequence = ?1,
               digest = ?2,
               updated_at = CASE
                   WHEN updated_at > ?3 THEN updated_at
                   ELSE ?3
               END
           WHERE singleton = 1 AND through_sequence = ?4 AND digest = ?5"#,
        params![
            new_through,
            new_digest,
            timestamp,
            through_sequence,
            previous_digest
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::CorruptData(
            "the bootstrap audit rollup changed concurrently".into(),
        ));
    }
    let deleted = connection.execute(
        r#"DELETE FROM bootstrap_tokens
           WHERE sequence > ?1 AND sequence <= ?2
             AND terminal_at IS NOT NULL AND terminal_reason IS NOT NULL"#,
        params![through_sequence, new_through],
    )?;
    if deleted != rows.len() {
        return Err(StorageError::CorruptData(
            "the bootstrap audit compacted prefix changed during deletion".into(),
        ));
    }
    Ok(())
}

fn bootstrap_audit_rollup_digest(
    previous_digest: &str,
    rows: &[BootstrapAuditTokenRow],
) -> Result<String, StorageError> {
    if !is_lower_hex_digest(previous_digest) {
        return Err(StorageError::CorruptData(
            "the bootstrap audit rollup digest is malformed".into(),
        ));
    }
    let mut digest = previous_digest.to_owned();
    for row in rows {
        let mut hasher = Sha256::new();
        hasher.update(b"zeus.bootstrap-audit-rollup.v1\0");
        hasher.update(digest.as_bytes());
        hasher.update(row.sequence.to_be_bytes());
        for field in [
            row.token_hash.as_bytes(),
            row.created_at.as_bytes(),
            row.expires_at.as_bytes(),
            row.terminal_at.as_bytes(),
            row.terminal_reason.as_bytes(),
        ] {
            let length = u64::try_from(field.len())
                .map_err(|_| StorageError::IntegerOutOfRange("bootstrap audit digest field"))?;
            hasher.update(length.to_be_bytes());
            hasher.update(field);
        }
        digest = format!("{:x}", hasher.finalize());
    }
    Ok(digest)
}

fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn require_auth_session_capacity(
    connection: &Connection,
    user_id: &str,
    timestamp: &str,
    limits: &StorageLimits,
) -> Result<(), StorageError> {
    let per_user_limit = capacity_limit(limits.auth_sessions_per_user)?;
    let per_user_count: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM (
               SELECT 1
               FROM auth_sessions session
               JOIN users user
                 ON user.id = session.user_id AND user.status = 'active'
               JOIN accounts account
                 ON account.id = session.account_id AND account.status = 'active'
               JOIN account_memberships membership
                 ON membership.account_id = session.account_id
                AND membership.user_id = session.user_id
                AND membership.status = 'active'
                AND membership.revision = session.membership_revision
               WHERE session.user_id = ?1 AND session.expires_at > ?2
               LIMIT ?3
           )"#,
        params![user_id, timestamp, per_user_limit],
        |row| row.get(0),
    )?;
    if per_user_count >= per_user_limit {
        return Err(StorageError::AuthSessionCapacityExceeded);
    }

    let global_limit = capacity_limit(limits.auth_sessions_global)?;
    let global_count: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM (
               SELECT 1
               FROM auth_sessions session
               JOIN users user
                 ON user.id = session.user_id AND user.status = 'active'
               JOIN accounts account
                 ON account.id = session.account_id AND account.status = 'active'
               JOIN account_memberships membership
                 ON membership.account_id = session.account_id
                AND membership.user_id = session.user_id
                AND membership.status = 'active'
                AND membership.revision = session.membership_revision
               WHERE session.expires_at > ?1
               LIMIT ?2
           )"#,
        params![timestamp, global_limit],
        |row| row.get(0),
    )?;
    if global_count >= global_limit {
        return Err(StorageError::AuthSessionCapacityExceeded);
    }
    Ok(())
}

fn require_session_count_capacity(
    connection: &Connection,
    account_id: &str,
    actor_user_id: Option<&str>,
    limits: &StorageLimits,
) -> Result<(), StorageError> {
    if let Some(actor_user_id) = actor_user_id {
        let actor_limit = capacity_limit(limits.sessions_per_actor)?;
        let actor_count: i64 = connection.query_row(
            r#"SELECT COUNT(*) FROM (
                   SELECT 1 FROM sessions
                   WHERE account_id = ?1 AND owner_user_id = ?2 LIMIT ?3
               )"#,
            params![account_id, actor_user_id, actor_limit],
            |row| row.get(0),
        )?;
        if actor_count >= actor_limit {
            return Err(StorageError::StorageQuotaExceeded);
        }
    }
    let account_limit = capacity_limit(limits.sessions_per_account)?;
    let account_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM (SELECT 1 FROM sessions WHERE account_id = ?1 LIMIT ?2)",
        params![account_id, account_limit],
        |row| row.get(0),
    )?;
    if account_count >= account_limit {
        return Err(StorageError::StorageQuotaExceeded);
    }

    let global_limit = capacity_limit(limits.sessions_global)?;
    let global_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM (SELECT 1 FROM sessions LIMIT ?1)",
        [global_limit],
        |row| row.get(0),
    )?;
    if global_count >= global_limit {
        return Err(StorageError::StorageQuotaExceeded);
    }
    Ok(())
}

fn require_open_turn_capacity(
    connection: &Connection,
    account_id: &str,
    actor_user_id: Option<&str>,
    limits: &StorageLimits,
) -> Result<(), StorageError> {
    if let Some(actor_user_id) = actor_user_id {
        let actor_limit = capacity_limit(limits.open_turns_per_actor)?;
        let actor_count: i64 = connection.query_row(
            r#"SELECT COUNT(*) FROM (SELECT 1 FROM finalization_reservations
               WHERE account_id = ?1 AND actor_user_id = ?2 AND kind = 'session_turn'
                 AND remaining_event_slots > 0 LIMIT ?3)"#,
            params![account_id, actor_user_id, actor_limit],
            |row| row.get(0),
        )?;
        if actor_count >= actor_limit {
            return Err(StorageError::StorageQuotaExceeded);
        }
    }
    let account_limit = capacity_limit(limits.open_turns_per_account)?;
    let account_count: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM (SELECT 1 FROM finalization_reservations
           WHERE account_id = ?1 AND kind = 'session_turn'
             AND remaining_event_slots > 0 LIMIT ?2)"#,
        params![account_id, account_limit],
        |row| row.get(0),
    )?;
    if account_count >= account_limit {
        return Err(StorageError::StorageQuotaExceeded);
    }

    let global_limit = capacity_limit(limits.open_turns_global)?;
    let global_count: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM (
               SELECT 1 FROM finalization_reservations
               WHERE kind = 'session_turn' AND remaining_event_slots > 0
               LIMIT ?1
           )"#,
        [global_limit],
        |row| row.get(0),
    )?;
    if global_count >= global_limit {
        return Err(StorageError::StorageQuotaExceeded);
    }
    Ok(())
}

fn require_reply_queue_capacity(
    connection: &Connection,
    account_id: &str,
    actor_user_id: Option<&str>,
    limits: &StorageLimits,
) -> Result<(), StorageError> {
    if let Some(actor_user_id) = actor_user_id {
        let actor_limit = capacity_limit(limits.active_reply_jobs_per_actor)?;
        let actor_count: i64 = connection.query_row(
            r#"SELECT COUNT(*) FROM (
                   SELECT 1 FROM reply_jobs
                   WHERE account_id = ?1 AND actor_user_id = ?2
                     AND status IN ('queued', 'started')
                   UNION ALL
                   SELECT 1 FROM agent_turns
                   WHERE account_id = ?1 AND actor_user_id = ?2
                     AND status NOT IN ('succeeded', 'failed', 'needs_attention')
                   UNION ALL
                   SELECT 1 FROM session_followups
                   WHERE account_id = ?1 AND actor_user_id = ?2
                     AND status = 'queued'
                   LIMIT ?3
               )"#,
            params![account_id, actor_user_id, actor_limit],
            |row| row.get(0),
        )?;
        if actor_count >= actor_limit {
            return Err(StorageError::ReplyQueueCapacityExceeded);
        }
    }
    let account_limit = capacity_limit(limits.active_reply_jobs_per_account)?;
    let account_count: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM (
               SELECT 1 FROM reply_jobs WHERE account_id = ?1
                 AND status IN ('queued','started')
               UNION ALL
               SELECT 1 FROM agent_turns WHERE account_id = ?1
                 AND status NOT IN ('succeeded', 'failed', 'needs_attention')
               UNION ALL
               SELECT 1 FROM session_followups WHERE account_id = ?1
                 AND status = 'queued'
               LIMIT ?2
           )"#,
        params![account_id, account_limit],
        |row| row.get(0),
    )?;
    if account_count >= account_limit {
        return Err(StorageError::ReplyQueueCapacityExceeded);
    }

    let global_limit = capacity_limit(limits.active_reply_jobs_global)?;
    let global_count: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM (
               SELECT 1 FROM reply_jobs
               WHERE status IN ('queued', 'started')
               UNION ALL
               SELECT 1 FROM agent_turns
               WHERE status NOT IN ('succeeded', 'failed', 'needs_attention')
               UNION ALL
               SELECT 1 FROM session_followups WHERE status = 'queued'
               LIMIT ?1
           )"#,
        [global_limit],
        |row| row.get(0),
    )?;
    if global_count >= global_limit {
        return Err(StorageError::ReplyQueueCapacityExceeded);
    }
    Ok(())
}

fn require_dispatch_queue_capacity(
    connection: &Connection,
    account_id: &str,
    actor_user_id: Option<&str>,
    limits: &StorageLimits,
) -> Result<(), StorageError> {
    if let Some(actor_user_id) = actor_user_id {
        let actor_limit = capacity_limit(limits.active_dispatch_jobs_per_actor)?;
        let actor_count: i64 = connection.query_row(
            r#"SELECT COUNT(*) FROM (
                   SELECT 1 FROM dispatch_jobs
                   WHERE account_id = ?1 AND initiating_actor_user_id = ?2
                     AND status IN ('queued', 'started') LIMIT ?3
               )"#,
            params![account_id, actor_user_id, actor_limit],
            |row| row.get(0),
        )?;
        if actor_count >= actor_limit {
            return Err(StorageError::DispatchQueueCapacityExceeded);
        }
    }
    let account_limit = capacity_limit(limits.active_dispatch_jobs_per_account)?;
    let account_count: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM (SELECT 1 FROM dispatch_jobs WHERE account_id = ?1
           AND status IN ('queued','started') LIMIT ?2)"#,
        params![account_id, account_limit],
        |row| row.get(0),
    )?;
    if account_count >= account_limit {
        return Err(StorageError::DispatchQueueCapacityExceeded);
    }

    let global_limit = capacity_limit(limits.active_dispatch_jobs_global)?;
    let global_count: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM (
               SELECT 1 FROM dispatch_jobs
               WHERE status IN ('queued', 'started') LIMIT ?1
           )"#,
        [global_limit],
        |row| row.get(0),
    )?;
    if global_count >= global_limit {
        return Err(StorageError::DispatchQueueCapacityExceeded);
    }
    Ok(())
}

fn require_session_event_capacity(
    connection: &Connection,
    session_id: &str,
    request: EventCapacityRequest,
    limits: &StorageLimits,
) -> Result<(), StorageError> {
    let (head, committed_bytes): (i64, i64) = connection.query_row(
        "SELECT sequence, event_payload_bytes FROM sessions WHERE id = ?1",
        [session_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let (reserved_slots, reserved_bytes) =
        session_finalization_reservation_totals(connection, session_id)?;
    let requested_slots = request
        .new_event_slots
        .checked_add(request.new_reserved_slots)
        .ok_or(StorageError::IntegerOutOfRange(
            "session event capacity request",
        ))?;
    let requested_slots = i64::try_from(requested_slots)
        .map_err(|_| StorageError::IntegerOutOfRange("session event capacity request"))?;
    let used_slots = head
        .checked_add(reserved_slots)
        .and_then(|value| value.checked_add(requested_slots))
        .ok_or(StorageError::IntegerOutOfRange("session event capacity"))?;
    if used_slots > capacity_limit(limits.session_event_slots_per_session)? {
        return Err(StorageError::StorageQuotaExceeded);
    }

    let requested_bytes = checked_nonnegative_payload_request(request)?;
    let used_bytes = committed_bytes
        .checked_add(reserved_bytes)
        .and_then(|value| value.checked_add(requested_bytes))
        .ok_or(StorageError::StorageQuotaExceeded)?;
    if used_bytes > capacity_limit(limits.session_event_payload_bytes_per_session)? {
        return Err(StorageError::StorageQuotaExceeded);
    }
    require_global_event_payload_capacity(connection, requested_bytes, limits)?;
    Ok(())
}

fn require_run_event_capacity(
    connection: &Connection,
    run_id: &str,
    request: EventCapacityRequest,
    limits: &StorageLimits,
) -> Result<(), StorageError> {
    let (head, committed_bytes): (i64, i64) = connection.query_row(
        "SELECT sequence, event_payload_bytes FROM runs WHERE id = ?1",
        [run_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let (reserved_slots, reserved_bytes) =
        dispatch_finalization_reservation_totals(connection, run_id)?;
    let requested_slots = request
        .new_event_slots
        .checked_add(request.new_reserved_slots)
        .ok_or(StorageError::IntegerOutOfRange(
            "run event capacity request",
        ))?;
    let requested_slots = i64::try_from(requested_slots)
        .map_err(|_| StorageError::IntegerOutOfRange("run event capacity request"))?;
    let used_slots = head
        .checked_add(reserved_slots)
        .and_then(|value| value.checked_add(requested_slots))
        .ok_or(StorageError::IntegerOutOfRange("run event capacity"))?;
    if used_slots > capacity_limit(limits.run_event_slots_per_run)? {
        return Err(StorageError::StorageQuotaExceeded);
    }

    let requested_bytes = checked_nonnegative_payload_request(request)?;
    let used_bytes = committed_bytes
        .checked_add(reserved_bytes)
        .and_then(|value| value.checked_add(requested_bytes))
        .ok_or(StorageError::StorageQuotaExceeded)?;
    if used_bytes > capacity_limit(limits.run_event_payload_bytes_per_run)? {
        return Err(StorageError::StorageQuotaExceeded);
    }
    require_global_event_payload_capacity(connection, requested_bytes, limits)?;
    Ok(())
}

fn checked_nonnegative_payload_request(request: EventCapacityRequest) -> Result<i64, StorageError> {
    if request.new_event_payload_bytes < 0 || request.new_reserved_payload_bytes < 0 {
        return Err(StorageError::IntegerOutOfRange(
            "event payload capacity request",
        ));
    }
    request
        .new_event_payload_bytes
        .checked_add(request.new_reserved_payload_bytes)
        .ok_or(StorageError::IntegerOutOfRange(
            "event payload capacity request",
        ))
}

fn session_finalization_reservation_totals(
    connection: &Connection,
    session_id: &str,
) -> Result<(i64, i64), StorageError> {
    let mut statement = connection.prepare(
        r#"SELECT remaining_event_slots, remaining_event_payload_bytes
           FROM finalization_reservations
           WHERE kind = 'session_turn' AND session_id = ?1"#,
    )?;
    let mut rows = statement.query([session_id])?;
    reservation_totals(&mut rows)
}

fn dispatch_finalization_reservation_totals(
    connection: &Connection,
    run_id: &str,
) -> Result<(i64, i64), StorageError> {
    let mut statement = connection.prepare(
        r#"SELECT remaining_event_slots, remaining_event_payload_bytes
           FROM finalization_reservations
           WHERE kind = 'dispatch' AND run_id = ?1"#,
    )?;
    let mut rows = statement.query([run_id])?;
    reservation_totals(&mut rows)
}

fn reservation_totals(rows: &mut rusqlite::Rows<'_>) -> Result<(i64, i64), StorageError> {
    let mut slots = 0_i64;
    let mut bytes = 0_i64;
    while let Some(row) = rows.next()? {
        let row_slots: i64 = row.get(0)?;
        let row_bytes: i64 = row.get(1)?;
        slots = slots
            .checked_add(row_slots)
            .ok_or(StorageError::StorageQuotaExceeded)?;
        bytes = bytes
            .checked_add(row_bytes)
            .ok_or(StorageError::StorageQuotaExceeded)?;
    }
    Ok((slots, bytes))
}

fn require_global_event_payload_capacity(
    connection: &Connection,
    requested_bytes: i64,
    limits: &StorageLimits,
) -> Result<(), StorageError> {
    let committed_bytes: i64 = connection.query_row(
        "SELECT used_bytes FROM event_payload_usage WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let limit = capacity_limit(limits.event_payload_bytes_global)?;
    let mut used_bytes = committed_bytes
        .checked_add(requested_bytes)
        .ok_or(StorageError::StorageQuotaExceeded)?;
    if used_bytes > limit {
        return Err(StorageError::StorageQuotaExceeded);
    }
    let mut statement = connection
        .prepare("SELECT remaining_event_payload_bytes FROM finalization_reservations")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let reserved_bytes: i64 = row.get(0)?;
        used_bytes = used_bytes
            .checked_add(reserved_bytes)
            .ok_or(StorageError::StorageQuotaExceeded)?;
        if used_bytes > limit {
            return Err(StorageError::StorageQuotaExceeded);
        }
    }
    Ok(())
}

fn encode_event_payload<T: Serialize>(value: &T) -> Result<EncodedEventPayload, StorageError> {
    let json = serde_json::to_string(value)?;
    let bytes = i64::try_from(json.len())
        .map_err(|_| StorageError::IntegerOutOfRange("serialized event payload bytes"))?;
    Ok(EncodedEventPayload { json, bytes })
}

fn checked_event_payload_total<'a>(
    payloads: impl IntoIterator<Item = &'a EncodedEventPayload>,
) -> Result<i64, StorageError> {
    payloads.into_iter().try_fold(0_i64, |total, payload| {
        total
            .checked_add(payload.bytes)
            .ok_or(StorageError::IntegerOutOfRange(
                "serialized event payload byte total",
            ))
    })
}

fn checked_scaled_utf8_bytes(
    value: &str,
    multiplier: i64,
    field: &'static str,
) -> Result<i64, StorageError> {
    i64::try_from(value.len())
        .map_err(|_| StorageError::IntegerOutOfRange(field))?
        .checked_mul(multiplier)
        .ok_or(StorageError::IntegerOutOfRange(field))
}

fn session_finalization_payload_reservation(
    turn_id: &str,
    provider_name: Option<&str>,
    model_name: Option<&str>,
) -> Result<i64, StorageError> {
    let turn_bytes = checked_scaled_utf8_bytes(
        turn_id,
        SESSION_FINALIZATION_TURN_ID_MULTIPLIER,
        "session finalization turn ID payload reservation",
    )?;
    let provider_bytes = provider_name
        .map(|value| {
            checked_scaled_utf8_bytes(
                value,
                SESSION_FINALIZATION_PROVIDER_MULTIPLIER,
                "session finalization provider payload reservation",
            )
        })
        .transpose()?
        .unwrap_or(0);
    let model_bytes = model_name
        .map(|value| {
            checked_scaled_utf8_bytes(
                value,
                SESSION_FINALIZATION_PROVIDER_MULTIPLIER,
                "session finalization model payload reservation",
            )
        })
        .transpose()?
        .unwrap_or(0);
    SESSION_FINALIZATION_BASE_BYTES
        .checked_add(turn_bytes)
        .and_then(|value| value.checked_add(provider_bytes))
        .and_then(|value| value.checked_add(model_bytes))
        .ok_or(StorageError::IntegerOutOfRange(
            "session finalization payload reservation",
        ))
}

fn dispatch_queued_payload_reservation(call_id: &str) -> Result<i64, StorageError> {
    DISPATCH_QUEUED_FINALIZATION_BASE_BYTES
        .checked_add(checked_scaled_utf8_bytes(
            call_id,
            DISPATCH_QUEUED_CALL_ID_MULTIPLIER,
            "queued dispatch payload reservation",
        )?)
        .ok_or(StorageError::IntegerOutOfRange(
            "queued dispatch payload reservation",
        ))
}

fn dispatch_terminal_payload_reservation(call_id: &str) -> Result<i64, StorageError> {
    DISPATCH_TERMINAL_FINALIZATION_BASE_BYTES
        .checked_add(checked_scaled_utf8_bytes(
            call_id,
            DISPATCH_TERMINAL_CALL_ID_MULTIPLIER,
            "terminal dispatch payload reservation",
        )?)
        .ok_or(StorageError::IntegerOutOfRange(
            "terminal dispatch payload reservation",
        ))
}

fn insert_session_finalization_reservation(
    connection: &Connection,
    account_id: &str,
    actor_user_id: Option<&str>,
    session_id: &str,
    turn_id: &str,
    remaining_event_payload_bytes: i64,
    timestamp: &str,
) -> Result<(), StorageError> {
    connection.execute(
        r#"INSERT INTO finalization_reservations(
               kind, account_id, actor_user_id, session_id, turn_id, run_id, call_id,
               remaining_event_slots, reserved_bytes,
               remaining_event_payload_bytes, created_at
           ) VALUES ('session_turn', ?1, ?2, ?3, ?4, NULL, NULL, 2, NULL, ?5, ?6)"#,
        params![
            account_id,
            actor_user_id,
            session_id,
            turn_id,
            remaining_event_payload_bytes,
            timestamp
        ],
    )?;
    Ok(())
}

fn require_session_finalization_capacity(
    connection: &Connection,
    session_id: &str,
    turn_id: &str,
    minimum: i64,
    minimum_payload_bytes: i64,
) -> Result<(i64, i64), StorageError> {
    let remaining = connection
        .query_row(
            r#"SELECT remaining_event_slots, remaining_event_payload_bytes
               FROM finalization_reservations
               WHERE kind = 'session_turn' AND session_id = ?1 AND turn_id = ?2"#,
            params![session_id, turn_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    match remaining {
        Some((remaining_slots, remaining_bytes))
            if remaining_slots >= minimum && remaining_bytes >= minimum_payload_bytes =>
        {
            Ok((remaining_slots, remaining_bytes))
        }
        _ => Err(StorageError::FinalizationReservationUnavailable),
    }
}

fn finish_session_finalization(
    connection: &Connection,
    session_id: &str,
    turn_id: &str,
    emitted_events: i64,
    emitted_payload_bytes: i64,
) -> Result<(), StorageError> {
    require_session_finalization_capacity(
        connection,
        session_id,
        turn_id,
        emitted_events,
        emitted_payload_bytes,
    )?;
    let changed = connection.execute(
        r#"UPDATE finalization_reservations
           SET remaining_event_slots = 0,
               remaining_event_payload_bytes = 0
           WHERE kind = 'session_turn'
             AND session_id = ?1 AND turn_id = ?2
             AND remaining_event_slots >= ?3
             AND remaining_event_payload_bytes >= ?4"#,
        params![session_id, turn_id, emitted_events, emitted_payload_bytes],
    )?;
    if changed != 1 {
        return Err(StorageError::FinalizationReservationUnavailable);
    }
    let deleted = connection.execute(
        r#"DELETE FROM finalization_reservations
           WHERE kind = 'session_turn'
             AND session_id = ?1 AND turn_id = ?2
             AND remaining_event_slots = 0
             AND remaining_event_payload_bytes = 0"#,
        params![session_id, turn_id],
    )?;
    if deleted != 1 {
        return Err(StorageError::FinalizationReservationUnavailable);
    }
    Ok(())
}

fn insert_dispatch_finalization_reservation(
    connection: &Connection,
    account_id: &str,
    actor_user_id: Option<&str>,
    run_id: &str,
    call_id: &str,
    remaining_event_payload_bytes: i64,
    timestamp: &str,
) -> Result<(), StorageError> {
    connection.execute(
        r#"INSERT INTO finalization_reservations(
               kind, account_id, actor_user_id, session_id, turn_id, run_id, call_id,
               remaining_event_slots, reserved_bytes,
               remaining_event_payload_bytes, created_at
           ) VALUES ('dispatch', ?1, ?2, NULL, NULL, ?3, ?4, 2, NULL, ?5, ?6)"#,
        params![
            account_id,
            actor_user_id,
            run_id,
            call_id,
            remaining_event_payload_bytes,
            timestamp
        ],
    )?;
    Ok(())
}

fn require_dispatch_finalization_capacity(
    connection: &Connection,
    run_id: &str,
    call_id: &str,
    expected_slots: i64,
    minimum_payload_bytes: i64,
) -> Result<i64, StorageError> {
    let remaining = connection
        .query_row(
            r#"SELECT remaining_event_slots, remaining_event_payload_bytes
               FROM finalization_reservations
               WHERE kind = 'dispatch' AND run_id = ?1 AND call_id = ?2"#,
            params![run_id, call_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    match remaining {
        Some((remaining_slots, remaining_bytes))
            if remaining_slots == expected_slots && remaining_bytes >= minimum_payload_bytes =>
        {
            Ok(remaining_bytes)
        }
        _ => Err(StorageError::FinalizationReservationUnavailable),
    }
}

fn consume_dispatch_claim_capacity(
    connection: &Connection,
    run_id: &str,
    call_id: &str,
    emitted_payload_bytes: i64,
    terminal_payload_reservation: i64,
) -> Result<(), StorageError> {
    let required = emitted_payload_bytes
        .checked_add(terminal_payload_reservation)
        .ok_or(StorageError::IntegerOutOfRange(
            "dispatch claim payload reservation",
        ))?;
    require_dispatch_finalization_capacity(connection, run_id, call_id, 2, required)?;
    let changed = connection.execute(
        r#"UPDATE finalization_reservations
           SET remaining_event_slots = 1,
               remaining_event_payload_bytes = ?3
           WHERE kind = 'dispatch' AND run_id = ?1 AND call_id = ?2
             AND remaining_event_slots = 2
             AND remaining_event_payload_bytes >= ?4"#,
        params![run_id, call_id, terminal_payload_reservation, required],
    )?;
    if changed != 1 {
        return Err(StorageError::FinalizationReservationUnavailable);
    }
    Ok(())
}

fn finish_dispatch_finalization(
    connection: &Connection,
    run_id: &str,
    call_id: &str,
    expected_remaining: i64,
    emitted_payload_bytes: i64,
) -> Result<(), StorageError> {
    require_dispatch_finalization_capacity(
        connection,
        run_id,
        call_id,
        expected_remaining,
        emitted_payload_bytes,
    )?;
    let changed = connection.execute(
        r#"UPDATE finalization_reservations
           SET remaining_event_slots = 0,
               remaining_event_payload_bytes = 0
           WHERE kind = 'dispatch' AND run_id = ?1 AND call_id = ?2
             AND remaining_event_slots = ?3
             AND remaining_event_payload_bytes >= ?4"#,
        params![run_id, call_id, expected_remaining, emitted_payload_bytes],
    )?;
    if changed != 1 {
        return Err(StorageError::FinalizationReservationUnavailable);
    }
    let deleted = connection.execute(
        r#"DELETE FROM finalization_reservations
           WHERE kind = 'dispatch' AND run_id = ?1 AND call_id = ?2
             AND remaining_event_slots = 0
             AND remaining_event_payload_bytes = 0"#,
        params![run_id, call_id],
    )?;
    if deleted != 1 {
        return Err(StorageError::FinalizationReservationUnavailable);
    }
    Ok(())
}

fn replace_bootstrap_token(
    connection: &mut Connection,
    token_hash: &str,
    expires_at: &str,
    limits: &StorageLimits,
    physical_limits: &SqlitePhysicalLimits,
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
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Admission,
    )?;
    transaction.execute(
        r#"UPDATE bootstrap_tokens
           SET terminal_at = ?1,
               terminal_reason = CASE
                   WHEN julianday(expires_at) <= julianday(?1) THEN 'expired'
                   ELSE 'superseded'
               END
           WHERE terminal_at IS NULL"#,
        [&timestamp],
    )?;
    compact_bootstrap_audit_to_capacity(&transaction, &timestamp, limits)?;
    require_bootstrap_audit_capacity(&transaction, limits)?;
    transaction.execute(
        r#"INSERT INTO bootstrap_tokens(
               token_hash, created_at, expires_at, terminal_at, terminal_reason
           ) VALUES (?1, ?2, ?3, NULL, NULL)"#,
        params![token_hash, timestamp, expires_at],
    )?;
    transaction.commit()?;
    Ok(())
}

fn bootstrap_owner(
    connection: &mut Connection,
    commit: BootstrapOwnerCommit,
    limits: &StorageLimits,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<(StoredUser, StoredPreferences), StorageError> {
    let bootstrap_token_hash =
        normalized_token_hash(&commit.bootstrap_token_hash, "bootstrap token hash")?;
    let user_id = normalized_account_value(&commit.user_id, "user ID", 128)?;
    let username = normalized_account_value(&commit.username, "username", 64)?;
    let password_hash = normalized_password_hash(&commit.password_hash)?;
    normalized_account_value(
        commit.auth_session_id.as_str(),
        "authentication session ID",
        128,
    )?;
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
               WHERE token_hash = ?1 AND terminal_at IS NULL"#,
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
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Admission,
    )?;
    cleanup_unusable_auth_sessions_in_transaction(&transaction, &timestamp, None)?;
    require_auth_session_capacity(&transaction, user_id, &timestamp, limits)?;

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
    let membership_inserted = transaction.execute(
        r#"INSERT INTO account_memberships(
               account_id, user_id, role, status, revision, created_at, updated_at
           )
           SELECT id, ?1, 'owner', 'active', 1, ?2, ?2
           FROM accounts
           WHERE id = ?3 AND status = 'active'"#,
        params![user_id, timestamp, LOCAL_ACCOUNT_ID],
    )?;
    if membership_inserted != 1 {
        return Err(StorageError::CorruptData(
            "the local account is missing or inactive during owner bootstrap".into(),
        ));
    }

    transaction.execute(
        "UPDATE sessions SET owner_user_id = ?1 WHERE owner_user_id IS NULL",
        [user_id],
    )?;
    transaction.execute(
        "UPDATE runs SET owner_user_id = ?1 WHERE owner_user_id IS NULL",
        [user_id],
    )?;
    transaction.execute(
        "UPDATE session_command_receipts SET actor_user_id = ?1 WHERE actor_user_id IS NULL",
        [user_id],
    )?;
    transaction.execute(
        "UPDATE idempotency_receipts SET actor_user_id = ?1 WHERE actor_user_id IS NULL",
        [user_id],
    )?;
    transaction.execute(
        r#"UPDATE dispatch_jobs
           SET approving_actor_user_id = ?1,
               approving_membership_revision = 1
           WHERE approving_actor_user_id IS NULL"#,
        [user_id],
    )?;
    transaction.execute(
        r#"UPDATE finalization_reservations
           SET actor_user_id = ?1
           WHERE actor_user_id IS NULL"#,
        [user_id],
    )?;

    let consumed = transaction.execute(
        r#"UPDATE bootstrap_tokens
           SET terminal_at = ?1, terminal_reason = 'consumed'
           WHERE token_hash = ?2 AND terminal_at IS NULL"#,
        params![timestamp, bootstrap_token_hash],
    )?;
    if consumed != 1 {
        return Err(StorageError::InvalidBootstrapToken);
    }
    insert_auth_session(
        &transaction,
        &AuthSessionInsert {
            auth_session_id: commit.auth_session_id.as_str(),
            account_id: LOCAL_ACCOUNT_ID,
            user_id,
            membership_revision: 1,
            token_hash: session_token_hash,
            csrf_hash,
            expires_at: session_expires_at,
            timestamp: &timestamp,
        },
    )?;

    let user = query_user(&transaction, user_id)?;
    let preferences = query_preferences(&transaction, user_id)?;
    transaction.commit()?;
    Ok((user, preferences))
}

fn query_credential(
    connection: &Connection,
    username: &str,
    account_id: &str,
) -> Result<Option<StoredCredential>, StorageError> {
    let row = connection
        .query_row(
            r#"SELECT user.id, user.username, user.role, user.status,
                      user.password_hash, user.created_at, user.updated_at,
                      membership.account_id, membership.role, membership.revision
               FROM users user
               JOIN account_memberships membership ON membership.user_id = user.id
               JOIN accounts account ON account.id = membership.account_id
               WHERE user.username = ?1 COLLATE NOCASE
                 AND membership.account_id = ?2
                 AND user.status = 'active'
                 AND membership.status = 'active'
                 AND account.status = 'active'"#,
            params![username, account_id],
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
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(
            id,
            username,
            role,
            status,
            password_hash,
            created_at,
            updated_at,
            account_id,
            membership_role,
            membership_revision,
        )| {
            Ok(StoredCredential {
                user: decode_user(id, username, role, status, created_at, updated_at)?,
                account_id: decode_account_id(account_id)?,
                membership_role: decode_membership_role(&membership_role)?,
                membership_revision: decode_membership_revision(membership_revision)?,
                password_hash,
            })
        },
    )
    .transpose()
}

struct StoredAccountRow {
    id: String,
    name: String,
    account_status: String,
    role: String,
    membership_status: String,
    membership_revision: i64,
    created_at: String,
    updated_at: String,
}

impl StoredAccountRow {
    fn decode(self) -> Result<StoredAccount, StorageError> {
        let status = match self.account_status.as_str() {
            "active" => StoredAccountStatus::Active,
            "suspended" => StoredAccountStatus::Suspended,
            other => {
                return Err(StorageError::CorruptData(format!(
                    "unsupported stored account status `{other}`"
                )));
            }
        };
        Ok(StoredAccount {
            id: decode_account_id(self.id)?,
            name: self.name,
            status,
            role: decode_membership_role(&self.role)?,
            membership_status: decode_membership_status(&self.membership_status)?,
            membership_revision: decode_membership_revision(self.membership_revision)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

fn decode_account_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredAccountRow> {
    Ok(StoredAccountRow {
        id: row.get(0)?,
        name: row.get(1)?,
        account_status: row.get(2)?,
        role: row.get(3)?,
        membership_status: row.get(4)?,
        membership_revision: row.get(5)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
    })
}

const ACCOUNT_FOR_USER_SELECT: &str = r#"SELECT account.id, account.name, account.status,
              membership.role, membership.status, membership.revision,
              account.created_at, account.updated_at
       FROM account_memberships membership
       JOIN accounts account ON account.id = membership.account_id"#;

fn query_accounts_for_user(
    connection: &Connection,
    user_id: &str,
) -> Result<Vec<StoredAccount>, StorageError> {
    let sql = format!(
        "{ACCOUNT_FOR_USER_SELECT} WHERE membership.user_id = ?1 ORDER BY account.name COLLATE NOCASE, account.id"
    );
    let mut statement = connection.prepare(&sql)?;
    statement
        .query_map([user_id], decode_account_row)?
        .map(|row| row.map_err(StorageError::from)?.decode())
        .collect()
}

fn query_account_for_user(
    connection: &Connection,
    user_id: &str,
    account_id: &str,
) -> Result<Option<StoredAccount>, StorageError> {
    let sql = format!(
        "{ACCOUNT_FOR_USER_SELECT} WHERE membership.user_id = ?1 AND membership.account_id = ?2"
    );
    connection
        .query_row(&sql, params![user_id, account_id], decode_account_row)
        .optional()?
        .map(StoredAccountRow::decode)
        .transpose()
}

fn create_account(
    connection: &mut Connection,
    context: &AuthzContext,
    commit: CreateAccountCommit,
    limits: &StorageLimits,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<CreateAccountResult, StorageError> {
    if commit.account_id == AccountId::local()
        || AccountId::parse(commit.account_id.as_str()).is_err()
    {
        return Err(StorageError::InvalidAccountData(
            "new account ID must use the canonical opaque representation".into(),
        ));
    }
    let name = tenancy::AccountName::parse(commit.name)
        .map_err(|error| StorageError::InvalidAccountData(error.to_string()))?;
    let timestamp = now();
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_current_authority(&transaction, context, AccountCapability::AccountAdmin)?;

    if let Some(existing) =
        query_account_for_user(&transaction, &context.user_id, commit.account_id.as_str())?
    {
        if existing.name == name.as_str()
            && existing.status == StoredAccountStatus::Active
            && existing.role == MembershipRole::Owner
            && existing.membership_status == StoredMembershipStatus::Active
            && existing.membership_revision.get() == 1
        {
            transaction.commit()?;
            return Ok(CreateAccountResult {
                account: existing,
                replayed: true,
            });
        }
        return Err(StorageError::IdempotencyConflict);
    }
    if transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM accounts WHERE id = ?1)",
        [commit.account_id.as_str()],
        |row| row.get::<_, i64>(0),
    )? != 0
    {
        return Err(StorageError::IdempotencyConflict);
    }

    let account_count: i64 =
        transaction.query_row("SELECT COUNT(*) FROM accounts", [], |row| row.get(0))?;
    let user_account_count: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM account_memberships WHERE user_id = ?1",
        [&context.user_id],
        |row| row.get(0),
    )?;
    if account_count >= MAX_ACCOUNTS_GLOBAL || user_account_count >= MAX_ACCOUNTS_PER_USER {
        return Err(StorageError::AccountCapacityExceeded);
    }
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Admission,
    )?;

    transaction.execute(
        r#"INSERT INTO accounts(id, name, status, created_at, updated_at)
           VALUES (?1, ?2, 'active', ?3, ?3)"#,
        params![commit.account_id.as_str(), name.as_str(), timestamp],
    )?;
    transaction.execute(
        r#"INSERT INTO account_memberships(
               account_id, user_id, role, status, revision, created_at, updated_at
           ) VALUES (?1, ?2, 'owner', 'active', 1, ?3, ?3)"#,
        params![commit.account_id.as_str(), context.user_id, timestamp],
    )?;
    transaction.execute(
        r#"INSERT INTO account_audit_rollups(
               account_id, through_sequence, event_count, digest, last_event_hash, updated_at
           ) VALUES (?1, 0, 0, ?2, ?2, ?3)"#,
        params![
            commit.account_id.as_str(),
            ACCOUNT_AUDIT_ZERO_DIGEST,
            timestamp
        ],
    )?;
    transaction.execute(
        r#"INSERT INTO account_audit_policies(
               account_id, detail_rows, legal_hold, archive_required, revision, updated_at
           ) VALUES (?1, ?2, 0, 0, 1, ?3)"#,
        params![
            commit.account_id.as_str(),
            capacity_limit(limits.account_audit_detail_rows)?,
            timestamp
        ],
    )?;
    transaction.execute(
        r#"INSERT INTO account_audit_archive_state(
               account_id, through_sequence, event_hash, archive_reference, revision, updated_at
           ) VALUES (?1, 0, ?2, NULL, 1, ?3)"#,
        params![
            commit.account_id.as_str(),
            ACCOUNT_AUDIT_ZERO_DIGEST,
            timestamp
        ],
    )?;
    prepare_account_audit_admission(
        &transaction,
        commit.account_id.as_str(),
        AuditAdmission::General,
        limits,
        &timestamp,
    )?;
    append_account_audit_event(
        &transaction,
        commit.account_id.as_str(),
        AccountAuditEventInput {
            actor_user_id: Some(&context.user_id),
            action: "account.created",
            target_kind: "account",
            target_id: commit.account_id.as_str(),
            metadata: json!({ "source_account_id": context.account_id.as_str() }),
        },
        &timestamp,
    )?;
    let account =
        query_account_for_user(&transaction, &context.user_id, commit.account_id.as_str())?
            .ok_or_else(|| {
                StorageError::CorruptData(
                    "new account membership was not readable after insert".into(),
                )
            })?;
    transaction.commit()?;
    Ok(CreateAccountResult {
        account,
        replayed: false,
    })
}

fn create_auth_session(
    connection: &mut Connection,
    commit: AuthSessionCommit,
    limits: &StorageLimits,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<AuthPrincipal, StorageError> {
    let context = validated_authz_context(&commit.authz)?;
    let user_id = context.user_id.as_str();
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
    let current_membership: i64 = transaction.query_row(
        r#"SELECT EXISTS(
               SELECT 1 FROM account_memberships membership
               JOIN accounts account ON account.id = membership.account_id
               WHERE membership.account_id = ?1 AND membership.user_id = ?2
                 AND membership.role = ?3 AND membership.status = 'active'
                 AND membership.revision = ?4 AND account.status = 'active'
           )"#,
        params![
            context.account_id.as_str(),
            context.user_id,
            context.membership_role.as_str(),
            u64_to_i64(context.membership_revision.get(), "membership revision")?,
        ],
        |row| row.get(0),
    )?;
    if current_membership == 0 {
        return Err(StorageError::AuthSessionNotFound);
    }
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Admission,
    )?;
    cleanup_unusable_auth_sessions_in_transaction(&transaction, &timestamp, Some(user_id))?;
    require_auth_session_capacity(&transaction, user_id, &timestamp, limits)?;
    insert_auth_session(
        &transaction,
        &AuthSessionInsert {
            auth_session_id: context.auth_session_id.as_str(),
            account_id: context.account_id.as_str(),
            user_id,
            membership_revision: context.membership_revision.get(),
            token_hash,
            csrf_hash,
            expires_at,
            timestamp: &timestamp,
        },
    )?;
    transaction.commit()?;
    Ok(AuthPrincipal {
        user,
        authz: context,
        csrf_hash: csrf_hash.to_owned(),
        expires_at: expires_at.to_owned(),
    })
}

fn switch_auth_session(
    connection: &mut Connection,
    commit: SwitchAuthSessionCommit,
    limits: &StorageLimits,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<SwitchAuthSessionResult, StorageError> {
    let current = validated_authz_context(&commit.current_authz)?;
    if AccountId::parse(commit.target_account_id.as_str()).is_err() {
        return Err(StorageError::AuthSessionNotFound);
    }
    let current_token_hash = normalized_token_hash(
        &commit.current_session_token_hash,
        "current session token hash",
    )?;
    normalized_account_value(
        commit.next_auth_session_id.as_str(),
        "next authentication session ID",
        128,
    )?;
    let next_token_hash =
        normalized_token_hash(&commit.next_session_token_hash, "next session token hash")?;
    let next_csrf_hash = normalized_token_hash(&commit.next_csrf_hash, "next CSRF token hash")?;
    let next_expires_at = normalized_timestamp(&commit.next_expires_at, "next session expiry")?;
    let timestamp = now();
    if next_expires_at <= timestamp.as_str() {
        return Err(StorageError::InvalidAccountData(
            "next session expiry must be in the future".into(),
        ));
    }

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_current_authority(&transaction, &current, AccountCapability::Read)?;
    let account = query_account_for_user(
        &transaction,
        &current.user_id,
        commit.target_account_id.as_str(),
    )?
    .filter(|account| {
        account.status == StoredAccountStatus::Active
            && account.membership_status == StoredMembershipStatus::Active
    })
    .ok_or(StorageError::AuthSessionNotFound)?;
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Admission,
    )?;
    let deleted = transaction.execute(
        r#"DELETE FROM auth_sessions
           WHERE id = ?1 AND token_hash = ?2 AND account_id = ?3 AND user_id = ?4
             AND membership_revision = ?5"#,
        params![
            current.auth_session_id.as_str(),
            current_token_hash,
            current.account_id.as_str(),
            current.user_id,
            u64_to_i64(current.membership_revision.get(), "membership revision")?,
        ],
    )?;
    if deleted != 1 {
        return Err(StorageError::AuthSessionNotFound);
    }
    cleanup_unusable_auth_sessions_in_transaction(
        &transaction,
        &timestamp,
        Some(&current.user_id),
    )?;
    require_auth_session_capacity(&transaction, &current.user_id, &timestamp, limits)?;
    insert_auth_session(
        &transaction,
        &AuthSessionInsert {
            auth_session_id: commit.next_auth_session_id.as_str(),
            account_id: account.id.as_str(),
            user_id: &current.user_id,
            membership_revision: account.membership_revision.get(),
            token_hash: next_token_hash,
            csrf_hash: next_csrf_hash,
            expires_at: next_expires_at,
            timestamp: &timestamp,
        },
    )?;
    let user = query_user(&transaction, &current.user_id)?;
    let principal = AuthPrincipal {
        user,
        authz: AuthzContext {
            account_id: account.id.clone(),
            user_id: current.user_id,
            membership_role: account.role,
            membership_revision: account.membership_revision,
            auth_session_id: commit.next_auth_session_id,
        },
        csrf_hash: next_csrf_hash.to_owned(),
        expires_at: next_expires_at.to_owned(),
    };
    transaction.commit()?;
    Ok(SwitchAuthSessionResult { principal, account })
}

struct AuthSessionInsert<'a> {
    auth_session_id: &'a str,
    account_id: &'a str,
    user_id: &'a str,
    membership_revision: u64,
    token_hash: &'a str,
    csrf_hash: &'a str,
    expires_at: &'a str,
    timestamp: &'a str,
}

fn insert_auth_session(
    connection: &Connection,
    insert: &AuthSessionInsert<'_>,
) -> Result<(), StorageError> {
    connection.execute(
        r#"INSERT INTO auth_sessions(
               id, token_hash, account_id, user_id, membership_revision,
               csrf_hash, created_at, expires_at, last_seen_at
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?7)"#,
        params![
            insert.auth_session_id,
            insert.token_hash,
            insert.account_id,
            insert.user_id,
            u64_to_i64(insert.membership_revision, "membership revision")?,
            insert.csrf_hash,
            insert.timestamp,
            insert.expires_at
        ],
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
            r#"SELECT user.id, user.username, user.role, user.status,
                      user.created_at, user.updated_at,
                      session.id, session.account_id, membership.role,
                      membership.revision, session.csrf_hash, session.expires_at
               FROM auth_sessions session
               JOIN users user ON user.id = session.user_id
               JOIN accounts account ON account.id = session.account_id
               JOIN account_memberships membership
                 ON membership.account_id = session.account_id
                AND membership.user_id = session.user_id
               WHERE session.token_hash = ?1 AND session.expires_at > ?2
                 AND user.status = 'active' AND account.status = 'active'
                 AND membership.status = 'active'
                 AND membership.revision = session.membership_revision"#,
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
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(
            id,
            username,
            role,
            status,
            created_at,
            updated_at,
            auth_session_id,
            account_id,
            membership_role,
            membership_revision,
            csrf_hash,
            expires_at,
        )| {
            Ok(AuthPrincipal {
                user: decode_user(id.clone(), username, role, status, created_at, updated_at)?,
                authz: AuthzContext {
                    account_id: decode_account_id(account_id)?,
                    user_id: id,
                    membership_role: decode_membership_role(&membership_role)?,
                    membership_revision: decode_membership_revision(membership_revision)?,
                    auth_session_id: decode_auth_session_id(auth_session_id)?,
                },
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

fn decode_account_id(value: String) -> Result<AccountId, StorageError> {
    AccountId::from_persistence(value).map_err(|error| StorageError::CorruptData(error.to_string()))
}

fn decode_auth_session_id(value: String) -> Result<AuthSessionId, StorageError> {
    AuthSessionId::from_persistence(value)
        .map_err(|error| StorageError::CorruptData(error.to_string()))
}

fn decode_membership_role(value: &str) -> Result<MembershipRole, StorageError> {
    value
        .parse()
        .map_err(|error: tenancy::MembershipRoleError| StorageError::CorruptData(error.to_string()))
}

fn decode_membership_revision(value: i64) -> Result<MembershipRevision, StorageError> {
    MembershipRevision::new(i64_to_u64(value, "membership revision")?)
        .map_err(|error| StorageError::CorruptData(error.to_string()))
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
    context: &AuthzContext,
    expected_revision: u64,
    theme: &str,
    preferred_model: Option<&str>,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<StoredPreferences, StorageError> {
    let expected_revision = u64_to_i64(expected_revision, "expected preference revision")?;
    let timestamp = now();
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_current_authority(&transaction, context, AccountCapability::SessionWrite)?;
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Admission,
    )?;
    let changed = transaction.execute(
        r#"UPDATE user_preferences
           SET theme = ?1, preferred_model = ?2, revision = revision + 1, updated_at = ?3
           WHERE user_id = ?4 AND revision = ?5"#,
        params![
            theme,
            preferred_model,
            timestamp,
            context.user_id,
            expected_revision
        ],
    )?;
    if changed != 1 {
        if transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM user_preferences WHERE user_id = ?1)",
            [&context.user_id],
            |row| row.get::<_, i64>(0),
        )? == 0
        {
            return Err(StorageError::UserNotFound(context.user_id.clone()));
        }
        return Err(StorageError::ConcurrentModification);
    }
    let preferences = query_preferences(&transaction, &context.user_id)?;
    transaction.commit()?;
    Ok(preferences)
}

fn decode_membership_status(value: &str) -> Result<StoredMembershipStatus, StorageError> {
    match value {
        "active" => Ok(StoredMembershipStatus::Active),
        "disabled" => Ok(StoredMembershipStatus::Disabled),
        other => Err(StorageError::CorruptData(format!(
            "unsupported stored membership status `{other}`"
        ))),
    }
}

fn membership_status_label(status: StoredMembershipStatus) -> &'static str {
    match status {
        StoredMembershipStatus::Active => "active",
        StoredMembershipStatus::Disabled => "disabled",
    }
}

fn decode_member_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredMemberRow> {
    Ok(StoredMemberRow {
        account_id: row.get(0)?,
        user_id: row.get(1)?,
        username: row.get(2)?,
        role: row.get(3)?,
        status: row.get(4)?,
        revision: row.get(5)?,
        setup_required: row.get::<_, i64>(6)? != 0,
        setup_token_expires_at: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
    })
}

struct StoredMemberRow {
    account_id: String,
    user_id: String,
    username: String,
    role: String,
    status: String,
    revision: i64,
    setup_required: bool,
    setup_token_expires_at: Option<String>,
    created_at: String,
    updated_at: String,
}

impl StoredMemberRow {
    fn decode(self) -> Result<StoredMember, StorageError> {
        Ok(StoredMember {
            account_id: decode_account_id(self.account_id)?,
            user_id: self.user_id,
            username: self.username,
            role: decode_membership_role(&self.role)?,
            status: decode_membership_status(&self.status)?,
            revision: decode_membership_revision(self.revision)?,
            setup_required: self.setup_required,
            setup_token_expires_at: self.setup_token_expires_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

const MEMBER_SELECT: &str = r#"SELECT membership.account_id, membership.user_id, user.username,
              membership.role, membership.status, membership.revision,
              NOT EXISTS(
                  SELECT 1 FROM user_preferences preference
                  WHERE preference.user_id = membership.user_id
              ) AS setup_required,
              setup.expires_at, membership.created_at, membership.updated_at
       FROM account_memberships membership
       JOIN users user ON user.id = membership.user_id
       LEFT JOIN member_setup_tokens setup
         ON setup.account_id = membership.account_id
        AND setup.user_id = membership.user_id"#;

fn query_member_optional(
    connection: &Connection,
    account_id: &str,
    user_id: &str,
) -> Result<Option<StoredMember>, StorageError> {
    let sql =
        format!("{MEMBER_SELECT} WHERE membership.account_id = ?1 AND membership.user_id = ?2");
    connection
        .query_row(&sql, params![account_id, user_id], decode_member_row)
        .optional()?
        .map(StoredMemberRow::decode)
        .transpose()
}

fn query_member(
    connection: &Connection,
    account_id: &str,
    user_id: &str,
) -> Result<StoredMember, StorageError> {
    query_member_optional(connection, account_id, user_id)?
        .ok_or_else(|| StorageError::MemberNotFound(user_id.to_owned()))
}

fn query_member_for_admin(
    connection: &Connection,
    context: &AuthzContext,
    user_id: &str,
) -> Result<StoredMember, StorageError> {
    require_current_authority(connection, context, AccountCapability::AccountAdmin)?;
    query_member(connection, context.account_id.as_str(), user_id)
}

fn query_member_page(
    connection: &Connection,
    context: &AuthzContext,
    cursor_value: Option<&str>,
    limit: usize,
) -> Result<StoredMemberPage, StorageError> {
    require_current_authority(connection, context, AccountCapability::AccountAdmin)?;
    let fetch_limit = validated_read_page_limit(limit, ACCOUNT_MEMBER_PAGE_MAX_LIMIT)?;
    let cursor = cursor_value
        .map(|value| {
            cursor::decode_account_members(value, context.account_id.as_str(), &context.user_id)
        })
        .transpose()?;
    let sql = format!(
        r#"{MEMBER_SELECT}
           WHERE membership.account_id = ?1
             AND (?2 IS NULL
                  OR user.username COLLATE NOCASE > ?2 COLLATE NOCASE
                  OR (user.username = ?2 COLLATE NOCASE AND user.id > ?3))
           ORDER BY user.username COLLATE NOCASE, user.id
           LIMIT ?4"#
    );
    let mut statement = connection.prepare(&sql)?;
    let mut items = statement
        .query_map(
            params![
                context.account_id.as_str(),
                cursor.as_ref().map(|cursor| cursor.first.as_str()),
                cursor.as_ref().map(|cursor| cursor.second.as_str()),
                fetch_limit,
            ],
            decode_member_row,
        )?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(StoredMemberRow::decode)
        .collect::<Result<Vec<_>, _>>()?;
    let has_more = items.len() > limit;
    if has_more {
        items.pop();
    }
    let next_cursor = if has_more {
        let tail = items
            .last()
            .expect("a page with more rows has a visible tail");
        Some(cursor::encode_account_members(
            context.account_id.as_str(),
            &context.user_id,
            &tail.username,
            &tail.user_id,
        )?)
    } else {
        None
    };
    Ok(StoredMemberPage { items, next_cursor })
}

fn create_member(
    connection: &mut Connection,
    context: &AuthzContext,
    commit: CreateMemberCommit,
    limits: &StorageLimits,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<CreateMemberResult, StorageError> {
    let user_id = normalized_account_value(&commit.user_id, "member user ID", 128)?;
    let username = normalized_account_value(&commit.username, "member username", 64)?;
    if username.len() < 3 {
        return Err(StorageError::InvalidAccountData(
            "member username must contain at least 3 bytes".into(),
        ));
    }
    let setup_digest = commit.setup_token.digest().to_persistence();
    let created = Utc::now();
    let timestamp = created.to_rfc3339_opts(SecondsFormat::Millis, true);
    let expires_at = created
        .checked_add_signed(chrono::Duration::seconds(MEMBER_SETUP_TOKEN_TTL_SECONDS))
        .ok_or(StorageError::IntegerOutOfRange("member setup token expiry"))?
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_current_authority(&transaction, context, AccountCapability::AccountAdmin)?;

    if let Some(existing) =
        query_member_optional(&transaction, context.account_id.as_str(), user_id)?
    {
        let stored_digest = transaction
            .query_row(
                r#"SELECT token_digest FROM member_setup_tokens
                   WHERE account_id = ?1 AND user_id = ?2"#,
                params![context.account_id.as_str(), user_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.username.eq_ignore_ascii_case(username)
            && existing.role == MembershipRole::Member
            && existing.status == StoredMembershipStatus::Active
            && existing.setup_required
            && stored_digest.as_deref() == Some(setup_digest.as_str())
        {
            transaction.commit()?;
            return Ok(CreateMemberResult {
                member: existing,
                replayed: true,
            });
        }
        return Err(StorageError::MemberAlreadyExists(user_id.to_owned()));
    }
    if transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1 OR username = ?2 COLLATE NOCASE)",
        params![user_id, username],
        |row| row.get::<_, i64>(0),
    )? != 0
    {
        return Err(StorageError::MemberAlreadyExists(username.to_owned()));
    }

    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Admission,
    )?;
    prepare_account_audit_admission(
        &transaction,
        context.account_id.as_str(),
        AuditAdmission::General,
        limits,
        &timestamp,
    )?;
    transaction.execute(
        r#"INSERT INTO users(
               id, username, role, status, password_hash, created_at, updated_at
           ) VALUES (?1, ?2, 'member', 'disabled', ?3, ?4, ?4)"#,
        params![user_id, username, PENDING_MEMBER_PASSWORD_HASH, timestamp,],
    )?;
    transaction.execute(
        r#"INSERT INTO account_memberships(
               account_id, user_id, role, status, revision, created_at, updated_at
           ) VALUES (?1, ?2, 'member', 'active', 1, ?3, ?3)"#,
        params![context.account_id.as_str(), user_id, timestamp],
    )?;
    transaction.execute(
        r#"INSERT INTO member_setup_tokens(
               token_digest, account_id, user_id, created_by_user_id,
               created_at, expires_at
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)"#,
        params![
            setup_digest,
            context.account_id.as_str(),
            user_id,
            context.user_id,
            timestamp,
            expires_at,
        ],
    )?;
    append_account_audit_event(
        &transaction,
        context.account_id.as_str(),
        AccountAuditEventInput {
            actor_user_id: Some(&context.user_id),
            action: "member.created",
            target_kind: "member",
            target_id: user_id,
            metadata: json!({
                "role": "member",
                "status": "active",
                "setup_token_expires_at": expires_at,
            }),
        },
        &timestamp,
    )?;
    let member = query_member(&transaction, context.account_id.as_str(), user_id)?;
    transaction.commit()?;
    Ok(CreateMemberResult {
        member,
        replayed: false,
    })
}

fn rotate_member_setup_token(
    connection: &mut Connection,
    context: &AuthzContext,
    commit: RotateMemberSetupTokenCommit,
    limits: &StorageLimits,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<RotateMemberSetupTokenResult, StorageError> {
    let user_id = normalized_account_value(&commit.user_id, "member user ID", 128)?;
    let setup_digest = commit.setup_token.digest().to_persistence();
    let created = Utc::now();
    let timestamp = created.to_rfc3339_opts(SecondsFormat::Millis, true);
    let expires_at = created
        .checked_add_signed(chrono::Duration::seconds(MEMBER_SETUP_TOKEN_TTL_SECONDS))
        .ok_or(StorageError::IntegerOutOfRange("member setup token expiry"))?
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_current_authority(&transaction, context, AccountCapability::AccountAdmin)?;
    let member = query_member(&transaction, context.account_id.as_str(), user_id)?;
    if member.revision != commit.expected_revision {
        return Err(StorageError::MembershipRevisionConflict);
    }
    let user_status: String =
        transaction.query_row("SELECT status FROM users WHERE id = ?1", [user_id], |row| {
            row.get(0)
        })?;
    if user_status != "disabled" {
        return Err(StorageError::MemberSetupAlreadyCompleted);
    }
    if member.role != MembershipRole::Member
        || member.status != StoredMembershipStatus::Active
        || !member.setup_required
    {
        return Err(StorageError::InvalidMemberSetupToken);
    }
    let current_digest = transaction
        .query_row(
            r#"SELECT token_digest FROM member_setup_tokens
               WHERE account_id = ?1 AND user_id = ?2"#,
            params![context.account_id.as_str(), user_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if current_digest.as_deref() == Some(setup_digest.as_str()) {
        transaction.commit()?;
        return Ok(RotateMemberSetupTokenResult {
            member,
            replayed: true,
        });
    }

    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Admission,
    )?;
    prepare_account_audit_admission(
        &transaction,
        context.account_id.as_str(),
        AuditAdmission::General,
        limits,
        &timestamp,
    )?;
    transaction.execute(
        "DELETE FROM member_setup_tokens WHERE account_id = ?1 AND user_id = ?2",
        params![context.account_id.as_str(), user_id],
    )?;
    transaction.execute(
        r#"INSERT INTO member_setup_tokens(
               token_digest, account_id, user_id, created_by_user_id,
               created_at, expires_at
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)"#,
        params![
            setup_digest,
            context.account_id.as_str(),
            user_id,
            context.user_id,
            timestamp,
            expires_at,
        ],
    )?;
    append_account_audit_event(
        &transaction,
        context.account_id.as_str(),
        AccountAuditEventInput {
            actor_user_id: Some(&context.user_id),
            action: "member.setup_token_rotated",
            target_kind: "member",
            target_id: user_id,
            metadata: json!({ "setup_token_expires_at": expires_at }),
        },
        &timestamp,
    )?;
    let member = query_member(&transaction, context.account_id.as_str(), user_id)?;
    transaction.commit()?;
    Ok(RotateMemberSetupTokenResult {
        member,
        replayed: false,
    })
}

fn complete_member_setup(
    connection: &mut Connection,
    commit: MemberSetupCommit,
    limits: &StorageLimits,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<MemberSetupResult, StorageError> {
    let setup_digest = commit.setup_token.digest().to_persistence();
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
    let pending = transaction
        .query_row(
            r#"SELECT token.account_id, token.user_id, token.expires_at,
                      membership.role, membership.status, membership.revision,
                      user.status
               FROM member_setup_tokens token
               JOIN accounts account ON account.id = token.account_id
               JOIN account_memberships membership
                 ON membership.account_id = token.account_id
                AND membership.user_id = token.user_id
               JOIN users user ON user.id = token.user_id
               WHERE token.token_digest = ?1 AND account.status = 'active'"#,
            [&setup_digest],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()?;
    let Some((account_id, user_id, token_expires_at, role, status, revision, user_status)) =
        pending
    else {
        return Err(StorageError::InvalidMemberSetupToken);
    };
    if token_expires_at <= timestamp {
        return Err(StorageError::MemberSetupExpired);
    }
    if user_status != "disabled" {
        return Err(StorageError::MemberSetupAlreadyCompleted);
    }
    if transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM user_preferences WHERE user_id = ?1)",
        [&user_id],
        |row| row.get::<_, i64>(0),
    )? != 0
    {
        return Err(StorageError::MemberSetupAlreadyCompleted);
    }
    let membership_role = decode_membership_role(&role)?;
    let membership_status = decode_membership_status(&status)?;
    let membership_revision = decode_membership_revision(revision)?;
    if membership_role != MembershipRole::Member
        || membership_status != StoredMembershipStatus::Active
    {
        return Err(StorageError::InvalidMemberSetupToken);
    }

    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Admission,
    )?;
    prepare_account_audit_admission(
        &transaction,
        &account_id,
        AuditAdmission::General,
        limits,
        &timestamp,
    )?;
    cleanup_unusable_auth_sessions_in_transaction(&transaction, &timestamp, Some(&user_id))?;
    require_auth_session_capacity(&transaction, &user_id, &timestamp, limits)?;
    let changed = transaction.execute(
        r#"UPDATE users
           SET password_hash = ?1, status = 'active', updated_at = ?2
           WHERE id = ?3 AND status = 'disabled'"#,
        params![password_hash, timestamp, user_id],
    )?;
    if changed != 1 {
        return Err(StorageError::MemberSetupAlreadyCompleted);
    }
    transaction.execute(
        r#"INSERT INTO user_preferences(
               user_id, theme, preferred_model, revision, updated_at
           ) VALUES (?1, 'system', NULL, 1, ?2)"#,
        params![user_id, timestamp],
    )?;
    let consumed = transaction.execute(
        "DELETE FROM member_setup_tokens WHERE token_digest = ?1",
        [&setup_digest],
    )?;
    if consumed != 1 {
        return Err(StorageError::InvalidMemberSetupToken);
    }
    insert_auth_session(
        &transaction,
        &AuthSessionInsert {
            auth_session_id: commit.auth_session_id.as_str(),
            account_id: &account_id,
            user_id: &user_id,
            membership_revision: membership_revision.get(),
            token_hash: session_token_hash,
            csrf_hash,
            expires_at: session_expires_at,
            timestamp: &timestamp,
        },
    )?;
    append_account_audit_event(
        &transaction,
        &account_id,
        AccountAuditEventInput {
            actor_user_id: Some(&user_id),
            action: "member.setup_completed",
            target_kind: "member",
            target_id: &user_id,
            metadata: json!({ "membership_revision": membership_revision.get() }),
        },
        &timestamp,
    )?;
    let member = query_member(&transaction, &account_id, &user_id)?;
    let user = query_user(&transaction, &user_id)?;
    let principal = AuthPrincipal {
        user,
        authz: AuthzContext {
            account_id: decode_account_id(account_id)?,
            user_id,
            membership_role,
            membership_revision,
            auth_session_id: commit.auth_session_id,
        },
        csrf_hash: csrf_hash.to_owned(),
        expires_at: session_expires_at.to_owned(),
    };
    transaction.commit()?;
    Ok(MemberSetupResult { principal, member })
}

fn transition_member(
    connection: &mut Connection,
    context: &AuthzContext,
    commit: TransitionMemberCommit,
    limits: &StorageLimits,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<MemberTransitionResult, StorageError> {
    let user_id = normalized_account_value(&commit.user_id, "member user ID", 128)?;
    let timestamp = now();
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_current_authority(&transaction, context, AccountCapability::AccountAdmin)?;
    let current = query_member(&transaction, context.account_id.as_str(), user_id)?;

    if current.revision != commit.expected_revision {
        let replay_revision = commit
            .expected_revision
            .get()
            .checked_add(1)
            .and_then(|revision| MembershipRevision::new(revision).ok());
        if replay_revision == Some(current.revision)
            && current.role == commit.role
            && current.status == commit.status
        {
            let in_flight =
                query_in_flight_work(&transaction, context.account_id.as_str(), user_id)?;
            transaction.commit()?;
            return Ok(MemberTransitionResult {
                member: current,
                replayed: true,
                revoked_auth_sessions: 0,
                revoked_setup_tokens: 0,
                in_flight,
            });
        }
        return Err(StorageError::MembershipRevisionConflict);
    }
    if current.role != commit.expected_role || current.status != commit.expected_status {
        return Err(StorageError::MembershipRevisionConflict);
    }
    if current.role == commit.role && current.status == commit.status {
        let in_flight = query_in_flight_work(&transaction, context.account_id.as_str(), user_id)?;
        transaction.commit()?;
        return Ok(MemberTransitionResult {
            member: current,
            replayed: true,
            revoked_auth_sessions: 0,
            revoked_setup_tokens: 0,
            in_flight,
        });
    }

    let user_state: (String, i64) = transaction.query_row(
        r#"SELECT user.status,
                  EXISTS(SELECT 1 FROM user_preferences preference
                         WHERE preference.user_id = user.id)
           FROM users user WHERE user.id = ?1"#,
        [user_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let setup_completed = user_state.1 != 0;
    if commit.role == MembershipRole::Owner
        && (commit.status != StoredMembershipStatus::Active || !setup_completed)
    {
        return Err(StorageError::InvalidAccountData(
            "an owner membership must be active and have completed setup".into(),
        ));
    }
    let removes_active_owner = current.role == MembershipRole::Owner
        && current.status == StoredMembershipStatus::Active
        && (commit.role != MembershipRole::Owner
            || commit.status != StoredMembershipStatus::Active);
    if removes_active_owner {
        let active_owner_count: i64 = transaction.query_row(
            r#"SELECT COUNT(*) FROM account_memberships
               WHERE account_id = ?1 AND role = 'owner' AND status = 'active'"#,
            [context.account_id.as_str()],
            |row| row.get(0),
        )?;
        if active_owner_count <= 1 {
            return Err(StorageError::LastAccountOwner);
        }
    }

    let revokes_authority = current.status == StoredMembershipStatus::Active
        && (commit.status == StoredMembershipStatus::Disabled
            || (current.role == MembershipRole::Owner && commit.role == MembershipRole::Member));
    let (physical_gate, admission) = if revokes_authority {
        (
            PhysicalCapacityGate::ReservedProgress,
            AuditAdmission::Progress,
        )
    } else {
        (PhysicalCapacityGate::Admission, AuditAdmission::General)
    };
    require_connection_physical_capacity(&transaction, physical_limits, physical_gate)?;
    prepare_account_audit_admission(
        &transaction,
        context.account_id.as_str(),
        admission,
        limits,
        &timestamp,
    )?;

    let next_revision = current
        .revision
        .get()
        .checked_add(1)
        .ok_or(StorageError::IntegerOutOfRange("membership revision"))?;
    let changed = transaction.execute(
        r#"UPDATE account_memberships
           SET role = ?1, status = ?2, revision = ?3, updated_at = ?4
           WHERE account_id = ?5 AND user_id = ?6 AND revision = ?7"#,
        params![
            commit.role.as_str(),
            membership_status_label(commit.status),
            u64_to_i64(next_revision, "membership revision")?,
            timestamp,
            context.account_id.as_str(),
            user_id,
            u64_to_i64(current.revision.get(), "membership revision")?,
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::MembershipRevisionConflict);
    }

    let user_status = if commit.status == StoredMembershipStatus::Disabled {
        "disabled"
    } else if setup_completed {
        "active"
    } else {
        "disabled"
    };
    transaction.execute(
        r#"UPDATE users SET role = ?1, status = ?2, updated_at = ?3 WHERE id = ?4"#,
        params![commit.role.as_str(), user_status, timestamp, user_id],
    )?;
    let revoked_auth_sessions = transaction.execute(
        "DELETE FROM auth_sessions WHERE account_id = ?1 AND user_id = ?2",
        params![context.account_id.as_str(), user_id],
    )?;
    let revoked_setup_tokens = transaction.execute(
        "DELETE FROM member_setup_tokens WHERE account_id = ?1 AND user_id = ?2",
        params![context.account_id.as_str(), user_id],
    )?;
    let in_flight = query_in_flight_work(&transaction, context.account_id.as_str(), user_id)?;

    let action = if current.status == StoredMembershipStatus::Active
        && commit.status == StoredMembershipStatus::Disabled
    {
        "member.disabled"
    } else if current.status == StoredMembershipStatus::Disabled
        && commit.status == StoredMembershipStatus::Active
    {
        "member.enabled"
    } else {
        "member.role_changed"
    };
    append_account_audit_event(
        &transaction,
        context.account_id.as_str(),
        AccountAuditEventInput {
            actor_user_id: Some(&context.user_id),
            action,
            target_kind: "member",
            target_id: user_id,
            metadata: json!({
                "from": {
                    "role": current.role.as_str(),
                    "status": membership_status_label(current.status),
                    "revision": current.revision.get(),
                },
                "to": {
                    "role": commit.role.as_str(),
                    "status": membership_status_label(commit.status),
                    "revision": next_revision,
                },
                "revoked_auth_sessions": revoked_auth_sessions,
                "revoked_setup_tokens": revoked_setup_tokens,
                "in_flight_reply_jobs": in_flight.reply_job_ids.len(),
                "in_flight_dispatch_jobs": in_flight.dispatch_call_ids.len(),
                "in_flight_agent_model_jobs": in_flight.agent_model_job_ids.len(),
                "in_flight_agent_tool_calls": in_flight.agent_tool_call_ids.len(),
            }),
        },
        &timestamp,
    )?;
    let member = query_member(&transaction, context.account_id.as_str(), user_id)?;
    transaction.commit()?;
    Ok(MemberTransitionResult {
        member,
        replayed: false,
        revoked_auth_sessions: u64::try_from(revoked_auth_sessions)
            .map_err(|_| StorageError::IntegerOutOfRange("revoked authentication sessions"))?,
        revoked_setup_tokens: u64::try_from(revoked_setup_tokens)
            .map_err(|_| StorageError::IntegerOutOfRange("revoked setup tokens"))?,
        in_flight,
    })
}

fn query_in_flight_work(
    connection: &Connection,
    account_id: &str,
    user_id: &str,
) -> Result<InFlightWorkSummary, StorageError> {
    let mut reply_statement = connection.prepare(
        r#"SELECT id FROM reply_jobs
           WHERE account_id = ?1 AND actor_user_id = ?2 AND status = 'started'
           ORDER BY id"#,
    )?;
    let reply_job_ids = reply_statement
        .query_map(params![account_id, user_id], |row| row.get(0))?
        .collect::<Result<Vec<String>, _>>()?;
    let mut dispatch_statement = connection.prepare(
        r#"SELECT call_id FROM dispatch_jobs
           WHERE account_id = ?1 AND status = 'started'
             AND (initiating_actor_user_id = ?2 OR approving_actor_user_id = ?2)
           ORDER BY call_id"#,
    )?;
    let dispatch_call_ids = dispatch_statement
        .query_map(params![account_id, user_id], |row| row.get(0))?
        .collect::<Result<Vec<String>, _>>()?;
    let mut agent_model_statement = connection.prepare(
        r#"SELECT id FROM agent_model_jobs
           WHERE account_id = ?1 AND actor_user_id = ?2 AND status = 'started'
           ORDER BY id"#,
    )?;
    let agent_model_job_ids = agent_model_statement
        .query_map(params![account_id, user_id], |row| row.get(0))?
        .collect::<Result<Vec<String>, _>>()?;
    let mut agent_tool_statement = connection.prepare(
        r#"SELECT call.call_id
           FROM agent_tool_calls call
           JOIN agent_turns agent ON agent.id = call.agent_id
           WHERE call.account_id = ?1 AND call.status = 'started'
             AND (agent.actor_user_id = ?2 OR call.approving_actor_user_id = ?2)
           ORDER BY call.call_id"#,
    )?;
    let agent_tool_call_ids = agent_tool_statement
        .query_map(params![account_id, user_id], |row| row.get(0))?
        .collect::<Result<Vec<String>, _>>()?;
    Ok(InFlightWorkSummary {
        reply_job_ids,
        dispatch_call_ids,
        agent_model_job_ids,
        agent_tool_call_ids,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuditAdmission {
    General,
    Progress,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuditCompactionOutcome {
    NotNeeded,
    Compacted,
    BlockedByLegalHold,
    BlockedByArchive,
}

fn account_audit_compaction_error(outcome: AuditCompactionOutcome) -> StorageError {
    match outcome {
        AuditCompactionOutcome::BlockedByLegalHold => StorageError::AuditLegalHold,
        AuditCompactionOutcome::BlockedByArchive => StorageError::AuditArchiveRequired,
        AuditCompactionOutcome::NotNeeded | AuditCompactionOutcome::Compacted => {
            StorageError::AuditStorageExhausted
        }
    }
}

/// Evaluates the next compaction without changing the rollup or detailed rows.
/// Readiness uses this to distinguish a full-but-recoverable window from a
/// full window held in place by legal hold or a missing archive checkpoint.
fn inspect_account_audit_compaction(
    connection: &Connection,
    account_id: &str,
    limits: &StorageLimits,
) -> Result<AuditCompactionOutcome, StorageError> {
    let (detail_rows, legal_hold, archive_required, archive_through): (i64, i64, i64, i64) =
        connection.query_row(
            r#"SELECT policy.detail_rows, policy.legal_hold, policy.archive_required,
                      archive.through_sequence
               FROM account_audit_policies policy
               JOIN account_audit_archive_state archive
                 ON archive.account_id = policy.account_id
               WHERE policy.account_id = ?1"#,
            [account_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
    let detailed_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM account_audit_events WHERE account_id = ?1",
        [account_id],
        |row| row.get(0),
    )?;
    if detailed_count < detail_rows {
        return Ok(AuditCompactionOutcome::NotNeeded);
    }
    if legal_hold != 0 {
        return Ok(AuditCompactionOutcome::BlockedByLegalHold);
    }
    let desired = detailed_count
        .checked_add(1)
        .and_then(|value| value.checked_sub(detail_rows))
        .ok_or(StorageError::IntegerOutOfRange(
            "account audit compaction target",
        ))?;
    let batch_size = desired
        .min(capacity_limit(limits.account_audit_compaction_batch)?)
        .max(1);
    if archive_required != 0 {
        let tail: Option<i64> = connection
            .query_row(
                r#"SELECT sequence FROM account_audit_events
                   WHERE account_id = ?1
                   ORDER BY sequence LIMIT 1 OFFSET ?2"#,
                params![account_id, batch_size - 1],
                |row| row.get(0),
            )
            .optional()?;
        let tail = tail.ok_or_else(|| {
            StorageError::CorruptData(
                "the account audit compaction window has no durable tail".into(),
            )
        })?;
        if archive_through < tail {
            return Ok(AuditCompactionOutcome::BlockedByArchive);
        }
    }
    Ok(AuditCompactionOutcome::Compacted)
}

fn require_account_audit_capacity_readiness(
    connection: &Connection,
    limits: &StorageLimits,
) -> Result<(), StorageError> {
    let account_ordinary = capacity_limit(
        limits
            .account_audit_rows_per_account
            .checked_sub(limits.account_audit_progress_rows_per_account)
            .ok_or(StorageError::IntegerOutOfRange(
                "account audit ordinary capacity",
            ))?,
    )?;
    let global_ordinary = capacity_limit(
        limits
            .account_audit_rows_global
            .checked_sub(limits.account_audit_progress_rows_global)
            .ok_or(StorageError::IntegerOutOfRange(
                "global audit ordinary capacity",
            ))?,
    )?;
    let global_count: i64 =
        connection.query_row("SELECT COUNT(*) FROM account_audit_events", [], |row| {
            row.get(0)
        })?;
    let global_full = global_count >= global_ordinary;
    let mut statement = connection.prepare(
        r#"SELECT account.id, COUNT(event.sequence)
           FROM accounts account
           LEFT JOIN account_audit_events event ON event.account_id = account.id
           GROUP BY account.id ORDER BY account.id"#,
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);

    let mut global_compactable = false;
    let mut global_legal_hold = false;
    let mut global_archive_required = false;
    for (account_id, account_count) in rows {
        let account_full = account_count >= account_ordinary;
        if !account_full && !global_full {
            continue;
        }
        let outcome = inspect_account_audit_compaction(connection, &account_id, limits)?;
        if account_full && outcome != AuditCompactionOutcome::Compacted {
            return Err(account_audit_compaction_error(outcome));
        }
        if global_full {
            match outcome {
                AuditCompactionOutcome::Compacted => global_compactable = true,
                AuditCompactionOutcome::BlockedByLegalHold => global_legal_hold = true,
                AuditCompactionOutcome::BlockedByArchive => global_archive_required = true,
                AuditCompactionOutcome::NotNeeded => {}
            }
        }
    }
    if global_full && !global_compactable {
        return Err(if global_legal_hold {
            StorageError::AuditLegalHold
        } else if global_archive_required {
            StorageError::AuditArchiveRequired
        } else {
            StorageError::AuditStorageExhausted
        });
    }
    Ok(())
}

#[derive(Debug)]
struct AccountAuditEventRow {
    account_id: String,
    sequence: i64,
    actor_user_id: Option<String>,
    action: String,
    outcome: String,
    target_kind: String,
    target_id: String,
    metadata_json: String,
    occurred_at: String,
    previous_hash: String,
    event_hash: String,
}

impl AccountAuditEventRow {
    fn decode(self) -> Result<AccountAuditEvent, StorageError> {
        Ok(AccountAuditEvent {
            account_id: decode_account_id(self.account_id)?,
            sequence: i64_to_u64(self.sequence, "account audit sequence")?,
            actor_user_id: self.actor_user_id,
            action: self.action,
            outcome: self.outcome,
            target_kind: self.target_kind,
            target_id: self.target_id,
            metadata: serde_json::from_str(&self.metadata_json)?,
            occurred_at: self.occurred_at,
            previous_hash: self.previous_hash,
            event_hash: self.event_hash,
        })
    }
}

fn decode_account_audit_event_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<AccountAuditEventRow> {
    Ok(AccountAuditEventRow {
        account_id: row.get(0)?,
        sequence: row.get(1)?,
        actor_user_id: row.get(2)?,
        action: row.get(3)?,
        outcome: row.get(4)?,
        target_kind: row.get(5)?,
        target_id: row.get(6)?,
        metadata_json: row.get(7)?,
        occurred_at: row.get(8)?,
        previous_hash: row.get(9)?,
        event_hash: row.get(10)?,
    })
}

const ACCOUNT_AUDIT_EVENT_SELECT: &str = r#"SELECT account_id, sequence, actor_user_id, action, outcome,
              target_kind, target_id, metadata_json, occurred_at,
              previous_hash, event_hash
       FROM account_audit_events"#;

fn prepare_account_audit_admission(
    connection: &Connection,
    account_id: &str,
    admission: AuditAdmission,
    limits: &StorageLimits,
    timestamp: &str,
) -> Result<(), StorageError> {
    let compaction = compact_account_audit_once(connection, account_id, limits, timestamp)?;
    let account_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM account_audit_events WHERE account_id = ?1",
        [account_id],
        |row| row.get(0),
    )?;
    let global_count: i64 =
        connection.query_row("SELECT COUNT(*) FROM account_audit_events", [], |row| {
            row.get(0)
        })?;
    let account_hard = capacity_limit(limits.account_audit_rows_per_account)?;
    let global_hard = capacity_limit(limits.account_audit_rows_global)?;
    let account_progress = capacity_limit(limits.account_audit_progress_rows_per_account)?;
    let global_progress = capacity_limit(limits.account_audit_progress_rows_global)?;
    let (account_limit, global_limit) =
        match admission {
            AuditAdmission::General => {
                (
                    account_hard.checked_sub(account_progress).ok_or(
                        StorageError::IntegerOutOfRange("account audit ordinary capacity"),
                    )?,
                    global_hard.checked_sub(global_progress).ok_or(
                        StorageError::IntegerOutOfRange("global audit ordinary capacity"),
                    )?,
                )
            }
            AuditAdmission::Progress => (account_hard, global_hard),
        };
    if account_count >= account_limit || global_count >= global_limit {
        return Err(account_audit_compaction_error(compaction));
    }
    Ok(())
}

fn compact_account_audit_once(
    connection: &Connection,
    account_id: &str,
    limits: &StorageLimits,
    timestamp: &str,
) -> Result<AuditCompactionOutcome, StorageError> {
    let (detail_rows, legal_hold, archive_required): (i64, i64, i64) = connection.query_row(
        r#"SELECT detail_rows, legal_hold, archive_required
           FROM account_audit_policies WHERE account_id = ?1"#,
        [account_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let detailed_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM account_audit_events WHERE account_id = ?1",
        [account_id],
        |row| row.get(0),
    )?;
    if detailed_count < detail_rows {
        return Ok(AuditCompactionOutcome::NotNeeded);
    }
    if legal_hold != 0 {
        return Ok(AuditCompactionOutcome::BlockedByLegalHold);
    }
    let desired = detailed_count
        .checked_add(1)
        .and_then(|value| value.checked_sub(detail_rows))
        .ok_or(StorageError::IntegerOutOfRange(
            "account audit compaction target",
        ))?;
    let batch_limit = capacity_limit(limits.account_audit_compaction_batch)?;
    let batch_size = desired.min(batch_limit).max(1);
    compact_account_audit_batch(
        connection,
        account_id,
        batch_size,
        archive_required != 0,
        timestamp,
    )
}

fn compact_account_audit_batch(
    connection: &Connection,
    account_id: &str,
    batch_size: i64,
    archive_required: bool,
    timestamp: &str,
) -> Result<AuditCompactionOutcome, StorageError> {
    if batch_size <= 0 {
        return Ok(AuditCompactionOutcome::NotNeeded);
    }
    let (through_sequence, event_count, previous_digest, previous_event_hash): (
        i64,
        i64,
        String,
        String,
    ) = connection.query_row(
        r#"SELECT through_sequence, event_count, digest, last_event_hash
           FROM account_audit_rollups WHERE account_id = ?1"#,
        [account_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    if through_sequence != event_count
        || !is_lower_hex_digest(&previous_digest)
        || !is_lower_hex_digest(&previous_event_hash)
    {
        return Err(StorageError::CorruptData(
            "the account audit rollup is structurally inconsistent".into(),
        ));
    }
    let sql = format!(
        r#"{ACCOUNT_AUDIT_EVENT_SELECT}
           WHERE account_id = ?1 AND sequence > ?2
           ORDER BY sequence LIMIT ?3"#
    );
    let mut statement = connection.prepare(&sql)?;
    let rows = statement
        .query_map(
            params![account_id, through_sequence, batch_size],
            decode_account_audit_event_row,
        )?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.is_empty() {
        return Ok(AuditCompactionOutcome::NotNeeded);
    }
    for (offset, row) in rows.iter().enumerate() {
        let expected_sequence = through_sequence
            .checked_add(i64::try_from(offset + 1).map_err(|_| {
                StorageError::IntegerOutOfRange("account audit compaction sequence offset")
            })?)
            .ok_or(StorageError::IntegerOutOfRange(
                "account audit compaction sequence",
            ))?;
        if row.sequence != expected_sequence {
            return Err(StorageError::CorruptData(
                "the account audit detailed prefix is not contiguous".into(),
            ));
        }
    }
    let tail = rows
        .last()
        .expect("a non-empty audit compaction batch has a tail");
    if archive_required {
        let archived_through: i64 = connection.query_row(
            "SELECT through_sequence FROM account_audit_archive_state WHERE account_id = ?1",
            [account_id],
            |row| row.get(0),
        )?;
        if archived_through < tail.sequence {
            return Ok(AuditCompactionOutcome::BlockedByArchive);
        }
    }
    let new_digest = account_audit_rollup_digest(&previous_digest, &rows)?;
    let changed = connection.execute(
        r#"UPDATE account_audit_rollups
           SET through_sequence = ?1, event_count = ?1, digest = ?2,
               last_event_hash = ?3, updated_at = ?4
           WHERE account_id = ?5 AND through_sequence = ?6 AND digest = ?7"#,
        params![
            tail.sequence,
            new_digest,
            tail.event_hash,
            timestamp,
            account_id,
            through_sequence,
            previous_digest,
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::CorruptData(
            "the account audit rollup changed during compaction".into(),
        ));
    }
    let deleted = connection.execute(
        r#"DELETE FROM account_audit_events
           WHERE account_id = ?1 AND sequence > ?2 AND sequence <= ?3"#,
        params![account_id, through_sequence, tail.sequence],
    )?;
    if deleted != rows.len() {
        return Err(StorageError::CorruptData(
            "the account audit detailed prefix changed during compaction".into(),
        ));
    }
    Ok(AuditCompactionOutcome::Compacted)
}

fn account_audit_rollup_digest(
    previous_digest: &str,
    rows: &[AccountAuditEventRow],
) -> Result<String, StorageError> {
    if !is_lower_hex_digest(previous_digest) {
        return Err(StorageError::CorruptData(
            "the account audit rollup digest is malformed".into(),
        ));
    }
    let mut digest = previous_digest.to_owned();
    for row in rows {
        let mut hasher = Sha256::new();
        hasher.update(ACCOUNT_AUDIT_ROLLUP_DOMAIN);
        hasher.update(digest.as_bytes());
        hasher.update(row.sequence.to_be_bytes());
        hasher.update(row.event_hash.as_bytes());
        digest = format!("{:x}", hasher.finalize());
    }
    Ok(digest)
}

struct AccountAuditEventInput<'a> {
    actor_user_id: Option<&'a str>,
    action: &'a str,
    target_kind: &'a str,
    target_id: &'a str,
    metadata: Value,
}

fn append_account_audit_event(
    connection: &Connection,
    account_id: &str,
    input: AccountAuditEventInput<'_>,
    timestamp: &str,
) -> Result<AccountAuditEvent, StorageError> {
    let AccountAuditEventInput {
        actor_user_id,
        action,
        target_kind,
        target_id,
        metadata,
    } = input;
    normalized_account_value(account_id, "audit account ID", 128)?;
    if let Some(actor_user_id) = actor_user_id {
        normalized_account_value(actor_user_id, "audit actor user ID", 128)?;
    }
    normalized_account_value(action, "audit action", 96)?;
    normalized_account_value(target_kind, "audit target kind", 64)?;
    normalized_account_value(target_id, "audit target ID", 384)?;
    if !metadata.is_object() {
        return Err(StorageError::InvalidAccountData(
            "audit metadata must be a JSON object".into(),
        ));
    }
    let metadata_json = serde_json::to_string(&metadata)?;
    if metadata_json.len() > ACCOUNT_AUDIT_METADATA_MAX_BYTES {
        return Err(StorageError::InvalidAccountData(
            "audit metadata exceeds its supported bound".into(),
        ));
    }
    let tail = connection
        .query_row(
            r#"SELECT sequence, event_hash FROM account_audit_events
               WHERE account_id = ?1 ORDER BY sequence DESC LIMIT 1"#,
            [account_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let (previous_sequence, previous_hash) = match tail {
        Some(tail) => tail,
        None => connection.query_row(
            r#"SELECT through_sequence, last_event_hash
               FROM account_audit_rollups WHERE account_id = ?1"#,
            [account_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?,
    };
    let sequence = previous_sequence
        .checked_add(1)
        .ok_or(StorageError::IntegerOutOfRange("account audit sequence"))?;
    let event_hash = account_audit_event_hash(
        &previous_hash,
        sequence,
        account_id,
        actor_user_id,
        action,
        "succeeded",
        target_kind,
        target_id,
        &metadata_json,
        timestamp,
    )?;
    connection.execute(
        r#"INSERT INTO account_audit_events(
               account_id, sequence, actor_user_id, action, outcome,
               target_kind, target_id, metadata_json, occurred_at,
               previous_hash, event_hash
           ) VALUES (?1, ?2, ?3, ?4, 'succeeded', ?5, ?6, ?7, ?8, ?9, ?10)"#,
        params![
            account_id,
            sequence,
            actor_user_id,
            action,
            target_kind,
            target_id,
            metadata_json,
            timestamp,
            previous_hash,
            event_hash,
        ],
    )?;
    Ok(AccountAuditEvent {
        account_id: decode_account_id(account_id.to_owned())?,
        sequence: i64_to_u64(sequence, "account audit sequence")?,
        actor_user_id: actor_user_id.map(str::to_owned),
        action: action.to_owned(),
        outcome: "succeeded".into(),
        target_kind: target_kind.to_owned(),
        target_id: target_id.to_owned(),
        metadata,
        occurred_at: timestamp.to_owned(),
        previous_hash,
        event_hash,
    })
}

#[allow(clippy::too_many_arguments)]
fn account_audit_event_hash(
    previous_hash: &str,
    sequence: i64,
    account_id: &str,
    actor_user_id: Option<&str>,
    action: &str,
    outcome: &str,
    target_kind: &str,
    target_id: &str,
    metadata_json: &str,
    occurred_at: &str,
) -> Result<String, StorageError> {
    if sequence <= 0 || !is_lower_hex_digest(previous_hash) {
        return Err(StorageError::CorruptData(
            "the account audit event chain boundary is malformed".into(),
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(ACCOUNT_AUDIT_EVENT_DOMAIN);
    hasher.update(previous_hash.as_bytes());
    hasher.update(sequence.to_be_bytes());
    for field in [
        account_id.as_bytes(),
        actor_user_id.unwrap_or_default().as_bytes(),
        action.as_bytes(),
        outcome.as_bytes(),
        target_kind.as_bytes(),
        target_id.as_bytes(),
        metadata_json.as_bytes(),
        occurred_at.as_bytes(),
    ] {
        let length = u64::try_from(field.len())
            .map_err(|_| StorageError::IntegerOutOfRange("account audit hash field"))?;
        hasher.update(length.to_be_bytes());
        hasher.update(field);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn query_account_audit_state(
    connection: &Connection,
    account_id: &str,
    limits: &StorageLimits,
) -> Result<AccountAuditState, StorageError> {
    let policy_row: (i64, i64, i64, i64, String) = connection.query_row(
        r#"SELECT detail_rows, legal_hold, archive_required, revision, updated_at
           FROM account_audit_policies WHERE account_id = ?1"#,
        [account_id],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;
    let rollup_row: (i64, i64, String, String, String) = connection.query_row(
        r#"SELECT through_sequence, event_count, digest, last_event_hash, updated_at
           FROM account_audit_rollups WHERE account_id = ?1"#,
        [account_id],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;
    let archive_row: (i64, String, Option<String>, i64, String) = connection.query_row(
        r#"SELECT through_sequence, event_hash, archive_reference, revision, updated_at
           FROM account_audit_archive_state WHERE account_id = ?1"#,
        [account_id],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;
    let account_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM account_audit_events WHERE account_id = ?1",
        [account_id],
        |row| row.get(0),
    )?;
    let global_count: i64 =
        connection.query_row("SELECT COUNT(*) FROM account_audit_events", [], |row| {
            row.get(0)
        })?;
    let account_hard = capacity_limit(limits.account_audit_rows_per_account)?;
    let global_hard = capacity_limit(limits.account_audit_rows_global)?;
    let account_ordinary = account_hard
        .checked_sub(capacity_limit(
            limits.account_audit_progress_rows_per_account,
        )?)
        .ok_or(StorageError::IntegerOutOfRange(
            "account audit ordinary capacity",
        ))?;
    let global_ordinary = global_hard
        .checked_sub(capacity_limit(limits.account_audit_progress_rows_global)?)
        .ok_or(StorageError::IntegerOutOfRange(
            "global audit ordinary capacity",
        ))?;
    let ordinary_remaining = account_ordinary
        .saturating_sub(account_count)
        .max(0)
        .min(global_ordinary.saturating_sub(global_count).max(0));
    let progress_remaining = account_hard
        .saturating_sub(account_count)
        .max(0)
        .min(global_hard.saturating_sub(global_count).max(0));
    let account = decode_account_id(account_id.to_owned())?;
    Ok(AccountAuditState {
        policy: AccountAuditPolicy {
            account_id: account.clone(),
            detail_rows: i64_to_u64(policy_row.0, "account audit detail rows")?,
            legal_hold: policy_row.1 != 0,
            archive_required: policy_row.2 != 0,
            revision: i64_to_u64(policy_row.3, "account audit policy revision")?,
            updated_at: policy_row.4,
        },
        rollup: AccountAuditRollup {
            account_id: account.clone(),
            through_sequence: i64_to_u64(rollup_row.0, "account audit rollup sequence")?,
            event_count: i64_to_u64(rollup_row.1, "account audit rollup event count")?,
            digest: rollup_row.2,
            last_event_hash: rollup_row.3,
            updated_at: rollup_row.4,
        },
        archive: AccountAuditArchiveState {
            account_id: account,
            through_sequence: i64_to_u64(archive_row.0, "account audit archive sequence")?,
            event_hash: archive_row.1,
            archive_reference: archive_row.2,
            revision: i64_to_u64(archive_row.3, "account audit archive revision")?,
            updated_at: archive_row.4,
        },
        detailed_rows: i64_to_u64(account_count, "account audit detailed rows")?,
        ordinary_capacity_remaining: i64_to_u64(
            ordinary_remaining,
            "account audit ordinary capacity",
        )?,
        progress_capacity_remaining: i64_to_u64(
            progress_remaining,
            "account audit progress capacity",
        )?,
    })
}

fn query_account_audit_page(
    connection: &Connection,
    context: &AuthzContext,
    cursor_value: Option<&str>,
    limit: usize,
    limits: &StorageLimits,
) -> Result<AccountAuditPage, StorageError> {
    require_current_authority(connection, context, AccountCapability::AuditRead)?;
    let fetch_limit = validated_read_page_limit(limit, ACCOUNT_AUDIT_PAGE_MAX_LIMIT)?;
    let cursor = cursor_value
        .map(|value| {
            cursor::decode_account_audit(value, context.account_id.as_str(), &context.user_id)
        })
        .transpose()?;
    let sql = format!(
        r#"{ACCOUNT_AUDIT_EVENT_SELECT}
           WHERE account_id = ?1 AND (?2 IS NULL OR sequence < ?2)
           ORDER BY sequence DESC LIMIT ?3"#
    );
    let mut statement = connection.prepare(&sql)?;
    let mut items = statement
        .query_map(
            params![context.account_id.as_str(), cursor, fetch_limit],
            decode_account_audit_event_row,
        )?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(AccountAuditEventRow::decode)
        .collect::<Result<Vec<_>, _>>()?;
    let has_more = items.len() > limit;
    if has_more {
        items.pop();
    }
    let next_cursor = if has_more {
        let tail = items
            .last()
            .expect("an audit page with more rows has a tail");
        Some(cursor::encode_account_audit(
            context.account_id.as_str(),
            &context.user_id,
            tail.sequence,
        )?)
    } else {
        None
    };
    Ok(AccountAuditPage {
        items,
        next_cursor,
        state: query_account_audit_state(connection, context.account_id.as_str(), limits)?,
    })
}

fn update_account_audit_policy(
    connection: &mut Connection,
    context: &AuthzContext,
    commit: UpdateAccountAuditPolicyCommit,
    limits: &StorageLimits,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<AccountAuditState, StorageError> {
    let timestamp = now();
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_current_authority(&transaction, context, AccountCapability::AccountAdmin)?;
    if commit.detail_rows == 0
        || commit.detail_rows
            > u64::try_from(limits.account_audit_detail_rows)
                .map_err(|_| StorageError::IntegerOutOfRange("account audit detail rows"))?
    {
        return Err(StorageError::InvalidAccountData(format!(
            "account audit detail rows must be between 1 and {}",
            limits.account_audit_detail_rows
        )));
    }
    let current: (i64, i64, i64, i64) = transaction.query_row(
        r#"SELECT detail_rows, legal_hold, archive_required, revision
           FROM account_audit_policies WHERE account_id = ?1"#,
        [context.account_id.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    if i64_to_u64(current.3, "account audit policy revision")? != commit.expected_revision {
        return Err(StorageError::AuditPolicyConflict);
    }
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::ReservedProgress,
    )?;
    transaction.execute(
        r#"UPDATE account_audit_policies
           SET detail_rows = ?1, legal_hold = ?2, archive_required = ?3,
               revision = revision + 1, updated_at = ?4
           WHERE account_id = ?5 AND revision = ?6"#,
        params![
            u64_to_i64(commit.detail_rows, "account audit detail rows")?,
            i64::from(commit.legal_hold),
            i64::from(commit.archive_required),
            timestamp,
            context.account_id.as_str(),
            current.3,
        ],
    )?;
    prepare_account_audit_admission(
        &transaction,
        context.account_id.as_str(),
        AuditAdmission::Progress,
        limits,
        &timestamp,
    )?;
    append_account_audit_event(
        &transaction,
        context.account_id.as_str(),
        AccountAuditEventInput {
            actor_user_id: Some(&context.user_id),
            action: "audit.policy_updated",
            target_kind: "account_audit_policy",
            target_id: context.account_id.as_str(),
            metadata: json!({
                "detail_rows": commit.detail_rows,
                "legal_hold": commit.legal_hold,
                "archive_required": commit.archive_required,
                "revision": commit.expected_revision + 1,
            }),
        },
        &timestamp,
    )?;
    let state = query_account_audit_state(&transaction, context.account_id.as_str(), limits)?;
    transaction.commit()?;
    Ok(state)
}

fn checkpoint_account_audit_archive(
    connection: &mut Connection,
    context: &AuthzContext,
    commit: AccountAuditCheckpointCommit,
    limits: &StorageLimits,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<AccountAuditState, StorageError> {
    let timestamp = now();
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_current_authority(&transaction, context, AccountCapability::AccountAdmin)?;
    if commit.through_sequence == 0 || !is_lower_hex_digest(&commit.event_hash) {
        return Err(StorageError::AuditCheckpointConflict);
    }
    let archive_reference = normalized_account_value(
        &commit.archive_reference,
        "account audit archive reference",
        512,
    )?;
    let through_sequence =
        u64_to_i64(commit.through_sequence, "account audit checkpoint sequence")?;
    let current: (i64, i64) = transaction.query_row(
        r#"SELECT through_sequence, revision FROM account_audit_archive_state
           WHERE account_id = ?1"#,
        [context.account_id.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if i64_to_u64(current.1, "account audit archive revision")? != commit.expected_revision
        || through_sequence < current.0
    {
        return Err(StorageError::AuditCheckpointConflict);
    }
    let rollup: (i64, String) = transaction.query_row(
        r#"SELECT through_sequence, last_event_hash FROM account_audit_rollups
           WHERE account_id = ?1"#,
        [context.account_id.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let durable_hash = if through_sequence == rollup.0 {
        Some(rollup.1)
    } else if through_sequence > rollup.0 {
        transaction
            .query_row(
                r#"SELECT event_hash FROM account_audit_events
                   WHERE account_id = ?1 AND sequence = ?2"#,
                params![context.account_id.as_str(), through_sequence],
                |row| row.get::<_, String>(0),
            )
            .optional()?
    } else {
        None
    };
    if durable_hash.as_deref() != Some(commit.event_hash.as_str()) {
        return Err(StorageError::AuditCheckpointConflict);
    }
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::ReservedProgress,
    )?;
    transaction.execute(
        r#"UPDATE account_audit_archive_state
           SET through_sequence = ?1, event_hash = ?2, archive_reference = ?3,
               revision = revision + 1, updated_at = ?4
           WHERE account_id = ?5 AND revision = ?6"#,
        params![
            through_sequence,
            commit.event_hash,
            archive_reference,
            timestamp,
            context.account_id.as_str(),
            current.1,
        ],
    )?;
    prepare_account_audit_admission(
        &transaction,
        context.account_id.as_str(),
        AuditAdmission::Progress,
        limits,
        &timestamp,
    )?;
    append_account_audit_event(
        &transaction,
        context.account_id.as_str(),
        AccountAuditEventInput {
            actor_user_id: Some(&context.user_id),
            action: "audit.archive_checkpointed",
            target_kind: "account_audit_archive",
            target_id: context.account_id.as_str(),
            metadata: json!({
                "through_sequence": commit.through_sequence,
                "event_hash": commit.event_hash,
                "archive_reference": archive_reference,
                "revision": commit.expected_revision + 1,
            }),
        },
        &timestamp,
    )?;
    let state = query_account_audit_state(&transaction, context.account_id.as_str(), limits)?;
    transaction.commit()?;
    Ok(state)
}

fn bind_runtime_identity(
    connection: &mut Connection,
    identity: RuntimeIdentity,
    physical_limits: &SqlitePhysicalLimits,
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
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Admission,
    )?;
    transaction.execute(
        r#"INSERT INTO runtime_identity(
               singleton, profile, environment, primary_session_id, primary_run_id,
               policy_id, policy_revision, bound_at, account_id
           ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
        params![
            identity.profile,
            identity.environment,
            identity.primary_session_id,
            identity.primary_run_id,
            identity.policy_id,
            identity.policy_revision,
            Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            LOCAL_ACCOUNT_ID,
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
    limits: &StorageLimits,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<bool, StorageError> {
    validate_seed(&snapshot, &events)?;
    let encoded_events = events
        .iter()
        .map(encode_event_payload)
        .collect::<Result<Vec<_>, _>>()?;
    let encoded_event_bytes = checked_event_payload_total(&encoded_events)?;
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
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Admission,
    )?;
    if events.len() > limits.run_event_slots_per_run {
        return Err(StorageError::StorageQuotaExceeded);
    }

    transaction.execute(
        r#"INSERT INTO incidents(
               id, title, severity, status, service, region, user_impact, since, account_id
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"#,
        params![
            snapshot.incident.id,
            snapshot.incident.title,
            severity_to_db(&snapshot.incident.severity),
            incident_status_to_db(&snapshot.incident.status),
            snapshot.incident.service,
            snapshot.incident.region,
            snapshot.incident.user_impact,
            snapshot.incident.since,
            LOCAL_ACCOUNT_ID,
        ],
    )?;
    transaction.execute(
        r#"INSERT INTO runs(
               id, incident_id, status, environment, started_at, duration_seconds, agent,
               sequence, projection_sequence, metrics_json, evidence_json, tool_policy_json,
               execution_status, account_id
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9, ?10, ?11, ?12, ?13)"#,
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
            LOCAL_ACCOUNT_ID,
        ],
    )?;
    require_run_event_capacity(
        &transaction,
        &snapshot.run.id,
        EventCapacityRequest::events(0, encoded_event_bytes),
        limits,
    )?;
    for (event, payload) in events.iter().zip(&encoded_events) {
        if event.data.is_some() {
            insert_event_v2(&transaction, &snapshot.run.id, event, payload)?;
        } else {
            insert_event_v1(&transaction, &snapshot.run.id, event, payload)?;
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
    limits: &StorageLimits,
    physical_limits: &SqlitePhysicalLimits,
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

    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Admission,
    )?;

    let mut summary = query_session_summary_optional(&transaction, session_id)?;
    if summary.is_none() {
        validated_new_session_id(session_id, "session ID")?;
        validated_new_session_title(title, "session title")?;
        require_session_count_capacity(&transaction, LOCAL_ACCOUNT_ID, None, limits)?;
        let timestamp = now();
        transaction.execute(
            r#"INSERT INTO sessions(
                   id, title, status, created_at, updated_at, sequence,
                   projection_sequence, active_turn_id, account_id
               ) VALUES (?1, ?2, 'ready', ?3, ?3, 0, 0, NULL, ?4)"#,
            params![session_id, title, timestamp, LOCAL_ACCOUNT_ID],
        )?;
        let event = build_session_event(
            session_id,
            1,
            &timestamp,
            SessionEventData::SessionCreated {
                title: title.to_owned(),
            },
        );
        let payload = encode_event_payload(&event)?;
        require_session_event_capacity(
            &transaction,
            session_id,
            EventCapacityRequest::events(1, payload.bytes),
            limits,
        )?;
        insert_session_event(&transaction, session_id, &event, &payload)?;
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
    let payload = encode_event_payload(&event)?;
    require_session_event_capacity(
        &transaction,
        session_id,
        EventCapacityRequest::events(1, payload.bytes),
        limits,
    )?;
    insert_session_event(&transaction, session_id, &event, &payload)?;
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
    context: &AuthzContext,
) -> Result<Vec<SessionSummary>, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_current_authority(&transaction, context, AccountCapability::Read)?;
    let mut statement = transaction.prepare(
        r#"SELECT id, title, status, created_at, updated_at, sequence,
                  projection_sequence, active_turn_id
           FROM sessions
           WHERE account_id = ?1
           ORDER BY updated_at DESC, id"#,
    )?;
    let rows = statement
        .query_map([context.account_id.as_str()], decode_session_summary_row)?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    let summaries = rows
        .into_iter()
        .map(StoredSessionSummaryRow::decode)
        .collect::<Result<Vec<_>, _>>()?;
    transaction.commit()?;
    Ok(summaries)
}

fn query_session_summary_page_for_actor(
    connection: &mut Connection,
    context: &AuthzContext,
    page_cursor: Option<&str>,
    limit: usize,
) -> Result<SessionSummaryPage, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_current_authority(&transaction, context, AccountCapability::Read)?;
    let fetch_limit = validated_read_page_limit(limit, COLLECTION_PAGE_MAX_LIMIT)?;
    let page_cursor = page_cursor
        .map(|value| {
            cursor::decode_session_list(value, context.account_id.as_str(), &context.user_id)
        })
        .transpose()?;

    let rows = if let Some(page_cursor) = page_cursor {
        let mut statement = transaction.prepare(
            r#"SELECT id, title, status, created_at, updated_at, sequence,
                      projection_sequence, active_turn_id
               FROM sessions
               WHERE account_id = ?1
                 AND (updated_at < ?2 OR (updated_at = ?2 AND id > ?3))
               ORDER BY updated_at DESC, id ASC
               LIMIT ?4"#,
        )?;
        statement
            .query_map(
                params![
                    context.account_id.as_str(),
                    page_cursor.first,
                    page_cursor.second,
                    fetch_limit
                ],
                decode_session_summary_row,
            )?
            .collect::<Result<Vec<_>, _>>()?
    } else {
        let mut statement = transaction.prepare(
            r#"SELECT id, title, status, created_at, updated_at, sequence,
                      projection_sequence, active_turn_id
               FROM sessions
               WHERE account_id = ?1
               ORDER BY updated_at DESC, id ASC
               LIMIT ?2"#,
        )?;
        statement
            .query_map(
                params![context.account_id.as_str(), fetch_limit],
                decode_session_summary_row,
            )?
            .collect::<Result<Vec<_>, _>>()?
    };

    let has_more = rows.len() > limit;
    let mut summaries = Vec::with_capacity(rows.len().min(limit));
    for row in rows.into_iter().take(limit) {
        let summary = row.decode()?;
        validate_session_event_tail(&transaction, &summary)?;
        summaries.push(summary);
    }
    let next_cursor = if has_more {
        let last = summaries.last().ok_or_else(|| {
            StorageError::CorruptData("Session page sentinel has no returned item".into())
        })?;
        Some(cursor::encode_session_list(
            context.account_id.as_str(),
            &context.user_id,
            &last.updated_at,
            &last.id,
        )?)
    } else {
        None
    };
    transaction.commit()?;
    Ok(SessionSummaryPage {
        items: summaries,
        next_cursor,
    })
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
    context: &AuthzContext,
    session_id: &str,
) -> Result<SessionSummary, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_active_session_actor(&transaction, session_id, context)?;
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
        pagination: None,
    })
}

fn query_session_detail_for_actor(
    connection: &mut Connection,
    context: &AuthzContext,
    session_id: &str,
) -> Result<SessionDetail, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_active_session_actor(&transaction, session_id, context)?;
    let session = query_session_summary(&transaction, session_id)?;

    let mut run_statement = transaction.prepare(
        r#"SELECT sr.run_id
           FROM session_runs sr
           JOIN runs r ON r.id = sr.run_id
           WHERE sr.session_id = ?1 AND r.account_id = ?2
           ORDER BY sr.attached_at, sr.run_id"#,
    )?;
    let run_ids = run_statement
        .query_map(params![session_id, context.account_id.as_str()], |row| {
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
        pagination: None,
    })
}

#[allow(clippy::too_many_arguments)]
fn query_session_detail_page_for_actor(
    connection: &mut Connection,
    context: &AuthzContext,
    session_id: &str,
    run_ids_before: Option<&str>,
    run_ids_limit: usize,
    turns_before: Option<&str>,
    turns_limit: usize,
    events_before: Option<&str>,
    events_limit: usize,
) -> Result<SessionDetail, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    // Authorization deliberately precedes semantic cursor and limit checks so
    // a foreign resource cannot become a cursor oracle.
    require_active_session_actor(&transaction, session_id, context)?;
    let run_ids_fetch = validated_read_page_limit(run_ids_limit, COLLECTION_PAGE_MAX_LIMIT)?;
    let turns_fetch = validated_read_page_limit(turns_limit, COLLECTION_PAGE_MAX_LIMIT)?;
    let events_fetch = validated_read_page_limit(events_limit, EVENT_PAGE_MAX_LIMIT)?;
    let run_ids_before = run_ids_before
        .map(|value| {
            cursor::decode_session_run_ids(
                value,
                context.account_id.as_str(),
                &context.user_id,
                session_id,
            )
        })
        .transpose()?;
    let turns_before = turns_before
        .map(|value| {
            cursor::decode_session_turns(
                value,
                context.account_id.as_str(),
                &context.user_id,
                session_id,
            )
        })
        .transpose()?;
    let events_before = events_before
        .map(|value| {
            cursor::decode_session_events(
                value,
                context.account_id.as_str(),
                &context.user_id,
                session_id,
            )
        })
        .transpose()?;

    let session = query_session_summary(&transaction, session_id)?;
    validate_session_event_tail(&transaction, &session)?;
    validate_active_turn_projection(&transaction, &session)?;

    let (run_ids, run_ids_page) = query_session_run_ids_tail(
        &transaction,
        context.account_id.as_str(),
        &context.user_id,
        session_id,
        run_ids_before.as_ref(),
        run_ids_limit,
        run_ids_fetch,
    )?;
    let (turns, turns_page) = query_session_turns_tail(
        &transaction,
        context.account_id.as_str(),
        &context.user_id,
        session_id,
        turns_before,
        turns_limit,
        turns_fetch,
    )?;
    let (events, events_page) = query_session_events_tail(
        &transaction,
        &ScopedEventTailQuery {
            account_id: context.account_id.as_str(),
            actor_user_id: &context.user_id,
            parent_id: session_id,
            head: session.sequence,
            before: events_before,
            limit: events_limit,
            fetch_limit: events_fetch,
        },
    )?;
    transaction.commit()?;
    Ok(SessionDetail {
        session,
        run_ids,
        turns,
        events,
        pagination: Some(SessionDetailPagination {
            run_ids: run_ids_page,
            turns: turns_page,
            events: events_page,
        }),
    })
}

#[allow(clippy::too_many_arguments)]
fn query_session_run_ids_tail(
    connection: &Connection,
    account_id: &str,
    actor_user_id: &str,
    session_id: &str,
    before: Option<&cursor::TextKeyCursor>,
    limit: usize,
    fetch_limit: i64,
) -> Result<(Vec<String>, ReadPageInfo), StorageError> {
    let mut rows = if let Some(before) = before {
        let mut statement = connection.prepare(
            r#"SELECT sr.run_id, sr.attached_at
               FROM session_runs sr
               JOIN runs r ON r.id = sr.run_id
               WHERE sr.session_id = ?1
                 AND r.account_id = ?2
                 AND (sr.attached_at < ?3 OR (sr.attached_at = ?3 AND sr.run_id < ?4))
               ORDER BY sr.attached_at DESC, sr.run_id DESC
               LIMIT ?5"#,
        )?;
        statement
            .query_map(
                params![
                    session_id,
                    account_id,
                    before.first,
                    before.second,
                    fetch_limit
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )?
            .collect::<Result<Vec<_>, _>>()?
    } else {
        let mut statement = connection.prepare(
            r#"SELECT sr.run_id, sr.attached_at
               FROM session_runs sr
               JOIN runs r ON r.id = sr.run_id
               WHERE sr.session_id = ?1 AND r.account_id = ?2
               ORDER BY sr.attached_at DESC, sr.run_id DESC
               LIMIT ?3"#,
        )?;
        statement
            .query_map(params![session_id, account_id, fetch_limit], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    let has_more = rows.len() > limit;
    rows.truncate(limit);
    let next_before = if has_more {
        let (run_id, attached_at) = rows.last().ok_or_else(|| {
            StorageError::CorruptData("Run attachment page sentinel has no returned item".into())
        })?;
        Some(cursor::encode_session_run_ids(
            account_id,
            actor_user_id,
            session_id,
            attached_at,
            run_id,
        )?)
    } else {
        None
    };
    rows.reverse();
    Ok((
        rows.into_iter().map(|(run_id, _)| run_id).collect(),
        ReadPageInfo {
            next_before,
            has_more,
        },
    ))
}

fn query_session_turns_tail(
    connection: &Connection,
    account_id: &str,
    actor_user_id: &str,
    session_id: &str,
    before: Option<u64>,
    limit: usize,
    fetch_limit: i64,
) -> Result<(Vec<SessionTurn>, ReadPageInfo), StorageError> {
    let head = connection.query_row(
        "SELECT COALESCE(MAX(ordinal), 0) FROM session_turns WHERE session_id = ?1",
        [session_id],
        |row| row.get::<_, i64>(0),
    )?;
    let head = i64_to_u64(head, "session turn head")?;
    if before.is_some_and(|position| position > head) {
        return Err(StorageError::PageCursorBeyondHead { head });
    }
    let mut rows = if let Some(before) = before {
        let mut statement = connection.prepare(
            r#"SELECT id, session_id, ordinal, status, user_message, assistant_message,
                      started_at, completed_at
               FROM session_turns
               WHERE session_id = ?1 AND ordinal < ?2
               ORDER BY ordinal DESC LIMIT ?3"#,
        )?;
        statement
            .query_map(
                params![session_id, u64_to_i64(before, "turn cursor")?, fetch_limit],
                decode_session_turn_row,
            )?
            .collect::<Result<Vec<_>, _>>()?
    } else {
        let mut statement = connection.prepare(
            r#"SELECT id, session_id, ordinal, status, user_message, assistant_message,
                      started_at, completed_at
               FROM session_turns
               WHERE session_id = ?1
               ORDER BY ordinal DESC LIMIT ?2"#,
        )?;
        statement
            .query_map(params![session_id, fetch_limit], decode_session_turn_row)?
            .collect::<Result<Vec<_>, _>>()?
    };
    validate_descending_ordinals(
        rows.iter().map(|row| row.ordinal),
        before.map_or(head, |position| position.saturating_sub(1)),
        "session turn",
    )?;
    let has_more = rows.len() > limit;
    rows.truncate(limit);
    let next_before = if has_more {
        let oldest = rows.last().ok_or_else(|| {
            StorageError::CorruptData("Session turn page sentinel has no returned item".into())
        })?;
        Some(cursor::encode_session_turns(
            account_id,
            actor_user_id,
            session_id,
            i64_to_u64(oldest.ordinal, "session turn ordinal")?,
        )?)
    } else {
        None
    };
    let mut turns = rows
        .into_iter()
        .map(StoredSessionTurnRow::decode)
        .collect::<Result<Vec<_>, _>>()?;
    turns.reverse();
    Ok((
        turns,
        ReadPageInfo {
            next_before,
            has_more,
        },
    ))
}

struct ScopedEventTailQuery<'a> {
    account_id: &'a str,
    actor_user_id: &'a str,
    parent_id: &'a str,
    head: u64,
    before: Option<u64>,
    limit: usize,
    fetch_limit: i64,
}

fn query_session_events_tail(
    connection: &Connection,
    query: &ScopedEventTailQuery<'_>,
) -> Result<(Vec<SessionEvent>, ReadPageInfo), StorageError> {
    let session_id = query.parent_id;
    let head = query.head;
    let before = query.before;
    let limit = query.limit;
    let fetch_limit = query.fetch_limit;
    if before.is_some_and(|position| position > head) {
        return Err(StorageError::PageCursorBeyondHead { head });
    }
    let mut rows = if let Some(before) = before {
        let mut statement = connection.prepare(
            r#"SELECT sequence, event_id, event_kind, payload_version, payload_json,
                      turn_id, created_at
               FROM session_events
               WHERE session_id = ?1 AND sequence < ?2
               ORDER BY sequence DESC LIMIT ?3"#,
        )?;
        statement
            .query_map(
                params![
                    session_id,
                    u64_to_i64(before, "Session history cursor")?,
                    fetch_limit
                ],
                decode_stored_session_event_row,
            )?
            .collect::<Result<Vec<_>, _>>()?
    } else {
        let mut statement = connection.prepare(
            r#"SELECT sequence, event_id, event_kind, payload_version, payload_json,
                      turn_id, created_at
               FROM session_events
               WHERE session_id = ?1
               ORDER BY sequence DESC LIMIT ?2"#,
        )?;
        statement
            .query_map(
                params![session_id, fetch_limit],
                decode_stored_session_event_row,
            )?
            .collect::<Result<Vec<_>, _>>()?
    };
    validate_descending_ordinals(
        rows.iter().map(|row| row.sequence),
        before.map_or(head, |position| position.saturating_sub(1)),
        "session event",
    )?;
    let has_more = rows.len() > limit;
    rows.truncate(limit);
    let next_before = if has_more {
        let oldest = rows.last().ok_or_else(|| {
            StorageError::CorruptData("Session event page sentinel has no returned item".into())
        })?;
        Some(cursor::encode_session_events(
            query.account_id,
            query.actor_user_id,
            session_id,
            i64_to_u64(oldest.sequence, "session event sequence")?,
        )?)
    } else {
        None
    };
    let mut events = rows
        .into_iter()
        .map(StoredSessionEventRow::decode)
        .collect::<Result<Vec<_>, _>>()?;
    events.reverse();
    Ok((
        events,
        ReadPageInfo {
            next_before,
            has_more,
        },
    ))
}

fn validate_active_turn_projection(
    connection: &Connection,
    session: &SessionSummary,
) -> Result<(), StorageError> {
    let mut statement = connection.prepare(
        r#"SELECT id, session_id, ordinal, status, user_message, assistant_message,
                  started_at, completed_at
           FROM session_turns
           WHERE session_id = ?1 AND status = 'open'
           ORDER BY ordinal LIMIT 2"#,
    )?;
    let rows = statement
        .query_map([&session.id], decode_session_turn_row)?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() > 1 {
        return Err(StorageError::CorruptData(format!(
            "session `{}` has more than one open turn",
            session.id
        )));
    }
    let open = rows
        .into_iter()
        .next()
        .map(StoredSessionTurnRow::decode)
        .transpose()?;
    match (
        &session.status,
        session.active_turn_id.as_deref(),
        open.as_ref(),
    ) {
        (SessionStatus::Running, Some(active), Some(turn)) if active == turn.id => Ok(()),
        (SessionStatus::Ready | SessionStatus::NeedsAttention, None, None) => Ok(()),
        _ => Err(StorageError::CorruptData(format!(
            "session `{}` projection disagrees with its open turn",
            session.id
        ))),
    }
}

fn validate_descending_ordinals(
    values: impl IntoIterator<Item = i64>,
    expected_first: u64,
    label: &'static str,
) -> Result<(), StorageError> {
    let mut expected = i64::try_from(expected_first)
        .map_err(|_| StorageError::IntegerOutOfRange("read page sequence"))?;
    for value in values {
        if value != expected {
            return Err(StorageError::CorruptData(format!(
                "{label} page gap: expected {expected}, found {value}"
            )));
        }
        expected = expected.saturating_sub(1);
    }
    Ok(())
}

fn decode_stored_session_event_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<StoredSessionEventRow> {
    Ok(StoredSessionEventRow {
        sequence: row.get(0)?,
        event_id: row.get(1)?,
        event_kind: row.get(2)?,
        payload_version: row.get(3)?,
        payload_json: row.get(4)?,
        turn_id: row.get(5)?,
        created_at: row.get(6)?,
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
    context: &AuthzContext,
    session_id: &str,
    after: u64,
) -> Result<Vec<SessionEvent>, StorageError> {
    let after = u64_to_i64(after, "session event cursor")?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_active_session_actor(&transaction, session_id, context)?;
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
    context: &AuthzContext,
    session_id: &str,
    after: u64,
    limit: usize,
) -> Result<SessionEventPage, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_active_session_actor(&transaction, session_id, context)?;
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
    authz: Option<&AuthzContext>,
    limits: &StorageLimits,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<CreateSessionResponse, StorageError> {
    normalized_key(idempotency_key)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(context) = authz {
        require_current_authority(&transaction, context, AccountCapability::SessionWrite)?;
    }
    validate_create_session_request(&request)?;
    let fingerprint = session_command_fingerprint(None, &request)?;
    let stored_response = match authz {
        Some(context) => load_session_command_receipt_for_actor::<CreateSessionResponse>(
            &transaction,
            context,
            idempotency_key,
            "create_session",
            &fingerprint,
            None,
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
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Admission,
    )?;
    if query_session_summary_optional(&transaction, &request.id)?.is_some() {
        return Err(StorageError::SessionAlreadyExists(request.id));
    }
    let actor_user_id = authz.map(|context| context.user_id.as_str());
    let account_id = authz.map_or(LOCAL_ACCOUNT_ID, |context| context.account_id.as_str());
    require_session_count_capacity(&transaction, account_id, actor_user_id, limits)?;
    let timestamp = now();
    transaction.execute(
        r#"INSERT INTO sessions(
               id, title, status, created_at, updated_at, sequence,
               projection_sequence, active_turn_id, owner_user_id, account_id
           ) VALUES (?1, ?2, 'ready', ?3, ?3, 0, 0, NULL, ?4, ?5)"#,
        params![
            request.id,
            request.title,
            timestamp,
            actor_user_id,
            account_id
        ],
    )?;
    let event = build_session_event(
        &request.id,
        1,
        &timestamp,
        SessionEventData::SessionCreated {
            title: request.title.clone(),
        },
    );
    let payload = encode_event_payload(&event)?;
    require_session_event_capacity(
        &transaction,
        &request.id,
        EventCapacityRequest::events(1, payload.bytes),
        limits,
    )?;
    insert_session_event(&transaction, &request.id, &event, &payload)?;
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
    if let Some(context) = authz {
        insert_session_command_receipt_for_actor(
            &transaction,
            context,
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
    authz: Option<&AuthzContext>,
    limits: &StorageLimits,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<AttachRunResponse, StorageError> {
    validated_durable_reference(session_id, "session ID")?;
    normalized_key(idempotency_key)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(context) = authz {
        require_current_authority(&transaction, context, AccountCapability::SessionWrite)?;
        require_active_session_actor(&transaction, session_id, context)?;
    }
    validated_durable_reference(&request.run_id, "run ID")?;
    let fingerprint = session_command_fingerprint(Some(session_id), &request)?;
    let stored_response = match authz {
        Some(context) => load_session_command_receipt_for_actor::<AttachRunResponse>(
            &transaction,
            context,
            idempotency_key,
            "attach_run",
            &fingerprint,
            None,
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
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Admission,
    )?;
    let summary = query_session_summary(&transaction, session_id)?;
    require_session_sequence(&summary, request.expected_sequence)?;
    let run_exists = match authz {
        Some(context) => transaction
            .query_row(
                "SELECT 1 FROM runs WHERE id = ?1 AND account_id = ?2",
                params![request.run_id, context.account_id.as_str()],
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
    let payload = encode_event_payload(&event)?;
    require_session_event_capacity(
        &transaction,
        session_id,
        EventCapacityRequest::events(1, payload.bytes),
        limits,
    )?;
    insert_session_event(&transaction, session_id, &event, &payload)?;
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
    if let Some(context) = authz {
        insert_session_command_receipt_for_actor(
            &transaction,
            context,
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

fn verify_session_followup_integrity(connection: &Connection) -> Result<(), StorageError> {
    let broken_ordinal = connection
        .query_row(
            r#"SELECT session_id FROM session_followups
               GROUP BY session_id
               HAVING MIN(ordinal) <> 1 OR MAX(ordinal) <> COUNT(*)
               LIMIT 1"#,
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(session_id) = broken_ordinal {
        return Err(StorageError::CorruptData(format!(
            "Session `{session_id}` follow-up ordinals are not contiguous"
        )));
    }
    let broken_followup = connection
        .query_row(
            r#"SELECT followup.turn_id
               FROM session_followups followup
               WHERE (
                   followup.status = 'claimed'
                   AND NOT EXISTS (
                       SELECT 1
                       FROM agent_turns agent
                       JOIN session_turns turn
                         ON turn.session_id = agent.session_id AND turn.id = agent.turn_id
                       JOIN agent_model_jobs job
                         ON job.agent_id = agent.id AND job.step = 1
                       WHERE agent.id = followup.claimed_agent_id
                         AND agent.account_id = followup.account_id
                         AND agent.actor_user_id = followup.actor_user_id
                         AND agent.actor_membership_revision = followup.actor_membership_revision
                         AND agent.session_id = followup.session_id
                         AND agent.turn_id = followup.turn_id
                         AND agent.created_at = followup.claimed_at
                         AND turn.started_at = followup.claimed_at
                         AND job.queued_at = followup.claimed_at
                   )
               ) OR (
                   followup.status <> 'claimed'
                   AND EXISTS (SELECT 1 FROM session_turns turn WHERE turn.id = followup.turn_id)
               )
               LIMIT 1"#,
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(turn_id) = broken_followup {
        return Err(StorageError::CorruptData(format!(
            "Session follow-up `{turn_id}` is not bound to its exact Agent turn"
        )));
    }
    let broken_receipt = connection
        .query_row(
            r#"SELECT receipt.turn_id
               FROM session_followup_receipts receipt
               JOIN session_followups followup
                 ON followup.session_id = receipt.session_id
                AND followup.turn_id = receipt.turn_id
               WHERE receipt.account_id <> followup.account_id
                  OR receipt.actor_user_id <> followup.actor_user_id
                  OR receipt.actor_membership_revision <> followup.actor_membership_revision
                  OR json_extract(receipt.request_fingerprint, '$.session_id') <> receipt.session_id
                  OR json_extract(receipt.request_fingerprint, '$.request.turn_id') <> receipt.turn_id
                  OR json_extract(receipt.request_fingerprint, '$.request.user_message') <> followup.user_message
                  OR json_type(receipt.request_fingerprint, '$.request.expected_sequence') <> 'integer'
                  OR json_extract(receipt.response_json, '$.replayed') <> 0
                  OR json_extract(receipt.response_json, '$.followup.session_id') <> followup.session_id
                  OR json_extract(receipt.response_json, '$.followup.turn_id') <> followup.turn_id
                  OR json_extract(receipt.response_json, '$.followup.ordinal') <> followup.ordinal
                  OR json_extract(receipt.response_json, '$.followup.status') <> 'queued'
                  OR json_extract(receipt.response_json, '$.followup.user_message') <> followup.user_message
                  OR json_extract(receipt.response_json, '$.followup.enqueued_at') <> followup.enqueued_at
               LIMIT 1"#,
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(turn_id) = broken_receipt {
        return Err(StorageError::CorruptData(format!(
            "Session follow-up receipt `{turn_id}` does not match its admission"
        )));
    }
    Ok(())
}

fn decode_session_followup_status(value: &str) -> Result<SessionFollowupStatus, StorageError> {
    match value {
        "queued" => Ok(SessionFollowupStatus::Queued),
        "claimed" => Ok(SessionFollowupStatus::Claimed),
        "discarded" => Ok(SessionFollowupStatus::Discarded),
        other => Err(StorageError::CorruptData(format!(
            "unsupported Session follow-up status `{other}`"
        ))),
    }
}

fn query_session_followup(
    connection: &Connection,
    session_id: &str,
    turn_id: &str,
) -> Result<SessionFollowup, StorageError> {
    connection
        .query_row(
            r#"SELECT session_id, turn_id, ordinal, status, user_message,
                      enqueued_at, claimed_at, discarded_at, discard_reason
               FROM session_followups
               WHERE session_id = ?1 AND turn_id = ?2"#,
            params![session_id, turn_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| StorageError::SessionTurnNotFound(turn_id.to_owned()))
        .and_then(
            |(
                session_id,
                turn_id,
                ordinal,
                status,
                user_message,
                enqueued_at,
                claimed_at,
                discarded_at,
                discard_reason,
            )| {
                Ok(SessionFollowup {
                    session_id,
                    turn_id,
                    ordinal: i64_to_u64(ordinal, "Session follow-up ordinal")?,
                    status: decode_session_followup_status(&status)?,
                    user_message,
                    enqueued_at,
                    claimed_at,
                    discarded_at,
                    discard_reason,
                })
            },
        )
}

fn query_session_followups(
    connection: &Connection,
    session_id: &str,
) -> Result<Vec<SessionFollowup>, StorageError> {
    let mut statement = connection.prepare(
        r#"SELECT turn_id FROM session_followups
           WHERE session_id = ?1
           ORDER BY ordinal DESC LIMIT 100"#,
    )?;
    let turn_ids = statement
        .query_map([session_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    turn_ids
        .into_iter()
        .rev()
        .map(|turn_id| query_session_followup(connection, session_id, &turn_id))
        .collect()
}

fn capture_session_flush_barrier(
    connection: &Connection,
    session_id: &str,
) -> Result<SessionFlushBarrier, StorageError> {
    let session = query_session_summary(connection, session_id)?;
    let through_followup_ordinal = connection.query_row(
        "SELECT COALESCE(MAX(ordinal), 0) FROM session_followups WHERE session_id = ?1",
        [session_id],
        |row| row.get::<_, i64>(0),
    )?;
    let first_unsettled_followup_ordinal = connection.query_row(
        r#"SELECT MIN(followup.ordinal)
           FROM session_followups followup
           LEFT JOIN agent_turns agent ON agent.id = followup.claimed_agent_id
           WHERE followup.session_id = ?1
             AND (
                 followup.status = 'queued'
                 OR (
                     followup.status = 'claimed'
                     AND (
                         agent.id IS NULL
                         OR agent.status NOT IN ('succeeded', 'failed', 'needs_attention')
                     )
                 )
             )"#,
        [session_id],
        |row| row.get::<_, Option<i64>>(0),
    )?;
    let after_followup_ordinal = first_unsettled_followup_ordinal
        .map(|ordinal| {
            ordinal.checked_sub(1).ok_or_else(|| {
                StorageError::CorruptData(
                    "Session flush follow-up interval starts before ordinal one".into(),
                )
            })
        })
        .transpose()?
        .unwrap_or(through_followup_ordinal);
    let barrier = SessionFlushBarrier {
        session_id: session.id,
        through_sequence: session.sequence,
        after_followup_ordinal: i64_to_u64(
            after_followup_ordinal,
            "Session flush settled follow-up ordinal",
        )?,
        through_followup_ordinal: i64_to_u64(
            through_followup_ordinal,
            "Session flush follow-up ordinal",
        )?,
        active_turn_id: session.active_turn_id,
        status: if session.status == SessionStatus::NeedsAttention {
            SessionFlushBarrierStatus::NeedsAttention
        } else {
            SessionFlushBarrierStatus::Pending
        },
        observed_sequence: session.sequence,
    };
    observe_session_flush_barrier(connection, barrier)
}

fn observe_session_flush_barrier(
    connection: &Connection,
    mut barrier: SessionFlushBarrier,
) -> Result<SessionFlushBarrier, StorageError> {
    let session = query_session_summary(connection, &barrier.session_id)?;
    barrier.observed_sequence = session.sequence;
    if barrier.status.is_terminal() {
        return Ok(barrier);
    }

    let mut pending = false;
    let mut needs_attention = false;
    if let Some(turn_id) = barrier.active_turn_id.as_deref() {
        match query_session_turn(connection, &barrier.session_id, turn_id)?.status {
            SessionTurnStatus::Open => pending = true,
            SessionTurnStatus::Flushed => {}
            SessionTurnStatus::Interrupted => needs_attention = true,
        }
    }

    let through_followup_ordinal = u64_to_i64(
        barrier.through_followup_ordinal,
        "Session flush follow-up ordinal",
    )?;
    let after_followup_ordinal = u64_to_i64(
        barrier.after_followup_ordinal,
        "Session flush settled follow-up ordinal",
    )?;
    if after_followup_ordinal > through_followup_ordinal {
        return Err(StorageError::CorruptData(
            "Session flush follow-up interval is reversed".into(),
        ));
    }
    let mut statement = connection.prepare(
        r#"SELECT followup.status, agent.status, turn.status
           FROM session_followups followup
           LEFT JOIN agent_turns agent ON agent.id = followup.claimed_agent_id
           LEFT JOIN session_turns turn
             ON turn.session_id = followup.session_id AND turn.id = followup.turn_id
           WHERE followup.session_id = ?1
             AND followup.ordinal > ?2 AND followup.ordinal <= ?3
           ORDER BY followup.ordinal"#,
    )?;
    let rows = statement.query_map(
        params![
            barrier.session_id,
            after_followup_ordinal,
            through_followup_ordinal
        ],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        },
    )?;
    for row in rows {
        let (followup_status, agent_status, turn_status) = row?;
        match followup_status.as_str() {
            "queued" => pending = true,
            "discarded" => {}
            "claimed" => match (agent_status.as_deref(), turn_status.as_deref()) {
                (Some("succeeded"), Some("flushed")) => {}
                (Some("failed" | "needs_attention"), _) | (_, Some("interrupted")) => {
                    needs_attention = true;
                }
                (
                    Some(
                        "waiting_model" | "model_running" | "waiting_approval" | "tool_queued"
                        | "tool_running",
                    ),
                    Some("open"),
                ) => pending = true,
                _ => {
                    return Err(StorageError::CorruptData(
                        "claimed Session follow-up has inconsistent Agent or turn state".into(),
                    ));
                }
            },
            _ => {
                return Err(StorageError::CorruptData(format!(
                    "unknown Session follow-up status `{followup_status}`"
                )));
            }
        }
    }

    barrier.status = if needs_attention {
        SessionFlushBarrierStatus::NeedsAttention
    } else if pending {
        SessionFlushBarrierStatus::Pending
    } else {
        SessionFlushBarrierStatus::Quiescent
    };
    Ok(barrier)
}

fn enqueue_session_followup(
    connection: &mut Connection,
    context: &AuthzContext,
    session_id: &str,
    request: EnqueueSessionFollowupRequest,
    idempotency_key: &str,
    limits: &StorageLimits,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<EnqueueSessionFollowupResponse, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_current_authority(&transaction, context, AccountCapability::SessionWrite)?;
    require_current_authority(&transaction, context, AccountCapability::Reply)?;
    require_active_session_actor(&transaction, session_id, context)?;
    let start_request = StartTurnRequest {
        turn_id: request.turn_id.clone(),
        user_message: request.user_message.clone(),
        expected_sequence: request.expected_sequence,
    };
    validate_start_turn_request(&start_request)?;
    normalized_key(idempotency_key)?;
    let fingerprint = session_command_fingerprint(Some(session_id), &request)?;
    let stored = transaction
        .query_row(
            r#"SELECT request_fingerprint, response_json
               FROM session_followup_receipts
               WHERE account_id = ?1 AND actor_user_id = ?2 AND idempotency_key = ?3"#,
            params![
                context.account_id.as_str(),
                context.user_id,
                idempotency_key
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    if let Some((stored_fingerprint, response_json)) = stored {
        if stored_fingerprint != fingerprint {
            return Err(StorageError::IdempotencyConflict);
        }
        let mut response: EnqueueSessionFollowupResponse = serde_json::from_str(&response_json)?;
        if response.replayed {
            return Err(StorageError::CorruptData(
                "stored Session follow-up receipt is not original".into(),
            ));
        }
        response.replayed = true;
        transaction.commit()?;
        return Ok(response);
    }
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Admission,
    )?;
    let summary = query_session_summary(&transaction, session_id)?;
    require_session_sequence(&summary, request.expected_sequence)?;
    let conflicting_turn: i64 = transaction.query_row(
        r#"SELECT EXISTS(
               SELECT 1 FROM session_turns WHERE id = ?1
               UNION ALL
               SELECT 1 FROM session_followups WHERE turn_id = ?1
           )"#,
        [&request.turn_id],
        |row| row.get(0),
    )?;
    if conflicting_turn != 0 {
        return Err(StorageError::InvalidSessionTransition(format!(
            "turn `{}` already exists",
            request.turn_id
        )));
    }
    let queued_for_session: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM session_followups WHERE session_id = ?1 AND status = 'queued'",
        [session_id],
        |row| row.get(0),
    )?;
    if queued_for_session >= SESSION_FOLLOWUP_QUEUE_MAX {
        return Err(StorageError::ReplyQueueCapacityExceeded);
    }
    require_reply_queue_capacity(
        &transaction,
        context.account_id.as_str(),
        Some(&context.user_id),
        limits,
    )?;
    let ordinal: i64 = transaction.query_row(
        "SELECT COALESCE(MAX(ordinal), 0) + 1 FROM session_followups WHERE session_id = ?1",
        [session_id],
        |row| row.get(0),
    )?;
    let timestamp = now();
    transaction.execute(
        r#"INSERT INTO session_followups(
               account_id, actor_user_id, actor_membership_revision,
               session_id, turn_id, ordinal, user_message, status,
               claimed_agent_id, enqueued_at, claimed_at, discarded_at, discard_reason
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'queued', NULL, ?8, NULL, NULL, NULL)"#,
        params![
            context.account_id.as_str(),
            context.user_id,
            u64_to_i64(context.membership_revision.get(), "membership revision")?,
            session_id,
            request.turn_id,
            ordinal,
            request.user_message,
            timestamp,
        ],
    )?;
    let response = EnqueueSessionFollowupResponse {
        followup: query_session_followup(&transaction, session_id, &request.turn_id)?,
        replayed: false,
    };
    transaction.execute(
        r#"INSERT INTO session_followup_receipts(
               account_id, actor_user_id, actor_membership_revision, idempotency_key,
               request_fingerprint, response_json, session_id, turn_id, created_at
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"#,
        params![
            context.account_id.as_str(),
            context.user_id,
            u64_to_i64(context.membership_revision.get(), "membership revision")?,
            idempotency_key,
            fingerprint,
            serde_json::to_string(&response)?,
            session_id,
            request.turn_id,
            timestamp,
        ],
    )?;
    transaction.commit()?;
    Ok(response)
}

fn query_next_session_followup_candidate(
    connection: &mut Connection,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<Option<SessionFollowupCandidate>, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    loop {
        let row = transaction
            .query_row(
                r#"SELECT followup.account_id, followup.actor_user_id,
                          followup.actor_membership_revision,
                          followup.session_id, followup.turn_id
                   FROM session_followups followup
                   JOIN sessions session ON session.id = followup.session_id
                   WHERE followup.status = 'queued'
                     AND session.status = 'ready'
                     AND session.active_turn_id IS NULL
                     AND NOT EXISTS (
                         SELECT 1 FROM session_followups prior
                         WHERE prior.session_id = followup.session_id
                           AND prior.status = 'queued'
                           AND prior.ordinal < followup.ordinal
                     )
                   ORDER BY followup.enqueued_at, followup.session_id, followup.ordinal
                   LIMIT 1"#,
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((account_id, actor_user_id, membership_revision, session_id, turn_id)) = row
        else {
            transaction.commit()?;
            return Ok(None);
        };
        let role = transaction
            .query_row(
                r#"SELECT membership.role
                   FROM accounts account
                   JOIN account_memberships membership
                     ON membership.account_id = account.id
                   JOIN users user ON user.id = membership.user_id
                   WHERE account.id = ?1 AND account.status = 'active'
                     AND membership.user_id = ?2 AND membership.status = 'active'
                     AND membership.revision = ?3 AND user.status = 'active'"#,
                params![account_id, actor_user_id, membership_revision],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let role = role.as_deref().map(decode_membership_role).transpose()?;
        if !role.is_some_and(|role| {
            membership_allows(role, AccountCapability::SessionWrite)
                && membership_allows(role, AccountCapability::Reply)
        }) {
            require_connection_physical_capacity(
                &transaction,
                physical_limits,
                PhysicalCapacityGate::ReservedProgress,
            )?;
            let timestamp = now();
            let updated = transaction.execute(
                r#"UPDATE session_followups
                   SET status = 'discarded', discarded_at = ?3, discard_reason = ?4
                   WHERE session_id = ?1 AND turn_id = ?2 AND status = 'queued'"#,
                params![
                    session_id,
                    turn_id,
                    timestamp,
                    SESSION_FOLLOWUP_AUTHORIZATION_REVOKED_REASON,
                ],
            )?;
            if updated != 1 {
                return Err(StorageError::ConcurrentModification);
            }
            continue;
        }
        let account_id = AccountId::from_persistence(account_id).map_err(|error| {
            StorageError::CorruptData(format!("invalid Session follow-up account: {error}"))
        })?;
        let membership_revision = MembershipRevision::new(i64_to_u64(
            membership_revision,
            "Session follow-up membership revision",
        )?)
        .map_err(|error| StorageError::CorruptData(error.to_string()))?;
        let auth_session_id =
            AuthSessionId::from_persistence("followup-driver-v1").map_err(|error| {
                StorageError::CorruptData(format!(
                    "invalid internal Session follow-up authority ID: {error}"
                ))
            })?;
        let candidate = SessionFollowupCandidate {
            authz: AuthzContext {
                account_id,
                user_id: actor_user_id,
                membership_role: role.expect("validated above"),
                membership_revision,
                auth_session_id,
            },
            session: query_session_summary(&transaction, &session_id)?,
            followup: query_session_followup(&transaction, &session_id, &turn_id)?,
        };
        transaction.commit()?;
        return Ok(Some(candidate));
    }
}

fn require_queued_followup_for_claim(
    connection: &Connection,
    followup: &SessionFollowup,
    context: &AuthzContext,
) -> Result<(), StorageError> {
    let found: i64 = connection.query_row(
        r#"SELECT EXISTS(
               SELECT 1 FROM session_followups queued
               WHERE queued.account_id = ?1
                 AND queued.actor_user_id = ?2
                 AND queued.actor_membership_revision = ?3
                 AND queued.session_id = ?4
                 AND queued.turn_id = ?5
                 AND queued.ordinal = ?6
                 AND queued.user_message = ?7
                 AND queued.enqueued_at = ?8
                 AND queued.status = 'queued'
                 AND NOT EXISTS (
                     SELECT 1 FROM session_followups prior
                     WHERE prior.session_id = queued.session_id
                       AND prior.status = 'queued'
                       AND prior.ordinal < queued.ordinal
                 )
           )"#,
        params![
            context.account_id.as_str(),
            context.user_id,
            u64_to_i64(context.membership_revision.get(), "membership revision")?,
            followup.session_id,
            followup.turn_id,
            u64_to_i64(followup.ordinal, "Session follow-up ordinal")?,
            followup.user_message,
            followup.enqueued_at,
        ],
        |row| row.get(0),
    )?;
    if found != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    Ok(())
}

fn claim_session_followup(
    connection: &Connection,
    followup: &SessionFollowup,
    agent: &AgentTurn,
    timestamp: &str,
) -> Result<(), StorageError> {
    let updated = connection.execute(
        r#"UPDATE session_followups
           SET status = 'claimed', claimed_agent_id = ?3, claimed_at = ?4
           WHERE session_id = ?1 AND turn_id = ?2 AND status = 'queued'"#,
        params![followup.session_id, followup.turn_id, agent.id, timestamp],
    )?;
    if updated != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    Ok(())
}

fn require_claimed_followup_matches_agent(
    connection: &Connection,
    followup: &SessionFollowup,
    agent: &AgentTurn,
) -> Result<(), StorageError> {
    let stored = query_session_followup(connection, &followup.session_id, &followup.turn_id)?;
    let claimed_agent_id: Option<String> = connection.query_row(
        r#"SELECT claimed_agent_id FROM session_followups
           WHERE session_id = ?1 AND turn_id = ?2"#,
        params![followup.session_id, followup.turn_id],
        |row| row.get(0),
    )?;
    if stored.status != SessionFollowupStatus::Claimed
        || stored.ordinal != followup.ordinal
        || stored.user_message != followup.user_message
        || stored.enqueued_at != followup.enqueued_at
        || claimed_agent_id.as_deref() != Some(agent.id.as_str())
    {
        return Err(StorageError::CorruptData(
            "claimed Session follow-up does not match its Agent".into(),
        ));
    }
    Ok(())
}

struct StartTurnOptions<'a> {
    authz: Option<&'a AuthzContext>,
    reply_job: Option<ReplyJobSpec>,
    agent_turn: Option<AgentTurnSpec>,
    goal_round: Option<AgentGoalRoundSpec>,
    followup: Option<SessionFollowup>,
    limits: &'a StorageLimits,
    physical_limits: &'a SqlitePhysicalLimits,
    fail_after_enqueue: bool,
}

fn load_agent_start_receipt_for_actor(
    connection: &mut Connection,
    context: &AuthzContext,
    session_id: &str,
    request: &StartTurnRequest,
    idempotency_key: &str,
    probe: &AgentTurnReceiptProbe,
) -> Result<Option<AgentTurnEnqueueResponse>, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_current_authority(&transaction, context, AccountCapability::SessionWrite)?;
    require_active_session_actor(&transaction, session_id, context)?;
    validate_start_turn_request(request)?;
    agent::validate_agent_turn_receipt_probe(probe)?;
    if probe.authz != *context {
        return Err(StorageError::SessionNotFound(session_id.to_owned()));
    }
    let fingerprint = agent::agent_start_fingerprint_for_probe(session_id, request, probe)?;
    let Some(mut start) = load_session_command_receipt_for_actor::<StartTurnResponse>(
        &transaction,
        context,
        idempotency_key,
        "start_turn",
        &fingerprint,
        None,
    )?
    else {
        transaction.commit()?;
        return Ok(None);
    };
    start.replayed = true;
    let agent =
        agent::query_agent_turn_for_session_turn(&transaction, session_id, &request.turn_id)?;
    agent::require_agent_matches_probe(&agent, probe)?;
    let job = agent::query_agent_model_job(&transaction, &agent.id, 1)?;
    agent::require_agent_knowledge_context_integrity(&transaction, &agent, &job)
        .map_err(agent::corrupt_agent_integrity)?;
    transaction.commit()?;
    Ok(Some(AgentTurnEnqueueResponse { start, agent, job }))
}

struct StartTurnOutcome {
    start: StartTurnResponse,
    reply_job: Option<ReplyJob>,
    agent_work: Option<(AgentTurn, AgentModelJob)>,
}

fn start_turn(
    connection: &mut Connection,
    session_id: &str,
    request: StartTurnRequest,
    idempotency_key: &str,
    options: StartTurnOptions<'_>,
) -> Result<StartTurnOutcome, StorageError> {
    let StartTurnOptions {
        authz,
        reply_job,
        agent_turn,
        goal_round,
        followup,
        limits,
        physical_limits,
        fail_after_enqueue,
    } = options;
    validated_durable_reference(session_id, "session ID")?;
    normalized_key(idempotency_key)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(context) = authz {
        if goal_round.is_some() || followup.is_some() {
            require_goal_round_authority(&transaction, session_id, context)?;
        } else {
            require_current_authority(&transaction, context, AccountCapability::SessionWrite)?;
            require_active_session_actor(&transaction, session_id, context)?;
        }
    }
    validate_start_turn_request(&request)?;
    if let Some(job) = &reply_job {
        validate_reply_job_spec(job)?;
        if authz != Some(&job.authz) {
            return Err(StorageError::SessionNotFound(session_id.to_owned()));
        }
    }
    if let Some(agent) = &agent_turn {
        agent::validate_agent_turn_spec(agent)?;
        if authz != Some(&agent.authz) {
            return Err(StorageError::SessionNotFound(session_id.to_owned()));
        }
    }
    if reply_job.is_some() && agent_turn.is_some() {
        return Err(StorageError::InvalidSessionTransition(
            "a turn cannot enqueue both a legacy reply and an agent loop".into(),
        ));
    }
    if let Some(round) = &goal_round {
        agent::validate_agent_goal_round_spec(round)?;
        if authz.is_none() || agent_turn.is_none() || reply_job.is_some() {
            return Err(StorageError::InvalidAgentTransition(
                "a Goal round requires exactly one actor-bound Agent turn".into(),
            ));
        }
    }
    if let Some(followup) = &followup {
        if authz.is_none() || agent_turn.is_none() || reply_job.is_some() || goal_round.is_some() {
            return Err(StorageError::InvalidAgentTransition(
                "a follow-up claim requires exactly one actor-bound Agent turn".into(),
            ));
        }
        if followup.session_id != session_id
            || followup.turn_id != request.turn_id
            || followup.user_message != request.user_message
            || followup.status != SessionFollowupStatus::Queued
        {
            return Err(StorageError::InvalidAgentTransition(
                "the queued follow-up does not match its Agent turn request".into(),
            ));
        }
    }
    let (fingerprint, legacy_fingerprint) = match (&reply_job, &agent_turn) {
        (Some(job), None) => (
            reply_start_fingerprint(session_id, &request, job)?,
            Some(legacy_reply_start_fingerprint_v1(
                session_id, &request, job,
            )?),
        ),
        (None, Some(agent)) => {
            let fingerprint = agent::agent_start_fingerprint(session_id, &request, agent)?;
            let fingerprint = match (&goal_round, &followup) {
                (Some(round), None) => serde_json::to_string(&json!({
                    "agent_start": serde_json::from_str::<Value>(&fingerprint)?,
                    "goal_round": round,
                }))?,
                (None, Some(followup)) => serde_json::to_string(&json!({
                    "agent_start": serde_json::from_str::<Value>(&fingerprint)?,
                    "followup": {
                        "ordinal": followup.ordinal,
                        "enqueued_at": followup.enqueued_at,
                    },
                }))?,
                (None, None) => fingerprint,
                (Some(_), Some(_)) => unreachable!("dual automatic origins were rejected above"),
            };
            (fingerprint, None)
        }
        (None, None) => (
            session_command_fingerprint(Some(session_id), &request)?,
            None,
        ),
        (Some(_), Some(_)) => unreachable!("dual work was rejected above"),
    };
    let stored_response = match authz {
        Some(context) => load_session_command_receipt_for_actor::<StartTurnResponse>(
            &transaction,
            context,
            idempotency_key,
            "start_turn",
            &fingerprint,
            legacy_fingerprint.as_deref(),
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
        let stored_agent = match &agent_turn {
            Some(spec) => {
                let agent = agent::query_agent_turn_for_session_turn(
                    &transaction,
                    session_id,
                    &request.turn_id,
                )?;
                agent::require_agent_matches_spec(&agent, spec)?;
                let job = agent::query_agent_model_job(&transaction, &agent.id, 1)?;
                agent::require_agent_knowledge_context_integrity(&transaction, &agent, &job)
                    .map_err(agent::corrupt_agent_integrity)?;
                if let Some(round) = &goal_round {
                    agent::require_agent_goal_round_matches_spec(
                        &transaction,
                        &request,
                        &agent,
                        round,
                    )?;
                }
                if let Some(followup) = &followup {
                    require_claimed_followup_matches_agent(&transaction, followup, &agent)?;
                }
                Some((agent, job))
            }
            None => None,
        };
        transaction.commit()?;
        return Ok(StartTurnOutcome {
            start: response,
            reply_job: stored_job,
            agent_work: stored_agent,
        });
    }
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Admission,
    )?;
    let summary = query_session_summary(&transaction, session_id)?;
    require_session_sequence(&summary, request.expected_sequence)?;
    if summary.status != SessionStatus::Ready || summary.active_turn_id.is_some() {
        return Err(StorageError::InvalidSessionTransition(format!(
            "session `{session_id}` must be ready before starting a turn"
        )));
    }
    if let Some(followup) = &followup {
        require_queued_followup_for_claim(&transaction, followup, authz.expect("validated"))?;
    }
    let turn_exists = transaction
        .query_row(
            "SELECT 1 FROM session_turns WHERE id = ?1",
            [&request.turn_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    let queued_turn_exists = if followup.is_none() {
        transaction
            .query_row(
                "SELECT 1 FROM session_followups WHERE turn_id = ?1",
                [&request.turn_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
    } else {
        None
    };
    if turn_exists.is_some() || queued_turn_exists.is_some() {
        return Err(StorageError::InvalidSessionTransition(format!(
            "turn `{}` already exists",
            request.turn_id
        )));
    }
    let account_id = authz.map_or(LOCAL_ACCOUNT_ID, |context| context.account_id.as_str());
    let actor_user_id = authz.map(|context| context.user_id.as_str());
    require_open_turn_capacity(&transaction, account_id, actor_user_id, limits)?;
    if (reply_job.is_some() || agent_turn.is_some()) && followup.is_none() {
        require_reply_queue_capacity(&transaction, account_id, actor_user_id, limits)?;
    }
    let finalization_payload_reservation = session_finalization_payload_reservation(
        &request.turn_id,
        reply_job
            .as_ref()
            .map(|job| job.provider_name.as_str())
            .or_else(|| {
                agent_turn
                    .as_ref()
                    .map(|agent| agent.provider_name.as_str())
            }),
        reply_job
            .as_ref()
            .and_then(|job| job.model_name.as_deref())
            .or_else(|| {
                agent_turn
                    .as_ref()
                    .and_then(|agent| agent.model_name.as_deref())
            }),
    )?;
    let timestamp = now();
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
    let payload = encode_event_payload(&event)?;
    require_session_event_capacity(
        &transaction,
        session_id,
        EventCapacityRequest {
            new_event_slots: 1,
            new_event_payload_bytes: payload.bytes,
            new_reserved_slots: 2,
            new_reserved_payload_bytes: finalization_payload_reservation,
        },
        limits,
    )?;
    let ordinal: i64 = transaction.query_row(
        "SELECT COALESCE(MAX(ordinal), 0) + 1 FROM session_turns WHERE session_id = ?1",
        [session_id],
        |row| row.get(0),
    )?;
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
    insert_session_finalization_reservation(
        &transaction,
        account_id,
        actor_user_id,
        session_id,
        &request.turn_id,
        finalization_payload_reservation,
        &timestamp,
    )?;
    insert_session_event(&transaction, session_id, &event, &payload)?;
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
    let stored_agent = if let Some(agent) = agent_turn {
        Some(agent::insert_agent_turn(
            &transaction,
            session_id,
            &request.turn_id,
            &agent,
            &timestamp,
        )?)
    } else {
        None
    };
    if let Some(round) = &goal_round {
        let (stored_agent, _) = stored_agent.as_ref().ok_or_else(|| {
            StorageError::CorruptData(
                "Goal round admission did not create its required Agent".into(),
            )
        })?;
        agent::insert_agent_goal_round(&transaction, &request, stored_agent, round, &timestamp)?;
    }
    if let Some(followup) = &followup {
        let (stored_agent, _) = stored_agent.as_ref().ok_or_else(|| {
            StorageError::CorruptData(
                "follow-up admission did not create its required Agent".into(),
            )
        })?;
        claim_session_followup(&transaction, followup, stored_agent, &timestamp)?;
    }

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
    if let Some(context) = authz {
        insert_session_command_receipt_for_actor(
            &transaction,
            context,
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
    Ok(StartTurnOutcome {
        start: response,
        reply_job: stored_job,
        agent_work: stored_agent,
    })
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
               id, account_id, actor_user_id, actor_membership_revision,
               session_id, turn_id, provider_name, model_name,
               status, attempt, request_json, response_json, error_json,
               completion_fingerprint, assistant_event_sequence,
               terminal_event_sequence, queued_at, started_at, finished_at
           ) VALUES (
               ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'queued', 0, ?9, NULL, NULL,
               NULL, NULL, NULL, ?10, NULL, NULL
           )"#,
        params![
            job.id,
            job.authz.account_id.as_str(),
            job.authz.user_id,
            u64_to_i64(job.authz.membership_revision.get(), "membership revision")?,
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

fn peek_next_reply(connection: &Connection) -> Result<Option<ReplyJob>, StorageError> {
    let job_id = connection
        .query_row(
            r#"SELECT id FROM reply_jobs
               WHERE status = 'queued' ORDER BY queued_at, id LIMIT 1"#,
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    job_id
        .map(|job_id| query_reply_job(connection, &job_id))
        .transpose()
}

fn claim_next_reply(
    connection: &mut Connection,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<ReplyClaimOutcome, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(job) = peek_next_reply(&transaction)? else {
        transaction.commit()?;
        return Ok(ReplyClaimOutcome::NotAvailable);
    };
    let outcome = start_reply_job(&transaction, &job.id, physical_limits, false)?;
    transaction.commit()?;
    Ok(outcome)
}

fn start_observed_reply(
    connection: &mut Connection,
    job_id: &str,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<ReplyClaimOutcome, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let outcome = start_reply_job(&transaction, job_id, physical_limits, true)?;
    transaction.commit()?;
    Ok(outcome)
}

fn start_reply_job(
    transaction: &Connection,
    job_id: &str,
    physical_limits: &SqlitePhysicalLimits,
    allow_exact_replay: bool,
) -> Result<ReplyClaimOutcome, StorageError> {
    let job = query_reply_job(transaction, job_id)?;
    match job.status {
        ReplyJobStatus::Started if allow_exact_replay => {
            return Ok(ReplyClaimOutcome::Claimed(Box::new(job)));
        }
        ReplyJobStatus::Failed if allow_exact_replay => {
            return Ok(match replay_reply_start_rejection(transaction, &job)? {
                Some(completion) => ReplyClaimOutcome::Rejected(Box::new(completion)),
                None => ReplyClaimOutcome::NotAvailable,
            });
        }
        ReplyJobStatus::Queued => {}
        ReplyJobStatus::Started
        | ReplyJobStatus::Succeeded
        | ReplyJobStatus::Failed
        | ReplyJobStatus::OutcomeUnknown => return Ok(ReplyClaimOutcome::NotAvailable),
    }

    if allow_exact_replay {
        let Some(head) = peek_next_reply(transaction)? else {
            return Ok(ReplyClaimOutcome::NotAvailable);
        };
        if head.id != job.id {
            return Ok(ReplyClaimOutcome::NotAvailable);
        }
    }

    let summary = require_open_reply_turn(transaction, &job)?;
    let required_payload_reservation = session_finalization_payload_reservation(
        &job.turn_id,
        Some(&job.provider_name),
        job.model_name.as_deref(),
    )?;
    if require_session_finalization_capacity(
        transaction,
        &job.session_id,
        &job.turn_id,
        2,
        required_payload_reservation,
    )?
    .0 != 2
    {
        return Err(StorageError::FinalizationReservationUnavailable);
    }
    require_connection_physical_capacity(
        transaction,
        physical_limits,
        PhysicalCapacityGate::ReservedProgress,
    )?;
    let changed = transaction.execute(
        r#"UPDATE reply_jobs
           SET status = 'started', attempt = 1, started_at = ?1
           WHERE id = ?2 AND status = 'queued' AND attempt = 0"#,
        params![now(), job_id],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    if !reply_actor_is_authorized(transaction, &job)? {
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
            transaction,
            job,
            summary.sequence,
            ReplyJobStatus::Failed,
            &error_json,
            &fingerprint,
            REPLY_AUTHORIZATION_REVOKED_REASON,
        )?;
        return Ok(ReplyClaimOutcome::Rejected(Box::new(completion)));
    }
    let claimed = query_reply_job(transaction, job_id)?;
    Ok(ReplyClaimOutcome::Claimed(Box::new(claimed)))
}

fn replay_reply_start_rejection(
    connection: &Connection,
    job: &ReplyJob,
) -> Result<Option<ReplyCompletion>, StorageError> {
    let rejection_code = job
        .error_json
        .as_ref()
        .and_then(|error| error.get("code"))
        .and_then(Value::as_str);
    if job.status != ReplyJobStatus::Failed || rejection_code != Some("authorization_revoked") {
        return Ok(None);
    }
    let terminal_sequence = job.terminal_event_sequence.ok_or_else(|| {
        StorageError::CorruptData(format!(
            "authorization-rejected reply job `{}` has no terminal event sequence",
            job.id
        ))
    })?;
    let expected_sequence = terminal_sequence.checked_sub(1).ok_or_else(|| {
        StorageError::CorruptData(format!(
            "authorization-rejected reply job `{}` has an invalid terminal event sequence",
            job.id
        ))
    })?;
    let expected_fingerprint = serde_json::to_string(&json!({
        "kind": "failed",
        "job_id": job.id,
        "expected_sequence": expected_sequence,
        "error_json": job.error_json,
    }))?;
    if query_reply_completion_fingerprint(connection, &job.id)?.as_deref()
        != Some(expected_fingerprint.as_str())
    {
        return Err(StorageError::CorruptData(format!(
            "authorization-rejected reply job `{}` has an incompatible completion fingerprint",
            job.id
        )));
    }

    let completion = query_reply_completion(connection, &job.id, true)?;
    if !matches!(
        completion.events.as_slice(),
        [SessionEvent {
            data: SessionEventData::TurnInterrupted { turn_id, reason },
            ..
        }] if turn_id == &job.turn_id && reason == REPLY_AUTHORIZATION_REVOKED_REASON
    ) {
        return Err(StorageError::CorruptData(format!(
            "authorization-rejected reply job `{}` points at incompatible interruption evidence",
            job.id
        )));
    }
    Ok(Some(completion))
}

fn reply_actor_is_authorized(
    connection: &Connection,
    job: &ReplyJob,
) -> Result<bool, StorageError> {
    let role = connection
        .query_row(
            r#"SELECT membership.role
               FROM sessions session
               JOIN accounts account ON account.id = session.account_id
               JOIN account_memberships membership
                 ON membership.account_id = session.account_id
               JOIN users user ON user.id = membership.user_id
               WHERE session.id = ?1 AND session.account_id = ?2
                 AND membership.user_id = ?3
                 AND membership.revision = ?4
                 AND membership.status = 'active'
                 AND account.status = 'active' AND user.status = 'active'"#,
            params![
                job.session_id,
                job.account_id.as_str(),
                job.actor_user_id,
                u64_to_i64(job.actor_membership_revision.get(), "membership revision")?,
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    role.map(|role| decode_membership_role(&role))
        .transpose()
        .map(|role| role.is_some_and(|role| membership_allows(role, AccountCapability::Reply)))
}

fn complete_reply_success(
    connection: &mut Connection,
    commit: ReplySuccessCommit,
    physical_limits: &SqlitePhysicalLimits,
    fail_before_flush_event: bool,
) -> Result<ReplyCompletion, StorageError> {
    normalized_reply_value(&commit.job_id, "reply job ID")?;
    validate_message(&commit.assistant_message, "assistant message")?;
    validate_reply_provenance(&commit.provenance)?;
    validate_reply_success_json(
        &commit.response_json,
        &commit.assistant_message,
        &commit.provenance,
    )?;
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
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Finalization,
    )?;
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
    let assistant_payload = encode_event_payload(&assistant_event)?;
    let terminal_sequence = assistant_sequence
        .checked_add(1)
        .ok_or(StorageError::IntegerOutOfRange("session sequence"))?;
    let flush_event = build_session_event(
        &job.session_id,
        terminal_sequence,
        &timestamp,
        SessionEventData::TurnFlushed {
            turn_id: job.turn_id.clone(),
        },
    );
    let flush_payload = encode_event_payload(&flush_event)?;
    let emitted_payload_bytes = checked_event_payload_total([&assistant_payload, &flush_payload])?;
    if require_session_finalization_capacity(
        &transaction,
        &job.session_id,
        &job.turn_id,
        2,
        emitted_payload_bytes,
    )?
    .0 != 2
    {
        return Err(StorageError::FinalizationReservationUnavailable);
    }
    insert_session_event(
        &transaction,
        &job.session_id,
        &assistant_event,
        &assistant_payload,
    )?;
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

    insert_session_event(&transaction, &job.session_id, &flush_event, &flush_payload)?;
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
    finish_session_finalization(
        &transaction,
        &job.session_id,
        &job.turn_id,
        2,
        emitted_payload_bytes,
    )?;
    let completion = query_reply_completion(&transaction, &job.id, false)?;
    transaction.commit()?;
    Ok(completion)
}

fn complete_reply_failure(
    connection: &mut Connection,
    commit: ReplyFailureCommit,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<ReplyCompletion, StorageError> {
    normalized_reply_value(&commit.job_id, "reply job ID")?;
    validate_reply_error_json(&commit.error_json, "reply failure JSON")?;
    let fingerprint = reply_completion_fingerprint("failed", &commit)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let job = query_reply_job(&transaction, &commit.job_id)?;
    if job.status != ReplyJobStatus::Started {
        let replay =
            replay_reply_completion(&transaction, job, ReplyJobStatus::Failed, &fingerprint)?;
        transaction.commit()?;
        return Ok(replay);
    }
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Finalization,
    )?;
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
    physical_limits: &SqlitePhysicalLimits,
) -> Result<ReplyCompletion, StorageError> {
    normalized_reply_value(&commit.job_id, "reply job ID")?;
    validate_reply_error_json(&commit.error_json, "reply outcome-unknown JSON")?;
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
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Finalization,
    )?;
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
    physical_limits: &SqlitePhysicalLimits,
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

    if !job_ids.is_empty() {
        require_connection_physical_capacity(
            &transaction,
            physical_limits,
            PhysicalCapacityGate::Finalization,
        )?;
    }

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
    let payload = encode_event_payload(&event)?;
    require_session_finalization_capacity(
        connection,
        &job.session_id,
        &job.turn_id,
        1,
        payload.bytes,
    )?;
    let changed = connection.execute(
        r#"UPDATE session_turns
           SET status = 'interrupted', completed_at = ?1
           WHERE session_id = ?2 AND id = ?3 AND status = 'open'"#,
        params![timestamp, job.session_id, job.turn_id],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }

    insert_session_event(connection, &job.session_id, &event, &payload)?;
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
    finish_session_finalization(connection, &job.session_id, &job.turn_id, 1, payload.bytes)?;
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
    authz: Option<&AuthzContext>,
    physical_limits: &SqlitePhysicalLimits,
    fail_before_flush_event: bool,
) -> Result<FlushSessionResponse, StorageError> {
    validated_durable_reference(session_id, "session ID")?;
    normalized_key(idempotency_key)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(context) = authz {
        require_current_authority(&transaction, context, AccountCapability::SessionWrite)?;
        require_active_session_actor(&transaction, session_id, context)?;
    }
    validated_durable_reference(&request.turn_id, "turn ID")?;
    if let Some(message) = &request.assistant_message {
        validate_message(message, "assistant message")?;
    }
    let fingerprint = session_command_fingerprint(Some(session_id), &request)?;
    let stored_response = match authz {
        Some(context) => load_session_command_receipt_for_actor::<FlushSessionResponse>(
            &transaction,
            context,
            idempotency_key,
            "flush_turn",
            &fingerprint,
            None,
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
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Finalization,
    )?;
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
    let active_reply: i64 = transaction.query_row(
        r#"SELECT EXISTS(
               SELECT 1 FROM reply_jobs
               WHERE session_id = ?1 AND turn_id = ?2
                 AND status IN ('queued', 'started')
           )"#,
        params![session_id, request.turn_id],
        |row| row.get(0),
    )?;
    if active_reply != 0 {
        return Err(StorageError::InvalidSessionTransition(
            "reply-backed turns must finalize through their durable reply job".into(),
        ));
    }
    let agent_backed: i64 = transaction.query_row(
        r#"SELECT EXISTS(
               SELECT 1 FROM agent_turns
               WHERE session_id = ?1 AND turn_id = ?2
           )"#,
        params![session_id, request.turn_id],
        |row| row.get(0),
    )?;
    if agent_backed != 0 {
        return Err(StorageError::InvalidSessionTransition(
            "agent-backed turns must finalize through their durable agent loop".into(),
        ));
    }
    let emitted_events = if request.assistant_message.is_some() {
        2
    } else {
        1
    };
    let timestamp = now();
    let prepared_assistant = if let Some(message) = &request.assistant_message {
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
        let payload = encode_event_payload(&event)?;
        Some((event, payload))
    } else {
        None
    };
    let flush_sequence = prepared_assistant
        .as_ref()
        .map(|(event, _)| event.sequence)
        .unwrap_or(summary.sequence)
        .checked_add(1)
        .ok_or(StorageError::IntegerOutOfRange("session sequence"))?;
    let flush_event = build_session_event(
        session_id,
        flush_sequence,
        &timestamp,
        SessionEventData::TurnFlushed {
            turn_id: request.turn_id.clone(),
        },
    );
    let flush_payload = encode_event_payload(&flush_event)?;
    let emitted_payload_bytes = match prepared_assistant.as_ref() {
        Some((_, assistant_payload)) => {
            checked_event_payload_total([assistant_payload, &flush_payload])?
        }
        None => flush_payload.bytes,
    };
    require_session_finalization_capacity(
        &transaction,
        session_id,
        &request.turn_id,
        emitted_events,
        emitted_payload_bytes,
    )?;

    let mut events = Vec::with_capacity(if request.assistant_message.is_some() {
        2
    } else {
        1
    });
    if let Some((event, payload)) = prepared_assistant {
        let sequence = event.sequence;
        insert_session_event(&transaction, session_id, &event, &payload)?;
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

    insert_session_event(&transaction, session_id, &flush_event, &flush_payload)?;
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
    if let Some(context) = authz {
        insert_session_command_receipt_for_actor(
            &transaction,
            context,
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
    finish_session_finalization(
        &transaction,
        session_id,
        &request.turn_id,
        emitted_events,
        emitted_payload_bytes,
    )?;
    transaction.commit()?;
    Ok(response)
}

fn resume_session(
    connection: &mut Connection,
    session_id: &str,
    request: ResumeSessionRequest,
    idempotency_key: &str,
    authz: Option<&AuthzContext>,
    limits: &StorageLimits,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<ResumeSessionResponse, StorageError> {
    validated_durable_reference(session_id, "session ID")?;
    normalized_key(idempotency_key)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(context) = authz {
        require_current_authority(&transaction, context, AccountCapability::SessionWrite)?;
        require_active_session_actor(&transaction, session_id, context)?;
    }
    let fingerprint = session_command_fingerprint(Some(session_id), &request)?;
    let stored_response = match authz {
        Some(context) => load_session_command_receipt_for_actor::<ResumeSessionResponse>(
            &transaction,
            context,
            idempotency_key,
            "resume_session",
            &fingerprint,
            None,
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

    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Admission,
    )?;

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
    let payload = encode_event_payload(&event)?;
    require_session_event_capacity(
        &transaction,
        session_id,
        EventCapacityRequest::events(1, payload.bytes),
        limits,
    )?;
    insert_session_event(&transaction, session_id, &event, &payload)?;
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
    if let Some(context) = authz {
        insert_session_command_receipt_for_actor(
            &transaction,
            context,
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
    physical_limits: &SqlitePhysicalLimits,
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
             AND NOT EXISTS (
                 SELECT 1 FROM agent_turns a
                 WHERE a.session_id = t.session_id AND a.turn_id = t.id
                   AND a.status NOT IN ('succeeded', 'failed', 'needs_attention')
             )
           ORDER BY t.session_id, t.ordinal LIMIT ?1"#,
    )?;
    let open_turns = statement
        .query_map([RECOVERY_BATCH_LIMIT], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);

    if !open_turns.is_empty() {
        require_connection_physical_capacity(
            &transaction,
            physical_limits,
            PhysicalCapacityGate::Finalization,
        )?;
    }

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
        let payload = encode_event_payload(&event)?;
        require_session_finalization_capacity(
            &transaction,
            &session_id,
            &turn_id,
            1,
            payload.bytes,
        )?;
        let changed = transaction.execute(
            r#"UPDATE session_turns
               SET status = 'interrupted', completed_at = ?1
               WHERE session_id = ?2 AND id = ?3 AND status = 'open'"#,
            params![timestamp, session_id, turn_id],
        )?;
        if changed != 1 {
            return Err(StorageError::ConcurrentModification);
        }
        insert_session_event(&transaction, &session_id, &event, &payload)?;
        update_session_projection(
            &transaction,
            &session_id,
            summary.sequence,
            SessionStatus::NeedsAttention,
            None,
            sequence,
            &timestamp,
        )?;
        finish_session_finalization(&transaction, &session_id, &turn_id, 1, payload.bytes)?;
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
            r#"SELECT id, account_id, actor_user_id, actor_membership_revision,
                      session_id, turn_id, provider_name, model_name,
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

fn query_reply_job_optional_for_account(
    connection: &Connection,
    account_id: &str,
    job_id: &str,
) -> Result<Option<ReplyJob>, StorageError> {
    connection
        .query_row(
            r#"SELECT id, account_id, actor_user_id, actor_membership_revision,
                      session_id, turn_id, provider_name, model_name,
                      status, attempt, request_json, response_json, error_json,
                      queued_at, started_at, finished_at, completion_fingerprint,
                      assistant_event_sequence, terminal_event_sequence
               FROM reply_jobs WHERE account_id = ?1 AND id = ?2"#,
            params![account_id, job_id],
            decode_reply_job_row,
        )
        .optional()?
        .map(StoredReplyJobRow::decode)
        .transpose()
}

fn query_reply_job_for_actor(
    connection: &mut Connection,
    context: &AuthzContext,
    job_id: &str,
) -> Result<Option<ReplyJob>, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_current_authority(&transaction, context, AccountCapability::Read)?;
    let job =
        query_reply_job_optional_for_account(&transaction, context.account_id.as_str(), job_id)?;
    transaction.commit()?;
    Ok(job)
}

#[cfg(test)]
pub(crate) fn query_reply_job_for_actor_with_snapshot_hook(
    connection: &mut Connection,
    context: &AuthzContext,
    job_id: &str,
    after_authority: impl FnOnce(),
) -> Result<Option<ReplyJob>, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_current_authority(&transaction, context, AccountCapability::Read)?;
    after_authority();
    let job =
        query_reply_job_optional_for_account(&transaction, context.account_id.as_str(), job_id)?;
    transaction.commit()?;
    Ok(job)
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
            r#"SELECT id, account_id, actor_user_id, actor_membership_revision,
                      session_id, turn_id, provider_name, model_name,
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
        account_id: row.get(1)?,
        actor_user_id: row.get(2)?,
        actor_membership_revision: row.get(3)?,
        session_id: row.get(4)?,
        turn_id: row.get(5)?,
        provider_name: row.get(6)?,
        model_name: row.get(7)?,
        status: row.get(8)?,
        attempt: row.get(9)?,
        request_json: row.get(10)?,
        response_json: row.get(11)?,
        error_json: row.get(12)?,
        queued_at: row.get(13)?,
        started_at: row.get(14)?,
        finished_at: row.get(15)?,
        completion_fingerprint: row.get(16)?,
        assistant_event_sequence: row.get(17)?,
        terminal_event_sequence: row.get(18)?,
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
    // request_json is server-derived durable context. On idempotent replay the
    // stored job remains authoritative so an upgraded context builder cannot
    // turn a lost response into a conflict.
    if job.id != spec.id
        || job.account_id != spec.authz.account_id
        || job.actor_user_id != spec.authz.user_id
        || job.provider_name != spec.provider_name
        || job.model_name != spec.model_name
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

fn validated_authz_context(context: &AuthzContext) -> Result<AuthzContext, StorageError> {
    normalized_account_value(context.account_id.as_str(), "account ID", 128)?;
    normalized_account_value(&context.user_id, "authorization user ID", 128)?;
    normalized_account_value(
        context.auth_session_id.as_str(),
        "authentication session ID",
        128,
    )?;
    Ok(context.clone())
}

/// Revalidates both the login-session binding and the current durable
/// membership at the same SQLite snapshot used by the caller's operation.
fn require_current_authority(
    connection: &Connection,
    context: &AuthzContext,
    capability: AccountCapability,
) -> Result<(), StorageError> {
    let durable_role = current_durable_role(connection, context)?;
    if !membership_allows(durable_role, capability) {
        return Err(StorageError::PermissionDenied);
    }
    Ok(())
}

/// Revalidates the exact membership captured when a Goal was armed. Automatic
/// rounds are process-owned work, so the original browser authentication
/// session is deliberately neither required nor accepted as durable authority.
fn require_goal_round_authority(
    connection: &Connection,
    session_id: &str,
    context: &AuthzContext,
) -> Result<(), StorageError> {
    let role = connection
        .query_row(
            r#"SELECT membership.role
               FROM accounts account
               JOIN account_memberships membership
                 ON membership.account_id = account.id
               JOIN users user ON user.id = membership.user_id
               JOIN sessions session ON session.account_id = account.id
               WHERE account.id = ?1
                 AND account.status = 'active'
                 AND membership.user_id = ?2
                 AND membership.status = 'active'
                 AND membership.revision = ?3
                 AND user.status = 'active'
                 AND session.id = ?4"#,
            params![
                context.account_id.as_str(),
                context.user_id,
                u64_to_i64(context.membership_revision.get(), "membership revision")?,
                session_id,
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let Some(role) = role else {
        return Err(StorageError::PermissionDenied);
    };
    let role = decode_membership_role(&role)?;
    if role != context.membership_role
        || !membership_allows(role, AccountCapability::SessionWrite)
        || !membership_allows(role, AccountCapability::Reply)
    {
        return Err(StorageError::PermissionDenied);
    }
    Ok(())
}

fn current_durable_role(
    connection: &Connection,
    context: &AuthzContext,
) -> Result<MembershipRole, StorageError> {
    let durable_role = connection
        .query_row(
            r#"SELECT membership.role
               FROM auth_sessions session
               JOIN users user ON user.id = session.user_id
               JOIN accounts account ON account.id = session.account_id
               JOIN account_memberships membership
                 ON membership.account_id = session.account_id
                AND membership.user_id = session.user_id
               WHERE session.id = ?1
                 AND session.account_id = ?2
                 AND session.user_id = ?3
                 AND session.membership_revision = ?4
                 AND session.expires_at > ?5
                 AND user.status = 'active'
                 AND account.status = 'active'
                 AND membership.status = 'active'
                 AND membership.revision = ?4
           "#,
            params![
                context.auth_session_id.as_str(),
                context.account_id.as_str(),
                context.user_id,
                u64_to_i64(context.membership_revision.get(), "membership revision")?,
                now(),
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let Some(durable_role) = durable_role else {
        return Err(StorageError::AuthSessionNotFound);
    };
    let durable_role = decode_membership_role(&durable_role)?;
    if durable_role != context.membership_role {
        return Err(StorageError::AuthSessionNotFound);
    }
    Ok(durable_role)
}

fn require_active_session_actor(
    connection: &Connection,
    session_id: &str,
    context: &AuthzContext,
) -> Result<(), StorageError> {
    let durable_role = current_durable_role(connection, context)?;
    let authorized = connection.query_row(
        r#"SELECT EXISTS(
                   SELECT 1
                   FROM sessions session
                   WHERE session.id = ?1 AND session.account_id = ?2
               )"#,
        params![session_id, context.account_id.as_str()],
        |row| row.get::<_, i64>(0),
    )?;
    if authorized == 0 {
        return Err(StorageError::SessionNotFound(session_id.to_owned()));
    }
    if !membership_allows(durable_role, AccountCapability::Read) {
        return Err(StorageError::PermissionDenied);
    }
    Ok(())
}

fn require_session_account(
    connection: &Connection,
    session_id: &str,
    account_id: &AccountId,
) -> Result<(), StorageError> {
    let authorized = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sessions WHERE id = ?1 AND account_id = ?2)",
        params![session_id, account_id.as_str()],
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
    context: &AuthzContext,
) -> Result<(), StorageError> {
    let durable_role = current_durable_role(connection, context)?;
    let authorized = connection.query_row(
        r#"SELECT EXISTS(
                   SELECT 1
                   FROM runs run
                   WHERE run.id = ?1 AND run.account_id = ?2
               )"#,
        params![run_id, context.account_id.as_str()],
        |row| row.get::<_, i64>(0),
    )?;
    if authorized == 0 {
        return Err(StorageError::RunNotFound(run_id.to_owned()));
    }
    if !membership_allows(durable_role, AccountCapability::ApproveDispatch) {
        return Err(StorageError::PermissionDenied);
    }
    Ok(())
}

fn require_active_run_actor(
    connection: &Connection,
    run_id: &str,
    context: &AuthzContext,
) -> Result<(), StorageError> {
    let durable_role = current_durable_role(connection, context)?;
    let authorized = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM runs WHERE id = ?1 AND account_id = ?2)",
        params![run_id, context.account_id.as_str()],
        |row| row.get::<_, i64>(0),
    )?;
    if authorized == 0 {
        return Err(StorageError::RunNotFound(run_id.to_owned()));
    }
    if !membership_allows(durable_role, AccountCapability::Read) {
        return Err(StorageError::PermissionDenied);
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

fn query_session_turn_for_actor(
    connection: &mut Connection,
    context: &AuthzContext,
    session_id: &str,
    turn_id: &str,
) -> Result<SessionTurn, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_active_session_actor(&transaction, session_id, context)?;
    let turn = query_session_turn(&transaction, session_id, turn_id)?;
    transaction.commit()?;
    Ok(turn)
}

fn query_session_reply_turns_for_actor(
    connection: &mut Connection,
    context: &AuthzContext,
    session_id: &str,
    through_sequence: u64,
    limit: usize,
) -> Result<Vec<SessionTurn>, StorageError> {
    query_session_reply_turns_after_for_actor(
        connection,
        context,
        session_id,
        0,
        through_sequence,
        limit,
    )
}

fn query_session_reply_turns_after_for_actor(
    connection: &mut Connection,
    context: &AuthzContext,
    session_id: &str,
    after_sequence: u64,
    through_sequence: u64,
    limit: usize,
) -> Result<Vec<SessionTurn>, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    // Authorization deliberately precedes sequence and limit checks so a
    // foreign Session cannot become a history-boundary oracle.
    require_active_session_actor(&transaction, session_id, context)?;
    let session = query_session_summary(&transaction, session_id)?;
    validate_session_event_tail(&transaction, &session)?;
    validate_active_turn_projection(&transaction, &session)?;
    if after_sequence > through_sequence || through_sequence > session.sequence {
        return Err(StorageError::ConcurrentModification);
    }
    let turns = query_session_reply_turns_after(
        &transaction,
        session_id,
        after_sequence,
        through_sequence,
        limit,
    )?;
    transaction.commit()?;
    Ok(turns)
}

fn query_session_reply_turns_after(
    connection: &Connection,
    session_id: &str,
    after_sequence: u64,
    through_sequence: u64,
    limit: usize,
) -> Result<Vec<SessionTurn>, StorageError> {
    if limit == 0 || limit > COLLECTION_PAGE_MAX_LIMIT {
        return Err(StorageError::InvalidPageLimit {
            limit,
            max: COLLECTION_PAGE_MAX_LIMIT,
        });
    }
    let through_sequence = u64_to_i64(through_sequence, "reply context sequence")?;
    let after_sequence = u64_to_i64(after_sequence, "reply context start sequence")?;
    let limit = capacity_limit(limit)?;
    // The partial index contains only assistant events, so legacy
    // assistant-less flushes never become scan candidates. Joining the
    // immediately following flush proves the pair was complete at this
    // historical boundary while LIMIT can stop the index scan after `limit`
    // complete pairs.
    let mut statement = connection.prepare(
        r#"SELECT turn.id, turn.session_id, turn.ordinal, turn.status,
                  turn.user_message, turn.assistant_message,
                  turn.started_at, turn.completed_at
           FROM session_events AS assistant
           JOIN session_events AS flushed
             ON flushed.session_id = assistant.session_id
            AND flushed.sequence = assistant.sequence + 1
            AND flushed.turn_id = assistant.turn_id
            AND flushed.event_kind = 'turn_flushed'
           JOIN session_turns AS turn
             ON turn.session_id = assistant.session_id
            AND turn.id = assistant.turn_id
           WHERE assistant.session_id = ?1
             AND assistant.sequence < ?2
             AND assistant.sequence > ?3
             AND assistant.event_kind = 'assistant_message'
             AND assistant.turn_id IS NOT NULL
             AND flushed.sequence <= ?2
             AND turn.status = 'flushed'
             AND turn.assistant_message IS NOT NULL
           ORDER BY assistant.sequence DESC
           LIMIT ?4"#,
    )?;
    let stored = statement
        .query_map(
            params![session_id, through_sequence, after_sequence, limit],
            decode_session_turn_row,
        )?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    let mut turns = stored
        .into_iter()
        .map(StoredSessionTurnRow::decode)
        .collect::<Result<Vec<_>, _>>()?;
    turns.reverse();
    for turn in &turns {
        let (_, durable_user) = query_session_user_message_event(connection, session_id, &turn.id)?;
        let assistant =
            query_session_turn_event(connection, session_id, &turn.id, "assistant_message")?;
        let flushed = query_session_turn_event(connection, session_id, &turn.id, "turn_flushed")?;
        let SessionEventData::AssistantMessage {
            turn_id,
            content: durable_assistant,
            ..
        } = assistant.data
        else {
            return Err(StorageError::CorruptData(format!(
                "Session turn `{}` assistant event has the wrong payload kind",
                turn.id
            )));
        };
        let SessionEventData::TurnFlushed {
            turn_id: flushed_turn_id,
        } = flushed.data
        else {
            return Err(StorageError::CorruptData(format!(
                "Session turn `{}` flush event has the wrong payload kind",
                turn.id
            )));
        };
        if turn_id != turn.id
            || flushed_turn_id != turn.id
            || durable_user != turn.user_message
            || Some(durable_assistant.as_str()) != turn.assistant_message.as_deref()
        {
            return Err(StorageError::CorruptData(format!(
                "Session turn `{}` reply history differs from its immutable events",
                turn.id
            )));
        }
    }
    Ok(turns)
}

fn query_session_turn_event(
    connection: &Connection,
    session_id: &str,
    turn_id: &str,
    event_kind: &str,
) -> Result<SessionEvent, StorageError> {
    let mut statement = connection.prepare(
        r#"SELECT sequence, event_id, event_kind, payload_version, payload_json,
                  turn_id, created_at
           FROM session_events
           WHERE session_id = ?1 AND turn_id = ?2 AND event_kind = ?3
           ORDER BY sequence LIMIT 2"#,
    )?;
    let mut stored = statement
        .query_map(
            params![session_id, turn_id, event_kind],
            decode_stored_session_event_row,
        )?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    if stored.len() != 1 {
        return Err(StorageError::CorruptData(format!(
            "Session turn `{turn_id}` must have exactly one `{event_kind}` event"
        )));
    }
    stored
        .pop()
        .expect("one durable turn event was required")
        .decode()
}

fn query_session_user_message_event(
    connection: &Connection,
    session_id: &str,
    turn_id: &str,
) -> Result<(u64, String), StorageError> {
    let event = query_session_turn_event(connection, session_id, turn_id, "user_message")?;
    let SessionEventData::UserMessage {
        turn_id: payload_turn_id,
        content,
    } = event.data
    else {
        return Err(StorageError::CorruptData(format!(
            "Session turn `{turn_id}` user event has the wrong payload kind"
        )));
    };
    if payload_turn_id != turn_id {
        return Err(StorageError::CorruptData(format!(
            "Session turn `{turn_id}` user event names a different turn"
        )));
    }
    Ok((event.sequence, content))
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
    payload: &EncodedEventPayload,
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
            payload.json,
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
        "reply_job": {
            "id": job.id,
            "provider_name": job.provider_name,
            "model_name": job.model_name,
        },
    }))?)
}

/// Compatibility fingerprint emitted before durable multi-turn context.
///
/// The old API always persisted exactly one user message. Accepting this
/// shape on replay lets an in-flight client cross the upgrade boundary while
/// all newly written receipts use the server-derived-context-independent
/// fingerprint above.
fn legacy_reply_start_fingerprint_v1(
    session_id: &str,
    request: &StartTurnRequest,
    job: &ReplyJobSpec,
) -> Result<String, StorageError> {
    let request_json = json!({
        "messages": [{
            "role": "user",
            "content": request.user_message,
        }],
    });
    Ok(serde_json::to_string(&json!({
        "session_id": session_id,
        "request": request,
        "reply_job": {
            "id": job.id,
            "provider_name": job.provider_name,
            "model_name": job.model_name,
            "request_json": request_json,
        },
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
               WHERE account_id = ?1 AND actor_user_id IS NULL AND operation = ?2
                 AND idempotency_key = ?3"#,
            params![LOCAL_ACCOUNT_ID, operation, idempotency_key],
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
    context: &AuthzContext,
    idempotency_key: &str,
    operation: &str,
    request_fingerprint: &str,
    compatible_fingerprint: Option<&str>,
) -> Result<Option<T>, StorageError> {
    let stored = connection
        .query_row(
            r#"SELECT request_fingerprint, response_json
               FROM session_command_receipts
               WHERE account_id = ?1 AND actor_user_id = ?2
                 AND operation = ?3 AND idempotency_key = ?4"#,
            params![
                context.account_id.as_str(),
                context.user_id,
                operation,
                idempotency_key
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((stored_fingerprint, response_json)) = stored else {
        return Ok(None);
    };
    if stored_fingerprint != request_fingerprint
        && compatible_fingerprint != Some(stored_fingerprint.as_str())
    {
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
               account_id, actor_user_id, idempotency_key, operation,
               request_fingerprint, response_json,
               session_id, event_sequence, created_at
           ) VALUES (?1, NULL, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
        params![
            LOCAL_ACCOUNT_ID,
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
    context: &AuthzContext,
    idempotency_key: &str,
    operation: &str,
    request_fingerprint: &str,
    response: &T,
    session_id: &str,
    event_sequence: u64,
) -> Result<(), StorageError> {
    connection.execute(
        r#"INSERT INTO session_command_receipts(
               account_id, actor_user_id, idempotency_key, operation, request_fingerprint,
               response_json, session_id, event_sequence, created_at
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"#,
        params![
            context.account_id.as_str(),
            context.user_id,
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
    protocol::validate_assistant_message(value)
        .map_err(|error| StorageError::InvalidSessionTransition(format!("{field} {error}")))
}

fn invalid_resource_envelope(field: &'static str, error: ResourceEnvelopeError) -> StorageError {
    StorageError::InvalidResourceEnvelope(format!("{field} {error}"))
}

fn validate_reply_job_spec(job: &ReplyJobSpec) -> Result<(), StorageError> {
    normalized_reply_value(&job.id, "reply job ID")?;
    if job.id.len() > REPLY_JOB_ID_MAX_BYTES {
        return Err(StorageError::InvalidReplyTransition(format!(
            "reply job ID cannot exceed {REPLY_JOB_ID_MAX_BYTES} UTF-8 bytes"
        )));
    }
    validated_authz_context(&job.authz)?;
    protocol::validate_reply_provider_id(&job.provider_name)
        .map_err(|error| invalid_resource_envelope("reply provider name", error))?;
    if let Some(model_name) = &job.model_name {
        protocol::validate_reply_model_id(model_name)
            .map_err(|error| invalid_resource_envelope("reply model name", error))?;
    }
    validate_reply_json(
        &job.request_json,
        "reply request JSON",
        REPLY_REQUEST_JSON_MAX_BYTES,
    )?;
    Ok(())
}

fn validate_reply_provenance(provenance: &AssistantReplyProvenance) -> Result<(), StorageError> {
    protocol::validate_reply_provider_id(&provenance.provider_id)
        .map_err(|error| invalid_resource_envelope("assistant reply provider ID", error))?;
    if let Some(model) = &provenance.model {
        protocol::validate_reply_model_id(model)
            .map_err(|error| invalid_resource_envelope("assistant reply model", error))?;
    }
    if !matches!(
        (&provenance.reply_kind, &provenance.model),
        (protocol::AssistantReplyKind::Model, Some(_))
            | (protocol::AssistantReplyKind::NonModelFallback, None)
    ) {
        return Err(StorageError::InvalidReplyTransition(
            "model provenance must declare a model and non-model provenance must omit it".into(),
        ));
    }
    Ok(())
}

fn validate_reply_success_json(
    value: &Value,
    assistant_message: &str,
    provenance: &AssistantReplyProvenance,
) -> Result<(), StorageError> {
    validate_reply_json(value, "reply response JSON", REPLY_RESPONSE_JSON_MAX_BYTES)?;
    let object = value.as_object().expect("validated as an object");
    if object.len() != 3
        || object.get("content").and_then(Value::as_str) != Some(assistant_message)
        || !object.contains_key("finish_reason")
    {
        return Err(StorageError::InvalidReplyTransition(
            "reply response JSON must match the assistant message and typed response shape".into(),
        ));
    }
    match object.get("finish_reason") {
        Some(Value::Null) => {}
        Some(Value::String(reason)) => protocol::validate_reply_finish_reason(reason)
            .map_err(|error| invalid_resource_envelope("reply finish reason", error))?,
        _ => {
            return Err(StorageError::InvalidReplyTransition(
                "reply finish reason must be a string or null".into(),
            ));
        }
    }

    let provider = object
        .get("provider")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            StorageError::InvalidReplyTransition(
                "reply response JSON must contain typed provider metadata".into(),
            )
        })?;
    let expected_kind = match provenance.reply_kind {
        protocol::AssistantReplyKind::Model => "model",
        protocol::AssistantReplyKind::NonModelFallback => "non_model_fallback",
    };
    let model_matches = match (&provenance.model, provider.get("model")) {
        (Some(expected), Some(Value::String(actual))) => expected == actual,
        (None, Some(Value::Null)) => true,
        _ => false,
    };
    if provider.len() != 3
        || provider.get("provider_id").and_then(Value::as_str)
            != Some(provenance.provider_id.as_str())
        || provider.get("reply_kind").and_then(Value::as_str) != Some(expected_kind)
        || !model_matches
    {
        return Err(StorageError::InvalidReplyTransition(
            "reply response provider metadata must match durable provenance".into(),
        ));
    }
    Ok(())
}

fn validate_reply_error_json(value: &Value, field: &'static str) -> Result<(), StorageError> {
    validate_reply_json(value, field, REPLY_ERROR_JSON_MAX_BYTES)?;
    let object = value.as_object().expect("validated as an object");
    let code = object.get("code").and_then(Value::as_str);
    let message = object.get("message").and_then(Value::as_str);
    if object.len() != 2 || code.is_none() || message.is_none() {
        return Err(StorageError::InvalidReplyTransition(format!(
            "{field} must contain only string code and message fields"
        )));
    }
    protocol::validate_reply_error_code(code.expect("checked above"))
        .map_err(|error| invalid_resource_envelope("reply error code", error))?;
    protocol::validate_reply_error_message(message.expect("checked above"))
        .map_err(|error| invalid_resource_envelope("reply error message", error))?;
    Ok(())
}

fn validate_reply_json(
    value: &Value,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), StorageError> {
    if !value.is_object() {
        return Err(StorageError::InvalidReplyTransition(format!(
            "{field} must be a JSON object"
        )));
    }
    if bounded_json_serialized_len(value, max_bytes)?.is_none() {
        return Err(StorageError::InvalidReplyTransition(format!(
            "{field} cannot exceed {max_bytes} serialized bytes"
        )));
    }
    Ok(())
}

fn bounded_json_serialized_len(
    value: &Value,
    max_bytes: usize,
) -> Result<Option<usize>, StorageError> {
    let mut writer = BoundedJsonWriter::new(max_bytes);
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => Ok(Some(writer.written)),
        Err(_) if writer.exceeded => Ok(None),
        Err(error) => Err(StorageError::Json(error)),
    }
}

struct BoundedJsonWriter {
    written: usize,
    max_bytes: usize,
    exceeded: bool,
}

impl BoundedJsonWriter {
    fn new(max_bytes: usize) -> Self {
        Self {
            written: 0,
            max_bytes,
            exceeded: false,
        }
    }
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next) = self.written.checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(io::Error::other("serialized JSON size overflow"));
        };
        if next > self.max_bytes {
            self.exceeded = true;
            return Err(io::Error::other("serialized JSON exceeds its limit"));
        }
        self.written = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
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
    context: &AuthzContext,
    run_id: &str,
) -> Result<RunSnapshot, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_active_run_actor(&transaction, run_id, context)?;
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
    context: &AuthzContext,
    run_id: &str,
    approval_id: &str,
) -> Result<ReviewContext, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    // Authorization deliberately precedes every lookup that could reveal
    // whether an approval or call exists.
    require_active_run_owner(&transaction, run_id, context)?;
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
    context: &AuthzContext,
    run_id: &str,
) -> Result<RunSnapshot, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_active_run_actor(&transaction, run_id, context)?;
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
    context: &AuthzContext,
    run_id: &str,
) -> Result<StoredRun, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_active_run_actor(&transaction, run_id, context)?;
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

fn query_bounded_run_for_actor(
    connection: &mut Connection,
    context: &AuthzContext,
    run_id: &str,
    events_before: Option<&str>,
    events_limit: usize,
) -> Result<BoundedRunRead, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    // Authorization precedes semantic cursor validation so an unowned Run is
    // indistinguishable from a missing Run even when a cursor was supplied.
    require_active_run_actor(&transaction, run_id, context)?;
    let fetch_limit = validated_read_page_limit(events_limit, EVENT_PAGE_MAX_LIMIT)?;
    let events_before = events_before
        .map(|value| {
            cursor::decode_run_events(value, context.account_id.as_str(), &context.user_id, run_id)
        })
        .transpose()?;
    let snapshot = query_snapshot(&transaction, run_id)?;
    validate_run_event_tail(&transaction, &snapshot)?;
    let (events, events_page) = query_run_events_tail(
        &transaction,
        &ScopedEventTailQuery {
            account_id: context.account_id.as_str(),
            actor_user_id: &context.user_id,
            parent_id: run_id,
            head: snapshot.run.sequence,
            before: events_before,
            limit: events_limit,
            fetch_limit,
        },
    )?;
    transaction.commit()?;
    Ok(BoundedRunRead {
        snapshot,
        events,
        events_page,
    })
}

fn query_run_events_tail(
    connection: &Connection,
    query: &ScopedEventTailQuery<'_>,
) -> Result<(Vec<RunEvent>, ReadPageInfo), StorageError> {
    let run_id = query.parent_id;
    let head = query.head;
    let before = query.before;
    let limit = query.limit;
    let fetch_limit = query.fetch_limit;
    if before.is_some_and(|position| position > head) {
        return Err(StorageError::PageCursorBeyondHead { head });
    }
    let mut rows = if let Some(before) = before {
        let mut statement = connection.prepare(
            r#"SELECT sequence, event_id, event_kind, payload_version, payload_json,
                      data_kind, call_id, approval_id, approval_status, policy_revision
               FROM run_events
               WHERE run_id = ?1 AND sequence < ?2
               ORDER BY sequence DESC LIMIT ?3"#,
        )?;
        statement
            .query_map(
                params![
                    run_id,
                    u64_to_i64(before, "Run history cursor")?,
                    fetch_limit
                ],
                decode_stored_event_row,
            )?
            .collect::<Result<Vec<_>, _>>()?
    } else {
        let mut statement = connection.prepare(
            r#"SELECT sequence, event_id, event_kind, payload_version, payload_json,
                      data_kind, call_id, approval_id, approval_status, policy_revision
               FROM run_events
               WHERE run_id = ?1
               ORDER BY sequence DESC LIMIT ?2"#,
        )?;
        statement
            .query_map(params![run_id, fetch_limit], decode_stored_event_row)?
            .collect::<Result<Vec<_>, _>>()?
    };
    validate_descending_ordinals(
        rows.iter().map(|row| row.sequence),
        before.map_or(head, |position| position.saturating_sub(1)),
        "Run event",
    )?;
    let has_more = rows.len() > limit;
    rows.truncate(limit);
    let next_before = if has_more {
        let oldest = rows.last().ok_or_else(|| {
            StorageError::CorruptData("Run event page sentinel has no returned item".into())
        })?;
        Some(cursor::encode_run_events(
            query.account_id,
            query.actor_user_id,
            run_id,
            i64_to_u64(oldest.sequence, "Run event sequence")?,
        )?)
    } else {
        None
    };
    let mut events = rows
        .into_iter()
        .map(StoredEventRow::decode)
        .collect::<Result<Vec<_>, _>>()?;
    events.reverse();
    Ok((
        events,
        ReadPageInfo {
            next_before,
            has_more,
        },
    ))
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
    context: &AuthzContext,
    run_id: &str,
    after: u64,
) -> Result<Vec<RunEvent>, StorageError> {
    let after = u64_to_i64(after, "event cursor")?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_active_run_actor(&transaction, run_id, context)?;
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
    context: &AuthzContext,
    run_id: &str,
    after: u64,
    limit: usize,
) -> Result<RunEventPage, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_active_run_actor(&transaction, run_id, context)?;
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
               WHERE account_id = ?1 AND actor_user_id IS NULL
                 AND operation = 'review'
                 AND idempotency_key = ?2"#,
            params![LOCAL_ACCOUNT_ID, idempotency_key],
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
    context: &AuthzContext,
    run_id: &str,
    idempotency_key: &str,
) -> Result<Option<ReviewReceipt>, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_active_run_owner(&transaction, run_id, context)?;
    let stored = transaction
        .query_row(
            r#"SELECT request_fingerprint, response_json, run_id, event_sequence
               FROM idempotency_receipts
               WHERE account_id = ?1 AND actor_user_id = ?2
                 AND operation = 'review'
                 AND idempotency_key = ?3"#,
            params![
                context.account_id.as_str(),
                context.user_id,
                idempotency_key
            ],
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
    context: &AuthzContext,
    run_id: &str,
    idempotency_key: &str,
) -> Result<Option<ReviewReceipt>, StorageError> {
    let stored = connection
        .query_row(
            r#"SELECT request_fingerprint, response_json, run_id, event_sequence
               FROM idempotency_receipts
               WHERE account_id = ?1 AND actor_user_id = ?2
                 AND operation = 'review'
                 AND idempotency_key = ?3"#,
            params![
                context.account_id.as_str(),
                context.user_id,
                idempotency_key
            ],
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
    authz: Option<&AuthzContext>,
    limits: &StorageLimits,
    physical_limits: &SqlitePhysicalLimits,
    fail_after_event: bool,
) -> Result<CommitOutcome, StorageError> {
    validated_durable_reference(&commit.snapshot.run.id, "run ID")?;
    let key = normalized_key(&commit.idempotency_key)?.to_owned();
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(context) = authz {
        require_active_run_owner(&transaction, &commit.snapshot.run.id, context)?;
        if commit.dispatch.as_ref().is_some_and(|dispatch| {
            dispatch.approving_authz != *context
                || dispatch
                    .initiating_authz
                    .as_ref()
                    .is_some_and(|initiator| initiator.account_id != context.account_id)
        }) {
            return Err(StorageError::RunNotFound(commit.snapshot.run.id.clone()));
        }
    }
    validate_commit(&commit)?;
    let new_sequence = u64_to_i64(commit.snapshot.run.sequence, "run sequence")?;
    let response_json = serde_json::to_string(&commit.response)?;
    let stored_receipt = match authz {
        Some(context) => load_review_receipt_for_actor_in_transaction(
            &transaction,
            context,
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

    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Admission,
    )?;

    if let Some(dispatch) = &commit.dispatch {
        validate_dispatch_admission_binding(
            &transaction,
            &commit.snapshot.run.id,
            commit.event.sequence,
            dispatch,
        )?;
    }

    let account_id = authz.map_or(LOCAL_ACCOUNT_ID, |context| context.account_id.as_str());
    let actor_user_id = authz.map(|context| context.user_id.as_str());
    let dispatch_actor_user_id = commit.dispatch.as_ref().map(|dispatch| {
        dispatch
            .initiating_authz
            .as_ref()
            .unwrap_or(&dispatch.approving_authz)
            .user_id
            .as_str()
    });
    if commit.dispatch.is_some() {
        require_dispatch_queue_capacity(&transaction, account_id, dispatch_actor_user_id, limits)?;
    }
    let event_payload = encode_event_payload(&commit.event)?;
    let dispatch_payload_reservation = commit
        .dispatch
        .as_ref()
        .map(|dispatch| dispatch_queued_payload_reservation(&dispatch.call_id))
        .transpose()?
        .unwrap_or(0);
    require_run_event_capacity(
        &transaction,
        &commit.snapshot.run.id,
        EventCapacityRequest {
            new_event_slots: 1,
            new_event_payload_bytes: event_payload.bytes,
            new_reserved_slots: if commit.dispatch.is_some() { 2 } else { 0 },
            new_reserved_payload_bytes: dispatch_payload_reservation,
        },
        limits,
    )?;

    update_projection(&transaction, &commit.snapshot, commit.expected_sequence)?;

    if commit.event.data.is_some() {
        insert_event_v2(
            &transaction,
            &commit.snapshot.run.id,
            &commit.event,
            &event_payload,
        )?;
    } else {
        insert_event_v1(
            &transaction,
            &commit.snapshot.run.id,
            &commit.event,
            &event_payload,
        )?;
    }

    transaction.execute(
        r#"INSERT INTO idempotency_receipts(
               account_id, actor_user_id, idempotency_key, operation, request_fingerprint,
               response_json, run_id, event_sequence, created_at
           ) VALUES (?1, ?2, ?3, 'review', ?4, ?5, ?6, ?7, ?8)"#,
        params![
            account_id,
            actor_user_id,
            key,
            commit.request_fingerprint,
            response_json,
            commit.snapshot.run.id,
            new_sequence,
            Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        ],
    )?;

    if let Some(dispatch) = &commit.dispatch {
        let queued_at = now();
        insert_dispatch_job(
            &transaction,
            &commit.snapshot.run.id,
            new_sequence,
            dispatch,
            &queued_at,
        )?;
        insert_dispatch_finalization_reservation(
            &transaction,
            account_id,
            dispatch_actor_user_id,
            &commit.snapshot.run.id,
            &dispatch.call_id,
            dispatch_payload_reservation,
            &queued_at,
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
                   call_id, account_id, run_id, approval_id, approval_event_sequence,
                   initiating_actor_user_id, initiating_membership_revision,
                   approving_actor_user_id, approving_membership_revision,
                   tool_name, tool_version, effect, args_json, args_digest,
                   policy_id, policy_revision, sandbox_profile, status, attempt,
                   result_json, authorization_error_json, queued_at, started_at, finished_at,
                   start_event_sequence, result_event_sequence
               FROM dispatch_jobs WHERE call_id = ?1"#,
            [call_id],
            |row| {
                Ok(StoredDispatchRow {
                    call_id: row.get(0)?,
                    account_id: row.get(1)?,
                    run_id: row.get(2)?,
                    approval_id: row.get(3)?,
                    approval_event_sequence: row.get(4)?,
                    initiating_actor_user_id: row.get(5)?,
                    initiating_membership_revision: row.get(6)?,
                    approving_actor_user_id: row.get(7)?,
                    approving_membership_revision: row.get(8)?,
                    tool_name: row.get(9)?,
                    tool_version: row.get(10)?,
                    effect: row.get(11)?,
                    args_json: row.get(12)?,
                    args_digest: row.get(13)?,
                    policy_id: row.get(14)?,
                    policy_revision: row.get(15)?,
                    sandbox_profile: row.get(16)?,
                    status: row.get(17)?,
                    attempt: row.get(18)?,
                    result_json: row.get(19)?,
                    authorization_error_json: row.get(20)?,
                    queued_at: row.get(21)?,
                    started_at: row.get(22)?,
                    finished_at: row.get(23)?,
                    start_event_sequence: row.get(24)?,
                    result_event_sequence: row.get(25)?,
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
    physical_limits: &SqlitePhysicalLimits,
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
    let queued_payload_reservation = dispatch_queued_payload_reservation(&job.call_id)?;
    require_dispatch_finalization_capacity(
        &transaction,
        &job.run_id,
        &job.call_id,
        2,
        queued_payload_reservation,
    )?;
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::ReservedProgress,
    )?;
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
    validate_canonical_dispatch_start(&transaction, &job, &commit)?;
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
    let event_payload = encode_event_payload(&commit.event)?;
    let terminal_payload_reservation = dispatch_terminal_payload_reservation(&job.call_id)?;
    let required_payload_reservation = event_payload
        .bytes
        .checked_add(terminal_payload_reservation)
        .ok_or(StorageError::IntegerOutOfRange(
            "dispatch claim payload reservation",
        ))?;
    require_dispatch_finalization_capacity(
        &transaction,
        &job.run_id,
        &job.call_id,
        2,
        required_payload_reservation,
    )?;

    update_projection(&transaction, &commit.snapshot, commit.expected_sequence)?;
    insert_event_v2(&transaction, &job.run_id, &commit.event, &event_payload)?;
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
    consume_dispatch_claim_capacity(
        &transaction,
        &job.run_id,
        &job.call_id,
        event_payload.bytes,
        terminal_payload_reservation,
    )?;

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
    let run_is_active: i64 = connection.query_row(
        r#"SELECT EXISTS(
               SELECT 1
               FROM runs run
               JOIN accounts account ON account.id = run.account_id
               WHERE run.id = ?1 AND run.account_id = ?2
                 AND account.status = 'active'
           )"#,
        params![job.run_id, job.account_id.as_str()],
        |row| row.get(0),
    )?;
    if run_is_active == 0 {
        return Ok(Some("dispatch_account_or_run_inactive"));
    }

    let Some(initiating_actor_user_id) = job.initiating_actor_user_id.as_deref() else {
        return Ok(Some("missing_initiating_actor"));
    };
    let Some(initiating_revision) = job.initiating_membership_revision else {
        return Ok(Some("missing_initiating_revision"));
    };
    let initiating_role = durable_job_membership_role(
        connection,
        job.account_id.as_str(),
        initiating_actor_user_id,
        initiating_revision,
    )?;
    let Some(initiating_role) = initiating_role else {
        return Ok(Some("initiating_authority_revoked"));
    };
    if !membership_allows(initiating_role, AccountCapability::SessionWrite) {
        return Ok(Some("initiating_capability_revoked"));
    }

    let Some(approving_actor_user_id) = job.approving_actor_user_id.as_deref() else {
        return Ok(Some("missing_approving_actor"));
    };
    let Some(approving_revision) = job.approving_membership_revision else {
        return Ok(Some("missing_approving_revision"));
    };
    let approving_role = durable_job_membership_role(
        connection,
        job.account_id.as_str(),
        approving_actor_user_id,
        approving_revision,
    )?;
    let Some(approving_role) = approving_role else {
        return Ok(Some("approving_authority_revoked"));
    };
    if !membership_allows(approving_role, AccountCapability::ApproveDispatch) {
        return Ok(Some("approving_capability_revoked"));
    }
    Ok(None)
}

fn durable_job_membership_role(
    connection: &Connection,
    account_id: &str,
    actor_user_id: &str,
    revision: MembershipRevision,
) -> Result<Option<MembershipRole>, StorageError> {
    let role = connection
        .query_row(
            r#"SELECT membership.role
               FROM accounts account
               JOIN account_memberships membership
                 ON membership.account_id = account.id
               JOIN users user ON user.id = membership.user_id
               WHERE account.id = ?1 AND account.status = 'active'
                 AND membership.user_id = ?2
                 AND membership.revision = ?3
                 AND membership.status = 'active'
                 AND user.status = 'active'"#,
            params![
                account_id,
                actor_user_id,
                u64_to_i64(revision.get(), "membership revision")?,
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    role.map(|role| decode_membership_role(&role)).transpose()
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
    let event_payload = encode_event_payload(&event)?;
    require_dispatch_finalization_capacity(
        connection,
        &job.run_id,
        &job.call_id,
        2,
        event_payload.bytes,
    )?;
    snapshot.run.status = RunStatus::NeedsAttention;
    snapshot.run.sequence = next_sequence;
    update_projection(connection, &snapshot, expected_sequence)?;
    insert_event_v2(connection, &job.run_id, &event, &event_payload)?;

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
    finish_dispatch_finalization(
        connection,
        &job.run_id,
        &job.call_id,
        2,
        event_payload.bytes,
    )?;
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
    physical_limits: &SqlitePhysicalLimits,
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
    if job.status == DispatchStatus::Finished {
        let replayed = replay_finished_dispatch(&transaction, job, &commit)?;
        transaction.commit()?;
        return Ok(replayed);
    }
    if job.status != DispatchStatus::Started || job.run_id != commit.snapshot.run.id {
        return Err(StorageError::InvalidDispatchTransition(
            "only the matching started dispatch may be completed".into(),
        ));
    }
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Finalization,
    )?;
    validate_canonical_dispatch_completion(&transaction, &job, &commit)?;
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
    let event_payload = encode_event_payload(&commit.event)?;
    require_dispatch_finalization_capacity(
        &transaction,
        &job.run_id,
        &job.call_id,
        1,
        event_payload.bytes,
    )?;

    update_projection(&transaction, &commit.snapshot, commit.expected_sequence)?;
    insert_event_v2(&transaction, &job.run_id, &commit.event, &event_payload)?;
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
    finish_dispatch_finalization(
        &transaction,
        &job.run_id,
        &job.call_id,
        1,
        event_payload.bytes,
    )?;

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

fn replay_finished_dispatch(
    connection: &Connection,
    job: DispatchJob,
    commit: &DispatchCompleteCommit,
) -> Result<DispatchJob, StorageError> {
    let stored_result = job.result_json.as_ref().ok_or_else(|| {
        StorageError::CorruptData(format!(
            "finished dispatch `{}` has no durable result",
            job.call_id
        ))
    })?;
    let result_sequence = job.result_event_sequence.ok_or_else(|| {
        StorageError::CorruptData(format!(
            "finished dispatch `{}` has no durable result event",
            job.call_id
        ))
    })?;
    let stored_event = query_run_event_at(
        connection,
        &job.run_id,
        u64_to_i64(result_sequence, "dispatch result event sequence")?,
    )?;
    let stored_snapshot = query_snapshot(connection, &job.run_id)?;
    validate_run_event_tail(connection, &stored_snapshot)?;

    if stored_snapshot.run.id != job.run_id
        || stored_snapshot.run.sequence != result_sequence
        || stored_event.sequence != result_sequence
    {
        return Err(StorageError::CorruptData(format!(
            "finished dispatch `{}` does not match its durable run head",
            job.call_id
        )));
    }
    match stored_event.data.as_ref() {
        Some(RunEventData::ToolResult {
            call_id,
            outcome,
            status,
        }) if call_id == &job.call_id
            && status == &outcome.call_status()
            && serde_json::to_value(outcome)? == *stored_result => {}
        _ => {
            return Err(StorageError::CorruptData(format!(
                "finished dispatch `{}` result disagrees with its durable event",
                job.call_id
            )));
        }
    }

    if commit.call_id != job.call_id
        || commit.snapshot != stored_snapshot
        || commit.event != stored_event
        || commit.result_json != *stored_result
    {
        return Err(StorageError::IdempotencyConflict);
    }
    Ok(job)
}

fn recover_started(
    connection: &mut Connection,
    commit: DispatchRecoveryCommit,
    physical_limits: &SqlitePhysicalLimits,
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
        physical_limits,
        false,
    )
}

fn insert_dispatch_job(
    connection: &Connection,
    run_id: &str,
    approval_event_sequence: i64,
    job: &DispatchJobSpec,
    queued_at: &str,
) -> Result<(), StorageError> {
    connection.execute(
        r#"INSERT INTO dispatch_jobs(
               call_id, account_id, run_id, approval_id, approval_event_sequence,
               initiating_actor_user_id, initiating_membership_revision,
               approving_actor_user_id, approving_membership_revision,
               tool_name, tool_version, effect, args_json, args_digest,
               policy_id, policy_revision, sandbox_profile, status, attempt, queued_at
           ) VALUES (
               ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
               ?13, ?14, ?15, ?16, ?17, 'queued', 0, ?18
           )"#,
        params![
            job.call_id,
            job.approving_authz.account_id.as_str(),
            run_id,
            job.approval_id,
            approval_event_sequence,
            job.initiating_authz
                .as_ref()
                .map(|context| context.user_id.as_str()),
            job.initiating_authz
                .as_ref()
                .map(|context| {
                    u64_to_i64(context.membership_revision.get(), "membership revision")
                })
                .transpose()?,
            job.approving_authz.user_id,
            u64_to_i64(
                job.approving_authz.membership_revision.get(),
                "membership revision"
            )?,
            job.tool_name,
            job.tool_version,
            tool_effect_to_db(&job.effect),
            serde_json::to_string(&job.args_json)?,
            job.args_digest,
            job.policy_id,
            job.policy_revision,
            sandbox_profile_to_db(&job.sandbox_profile),
            queued_at,
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
    payload: &EncodedEventPayload,
) -> Result<(), StorageError> {
    insert_event(connection, run_id, event, payload, EVENT_PAYLOAD_VERSION_V1)
}

fn insert_event_v2(
    connection: &Connection,
    run_id: &str,
    event: &RunEvent,
    payload: &EncodedEventPayload,
) -> Result<(), StorageError> {
    insert_event(connection, run_id, event, payload, EVENT_PAYLOAD_VERSION_V2)
}

fn insert_event(
    connection: &Connection,
    run_id: &str,
    event: &RunEvent,
    payload: &EncodedEventPayload,
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
            payload.json,
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
    validate_new_dispatch_text(&job.call_id, "call ID", DISPATCH_CALL_ID_MAX_BYTES)?;
    validate_new_dispatch_text(
        &job.approval_id,
        "approval ID",
        DISPATCH_IDENTIFIER_MAX_BYTES,
    )?;
    if let Some(initiator) = &job.initiating_authz {
        validated_authz_context(initiator)?;
    }
    validated_authz_context(&job.approving_authz)?;
    if job
        .initiating_authz
        .as_ref()
        .is_some_and(|initiator| initiator.account_id != job.approving_authz.account_id)
    {
        return Err(StorageError::InvalidDispatchTransition(
            "dispatch actors must belong to the same account".into(),
        ));
    }
    validate_new_dispatch_tool_name(&job.tool_name)?;
    validate_new_dispatch_id_component(
        &job.tool_version,
        "tool version",
        DISPATCH_TOOL_VERSION_MAX_BYTES,
    )?;
    validate_sha256_digest(&job.args_digest)?;
    validate_new_dispatch_text(&job.policy_id, "policy ID", DISPATCH_IDENTIFIER_MAX_BYTES)?;
    validate_new_dispatch_text(
        &job.policy_revision,
        "policy revision",
        DISPATCH_IDENTIFIER_MAX_BYTES,
    )?;
    if !job.args_json.is_object() {
        return Err(StorageError::InvalidDispatchTransition(
            "tool arguments must be a JSON object".into(),
        ));
    }
    let mut writer = BoundedJsonWriter::new(DISPATCH_ARGS_JSON_MAX_BYTES);
    match serde_json::to_writer(&mut writer, &job.args_json) {
        Ok(()) => {}
        Err(_) if writer.exceeded => {
            return Err(StorageError::InvalidDispatchTransition(format!(
                "tool arguments cannot exceed {DISPATCH_ARGS_JSON_MAX_BYTES} serialized bytes"
            )));
        }
        Err(error) => return Err(StorageError::Json(error)),
    }
    Ok(())
}

fn validate_dispatch_admission_binding(
    connection: &Connection,
    run_id: &str,
    approval_event_sequence: u64,
    job: &DispatchJobSpec,
) -> Result<(), StorageError> {
    let runtime_identity = connection
        .query_row(
            r#"SELECT primary_run_id, policy_id, policy_revision
               FROM runtime_identity WHERE singleton = 1"#,
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    if let Some((primary_run_id, policy_id, policy_revision)) = runtime_identity
        && (run_id != primary_run_id
            || job.policy_id != policy_id
            || job.policy_revision != policy_revision)
    {
        return Err(StorageError::InvalidDispatchTransition(
            "dispatch policy must match the bound runtime identity".into(),
        ));
    }

    let (call_sequence, call) = query_requested_call(connection, run_id, &job.call_id)?
        .ok_or_else(|| {
            StorageError::InvalidDispatchTransition(
                "dispatch requires an earlier durable requested tool call".into(),
            )
        })?;
    if call_sequence >= approval_event_sequence {
        return Err(StorageError::InvalidDispatchTransition(
            "dispatch approval must follow its durable requested tool call".into(),
        ));
    }
    if job.tool_name != call.tool
        || job.tool_version != call.tool_version
        || job.effect != call.effect
        || job.args_json != call.arguments
        || job.args_digest != call.arguments_digest
        || job.sandbox_profile != call.sandbox_profile
    {
        return Err(StorageError::InvalidDispatchTransition(
            "dispatch must exactly match its durable requested tool call".into(),
        ));
    }
    Ok(())
}

fn validate_new_dispatch_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), StorageError> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > max_bytes
        || value.chars().any(char::is_control)
    {
        return Err(StorageError::InvalidDispatchTransition(format!(
            "{field} must be canonical, control-free, and at most {max_bytes} UTF-8 bytes"
        )));
    }
    Ok(())
}

fn validate_new_dispatch_id_component(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), StorageError> {
    validate_new_dispatch_text(value, field, max_bytes)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(StorageError::InvalidDispatchTransition(format!(
            "{field} contains unsupported characters"
        )));
    }
    Ok(())
}

fn validate_new_dispatch_tool_name(value: &str) -> Result<(), StorageError> {
    validate_new_dispatch_text(value, "tool name", DISPATCH_TOOL_NAME_MAX_BYTES)?;
    if value.starts_with('.')
        || value.ends_with('.')
        || value.split('.').any(str::is_empty)
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(StorageError::InvalidDispatchTransition(
            "tool name must use lowercase ASCII segments separated by dots".into(),
        ));
    }
    Ok(())
}

fn validate_sha256_digest(value: &str) -> Result<(), StorageError> {
    let valid = value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    });
    if !valid {
        return Err(StorageError::InvalidDispatchTransition(
            "argument digest must be canonical lowercase SHA-256".into(),
        ));
    }
    Ok(())
}

fn validate_canonical_dispatch_start(
    connection: &Connection,
    job: &DispatchJob,
    commit: &DispatchStartCommit,
) -> Result<(), StorageError> {
    let current = canonical_dispatch_context(connection, job, commit.expected_sequence)?;
    let executor = match commit.event.data.as_ref() {
        Some(RunEventData::ToolDispatchStarted { executor, .. }) => executor,
        _ => {
            return Err(StorageError::InvalidDispatchTransition(
                "dispatch start event is missing typed executor data".into(),
            ));
        }
    };
    validate_dispatch_timestamp(&commit.event.at)?;
    let transition = kernel::start_tool_dispatch(
        &current.snapshot.run,
        &current.approval,
        &current.call,
        executor.clone(),
        commit.event.sequence,
        commit.event.at.clone(),
    )
    .map_err(|_| {
        StorageError::InvalidDispatchTransition(
            "dispatch start does not satisfy the canonical kernel transition".into(),
        )
    })?;
    let mut expected_snapshot = current.snapshot;
    expected_snapshot.run = transition.run;
    if commit.snapshot != expected_snapshot || commit.event != transition.event {
        return Err(StorageError::InvalidDispatchTransition(
            "dispatch start projection and event must equal the canonical transition".into(),
        ));
    }
    Ok(())
}

fn validate_canonical_dispatch_completion(
    connection: &Connection,
    job: &DispatchJob,
    commit: &DispatchCompleteCommit,
) -> Result<(), StorageError> {
    let current = canonical_dispatch_context(connection, job, commit.expected_sequence)?;
    let outcome: ToolOutcome =
        serde_json::from_value(commit.result_json.clone()).map_err(|_| {
            StorageError::InvalidDispatchTransition(
                "dispatch result JSON must contain a typed tool outcome".into(),
            )
        })?;
    outcome.validate_resource_envelope().map_err(|error| {
        StorageError::InvalidDispatchTransition(format!(
            "dispatch result exceeds the durable resource envelope: {error}"
        ))
    })?;
    validate_dispatch_timestamp(&commit.event.at)?;
    let transition = kernel::apply_tool_result(
        &current.snapshot.run,
        &current.call,
        outcome,
        commit.event.sequence,
        commit.event.at.clone(),
    )
    .map_err(|_| {
        StorageError::InvalidDispatchTransition(
            "dispatch result does not satisfy the canonical kernel transition".into(),
        )
    })?;
    let mut expected_snapshot = current.snapshot;
    expected_snapshot.run = transition.run;
    if commit.snapshot != expected_snapshot || commit.event != transition.event {
        return Err(StorageError::InvalidDispatchTransition(
            "dispatch result projection and event must equal the canonical transition".into(),
        ));
    }
    Ok(())
}

struct CanonicalDispatchContext {
    snapshot: RunSnapshot,
    approval: protocol::Approval,
    call: protocol::ToolCall,
}

fn canonical_dispatch_context(
    connection: &Connection,
    job: &DispatchJob,
    expected_sequence: u64,
) -> Result<CanonicalDispatchContext, StorageError> {
    let snapshot = query_snapshot(connection, &job.run_id)?;
    validate_run_event_tail(connection, &snapshot)?;
    if snapshot.run.sequence != expected_sequence {
        return Err(StorageError::ConcurrentModification);
    }
    let approval_event = query_run_event_at(
        connection,
        &job.run_id,
        u64_to_i64(job.approval_event_sequence, "approval event sequence")?,
    )?;
    validate_dispatch_approval_event(&approval_event, &job.approval_id, &job.call_id)?;
    let (_, call) =
        query_requested_call(connection, &job.run_id, &job.call_id)?.ok_or_else(|| {
            StorageError::CorruptData("dispatch job has no requested-call event".into())
        })?;
    validate_dispatch_job_binding(job, &snapshot, &approval_event, &call)?;
    let approval = approval_event.approval.ok_or_else(|| {
        StorageError::CorruptData("dispatch approval event lost its approval binding".into())
    })?;
    Ok(CanonicalDispatchContext {
        snapshot,
        approval,
        call,
    })
}

fn validate_dispatch_timestamp(value: &str) -> Result<(), StorageError> {
    if value.len() > 64
        || value.trim() != value
        || chrono::DateTime::parse_from_rfc3339(value).is_err()
    {
        return Err(StorageError::InvalidDispatchTransition(
            "dispatch event timestamp must be bounded RFC 3339".into(),
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
    let parsed = chrono::DateTime::parse_from_rfc3339(value).map_err(|_| {
        StorageError::InvalidAccountData(format!("{field} must be an RFC 3339 timestamp"))
    })?;
    let canonical = parsed
        .with_timezone(&Utc)
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    if value != canonical {
        return Err(StorageError::InvalidAccountData(format!(
            "{field} must use canonical UTC millisecond form"
        )));
    }
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

fn validated_read_page_limit(limit: usize, max: usize) -> Result<i64, StorageError> {
    if limit == 0 || limit > max {
        return Err(StorageError::InvalidPageLimit { limit, max });
    }
    i64::try_from(limit + 1).map_err(|_| StorageError::IntegerOutOfRange("read page limit"))
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
    account_id: String,
    actor_user_id: String,
    actor_membership_revision: i64,
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
            account_id: decode_account_id(self.account_id)?,
            actor_user_id: self.actor_user_id,
            actor_membership_revision: decode_membership_revision(self.actor_membership_revision)?,
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
    account_id: String,
    run_id: String,
    approval_id: String,
    approval_event_sequence: i64,
    initiating_actor_user_id: Option<String>,
    initiating_membership_revision: Option<i64>,
    approving_actor_user_id: Option<String>,
    approving_membership_revision: Option<i64>,
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
            account_id: decode_account_id(self.account_id)?,
            run_id: self.run_id,
            approval_id: self.approval_id,
            approval_event_sequence: i64_to_u64(
                self.approval_event_sequence,
                "approval event sequence",
            )?,
            initiating_actor_user_id: self.initiating_actor_user_id,
            initiating_membership_revision: self
                .initiating_membership_revision
                .map(decode_membership_revision)
                .transpose()?,
            approving_actor_user_id: self.approving_actor_user_id,
            approving_membership_revision: self
                .approving_membership_revision
                .map(decode_membership_revision)
                .transpose()?,
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
