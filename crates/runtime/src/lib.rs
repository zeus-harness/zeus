//! Durable runtime orchestration for the Zeus Alpha vertical slice.
//!
//! The runtime keeps policy, persistence, and execution as separate gates:
//! approval and enqueue commit atomically; a durable dispatch checkpoint is
//! committed before an executor can observe a request; and a started call
//! without a durable result becomes outcome_unknown on restart instead of
//! being retried.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use authz::{PolicyBuildError, PolicyContext, PolicyEngine, PolicyRule};
use chrono::{SecondsFormat, Utc};
use connectors::{ConnectorConfigError, LOCAL_DEV_ENVIRONMENT, register_local_dev_connectors};
use kernel::{
    DemoScenario, KernelError, LOCAL_POLICY_REVISION, PRODUCTION_POLICY_REVISION, apply_review,
    apply_tool_result, start_tool_dispatch,
};
use protocol::{
    Approval, ApprovalStatus, AttachRunRequest, AttachRunResponse, CreateSessionRequest,
    CreateSessionResponse, EVENT_PAGE_DEFAULT_LIMIT, FlushSessionRequest, FlushSessionResponse,
    NotDispatchedReason, OverviewResponse, PolicyDecision, ResourceEnvelopeError,
    ResumeSessionRequest, ResumeSessionResponse, ReviewDecision, ReviewRequest, ReviewResponse,
    RunDetail, RunDetailPagination, RunEvent, RunEventData, RunEventPage, RunSummary,
    SessionDetail, SessionEvent, SessionEventData, SessionEventPage, SessionSummary, SessionTurn,
    StartTurnRequest, StartTurnResponse, ToolCall, ToolExecutorStatus, ToolOutcome,
};
pub use storage::{
    AuthPrincipal, AuthSessionCommit, BootstrapOwnerCommit, ReplyClaimOutcome, ReplyCompletion,
    ReplyFailureCommit, ReplyJob, ReplyJobEnqueueResponse, ReplyJobSpec, ReplyJobStatus,
    ReplyOutcomeUnknownCommit, ReplySuccessCommit, SessionSummaryPage, StorageLimits,
    StorageLimitsError, StoredCredential, StoredPreferences, StoredUser, StoredUserRole,
    StoredUserStatus,
};
use storage::{
    ClaimOutcome, CommitOutcome, DispatchCompleteCommit, DispatchContext, DispatchJob,
    DispatchJobSpec, DispatchRecoveryCommit, DispatchStartCommit, ReviewCommit, ReviewContext,
    ReviewReceipt, RunSnapshot, RuntimeIdentity, SqliteStore, StorageError,
};
use thiserror::Error;
use tokio::sync::{Mutex, broadcast};
use tools::{ExecutorError, RegistryError, ToolRegistry, arguments_digest};

const PRODUCTION_POLICY_ID: &str = "production-guarded";
const LOCAL_POLICY_ID: &str = "local-development";

/// Selects both the demo fixture and the only tool capability available to it.
///
/// ProductionGuarded intentionally registers no production executor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DemoProfile {
    ProductionGuarded,
    LocalDevelopment { marker_root: PathBuf },
}

#[derive(Clone)]
pub struct DemoStore {
    storage: SqliteStore,
    publisher: broadcast::Sender<PublishedEvent>,
    session_publisher: broadcast::Sender<PublishedSessionEvent>,
    policy: Arc<PolicyEngine>,
    registry: Arc<ToolRegistry>,
    policy_id: Arc<str>,
    policy_revision: Arc<str>,
    primary_session_id: Arc<str>,
    primary_run_id: Arc<str>,
    dispatcher: Arc<Mutex<()>>,
    auto_dispatch: bool,
}

#[derive(Clone, Debug)]
pub struct PublishedEvent {
    pub run_id: String,
    pub event: RunEvent,
}

pub struct EventFeed {
    pub replay: Vec<RunEvent>,
    pub receiver: broadcast::Receiver<PublishedEvent>,
}

pub struct EventPageFeed {
    pub replay: RunEventPage,
    pub receiver: broadcast::Receiver<PublishedEvent>,
}

#[derive(Clone, Debug)]
pub struct PublishedSessionEvent {
    pub session_id: String,
    pub event: SessionEvent,
}

pub struct SessionEventFeed {
    pub replay: Vec<SessionEvent>,
    pub receiver: broadcast::Receiver<PublishedSessionEvent>,
}

pub struct SessionEventPageFeed {
    pub replay: SessionEventPage,
    pub receiver: broadcast::Receiver<PublishedSessionEvent>,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("run {0} was not found")]
    RunNotFound(String),
    #[error("session {0} was not found")]
    SessionNotFound(String),
    #[error("session turn {0} was not found")]
    SessionTurnNotFound(String),
    #[error("session {0} already exists")]
    SessionAlreadyExists(String),
    #[error("the local owner account is already configured")]
    AccountAlreadyConfigured,
    #[error("the bootstrap credential is invalid, expired, or already used")]
    InvalidBootstrapToken,
    #[error("user {0} was not found")]
    UserNotFound(String),
    #[error("user {0} is disabled")]
    UserDisabled(String),
    #[error("the durable storage quota is exhausted")]
    StorageQuotaExceeded,
    #[error("the durable reply queue is at capacity")]
    ReplyQueueCapacityExceeded,
    #[error("the durable dispatch queue is at capacity")]
    DispatchQueueCapacityExceeded,
    #[error("the authentication session store is at capacity")]
    AuthSessionCapacityExceeded,
    #[error("durable finalization capacity is unavailable")]
    FinalizationReservationUnavailable,
    #[error("invalid account data: {0}")]
    InvalidAccountData(String),
    #[error("run {run_id} already belongs to session {session_id}")]
    RunAlreadyAttached { run_id: String, session_id: String },
    #[error("invalid session request: {0}")]
    InvalidSessionRequest(String),
    #[error("invalid session state transition: {0}")]
    InvalidSessionTransition(String),
    #[error("approval {approval_id} was not found or is no longer pending for run {run_id}")]
    ApprovalNotPending { run_id: String, approval_id: String },
    #[error("the approval has no matching persisted tool call")]
    ToolCallNotFound,
    #[error("the policy no longer authorizes this exact approval: {0}")]
    PolicyChanged(String),
    #[error("the current policy denies this tool call: {0}")]
    PolicyDenied(String),
    #[error("stored execution data is inconsistent: {0}")]
    ExecutionInvariant(String),
    #[error("the idempotency key is empty")]
    EmptyIdempotencyKey,
    #[error("the idempotency key was already used with different command input")]
    IdempotencyConflict,
    #[error("the durable projection changed concurrently while committing the command")]
    ConcurrentModification,
    #[error("the run sequence cannot advance any further")]
    SequenceOverflow,
    #[error("event cursor {after} cannot be represented by SQLite")]
    EventCursorOutOfRange { after: u64 },
    #[error("event cursor {after} is ahead of durable ledger head {head_sequence}")]
    EventCursorBeyondHead { after: u64, head_sequence: u64 },
    #[error("read page limit {limit} is invalid; expected 1..={max}")]
    InvalidPageLimit { limit: usize, max: usize },
    #[error("read page cursor is invalid")]
    InvalidPageCursor,
    #[error("read page cursor is ahead of the durable collection head {head}")]
    PageCursorBeyondHead { head: u64 },
    #[error(transparent)]
    Kernel(#[from] KernelError),
    #[error(transparent)]
    PolicyBuild(#[from] PolicyBuildError),
    #[error(transparent)]
    ConnectorConfig(#[from] ConnectorConfigError),
    #[error(transparent)]
    Registry(#[from] RegistryError),
    #[error("storage error: {0}")]
    Storage(StorageError),
}

impl From<StorageError> for StoreError {
    fn from(error: StorageError) -> Self {
        match error {
            StorageError::RunNotFound(id) => Self::RunNotFound(id),
            StorageError::SessionNotFound(id) => Self::SessionNotFound(id),
            StorageError::SessionTurnNotFound(id) => Self::SessionTurnNotFound(id),
            StorageError::SessionAlreadyExists(id) => Self::SessionAlreadyExists(id),
            StorageError::AccountAlreadyConfigured => Self::AccountAlreadyConfigured,
            StorageError::InvalidBootstrapToken => Self::InvalidBootstrapToken,
            StorageError::UserNotFound(id) => Self::UserNotFound(id),
            StorageError::UserDisabled(id) => Self::UserDisabled(id),
            StorageError::StorageQuotaExceeded => Self::StorageQuotaExceeded,
            StorageError::ReplyQueueCapacityExceeded => Self::ReplyQueueCapacityExceeded,
            StorageError::DispatchQueueCapacityExceeded => Self::DispatchQueueCapacityExceeded,
            StorageError::AuthSessionCapacityExceeded => Self::AuthSessionCapacityExceeded,
            StorageError::FinalizationReservationUnavailable => {
                Self::FinalizationReservationUnavailable
            }
            StorageError::InvalidAccountData(detail) => Self::InvalidAccountData(detail),
            StorageError::RunAlreadyAttached { run_id, session_id } => {
                Self::RunAlreadyAttached { run_id, session_id }
            }
            StorageError::InvalidSessionTransition(detail) => {
                Self::InvalidSessionTransition(detail)
            }
            StorageError::InvalidResourceEnvelope(detail) => Self::InvalidSessionRequest(detail),
            StorageError::EmptyIdempotencyKey => Self::EmptyIdempotencyKey,
            StorageError::IdempotencyConflict => Self::IdempotencyConflict,
            StorageError::ConcurrentModification => Self::ConcurrentModification,
            StorageError::EventCursorOutOfRange { after } => Self::EventCursorOutOfRange { after },
            StorageError::EventCursorBeyondHead {
                after,
                head_sequence,
            } => Self::EventCursorBeyondHead {
                after,
                head_sequence,
            },
            StorageError::InvalidPageLimit { limit, max } => Self::InvalidPageLimit { limit, max },
            StorageError::InvalidPageCursor => Self::InvalidPageCursor,
            StorageError::PageCursorBeyondHead { head } => Self::PageCursorBeyondHead { head },
            other => Self::Storage(other),
        }
    }
}

impl DemoStore {
    /// Opens the fail-closed production demonstration.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_with_profile(path, DemoProfile::ProductionGuarded).await
    }

    pub async fn open_with_limits(
        path: impl AsRef<Path>,
        limits: StorageLimits,
    ) -> Result<Self, StoreError> {
        Self::open_with_profile_and_limits(path, DemoProfile::ProductionGuarded, limits).await
    }

    /// Opens an explicit local-development demonstration with one fixed marker
    /// root and no production connector.
    pub async fn open_local(
        path: impl AsRef<Path>,
        marker_root: impl Into<PathBuf>,
    ) -> Result<Self, StoreError> {
        Self::open_with_profile(
            path,
            DemoProfile::LocalDevelopment {
                marker_root: marker_root.into(),
            },
        )
        .await
    }

    pub async fn open_local_with_limits(
        path: impl AsRef<Path>,
        marker_root: impl Into<PathBuf>,
        limits: StorageLimits,
    ) -> Result<Self, StoreError> {
        Self::open_with_profile_and_limits(
            path,
            DemoProfile::LocalDevelopment {
                marker_root: marker_root.into(),
            },
            limits,
        )
        .await
    }

    pub async fn open_with_profile(
        path: impl AsRef<Path>,
        profile: DemoProfile,
    ) -> Result<Self, StoreError> {
        Self::open_with_profile_and_limits(path, profile, StorageLimits::default()).await
    }

    pub async fn open_with_profile_and_limits(
        path: impl AsRef<Path>,
        profile: DemoProfile,
        limits: StorageLimits,
    ) -> Result<Self, StoreError> {
        let storage = SqliteStore::open_with_limits(path, limits).await?;
        Self::from_storage(storage, profile, true).await
    }

    /// Creates an isolated production-profile store for tests.
    pub async fn seeded() -> Result<Self, StoreError> {
        Self::open(":memory:").await
    }

    async fn from_storage(
        storage: SqliteStore,
        profile: DemoProfile,
        auto_dispatch: bool,
    ) -> Result<Self, StoreError> {
        let components = RuntimeComponents::build(profile)?;
        let primary_session_id = components.primary_session_id;
        let primary_run_id = components.scenario.run.id.clone();
        storage
            .bind_runtime_identity(RuntimeIdentity {
                profile: components.profile_id.into(),
                environment: components.scenario.run.environment.clone(),
                primary_session_id: primary_session_id.into(),
                primary_run_id: primary_run_id.clone(),
                policy_id: components.policy_id.into(),
                policy_revision: components.policy_revision.into(),
            })
            .await?;
        storage
            .seed_if_empty(
                snapshot_from_scenario(&components.scenario),
                components.scenario.events.clone(),
            )
            .await?;
        storage
            .seed_demo_session(
                primary_session_id,
                &components.scenario.incident.title,
                &primary_run_id,
            )
            .await?;

        // A database created for another profile must fail visibly instead of
        // silently serving or executing a different run or session attachment.
        storage.snapshot(&primary_run_id).await?;
        if !storage
            .session_has_run(primary_session_id, &primary_run_id)
            .await?
        {
            return Err(StoreError::ExecutionInvariant(
                "the primary session is not attached to the primary run".into(),
            ));
        }

        let (publisher, _) = broadcast::channel(128);
        let (session_publisher, _) = broadcast::channel(128);
        let store = Self {
            storage,
            publisher,
            session_publisher,
            policy: Arc::new(components.policy),
            registry: Arc::new(components.registry),
            policy_id: Arc::from(components.policy_id),
            policy_revision: Arc::from(components.policy_revision),
            primary_session_id: Arc::from(primary_session_id),
            primary_run_id: Arc::from(primary_run_id),
            dispatcher: Arc::new(Mutex::new(())),
            auto_dispatch,
        };

        // A claimed reply is a potentially billable external operation, so a
        // missing result becomes outcome_unknown before generic turn recovery.
        // Queued reply turns are deliberately left open and claimable.
        store.recover_started_reply_jobs().await?;

        // Session recovery precedes run-dispatch recovery. Started calls are
        // settled next and never re-executed. Only then are queued calls safe
        // to resume because they have no dispatch checkpoint yet.
        store.recover_open_session_turns().await?;
        store.recover_started_dispatches().await?;
        if auto_dispatch {
            store.dispatch_pending().await?;
        }
        Ok(store)
    }

    pub async fn readiness(&self) -> Result<(), StoreError> {
        self.storage.readiness().await?;
        Ok(())
    }

    pub async fn has_users(&self) -> Result<bool, StoreError> {
        Ok(self.storage.has_users().await?)
    }

    pub async fn replace_bootstrap_token(
        &self,
        token_hash: &str,
        expires_at: &str,
    ) -> Result<(), StoreError> {
        Ok(self
            .storage
            .replace_bootstrap_token(token_hash, expires_at)
            .await?)
    }

    pub async fn bootstrap_owner(
        &self,
        commit: BootstrapOwnerCommit,
    ) -> Result<(StoredUser, StoredPreferences), StoreError> {
        Ok(self.storage.bootstrap_owner(commit).await?)
    }

    pub async fn credential_for_username(
        &self,
        username: &str,
    ) -> Result<Option<StoredCredential>, StoreError> {
        Ok(self.storage.credential_for_username(username).await?)
    }

    pub async fn create_auth_session(
        &self,
        commit: AuthSessionCommit,
    ) -> Result<AuthPrincipal, StoreError> {
        Ok(self.storage.create_auth_session(commit).await?)
    }

    pub async fn authenticate(
        &self,
        session_token_hash: &str,
    ) -> Result<Option<AuthPrincipal>, StoreError> {
        Ok(self.storage.authenticate(session_token_hash).await?)
    }

    pub async fn revoke_auth_session(&self, session_token_hash: &str) -> Result<bool, StoreError> {
        Ok(self.storage.revoke_auth_session(session_token_hash).await?)
    }

    pub async fn preferences(&self, user_id: &str) -> Result<StoredPreferences, StoreError> {
        Ok(self.storage.preferences(user_id).await?)
    }

    pub async fn update_preferences(
        &self,
        user_id: &str,
        expected_revision: u64,
        theme: &str,
        preferred_model: Option<&str>,
    ) -> Result<StoredPreferences, StoreError> {
        Ok(self
            .storage
            .update_preferences(user_id, expected_revision, theme, preferred_model)
            .await?)
    }

    pub async fn overview(&self) -> Result<OverviewResponse, StoreError> {
        let stored = self.storage.load_run(&self.primary_run_id).await?;
        Ok(OverviewResponse {
            primary_session_id: self.primary_session_id.to_string(),
            incident: stored.snapshot.incident,
            run: stored.snapshot.run,
            metrics: stored.snapshot.metrics,
            recent_events: stored.events,
            evidence: stored.snapshot.evidence,
            tool_policy: stored.snapshot.tool_policy,
            recent_events_page: None,
        })
    }

    /// Returns the primary workspace only when the actor is still an active
    /// owner of its primary Run. The storage predicate intentionally maps a
    /// missing, unowned, disabled, or non-owner actor to the same not-found
    /// result.
    pub async fn overview_for_actor(
        &self,
        actor_user_id: &str,
    ) -> Result<OverviewResponse, StoreError> {
        let stored = self
            .storage
            .bounded_run_for_actor(
                actor_user_id,
                &self.primary_run_id,
                None,
                EVENT_PAGE_DEFAULT_LIMIT,
            )
            .await?;
        Ok(OverviewResponse {
            primary_session_id: self.primary_session_id.to_string(),
            incident: stored.snapshot.incident,
            run: stored.snapshot.run,
            metrics: stored.snapshot.metrics,
            recent_events: stored.events,
            evidence: stored.snapshot.evidence,
            tool_policy: stored.snapshot.tool_policy,
            recent_events_page: Some(stored.events_page),
        })
    }

    pub async fn run_detail(&self, run_id: &str) -> Result<RunDetail, StoreError> {
        validate_durable_reference(run_id, "run ID")?;
        let stored = self.storage.load_run(run_id).await?;
        Ok(RunDetail {
            incident: stored.snapshot.incident,
            run: stored.snapshot.run,
            events: stored.events,
            pagination: None,
        })
    }

    pub async fn run_detail_for_actor(
        &self,
        actor_user_id: &str,
        run_id: &str,
        events_before: Option<&str>,
        events_limit: usize,
    ) -> Result<RunDetail, StoreError> {
        validate_durable_reference(run_id, "run ID")?;
        let stored = self
            .storage
            .bounded_run_for_actor(actor_user_id, run_id, events_before, events_limit)
            .await?;
        Ok(RunDetail {
            incident: stored.snapshot.incident,
            run: stored.snapshot.run,
            events: stored.events,
            pagination: Some(RunDetailPagination {
                events: stored.events_page,
            }),
        })
    }

    pub async fn events_after(
        &self,
        run_id: &str,
        after: u64,
    ) -> Result<Vec<RunEvent>, StoreError> {
        validate_durable_reference(run_id, "run ID")?;
        Ok(self.storage.events_after(run_id, after).await?)
    }

    pub async fn events_after_for_actor(
        &self,
        actor_user_id: &str,
        run_id: &str,
        after: u64,
    ) -> Result<Vec<RunEvent>, StoreError> {
        validate_durable_reference(run_id, "run ID")?;
        Ok(self
            .storage
            .events_after_for_actor(actor_user_id, run_id, after)
            .await?)
    }

    pub async fn run_event_page(
        &self,
        run_id: &str,
        after: u64,
        limit: usize,
    ) -> Result<RunEventPage, StoreError> {
        validate_durable_reference(run_id, "run ID")?;
        Ok(self.storage.run_event_page(run_id, after, limit).await?)
    }

    pub async fn run_event_page_for_actor(
        &self,
        actor_user_id: &str,
        run_id: &str,
        after: u64,
        limit: usize,
    ) -> Result<RunEventPage, StoreError> {
        validate_durable_reference(run_id, "run ID")?;
        Ok(self
            .storage
            .run_event_page_for_actor(actor_user_id, run_id, after, limit)
            .await?)
    }

    /// Subscribes before taking the durable replay snapshot. Consumers discard
    /// broadcasts at or below their cursor, avoiding both gaps and duplicates.
    pub async fn event_feed(&self, run_id: &str, after: u64) -> Result<EventFeed, StoreError> {
        let receiver = self.publisher.subscribe();
        let replay = self.events_after(run_id, after).await?;
        Ok(EventFeed { replay, receiver })
    }

    /// Subscribes before the actor-scoped durable snapshot so a commit cannot
    /// fall between authorization/replay and the live wake channel.
    pub async fn event_feed_for_actor(
        &self,
        actor_user_id: &str,
        run_id: &str,
        after: u64,
    ) -> Result<EventFeed, StoreError> {
        let receiver = self.publisher.subscribe();
        let replay = self
            .events_after_for_actor(actor_user_id, run_id, after)
            .await?;
        Ok(EventFeed { replay, receiver })
    }

    /// Subscribes before loading a bounded durable page so consumers cannot
    /// miss a commit between the replay snapshot and the live wake channel.
    pub async fn event_page_feed_for_actor(
        &self,
        actor_user_id: &str,
        run_id: &str,
        after: u64,
        limit: usize,
    ) -> Result<EventPageFeed, StoreError> {
        let receiver = self.publisher.subscribe();
        let replay = self
            .run_event_page_for_actor(actor_user_id, run_id, after, limit)
            .await?;
        Ok(EventPageFeed { replay, receiver })
    }

    pub async fn list_sessions(&self) -> Result<Vec<SessionSummary>, StoreError> {
        Ok(self.storage.list_sessions().await?)
    }

    pub async fn list_sessions_for_actor(
        &self,
        actor_user_id: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<SessionSummaryPage, StoreError> {
        Ok(self
            .storage
            .session_summary_page_for_actor(actor_user_id, cursor, limit)
            .await?)
    }

    pub async fn get_session(&self, session_id: &str) -> Result<SessionDetail, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        Ok(self.storage.get_session(session_id).await?)
    }

    pub async fn session_summary(&self, session_id: &str) -> Result<SessionSummary, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        Ok(self.storage.session_summary(session_id).await?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn get_session_for_actor(
        &self,
        actor_user_id: &str,
        session_id: &str,
        run_ids_before: Option<&str>,
        run_ids_limit: usize,
        turns_before: Option<&str>,
        turns_limit: usize,
        events_before: Option<&str>,
        events_limit: usize,
    ) -> Result<SessionDetail, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        Ok(self
            .storage
            .session_detail_page_for_actor(
                actor_user_id,
                session_id,
                run_ids_before,
                run_ids_limit,
                turns_before,
                turns_limit,
                events_before,
                events_limit,
            )
            .await?)
    }

    pub async fn session_turn_for_actor(
        &self,
        actor_user_id: &str,
        session_id: &str,
        turn_id: &str,
    ) -> Result<SessionTurn, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        Ok(self
            .storage
            .session_turn_for_actor(actor_user_id, session_id, turn_id)
            .await?)
    }

    pub async fn session_events_after(
        &self,
        session_id: &str,
        after: u64,
    ) -> Result<Vec<SessionEvent>, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        validate_session_sequence(after, "session event cursor")?;
        Ok(self.storage.session_events_after(session_id, after).await?)
    }

    pub async fn session_events_after_for_actor(
        &self,
        actor_user_id: &str,
        session_id: &str,
        after: u64,
    ) -> Result<Vec<SessionEvent>, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        validate_session_sequence(after, "session event cursor")?;
        Ok(self
            .storage
            .session_events_after_for_actor(actor_user_id, session_id, after)
            .await?)
    }

    pub async fn session_event_page(
        &self,
        session_id: &str,
        after: u64,
        limit: usize,
    ) -> Result<SessionEventPage, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        Ok(self
            .storage
            .session_event_page(session_id, after, limit)
            .await?)
    }

    pub async fn session_event_page_for_actor(
        &self,
        actor_user_id: &str,
        session_id: &str,
        after: u64,
        limit: usize,
    ) -> Result<SessionEventPage, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        Ok(self
            .storage
            .session_event_page_for_actor(actor_user_id, session_id, after, limit)
            .await?)
    }

    /// Subscribes to the session channel before loading the durable replay.
    /// The session channel is intentionally independent from run dispatch and
    /// its event ledger. Receiver items are post-commit wake hints, not an
    /// ordered source of truth: concurrent publishers may send out of order,
    /// so consumers must reconcile from `session_events_after` before moving
    /// their durable cursor.
    pub async fn session_event_feed(
        &self,
        session_id: &str,
        after: u64,
    ) -> Result<SessionEventFeed, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        let receiver = self.session_publisher.subscribe();
        let replay = self.session_events_after(session_id, after).await?;
        Ok(SessionEventFeed { replay, receiver })
    }

    /// Actor-scoped counterpart used by authenticated SSE. Subscription still
    /// precedes the durable query, while storage performs the owner check in
    /// the same read transaction that builds the replay.
    pub async fn session_event_feed_for_actor(
        &self,
        actor_user_id: &str,
        session_id: &str,
        after: u64,
    ) -> Result<SessionEventFeed, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        let receiver = self.session_publisher.subscribe();
        let replay = self
            .session_events_after_for_actor(actor_user_id, session_id, after)
            .await?;
        Ok(SessionEventFeed { replay, receiver })
    }

    /// Actor-scoped bounded counterpart for authenticated SSE. Subscription
    /// precedes the storage transaction that authorizes and builds the page.
    pub async fn session_event_page_feed_for_actor(
        &self,
        actor_user_id: &str,
        session_id: &str,
        after: u64,
        limit: usize,
    ) -> Result<SessionEventPageFeed, StoreError> {
        let receiver = self.session_publisher.subscribe();
        let replay = self
            .session_event_page_for_actor(actor_user_id, session_id, after, limit)
            .await?;
        Ok(SessionEventPageFeed { replay, receiver })
    }

    pub async fn create_session(
        &self,
        request: CreateSessionRequest,
        idempotency_key: &str,
    ) -> Result<CreateSessionResponse, StoreError> {
        validate_new_session_id(&request.id, "session ID")?;
        validate_new_session_title(&request.title, "session title")?;
        let idempotency_key = normalized_idempotency_key(idempotency_key)?;
        let response = self
            .storage
            .create_session(request, idempotency_key)
            .await?;
        if !response.replayed {
            self.publish_session_event(&response.session.id, response.event.clone());
        }
        Ok(response)
    }

    pub async fn create_session_for_actor(
        &self,
        actor_user_id: &str,
        request: CreateSessionRequest,
        idempotency_key: &str,
    ) -> Result<CreateSessionResponse, StoreError> {
        validate_new_session_id(&request.id, "session ID")?;
        validate_new_session_title(&request.title, "session title")?;
        let idempotency_key = normalized_idempotency_key(idempotency_key)?;
        let response = self
            .storage
            .create_session_for_actor(actor_user_id, request, idempotency_key)
            .await?;
        if !response.replayed {
            self.publish_session_event(&response.session.id, response.event.clone());
        }
        Ok(response)
    }

    pub async fn attach_run_for_actor(
        &self,
        actor_user_id: &str,
        session_id: &str,
        request: AttachRunRequest,
        idempotency_key: &str,
    ) -> Result<AttachRunResponse, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        validate_durable_reference(&request.run_id, "run ID")?;
        validate_session_sequence(request.expected_sequence, "expected session sequence")?;
        let idempotency_key = normalized_idempotency_key(idempotency_key)?;
        let response = self
            .storage
            .attach_run_for_actor(actor_user_id, session_id, request, idempotency_key)
            .await?;
        if !response.replayed {
            self.publish_session_event(session_id, response.event.clone());
        }
        Ok(response)
    }

    pub async fn resume_session(
        &self,
        session_id: &str,
        request: ResumeSessionRequest,
        idempotency_key: &str,
    ) -> Result<ResumeSessionResponse, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        validate_session_sequence(request.expected_sequence, "expected session sequence")?;
        let idempotency_key = normalized_idempotency_key(idempotency_key)?;
        let response = self
            .storage
            .resume_session(session_id, request, idempotency_key)
            .await?;
        if !response.replayed {
            self.publish_session_event(session_id, response.event.clone());
        }
        Ok(response)
    }

    pub async fn resume_session_for_actor(
        &self,
        actor_user_id: &str,
        session_id: &str,
        request: ResumeSessionRequest,
        idempotency_key: &str,
    ) -> Result<ResumeSessionResponse, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        validate_session_sequence(request.expected_sequence, "expected session sequence")?;
        let idempotency_key = normalized_idempotency_key(idempotency_key)?;
        let response = self
            .storage
            .resume_session_for_actor(actor_user_id, session_id, request, idempotency_key)
            .await?;
        if !response.replayed {
            self.publish_session_event(session_id, response.event.clone());
        }
        Ok(response)
    }

    pub async fn start_turn(
        &self,
        session_id: &str,
        request: StartTurnRequest,
        idempotency_key: &str,
    ) -> Result<StartTurnResponse, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        validate_new_turn_id(&request.turn_id, "turn ID")?;
        validate_user_message_value(&request.user_message, "user message")?;
        validate_session_sequence(request.expected_sequence, "expected session sequence")?;
        let idempotency_key = normalized_idempotency_key(idempotency_key)?;
        let response = self
            .storage
            .start_turn(session_id, request, idempotency_key)
            .await?;
        if !response.replayed {
            self.publish_session_event(session_id, response.event.clone());
        }
        Ok(response)
    }

    pub async fn start_turn_for_actor(
        &self,
        actor_user_id: &str,
        session_id: &str,
        request: StartTurnRequest,
        idempotency_key: &str,
    ) -> Result<StartTurnResponse, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        validate_new_turn_id(&request.turn_id, "turn ID")?;
        validate_user_message_value(&request.user_message, "user message")?;
        validate_session_sequence(request.expected_sequence, "expected session sequence")?;
        let idempotency_key = normalized_idempotency_key(idempotency_key)?;
        let response = self
            .storage
            .start_turn_for_actor(actor_user_id, session_id, request, idempotency_key)
            .await?;
        if !response.replayed {
            self.publish_session_event(session_id, response.event.clone());
        }
        Ok(response)
    }

    pub async fn start_turn_and_enqueue_reply(
        &self,
        session_id: &str,
        request: StartTurnRequest,
        idempotency_key: &str,
        job: ReplyJobSpec,
    ) -> Result<ReplyJobEnqueueResponse, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        validate_new_turn_id(&request.turn_id, "turn ID")?;
        validate_user_message_value(&request.user_message, "user message")?;
        validate_session_sequence(request.expected_sequence, "expected session sequence")?;
        let idempotency_key = normalized_idempotency_key(idempotency_key)?;
        let response = self
            .storage
            .start_turn_and_enqueue_reply(session_id, request, idempotency_key, job)
            .await?;
        if !response.start.replayed {
            self.publish_session_event(session_id, response.start.event.clone());
        }
        Ok(response)
    }

    pub async fn start_turn_and_enqueue_reply_for_actor(
        &self,
        actor_user_id: &str,
        session_id: &str,
        request: StartTurnRequest,
        idempotency_key: &str,
        job: ReplyJobSpec,
    ) -> Result<ReplyJobEnqueueResponse, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        validate_new_turn_id(&request.turn_id, "turn ID")?;
        validate_user_message_value(&request.user_message, "user message")?;
        validate_session_sequence(request.expected_sequence, "expected session sequence")?;
        let idempotency_key = normalized_idempotency_key(idempotency_key)?;
        let response = self
            .storage
            .start_turn_and_enqueue_reply_for_actor(
                actor_user_id,
                session_id,
                request,
                idempotency_key,
                job,
            )
            .await?;
        if !response.start.replayed {
            self.publish_session_event(session_id, response.start.event.clone());
        }
        Ok(response)
    }

    pub async fn claim_next_reply(&self) -> Result<ReplyClaimOutcome, StoreError> {
        loop {
            match self.storage.claim_next_reply().await? {
                ReplyClaimOutcome::Rejected(completion) => {
                    // Storage committed the terminal failure before returning.
                    // Publish only as a post-commit wake hint and continue to
                    // the next queue item without exposing rejected work to a
                    // provider caller.
                    for event in &completion.events {
                        self.publish_session_event(&completion.session.id, event.clone());
                    }
                }
                outcome => return Ok(outcome),
            }
        }
    }

    pub async fn reply_job(&self, job_id: &str) -> Result<Option<ReplyJob>, StoreError> {
        Ok(self.storage.reply_job(job_id).await?)
    }

    pub async fn complete_reply_success(
        &self,
        commit: ReplySuccessCommit,
    ) -> Result<ReplyCompletion, StoreError> {
        let completion = self.storage.complete_reply_success(commit).await?;
        if !completion.replayed {
            for event in &completion.events {
                self.publish_session_event(&completion.session.id, event.clone());
            }
        }
        Ok(completion)
    }

    pub async fn complete_reply_failure(
        &self,
        commit: ReplyFailureCommit,
    ) -> Result<ReplyCompletion, StoreError> {
        let completion = self.storage.complete_reply_failure(commit).await?;
        if !completion.replayed {
            for event in &completion.events {
                self.publish_session_event(&completion.session.id, event.clone());
            }
        }
        Ok(completion)
    }

    pub async fn complete_reply_outcome_unknown(
        &self,
        commit: ReplyOutcomeUnknownCommit,
    ) -> Result<ReplyCompletion, StoreError> {
        let completion = self.storage.complete_reply_outcome_unknown(commit).await?;
        if !completion.replayed {
            for event in &completion.events {
                self.publish_session_event(&completion.session.id, event.clone());
            }
        }
        Ok(completion)
    }

    pub async fn flush_turn(
        &self,
        session_id: &str,
        request: FlushSessionRequest,
        idempotency_key: &str,
    ) -> Result<FlushSessionResponse, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        validate_durable_reference(&request.turn_id, "turn ID")?;
        if let Some(message) = &request.assistant_message {
            validate_session_message(message, "assistant message")?;
        }
        validate_session_sequence(request.expected_sequence, "expected session sequence")?;
        let idempotency_key = normalized_idempotency_key(idempotency_key)?;
        let response = self
            .storage
            .flush_turn(session_id, request, idempotency_key)
            .await?;
        if !response.replayed {
            for event in &response.events {
                self.publish_session_event(session_id, event.clone());
            }
        }
        Ok(response)
    }

    pub async fn flush_turn_for_actor(
        &self,
        actor_user_id: &str,
        session_id: &str,
        request: FlushSessionRequest,
        idempotency_key: &str,
    ) -> Result<FlushSessionResponse, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        validate_durable_reference(&request.turn_id, "turn ID")?;
        if let Some(message) = &request.assistant_message {
            validate_session_message(message, "assistant message")?;
        }
        validate_session_sequence(request.expected_sequence, "expected session sequence")?;
        let idempotency_key = normalized_idempotency_key(idempotency_key)?;
        let response = self
            .storage
            .flush_turn_for_actor(actor_user_id, session_id, request, idempotency_key)
            .await?;
        if !response.replayed {
            for event in &response.events {
                self.publish_session_event(session_id, event.clone());
            }
        }
        Ok(response)
    }

    /// Records one call-bound approval decision. Approving only queues the
    /// exact call; it does not claim that execution has started.
    pub async fn review(
        &self,
        run_id: &str,
        approval_id: &str,
        request: ReviewRequest,
        idempotency_key: &str,
    ) -> Result<ReviewResponse, StoreError> {
        self.review_inner(None, run_id, approval_id, request, idempotency_key)
            .await
    }

    /// Actor-scoped approval boundary used by the authenticated server.
    ///
    /// Resource authorization deliberately happens before receipt lookup, so
    /// possession of another owner's idempotency key can neither replay their
    /// response nor turn an ownership miss into an idempotency conflict.
    pub async fn review_for_actor(
        &self,
        actor_user_id: &str,
        run_id: &str,
        approval_id: &str,
        request: ReviewRequest,
        idempotency_key: &str,
    ) -> Result<ReviewResponse, StoreError> {
        self.review_inner(
            Some(actor_user_id),
            run_id,
            approval_id,
            request,
            idempotency_key,
        )
        .await
    }

    async fn review_inner(
        &self,
        actor_user_id: Option<&str>,
        run_id: &str,
        approval_id: &str,
        request: ReviewRequest,
        idempotency_key: &str,
    ) -> Result<ReviewResponse, StoreError> {
        validate_durable_reference(run_id, "run ID")?;
        validate_durable_reference(approval_id, "approval ID")?;
        let idempotency_key = normalized_idempotency_key(idempotency_key)?;

        // Read the execution context before payload fingerprinting and receipt
        // lookup. Besides preserving the resource-not-found mask, this keeps a
        // pending approval visible across a same-key commit race; the final
        // write transaction can then replay the winning receipt instead of
        // incorrectly reporting that the approval is no longer pending.
        let context = if let Some(actor_user_id) = actor_user_id {
            self.storage
                .review_context_for_actor(actor_user_id, run_id, approval_id)
                .await?
        } else {
            self.storage.review_context(run_id, approval_id).await?
        };
        validate_review_request_value(&request)?;
        let fingerprint = review_fingerprint(run_id, approval_id, &request)?;

        if let Some(actor_user_id) = actor_user_id {
            if let Some(receipt) = self
                .storage
                .review_receipt_for_actor(actor_user_id, run_id, idempotency_key)
                .await?
            {
                let response = replay_receipt(receipt, &fingerprint)?;
                self.kick_dispatcher();
                return Ok(response);
            }
        } else if let Some(receipt) = self.storage.review_receipt(idempotency_key).await? {
            let response = replay_receipt(receipt, &fingerprint)?;
            self.kick_dispatcher();
            return Ok(response);
        }
        let (pending, call) = pending_approval_and_call(&context, approval_id)?;
        let approving = request.decision == ReviewDecision::Approve;
        if approving {
            self.validate_pending_policy(&context.snapshot.run, &pending, &call)?;
        }

        let expected_sequence = context.snapshot.run.sequence;
        let transition = apply_review(
            &context.snapshot.run,
            &pending,
            request.decision.clone(),
            request.note.as_deref(),
            next_sequence(expected_sequence)?,
            now(),
        )?;

        let dispatch = if approving {
            let approving_actor_user_id = actor_user_id.ok_or_else(|| {
                StoreError::ExecutionInvariant(
                    "approval execution requires an authenticated owner actor".into(),
                )
            })?;
            let approved = transition.event.approval.as_ref().ok_or_else(|| {
                StoreError::ExecutionInvariant(
                    "an approved transition is missing its approval binding".into(),
                )
            })?;
            let evaluation = self.policy.guard_dispatch(
                &context.snapshot.run.environment,
                &call,
                Some(approved),
            );
            if evaluation.decision != PolicyDecision::Allow {
                return Err(policy_guard_error(evaluation));
            }
            Some(DispatchJobSpec {
                call_id: call.call_id.clone(),
                approval_id: approved.id.clone(),
                tool_name: call.tool.clone(),
                tool_version: call.tool_version.clone(),
                effect: call.effect.clone(),
                args_json: call.arguments.clone(),
                args_digest: call.arguments_digest.clone(),
                policy_id: self.policy_id.to_string(),
                policy_revision: evaluation.policy_revision,
                sandbox_profile: call.sandbox_profile.clone(),
                approving_actor_user_id: approving_actor_user_id.to_owned(),
            })
        } else {
            None
        };

        let mut snapshot = context.snapshot;
        snapshot.run = transition.run.clone();
        clear_pending_approval_metric(&mut snapshot);
        let response = ReviewResponse {
            run: transition.run,
            event: transition.event.clone(),
            replayed: false,
        };
        let published = PublishedEvent {
            run_id: run_id.to_owned(),
            event: transition.event.clone(),
        };
        let commit = ReviewCommit {
            expected_sequence,
            snapshot,
            event: transition.event,
            idempotency_key: idempotency_key.to_owned(),
            request_fingerprint: fingerprint.clone(),
            response: response.clone(),
            dispatch,
        };
        let outcome = if let Some(actor_user_id) = actor_user_id {
            self.storage
                .commit_review_for_actor(actor_user_id, commit)
                .await?
        } else {
            self.storage.commit_review(commit).await?
        };

        match outcome {
            CommitOutcome::Committed => {
                // The database commit is the source of truth; broadcast is only
                // a low-latency hint and happens strictly after commit.
                let _ = self.publisher.send(published);
                self.kick_dispatcher();
                Ok(response)
            }
            CommitOutcome::Replayed(receipt) => {
                let response = replay_receipt(*receipt, &fingerprint)?;
                self.kick_dispatcher();
                Ok(response)
            }
        }
    }

    /// Drains durable queued work. A Tokio mutex prevents duplicate workers in
    /// one process; SQLite's queue-head transaction arbitrates across racers.
    pub async fn dispatch_pending(&self) -> Result<(), StoreError> {
        let _worker = self.dispatcher.lock().await;
        while let Some(claimed) = self.claim_next_dispatch().await? {
            let outcome = self.dispatch_outcome(&claimed).await;
            self.complete_dispatch(claimed, outcome).await?;
        }
        Ok(())
    }

    pub async fn current_run(&self) -> Result<RunSummary, StoreError> {
        Ok(self.storage.snapshot(&self.primary_run_id).await?.run)
    }

    pub async fn current_run_for_actor(
        &self,
        actor_user_id: &str,
    ) -> Result<RunSummary, StoreError> {
        Ok(self
            .storage
            .snapshot_for_actor(actor_user_id, &self.primary_run_id)
            .await?
            .run)
    }

    async fn recover_started_reply_jobs(&self) -> Result<(), StoreError> {
        loop {
            let recovered = self.storage.recover_started_replies().await?;
            if recovered.is_empty() {
                return Ok(());
            }
            for completion in recovered {
                for event in completion.events {
                    if !matches!(event.data, SessionEventData::TurnInterrupted { .. }) {
                        return Err(StoreError::ExecutionInvariant(
                            "started-reply recovery returned a non-interruption event".into(),
                        ));
                    }
                    self.publish_session_event(&completion.session.id, event);
                }
            }
        }
    }

    async fn recover_open_session_turns(&self) -> Result<(), StoreError> {
        loop {
            let recovered = self.storage.recover_open_turns().await?;
            if recovered.is_empty() {
                return Ok(());
            }
            for recovered_turn in recovered {
                if !matches!(
                    recovered_turn.event.data,
                    SessionEventData::TurnInterrupted { .. }
                ) {
                    return Err(StoreError::ExecutionInvariant(
                        "open-turn recovery returned a non-interruption session event".into(),
                    ));
                }
                self.publish_session_event(&recovered_turn.session_id, recovered_turn.event);
            }
        }
    }

    fn publish_session_event(&self, session_id: &str, event: SessionEvent) {
        let _ = self.session_publisher.send(PublishedSessionEvent {
            session_id: session_id.to_owned(),
            event,
        });
    }

    fn kick_dispatcher(&self) {
        if !self.auto_dispatch {
            return;
        }
        let store = self.clone();
        tokio::spawn(async move {
            if let Err(error) = store.dispatch_pending().await {
                eprintln!("zeus dispatcher stopped: {error}");
            }
        });
    }

    fn validate_pending_policy(
        &self,
        run: &RunSummary,
        approval: &Approval,
        call: &ToolCall,
    ) -> Result<(), StoreError> {
        let evaluation = self
            .policy
            .evaluate(&PolicyContext::for_call(&run.environment, call));
        if evaluation.decision == PolicyDecision::Deny {
            return Err(StoreError::PolicyDenied(evaluation.reason));
        }
        if evaluation.decision != PolicyDecision::RequireApproval
            || approval.policy_revision.as_deref() != Some(&evaluation.policy_revision)
        {
            return Err(StoreError::PolicyChanged(
                "the pending approval does not match the current policy revision".into(),
            ));
        }
        Ok(())
    }

    async fn claim_next_dispatch(&self) -> Result<Option<ClaimedDispatch>, StoreError> {
        loop {
            let Some(job) = self.storage.peek_next_dispatch().await? else {
                return Ok(None);
            };
            self.validate_dispatch_job_identity(&job)?;
            let context = self.storage.dispatch_context(&job).await?;
            let (call, approval) = bindings_for_job(&context, &job)?;
            let environment = context.snapshot.run.environment.clone();
            let expected_sequence = context.snapshot.run.sequence;
            let transition = start_tool_dispatch(
                &context.snapshot.run,
                &approval,
                &call,
                executor_label(&self.registry, &call),
                next_sequence(expected_sequence)?,
                now(),
            )?;
            let mut snapshot = context.snapshot;
            snapshot.run = transition.run;
            let event = transition.event.clone();

            match self
                .storage
                .claim_next_dispatch(DispatchStartCommit {
                    call_id: job.call_id.clone(),
                    expected_sequence,
                    snapshot,
                    event: transition.event,
                })
                .await?
            {
                ClaimOutcome::Claimed(claimed_job) => {
                    let _ = self.publisher.send(PublishedEvent {
                        run_id: claimed_job.run_id.clone(),
                        event,
                    });
                    return Ok(Some(ClaimedDispatch {
                        job: *claimed_job,
                        call,
                        approval,
                        environment,
                    }));
                }
                ClaimOutcome::Rejected(rejection) => {
                    // Storage revalidated the approving actor and committed
                    // both the terminal job state and durable rejection event.
                    // Publish only after that commit, then skip the connector.
                    let rejection = *rejection;
                    let _ = self.publisher.send(PublishedEvent {
                        run_id: rejection.job.run_id,
                        event: rejection.event,
                    });
                }
                ClaimOutcome::NotAvailable => return Ok(None),
            }
        }
    }

    async fn dispatch_outcome(&self, claimed: &ClaimedDispatch) -> ToolOutcome {
        if claimed.job.policy_id != self.policy_id.as_ref() {
            return not_dispatched(
                NotDispatchedReason::PolicyChanged,
                "The persisted policy identity no longer matches this runtime.",
            );
        }

        let evaluation = self.policy.guard_dispatch(
            &claimed.environment,
            &claimed.call,
            Some(&claimed.approval),
        );
        match evaluation.decision {
            PolicyDecision::Deny => {
                return not_dispatched(NotDispatchedReason::PolicyDenied, evaluation.reason);
            }
            PolicyDecision::RequireApproval => {
                return not_dispatched(NotDispatchedReason::PolicyChanged, evaluation.reason);
            }
            PolicyDecision::Allow if evaluation.policy_revision != claimed.job.policy_revision => {
                return not_dispatched(
                    NotDispatchedReason::PolicyChanged,
                    "The policy revision changed after the call was queued.",
                );
            }
            PolicyDecision::Allow => {}
        }

        if claimed.call.executor_status != ToolExecutorStatus::Available
            || self.registry.descriptor(&claimed.call.tool).is_none()
        {
            return not_dispatched(
                NotDispatchedReason::ExecutorUnavailable,
                "No executable provider is configured for this tool call.",
            );
        }

        match self
            .registry
            .dispatch(claimed.call.clone(), &claimed.environment)
            .await
        {
            Ok(output) => ToolOutcome::Succeeded {
                summary: if output.replayed {
                    "The provider returned the durable result for this existing logical call."
                        .into()
                } else {
                    "The tool completed and its result was durably recorded.".into()
                },
                output_digest: Some(arguments_digest(&output.value)),
            },
            Err(error) => registry_error_outcome(error),
        }
    }

    async fn complete_dispatch(
        &self,
        claimed: ClaimedDispatch,
        outcome: ToolOutcome,
    ) -> Result<(), StoreError> {
        let mut snapshot = self
            .storage
            .consistent_snapshot(&claimed.job.run_id)
            .await?;
        let expected_sequence = snapshot.run.sequence;
        let transition = apply_tool_result(
            &snapshot.run,
            &claimed.call,
            outcome.clone(),
            next_sequence(expected_sequence)?,
            now(),
        )?;
        snapshot.run = transition.run;
        let event = transition.event.clone();
        let result_json = serde_json::to_value(&outcome).map_err(StorageError::from)?;
        self.storage
            .complete_dispatch(DispatchCompleteCommit {
                call_id: claimed.job.call_id,
                expected_sequence,
                snapshot,
                event: transition.event,
                result_json,
            })
            .await?;
        let _ = self.publisher.send(PublishedEvent {
            run_id: claimed.job.run_id,
            event,
        });
        Ok(())
    }

    async fn recover_started_dispatches(&self) -> Result<(), StoreError> {
        loop {
            let jobs = self.storage.started_dispatches().await?;
            if jobs.is_empty() {
                return Ok(());
            }
            for job in jobs {
                self.validate_dispatch_job_identity(&job)?;
                let context = self.storage.dispatch_context(&job).await?;
                let (call, _) = bindings_for_job(&context, &job)?;
                let outcome = ToolOutcome::OutcomeUnknown {
                    summary: "Zeus restarted after the durable dispatch checkpoint but before a durable result; the call was not retried.".into(),
                };
                let expected_sequence = context.snapshot.run.sequence;
                let transition = apply_tool_result(
                    &context.snapshot.run,
                    &call,
                    outcome.clone(),
                    next_sequence(expected_sequence)?,
                    now(),
                )?;
                let mut snapshot = context.snapshot;
                snapshot.run = transition.run;
                let event = transition.event.clone();
                let result_json = serde_json::to_value(&outcome).map_err(StorageError::from)?;
                self.storage
                    .recover_started(DispatchRecoveryCommit {
                        call_id: job.call_id,
                        expected_sequence,
                        snapshot,
                        event: transition.event,
                        result_json,
                    })
                    .await?;
                let _ = self.publisher.send(PublishedEvent {
                    run_id: job.run_id,
                    event,
                });
            }
        }
    }

    fn validate_dispatch_job_identity(&self, job: &DispatchJob) -> Result<(), StoreError> {
        if job.run_id != self.primary_run_id.as_ref()
            || job.policy_id != self.policy_id.as_ref()
            || job.policy_revision != self.policy_revision.as_ref()
        {
            return Err(StoreError::ExecutionInvariant(format!(
                "dispatch job {} is not bound to this runtime's run and policy identity",
                job.call_id
            )));
        }
        Ok(())
    }
}

struct RuntimeComponents {
    scenario: DemoScenario,
    policy: PolicyEngine,
    registry: ToolRegistry,
    profile_id: &'static str,
    primary_session_id: &'static str,
    policy_id: &'static str,
    policy_revision: &'static str,
}

impl RuntimeComponents {
    fn build(profile: DemoProfile) -> Result<Self, StoreError> {
        match profile {
            DemoProfile::ProductionGuarded => {
                let scenario = DemoScenario::zr_1842();
                let call = requested_call(&scenario.events)?;
                let policy = PolicyEngine::new(vec![PolicyRule {
                    revision: PRODUCTION_POLICY_REVISION.into(),
                    tool: call.tool,
                    environment: scenario.run.environment.clone(),
                    effect: call.effect,
                    sandbox_profile: call.sandbox_profile,
                    decision: PolicyDecision::RequireApproval,
                }])?;
                Ok(Self {
                    scenario,
                    policy,
                    registry: ToolRegistry::new(),
                    profile_id: "production-guarded",
                    primary_session_id: protocol::DEMO_SESSION_ID,
                    policy_id: PRODUCTION_POLICY_ID,
                    policy_revision: PRODUCTION_POLICY_REVISION,
                })
            }
            DemoProfile::LocalDevelopment { marker_root } => {
                let scenario = DemoScenario::local_marker();
                if scenario.run.environment != LOCAL_DEV_ENVIRONMENT {
                    return Err(StoreError::ExecutionInvariant(
                        "kernel and connector local environment names disagree".into(),
                    ));
                }
                let call = requested_call(&scenario.events)?;
                let policy = PolicyEngine::new(vec![PolicyRule {
                    revision: LOCAL_POLICY_REVISION.into(),
                    tool: call.tool,
                    environment: scenario.run.environment.clone(),
                    effect: call.effect,
                    sandbox_profile: call.sandbox_profile,
                    decision: PolicyDecision::RequireApproval,
                }])?;
                let mut registry = ToolRegistry::new();
                register_local_dev_connectors(
                    &mut registry,
                    &scenario.run.environment,
                    marker_root,
                )?;
                Ok(Self {
                    scenario,
                    policy,
                    registry,
                    profile_id: "local-development",
                    primary_session_id: protocol::LOCAL_DEMO_SESSION_ID,
                    policy_id: LOCAL_POLICY_ID,
                    policy_revision: LOCAL_POLICY_REVISION,
                })
            }
        }
    }
}

struct ClaimedDispatch {
    job: DispatchJob,
    call: ToolCall,
    approval: Approval,
    environment: String,
}

fn snapshot_from_scenario(scenario: &DemoScenario) -> RunSnapshot {
    RunSnapshot {
        incident: scenario.incident.clone(),
        run: scenario.run.clone(),
        metrics: scenario.metrics.clone(),
        evidence: scenario.evidence.clone(),
        tool_policy: Some(scenario.tool_policy.clone()),
    }
}

fn requested_call(events: &[RunEvent]) -> Result<ToolCall, StoreError> {
    events
        .iter()
        .find_map(|event| match &event.data {
            Some(RunEventData::ToolCallRequested { call, .. }) => Some(call.clone()),
            _ => None,
        })
        .ok_or(StoreError::ToolCallNotFound)
}

fn pending_approval_and_call(
    context: &ReviewContext,
    approval_id: &str,
) -> Result<(Approval, ToolCall), StoreError> {
    let approval = context
        .approval
        .as_ref()
        .filter(|approval| approval.id == approval_id && approval.status == ApprovalStatus::Pending)
        .cloned()
        .ok_or_else(|| StoreError::ApprovalNotPending {
            run_id: context.snapshot.run.id.clone(),
            approval_id: approval_id.to_owned(),
        })?;
    let call_id = approval
        .call_id
        .as_deref()
        .ok_or(KernelError::ApprovalBindingIncomplete)?;
    let call = context
        .requested_call
        .as_ref()
        .filter(|call| call.call_id == call_id)
        .cloned()
        .ok_or(StoreError::ToolCallNotFound)?;
    Ok((approval, call))
}

fn bindings_for_job(
    context: &DispatchContext,
    job: &DispatchJob,
) -> Result<(ToolCall, Approval), StoreError> {
    if context.approval_event.sequence != job.approval_event_sequence {
        return Err(StoreError::ExecutionInvariant(
            "dispatch approval event sequence does not match the queue record".into(),
        ));
    }
    let approval = context
        .approval_event
        .approval
        .as_ref()
        .filter(|approval| {
            approval.id == job.approval_id && approval.status == ApprovalStatus::Approved
        })
        .cloned()
        .ok_or_else(|| {
            StoreError::ExecutionInvariant(
                "dispatch job is not bound to an approved ledger event".into(),
            )
        })?;
    let call = context
        .requested_call
        .as_ref()
        .filter(|call| call.call_id == job.call_id)
        .cloned()
        .ok_or(StoreError::ToolCallNotFound)?;

    let matches = job.run_id == context.snapshot.run.id
        && job.tool_name == call.tool
        && job.tool_version == call.tool_version
        && job.effect == call.effect
        && job.args_json == call.arguments
        && job.args_digest == call.arguments_digest
        && job.sandbox_profile == call.sandbox_profile
        && approval.call_id.as_deref() == Some(job.call_id.as_str())
        && approval.policy_revision.as_deref() == Some(job.policy_revision.as_str())
        && approval.arguments_digest.as_deref() == Some(job.args_digest.as_str())
        && approval.sandbox_profile.as_ref() == Some(&job.sandbox_profile);
    if !matches {
        return Err(StoreError::ExecutionInvariant(
            "dispatch job, approval, and requested call do not have one exact binding".into(),
        ));
    }
    Ok((call, approval))
}

fn executor_label(registry: &ToolRegistry, call: &ToolCall) -> String {
    match registry.descriptor(&call.tool) {
        Some(descriptor) => format!("registry:{}@{}", descriptor.name, descriptor.version),
        None => format!("unavailable:{}@{}", call.tool, call.tool_version),
    }
}

fn clear_pending_approval_metric(snapshot: &mut RunSnapshot) {
    if let Some(metric) = snapshot
        .metrics
        .iter_mut()
        .find(|metric| metric.label == "Pending approvals")
    {
        metric.value = "0".into();
    }
}

fn policy_guard_error(evaluation: authz::PolicyEvaluation) -> StoreError {
    match evaluation.decision {
        PolicyDecision::Deny => StoreError::PolicyDenied(evaluation.reason),
        PolicyDecision::RequireApproval | PolicyDecision::Allow => {
            StoreError::PolicyChanged(evaluation.reason)
        }
    }
}

fn registry_error_outcome(error: RegistryError) -> ToolOutcome {
    match error {
        RegistryError::UnknownTool(_) | RegistryError::ExecutorUnavailable(_) => not_dispatched(
            NotDispatchedReason::ExecutorUnavailable,
            "No executable provider is configured for this tool call.",
        ),
        RegistryError::ContractMismatch {
            field: "sandbox_profile",
        } => not_dispatched(
            NotDispatchedReason::SandboxUnavailable,
            "The configured executor does not provide the approved sandbox profile.",
        ),
        RegistryError::InvalidDescriptor(_)
        | RegistryError::DuplicateTool(_)
        | RegistryError::InvalidCall(_)
        | RegistryError::InvalidArguments(_)
        | RegistryError::ContractMismatch { .. } => not_dispatched(
            NotDispatchedReason::PolicyChanged,
            "The registered tool contract no longer matches the approved call.",
        ),
        RegistryError::ExecutorOutputTooLarge { .. } => ToolOutcome::Failed {
            summary: "The executor returned a result larger than the allowed inline envelope."
                .into(),
            error_code: Some("executor_output_too_large".into()),
        },
        RegistryError::InvalidExecutorOutput { .. } => ToolOutcome::Failed {
            summary: "The executor returned output that does not satisfy the durable contract."
                .into(),
            error_code: Some("executor_output_invalid".into()),
        },
        RegistryError::InvalidExecutorDiagnostic { .. } => ToolOutcome::Failed {
            summary: "The executor returned an invalid or oversized failure diagnostic.".into(),
            error_code: Some("executor_diagnostic_invalid".into()),
        },
        RegistryError::Executor(ExecutorError::Unavailable { .. }) => ToolOutcome::Failed {
            summary: "The executor was invoked after the checkpoint but reported unavailable."
                .into(),
            error_code: Some("executor_unavailable_after_dispatch".into()),
        },
        RegistryError::Executor(ExecutorError::Failed { code, message, .. }) => {
            ToolOutcome::Failed {
                summary: message,
                error_code: Some(code),
            }
        }
    }
}

fn not_dispatched(reason: NotDispatchedReason, summary: impl Into<String>) -> ToolOutcome {
    let summary = summary.into();
    let summary = if protocol::validate_tool_outcome_summary(&summary).is_ok() {
        summary
    } else {
        "The tool was not dispatched because a bounded diagnostic was unavailable.".into()
    };
    ToolOutcome::NotDispatched { reason, summary }
}

fn next_sequence(sequence: u64) -> Result<u64, StoreError> {
    sequence.checked_add(1).ok_or(StoreError::SequenceOverflow)
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn normalized_idempotency_key(key: &str) -> Result<&str, StoreError> {
    match protocol::validate_idempotency_key(key) {
        Ok(()) => Ok(key),
        Err(ResourceEnvelopeError::Empty) => Err(StoreError::EmptyIdempotencyKey),
        Err(error) => Err(invalid_resource_envelope("idempotency key", error)),
    }
}

fn validate_new_session_id(value: &str, field: &'static str) -> Result<(), StoreError> {
    protocol::validate_session_id(value).map_err(|error| invalid_resource_envelope(field, error))
}

fn validate_new_turn_id(value: &str, field: &'static str) -> Result<(), StoreError> {
    protocol::validate_turn_id(value).map_err(|error| invalid_resource_envelope(field, error))
}

fn validate_new_session_title(value: &str, field: &'static str) -> Result<(), StoreError> {
    protocol::validate_session_title(value).map_err(|error| invalid_resource_envelope(field, error))
}

fn validate_durable_reference(value: &str, field: &'static str) -> Result<(), StoreError> {
    if value.is_empty() || value.trim() != value {
        Err(StoreError::InvalidSessionRequest(format!(
            "{field} must be non-empty and canonical"
        )))
    } else {
        Ok(())
    }
}

fn validate_user_message_value(value: &str, field: &'static str) -> Result<(), StoreError> {
    protocol::validate_user_message(value).map_err(|error| invalid_resource_envelope(field, error))
}

fn validate_session_message(value: &str, field: &'static str) -> Result<(), StoreError> {
    protocol::validate_assistant_message(value)
        .map_err(|error| invalid_resource_envelope(field, error))
}

fn validate_review_request_value(request: &ReviewRequest) -> Result<(), StoreError> {
    if let Some(note) = &request.note {
        protocol::validate_review_note(note)
            .map_err(|error| invalid_resource_envelope("review note", error))?;
    }
    if let Some(idempotency_key) = &request.idempotency_key {
        normalized_idempotency_key(idempotency_key)?;
    }
    Ok(())
}

fn invalid_resource_envelope(field: &'static str, error: ResourceEnvelopeError) -> StoreError {
    StoreError::InvalidSessionRequest(format!("{field} {error}"))
}

fn validate_session_sequence(value: u64, field: &'static str) -> Result<(), StoreError> {
    if i64::try_from(value).is_err() {
        Err(StoreError::InvalidSessionRequest(format!(
            "{field} is out of range"
        )))
    } else {
        Ok(())
    }
}

fn review_fingerprint(
    run_id: &str,
    approval_id: &str,
    request: &ReviewRequest,
) -> Result<String, StoreError> {
    serde_json::to_string(&serde_json::json!({
        "approval_id": approval_id,
        "decision": request.decision,
        "note": request.note,
        "run_id": run_id,
    }))
    .map_err(StorageError::from)
    .map_err(StoreError::from)
}

fn replay_receipt(receipt: ReviewReceipt, fingerprint: &str) -> Result<ReviewResponse, StoreError> {
    if receipt.request_fingerprint != fingerprint {
        return Err(StoreError::IdempotencyConflict);
    }
    let mut response = receipt.response;
    response.replayed = true;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use kernel::{LOCAL_MARKER_CALL_ID, PRODUCTION_DEMO_CALL_ID};
    use protocol::{
        DEMO_RUN_ID, DEMO_SESSION_ID, LOCAL_DEMO_RUN_ID, LOCAL_DEMO_SESSION_ID, RunStatus,
        SessionStatus, SessionTurnStatus, ToolCallStatus,
    };
    use rusqlite::{Connection, params};
    use storage::DispatchStatus;
    use tools::{RecordingExecutor, TOOL_OUTPUT_MAX_SERIALIZED_BYTES};

    use super::*;

    static NEXT_PATH: AtomicU64 = AtomicU64::new(1);
    const TEST_OWNER_ID: &str = "user-runtime-owner";

    fn approval_request(decision: ReviewDecision) -> ReviewRequest {
        ReviewRequest {
            decision,
            note: Some("Reviewed by the local Alpha test".into()),
            idempotency_key: None,
        }
    }

    #[tokio::test]
    async fn replay_is_strictly_after_the_cursor() {
        let store = production_store(false).await;
        let replay = store
            .events_after_for_actor(TEST_OWNER_ID, protocol::DEMO_RUN_ID, 4)
            .await
            .unwrap();

        assert_eq!(
            replay
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![5, 6, 7, 8]
        );
    }

    #[tokio::test]
    async fn actor_scoped_event_pages_and_paged_feeds_preserve_cursor_contracts() {
        let store = production_store(false).await;

        let first = store
            .event_page_feed_for_actor(TEST_OWNER_ID, DEMO_RUN_ID, 0, 3)
            .await
            .unwrap();
        assert_eq!(
            first
                .replay
                .items
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(first.replay.next_after, Some(3));
        assert_eq!(first.replay.head_sequence, 8);
        assert!(first.replay.has_more);

        let last = store
            .run_event_page_for_actor(TEST_OWNER_ID, DEMO_RUN_ID, 3, 5)
            .await
            .unwrap();
        assert_eq!(
            last.items
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![4, 5, 6, 7, 8]
        );
        assert_eq!(last.next_after, None);
        assert_eq!(last.head_sequence, 8);
        assert!(!last.has_more);

        assert!(matches!(
            store
                .run_event_page_for_actor(TEST_OWNER_ID, DEMO_RUN_ID, 9, 1)
                .await,
            Err(StoreError::EventCursorBeyondHead {
                after: 9,
                head_sequence: 8,
            })
        ));
        assert!(matches!(
            store
                .run_event_page_for_actor(TEST_OWNER_ID, DEMO_RUN_ID, u64::MAX, 1)
                .await,
            Err(StoreError::EventCursorOutOfRange { after }) if after == u64::MAX
        ));
        assert!(matches!(
            store
                .run_event_page_for_actor(TEST_OWNER_ID, DEMO_RUN_ID, 0, 0)
                .await,
            Err(StoreError::Storage(StorageError::InvalidEventPageLimit {
                limit: 0,
                max: protocol::EVENT_PAGE_MAX_LIMIT,
            }))
        ));
        assert!(matches!(
            store
                .run_event_page_for_actor("foreign-user", DEMO_RUN_ID, 9, 0)
                .await,
            Err(StoreError::RunNotFound(id)) if id == DEMO_RUN_ID
        ));

        let mut session_feed = store
            .session_event_page_feed_for_actor(TEST_OWNER_ID, DEMO_SESSION_ID, 2, 1)
            .await
            .unwrap();
        assert!(session_feed.replay.items.is_empty());
        assert_eq!(session_feed.replay.next_after, None);
        assert_eq!(session_feed.replay.head_sequence, 2);
        assert!(!session_feed.replay.has_more);

        let started = store
            .start_turn_for_actor(
                TEST_OWNER_ID,
                DEMO_SESSION_ID,
                StartTurnRequest {
                    turn_id: "turn-paged-feed".into(),
                    user_message: "Verify the bounded feed wake channel.".into(),
                    expected_sequence: 2,
                },
                "runtime-paged-feed-start",
            )
            .await
            .unwrap();
        assert_eq!(
            session_feed.receiver.recv().await.unwrap().event,
            started.event
        );
    }

    #[tokio::test]
    async fn session_start_and_flush_do_not_touch_run_or_dispatch_state() {
        let mut store = production_store(false).await;
        let queued = enqueue_job_with_identity(
            &store,
            PRODUCTION_POLICY_ID,
            PRODUCTION_POLICY_REVISION,
            "runtime-session-isolation-queue",
        )
        .await
        .unwrap();
        assert_eq!(queued.status, DispatchStatus::Queued);
        assert_eq!(queued.attempt, 0);
        // Make an accidental `kick_dispatcher` observable without draining the
        // pre-existing queued job during startup.
        store.auto_dispatch = true;
        let run_before = store
            .run_detail_for_actor(
                TEST_OWNER_ID,
                DEMO_RUN_ID,
                None,
                protocol::EVENT_PAGE_DEFAULT_LIMIT,
            )
            .await
            .unwrap();
        let mut session_feed = store
            .session_event_feed_for_actor(TEST_OWNER_ID, DEMO_SESSION_ID, 2)
            .await
            .unwrap();
        let mut run_feed = store
            .event_feed_for_actor(TEST_OWNER_ID, DEMO_RUN_ID, run_before.run.sequence)
            .await
            .unwrap();
        assert!(session_feed.replay.is_empty());
        assert!(run_feed.replay.is_empty());

        let started = store
            .start_turn_for_actor(
                TEST_OWNER_ID,
                DEMO_SESSION_ID,
                StartTurnRequest {
                    turn_id: "turn-runtime-isolation".into(),
                    user_message: "Summarize the durable evidence.".into(),
                    expected_sequence: 2,
                },
                "runtime-start-isolation",
            )
            .await
            .unwrap();
        assert_eq!(started.session.status, SessionStatus::Running);
        assert_eq!(started.event.sequence, 3);
        let published = session_feed.receiver.recv().await.unwrap();
        assert_eq!(published.session_id, DEMO_SESSION_ID);
        assert_eq!(published.event, started.event);
        assert!(matches!(
            run_feed.receiver.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));

        let flush_request = FlushSessionRequest {
            turn_id: "turn-runtime-isolation".into(),
            assistant_message: Some("The durable evidence remains unchanged.".into()),
            expected_sequence: 3,
        };
        let flushed = store
            .flush_turn_for_actor(
                TEST_OWNER_ID,
                DEMO_SESSION_ID,
                flush_request.clone(),
                "runtime-flush-isolation",
            )
            .await
            .unwrap();
        assert_eq!(flushed.session.status, SessionStatus::Ready);
        assert_eq!(flushed.turn.status, SessionTurnStatus::Flushed);
        assert_eq!(flushed.ack.durability_sequence, 5);
        assert_eq!(
            session_feed.receiver.recv().await.unwrap().event,
            flushed.events[0]
        );
        assert_eq!(
            session_feed.receiver.recv().await.unwrap().event,
            flushed.events[1]
        );

        let replayed = store
            .flush_turn_for_actor(
                TEST_OWNER_ID,
                DEMO_SESSION_ID,
                flush_request,
                "runtime-flush-isolation",
            )
            .await
            .unwrap();
        assert!(replayed.replayed);
        assert_eq!(replayed.events, flushed.events);
        assert_eq!(replayed.ack, flushed.ack);
        assert!(matches!(
            session_feed.receiver.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert_eq!(
            store
                .run_detail_for_actor(
                    TEST_OWNER_ID,
                    DEMO_RUN_ID,
                    None,
                    protocol::EVENT_PAGE_DEFAULT_LIMIT,
                )
                .await
                .unwrap(),
            run_before
        );
        let still_queued = store
            .storage
            .dispatch_job(PRODUCTION_DEMO_CALL_ID)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(still_queued.status, DispatchStatus::Queued);
        assert_eq!(still_queued.attempt, 0);
        assert!(matches!(
            run_feed.receiver.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn restart_interrupts_open_session_turn_without_changing_run_ledger() {
        let paths = TestPaths::new("session-recovery");
        let store = DemoStore::from_storage(
            SqliteStore::open(&paths.database).await.unwrap(),
            DemoProfile::ProductionGuarded,
            false,
        )
        .await
        .unwrap();
        bootstrap_test_owner(&store).await;
        let run_before = store
            .run_detail_for_actor(
                TEST_OWNER_ID,
                DEMO_RUN_ID,
                None,
                protocol::EVENT_PAGE_DEFAULT_LIMIT,
            )
            .await
            .unwrap();
        store
            .start_turn_for_actor(
                TEST_OWNER_ID,
                DEMO_SESSION_ID,
                StartTurnRequest {
                    turn_id: "turn-restart-recovery".into(),
                    user_message: "Continue after a restart.".into(),
                    expected_sequence: 2,
                },
                "runtime-start-recovery",
            )
            .await
            .unwrap();
        drop(store);

        let reopened = DemoStore::from_storage(
            SqliteStore::open(&paths.database).await.unwrap(),
            DemoProfile::ProductionGuarded,
            false,
        )
        .await
        .unwrap();
        let detail = reopened
            .get_session_for_actor(
                TEST_OWNER_ID,
                DEMO_SESSION_ID,
                None,
                protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                None,
                protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                None,
                protocol::EVENT_PAGE_DEFAULT_LIMIT,
            )
            .await
            .unwrap();
        assert_eq!(detail.session.status, SessionStatus::NeedsAttention);
        assert_eq!(detail.session.sequence, 4);
        assert_eq!(detail.turns[0].status, SessionTurnStatus::Interrupted);
        assert!(matches!(
            detail.events.last().map(|event| &event.data),
            Some(SessionEventData::TurnInterrupted { turn_id, .. })
                if turn_id == "turn-restart-recovery"
        ));
        assert!(
            detail
                .events
                .iter()
                .all(|event| !matches!(event.data, SessionEventData::TurnFlushed { .. }))
        );
        assert_eq!(
            reopened
                .run_detail_for_actor(
                    TEST_OWNER_ID,
                    DEMO_RUN_ID,
                    None,
                    protocol::EVENT_PAGE_DEFAULT_LIMIT,
                )
                .await
                .unwrap(),
            run_before
        );

        let resume_request = ResumeSessionRequest {
            expected_sequence: 4,
        };
        let resumed = reopened
            .resume_session_for_actor(
                TEST_OWNER_ID,
                DEMO_SESSION_ID,
                resume_request.clone(),
                "runtime-resume-recovery",
            )
            .await
            .unwrap();
        assert_eq!(resumed.session.status, SessionStatus::Ready);
        assert_eq!(resumed.session.sequence, 5);
        let replayed = reopened
            .resume_session_for_actor(
                TEST_OWNER_ID,
                DEMO_SESSION_ID,
                resume_request,
                "runtime-resume-recovery",
            )
            .await
            .unwrap();
        assert!(replayed.replayed);
        assert_eq!(
            reopened
                .get_session_for_actor(
                    TEST_OWNER_ID,
                    DEMO_SESSION_ID,
                    None,
                    protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                    None,
                    protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                    None,
                    protocol::EVENT_PAGE_DEFAULT_LIMIT,
                )
                .await
                .unwrap()
                .session
                .sequence,
            5
        );
        assert_eq!(
            reopened
                .run_detail_for_actor(
                    TEST_OWNER_ID,
                    DEMO_RUN_ID,
                    None,
                    protocol::EVENT_PAGE_DEFAULT_LIMIT,
                )
                .await
                .unwrap(),
            run_before
        );
    }

    #[tokio::test]
    async fn overview_and_session_queries_expose_the_stable_primary_session() {
        let store = production_store(false).await;
        let overview = store.overview_for_actor(TEST_OWNER_ID).await.unwrap();
        assert_eq!(overview.primary_session_id, DEMO_SESSION_ID);
        assert_eq!(overview.recent_events.len(), 8);
        assert_eq!(
            overview.recent_events_page,
            Some(protocol::ReadPageInfo {
                next_before: None,
                has_more: false,
            })
        );
        let latest_run = store
            .run_detail_for_actor(TEST_OWNER_ID, DEMO_RUN_ID, None, 3)
            .await
            .unwrap();
        assert_eq!(
            latest_run
                .events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![6, 7, 8]
        );
        let run_page = latest_run.pagination.unwrap().events;
        assert!(run_page.has_more);
        let older_run = store
            .run_detail_for_actor(
                TEST_OWNER_ID,
                DEMO_RUN_ID,
                run_page.next_before.as_deref(),
                3,
            )
            .await
            .unwrap();
        assert_eq!(
            older_run
                .events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![3, 4, 5]
        );
        let sessions = store
            .list_sessions_for_actor(TEST_OWNER_ID, None, protocol::COLLECTION_PAGE_DEFAULT_LIMIT)
            .await
            .unwrap();
        assert_eq!(sessions.items.len(), 1);
        assert_eq!(sessions.items[0].id, DEMO_SESSION_ID);
        assert!(sessions.next_cursor.is_none());
        let detail = store
            .get_session_for_actor(
                TEST_OWNER_ID,
                DEMO_SESSION_ID,
                None,
                protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                None,
                protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                None,
                protocol::EVENT_PAGE_DEFAULT_LIMIT,
            )
            .await
            .unwrap();
        assert_eq!(detail.run_ids, vec![DEMO_RUN_ID]);
        assert_eq!(detail.events.len(), 2);
        let detail_page = detail.pagination.unwrap();
        assert!(!detail_page.run_ids.has_more);
        assert!(!detail_page.turns.has_more);
        assert!(!detail_page.events.has_more);
    }

    #[tokio::test]
    async fn actor_scoped_queries_and_commands_hide_another_owners_resources() {
        const OTHER_ACTOR: &str = "user-other-owner";

        let store = production_store(false).await;
        assert_eq!(
            store.current_run_for_actor(TEST_OWNER_ID).await.unwrap().id,
            DEMO_RUN_ID
        );
        assert!(
            matches!(
                store.overview_for_actor(OTHER_ACTOR).await,
                Err(StoreError::RunNotFound(id)) if id == DEMO_RUN_ID
            ),
            "overview must conceal another owner's run"
        );
        assert!(
            matches!(
                store
                    .run_detail_for_actor(
                        OTHER_ACTOR,
                        DEMO_RUN_ID,
                        None,
                        protocol::EVENT_PAGE_DEFAULT_LIMIT,
                    )
                    .await,
                Err(StoreError::RunNotFound(id)) if id == DEMO_RUN_ID
            ),
            "run detail must conceal another owner's run"
        );
        assert!(
            matches!(
                store.events_after_for_actor(OTHER_ACTOR, DEMO_RUN_ID, 0).await,
                Err(StoreError::RunNotFound(id)) if id == DEMO_RUN_ID
            ),
            "run replay must conceal another owner's run"
        );
        let run_feed_error = match store
            .event_feed_for_actor(OTHER_ACTOR, DEMO_RUN_ID, 0)
            .await
        {
            Ok(_) => panic!("run feed must conceal another owner's run"),
            Err(error) => error,
        };
        assert!(matches!(
            run_feed_error,
            StoreError::RunNotFound(id) if id == DEMO_RUN_ID
        ));

        assert!(
            matches!(
                store
                    .get_session_for_actor(
                        OTHER_ACTOR,
                        DEMO_SESSION_ID,
                        None,
                        protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                        None,
                        protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                        None,
                        protocol::EVENT_PAGE_DEFAULT_LIMIT,
                    )
                    .await,
                Err(StoreError::SessionNotFound(id)) if id == DEMO_SESSION_ID
            ),
            "session detail must conceal another owner's session"
        );
        assert!(
            matches!(
                store
                    .session_events_after_for_actor(OTHER_ACTOR, DEMO_SESSION_ID, 0)
                    .await,
                Err(StoreError::SessionNotFound(id)) if id == DEMO_SESSION_ID
            ),
            "session replay must conceal another owner's session"
        );
        let session_feed_error = match store
            .session_event_feed_for_actor(OTHER_ACTOR, DEMO_SESSION_ID, 0)
            .await
        {
            Ok(_) => panic!("session feed must conceal another owner's session"),
            Err(error) => error,
        };
        assert!(matches!(
            session_feed_error,
            StoreError::SessionNotFound(id) if id == DEMO_SESSION_ID
        ));
        assert!(
            matches!(
                store
                    .start_turn_for_actor(
                        OTHER_ACTOR,
                        DEMO_SESSION_ID,
                        StartTurnRequest {
                            turn_id: "turn-other-owner".into(),
                            user_message: "This must remain unauthorized.".into(),
                            expected_sequence: 2,
                        },
                        "runtime-other-owner-start",
                    )
                    .await,
                Err(StoreError::SessionNotFound(id)) if id == DEMO_SESSION_ID
            ),
            "session commands must authorize the resource before transition validation"
        );
        assert!(
            matches!(
                store
                    .attach_run_for_actor(
                        OTHER_ACTOR,
                        DEMO_SESSION_ID,
                        AttachRunRequest {
                            run_id: DEMO_RUN_ID.into(),
                            expected_sequence: 2,
                        },
                        "runtime-other-owner-attach",
                    )
                    .await,
                Err(StoreError::SessionNotFound(id)) if id == DEMO_SESSION_ID
            ),
            "run attachment must authorize the session before checking attachment state"
        );
        assert!(
            matches!(
                store
                    .resume_session_for_actor(
                        OTHER_ACTOR,
                        DEMO_SESSION_ID,
                        ResumeSessionRequest {
                            expected_sequence: 2,
                        },
                        "runtime-other-owner-resume",
                    )
                    .await,
                Err(StoreError::SessionNotFound(id)) if id == DEMO_SESSION_ID
            ),
            "resume must authorize the session before checking its state"
        );
        assert_eq!(
            store
                .get_session_for_actor(
                    TEST_OWNER_ID,
                    DEMO_SESSION_ID,
                    None,
                    protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                    None,
                    protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                    None,
                    protocol::EVENT_PAGE_DEFAULT_LIMIT,
                )
                .await
                .unwrap()
                .session
                .sequence,
            2
        );
    }

    #[tokio::test]
    async fn actor_review_authorizes_the_run_before_receipt_replay() {
        const OTHER_ACTOR: &str = "user-other-owner";

        let store = production_store(false).await;
        let request = approval_request(ReviewDecision::Reject);
        let first = store
            .review_for_actor(
                TEST_OWNER_ID,
                DEMO_RUN_ID,
                "APR-901",
                request.clone(),
                "actor-review-replay",
            )
            .await
            .unwrap();
        assert!(!first.replayed);
        assert_eq!(first.run.status, RunStatus::Blocked);

        let replay = store
            .review_for_actor(
                TEST_OWNER_ID,
                DEMO_RUN_ID,
                "APR-901",
                request.clone(),
                "actor-review-replay",
            )
            .await
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.event, first.event);

        assert!(
            matches!(
                store
                    .review_for_actor(
                        OTHER_ACTOR,
                        DEMO_RUN_ID,
                        "APR-901",
                        request,
                        "actor-review-replay",
                    )
                    .await,
                Err(StoreError::RunNotFound(id)) if id == DEMO_RUN_ID
            ),
            "receipt possession must not bypass run authorization"
        );
    }

    #[tokio::test]
    async fn concurrent_actor_reviews_with_one_key_commit_once_and_replay() {
        const CONCURRENCY: usize = 16;

        let store = production_store(false).await;
        let barrier = Arc::new(tokio::sync::Barrier::new(CONCURRENCY));
        let mut tasks = Vec::with_capacity(CONCURRENCY);
        for _ in 0..CONCURRENCY {
            let store = store.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                store
                    .review_for_actor(
                        TEST_OWNER_ID,
                        DEMO_RUN_ID,
                        "APR-901",
                        approval_request(ReviewDecision::Reject),
                        "concurrent-actor-review",
                    )
                    .await
            }));
        }

        let mut responses = Vec::with_capacity(CONCURRENCY);
        for task in tasks {
            responses.push(task.await.unwrap().unwrap());
        }
        assert_eq!(
            responses
                .iter()
                .filter(|response| !response.replayed)
                .count(),
            1
        );
        assert_eq!(
            responses
                .iter()
                .filter(|response| response.replayed)
                .count(),
            CONCURRENCY - 1
        );
        let event = responses[0].event.clone();
        assert!(responses.iter().all(|response| response.event == event));
    }

    #[tokio::test]
    async fn runtime_envelope_rejections_leave_session_receipts_and_ledger_untouched() {
        let store = production_store(false).await;
        let before = store
            .get_session_for_actor(
                TEST_OWNER_ID,
                DEMO_SESSION_ID,
                None,
                protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                None,
                protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                None,
                protocol::EVENT_PAGE_DEFAULT_LIMIT,
            )
            .await
            .unwrap();

        assert!(matches!(
            store
                .start_turn_for_actor(
                    TEST_OWNER_ID,
                    DEMO_SESSION_ID,
                    StartTurnRequest {
                        turn_id: "turn-runtime-over-message".into(),
                        user_message: "🙂".repeat(protocol::USER_MESSAGE_MAX_BYTES / 4 + 1),
                        expected_sequence: before.session.sequence,
                    },
                    "runtime-over-message",
                )
                .await,
            Err(StoreError::InvalidSessionRequest(_))
        ));
        assert!(matches!(
            store
                .start_turn_for_actor(
                    TEST_OWNER_ID,
                    DEMO_SESSION_ID,
                    StartTurnRequest {
                        turn_id: "turn-runtime-key".into(),
                        user_message: "This must not be persisted yet".into(),
                        expected_sequence: before.session.sequence,
                    },
                    " runtime-key",
                )
                .await,
            Err(StoreError::InvalidSessionRequest(_))
        ));

        let unchanged = store
            .get_session_for_actor(
                TEST_OWNER_ID,
                DEMO_SESSION_ID,
                None,
                protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                None,
                protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                None,
                protocol::EVENT_PAGE_DEFAULT_LIMIT,
            )
            .await
            .unwrap();
        assert_eq!(unchanged, before);
        let started = store
            .start_turn_for_actor(
                TEST_OWNER_ID,
                DEMO_SESSION_ID,
                StartTurnRequest {
                    turn_id: "turn-runtime-key".into(),
                    user_message: "The exact canonical key remains unused".into(),
                    expected_sequence: before.session.sequence,
                },
                "runtime-key",
            )
            .await
            .unwrap();
        assert!(!started.replayed);
    }

    #[tokio::test]
    async fn runtime_review_note_envelope_rejects_before_fingerprint_receipt_and_ledger() {
        let store = production_store(false).await;
        let before = store
            .run_detail_for_actor(
                TEST_OWNER_ID,
                DEMO_RUN_ID,
                None,
                protocol::EVENT_PAGE_DEFAULT_LIMIT,
            )
            .await
            .unwrap();
        assert!(matches!(
            store
                .review_for_actor(
                    TEST_OWNER_ID,
                    DEMO_RUN_ID,
                    "APR-901",
                    ReviewRequest {
                        decision: ReviewDecision::Reject,
                        note: Some("🙂".repeat(protocol::REVIEW_NOTE_MAX_BYTES / 4 + 1)),
                        idempotency_key: None,
                    },
                    "runtime-review-envelope",
                )
                .await,
            Err(StoreError::InvalidSessionRequest(_))
        ));
        assert!(matches!(
            store
                .review_for_actor(
                    TEST_OWNER_ID,
                    DEMO_RUN_ID,
                    "APR-901",
                    ReviewRequest {
                        decision: ReviewDecision::Reject,
                        note: Some("The body key is not canonical".into()),
                        idempotency_key: Some(" body-review-key".into()),
                    },
                    "runtime-body-key-envelope",
                )
                .await,
            Err(StoreError::InvalidSessionRequest(_))
        ));
        assert!(
            store
                .storage
                .review_receipt_for_actor(TEST_OWNER_ID, DEMO_RUN_ID, "runtime-review-envelope",)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .storage
                .review_receipt_for_actor(TEST_OWNER_ID, DEMO_RUN_ID, "runtime-body-key-envelope",)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .run_detail_for_actor(
                    TEST_OWNER_ID,
                    DEMO_RUN_ID,
                    None,
                    protocol::EVENT_PAGE_DEFAULT_LIMIT,
                )
                .await
                .unwrap(),
            before
        );
    }

    #[tokio::test]
    async fn actor_review_without_a_bootstrapped_owner_fails_closed() {
        let store = DemoStore::from_storage(
            SqliteStore::open(":memory:").await.unwrap(),
            DemoProfile::ProductionGuarded,
            false,
        )
        .await
        .unwrap();

        assert!(matches!(
            store
                .review_for_actor(
                    TEST_OWNER_ID,
                    DEMO_RUN_ID,
                    "APR-901",
                    approval_request(ReviewDecision::Reject),
                    "unbootstrapped-review",
                )
                .await,
            Err(StoreError::RunNotFound(id)) if id == DEMO_RUN_ID
        ));
    }

    #[tokio::test]
    async fn production_approval_is_never_reported_as_execution_success() {
        let store = production_store(false).await;
        let response = store
            .review_for_actor(
                TEST_OWNER_ID,
                protocol::DEMO_RUN_ID,
                "APR-901",
                approval_request(ReviewDecision::Approve),
                "production-review",
            )
            .await
            .unwrap();
        assert_eq!(response.run.status, RunStatus::Queued);

        store.dispatch_pending().await.unwrap();
        let detail = store.run_detail(protocol::DEMO_RUN_ID).await.unwrap();
        assert_eq!(detail.run.status, RunStatus::NeedsAttention);
        assert!(matches!(
            detail.events.last().and_then(|event| event.data.as_ref()),
            Some(RunEventData::ToolResult {
                outcome: ToolOutcome::NotDispatched {
                    reason: NotDispatchedReason::ExecutorUnavailable,
                    ..
                },
                status: ToolCallStatus::NotDispatched,
                ..
            })
        ));
        let job = store
            .storage
            .dispatch_job(PRODUCTION_DEMO_CALL_ID)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(job.approving_actor_user_id.as_deref(), Some(TEST_OWNER_ID));
        assert_eq!(job.status, DispatchStatus::Finished);
        assert_eq!(job.attempt, 1);
    }

    #[tokio::test]
    async fn local_approval_executes_one_marker_and_replay_does_not_execute_twice() {
        let paths = TestPaths::new("local-success");
        let store = local_store(&paths, false).await;
        let request = approval_request(ReviewDecision::Approve);
        let first = store
            .review_for_actor(
                TEST_OWNER_ID,
                LOCAL_DEMO_RUN_ID,
                "APR-DEV-1",
                request.clone(),
                "local-review",
            )
            .await
            .unwrap();
        assert_eq!(first.run.status, RunStatus::Queued);

        store.dispatch_pending().await.unwrap();
        assert_eq!(
            store.current_run().await.unwrap().status,
            RunStatus::Succeeded
        );
        assert_eq!(directory_entries(&paths.marker_root), 1);

        let replay = store
            .review_for_actor(
                TEST_OWNER_ID,
                LOCAL_DEMO_RUN_ID,
                "APR-DEV-1",
                request,
                "local-review",
            )
            .await
            .unwrap();
        assert!(replay.replayed);
        store.dispatch_pending().await.unwrap();
        assert_eq!(directory_entries(&paths.marker_root), 1);
        let job = store
            .storage
            .dispatch_job(LOCAL_MARKER_CALL_ID)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(job.attempt, 1);
    }

    #[tokio::test]
    async fn oversized_executor_output_settles_once_without_persisting_the_payload() {
        let paths = TestPaths::new("local-oversized-output");
        let mut store = local_store(&paths, false).await;
        let descriptor = store
            .registry
            .descriptor(connectors::DEV_MARKER_TOOL_NAME)
            .unwrap()
            .clone();
        let payload_marker = "SECRET-EXECUTOR-OVERSIZE";
        let executor = RecordingExecutor::new(serde_json::json!({
            "payload": format!(
                "{payload_marker}{}",
                "x".repeat(TOOL_OUTPUT_MAX_SERIALIZED_BYTES)
            ),
        }));
        let calls = executor.clone();
        let mut registry = ToolRegistry::new();
        registry.register(descriptor, executor).unwrap();
        store.registry = Arc::new(registry);

        let approved = store
            .review_for_actor(
                TEST_OWNER_ID,
                LOCAL_DEMO_RUN_ID,
                "APR-DEV-1",
                approval_request(ReviewDecision::Approve),
                "local-oversized-output-review",
            )
            .await
            .unwrap();
        assert_eq!(approved.run.status, RunStatus::Queued);

        store.dispatch_pending().await.unwrap();
        assert_eq!(calls.calls().len(), 1);
        let detail = store.run_detail(LOCAL_DEMO_RUN_ID).await.unwrap();
        assert_eq!(detail.run.status, RunStatus::Failed);
        assert!(matches!(
            detail.events.last().and_then(|event| event.data.as_ref()),
            Some(RunEventData::ToolResult {
                outcome: ToolOutcome::Failed {
                    summary,
                    error_code: Some(error_code),
                },
                status: ToolCallStatus::Failed,
                ..
            }) if summary == "The executor returned a result larger than the allowed inline envelope."
                && error_code == "executor_output_too_large"
        ));
        let job = store
            .storage
            .dispatch_job(LOCAL_MARKER_CALL_ID)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(job.status, DispatchStatus::Finished);
        assert_eq!(job.attempt, 1);
        assert!(
            !serde_json::to_string(&detail)
                .unwrap()
                .contains(payload_marker)
        );
        assert!(
            !job.result_json
                .as_ref()
                .is_some_and(|value| value.to_string().contains(payload_marker))
        );

        store.dispatch_pending().await.unwrap();
        assert_eq!(calls.calls().len(), 1, "terminal jobs must never retry");
    }

    #[tokio::test]
    async fn execution_point_queries_do_not_decode_unrelated_history() {
        let paths = TestPaths::new("point-query-history");
        let store = local_store(&paths, false).await;
        // Deliberately bypass the append-only trigger to prove only that
        // execution-context reads are bounded. A real v9 database first
        // validates the full pre-v9 ledger during migration and then relies on
        // immutable/contiguous triggers; corruption in a selected row or tail
        // still fails closed.
        corrupt_unrelated_run_event(&paths.database, LOCAL_DEMO_RUN_ID, 1);

        assert!(matches!(
            store.storage.load_run(LOCAL_DEMO_RUN_ID).await,
            Err(StorageError::UnsupportedPayloadVersion { version: 99, .. })
        ));

        let approved = store
            .review_for_actor(
                TEST_OWNER_ID,
                LOCAL_DEMO_RUN_ID,
                "APR-DEV-1",
                approval_request(ReviewDecision::Approve),
                "point-query-review",
            )
            .await
            .unwrap();
        assert_eq!(approved.run.status, RunStatus::Queued);

        store.dispatch_pending().await.unwrap();
        assert_eq!(
            store.current_run().await.unwrap().status,
            RunStatus::Succeeded
        );
        assert_eq!(directory_entries(&paths.marker_root), 1);
        assert!(matches!(
            store.storage.load_run(LOCAL_DEMO_RUN_ID).await,
            Err(StorageError::UnsupportedPayloadVersion { version: 99, .. })
        ));
    }

    #[tokio::test]
    async fn rejected_local_call_never_creates_a_marker_or_dispatch_job() {
        let paths = TestPaths::new("local-reject");
        let store = local_store(&paths, false).await;
        let response = store
            .review_for_actor(
                TEST_OWNER_ID,
                LOCAL_DEMO_RUN_ID,
                "APR-DEV-1",
                approval_request(ReviewDecision::Reject),
                "reject-local",
            )
            .await
            .unwrap();

        assert_eq!(response.run.status, RunStatus::Blocked);
        store.dispatch_pending().await.unwrap();
        assert_eq!(directory_entries(&paths.marker_root), 0);
        assert!(
            store
                .storage
                .dispatch_job(LOCAL_MARKER_CALL_ID)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn revoked_owner_dispatch_is_rejected_before_the_connector_runs() {
        for revocation in [ActorRevocation::Member, ActorRevocation::Disabled] {
            let label = format!("dispatch-revoked-{}", revocation.label());
            let paths = TestPaths::new(&label);
            let store = local_store(&paths, false).await;
            let approved = store
                .review_for_actor(
                    TEST_OWNER_ID,
                    LOCAL_DEMO_RUN_ID,
                    "APR-DEV-1",
                    approval_request(ReviewDecision::Approve),
                    &format!("approve-{label}"),
                )
                .await
                .unwrap();
            assert_eq!(approved.run.status, RunStatus::Queued);
            let mut feed = store
                .event_feed_for_actor(TEST_OWNER_ID, LOCAL_DEMO_RUN_ID, approved.event.sequence)
                .await
                .unwrap();

            revoke_test_actor(&paths.database, revocation);
            store.dispatch_pending().await.unwrap();

            assert_eq!(directory_entries(&paths.marker_root), 0);
            let job = store
                .storage
                .dispatch_job(LOCAL_MARKER_CALL_ID)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(job.status, DispatchStatus::Rejected);
            assert_eq!(job.attempt, 0);
            assert!(job.started_at.is_none());
            assert!(job.start_event_sequence.is_none());
            assert_eq!(
                job.authorization_error_json
                    .as_ref()
                    .and_then(|error| error.get("code"))
                    .and_then(serde_json::Value::as_str),
                Some("authorization_revoked")
            );

            let detail = store.run_detail(LOCAL_DEMO_RUN_ID).await.unwrap();
            assert_eq!(detail.run.status, RunStatus::NeedsAttention);
            let rejection = detail.events.last().unwrap();
            assert_eq!(
                rejection.metadata.get("executor_invoked"),
                Some(&serde_json::Value::Bool(false))
            );
            assert_eq!(
                job.result_event_sequence,
                Some(rejection.sequence),
                "the rejected queue record must reference the durable rejection event"
            );
            assert!(matches!(
                rejection.data.as_ref(),
                Some(RunEventData::ToolResult {
                    outcome: ToolOutcome::NotDispatched {
                        reason: NotDispatchedReason::AuthorizationRevoked,
                        ..
                    },
                    status: ToolCallStatus::NotDispatched,
                    ..
                })
            ));
            let published =
                tokio::time::timeout(std::time::Duration::from_secs(1), feed.receiver.recv())
                    .await
                    .expect("runtime must publish the committed authorization rejection")
                    .unwrap();
            assert_eq!(published.run_id, LOCAL_DEMO_RUN_ID);
            assert_eq!(published.event, *rejection);
            assert!(matches!(
                feed.receiver.try_recv(),
                Err(broadcast::error::TryRecvError::Empty)
            ));
        }
    }

    #[tokio::test]
    async fn disabled_reply_actor_is_interrupted_without_exposing_a_claimed_job() {
        let paths = TestPaths::new("reply-actor-disabled");
        let store = local_store(&paths, false).await;
        let job_id = "reply-runtime-authorization-revoked";
        let enqueued = store
            .start_turn_and_enqueue_reply_for_actor(
                TEST_OWNER_ID,
                LOCAL_DEMO_SESSION_ID,
                StartTurnRequest {
                    turn_id: "turn-runtime-authorization-revoked".into(),
                    user_message: "Do not call a provider after authorization is revoked.".into(),
                    expected_sequence: 2,
                },
                "enqueue-runtime-authorization-revoked",
                ReplyJobSpec {
                    id: job_id.into(),
                    actor_user_id: TEST_OWNER_ID.into(),
                    provider_name: "provider-must-not-run".into(),
                    model_name: Some("model-must-not-run".into()),
                    request_json: serde_json::json!({"prompt": "must remain durable only"}),
                },
            )
            .await
            .unwrap();
        assert_eq!(enqueued.job.status, ReplyJobStatus::Queued);
        let mut feed = store
            .session_event_feed_for_actor(
                TEST_OWNER_ID,
                LOCAL_DEMO_SESSION_ID,
                enqueued.start.event.sequence,
            )
            .await
            .unwrap();

        revoke_test_actor(&paths.database, ActorRevocation::Disabled);
        assert!(matches!(
            store.claim_next_reply().await.unwrap(),
            ReplyClaimOutcome::NotAvailable
        ));

        let job = store.reply_job(job_id).await.unwrap().unwrap();
        assert_eq!(job.status, ReplyJobStatus::Failed);
        assert_eq!(job.attempt, 1);
        assert_eq!(
            job.error_json
                .as_ref()
                .and_then(|error| error.get("code"))
                .and_then(serde_json::Value::as_str),
            Some("authorization_revoked")
        );
        let detail = store.get_session(LOCAL_DEMO_SESSION_ID).await.unwrap();
        assert_eq!(detail.session.status, SessionStatus::NeedsAttention);
        let interruption = detail.events.last().unwrap();
        assert!(matches!(
            &interruption.data,
            SessionEventData::TurnInterrupted { turn_id, .. }
                if turn_id == "turn-runtime-authorization-revoked"
        ));
        let published =
            tokio::time::timeout(std::time::Duration::from_secs(1), feed.receiver.recv())
                .await
                .expect("runtime must publish the committed reply interruption")
                .unwrap();
        assert_eq!(published.session_id, LOCAL_DEMO_SESSION_ID);
        assert_eq!(published.event, *interruption);
        assert!(matches!(
            feed.receiver.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn started_call_becomes_outcome_unknown_after_restart_and_is_not_retried() {
        let paths = TestPaths::new("recovery");
        let store = local_store(&paths, false).await;
        store
            .review_for_actor(
                TEST_OWNER_ID,
                LOCAL_DEMO_RUN_ID,
                "APR-DEV-1",
                approval_request(ReviewDecision::Approve),
                "recovery-review",
            )
            .await
            .unwrap();
        let claimed = store.claim_next_dispatch().await.unwrap().unwrap();
        assert_eq!(claimed.job.status, DispatchStatus::Started);
        assert_eq!(directory_entries(&paths.marker_root), 0);
        drop(store);

        let storage = SqliteStore::open(&paths.database).await.unwrap();
        let reopened = DemoStore::from_storage(
            storage,
            DemoProfile::LocalDevelopment {
                marker_root: paths.marker_root.clone(),
            },
            false,
        )
        .await
        .unwrap();
        let detail = reopened.run_detail(LOCAL_DEMO_RUN_ID).await.unwrap();
        assert_eq!(detail.run.status, RunStatus::NeedsAttention);
        assert!(matches!(
            detail.events.last().and_then(|event| event.data.as_ref()),
            Some(RunEventData::ToolResult {
                outcome: ToolOutcome::OutcomeUnknown { .. },
                status: ToolCallStatus::OutcomeUnknown,
                ..
            })
        ));
        reopened.dispatch_pending().await.unwrap();
        assert_eq!(directory_entries(&paths.marker_root), 0);
        let job = reopened
            .storage
            .dispatch_job(LOCAL_MARKER_CALL_ID)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(job.status, DispatchStatus::Finished);
        assert_eq!(job.attempt, 1);
    }

    #[tokio::test]
    async fn one_key_cannot_be_reused_for_another_approval_decision() {
        let store = production_store(false).await;
        store
            .review_for_actor(
                TEST_OWNER_ID,
                protocol::DEMO_RUN_ID,
                "APR-901",
                approval_request(ReviewDecision::Approve),
                "same-key",
            )
            .await
            .unwrap();
        let error = store
            .review_for_actor(
                TEST_OWNER_ID,
                protocol::DEMO_RUN_ID,
                "APR-901",
                approval_request(ReviewDecision::Reject),
                "same-key",
            )
            .await
            .unwrap_err();
        assert!(matches!(error, StoreError::IdempotencyConflict));
    }

    #[tokio::test]
    async fn persistent_database_rejects_a_second_runtime_owner() {
        let paths = TestPaths::new("single-owner");
        let first = DemoStore::open(&paths.database).await.unwrap();
        let error = match DemoStore::open(&paths.database).await {
            Ok(_) => panic!("a second runtime must not open the same persistent database"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            StoreError::Storage(StorageError::DatabaseLocked(_))
        ));

        drop(first);
        DemoStore::open(&paths.database).await.unwrap();
    }

    #[tokio::test]
    async fn persistent_database_cannot_change_runtime_profile() {
        let paths = TestPaths::new("profile-identity");
        let production = DemoStore::open(&paths.database).await.unwrap();
        drop(production);

        let error = match DemoStore::open_local(&paths.database, &paths.marker_root).await {
            Ok(_) => panic!("a production database must not be adopted by a local profile"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            StoreError::Storage(StorageError::RuntimeIdentityMismatch { .. })
        ));

        DemoStore::open(&paths.database).await.unwrap();
    }

    #[tokio::test]
    async fn compatible_pre_identity_database_is_adopted_once() {
        let paths = TestPaths::new("legacy-identity");
        let scenario = DemoScenario::zr_1842();
        let storage = SqliteStore::open(&paths.database).await.unwrap();
        storage
            .seed_if_empty(snapshot_from_scenario(&scenario), scenario.events)
            .await
            .unwrap();
        drop(storage);

        let store = DemoStore::open(&paths.database).await.unwrap();
        assert_eq!(store.current_run().await.unwrap().id, protocol::DEMO_RUN_ID);
    }

    #[tokio::test]
    async fn mismatched_policy_id_is_rejected_before_dispatch_admission() {
        let store = production_store(false).await;
        let error = enqueue_job_with_identity(
            &store,
            "local-development",
            PRODUCTION_POLICY_REVISION,
            "wrong-policy-id",
        )
        .await
        .unwrap_err();
        assert!(matches!(error, StorageError::InvalidDispatchTransition(_)));
        assert!(
            store
                .storage
                .dispatch_job(PRODUCTION_DEMO_CALL_ID)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store.current_run().await.unwrap().status,
            RunStatus::WaitingForApproval
        );
    }

    #[tokio::test]
    async fn mismatched_policy_revision_is_rejected_before_dispatch_admission() {
        let store = production_store(false).await;
        let error = enqueue_job_with_identity(
            &store,
            PRODUCTION_POLICY_ID,
            "production-guarded/v0",
            "wrong-policy-revision",
        )
        .await
        .unwrap_err();
        assert!(matches!(error, StorageError::InvalidDispatchTransition(_)));
        assert!(
            store
                .storage
                .dispatch_job(PRODUCTION_DEMO_CALL_ID)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store.current_run().await.unwrap().status,
            RunStatus::WaitingForApproval
        );
    }

    async fn enqueue_job_with_identity(
        store: &DemoStore,
        policy_id: &str,
        policy_revision: &str,
        idempotency_key: &str,
    ) -> Result<DispatchJob, StorageError> {
        let context = store
            .storage
            .review_context(protocol::DEMO_RUN_ID, "APR-901")
            .await
            .unwrap();
        let (pending, call) = pending_approval_and_call(&context, "APR-901").unwrap();
        let expected_sequence = context.snapshot.run.sequence;
        let mut transition = apply_review(
            &context.snapshot.run,
            &pending,
            ReviewDecision::Approve,
            Some("identity guard fixture"),
            next_sequence(expected_sequence).unwrap(),
            now(),
        )
        .unwrap();
        transition.event.approval.as_mut().unwrap().policy_revision = Some(policy_revision.into());
        let mut snapshot = context.snapshot;
        snapshot.run = transition.run.clone();
        let response = ReviewResponse {
            run: transition.run,
            event: transition.event.clone(),
            replayed: false,
        };
        let outcome = store
            .storage
            .commit_review_for_actor(
                TEST_OWNER_ID,
                ReviewCommit {
                    expected_sequence,
                    snapshot,
                    event: transition.event,
                    idempotency_key: idempotency_key.into(),
                    request_fingerprint: format!(r#"{{"fixture":"{idempotency_key}"}}"#),
                    response,
                    dispatch: Some(DispatchJobSpec {
                        call_id: call.call_id.clone(),
                        approval_id: pending.id,
                        approving_actor_user_id: TEST_OWNER_ID.into(),
                        tool_name: call.tool,
                        tool_version: call.tool_version,
                        effect: call.effect,
                        args_json: call.arguments,
                        args_digest: call.arguments_digest,
                        policy_id: policy_id.into(),
                        policy_revision: policy_revision.into(),
                        sandbox_profile: call.sandbox_profile,
                    }),
                },
            )
            .await?;
        assert_eq!(outcome, CommitOutcome::Committed);
        Ok(store
            .storage
            .dispatch_job(&call.call_id)
            .await?
            .expect("committed dispatch job must be readable"))
    }

    async fn production_store(auto_dispatch: bool) -> DemoStore {
        let store = DemoStore::from_storage(
            SqliteStore::open(":memory:").await.unwrap(),
            DemoProfile::ProductionGuarded,
            auto_dispatch,
        )
        .await
        .unwrap();
        bootstrap_test_owner(&store).await;
        store
    }

    async fn local_store(paths: &TestPaths, auto_dispatch: bool) -> DemoStore {
        let store = DemoStore::from_storage(
            SqliteStore::open(&paths.database).await.unwrap(),
            DemoProfile::LocalDevelopment {
                marker_root: paths.marker_root.clone(),
            },
            auto_dispatch,
        )
        .await
        .unwrap();
        bootstrap_test_owner(&store).await;
        store
    }

    async fn bootstrap_test_owner(store: &DemoStore) {
        let bootstrap_token_hash = "a".repeat(64);
        let expiry = "2999-01-01T00:00:00.000Z";
        store
            .replace_bootstrap_token(&bootstrap_token_hash, expiry)
            .await
            .unwrap();
        let (owner, _) = store
            .bootstrap_owner(BootstrapOwnerCommit {
                bootstrap_token_hash,
                user_id: TEST_OWNER_ID.into(),
                username: "runtime-owner".into(),
                password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGlnaWVzdA".into(),
                session_token_hash: "b".repeat(64),
                csrf_hash: "c".repeat(64),
                session_expires_at: expiry.into(),
            })
            .await
            .unwrap();
        assert_eq!(owner.id, TEST_OWNER_ID);
    }

    #[derive(Clone, Copy)]
    enum ActorRevocation {
        Member,
        Disabled,
    }

    impl ActorRevocation {
        fn label(self) -> &'static str {
            match self {
                Self::Member => "member",
                Self::Disabled => "disabled",
            }
        }
    }

    fn revoke_test_actor(path: &Path, revocation: ActorRevocation) {
        let connection = Connection::open(path).unwrap();
        connection
            .busy_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let changed = match revocation {
            ActorRevocation::Member => connection.execute(
                "UPDATE users SET role = 'member', updated_at = ?1 WHERE id = ?2",
                params![timestamp, TEST_OWNER_ID],
            ),
            ActorRevocation::Disabled => connection.execute(
                "UPDATE users SET status = 'disabled', updated_at = ?1 WHERE id = ?2",
                params![timestamp, TEST_OWNER_ID],
            ),
        }
        .unwrap();
        assert_eq!(changed, 1);
    }

    fn corrupt_unrelated_run_event(path: &Path, run_id: &str, sequence: i64) {
        let connection = Connection::open(path).unwrap();
        connection
            .execute_batch("DROP TRIGGER run_events_reject_update;")
            .unwrap();
        assert_eq!(
            connection
                .execute(
                    "UPDATE run_events SET payload_version = 99 WHERE run_id = ?1 AND sequence = ?2",
                    params![run_id, sequence],
                )
                .unwrap(),
            1
        );
        connection
            .execute_batch(
                r#"CREATE TRIGGER run_events_reject_update
                   BEFORE UPDATE ON run_events
                   BEGIN
                       SELECT RAISE(ABORT, 'run_events are append-only');
                   END;"#,
            )
            .unwrap();
    }

    fn directory_entries(path: &Path) -> usize {
        fs::read_dir(path).unwrap().count()
    }

    struct TestPaths {
        root: PathBuf,
        database: PathBuf,
        marker_root: PathBuf,
    }

    impl TestPaths {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let serial = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "zeus-runtime-{label}-{}-{nonce}-{serial}",
                std::process::id()
            ));
            fs::create_dir(&root).unwrap();
            Self {
                database: root.join("zeus.db"),
                marker_root: root.join("markers"),
                root,
            }
        }
    }

    impl Drop for TestPaths {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
