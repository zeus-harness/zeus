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
    Approval, ApprovalStatus, CreateSessionRequest, CreateSessionResponse, FlushSessionRequest,
    FlushSessionResponse, NotDispatchedReason, OverviewResponse, PolicyDecision,
    ResumeSessionRequest, ResumeSessionResponse, ReviewDecision, ReviewRequest, ReviewResponse,
    RunDetail, RunEvent, RunEventData, RunSummary, SessionDetail, SessionEvent, SessionEventData,
    SessionSummary, StartTurnRequest, StartTurnResponse, ToolCall, ToolExecutorStatus, ToolOutcome,
};
pub use storage::{
    AuthPrincipal, AuthSessionCommit, BootstrapOwnerCommit, ReplyClaimOutcome, ReplyCompletion,
    ReplyFailureCommit, ReplyJob, ReplyJobEnqueueResponse, ReplyJobSpec, ReplyJobStatus,
    ReplyOutcomeUnknownCommit, ReplySuccessCommit, StoredCredential, StoredPreferences, StoredUser,
    StoredUserRole, StoredUserStatus,
};
use storage::{
    ClaimOutcome, CommitOutcome, DispatchCompleteCommit, DispatchJob, DispatchJobSpec,
    DispatchRecoveryCommit, DispatchStartCommit, ReviewCommit, ReviewReceipt, RunSnapshot,
    RuntimeIdentity, SqliteStore, StorageError, StoredRun,
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

#[derive(Clone, Debug)]
pub struct PublishedSessionEvent {
    pub session_id: String,
    pub event: SessionEvent,
}

pub struct SessionEventFeed {
    pub replay: Vec<SessionEvent>,
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
            StorageError::InvalidAccountData(detail) => Self::InvalidAccountData(detail),
            StorageError::RunAlreadyAttached { run_id, session_id } => {
                Self::RunAlreadyAttached { run_id, session_id }
            }
            StorageError::InvalidSessionTransition(detail) => {
                Self::InvalidSessionTransition(detail)
            }
            StorageError::EmptyIdempotencyKey => Self::EmptyIdempotencyKey,
            StorageError::IdempotencyConflict => Self::IdempotencyConflict,
            StorageError::ConcurrentModification => Self::ConcurrentModification,
            other => Self::Storage(other),
        }
    }
}

impl DemoStore {
    /// Opens the fail-closed production demonstration.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_with_profile(path, DemoProfile::ProductionGuarded).await
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

    pub async fn open_with_profile(
        path: impl AsRef<Path>,
        profile: DemoProfile,
    ) -> Result<Self, StoreError> {
        let storage = SqliteStore::open(path).await?;
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
        let primary_session = storage.get_session(primary_session_id).await?;
        if !primary_session
            .run_ids
            .iter()
            .any(|id| id == &primary_run_id)
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
        })
    }

    pub async fn run_detail(&self, run_id: &str) -> Result<RunDetail, StoreError> {
        let stored = self.storage.load_run(run_id).await?;
        Ok(RunDetail {
            incident: stored.snapshot.incident,
            run: stored.snapshot.run,
            events: stored.events,
        })
    }

    pub async fn events_after(
        &self,
        run_id: &str,
        after: u64,
    ) -> Result<Vec<RunEvent>, StoreError> {
        Ok(self.storage.events_after(run_id, after).await?)
    }

    /// Subscribes before taking the durable replay snapshot. Consumers discard
    /// broadcasts at or below their cursor, avoiding both gaps and duplicates.
    pub async fn event_feed(&self, run_id: &str, after: u64) -> Result<EventFeed, StoreError> {
        let receiver = self.publisher.subscribe();
        let replay = self.events_after(run_id, after).await?;
        Ok(EventFeed { replay, receiver })
    }

    pub async fn list_sessions(&self) -> Result<Vec<SessionSummary>, StoreError> {
        Ok(self.storage.list_sessions().await?)
    }

    pub async fn get_session(&self, session_id: &str) -> Result<SessionDetail, StoreError> {
        validate_canonical_session_value(session_id, "session ID")?;
        Ok(self.storage.get_session(session_id).await?)
    }

    pub async fn session_events_after(
        &self,
        session_id: &str,
        after: u64,
    ) -> Result<Vec<SessionEvent>, StoreError> {
        validate_canonical_session_value(session_id, "session ID")?;
        validate_session_sequence(after, "session event cursor")?;
        Ok(self.storage.session_events_after(session_id, after).await?)
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
        validate_canonical_session_value(session_id, "session ID")?;
        let receiver = self.session_publisher.subscribe();
        let replay = self.session_events_after(session_id, after).await?;
        Ok(SessionEventFeed { replay, receiver })
    }

    pub async fn create_session(
        &self,
        request: CreateSessionRequest,
        idempotency_key: &str,
    ) -> Result<CreateSessionResponse, StoreError> {
        validate_canonical_session_value(&request.id, "session ID")?;
        validate_canonical_session_value(&request.title, "session title")?;
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
        validate_canonical_session_value(&request.id, "session ID")?;
        validate_canonical_session_value(&request.title, "session title")?;
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

    pub async fn resume_session(
        &self,
        session_id: &str,
        request: ResumeSessionRequest,
        idempotency_key: &str,
    ) -> Result<ResumeSessionResponse, StoreError> {
        validate_canonical_session_value(session_id, "session ID")?;
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

    pub async fn start_turn(
        &self,
        session_id: &str,
        request: StartTurnRequest,
        idempotency_key: &str,
    ) -> Result<StartTurnResponse, StoreError> {
        validate_canonical_session_value(session_id, "session ID")?;
        validate_canonical_session_value(&request.turn_id, "turn ID")?;
        validate_session_message(&request.user_message, "user message")?;
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

    pub async fn start_turn_and_enqueue_reply(
        &self,
        session_id: &str,
        request: StartTurnRequest,
        idempotency_key: &str,
        job: ReplyJobSpec,
    ) -> Result<ReplyJobEnqueueResponse, StoreError> {
        validate_canonical_session_value(session_id, "session ID")?;
        validate_canonical_session_value(&request.turn_id, "turn ID")?;
        validate_session_message(&request.user_message, "user message")?;
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

    pub async fn claim_next_reply(&self) -> Result<ReplyClaimOutcome, StoreError> {
        Ok(self.storage.claim_next_reply().await?)
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
        validate_canonical_session_value(session_id, "session ID")?;
        validate_canonical_session_value(&request.turn_id, "turn ID")?;
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

    /// Records one call-bound approval decision. Approving only queues the
    /// exact call; it does not claim that execution has started.
    pub async fn review(
        &self,
        run_id: &str,
        approval_id: &str,
        request: ReviewRequest,
        idempotency_key: &str,
    ) -> Result<ReviewResponse, StoreError> {
        let idempotency_key = idempotency_key.trim();
        if idempotency_key.is_empty() {
            return Err(StoreError::EmptyIdempotencyKey);
        }
        let fingerprint = review_fingerprint(run_id, approval_id, &request)?;

        if let Some(receipt) = self.storage.review_receipt(idempotency_key).await? {
            let response = replay_receipt(receipt, &fingerprint)?;
            self.kick_dispatcher();
            return Ok(response);
        }

        let stored = self.storage.load_run(run_id).await?;
        let (pending, call) = pending_approval_and_call(&stored, approval_id)?;
        let approving = request.decision == ReviewDecision::Approve;
        if approving {
            self.validate_pending_policy(&stored.snapshot.run, &pending, &call)?;
        }

        let expected_sequence = stored.snapshot.run.sequence;
        let transition = apply_review(
            &stored.snapshot.run,
            &pending,
            request.decision.clone(),
            request.note.as_deref(),
            next_sequence(expected_sequence)?,
            now(),
        )?;

        let dispatch = if approving {
            let approved = transition.event.approval.as_ref().ok_or_else(|| {
                StoreError::ExecutionInvariant(
                    "an approved transition is missing its approval binding".into(),
                )
            })?;
            let evaluation =
                self.policy
                    .guard_dispatch(&stored.snapshot.run.environment, &call, Some(approved));
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
            })
        } else {
            None
        };

        let mut snapshot = stored.snapshot;
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
        let outcome = self
            .storage
            .commit_review(ReviewCommit {
                expected_sequence,
                snapshot,
                event: transition.event,
                idempotency_key: idempotency_key.to_owned(),
                request_fingerprint: fingerprint.clone(),
                response: response.clone(),
                dispatch,
            })
            .await?;

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

    async fn recover_started_reply_jobs(&self) -> Result<(), StoreError> {
        let recovered = self.storage.recover_started_replies().await?;
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
        Ok(())
    }

    async fn recover_open_session_turns(&self) -> Result<(), StoreError> {
        let sessions = self.storage.list_sessions().await?;
        let recovered = self.storage.recover_open_turns().await?;
        for event in recovered {
            let turn_id = match &event.data {
                SessionEventData::TurnInterrupted { turn_id, .. } => turn_id,
                _ => {
                    return Err(StoreError::ExecutionInvariant(
                        "open-turn recovery returned a non-interruption session event".into(),
                    ));
                }
            };
            let session_id = sessions
                .iter()
                .find(|session| session.active_turn_id.as_deref() == Some(turn_id.as_str()))
                .map(|session| session.id.as_str())
                .ok_or_else(|| {
                    StoreError::ExecutionInvariant(
                        "open-turn recovery returned an event without an owning session".into(),
                    )
                })?;
            self.publish_session_event(session_id, event);
        }
        Ok(())
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
        let Some(job) = self.storage.peek_next_dispatch().await? else {
            return Ok(None);
        };
        self.validate_dispatch_job_identity(&job)?;
        let stored = self.storage.load_run(&job.run_id).await?;
        let (call, approval) = bindings_for_job(&stored, &job)?;
        let environment = stored.snapshot.run.environment.clone();
        let expected_sequence = stored.snapshot.run.sequence;
        let transition = start_tool_dispatch(
            &stored.snapshot.run,
            &approval,
            &call,
            executor_label(&self.registry, &call),
            next_sequence(expected_sequence)?,
            now(),
        )?;
        let mut snapshot = stored.snapshot;
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
                Ok(Some(ClaimedDispatch {
                    job: *claimed_job,
                    call,
                    approval,
                    environment,
                }))
            }
            ClaimOutcome::NotAvailable => Ok(None),
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
        let stored = self.storage.load_run(&claimed.job.run_id).await?;
        let expected_sequence = stored.snapshot.run.sequence;
        let transition = apply_tool_result(
            &stored.snapshot.run,
            &claimed.call,
            outcome.clone(),
            next_sequence(expected_sequence)?,
            now(),
        )?;
        let mut snapshot = stored.snapshot;
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
        for job in self.storage.started_dispatches().await? {
            self.validate_dispatch_job_identity(&job)?;
            let stored = self.storage.load_run(&job.run_id).await?;
            let (call, _) = bindings_for_job(&stored, &job)?;
            let outcome = ToolOutcome::OutcomeUnknown {
                summary: "Zeus restarted after the durable dispatch checkpoint but before a durable result; the call was not retried.".into(),
            };
            let expected_sequence = stored.snapshot.run.sequence;
            let transition = apply_tool_result(
                &stored.snapshot.run,
                &call,
                outcome.clone(),
                next_sequence(expected_sequence)?,
                now(),
            )?;
            let mut snapshot = stored.snapshot;
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
        Ok(())
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
    stored: &StoredRun,
    approval_id: &str,
) -> Result<(Approval, ToolCall), StoreError> {
    let approval = stored
        .events
        .iter()
        .rev()
        .filter_map(|event| event.approval.as_ref())
        .find(|approval| approval.id == approval_id && approval.status == ApprovalStatus::Pending)
        .cloned()
        .ok_or_else(|| StoreError::ApprovalNotPending {
            run_id: stored.snapshot.run.id.clone(),
            approval_id: approval_id.to_owned(),
        })?;
    let call_id = approval
        .call_id
        .as_deref()
        .ok_or(KernelError::ApprovalBindingIncomplete)?;
    let call = stored
        .events
        .iter()
        .find_map(|event| match &event.data {
            Some(RunEventData::ToolCallRequested { call, .. }) if call.call_id == call_id => {
                Some(call.clone())
            }
            _ => None,
        })
        .ok_or(StoreError::ToolCallNotFound)?;
    Ok((approval, call))
}

fn bindings_for_job(
    stored: &StoredRun,
    job: &DispatchJob,
) -> Result<(ToolCall, Approval), StoreError> {
    let approval_event = stored
        .events
        .iter()
        .find(|event| event.sequence == job.approval_event_sequence)
        .ok_or_else(|| {
            StoreError::ExecutionInvariant(
                "dispatch approval event is missing from the ledger".into(),
            )
        })?;
    let approval = approval_event
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
    let call = stored
        .events
        .iter()
        .find_map(|event| match &event.data {
            Some(RunEventData::ToolCallRequested { call, .. }) if call.call_id == job.call_id => {
                Some(call.clone())
            }
            _ => None,
        })
        .ok_or(StoreError::ToolCallNotFound)?;

    let matches = job.run_id == stored.snapshot.run.id
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
        RegistryError::Executor(ExecutorError::Unavailable { reason }) => ToolOutcome::Failed {
            summary: format!(
                "The executor was invoked after the checkpoint but reported unavailable: {reason}"
            ),
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
    ToolOutcome::NotDispatched {
        reason,
        summary: summary.into(),
    }
}

fn next_sequence(sequence: u64) -> Result<u64, StoreError> {
    sequence.checked_add(1).ok_or(StoreError::SequenceOverflow)
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn normalized_idempotency_key(key: &str) -> Result<&str, StoreError> {
    let key = key.trim();
    if key.is_empty() {
        Err(StoreError::EmptyIdempotencyKey)
    } else {
        Ok(key)
    }
}

fn validate_canonical_session_value(value: &str, field: &'static str) -> Result<(), StoreError> {
    if value.is_empty() || value.trim() != value {
        Err(StoreError::InvalidSessionRequest(format!(
            "{field} must be non-empty and canonical"
        )))
    } else {
        Ok(())
    }
}

fn validate_session_message(value: &str, field: &'static str) -> Result<(), StoreError> {
    if value.trim().is_empty() {
        Err(StoreError::InvalidSessionRequest(format!(
            "{field} cannot be empty"
        )))
    } else {
        Ok(())
    }
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
        DEMO_RUN_ID, DEMO_SESSION_ID, LOCAL_DEMO_RUN_ID, RunStatus, SessionStatus,
        SessionTurnStatus, ToolCallStatus,
    };
    use storage::DispatchStatus;

    use super::*;

    static NEXT_PATH: AtomicU64 = AtomicU64::new(1);

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
        let replay = store.events_after(protocol::DEMO_RUN_ID, 4).await.unwrap();

        assert_eq!(
            replay
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![5, 6, 7, 8]
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
        .await;
        assert_eq!(queued.status, DispatchStatus::Queued);
        assert_eq!(queued.attempt, 0);
        // Make an accidental `kick_dispatcher` observable without draining the
        // pre-existing queued job during startup.
        store.auto_dispatch = true;
        let run_before = store.run_detail(DEMO_RUN_ID).await.unwrap();
        let mut session_feed = store.session_event_feed(DEMO_SESSION_ID, 2).await.unwrap();
        let mut run_feed = store
            .event_feed(DEMO_RUN_ID, run_before.run.sequence)
            .await
            .unwrap();
        assert!(session_feed.replay.is_empty());
        assert!(run_feed.replay.is_empty());

        let started = store
            .start_turn(
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
            .flush_turn(
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
            .flush_turn(DEMO_SESSION_ID, flush_request, "runtime-flush-isolation")
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

        assert_eq!(store.run_detail(DEMO_RUN_ID).await.unwrap(), run_before);
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
        let run_before = store.run_detail(DEMO_RUN_ID).await.unwrap();
        store
            .start_turn(
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
        let detail = reopened.get_session(DEMO_SESSION_ID).await.unwrap();
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
        assert_eq!(reopened.run_detail(DEMO_RUN_ID).await.unwrap(), run_before);

        let resume_request = ResumeSessionRequest {
            expected_sequence: 4,
        };
        let resumed = reopened
            .resume_session(
                DEMO_SESSION_ID,
                resume_request.clone(),
                "runtime-resume-recovery",
            )
            .await
            .unwrap();
        assert_eq!(resumed.session.status, SessionStatus::Ready);
        assert_eq!(resumed.session.sequence, 5);
        let replayed = reopened
            .resume_session(DEMO_SESSION_ID, resume_request, "runtime-resume-recovery")
            .await
            .unwrap();
        assert!(replayed.replayed);
        assert_eq!(
            reopened
                .get_session(DEMO_SESSION_ID)
                .await
                .unwrap()
                .session
                .sequence,
            5
        );
        assert_eq!(reopened.run_detail(DEMO_RUN_ID).await.unwrap(), run_before);
    }

    #[tokio::test]
    async fn overview_and_session_queries_expose_the_stable_primary_session() {
        let store = production_store(false).await;
        let overview = store.overview().await.unwrap();
        assert_eq!(overview.primary_session_id, DEMO_SESSION_ID);
        let sessions = store.list_sessions().await.unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, DEMO_SESSION_ID);
        let detail = store.get_session(DEMO_SESSION_ID).await.unwrap();
        assert_eq!(detail.run_ids, vec![DEMO_RUN_ID]);
        assert_eq!(detail.events.len(), 2);
    }

    #[tokio::test]
    async fn production_approval_is_never_reported_as_execution_success() {
        let store = production_store(false).await;
        let response = store
            .review(
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
        assert_eq!(job.status, DispatchStatus::Finished);
        assert_eq!(job.attempt, 1);
    }

    #[tokio::test]
    async fn local_approval_executes_one_marker_and_replay_does_not_execute_twice() {
        let paths = TestPaths::new("local-success");
        let store = local_store(&paths, false).await;
        let request = approval_request(ReviewDecision::Approve);
        let first = store
            .review(
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
            .review(LOCAL_DEMO_RUN_ID, "APR-DEV-1", request, "local-review")
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
    async fn rejected_local_call_never_creates_a_marker_or_dispatch_job() {
        let paths = TestPaths::new("local-reject");
        let store = local_store(&paths, false).await;
        let response = store
            .review(
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
    async fn started_call_becomes_outcome_unknown_after_restart_and_is_not_retried() {
        let paths = TestPaths::new("recovery");
        let store = local_store(&paths, false).await;
        store
            .review(
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
            .review(
                protocol::DEMO_RUN_ID,
                "APR-901",
                approval_request(ReviewDecision::Approve),
                "same-key",
            )
            .await
            .unwrap();
        let error = store
            .review(
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
    async fn mismatched_queued_job_is_rejected_before_claim() {
        let store = production_store(false).await;
        let job = enqueue_job_with_identity(
            &store,
            "local-development",
            PRODUCTION_POLICY_REVISION,
            "wrong-policy-id",
        )
        .await;

        let error = store.dispatch_pending().await.unwrap_err();
        assert!(matches!(error, StoreError::ExecutionInvariant(_)));
        let unchanged = store
            .storage
            .dispatch_job(&job.call_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(unchanged.status, DispatchStatus::Queued);
        assert_eq!(unchanged.attempt, 0);
        assert_eq!(store.current_run().await.unwrap().status, RunStatus::Queued);
    }

    #[tokio::test]
    async fn mismatched_started_job_is_rejected_before_recovery() {
        let store = production_store(false).await;
        let job = enqueue_job_with_identity(
            &store,
            PRODUCTION_POLICY_ID,
            "production-guarded/v0",
            "wrong-policy-revision",
        )
        .await;
        claim_job_directly(&store, &job).await;

        let error = store.recover_started_dispatches().await.unwrap_err();
        assert!(matches!(error, StoreError::ExecutionInvariant(_)));
        let unchanged = store
            .storage
            .dispatch_job(&job.call_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(unchanged.status, DispatchStatus::Started);
        assert_eq!(unchanged.attempt, 1);
        assert_eq!(
            store.current_run().await.unwrap().status,
            RunStatus::Running
        );
    }

    async fn enqueue_job_with_identity(
        store: &DemoStore,
        policy_id: &str,
        policy_revision: &str,
        idempotency_key: &str,
    ) -> DispatchJob {
        let stored = store.storage.load_run(protocol::DEMO_RUN_ID).await.unwrap();
        let (pending, call) = pending_approval_and_call(&stored, "APR-901").unwrap();
        let expected_sequence = stored.snapshot.run.sequence;
        let mut transition = apply_review(
            &stored.snapshot.run,
            &pending,
            ReviewDecision::Approve,
            Some("identity guard fixture"),
            next_sequence(expected_sequence).unwrap(),
            now(),
        )
        .unwrap();
        transition.event.approval.as_mut().unwrap().policy_revision = Some(policy_revision.into());
        let mut snapshot = stored.snapshot;
        snapshot.run = transition.run.clone();
        let response = ReviewResponse {
            run: transition.run,
            event: transition.event.clone(),
            replayed: false,
        };
        let outcome = store
            .storage
            .commit_review(ReviewCommit {
                expected_sequence,
                snapshot,
                event: transition.event,
                idempotency_key: idempotency_key.into(),
                request_fingerprint: format!(r#"{{"fixture":"{idempotency_key}"}}"#),
                response,
                dispatch: Some(DispatchJobSpec {
                    call_id: call.call_id.clone(),
                    approval_id: pending.id,
                    tool_name: call.tool,
                    tool_version: call.tool_version,
                    effect: call.effect,
                    args_json: call.arguments,
                    args_digest: call.arguments_digest,
                    policy_id: policy_id.into(),
                    policy_revision: policy_revision.into(),
                    sandbox_profile: call.sandbox_profile,
                }),
            })
            .await
            .unwrap();
        assert_eq!(outcome, CommitOutcome::Committed);
        store
            .storage
            .dispatch_job(&call.call_id)
            .await
            .unwrap()
            .unwrap()
    }

    async fn claim_job_directly(store: &DemoStore, job: &DispatchJob) {
        let stored = store.storage.load_run(&job.run_id).await.unwrap();
        let (call, approval) = bindings_for_job(&stored, job).unwrap();
        let expected_sequence = stored.snapshot.run.sequence;
        let transition = start_tool_dispatch(
            &stored.snapshot.run,
            &approval,
            &call,
            "identity-guard-test",
            next_sequence(expected_sequence).unwrap(),
            now(),
        )
        .unwrap();
        let mut snapshot = stored.snapshot;
        snapshot.run = transition.run;
        assert!(matches!(
            store
                .storage
                .claim_next_dispatch(DispatchStartCommit {
                    call_id: job.call_id.clone(),
                    expected_sequence,
                    snapshot,
                    event: transition.event,
                })
                .await
                .unwrap(),
            ClaimOutcome::Claimed(_)
        ));
    }

    async fn production_store(auto_dispatch: bool) -> DemoStore {
        DemoStore::from_storage(
            SqliteStore::open(":memory:").await.unwrap(),
            DemoProfile::ProductionGuarded,
            auto_dispatch,
        )
        .await
        .unwrap()
    }

    async fn local_store(paths: &TestPaths, auto_dispatch: bool) -> DemoStore {
        DemoStore::from_storage(
            SqliteStore::open(&paths.database).await.unwrap(),
            DemoProfile::LocalDevelopment {
                marker_root: paths.marker_root.clone(),
            },
            auto_dispatch,
        )
        .await
        .unwrap()
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
