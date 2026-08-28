//! Durable runtime orchestration for the Zeus Alpha vertical slice.
//!
//! The runtime keeps policy, persistence, and execution as separate gates:
//! approval and enqueue commit atomically; a durable dispatch checkpoint is
//! committed before an executor can observe a request; and a started call
//! without a durable result becomes outcome_unknown on restart instead of
//! being retried.

use std::{
    fmt,
    future::Future,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering as AtomicOrdering},
    },
    time::Duration,
};

use authz::{PolicyBuildError, PolicyContext, PolicyEngine, PolicyEvaluation, PolicyRule};
use chrono::{SecondsFormat, Utc};
use connectors::{
    ConnectorConfigError, LOCAL_DEV_ENVIRONMENT, register_local_dev_connectors,
    register_local_terminal_connectors, register_local_workspace_connectors,
    terminal_close_descriptor, terminal_list_descriptor, terminal_open_descriptor,
    terminal_read_descriptor, terminal_send_descriptor, terminal_signal_descriptor,
    workspace_create_file_descriptor, workspace_find_paths_descriptor,
    workspace_insert_text_descriptor, workspace_list_directory_descriptor,
    workspace_read_file_descriptor, workspace_read_lines_descriptor,
    workspace_replace_text_descriptor, workspace_search_text_descriptor,
};
pub use deployment::ManifestEnvelope;
use deployment::{
    AgentDeployment, AgentSpec, ManifestPolicy, ManifestPromptBinding, ManifestProvider,
    ManifestTool,
};
pub use execution::{AgentExecutionExplain, AgentRunEpochExplain};
use kernel::{
    DemoScenario, KernelError, LOCAL_POLICY_REVISION, PRODUCTION_POLICY_REVISION, apply_review,
    apply_tool_result, start_tool_dispatch,
};
pub use knowledge::EntryRevision;
use knowledge::{CorpusRevisionEnvelope, SelectionSnapshotEnvelope, select_context};
use planning::{
    TODO_WRITE_TOOL_NAME, TODO_WRITE_TOOL_VERSION, prepare_todo_write, register_todo_tool,
    todo_write_descriptor,
};
use protocol::{
    Approval, ApprovalStatus, AssistantReplyKind, AttachRunRequest, AttachRunResponse,
    CancelAgentTurnResponse, CreateSessionRequest, CreateSessionResponse, EVENT_PAGE_DEFAULT_LIMIT,
    FlushSessionRequest, FlushSessionResponse, NotDispatchedReason, OverviewResponse,
    PolicyDecision, ResourceEnvelopeError, ResumeSessionRequest, ResumeSessionResponse,
    ReviewDecision, ReviewRequest, ReviewResponse, RunDetail, RunDetailPagination, RunEvent,
    RunEventData, RunEventPage, RunSummary, SessionDetail, SessionEvent, SessionEventData,
    SessionEventPage, SessionSummary, SessionTurn, StartTurnRequest, StartTurnResponse, ToolCall,
    ToolExecutorStatus, ToolOutcome,
};
use serde_json::Value;
use skills::{SkillCatalog, register_skill_tools, skill_tool_descriptors};
pub use storage::{
    AGENT_SYSTEM_PROMPT_MAX_BYTES, AccountAuditArchiveState, AccountAuditCheckpointCommit,
    AccountAuditEvent, AccountAuditPage, AccountAuditPolicy, AccountAuditRollup, AccountAuditState,
    AccountId, AccountReplyProviderCommit, AccountReplyProviderState,
    AccountReplyProviderUpdateResult, AgentFinalCompletion, AgentKnowledgeContextExplain,
    AgentKnowledgeContextSpec, AgentModelClaimOutcome, AgentModelCompletion,
    AgentModelFailureCommit, AgentModelJob, AgentModelJobStatus, AgentModelResolution,
    AgentModelStartOutcome, AgentModelSuccessCommit, AgentOperationClaim, AgentOperationKind,
    AgentPreparedModel, AgentPreparedTool, AgentPromptCommit, AgentPromptRevisionPage,
    AgentPromptRevisionSummary, AgentPromptState, AgentPromptUpdateResult, AgentReviewCommit,
    AgentReviewContext, AgentReviewResult, AgentTerminalCompletion, AgentToolCall,
    AgentToolCallSpec, AgentToolClaimOutcome, AgentToolCompletion, AgentToolCompletionCommit,
    AgentToolOutcomeUnknownCommit, AgentToolStartOutcome, AgentToolWork, AgentTurn,
    AgentTurnEnqueueResponse, AgentTurnReceiptProbe, AgentTurnSpec, AuthPrincipal,
    AuthSessionCommit, AuthSessionId, AuthzContext, BootstrapOwnerCommit, CreateAccountCommit,
    CreateAccountResult, CreateMemberResult, DEFAULT_SESSION_AGENT_PROMPT_REVISION,
    DEFAULT_SESSION_AGENT_SYSTEM_PROMPT, InFlightWorkSummary, KnowledgeCatalogCommit,
    KnowledgeCatalogRevisionPage, KnowledgeCatalogRevisionSummary, KnowledgeCatalogState,
    KnowledgeCatalogUpdateResult, MEMBER_SETUP_TOKEN_TTL_SECONDS, MemberSetupCommit,
    MemberSetupResult, MemberSetupToken, MemberTransitionResult, MembershipRevision,
    MembershipRole, ReplyClaimOutcome, ReplyCompletion, ReplyFailureCommit, ReplyJob,
    ReplyJobEnqueueResponse, ReplyJobSpec, ReplyJobStatus, ReplyOutcomeUnknownCommit,
    ReplySuccessCommit, RotateMemberSetupTokenResult, SESSION_AGENT_PROMPT_ID,
    SessionCompactionClaimOutcome, SessionCompactionFailureCommit, SessionCompactionJob,
    SessionCompactionSuccessCommit, SessionContextCheckpoint, SessionSummaryPage,
    SqliteOperationLimits, SqliteOperationLimitsError, SqlitePhysicalLimits,
    SqlitePhysicalLimitsError, StorageLimits, StorageLimitsError, StoredAccount,
    StoredAccountStatus, StoredCredential, StoredMember, StoredMemberPage, StoredMembershipStatus,
    StoredPreferences, StoredUser, StoredUserRole, StoredUserStatus, SwitchAuthSessionCommit,
    SwitchAuthSessionResult, TransitionMemberCommit, UpdateAccountAuditPolicyCommit,
};
use storage::{
    ClaimOutcome, CommitOutcome, CreateMemberCommit, DispatchCompleteCommit, DispatchContext,
    DispatchJob, DispatchJobSpec, DispatchRecoveryCommit, DispatchStartCommit, ReviewCommit,
    ReviewContext, ReviewReceipt, RotateMemberSetupTokenCommit, RunSnapshot, RuntimeIdentity,
    SqliteStore, StorageError,
};
use terminal::TerminalService;
use thiserror::Error;
use tokio::sync::{Mutex, broadcast};
pub use tools::{ExecutionScope, ToolOutput};
use tools::{ExecutorError, RegistryError, ToolRegistry, arguments_digest, stable_agent_call_id};

const PRODUCTION_POLICY_ID: &str = "production-guarded";
const LOCAL_POLICY_ID: &str = "local-development";
const SESSION_AGENT_SPEC_ID: &str = "zeus-session-agent";
const SESSION_AGENT_SPEC_REVISION: &str = "2";
const SESSION_AGENT_DEPLOYMENT_ID_PREFIX: &str = "zeus-session-agent";
const SESSION_AGENT_DEPLOYMENT_REVISION: &str = "2";
const INTERNAL_PROGRESS_RETRY_DELAY: Duration = Duration::from_millis(25);
const INTERNAL_PROGRESS_RETRY_MAX_DELAY: Duration = Duration::from_secs(1);
const WORKER_IDLE: u8 = 0;
const WORKER_RUNNING: u8 = 1;
const WORKER_PENDING: u8 = 2;

#[derive(Default)]
struct WorkerWakeState {
    state: AtomicU8,
}

impl WorkerWakeState {
    fn request(&self) -> bool {
        loop {
            match self.state.load(AtomicOrdering::Acquire) {
                WORKER_IDLE => {
                    if self
                        .state
                        .compare_exchange(
                            WORKER_IDLE,
                            WORKER_RUNNING,
                            AtomicOrdering::AcqRel,
                            AtomicOrdering::Acquire,
                        )
                        .is_ok()
                    {
                        return true;
                    }
                }
                WORKER_RUNNING => {
                    if self
                        .state
                        .compare_exchange(
                            WORKER_RUNNING,
                            WORKER_PENDING,
                            AtomicOrdering::AcqRel,
                            AtomicOrdering::Acquire,
                        )
                        .is_ok()
                    {
                        return false;
                    }
                }
                WORKER_PENDING => return false,
                _ => unreachable!("invalid worker wake state"),
            }
        }
    }

    fn complete_cycle(&self) -> bool {
        loop {
            match self.state.load(AtomicOrdering::Acquire) {
                WORKER_RUNNING => {
                    if self
                        .state
                        .compare_exchange(
                            WORKER_RUNNING,
                            WORKER_IDLE,
                            AtomicOrdering::AcqRel,
                            AtomicOrdering::Acquire,
                        )
                        .is_ok()
                    {
                        return false;
                    }
                }
                WORKER_PENDING => {
                    if self
                        .state
                        .compare_exchange(
                            WORKER_PENDING,
                            WORKER_RUNNING,
                            AtomicOrdering::AcqRel,
                            AtomicOrdering::Acquire,
                        )
                        .is_ok()
                    {
                        return true;
                    }
                }
                WORKER_IDLE => return false,
                _ => unreachable!("invalid worker wake state"),
            }
        }
    }
}

async fn retry_operation_capacity<T, F, Fut>(mut operation: F) -> Result<T, StoreError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, StoreError>>,
{
    loop {
        match operation().await {
            Err(StoreError::OperationCapacityExceeded) => {
                tokio::time::sleep(INTERNAL_PROGRESS_RETRY_DELAY).await;
            }
            result => return result,
        }
    }
}

/// Keep one exact durable progress step in memory until its outcome is known.
/// The closure may read or write durable state but must never invoke the
/// external operation again.
async fn retry_durable_progress<T, F, Fut>(label: &str, mut operation: F) -> Result<T, StoreError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, StoreError>>,
{
    let mut attempt = 1_u64;
    let mut retry_delay = INTERNAL_PROGRESS_RETRY_DELAY;
    loop {
        match operation().await {
            Ok(completion) => return Ok(completion),
            Err(error) if error.is_retryable_durable_completion_error() => {
                eprintln!(
                    "zeus {label} durable attempt {attempt} failed; retrying the exact step without repeating external I/O: {error}"
                );
                tokio::time::sleep(retry_delay).await;
                retry_delay = retry_delay
                    .saturating_mul(2)
                    .min(INTERNAL_PROGRESS_RETRY_MAX_DELAY);
                attempt = attempt.saturating_add(1);
            }
            Err(error) => return Err(error),
        }
    }
}

/// Selects both the demo fixture and the only tool capability available to it.
///
/// ProductionGuarded intentionally registers no production executor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DemoProfile {
    ProductionGuarded,
    LocalDevelopment {
        marker_root: PathBuf,
        workspace_root: Option<PathBuf>,
    },
}

#[derive(Clone)]
pub struct DemoStore {
    storage: SqliteStore,
    publisher: broadcast::Sender<PublishedEvent>,
    session_publisher: broadcast::Sender<PublishedSessionEvent>,
    policy: Arc<PolicyEngine>,
    registry: Arc<ToolRegistry>,
    terminal_service: Option<Arc<TerminalService>>,
    profile_id: Arc<str>,
    environment: Arc<str>,
    policy_id: Arc<str>,
    policy_revision: Arc<str>,
    primary_session_id: Arc<str>,
    primary_run_id: Arc<str>,
    dispatcher: Arc<Mutex<()>>,
    dispatcher_wake: Arc<WorkerWakeState>,
    auto_dispatch: bool,
}

/// Secret-free tool definition suitable for a model-provider request.
///
/// Execution-owned version, effect, sandbox, and executor fields are omitted;
/// the runtime resolves them from its registry after the model chooses only a
/// name and arguments.
#[derive(Clone, Debug, PartialEq)]
pub struct SessionAgentToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

/// Server-resolved immutable call contract for one Session Agent tool step.
/// Private fields prevent callers from substituting model-selected execution
/// attributes before the runtime performs its final guard.
#[derive(Debug, PartialEq)]
pub struct ResolvedSessionAgentTool {
    call: ToolCall,
    environment: String,
    policy_evaluation: PolicyEvaluation,
}

/// A verified Agent tool call paired with server-derived execution ownership.
///
/// The private fields ensure stateful executors never receive model-selected
/// or caller-substituted ownership context.
#[derive(Debug, PartialEq)]
pub struct ScopedSessionAgentTool {
    resolved: ResolvedSessionAgentTool,
    scope: ExecutionScope,
}

impl ResolvedSessionAgentTool {
    pub const fn call(&self) -> &ToolCall {
        &self.call
    }

    pub fn environment(&self) -> &str {
        &self.environment
    }

    pub const fn policy_evaluation(&self) -> &PolicyEvaluation {
        &self.policy_evaluation
    }
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

/// A one-transport member setup bearer paired with its durable mutation.
///
/// The bearer is deliberately not `Clone` or directly `Debug`; callers should
/// move it into the HTTP response and must never log or persist it.
pub struct IssuedMemberSetupToken<T> {
    pub result: T,
    setup_token: String,
}

impl<T> IssuedMemberSetupToken<T> {
    pub fn expose_secret(&self) -> &str {
        &self.setup_token
    }

    pub fn into_parts(self) -> (T, String) {
        (self.result, self.setup_token)
    }
}

impl<T: fmt::Debug> fmt::Debug for IssuedMemberSetupToken<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedMemberSetupToken")
            .field("result", &self.result)
            .field("setup_token", &"[REDACTED]")
            .finish()
    }
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
    #[error("the authentication session was not found or has expired")]
    AuthSessionNotFound,
    #[error("the current account membership lacks the required capability")]
    PermissionDenied,
    #[error("account member {0} was not found")]
    MemberNotFound(String),
    #[error("account member {0} already exists")]
    MemberAlreadyExists(String),
    #[error("the account membership revision changed concurrently")]
    MembershipRevisionConflict,
    #[error("an account must retain at least one active owner")]
    LastAccountOwner,
    #[error("the member setup credential is invalid or already used")]
    InvalidMemberSetupToken,
    #[error("the member setup credential has expired")]
    MemberSetupExpired,
    #[error("member setup is already complete")]
    MemberSetupAlreadyCompleted,
    #[error("secure member setup credential generation is unavailable")]
    MemberSetupTokenGenerationUnavailable,
    #[error("the account security audit has exhausted its bounded local capacity")]
    AuditStorageExhausted,
    #[error("account audit detail compaction is blocked by legal hold")]
    AuditLegalHold,
    #[error("account audit detail compaction requires an archive checkpoint")]
    AuditArchiveRequired,
    #[error("the account audit policy revision changed concurrently")]
    AuditPolicyConflict,
    #[error("the account audit archive checkpoint changed concurrently or is invalid")]
    AuditCheckpointConflict,
    #[error("the account knowledge catalog revision changed concurrently")]
    KnowledgeCatalogRevisionConflict,
    #[error("account knowledge catalog revision {0} was not found")]
    KnowledgeCatalogRevisionNotFound(u64),
    #[error("invalid account knowledge catalog: {0}")]
    InvalidKnowledgeCatalog(String),
    #[error("the account Agent prompt revision changed concurrently")]
    AgentPromptRevisionConflict,
    #[error("account Agent prompt revision {0} was not found")]
    AgentPromptRevisionNotFound(u64),
    #[error("invalid account Agent prompt: {0}")]
    InvalidAgentPrompt(String),
    #[error("the account reply provider revision changed concurrently")]
    AccountReplyProviderRevisionConflict,
    #[error("invalid account reply provider: {0}")]
    InvalidAccountReplyProvider(String),
    #[error("the durable storage quota is exhausted")]
    StorageQuotaExceeded,
    #[error("SQLite physical storage cannot safely accept this operation")]
    PhysicalStorageExhausted,
    #[error("SQLite operation capacity is exhausted")]
    OperationCapacityExceeded,
    #[error("the durable reply queue is at capacity")]
    ReplyQueueCapacityExceeded,
    #[error("the durable dispatch queue is at capacity")]
    DispatchQueueCapacityExceeded,
    #[error("the authentication session store is at capacity")]
    AuthSessionCapacityExceeded,
    #[error("the durable account set is at capacity")]
    AccountCapacityExceeded,
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
    #[error("agent turn {0} was not found")]
    AgentTurnNotFound(String),
    #[error("agent model job {0} was not found")]
    AgentModelJobNotFound(String),
    #[error("agent tool call {0} was not found")]
    AgentToolCallNotFound(String),
    #[error("the Agent revision changed before cancellation")]
    AgentRevisionConflict,
    #[error("the Agent todo revision changed: expected {expected}, current {current}")]
    AgentTodoRevisionConflict { expected: u64, current: u64 },
    #[error("the Agent external operation has already started")]
    AgentOperationInFlight,
    #[error("the Agent turn is already terminal")]
    AgentAlreadyTerminal,
    #[error("invalid agent state transition: {0}")]
    InvalidAgentTransition(String),
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
            StorageError::AuthSessionNotFound => Self::AuthSessionNotFound,
            StorageError::PermissionDenied => Self::PermissionDenied,
            StorageError::MemberNotFound(id) => Self::MemberNotFound(id),
            StorageError::MemberAlreadyExists(id) => Self::MemberAlreadyExists(id),
            StorageError::MembershipRevisionConflict => Self::MembershipRevisionConflict,
            StorageError::LastAccountOwner => Self::LastAccountOwner,
            StorageError::InvalidMemberSetupToken => Self::InvalidMemberSetupToken,
            StorageError::MemberSetupExpired => Self::MemberSetupExpired,
            StorageError::MemberSetupAlreadyCompleted => Self::MemberSetupAlreadyCompleted,
            StorageError::AuditStorageExhausted => Self::AuditStorageExhausted,
            StorageError::AuditLegalHold => Self::AuditLegalHold,
            StorageError::AuditArchiveRequired => Self::AuditArchiveRequired,
            StorageError::AuditPolicyConflict => Self::AuditPolicyConflict,
            StorageError::AuditCheckpointConflict => Self::AuditCheckpointConflict,
            StorageError::KnowledgeCatalogRevisionConflict => {
                Self::KnowledgeCatalogRevisionConflict
            }
            StorageError::KnowledgeCatalogRevisionNotFound(revision) => {
                Self::KnowledgeCatalogRevisionNotFound(revision)
            }
            StorageError::InvalidKnowledgeCatalog(detail) => Self::InvalidKnowledgeCatalog(detail),
            StorageError::AgentPromptRevisionConflict => Self::AgentPromptRevisionConflict,
            StorageError::AgentPromptRevisionNotFound(revision) => {
                Self::AgentPromptRevisionNotFound(revision)
            }
            StorageError::InvalidAgentPrompt(detail) => Self::InvalidAgentPrompt(detail),
            StorageError::AccountReplyProviderRevisionConflict => {
                Self::AccountReplyProviderRevisionConflict
            }
            StorageError::InvalidAccountReplyProvider(detail) => {
                Self::InvalidAccountReplyProvider(detail)
            }
            StorageError::StorageQuotaExceeded => Self::StorageQuotaExceeded,
            StorageError::PhysicalStorageExhausted => Self::PhysicalStorageExhausted,
            StorageError::OperationCapacityExceeded => Self::OperationCapacityExceeded,
            StorageError::ReplyQueueCapacityExceeded => Self::ReplyQueueCapacityExceeded,
            StorageError::DispatchQueueCapacityExceeded => Self::DispatchQueueCapacityExceeded,
            StorageError::AuthSessionCapacityExceeded => Self::AuthSessionCapacityExceeded,
            StorageError::AccountCapacityExceeded => Self::AccountCapacityExceeded,
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
            StorageError::AgentTurnNotFound(id) => Self::AgentTurnNotFound(id),
            StorageError::AgentModelJobNotFound(id) => Self::AgentModelJobNotFound(id),
            StorageError::AgentToolCallNotFound(id) => Self::AgentToolCallNotFound(id),
            StorageError::AgentRevisionConflict => Self::AgentRevisionConflict,
            StorageError::AgentTodoRevisionConflict { expected, current } => {
                Self::AgentTodoRevisionConflict { expected, current }
            }
            StorageError::AgentOperationInFlight => Self::AgentOperationInFlight,
            StorageError::AgentAlreadyTerminal => Self::AgentAlreadyTerminal,
            StorageError::InvalidAgentTransition(detail) => Self::InvalidAgentTransition(detail),
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

impl StoreError {
    /// Return whether an exact durable completion may be retried without
    /// repeating the external operation it records.
    pub fn is_retryable_durable_completion_error(&self) -> bool {
        match self {
            Self::StorageQuotaExceeded
            | Self::PhysicalStorageExhausted
            | Self::OperationCapacityExceeded
            | Self::ConcurrentModification => true,
            Self::Storage(error) => error.is_retryable_durable_completion_error(),
            _ => false,
        }
    }

    /// Return whether an already-started executor reported an indeterminate
    /// side-effect outcome. This must settle as `outcome_unknown`, never as a
    /// known failure or a retryable operation.
    pub fn is_executor_outcome_unknown(&self) -> bool {
        matches!(
            self,
            Self::Registry(RegistryError::Executor(
                ExecutorError::OutcomeUnknown { .. }
            ))
        )
    }

    /// Preserve a bounded, known executor diagnostic for the model-visible
    /// tool result. This includes semantic validation and optimistic revision
    /// conflicts, but never an indeterminate side-effect outcome.
    pub fn known_executor_failure(&self) -> Option<(&str, &str, bool)> {
        match self {
            Self::Registry(RegistryError::Executor(ExecutorError::Failed {
                code,
                message,
                retryable,
            })) => Some((code.as_str(), message.as_str(), *retryable)),
            _ => None,
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

    pub async fn open_with_limits_and_physical(
        path: impl AsRef<Path>,
        limits: StorageLimits,
        physical_limits: SqlitePhysicalLimits,
    ) -> Result<Self, StoreError> {
        Self::open_with_limits_and_physical_and_operations(
            path,
            limits,
            physical_limits,
            SqliteOperationLimits::default(),
        )
        .await
    }

    pub async fn open_with_limits_and_physical_and_operations(
        path: impl AsRef<Path>,
        limits: StorageLimits,
        physical_limits: SqlitePhysicalLimits,
        operation_limits: SqliteOperationLimits,
    ) -> Result<Self, StoreError> {
        Self::open_with_profile_and_limits_and_physical_and_operations(
            path,
            DemoProfile::ProductionGuarded,
            limits,
            physical_limits,
            operation_limits,
        )
        .await
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
                workspace_root: None,
            },
        )
        .await
    }

    pub async fn open_local_with_workspace(
        path: impl AsRef<Path>,
        marker_root: impl Into<PathBuf>,
        workspace_root: impl Into<PathBuf>,
    ) -> Result<Self, StoreError> {
        Self::open_with_profile(
            path,
            DemoProfile::LocalDevelopment {
                marker_root: marker_root.into(),
                workspace_root: Some(workspace_root.into()),
            },
        )
        .await
    }

    /// Opens local development with an explicitly configured isolated
    /// terminal service and no workspace-file capability.
    pub async fn open_local_with_terminal(
        path: impl AsRef<Path>,
        marker_root: impl Into<PathBuf>,
        terminal_service: Arc<TerminalService>,
    ) -> Result<Self, StoreError> {
        Self::open_local_with_optional_workspace_and_terminal(
            path,
            marker_root.into(),
            None,
            terminal_service,
        )
        .await
    }

    /// Opens local development with rooted workspace tools and an explicitly
    /// configured isolated terminal service. The runtime never constructs a
    /// host-process fallback for this capability.
    pub async fn open_local_with_workspace_and_terminal(
        path: impl AsRef<Path>,
        marker_root: impl Into<PathBuf>,
        workspace_root: impl Into<PathBuf>,
        terminal_service: Arc<TerminalService>,
    ) -> Result<Self, StoreError> {
        Self::open_local_with_optional_workspace_and_terminal(
            path,
            marker_root.into(),
            Some(workspace_root.into()),
            terminal_service,
        )
        .await
    }

    async fn open_local_with_optional_workspace_and_terminal(
        path: impl AsRef<Path>,
        marker_root: PathBuf,
        workspace_root: Option<PathBuf>,
        terminal_service: Arc<TerminalService>,
    ) -> Result<Self, StoreError> {
        let profile = DemoProfile::LocalDevelopment {
            marker_root,
            workspace_root,
        };
        let storage = SqliteStore::open_with_limits_and_physical_and_operations(
            path,
            StorageLimits::default(),
            SqlitePhysicalLimits::default(),
            SqliteOperationLimits::default(),
        )
        .await?;
        Self::from_storage_with_terminal(storage, profile, true, Some(terminal_service)).await
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
                workspace_root: None,
            },
            limits,
        )
        .await
    }

    pub async fn open_local_with_limits_and_physical(
        path: impl AsRef<Path>,
        marker_root: impl Into<PathBuf>,
        limits: StorageLimits,
        physical_limits: SqlitePhysicalLimits,
    ) -> Result<Self, StoreError> {
        Self::open_local_with_limits_and_physical_and_operations(
            path,
            marker_root,
            limits,
            physical_limits,
            SqliteOperationLimits::default(),
        )
        .await
    }

    pub async fn open_local_with_limits_and_physical_and_operations(
        path: impl AsRef<Path>,
        marker_root: impl Into<PathBuf>,
        limits: StorageLimits,
        physical_limits: SqlitePhysicalLimits,
        operation_limits: SqliteOperationLimits,
    ) -> Result<Self, StoreError> {
        Self::open_with_profile_and_limits_and_physical_and_operations(
            path,
            DemoProfile::LocalDevelopment {
                marker_root: marker_root.into(),
                workspace_root: None,
            },
            limits,
            physical_limits,
            operation_limits,
        )
        .await
    }

    /// Opens local development with the bounded marker writer plus a rooted,
    /// read-only workspace file capability exposed to the Agent.
    pub async fn open_local_with_workspace_and_limits_and_physical_and_operations(
        path: impl AsRef<Path>,
        marker_root: impl Into<PathBuf>,
        workspace_root: impl Into<PathBuf>,
        limits: StorageLimits,
        physical_limits: SqlitePhysicalLimits,
        operation_limits: SqliteOperationLimits,
    ) -> Result<Self, StoreError> {
        Self::open_with_profile_and_limits_and_physical_and_operations(
            path,
            DemoProfile::LocalDevelopment {
                marker_root: marker_root.into(),
                workspace_root: Some(workspace_root.into()),
            },
            limits,
            physical_limits,
            operation_limits,
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
        Self::open_with_profile_and_limits_and_physical(
            path,
            profile,
            limits,
            SqlitePhysicalLimits::default(),
        )
        .await
    }

    pub async fn open_with_profile_and_limits_and_physical(
        path: impl AsRef<Path>,
        profile: DemoProfile,
        limits: StorageLimits,
        physical_limits: SqlitePhysicalLimits,
    ) -> Result<Self, StoreError> {
        Self::open_with_profile_and_limits_and_physical_and_operations(
            path,
            profile,
            limits,
            physical_limits,
            SqliteOperationLimits::default(),
        )
        .await
    }

    pub async fn open_with_profile_and_limits_and_physical_and_operations(
        path: impl AsRef<Path>,
        profile: DemoProfile,
        limits: StorageLimits,
        physical_limits: SqlitePhysicalLimits,
        operation_limits: SqliteOperationLimits,
    ) -> Result<Self, StoreError> {
        Self::open_with_profile_and_limits_and_physical_and_operations_and_skills(
            path,
            profile,
            limits,
            physical_limits,
            operation_limits,
            None,
        )
        .await
    }

    /// Opens a runtime with an optional immutable Skill Catalog. Catalog tools
    /// are registered for either profile and their catalog-digest versions are
    /// included in every newly resolved Agent deployment manifest.
    pub async fn open_with_profile_and_limits_and_physical_and_operations_and_skills(
        path: impl AsRef<Path>,
        profile: DemoProfile,
        limits: StorageLimits,
        physical_limits: SqlitePhysicalLimits,
        operation_limits: SqliteOperationLimits,
        skill_catalog: Option<Arc<SkillCatalog>>,
    ) -> Result<Self, StoreError> {
        let storage = SqliteStore::open_with_limits_and_physical_and_operations(
            path,
            limits,
            physical_limits,
            operation_limits,
        )
        .await?;
        Self::from_storage_with_terminal_and_skills(storage, profile, true, None, skill_catalog)
            .await
    }

    /// Creates an isolated production-profile store for tests.
    pub async fn seeded() -> Result<Self, StoreError> {
        Self::open(":memory:").await
    }

    #[cfg(test)]
    async fn from_storage(
        storage: SqliteStore,
        profile: DemoProfile,
        auto_dispatch: bool,
    ) -> Result<Self, StoreError> {
        Self::from_storage_with_terminal(storage, profile, auto_dispatch, None).await
    }

    async fn from_storage_with_terminal(
        storage: SqliteStore,
        profile: DemoProfile,
        auto_dispatch: bool,
        terminal_service: Option<Arc<TerminalService>>,
    ) -> Result<Self, StoreError> {
        Self::from_storage_with_terminal_and_skills(
            storage,
            profile,
            auto_dispatch,
            terminal_service,
            None,
        )
        .await
    }

    async fn from_storage_with_terminal_and_skills(
        storage: SqliteStore,
        profile: DemoProfile,
        auto_dispatch: bool,
        terminal_service: Option<Arc<TerminalService>>,
        skill_catalog: Option<Arc<SkillCatalog>>,
    ) -> Result<Self, StoreError> {
        let terminal_service_for_cleanup = terminal_service.clone();
        let components = RuntimeComponents::build(profile, terminal_service, skill_catalog)?;
        let profile_id = components.profile_id;
        let primary_session_id = components.primary_session_id;
        let primary_run_id = components.scenario.run.id.clone();
        let environment = components.scenario.run.environment.clone();
        storage
            .bind_runtime_identity(RuntimeIdentity {
                profile: profile_id.into(),
                environment: environment.clone(),
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
            terminal_service: terminal_service_for_cleanup,
            profile_id: Arc::from(profile_id),
            environment: Arc::from(environment),
            policy_id: Arc::from(components.policy_id),
            policy_revision: Arc::from(components.policy_revision),
            primary_session_id: Arc::from(primary_session_id),
            primary_run_id: Arc::from(primary_run_id),
            dispatcher: Arc::new(Mutex::new(())),
            dispatcher_wake: Arc::new(WorkerWakeState::default()),
            auto_dispatch,
        };

        // A claimed reply is a potentially billable external operation, so a
        // missing result becomes outcome_unknown before generic turn recovery.
        // Queued reply turns are deliberately left open and claimable.
        store.recover_started_reply_jobs().await?;
        store.recover_started_session_compactions().await?;
        store.recover_started_agent_work().await?;

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

    /// Return the deterministic, secret-free tool catalog visible to a model.
    /// The returned values are copies and cannot alter the executable registry.
    pub fn session_agent_tool_definitions(
        &self,
    ) -> Result<Vec<SessionAgentToolDefinition>, StoreError> {
        Ok(self
            .session_agent_manifest_tools()?
            .into_iter()
            .map(|tool| SessionAgentToolDefinition {
                name: tool.name,
                description: tool.description,
                input_schema: tool.input_schema,
            })
            .collect())
    }

    /// Return the built-in revision-zero system prompt. Production admission
    /// resolves the active account prompt through durable storage instead.
    pub fn session_agent_system_prompt(&self) -> &'static str {
        DEFAULT_SESSION_AGENT_SYSTEM_PROMPT
    }

    /// Resolve the active account Agent prompt after checking Reply authority.
    pub async fn session_agent_prompt_for_actor(
        &self,
        context: &AuthzContext,
    ) -> Result<AgentPromptState, StoreError> {
        Ok(self.storage.active_agent_prompt_for_actor(context).await?)
    }

    /// Resolve the active account prompt for trusted worker manifest
    /// construction. Storage checks the binding again in the claim transaction.
    pub async fn current_session_agent_prompt_for_account(
        &self,
        account_id: &AccountId,
    ) -> Result<AgentPromptState, StoreError> {
        Ok(self
            .storage
            .active_agent_prompt_for_runtime(account_id)
            .await?)
    }

    /// Backward-compatible local-account prompt lookup used by direct runtime
    /// tests and legacy callers.
    pub async fn current_session_agent_prompt(&self) -> Result<AgentPromptState, StoreError> {
        self.current_session_agent_prompt_for_account(&AccountId::local())
            .await
    }

    pub async fn session_reply_provider_for_actor(
        &self,
        context: &AuthzContext,
        startup_default: AccountReplyProviderState,
    ) -> Result<AccountReplyProviderState, StoreError> {
        Ok(self
            .storage
            .reply_provider_for_actor(context, startup_default)
            .await?)
    }

    pub async fn current_session_reply_provider_for_account(
        &self,
        account_id: &AccountId,
        startup_default: AccountReplyProviderState,
    ) -> Result<AccountReplyProviderState, StoreError> {
        Ok(self
            .storage
            .reply_provider_for_runtime(account_id, startup_default)
            .await?)
    }

    pub async fn replace_reply_provider(
        &self,
        context: &AuthzContext,
        expected_revision: u64,
        provider_id: String,
        model: Option<String>,
        reply_kind: AssistantReplyKind,
        idempotency_key: String,
    ) -> Result<AccountReplyProviderUpdateResult, StoreError> {
        Ok(self
            .storage
            .replace_reply_provider(
                context,
                AccountReplyProviderCommit {
                    expected_revision,
                    provider_id,
                    model,
                    reply_kind,
                    idempotency_key,
                },
            )
            .await?)
    }

    /// Select the immutable active account knowledge context admitted with one
    /// Session Agent turn. The catalog read is capability-gated; the resulting
    /// corpus and exact query selection are persisted with the Agent admission.
    pub async fn session_agent_knowledge_context(
        &self,
        context: &AuthzContext,
        user_message: &str,
    ) -> Result<AgentKnowledgeContextSpec, StoreError> {
        let corpus = self
            .storage
            .active_knowledge_corpus_for_actor(context)
            .await?;
        let snapshot = select_context(user_message, corpus.entries())
            .and_then(SelectionSnapshotEnvelope::new)
            .map_err(|error| StoreError::InvalidAgentTransition(error.to_string()))?;
        Ok(AgentKnowledgeContextSpec { corpus, snapshot })
    }

    /// Build the validated, secret-free deployment manifest for this runtime.
    ///
    /// `provider_id` must already be the provider's stable non-secret identity;
    /// endpoints, API keys, and resolved credentials have no manifest field.
    pub fn session_agent_manifest(
        &self,
        provider_id: impl Into<String>,
        model: Option<String>,
        reply_kind: AssistantReplyKind,
    ) -> Result<ManifestEnvelope, StoreError> {
        let prompt = ManifestPromptBinding::from_content(
            SESSION_AGENT_PROMPT_ID,
            DEFAULT_SESSION_AGENT_PROMPT_REVISION,
            DEFAULT_SESSION_AGENT_SYSTEM_PROMPT,
        )
        .map_err(invalid_deployment_manifest)?;
        self.session_agent_manifest_with_binding(provider_id, model, reply_kind, prompt)
    }

    /// Build a deployment manifest bound to one exact durable account prompt.
    pub fn session_agent_manifest_with_prompt(
        &self,
        prompt: &AgentPromptState,
        provider_id: impl Into<String>,
        model: Option<String>,
        reply_kind: AssistantReplyKind,
    ) -> Result<ManifestEnvelope, StoreError> {
        let binding = ManifestPromptBinding::new(
            prompt.prompt_id.clone(),
            prompt.binding_revision.clone(),
            prompt.content_digest.clone(),
        )
        .map_err(invalid_deployment_manifest)?;
        if !binding.matches_content(&prompt.content) {
            return Err(StoreError::ExecutionInvariant(
                "the active Agent prompt content disagrees with its durable digest".into(),
            ));
        }
        self.session_agent_manifest_with_binding(provider_id, model, reply_kind, binding)
    }

    fn session_agent_manifest_with_binding(
        &self,
        provider_id: impl Into<String>,
        model: Option<String>,
        reply_kind: AssistantReplyKind,
        prompt: ManifestPromptBinding,
    ) -> Result<ManifestEnvelope, StoreError> {
        let provider = ManifestProvider::new(provider_id, model, reply_kind)
            .map_err(invalid_deployment_manifest)?;
        let policy = ManifestPolicy::new(
            self.policy_id.as_ref().to_owned(),
            self.policy_revision.as_ref().to_owned(),
        )
        .map_err(invalid_deployment_manifest)?;
        let spec = AgentSpec::new(
            SESSION_AGENT_SPEC_ID,
            SESSION_AGENT_SPEC_REVISION,
            self.profile_id.as_ref(),
            self.environment.as_ref(),
            provider,
            policy,
        )
        .map_err(invalid_deployment_manifest)?
        .with_prompt(prompt)
        .map_err(invalid_deployment_manifest)?
        .with_workflow(
            workflows::STATE_SCHEMA_VERSION,
            workflows::Limits::default(),
        )
        .map_err(invalid_deployment_manifest)?
        .with_tools(self.session_agent_manifest_tools()?)
        .map_err(invalid_deployment_manifest)?;
        let deployment = AgentDeployment::new(
            format!("{SESSION_AGENT_DEPLOYMENT_ID_PREFIX}-{}", self.profile_id),
            SESSION_AGENT_DEPLOYMENT_REVISION,
            spec,
        )
        .map_err(invalid_deployment_manifest)?;
        ManifestEnvelope::from_deployment(deployment).map_err(invalid_deployment_manifest)
    }

    /// Validate that a caller-supplied manifest is structurally exact for this
    /// runtime and uses the governed Zeus prompt identity. Storage compares the
    /// prompt revision/digest with the active account head again inside the
    /// admission or claim transaction, closing configuration-change races.
    ///
    /// The explicit binding checks make configuration drift diagnosable. The
    /// final equality check also rejects otherwise-valid substitutions of
    /// deployment identity, workflow limits, prompt binding, or tool contract.
    fn validate_session_agent_manifest_binding(
        &self,
        manifest: &ManifestEnvelope,
        provider_id: &str,
        model: Option<&str>,
    ) -> Result<(), StoreError> {
        manifest
            .validate()
            .map_err(invalid_agent_deployment_manifest)?;
        let spec = &manifest.manifest.deployment.spec;

        if spec.profile != self.profile_id.as_ref() {
            return Err(StoreError::InvalidAgentTransition(
                "the Agent deployment profile does not match the bound runtime".into(),
            ));
        }
        if spec.environment != self.environment.as_ref() {
            return Err(StoreError::InvalidAgentTransition(
                "the Agent deployment environment does not match the bound runtime".into(),
            ));
        }
        if spec.policy.policy_id != self.policy_id.as_ref()
            || spec.policy.revision != self.policy_revision.as_ref()
        {
            return Err(StoreError::InvalidAgentTransition(
                "the Agent deployment policy does not match the bound runtime".into(),
            ));
        }
        if spec.provider.provider_id != provider_id {
            return Err(StoreError::InvalidAgentTransition(
                "the Agent deployment provider does not match the Agent turn".into(),
            ));
        }
        if spec.provider.model.as_deref() != model {
            return Err(StoreError::InvalidAgentTransition(
                "the Agent deployment model does not match the Agent turn".into(),
            ));
        }

        let prompt = spec.prompt.clone().ok_or_else(|| {
            StoreError::InvalidAgentTransition(
                "the Agent deployment manifest has no governed prompt binding".into(),
            )
        })?;
        if prompt.prompt_id != SESSION_AGENT_PROMPT_ID {
            return Err(StoreError::InvalidAgentTransition(
                "the Agent deployment prompt identity does not match Zeus".into(),
            ));
        }
        let expected = self
            .session_agent_manifest_with_binding(
                provider_id.to_owned(),
                model.map(str::to_owned),
                spec.provider.reply_kind.clone(),
                prompt,
            )
            .map_err(|error| {
                StoreError::ExecutionInvariant(format!(
                    "the runtime could not resolve its current Agent deployment manifest: {error}"
                ))
            })?;
        if manifest != &expected {
            return Err(StoreError::InvalidAgentTransition(
                "the Agent deployment manifest does not match the runtime-resolved deployment"
                    .into(),
            ));
        }
        Ok(())
    }

    fn session_agent_manifest_tools(&self) -> Result<Vec<ManifestTool>, StoreError> {
        self.registry
            .descriptors()
            .map(|descriptor| {
                ManifestTool::new(
                    descriptor.name.clone(),
                    descriptor.version.clone(),
                    descriptor.description.clone(),
                    descriptor.input_schema.provider_json_schema()?,
                    descriptor.effect.clone(),
                    descriptor.sandbox_profile.clone(),
                    ToolExecutorStatus::Available,
                )
                .map_err(invalid_deployment_manifest)
            })
            .collect()
    }

    /// Return the runtime-bound environment persisted with each Session Agent.
    pub fn session_agent_environment(&self) -> &str {
        &self.environment
    }

    /// Resolve the only model-controlled fields, `name` and `arguments`, into
    /// an immutable server-owned call and its exact policy/environment facts.
    pub fn resolve_session_agent_tool(
        &self,
        agent_id: &str,
        model_step: u32,
        call_ordinal: u32,
        name: &str,
        arguments: Value,
    ) -> Result<ResolvedSessionAgentTool, StoreError> {
        let call_id = stable_agent_call_id(agent_id, model_step, call_ordinal)?;
        let descriptor = self
            .registry
            .descriptor(name)
            .ok_or_else(|| RegistryError::UnknownTool(name.to_owned()))?;
        descriptor.input_schema.validate_arguments(&arguments)?;
        let call = ToolCall {
            call_id,
            tool: descriptor.name.clone(),
            tool_version: descriptor.version.clone(),
            arguments_digest: arguments_digest(&arguments),
            arguments,
            effect: descriptor.effect.clone(),
            sandbox_profile: descriptor.sandbox_profile.clone(),
            executor_status: ToolExecutorStatus::Available,
        };
        let environment = self.environment.to_string();
        let policy_evaluation = self
            .policy
            .evaluate(&PolicyContext::for_call(&environment, &call));
        Ok(ResolvedSessionAgentTool {
            call,
            environment,
            policy_evaluation,
        })
    }

    /// Rehydrate a claimed durable call from the current registry and prove
    /// that every execution-owned field still matches the persisted contract.
    ///
    /// This method performs no execution. Callers must run it only after the
    /// durable `started` checkpoint and pass the returned value directly to
    /// [`Self::dispatch_session_agent_tool_after_checkpoint`]. Registry or
    /// policy drift therefore fails closed before an executor can observe the
    /// request.
    pub fn verify_persisted_session_agent_tool(
        &self,
        persisted: &AgentToolCall,
    ) -> Result<ResolvedSessionAgentTool, StoreError> {
        let resolved = self.resolve_session_agent_tool(
            &persisted.agent_id,
            persisted.model_step,
            persisted.ordinal,
            &persisted.tool_name,
            persisted.arguments_json.clone(),
        )?;
        let call = resolved.call();
        let policy = resolved.policy_evaluation();

        for (field, matches) in [
            ("call_id", call.call_id == persisted.call_id),
            ("tool", call.tool == persisted.tool_name),
            ("tool_version", call.tool_version == persisted.tool_version),
            (
                "arguments_digest",
                call.arguments_digest == persisted.arguments_digest,
            ),
            ("effect", call.effect == persisted.effect),
            (
                "sandbox_profile",
                call.sandbox_profile == persisted.sandbox_profile,
            ),
            (
                "executor_status",
                call.executor_status == persisted.executor_status,
            ),
            (
                "policy_decision",
                policy.decision == persisted.policy_decision,
            ),
            (
                "policy_revision",
                policy.policy_revision == persisted.policy_revision,
            ),
        ] {
            if !matches {
                return Err(StoreError::PolicyChanged(format!(
                    "the persisted agent tool {field} no longer matches the current runtime"
                )));
            }
        }

        Ok(resolved)
    }

    /// Rehydrate one complete durable Agent tool work item and bind it to its
    /// server-owned execution scope.
    pub fn verify_persisted_session_agent_tool_work(
        &self,
        work: &AgentToolWork,
    ) -> Result<ScopedSessionAgentTool, StoreError> {
        for (field, matches) in [
            ("agent_id", work.call.agent_id == work.model_job.agent_id),
            (
                "account_id",
                work.call.account_id == work.model_job.account_id,
            ),
            (
                "session_id",
                work.call.session_id == work.model_job.session_id,
            ),
            ("turn_id", work.call.turn_id == work.model_job.turn_id),
        ] {
            if !matches {
                return Err(StoreError::PolicyChanged(format!(
                    "the persisted agent tool {field} does not match its initiating model job"
                )));
            }
        }
        let resolved = self.verify_persisted_session_agent_tool(&work.call)?;
        let scope = ExecutionScope::new(
            work.call.account_id.as_str(),
            work.model_job.actor_user_id.as_str(),
            work.call.session_id.as_str(),
            work.call.turn_id.as_str(),
            work.call.agent_id.as_str(),
        )?;
        Ok(ScopedSessionAgentTool { resolved, scope })
    }

    /// Release non-durable executor resources only after storage has committed
    /// a terminal Agent state. Cleanup never changes or reopens that outcome.
    async fn cleanup_agent_terminal_resources(&self, agent: &AgentTurn) {
        let Some(service) = &self.terminal_service else {
            return;
        };
        let scope = match ExecutionScope::new(
            agent.account_id.as_str(),
            agent.actor_user_id.as_str(),
            agent.session_id.as_str(),
            agent.turn_id.as_str(),
            agent.id.as_str(),
        ) {
            Ok(scope) => scope,
            Err(error) => {
                eprintln!("zeus could not derive terminal cleanup scope: {error}");
                return;
            }
        };
        match service.close_owner(&scope).await {
            Ok(report) if report.close_failed > 0 => eprintln!(
                "zeus terminal cleanup removed {} records but {} backend closes failed",
                report.removed, report.close_failed
            ),
            Ok(_) => {}
            Err(error) => {
                eprintln!("zeus terminal cleanup could not access service state: {error}")
            }
        }
    }

    /// Re-evaluate policy and the complete registry contract immediately before
    /// executing a previously resolved call.
    ///
    /// The caller must persist its single durable `started` checkpoint before
    /// invoking this method. This façade never retries an executor.
    pub async fn dispatch_session_agent_tool_after_checkpoint(
        &self,
        scoped: ScopedSessionAgentTool,
        approval: Option<&Approval>,
    ) -> Result<ToolOutput, StoreError> {
        let ScopedSessionAgentTool { resolved, scope } = scoped;
        if resolved.environment != self.environment.as_ref() {
            return Err(StoreError::PolicyChanged(
                "the resolved tool environment no longer matches this runtime".into(),
            ));
        }
        let current_policy_evaluation = self.policy.evaluate(&PolicyContext::for_call(
            &resolved.environment,
            &resolved.call,
        ));
        if current_policy_evaluation != resolved.policy_evaluation {
            return Err(StoreError::PolicyChanged(
                "the tool policy evaluation changed after server-side resolution".into(),
            ));
        }
        let evaluation =
            self.policy
                .guard_dispatch(&resolved.environment, &resolved.call, approval);
        if evaluation.decision != PolicyDecision::Allow {
            return Err(policy_guard_error(evaluation));
        }
        if evaluation.policy_revision != resolved.policy_evaluation.policy_revision {
            return Err(StoreError::PolicyChanged(
                "the tool policy revision changed after server-side resolution".into(),
            ));
        }
        if resolved.call.tool == TODO_WRITE_TOOL_NAME
            && resolved.call.tool_version == TODO_WRITE_TOOL_VERSION
            && let Ok(prepared) = prepare_todo_write(&resolved.call.arguments)
        {
            let current = self.storage.current_agent_todo_revision(&scope).await?;
            if prepared.expected_revision() != current {
                return Err(StoreError::Registry(RegistryError::Executor(
                    ExecutorError::Failed {
                        code: "todo_revision_conflict".into(),
                        message: format!(
                            "The todo list changed: expected revision {}, current revision {current}",
                            prepared.expected_revision()
                        ),
                        retryable: false,
                    },
                )));
            }
        }
        self.registry
            .dispatch_scoped(resolved.call, &resolved.environment, scope)
            .await
            .map_err(StoreError::from)
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

    pub async fn credential_for_username_in_account(
        &self,
        username: &str,
        account_id: &AccountId,
    ) -> Result<Option<StoredCredential>, StoreError> {
        Ok(self
            .storage
            .credential_for_username_in_account(username, account_id)
            .await?)
    }

    pub async fn accounts_for_user(
        &self,
        context: &AuthzContext,
    ) -> Result<Vec<StoredAccount>, StoreError> {
        Ok(self.storage.accounts_for_user(context).await?)
    }

    pub async fn create_account(
        &self,
        context: &AuthzContext,
        commit: CreateAccountCommit,
    ) -> Result<CreateAccountResult, StoreError> {
        Ok(self.storage.create_account(context, commit).await?)
    }

    pub async fn create_auth_session(
        &self,
        commit: AuthSessionCommit,
    ) -> Result<AuthPrincipal, StoreError> {
        Ok(self.storage.create_auth_session(commit).await?)
    }

    pub async fn switch_auth_session(
        &self,
        commit: SwitchAuthSessionCommit,
    ) -> Result<SwitchAuthSessionResult, StoreError> {
        Ok(self.storage.switch_auth_session(commit).await?)
    }

    pub async fn authenticate(
        &self,
        session_token_hash: &str,
    ) -> Result<Option<AuthPrincipal>, StoreError> {
        Ok(self.storage.authenticate(session_token_hash).await?)
    }

    pub async fn revoke_auth_session(
        &self,
        context: &AuthzContext,
        session_token_hash: &str,
    ) -> Result<bool, StoreError> {
        Ok(self
            .storage
            .revoke_auth_session(context, session_token_hash)
            .await?)
    }

    pub async fn preferences(
        &self,
        context: &AuthzContext,
    ) -> Result<StoredPreferences, StoreError> {
        Ok(self.storage.preferences(context).await?)
    }

    pub async fn update_preferences(
        &self,
        context: &AuthzContext,
        expected_revision: u64,
        theme: &str,
        preferred_model: Option<&str>,
    ) -> Result<StoredPreferences, StoreError> {
        Ok(self
            .storage
            .update_preferences(context, expected_revision, theme, preferred_model)
            .await?)
    }

    pub async fn knowledge_catalog_for_admin(
        &self,
        context: &AuthzContext,
    ) -> Result<KnowledgeCatalogState, StoreError> {
        Ok(self.storage.knowledge_catalog_for_admin(context).await?)
    }

    pub async fn knowledge_catalog_revision_for_admin(
        &self,
        context: &AuthzContext,
        revision: u64,
    ) -> Result<KnowledgeCatalogState, StoreError> {
        Ok(self
            .storage
            .knowledge_catalog_revision_for_admin(context, revision)
            .await?)
    }

    pub async fn knowledge_catalog_revisions_for_admin(
        &self,
        context: &AuthzContext,
        before_revision: Option<u64>,
        limit: usize,
    ) -> Result<KnowledgeCatalogRevisionPage, StoreError> {
        Ok(self
            .storage
            .knowledge_catalog_revisions_for_admin(context, before_revision, limit)
            .await?)
    }

    pub async fn replace_knowledge_catalog(
        &self,
        context: &AuthzContext,
        expected_revision: u64,
        entries: Vec<EntryRevision>,
        idempotency_key: String,
    ) -> Result<KnowledgeCatalogUpdateResult, StoreError> {
        let corpus = CorpusRevisionEnvelope::new(entries)
            .map_err(|error| StoreError::InvalidKnowledgeCatalog(error.to_string()))?;
        Ok(self
            .storage
            .replace_knowledge_catalog(
                context,
                KnowledgeCatalogCommit {
                    expected_revision,
                    corpus,
                    idempotency_key,
                },
            )
            .await?)
    }

    pub async fn agent_prompt_for_admin(
        &self,
        context: &AuthzContext,
    ) -> Result<AgentPromptState, StoreError> {
        Ok(self.storage.agent_prompt_for_admin(context).await?)
    }

    pub async fn agent_prompt_revision_for_admin(
        &self,
        context: &AuthzContext,
        revision: u64,
    ) -> Result<AgentPromptState, StoreError> {
        Ok(self
            .storage
            .agent_prompt_revision_for_admin(context, revision)
            .await?)
    }

    pub async fn agent_prompt_revisions_for_admin(
        &self,
        context: &AuthzContext,
        before_revision: Option<u64>,
        limit: usize,
    ) -> Result<AgentPromptRevisionPage, StoreError> {
        Ok(self
            .storage
            .agent_prompt_revisions_for_admin(context, before_revision, limit)
            .await?)
    }

    pub async fn replace_agent_prompt(
        &self,
        context: &AuthzContext,
        expected_revision: u64,
        content: String,
        idempotency_key: String,
    ) -> Result<AgentPromptUpdateResult, StoreError> {
        Ok(self
            .storage
            .replace_agent_prompt(
                context,
                AgentPromptCommit {
                    expected_revision,
                    content,
                    idempotency_key,
                },
            )
            .await?)
    }

    pub async fn get_member(
        &self,
        context: &AuthzContext,
        user_id: &str,
    ) -> Result<StoredMember, StoreError> {
        Ok(self.storage.get_member(context, user_id).await?)
    }

    pub async fn list_members(
        &self,
        context: &AuthzContext,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<StoredMemberPage, StoreError> {
        Ok(self.storage.list_members(context, cursor, limit).await?)
    }

    pub async fn create_member(
        &self,
        context: &AuthzContext,
        user_id: String,
        username: String,
    ) -> Result<IssuedMemberSetupToken<CreateMemberResult>, StoreError> {
        let setup_token = MemberSetupToken::generate()
            .map_err(|_| StoreError::MemberSetupTokenGenerationUnavailable)?;
        let exposed_token = setup_token.expose_secret().to_owned();
        let result = self
            .storage
            .create_member(
                context,
                CreateMemberCommit {
                    user_id,
                    username,
                    setup_token,
                },
            )
            .await?;
        Ok(IssuedMemberSetupToken {
            result,
            setup_token: exposed_token,
        })
    }

    pub async fn rotate_member_setup_token(
        &self,
        context: &AuthzContext,
        user_id: String,
        expected_revision: MembershipRevision,
    ) -> Result<IssuedMemberSetupToken<RotateMemberSetupTokenResult>, StoreError> {
        let setup_token = MemberSetupToken::generate()
            .map_err(|_| StoreError::MemberSetupTokenGenerationUnavailable)?;
        let exposed_token = setup_token.expose_secret().to_owned();
        let result = self
            .storage
            .rotate_member_setup_token(
                context,
                RotateMemberSetupTokenCommit {
                    user_id,
                    expected_revision,
                    setup_token,
                },
            )
            .await?;
        Ok(IssuedMemberSetupToken {
            result,
            setup_token: exposed_token,
        })
    }

    pub async fn complete_member_setup(
        &self,
        commit: MemberSetupCommit,
    ) -> Result<MemberSetupResult, StoreError> {
        Ok(self.storage.complete_member_setup(commit).await?)
    }

    pub async fn transition_member(
        &self,
        context: &AuthzContext,
        commit: TransitionMemberCommit,
    ) -> Result<MemberTransitionResult, StoreError> {
        Ok(self.storage.transition_member(context, commit).await?)
    }

    pub async fn account_audit_state(
        &self,
        context: &AuthzContext,
    ) -> Result<AccountAuditState, StoreError> {
        Ok(self.storage.account_audit_state(context).await?)
    }

    pub async fn list_account_audit_events(
        &self,
        context: &AuthzContext,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<AccountAuditPage, StoreError> {
        Ok(self
            .storage
            .list_account_audit_events(context, cursor, limit)
            .await?)
    }

    pub async fn update_account_audit_policy(
        &self,
        context: &AuthzContext,
        commit: UpdateAccountAuditPolicyCommit,
    ) -> Result<AccountAuditState, StoreError> {
        Ok(self
            .storage
            .update_account_audit_policy(context, commit)
            .await?)
    }

    pub async fn checkpoint_account_audit_archive(
        &self,
        context: &AuthzContext,
        commit: AccountAuditCheckpointCommit,
    ) -> Result<AccountAuditState, StoreError> {
        Ok(self
            .storage
            .checkpoint_account_audit_archive(context, commit)
            .await?)
    }

    /// Returns the primary workspace only when the complete authority context
    /// still has read capability for the account that owns its primary Run.
    /// Storage intentionally maps missing, cross-account, disabled, stale, or
    /// insufficient authority to the same not-found result.
    pub async fn overview_for_actor(
        &self,
        context: &AuthzContext,
    ) -> Result<OverviewResponse, StoreError> {
        let stored = self
            .storage
            .bounded_run_for_actor(
                context,
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

    #[cfg(test)]
    async fn run_detail(&self, run_id: &str) -> Result<RunDetail, StoreError> {
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
        context: &AuthzContext,
        run_id: &str,
        events_before: Option<&str>,
        events_limit: usize,
    ) -> Result<RunDetail, StoreError> {
        validate_durable_reference(run_id, "run ID")?;
        self.authorize_run_for_actor(context, run_id).await?;
        let stored = self
            .storage
            .bounded_run_for_actor(context, run_id, events_before, events_limit)
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

    /// Performs the narrow account-scoped point authorization used by API
    /// handlers before parsing resource-specific cursors or request bodies.
    pub async fn authorize_run_for_actor(
        &self,
        context: &AuthzContext,
        run_id: &str,
    ) -> Result<(), StoreError> {
        validate_durable_reference(run_id, "run ID")?;
        self.storage
            .consistent_snapshot_for_actor(context, run_id)
            .await?;
        Ok(())
    }

    pub async fn events_after_for_actor(
        &self,
        context: &AuthzContext,
        run_id: &str,
        after: u64,
    ) -> Result<Vec<RunEvent>, StoreError> {
        validate_durable_reference(run_id, "run ID")?;
        self.authorize_run_for_actor(context, run_id).await?;
        Ok(self
            .storage
            .events_after_for_actor(context, run_id, after)
            .await?)
    }

    pub async fn run_event_page_for_actor(
        &self,
        context: &AuthzContext,
        run_id: &str,
        after: u64,
        limit: usize,
    ) -> Result<RunEventPage, StoreError> {
        validate_durable_reference(run_id, "run ID")?;
        self.authorize_run_for_actor(context, run_id).await?;
        Ok(self
            .storage
            .run_event_page_for_actor(context, run_id, after, limit)
            .await?)
    }

    /// Subscribes before the actor-scoped durable snapshot so a commit cannot
    /// fall between authorization/replay and the live wake channel.
    pub async fn event_feed_for_actor(
        &self,
        context: &AuthzContext,
        run_id: &str,
        after: u64,
    ) -> Result<EventFeed, StoreError> {
        let receiver = self.publisher.subscribe();
        let replay = self.events_after_for_actor(context, run_id, after).await?;
        Ok(EventFeed { replay, receiver })
    }

    /// Subscribes before loading a bounded durable page so consumers cannot
    /// miss a commit between the replay snapshot and the live wake channel.
    pub async fn event_page_feed_for_actor(
        &self,
        context: &AuthzContext,
        run_id: &str,
        after: u64,
        limit: usize,
    ) -> Result<EventPageFeed, StoreError> {
        let receiver = self.publisher.subscribe();
        let replay = self
            .run_event_page_for_actor(context, run_id, after, limit)
            .await?;
        Ok(EventPageFeed { replay, receiver })
    }

    pub async fn list_sessions_for_actor(
        &self,
        context: &AuthzContext,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<SessionSummaryPage, StoreError> {
        Ok(self
            .storage
            .session_summary_page_for_actor(context, cursor, limit)
            .await?)
    }

    /// Performs the narrow account-scoped point authorization used by API
    /// handlers before parsing resource-specific cursors or request bodies.
    pub async fn authorize_session_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
    ) -> Result<(), StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        self.storage
            .session_summary_for_actor(context, session_id)
            .await?;
        Ok(())
    }

    /// Durable worker-only point read using the reserved progress lane.
    pub async fn session_summary_for_progress(
        &self,
        session_id: &str,
    ) -> Result<SessionSummary, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        retry_durable_progress("Session progress read", || async {
            Ok(self
                .storage
                .session_summary_for_progress(session_id)
                .await?)
        })
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn get_session_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        run_ids_before: Option<&str>,
        run_ids_limit: usize,
        turns_before: Option<&str>,
        turns_limit: usize,
        events_before: Option<&str>,
        events_limit: usize,
    ) -> Result<SessionDetail, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        self.authorize_session_for_actor(context, session_id)
            .await?;
        Ok(self
            .storage
            .session_detail_page_for_actor(
                context,
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
        context: &AuthzContext,
        session_id: &str,
        turn_id: &str,
    ) -> Result<SessionTurn, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        self.authorize_session_for_actor(context, session_id)
            .await?;
        Ok(self
            .storage
            .session_turn_for_actor(context, session_id, turn_id)
            .await?)
    }

    /// Reads the bounded, complete conversation history visible at a caller's
    /// immutable pre-turn Session sequence.
    pub async fn session_reply_turns_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        through_sequence: u64,
        limit: usize,
    ) -> Result<Vec<SessionTurn>, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        self.authorize_session_for_actor(context, session_id)
            .await?;
        Ok(self
            .storage
            .session_reply_turns_for_actor(context, session_id, through_sequence, limit)
            .await?)
    }

    pub async fn session_reply_turns_after_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        after_sequence: u64,
        through_sequence: u64,
        limit: usize,
    ) -> Result<Vec<SessionTurn>, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        self.authorize_session_for_actor(context, session_id)
            .await?;
        Ok(self
            .storage
            .session_reply_turns_after_for_actor(
                context,
                session_id,
                after_sequence,
                through_sequence,
                limit,
            )
            .await?)
    }

    pub async fn session_events_after_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        after: u64,
    ) -> Result<Vec<SessionEvent>, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        self.authorize_session_for_actor(context, session_id)
            .await?;
        validate_session_sequence(after, "session event cursor")?;
        Ok(self
            .storage
            .session_events_after_for_actor(context, session_id, after)
            .await?)
    }

    pub async fn session_event_page_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        after: u64,
        limit: usize,
    ) -> Result<SessionEventPage, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        self.authorize_session_for_actor(context, session_id)
            .await?;
        Ok(self
            .storage
            .session_event_page_for_actor(context, session_id, after, limit)
            .await?)
    }

    /// Actor-scoped counterpart used by authenticated SSE. Subscription still
    /// precedes the durable query, while storage revalidates account authority
    /// in the same read transaction that builds the replay.
    pub async fn session_event_feed_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        after: u64,
    ) -> Result<SessionEventFeed, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        let receiver = self.session_publisher.subscribe();
        let replay = self
            .session_events_after_for_actor(context, session_id, after)
            .await?;
        Ok(SessionEventFeed { replay, receiver })
    }

    /// Actor-scoped bounded counterpart for authenticated SSE. Subscription
    /// precedes the storage transaction that authorizes and builds the page.
    pub async fn session_event_page_feed_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        after: u64,
        limit: usize,
    ) -> Result<SessionEventPageFeed, StoreError> {
        let receiver = self.session_publisher.subscribe();
        let replay = self
            .session_event_page_for_actor(context, session_id, after, limit)
            .await?;
        Ok(SessionEventPageFeed { replay, receiver })
    }

    pub async fn create_session_for_actor(
        &self,
        context: &AuthzContext,
        request: CreateSessionRequest,
        idempotency_key: &str,
    ) -> Result<CreateSessionResponse, StoreError> {
        validate_new_session_id(&request.id, "session ID")?;
        validate_new_session_title(&request.title, "session title")?;
        let idempotency_key = normalized_idempotency_key(idempotency_key)?;
        let response = self
            .storage
            .create_session_for_actor(context, request, idempotency_key)
            .await?;
        if !response.replayed {
            self.publish_session_event(&response.session.id, response.event.clone());
        }
        Ok(response)
    }

    pub async fn attach_run_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        request: AttachRunRequest,
        idempotency_key: &str,
    ) -> Result<AttachRunResponse, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        validate_durable_reference(&request.run_id, "run ID")?;
        self.authorize_session_for_actor(context, session_id)
            .await?;
        self.authorize_run_for_actor(context, &request.run_id)
            .await?;
        validate_session_sequence(request.expected_sequence, "expected session sequence")?;
        let idempotency_key = normalized_idempotency_key(idempotency_key)?;
        let response = self
            .storage
            .attach_run_for_actor(context, session_id, request, idempotency_key)
            .await?;
        if !response.replayed {
            self.publish_session_event(session_id, response.event.clone());
        }
        Ok(response)
    }

    pub async fn resume_session_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        request: ResumeSessionRequest,
        idempotency_key: &str,
    ) -> Result<ResumeSessionResponse, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        self.authorize_session_for_actor(context, session_id)
            .await?;
        validate_session_sequence(request.expected_sequence, "expected session sequence")?;
        let idempotency_key = normalized_idempotency_key(idempotency_key)?;
        let response = self
            .storage
            .resume_session_for_actor(context, session_id, request, idempotency_key)
            .await?;
        if !response.replayed {
            self.publish_session_event(session_id, response.event.clone());
        }
        Ok(response)
    }

    pub async fn start_turn_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        request: StartTurnRequest,
        idempotency_key: &str,
    ) -> Result<StartTurnResponse, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        validate_new_turn_id(&request.turn_id, "turn ID")?;
        self.authorize_session_for_actor(context, session_id)
            .await?;
        validate_user_message_value(&request.user_message, "user message")?;
        validate_session_sequence(request.expected_sequence, "expected session sequence")?;
        let idempotency_key = normalized_idempotency_key(idempotency_key)?;
        let response = self
            .storage
            .start_turn_for_actor(context, session_id, request, idempotency_key)
            .await?;
        if !response.replayed {
            self.publish_session_event(session_id, response.event.clone());
        }
        Ok(response)
    }

    pub async fn start_turn_and_enqueue_reply_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        request: StartTurnRequest,
        idempotency_key: &str,
        job: ReplyJobSpec,
    ) -> Result<ReplyJobEnqueueResponse, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        validate_new_turn_id(&request.turn_id, "turn ID")?;
        self.authorize_session_for_actor(context, session_id)
            .await?;
        validate_user_message_value(&request.user_message, "user message")?;
        validate_session_sequence(request.expected_sequence, "expected session sequence")?;
        let idempotency_key = normalized_idempotency_key(idempotency_key)?;
        let response = self
            .storage
            .start_turn_and_enqueue_reply_for_actor(
                context,
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

    /// Resolve an exact durable Agent start replay without rebuilding its
    /// server-derived request or knowledge selection.
    pub async fn agent_start_receipt_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        request: &StartTurnRequest,
        idempotency_key: &str,
        probe: &AgentTurnReceiptProbe,
    ) -> Result<Option<AgentTurnEnqueueResponse>, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        validate_new_turn_id(&request.turn_id, "turn ID")?;
        self.authorize_session_for_actor(context, session_id)
            .await?;
        validate_user_message_value(&request.user_message, "user message")?;
        validate_session_sequence(request.expected_sequence, "expected session sequence")?;
        if probe.authz != *context || probe.environment != self.environment.as_ref() {
            return Err(StoreError::InvalidAgentTransition(
                "the Agent receipt identity does not match the bound runtime actor or environment"
                    .into(),
            ));
        }
        let idempotency_key = normalized_idempotency_key(idempotency_key)?;
        self.storage
            .agent_start_receipt_for_actor(context, session_id, request, idempotency_key, probe)
            .await
            .map_err(StoreError::from)
    }

    /// Atomically append one Session user turn and enqueue the immutable first
    /// model step for Zeus' Session-native Agent Loop.
    pub async fn start_turn_and_enqueue_agent_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        request: StartTurnRequest,
        idempotency_key: &str,
        agent: AgentTurnSpec,
    ) -> Result<AgentTurnEnqueueResponse, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        validate_new_turn_id(&request.turn_id, "turn ID")?;
        self.authorize_session_for_actor(context, session_id)
            .await?;
        validate_user_message_value(&request.user_message, "user message")?;
        validate_session_sequence(request.expected_sequence, "expected session sequence")?;
        if agent.environment != self.environment.as_ref() {
            return Err(StoreError::InvalidAgentTransition(
                "the Agent environment does not match the bound runtime".into(),
            ));
        }
        self.validate_session_agent_manifest_binding(
            &agent.manifest,
            &agent.provider_name,
            agent.model_name.as_deref(),
        )?;
        let idempotency_key = normalized_idempotency_key(idempotency_key)?;
        let response = self
            .storage
            .start_turn_and_enqueue_agent_for_actor(
                context,
                session_id,
                request,
                idempotency_key,
                agent,
            )
            .await?;
        if !response.start.replayed {
            self.publish_session_event(session_id, response.start.event.clone());
        }
        Ok(response)
    }

    /// Durable model-worker preparation façade. This phase does not authorize
    /// provider I/O and is therefore safe to reclaim after expiry or restart.
    pub async fn next_agent_model_for_holder(
        &self,
        holder_id: &str,
    ) -> Result<Option<AgentModelJob>, StoreError> {
        Ok(self.storage.next_agent_model_for_holder(holder_id).await?)
    }

    /// Durable model-worker preparation façade. This phase does not authorize
    /// provider I/O and is therefore safe to reclaim after expiry or restart.
    pub async fn prepare_next_agent_model(
        &self,
        manifest: &ManifestEnvelope,
        holder_id: &str,
    ) -> Result<AgentModelClaimOutcome, StoreError> {
        let provider = &manifest.manifest.deployment.spec.provider;
        self.validate_session_agent_manifest_binding(
            manifest,
            &provider.provider_id,
            provider.model.as_deref(),
        )?;
        loop {
            match retry_operation_capacity(|| async {
                Ok(self
                    .storage
                    .prepare_next_agent_model(manifest, holder_id)
                    .await?)
            })
            .await?
            {
                AgentModelClaimOutcome::Rejected(completion) => {
                    if !completion.replayed {
                        self.publish_session_event(
                            &completion.session.id,
                            completion.event.clone(),
                        );
                    }
                    self.cleanup_agent_terminal_resources(&completion.agent)
                        .await;
                }
                outcome => return Ok(outcome),
            }
        }
    }

    /// Release one exact prepared model operation into its durable start
    /// checkpoint. A rejection is already terminal and is published once.
    pub async fn start_prepared_agent_model(
        &self,
        claim: &AgentOperationClaim,
        manifest: &ManifestEnvelope,
    ) -> Result<AgentModelStartOutcome, StoreError> {
        let provider = &manifest.manifest.deployment.spec.provider;
        self.validate_session_agent_manifest_binding(
            manifest,
            &provider.provider_id,
            provider.model.as_deref(),
        )?;
        let outcome = retry_operation_capacity(|| async {
            Ok(self
                .storage
                .start_prepared_agent_model(claim, manifest)
                .await?)
        })
        .await?;
        if let AgentModelStartOutcome::Rejected(completion) = &outcome {
            if !completion.replayed {
                self.publish_session_event(&completion.session.id, completion.event.clone());
            }
            self.cleanup_agent_terminal_resources(&completion.agent)
                .await;
        }
        Ok(outcome)
    }

    /// Compatibility façade for direct runtime integrations that expect one
    /// call to return an already-started model operation. Server workers use
    /// the explicit prepare/start boundary.
    pub async fn claim_next_agent_model(
        &self,
        manifest: &ManifestEnvelope,
    ) -> Result<AgentModelClaimOutcome, StoreError> {
        match self
            .prepare_next_agent_model(manifest, "runtime-direct-model-v1")
            .await?
        {
            AgentModelClaimOutcome::Prepared(prepared) => {
                match self
                    .start_prepared_agent_model(&prepared.claim, manifest)
                    .await?
                {
                    AgentModelStartOutcome::Started(job) => {
                        Ok(AgentModelClaimOutcome::Claimed(job))
                    }
                    AgentModelStartOutcome::Rejected(completion) => {
                        Ok(AgentModelClaimOutcome::Rejected(completion))
                    }
                }
            }
            outcome => Ok(outcome),
        }
    }

    /// Commit one trusted provider response after a claimed model checkpoint.
    pub async fn complete_agent_model_success(
        &self,
        commit: AgentModelSuccessCommit,
    ) -> Result<AgentModelCompletion, StoreError> {
        let completion = retry_durable_progress("Agent model completion", || async {
            Ok(self
                .storage
                .complete_agent_model_success(commit.clone())
                .await?)
        })
        .await?;
        match &completion {
            AgentModelCompletion::Final(finalized) => {
                if !finalized.replayed {
                    for event in &finalized.events {
                        self.publish_session_event(&finalized.session.id, event.clone());
                    }
                }
                self.cleanup_agent_terminal_resources(&finalized.agent)
                    .await;
            }
            AgentModelCompletion::Terminal(terminal) => {
                if !terminal.replayed {
                    self.publish_session_event(&terminal.session.id, terminal.event.clone());
                }
                self.cleanup_agent_terminal_resources(&terminal.agent).await;
            }
            AgentModelCompletion::ToolCall { .. } => {}
        }
        Ok(completion)
    }

    /// Commit a known or indeterminate provider failure after model start.
    pub async fn complete_agent_model_failure(
        &self,
        commit: AgentModelFailureCommit,
    ) -> Result<AgentTerminalCompletion, StoreError> {
        let completion = retry_durable_progress("Agent model failure", || async {
            Ok(self
                .storage
                .complete_agent_model_failure(commit.clone())
                .await?)
        })
        .await?;
        if !completion.replayed {
            self.publish_session_event(&completion.session.id, completion.event.clone());
        }
        self.cleanup_agent_terminal_resources(&completion.agent)
            .await;
        Ok(completion)
    }

    /// Durable tool-worker preparation façade. A rejected preparation has
    /// already terminalized its Session, so it is published and skipped.
    pub async fn next_agent_tool_for_holder(
        &self,
        holder_id: &str,
    ) -> Result<Option<AgentToolWork>, StoreError> {
        Ok(self.storage.next_agent_tool_for_holder(holder_id).await?)
    }

    /// Durable tool-worker preparation façade. A rejected preparation has
    /// already terminalized its Session, so it is published and skipped.
    pub async fn prepare_next_agent_tool(
        &self,
        manifest: &ManifestEnvelope,
        holder_id: &str,
    ) -> Result<AgentToolClaimOutcome, StoreError> {
        let provider = &manifest.manifest.deployment.spec.provider;
        self.validate_session_agent_manifest_binding(
            manifest,
            &provider.provider_id,
            provider.model.as_deref(),
        )?;
        loop {
            match retry_operation_capacity(|| async {
                Ok(self
                    .storage
                    .prepare_next_agent_tool(manifest, holder_id)
                    .await?)
            })
            .await?
            {
                AgentToolClaimOutcome::Rejected(completion) => {
                    if !completion.replayed {
                        self.publish_session_event(
                            &completion.session.id,
                            completion.event.clone(),
                        );
                    }
                    self.cleanup_agent_terminal_resources(&completion.agent)
                        .await;
                }
                outcome => return Ok(outcome),
            }
        }
    }

    /// Release one exact prepared tool operation into its durable start
    /// checkpoint. A rejection is already terminal and is published once.
    pub async fn start_prepared_agent_tool(
        &self,
        claim: &AgentOperationClaim,
        manifest: &ManifestEnvelope,
    ) -> Result<AgentToolStartOutcome, StoreError> {
        let provider = &manifest.manifest.deployment.spec.provider;
        self.validate_session_agent_manifest_binding(
            manifest,
            &provider.provider_id,
            provider.model.as_deref(),
        )?;
        let outcome = retry_operation_capacity(|| async {
            Ok(self
                .storage
                .start_prepared_agent_tool(claim, manifest)
                .await?)
        })
        .await?;
        if let AgentToolStartOutcome::Rejected(completion) = &outcome {
            if !completion.replayed {
                self.publish_session_event(&completion.session.id, completion.event.clone());
            }
            self.cleanup_agent_terminal_resources(&completion.agent)
                .await;
        }
        Ok(outcome)
    }

    /// Commit one known connector result and its immutable continuation.
    pub async fn complete_agent_tool(
        &self,
        commit: AgentToolCompletionCommit,
    ) -> Result<AgentToolCompletion, StoreError> {
        let completion = retry_durable_progress("Agent tool completion", || async {
            Ok(self.storage.complete_agent_tool(commit.clone()).await?)
        })
        .await?;
        if let AgentToolCompletion::Terminal(terminal) = &completion {
            if !terminal.replayed {
                self.publish_session_event(&terminal.session.id, terminal.event.clone());
            }
            self.cleanup_agent_terminal_resources(&terminal.agent).await;
        }
        Ok(completion)
    }

    /// Commit an indeterminate connector outcome without ever re-queuing it.
    pub async fn complete_agent_tool_outcome_unknown(
        &self,
        commit: AgentToolOutcomeUnknownCommit,
    ) -> Result<AgentTerminalCompletion, StoreError> {
        let completion = retry_durable_progress("Agent tool unknown outcome", || async {
            Ok(self
                .storage
                .complete_agent_tool_outcome_unknown(commit.clone())
                .await?)
        })
        .await?;
        if !completion.replayed {
            self.publish_session_event(&completion.session.id, completion.event.clone());
        }
        self.cleanup_agent_terminal_resources(&completion.agent)
            .await;
        Ok(completion)
    }

    /// Cancel an Agent turn only while no provider or connector operation has
    /// crossed its durable started checkpoint. The revision CAS makes an
    /// ambiguous successful response reconstructable without a second state
    /// transition.
    pub async fn cancel_agent_turn_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        turn_id: &str,
        expected_revision: u64,
    ) -> Result<CancelAgentTurnResponse, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        validate_durable_reference(turn_id, "turn ID")?;
        let completion = self
            .storage
            .cancel_agent_turn_for_actor(context, session_id, turn_id, expected_revision)
            .await?;
        let detail = self
            .storage
            .agent_turn_detail_for_actor(context, session_id, turn_id)
            .await?;
        if !completion.replayed {
            self.publish_session_event(&completion.session.id, completion.event.clone());
        }
        self.cleanup_agent_terminal_resources(&completion.agent)
            .await;
        Ok(CancelAgentTurnResponse {
            agent: detail,
            turn: completion.turn,
            event: completion.event,
            replayed: completion.replayed,
        })
    }

    /// Return one authenticated, account-scoped Session Agent projection.
    pub async fn agent_turn_detail_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        turn_id: &str,
    ) -> Result<protocol::AgentTurnDetail, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        validate_durable_reference(turn_id, "turn ID")?;
        Ok(self
            .storage
            .agent_turn_detail_for_actor(context, session_id, turn_id)
            .await?)
    }

    /// Return the exact immutable knowledge selection bound to an
    /// authenticated Session Agent turn. Frozen pre-v22 turns return `None`.
    pub async fn agent_knowledge_context_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        turn_id: &str,
    ) -> Result<Option<AgentKnowledgeContextExplain>, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        validate_durable_reference(turn_id, "turn ID")?;
        self.storage
            .agent_knowledge_context_for_actor(context, session_id, turn_id)
            .await
            .map_err(|error| match error {
                StorageError::CorruptData(detail) => StoreError::ExecutionInvariant(detail),
                other => StoreError::from(other),
            })
    }

    /// Return the immutable deployment manifest bound to an authenticated
    /// Session Agent turn. Storage performs the account-scoped authorization;
    /// runtime treats an invalid persisted envelope as an invariant failure.
    pub async fn agent_deployment_manifest_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        turn_id: &str,
    ) -> Result<Option<ManifestEnvelope>, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        validate_durable_reference(turn_id, "turn ID")?;
        let manifest = self
            .storage
            .agent_deployment_manifest_for_actor(context, session_id, turn_id)
            .await
            .map_err(|error| match error {
                StorageError::CorruptData(detail) => StoreError::ExecutionInvariant(detail),
                other => StoreError::from(other),
            })?;
        if let Some(manifest) = &manifest {
            manifest.validate().map_err(|error| {
                StoreError::ExecutionInvariant(format!(
                    "invalid persisted Session Agent deployment manifest: {error}"
                ))
            })?;
        }
        Ok(manifest)
    }

    /// Return one authenticated, account-scoped explanation of the complete
    /// durable Agent execution history observed at a single storage watermark.
    pub async fn agent_execution_explain_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        turn_id: &str,
    ) -> Result<AgentExecutionExplain, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        validate_durable_reference(turn_id, "turn ID")?;
        let explanation = self
            .storage
            .agent_execution_explain_for_actor(context, session_id, turn_id)
            .await
            .map_err(|error| match error {
                StorageError::CorruptData(detail) => StoreError::ExecutionInvariant(detail),
                other => StoreError::from(other),
            })?;
        explanation.validate().map_err(|error| {
            StoreError::ExecutionInvariant(format!(
                "invalid persisted Session Agent execution explanation: {error}"
            ))
        })?;
        Ok(explanation)
    }

    /// Return the exact persisted request and outcome for one authenticated
    /// model RunEpoch. Reconstruction never authorizes provider re-execution.
    pub async fn agent_run_epoch_explain_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        turn_id: &str,
        step: u32,
    ) -> Result<AgentRunEpochExplain, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        validate_durable_reference(turn_id, "turn ID")?;
        if step == 0 {
            return Err(StoreError::InvalidAgentTransition(
                "Agent model step must be greater than zero".into(),
            ));
        }
        let explanation = self
            .storage
            .agent_run_epoch_explain_for_actor(context, session_id, turn_id, step)
            .await
            .map_err(|error| match error {
                StorageError::CorruptData(detail) => StoreError::ExecutionInvariant(detail),
                other => StoreError::from(other),
            })?;
        explanation.validate().map_err(|error| {
            StoreError::ExecutionInvariant(format!(
                "invalid persisted Session Agent RunEpoch explanation: {error}"
            ))
        })?;
        Ok(explanation)
    }

    /// Load the server-owned transcript required to derive an approval
    /// rejection continuation. Storage authorizes before exposing the call.
    pub async fn agent_review_context_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        turn_id: &str,
        call_id: &str,
    ) -> Result<AgentReviewContext, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        validate_durable_reference(turn_id, "turn ID")?;
        validate_durable_reference(call_id, "agent call ID")?;
        Ok(self
            .storage
            .agent_review_context_for_actor(context, session_id, turn_id, call_id)
            .await?)
    }

    /// Predict whether rejecting an authenticated pending Agent call requires
    /// a model continuation. This is pure and uses the same canonical result,
    /// reducer, and fixed-limit settlement as the storage transaction.
    pub fn agent_rejection_requires_continuation(
        &self,
        context: &AgentReviewContext,
        note: Option<&str>,
    ) -> Result<bool, StoreError> {
        Ok(context.rejection_requires_continuation(note)?)
    }

    /// Atomically record one owner decision and queue its permitted next step.
    pub async fn review_agent_tool_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        turn_id: &str,
        commit: AgentReviewCommit,
    ) -> Result<AgentReviewResult, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        validate_durable_reference(turn_id, "turn ID")?;
        validate_durable_reference(&commit.call_id, "agent call ID")?;
        normalized_idempotency_key(&commit.idempotency_key)?;
        if let Some(note) = &commit.note {
            protocol::validate_review_note(note)
                .map_err(|error| invalid_resource_envelope("review note", error))?;
        }
        let result = self
            .storage
            .review_agent_tool_for_actor(context, session_id, turn_id, commit)
            .await?;
        if let Some(completion) = &result.terminal_completion {
            if !completion.replayed {
                self.publish_session_event(&completion.session.id, completion.event.clone());
            }
            self.cleanup_agent_terminal_resources(&completion.agent)
                .await;
        }
        Ok(result)
    }

    /// Durable reply-worker claim façade. No handler authority is accepted;
    /// storage revalidates the persisted initiating authority atomically.
    pub async fn claim_next_reply(&self) -> Result<ReplyClaimOutcome, StoreError> {
        loop {
            let Some(observed) = retry_durable_progress("reply queue observation", || async {
                Ok(self.storage.peek_next_reply().await?)
            })
            .await?
            else {
                return Ok(ReplyClaimOutcome::NotAvailable);
            };
            let job_id = observed.id;
            let outcome = retry_durable_progress("reply exact start", || {
                let job_id = job_id.clone();
                async move { Ok(self.storage.start_observed_reply(&job_id).await?) }
            })
            .await?;
            match outcome {
                ReplyClaimOutcome::Rejected(completion) => {
                    // Storage committed the terminal failure before returning.
                    // Publish only as a post-commit wake hint and continue to
                    // the next queue item without exposing rejected work to a
                    // provider caller.
                    for event in &completion.events {
                        self.publish_session_event(&completion.session.id, event.clone());
                    }
                }
                ReplyClaimOutcome::NotAvailable => {
                    // The observation lost a race before its exact start. A
                    // fresh read may now expose the next stable queue head.
                }
                outcome => return Ok(outcome),
            }
        }
    }

    /// Durable Session-compaction claim with exact-start replay across an
    /// ambiguous SQLite commit acknowledgement.
    pub async fn claim_next_session_compaction(
        &self,
    ) -> Result<SessionCompactionClaimOutcome, StoreError> {
        let Some(observed) = retry_durable_progress("compaction queue observation", || async {
            Ok(self.storage.peek_next_session_compaction().await?)
        })
        .await?
        else {
            return Ok(SessionCompactionClaimOutcome::NotAvailable);
        };
        let job_id = observed.id;
        retry_durable_progress("compaction exact start", || {
            let job_id = job_id.clone();
            async move {
                Ok(self
                    .storage
                    .start_observed_session_compaction(&job_id)
                    .await?)
            }
        })
        .await
    }

    pub async fn complete_session_compaction_success(
        &self,
        commit: SessionCompactionSuccessCommit,
    ) -> Result<SessionCompactionJob, StoreError> {
        retry_durable_progress("compaction success", || async {
            Ok(self
                .storage
                .complete_session_compaction_success(commit.clone())
                .await?)
        })
        .await
    }

    pub async fn complete_session_compaction_failure(
        &self,
        commit: SessionCompactionFailureCommit,
    ) -> Result<SessionCompactionJob, StoreError> {
        retry_durable_progress("compaction failure", || async {
            Ok(self
                .storage
                .complete_session_compaction_failure(commit.clone())
                .await?)
        })
        .await
    }

    pub async fn session_context_checkpoint_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        through_sequence: u64,
    ) -> Result<Option<SessionContextCheckpoint>, StoreError> {
        Ok(self
            .storage
            .session_context_checkpoint_for_actor(context, session_id, through_sequence)
            .await?)
    }

    /// Account-scoped durable queue inspection for authenticated diagnostics.
    pub async fn reply_job_for_actor(
        &self,
        context: &AuthzContext,
        job_id: &str,
    ) -> Result<Option<ReplyJob>, StoreError> {
        Ok(self.storage.reply_job_for_actor(context, job_id).await?)
    }

    /// Durable worker-only completion after a successful claimed provider call.
    pub async fn complete_reply_success(
        &self,
        commit: ReplySuccessCommit,
    ) -> Result<ReplyCompletion, StoreError> {
        let completion = retry_durable_progress("reply success", || async {
            Ok(self.storage.complete_reply_success(commit.clone()).await?)
        })
        .await?;
        if !completion.replayed {
            for event in &completion.events {
                self.publish_session_event(&completion.session.id, event.clone());
            }
        }
        Ok(completion)
    }

    /// Durable worker-only completion after a failed claimed provider call.
    pub async fn complete_reply_failure(
        &self,
        commit: ReplyFailureCommit,
    ) -> Result<ReplyCompletion, StoreError> {
        let completion = retry_durable_progress("reply failure", || async {
            Ok(self.storage.complete_reply_failure(commit.clone()).await?)
        })
        .await?;
        if !completion.replayed {
            for event in &completion.events {
                self.publish_session_event(&completion.session.id, event.clone());
            }
        }
        Ok(completion)
    }

    /// Durable worker-only completion for an indeterminate claimed provider call.
    pub async fn complete_reply_outcome_unknown(
        &self,
        commit: ReplyOutcomeUnknownCommit,
    ) -> Result<ReplyCompletion, StoreError> {
        let completion = retry_durable_progress("reply unknown outcome", || async {
            Ok(self
                .storage
                .complete_reply_outcome_unknown(commit.clone())
                .await?)
        })
        .await?;
        if !completion.replayed {
            for event in &completion.events {
                self.publish_session_event(&completion.session.id, event.clone());
            }
        }
        Ok(completion)
    }

    pub async fn flush_turn_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        request: FlushSessionRequest,
        idempotency_key: &str,
    ) -> Result<FlushSessionResponse, StoreError> {
        validate_durable_reference(session_id, "session ID")?;
        validate_durable_reference(&request.turn_id, "turn ID")?;
        self.authorize_session_for_actor(context, session_id)
            .await?;
        if let Some(message) = &request.assistant_message {
            validate_session_message(message, "assistant message")?;
        }
        validate_session_sequence(request.expected_sequence, "expected session sequence")?;
        let idempotency_key = normalized_idempotency_key(idempotency_key)?;
        let response = self
            .storage
            .flush_turn_for_actor(context, session_id, request, idempotency_key)
            .await?;
        if !response.replayed {
            for event in &response.events {
                self.publish_session_event(session_id, event.clone());
            }
        }
        Ok(response)
    }

    /// Actor-scoped approval boundary used by the authenticated server.
    ///
    /// Resource authorization deliberately happens before receipt lookup, so
    /// possession of another owner's idempotency key can neither replay their
    /// response nor turn an ownership miss into an idempotency conflict.
    pub async fn review_for_actor(
        &self,
        context: &AuthzContext,
        run_id: &str,
        approval_id: &str,
        request: ReviewRequest,
        idempotency_key: &str,
    ) -> Result<ReviewResponse, StoreError> {
        self.review_inner(context, None, run_id, approval_id, request, idempotency_key)
            .await
    }

    /// Test-only entrypoint for exercising dispatch after a requested-call
    /// fixture supplies explicit initiating authority. Production review has
    /// no such provenance in the current payload and must always pass `None`.
    #[cfg(test)]
    async fn review_for_actor_with_initiator(
        &self,
        context: &AuthzContext,
        initiating_context: &AuthzContext,
        run_id: &str,
        approval_id: &str,
        request: ReviewRequest,
        idempotency_key: &str,
    ) -> Result<ReviewResponse, StoreError> {
        self.review_inner(
            context,
            Some(initiating_context),
            run_id,
            approval_id,
            request,
            idempotency_key,
        )
        .await
    }

    async fn review_inner(
        &self,
        context: &AuthzContext,
        initiating_context: Option<&AuthzContext>,
        run_id: &str,
        approval_id: &str,
        request: ReviewRequest,
        idempotency_key: &str,
    ) -> Result<ReviewResponse, StoreError> {
        validate_durable_reference(run_id, "run ID")?;
        validate_durable_reference(approval_id, "approval ID")?;

        // Read the execution context before payload fingerprinting and receipt
        // lookup. Besides preserving the resource-not-found mask, this keeps a
        // pending approval visible across a same-key commit race; the final
        // write transaction can then replay the winning receipt instead of
        // incorrectly reporting that the approval is no longer pending.
        let review_context = self
            .storage
            .review_context_for_actor(context, run_id, approval_id)
            .await?;
        let idempotency_key = normalized_idempotency_key(idempotency_key)?;
        validate_review_request_value(&request)?;
        let fingerprint = review_fingerprint(run_id, approval_id, &request)?;

        if let Some(receipt) = self
            .storage
            .review_receipt_for_actor(context, run_id, idempotency_key)
            .await?
        {
            let response = replay_receipt(receipt, &fingerprint)?;
            self.kick_dispatcher();
            return Ok(response);
        }
        let (pending, call) = pending_approval_and_call(&review_context, approval_id)?;
        let approving = request.decision == ReviewDecision::Approve;
        if approving {
            self.validate_pending_policy(&review_context.snapshot.run, &pending, &call)?;
        }

        let expected_sequence = review_context.snapshot.run.sequence;
        let transition = apply_review(
            &review_context.snapshot.run,
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
            let evaluation = self.policy.guard_dispatch(
                &review_context.snapshot.run.environment,
                &call,
                Some(approved),
            );
            if evaluation.decision != PolicyDecision::Allow {
                return Err(policy_guard_error(evaluation));
            }
            Some(DispatchJobSpec {
                call_id: call.call_id.clone(),
                approval_id: approved.id.clone(),
                // ToolCallRequested does not yet carry trustworthy initiating
                // authority. Never substitute the approver: `None` persists
                // the missing provenance and claim rejects it before external
                // I/O. A future request payload must supply the exact durable
                // actor context before production may enqueue `Some` here.
                initiating_authz: initiating_context.cloned(),
                approving_authz: context.clone(),
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

        let mut snapshot = review_context.snapshot;
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
        let outcome = self
            .storage
            .commit_review_for_actor(context, commit)
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

    /// Durable dispatch-worker façade. No handler authority is accepted;
    /// storage revalidates both persisted subjects at the claim boundary.
    ///
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

    #[cfg(test)]
    async fn current_run(&self) -> Result<RunSummary, StoreError> {
        Ok(self.storage.snapshot(&self.primary_run_id).await?.run)
    }

    pub async fn current_run_for_actor(
        &self,
        context: &AuthzContext,
    ) -> Result<RunSummary, StoreError> {
        Ok(self
            .storage
            .snapshot_for_actor(context, &self.primary_run_id)
            .await?
            .run)
    }

    async fn recover_started_reply_jobs(&self) -> Result<(), StoreError> {
        loop {
            let recovered = retry_operation_capacity(|| async {
                Ok(self.storage.recover_started_replies().await?)
            })
            .await?;
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

    async fn recover_started_session_compactions(&self) -> Result<(), StoreError> {
        loop {
            let recovered = retry_operation_capacity(|| async {
                Ok(self.storage.recover_started_session_compactions().await?)
            })
            .await?;
            if recovered.is_empty() {
                return Ok(());
            }
        }
    }

    /// Recover every started Agent model/tool operation as outcome unknown.
    /// Queued work remains claimable and is never consumed by this pass.
    pub async fn recover_started_agent_work(&self) -> Result<(), StoreError> {
        loop {
            let recovered = retry_operation_capacity(|| async {
                Ok(self.storage.recover_started_agent_work().await?)
            })
            .await?;
            if recovered.is_empty() {
                return Ok(());
            }
            for completion in recovered {
                if !matches!(
                    completion.event.data,
                    SessionEventData::TurnInterrupted { .. }
                ) {
                    return Err(StoreError::ExecutionInvariant(
                        "started-Agent recovery returned a non-interruption event".into(),
                    ));
                }
                if !completion.replayed {
                    self.publish_session_event(&completion.session.id, completion.event);
                }
            }
        }
    }

    async fn recover_open_session_turns(&self) -> Result<(), StoreError> {
        loop {
            let recovered =
                retry_operation_capacity(|| async { Ok(self.storage.recover_open_turns().await?) })
                    .await?;
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
        if !self.auto_dispatch || !self.dispatcher_wake.request() {
            return;
        }
        let store = self.clone();
        tokio::spawn(async move {
            let mut retry_delay = INTERNAL_PROGRESS_RETRY_DELAY;
            loop {
                match store.dispatch_pending().await {
                    Err(error) if error.is_retryable_durable_completion_error() => {
                        eprintln!("zeus dispatcher retrying durable queue: {error}");
                        store.dispatcher_wake.request();
                        tokio::time::sleep(retry_delay).await;
                        retry_delay = retry_delay
                            .saturating_mul(2)
                            .min(INTERNAL_PROGRESS_RETRY_MAX_DELAY);
                    }
                    Err(error) => {
                        eprintln!("zeus dispatcher stopped on a permanent queue error: {error}");
                        retry_delay = INTERNAL_PROGRESS_RETRY_DELAY;
                    }
                    Ok(()) => retry_delay = INTERNAL_PROGRESS_RETRY_DELAY,
                }
                if !store.dispatcher_wake.complete_cycle() {
                    return;
                }
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
            let Some(job) =
                retry_operation_capacity(|| async { Ok(self.storage.peek_next_dispatch().await?) })
                    .await?
            else {
                return Ok(None);
            };
            self.validate_dispatch_job_identity(&job)?;
            let context = retry_operation_capacity(|| async {
                Ok(self.storage.dispatch_context(&job).await?)
            })
            .await?;
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

            let commit = DispatchStartCommit {
                call_id: job.call_id.clone(),
                expected_sequence,
                snapshot,
                event: transition.event,
            };
            match retry_operation_capacity(|| async {
                Ok(self.storage.claim_next_dispatch(commit.clone()).await?)
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

        let registry = Arc::clone(&self.registry);
        let call = claimed.call.clone();
        let environment = claimed.environment.clone();
        match tokio::spawn(async move { registry.dispatch(call, &environment).await }).await {
            Ok(Ok(output)) => ToolOutcome::Succeeded {
                summary: if output.replayed {
                    "The provider returned the durable result for this existing logical call."
                        .into()
                } else {
                    "The tool completed and its result was durably recorded.".into()
                },
                output_digest: Some(arguments_digest(&output.value)),
            },
            Ok(Err(error)) => registry_error_outcome(error),
            Err(_) => {
                eprintln!("zeus connector task panicked; settling outcome_unknown");
                ToolOutcome::OutcomeUnknown {
                    summary: "The connector stopped unexpectedly after the durable dispatch checkpoint; Zeus did not retry the external operation.".into(),
                }
            }
        }
    }

    async fn complete_dispatch(
        &self,
        claimed: ClaimedDispatch,
        outcome: ToolOutcome,
    ) -> Result<(), StoreError> {
        let mut snapshot = self
            .retry_consistent_snapshot_for_progress(&claimed.job.run_id)
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
        let commit = DispatchCompleteCommit {
            call_id: claimed.job.call_id,
            expected_sequence,
            snapshot,
            event: transition.event,
            result_json,
        };
        retry_durable_progress("dispatch completion", || async {
            Ok(self.storage.complete_dispatch(commit.clone()).await?)
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
            let jobs =
                retry_operation_capacity(|| async { Ok(self.storage.started_dispatches().await?) })
                    .await?;
            if jobs.is_empty() {
                return Ok(());
            }
            for job in jobs {
                self.validate_dispatch_job_identity(&job)?;
                let context = retry_operation_capacity(|| async {
                    Ok(self.storage.dispatch_context(&job).await?)
                })
                .await?;
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
                let commit = DispatchRecoveryCommit {
                    call_id: job.call_id,
                    expected_sequence,
                    snapshot,
                    event: transition.event,
                    result_json,
                };
                retry_durable_progress("dispatch recovery", || async {
                    Ok(self.storage.recover_started(commit.clone()).await?)
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
        if job.account_id != AccountId::local()
            || job.run_id != self.primary_run_id.as_ref()
            || job.policy_id != self.policy_id.as_ref()
            || job.policy_revision != self.policy_revision.as_ref()
        {
            return Err(StoreError::ExecutionInvariant(format!(
                "dispatch job {} is not bound to this runtime's account, run, and policy identity",
                job.call_id
            )));
        }
        Ok(())
    }

    async fn retry_consistent_snapshot_for_progress(
        &self,
        run_id: &str,
    ) -> Result<RunSnapshot, StoreError> {
        retry_durable_progress("dispatch result snapshot read", || async {
            Ok(self
                .storage
                .consistent_snapshot_for_progress(run_id)
                .await?)
        })
        .await
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
    fn build(
        profile: DemoProfile,
        terminal_service: Option<Arc<TerminalService>>,
        skill_catalog: Option<Arc<SkillCatalog>>,
    ) -> Result<Self, StoreError> {
        match profile {
            DemoProfile::ProductionGuarded => {
                if terminal_service.is_some() {
                    return Err(StoreError::ExecutionInvariant(
                        "terminal services are not accepted by the guarded production profile"
                            .into(),
                    ));
                }
                let scenario = DemoScenario::zr_1842();
                let call = requested_call(&scenario.events)?;
                let mut policy_rules = vec![PolicyRule {
                    revision: PRODUCTION_POLICY_REVISION.into(),
                    tool: call.tool,
                    environment: scenario.run.environment.clone(),
                    effect: call.effect,
                    sandbox_profile: call.sandbox_profile,
                    decision: PolicyDecision::RequireApproval,
                }];
                let mut registry = ToolRegistry::new();
                register_runtime_planning_tool(
                    &mut policy_rules,
                    &mut registry,
                    &scenario.run.environment,
                    PRODUCTION_POLICY_REVISION,
                )?;
                register_runtime_skill_tools(
                    &mut policy_rules,
                    &mut registry,
                    &scenario.run.environment,
                    PRODUCTION_POLICY_REVISION,
                    skill_catalog.as_ref(),
                )?;
                let policy = PolicyEngine::new(policy_rules)?;
                Ok(Self {
                    scenario,
                    policy,
                    registry,
                    profile_id: "production-guarded",
                    primary_session_id: protocol::DEMO_SESSION_ID,
                    policy_id: PRODUCTION_POLICY_ID,
                    policy_revision: PRODUCTION_POLICY_REVISION,
                })
            }
            DemoProfile::LocalDevelopment {
                marker_root,
                workspace_root,
            } => {
                let scenario = DemoScenario::local_marker();
                if scenario.run.environment != LOCAL_DEV_ENVIRONMENT {
                    return Err(StoreError::ExecutionInvariant(
                        "kernel and connector local environment names disagree".into(),
                    ));
                }
                let call = requested_call(&scenario.events)?;
                let mut policy_rules = vec![PolicyRule {
                    revision: LOCAL_POLICY_REVISION.into(),
                    tool: call.tool,
                    environment: scenario.run.environment.clone(),
                    effect: call.effect,
                    sandbox_profile: call.sandbox_profile,
                    decision: PolicyDecision::RequireApproval,
                }];
                let mut registry = ToolRegistry::new();
                register_runtime_planning_tool(
                    &mut policy_rules,
                    &mut registry,
                    &scenario.run.environment,
                    LOCAL_POLICY_REVISION,
                )?;
                register_local_dev_connectors(
                    &mut registry,
                    &scenario.run.environment,
                    marker_root,
                )?;
                if let Some(workspace_root) = workspace_root {
                    for descriptor in [
                        workspace_list_directory_descriptor(),
                        workspace_find_paths_descriptor(),
                        workspace_read_file_descriptor(),
                        workspace_read_lines_descriptor(),
                        workspace_search_text_descriptor(),
                    ] {
                        policy_rules.push(PolicyRule {
                            revision: LOCAL_POLICY_REVISION.into(),
                            tool: descriptor.name,
                            environment: scenario.run.environment.clone(),
                            effect: descriptor.effect,
                            sandbox_profile: descriptor.sandbox_profile,
                            decision: PolicyDecision::Allow,
                        });
                    }
                    for descriptor in [
                        workspace_replace_text_descriptor(),
                        workspace_create_file_descriptor(),
                        workspace_insert_text_descriptor(),
                    ] {
                        policy_rules.push(PolicyRule {
                            revision: LOCAL_POLICY_REVISION.into(),
                            tool: descriptor.name,
                            environment: scenario.run.environment.clone(),
                            effect: descriptor.effect,
                            sandbox_profile: descriptor.sandbox_profile,
                            decision: PolicyDecision::RequireApproval,
                        });
                    }
                    register_local_workspace_connectors(
                        &mut registry,
                        &scenario.run.environment,
                        workspace_root,
                    )?;
                }
                if let Some(terminal_service) = terminal_service {
                    for descriptor in [terminal_read_descriptor(), terminal_list_descriptor()] {
                        policy_rules.push(PolicyRule {
                            revision: LOCAL_POLICY_REVISION.into(),
                            tool: descriptor.name,
                            environment: scenario.run.environment.clone(),
                            effect: descriptor.effect,
                            sandbox_profile: descriptor.sandbox_profile,
                            decision: PolicyDecision::Allow,
                        });
                    }
                    for descriptor in [
                        terminal_open_descriptor(),
                        terminal_send_descriptor(),
                        terminal_signal_descriptor(),
                        terminal_close_descriptor(),
                    ] {
                        policy_rules.push(PolicyRule {
                            revision: LOCAL_POLICY_REVISION.into(),
                            tool: descriptor.name,
                            environment: scenario.run.environment.clone(),
                            effect: descriptor.effect,
                            sandbox_profile: descriptor.sandbox_profile,
                            decision: PolicyDecision::RequireApproval,
                        });
                    }
                    register_local_terminal_connectors(
                        &mut registry,
                        &scenario.run.environment,
                        terminal_service,
                    )?;
                }
                register_runtime_skill_tools(
                    &mut policy_rules,
                    &mut registry,
                    &scenario.run.environment,
                    LOCAL_POLICY_REVISION,
                    skill_catalog.as_ref(),
                )?;
                let policy = PolicyEngine::new(policy_rules)?;
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

fn register_runtime_planning_tool(
    policy_rules: &mut Vec<PolicyRule>,
    registry: &mut ToolRegistry,
    environment: &str,
    policy_revision: &str,
) -> Result<(), StoreError> {
    let descriptor = todo_write_descriptor();
    policy_rules.push(PolicyRule {
        revision: policy_revision.into(),
        tool: descriptor.name,
        environment: environment.into(),
        effect: descriptor.effect,
        sandbox_profile: descriptor.sandbox_profile,
        decision: PolicyDecision::Allow,
    });
    register_todo_tool(registry)?;
    Ok(())
}

fn register_runtime_skill_tools(
    policy_rules: &mut Vec<PolicyRule>,
    registry: &mut ToolRegistry,
    environment: &str,
    policy_revision: &str,
    catalog: Option<&Arc<SkillCatalog>>,
) -> Result<(), StoreError> {
    let Some(catalog) = catalog else {
        return Ok(());
    };
    for descriptor in skill_tool_descriptors(catalog) {
        policy_rules.push(PolicyRule {
            revision: policy_revision.into(),
            tool: descriptor.name,
            environment: environment.into(),
            effect: descriptor.effect,
            sandbox_profile: descriptor.sandbox_profile,
            decision: PolicyDecision::Allow,
        });
    }
    register_skill_tools(registry, Arc::clone(catalog))?;
    Ok(())
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
        | RegistryError::InvalidExecutionScope(_)
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
        RegistryError::Executor(ExecutorError::OutcomeUnknown { message }) => {
            ToolOutcome::OutcomeUnknown { summary: message }
        }
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

fn invalid_deployment_manifest(error: deployment::ManifestError) -> StoreError {
    StoreError::ExecutionInvariant(format!(
        "invalid session Agent deployment manifest: {error}"
    ))
}

fn invalid_agent_deployment_manifest(error: deployment::ManifestError) -> StoreError {
    StoreError::InvalidAgentTransition(format!("invalid Agent deployment manifest: {error}"))
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
        AgentToolCallStatus, AgentTurnStatus, ApprovalScope, DEMO_RUN_ID, DEMO_SESSION_ID,
        LOCAL_DEMO_RUN_ID, LOCAL_DEMO_SESSION_ID, RunStatus, SandboxProfile, SessionStatus,
        SessionTurnStatus, ToolCallStatus, ToolEffect,
    };
    use rusqlite::{Connection, params};
    use storage::DispatchStatus;
    use tools::{
        ExecutionFuture, ExecutionRequest, RecordingExecutor, TOOL_OUTPUT_MAX_SERIALIZED_BYTES,
        ToolExecutor,
    };

    use super::*;

    static NEXT_PATH: AtomicU64 = AtomicU64::new(1);
    const TEST_OWNER_ID: &str = "user-runtime-owner";

    fn test_authz(user_id: &str) -> AuthzContext {
        AuthzContext {
            account_id: AccountId::local(),
            user_id: user_id.into(),
            membership_role: MembershipRole::Owner,
            membership_revision: MembershipRevision::new(1).unwrap(),
            auth_session_id: AuthSessionId::from_persistence(format!("runtime-test-{user_id}"))
                .unwrap(),
        }
    }

    fn approval_for_resolved_tool(resolved: &ResolvedSessionAgentTool) -> Approval {
        Approval {
            id: "APR-agent-tool".into(),
            status: ApprovalStatus::Approved,
            action: "execute the resolved agent tool".into(),
            tool: resolved.call().tool.clone(),
            change: "apply the exact approved tool call".into(),
            requires_approval: true,
            call_id: Some(resolved.call().call_id.clone()),
            policy_revision: Some(resolved.policy_evaluation().policy_revision.clone()),
            arguments_digest: Some(resolved.call().arguments_digest.clone()),
            sandbox_profile: Some(resolved.call().sandbox_profile.clone()),
            scope: Some(ApprovalScope::AllowOnce),
        }
    }

    fn scoped_resolved_tool(
        resolved: ResolvedSessionAgentTool,
        agent_id: &str,
    ) -> ScopedSessionAgentTool {
        ScopedSessionAgentTool {
            resolved,
            scope: ExecutionScope::new(
                AccountId::local().as_str(),
                TEST_OWNER_ID,
                "session-agent-runtime",
                "turn-agent-runtime",
                agent_id,
            )
            .unwrap(),
        }
    }

    fn persisted_agent_tool_call(
        resolved: &ResolvedSessionAgentTool,
        agent_id: &str,
        model_step: u32,
        ordinal: u32,
    ) -> AgentToolCall {
        let call = resolved.call();
        let timestamp = now();
        AgentToolCall {
            call_id: call.call_id.clone(),
            agent_id: agent_id.into(),
            account_id: AccountId::local(),
            session_id: "session-agent-runtime".into(),
            turn_id: "turn-agent-runtime".into(),
            provider_call_id: "provider-call-runtime".into(),
            ordinal,
            model_step,
            tool_name: call.tool.clone(),
            tool_version: call.tool_version.clone(),
            arguments_json: call.arguments.clone(),
            arguments_digest: call.arguments_digest.clone(),
            effect: call.effect.clone(),
            sandbox_profile: call.sandbox_profile.clone(),
            executor_status: call.executor_status.clone(),
            policy_decision: resolved.policy_evaluation().decision.clone(),
            policy_revision: resolved.policy_evaluation().policy_revision.clone(),
            status: AgentToolCallStatus::Running,
            approving_actor_user_id: Some(TEST_OWNER_ID.into()),
            approving_membership_revision: Some(MembershipRevision::new(1).unwrap()),
            review_note: None,
            reviewed_at: Some(timestamp.clone()),
            result_json: None,
            provider_request_id: None,
            created_at: timestamp.clone(),
            started_at: Some(timestamp),
            finished_at: None,
        }
    }

    fn manifest_with_spec_mutation(
        manifest: &ManifestEnvelope,
        mutate: impl FnOnce(&mut AgentSpec),
    ) -> ManifestEnvelope {
        let mut changed = manifest.manifest.clone();
        mutate(&mut changed.deployment.spec);
        ManifestEnvelope::new(changed).unwrap()
    }

    fn agent_request_for_manifest(manifest: &ManifestEnvelope, content: &str) -> Value {
        let knowledge = agent_knowledge_for_message(content);
        let tools = manifest
            .manifest
            .deployment
            .spec
            .tools
            .iter()
            .map(|tool| {
                serde_json::json!({
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.input_schema,
                })
            })
            .collect::<Vec<_>>();
        let mut messages = Vec::new();
        if manifest.manifest.deployment.spec.prompt.is_some() {
            messages.push(serde_json::json!({
                "role": "system",
                "content": DEFAULT_SESSION_AGENT_SYSTEM_PROMPT,
            }));
        }
        messages.push(serde_json::json!({
            "role": "user",
            "content": content,
        }));
        messages.push(serde_json::json!({
            "role": "context",
            "content": knowledge.snapshot.snapshot().canonical_context(),
        }));
        serde_json::json!({
            "messages": messages,
            "tools": tools,
        })
    }

    fn agent_knowledge_for_message(content: &str) -> AgentKnowledgeContextSpec {
        let corpus = CorpusRevisionEnvelope::new(Vec::new()).unwrap();
        let snapshot =
            SelectionSnapshotEnvelope::new(select_context(content, corpus.entries()).unwrap())
                .unwrap();
        AgentKnowledgeContextSpec { corpus, snapshot }
    }

    fn test_skill_catalog(content: &str) -> Arc<SkillCatalog> {
        Arc::new(
            SkillCatalog::from_json_slice(
                &serde_json::to_vec(&serde_json::json!({
                    "version": 1,
                    "skills": [{
                        "name": "incident_triage",
                        "version": "1.0.0",
                        "description": "Triage an incident using bounded evidence",
                        "content": content,
                    }]
                }))
                .unwrap(),
            )
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn session_agent_tool_definitions_expose_only_provider_contracts() {
        let paths = TestPaths::new("agent-tool-definitions");
        let store = local_store(&paths, false).await;

        let definitions = store.session_agent_tool_definitions().unwrap();
        assert_eq!(definitions.len(), 2);
        assert_eq!(definitions[0].name, connectors::DEV_MARKER_TOOL_NAME);
        assert_eq!(
            definitions[0].input_schema,
            serde_json::json!({
                "type": "object",
                "properties": {
                    "marker": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 128
                    }
                },
                "required": ["marker"],
                "additionalProperties": false,
                "x-zeus-max-serialized-bytes": 160
            })
        );
        assert_eq!(definitions[1].name, planning::TODO_WRITE_TOOL_NAME);
        assert_eq!(
            definitions[1].input_schema["properties"]["todos"]["maxItems"],
            planning::TODO_MAX_ITEMS
        );
        assert_eq!(
            definitions[1].input_schema["properties"]["todos"]["items"]["properties"]["status"]["enum"],
            serde_json::json!(["pending", "in_progress", "completed"])
        );

        let production = DemoStore::seeded().await.unwrap();
        assert_eq!(
            production
                .session_agent_tool_definitions()
                .unwrap()
                .iter()
                .map(|definition| definition.name.as_str())
                .collect::<Vec<_>>(),
            [planning::TODO_WRITE_TOOL_NAME]
        );
    }

    #[tokio::test]
    async fn todo_dispatch_preflights_the_durable_agent_revision() {
        let paths = TestPaths::new("agent-todo-revision-preflight");
        let store = local_store(&paths, false).await;
        let owner = test_authz(TEST_OWNER_ID);
        let manifest = store
            .session_agent_manifest(
                "test-provider",
                Some("test-model".into()),
                AssistantReplyKind::Model,
            )
            .unwrap();
        let agent_id = "agent-todo-revision-preflight";
        let turn_id = "turn-todo-revision-preflight";
        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner,
                LOCAL_DEMO_SESSION_ID,
                StartTurnRequest {
                    turn_id: turn_id.into(),
                    user_message: "Create a durable plan".into(),
                    expected_sequence: 2,
                },
                "todo-revision-preflight-start",
                AgentTurnSpec {
                    id: agent_id.into(),
                    authz: owner.clone(),
                    environment: LOCAL_DEV_ENVIRONMENT.into(),
                    provider_name: "test-provider".into(),
                    model_name: Some("test-model".into()),
                    request_json: agent_request_for_manifest(&manifest, "Create a durable plan"),
                    knowledge: agent_knowledge_for_message("Create a durable plan"),
                    manifest,
                },
            )
            .await
            .unwrap();

        let scope = || {
            ExecutionScope::new(
                AccountId::local().as_str(),
                TEST_OWNER_ID,
                LOCAL_DEMO_SESSION_ID,
                turn_id,
                agent_id,
            )
            .unwrap()
        };
        let stale = store
            .resolve_session_agent_tool(
                agent_id,
                1,
                1,
                planning::TODO_WRITE_TOOL_NAME,
                serde_json::json!({
                    "expected_revision": 1,
                    "todos": [{"content": "stale write", "status": "in_progress"}],
                }),
            )
            .unwrap();
        let error = store
            .dispatch_session_agent_tool_after_checkpoint(
                ScopedSessionAgentTool {
                    resolved: stale,
                    scope: scope(),
                },
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.known_executor_failure(),
            Some((
                "todo_revision_conflict",
                "The todo list changed: expected revision 1, current revision 0",
                false,
            ))
        );

        let fresh = store
            .resolve_session_agent_tool(
                agent_id,
                1,
                1,
                planning::TODO_WRITE_TOOL_NAME,
                serde_json::json!({
                    "expected_revision": 0,
                    "todos": [{"content": "fresh write", "status": "in_progress"}],
                }),
            )
            .unwrap();
        let output = store
            .dispatch_session_agent_tool_after_checkpoint(
                ScopedSessionAgentTool {
                    resolved: fresh,
                    scope: scope(),
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(output.value["revision"], 1);
        assert_eq!(output.value["todos"][0]["content"], "fresh write");
    }

    #[tokio::test]
    async fn startup_skill_catalog_is_manifest_bound_and_policy_allowed() {
        let paths = TestPaths::new("agent-skill-catalog");
        let catalog = test_skill_catalog("# Incident triage\nInspect evidence before acting.");
        let store = DemoStore::from_storage_with_terminal_and_skills(
            SqliteStore::open(&paths.database).await.unwrap(),
            DemoProfile::LocalDevelopment {
                marker_root: paths.marker_root.clone(),
                workspace_root: None,
            },
            false,
            None,
            Some(Arc::clone(&catalog)),
        )
        .await
        .unwrap();
        bootstrap_test_owner(&store).await;

        let definitions = store.session_agent_tool_definitions().unwrap();
        assert_eq!(
            definitions
                .iter()
                .map(|definition| definition.name.as_str())
                .collect::<Vec<_>>(),
            [
                connectors::DEV_MARKER_TOOL_NAME,
                skills::SKILL_LIST_TOOL_NAME,
                skills::SKILL_LOAD_TOOL_NAME,
                planning::TODO_WRITE_TOOL_NAME,
            ]
        );
        let manifest = store
            .session_agent_manifest(
                "test-provider",
                Some("test-model".into()),
                AssistantReplyKind::Model,
            )
            .unwrap();
        for tool in manifest
            .manifest
            .deployment
            .spec
            .tools
            .iter()
            .filter(|tool| tool.name.starts_with("skill_"))
        {
            assert_eq!(tool.version, catalog.digest());
            assert_eq!(tool.effect, ToolEffect::ReadOnly);
            assert_eq!(tool.sandbox_profile, SandboxProfile::ReadOnly);
        }
        let resolved = store
            .resolve_session_agent_tool(
                "agent-skill-policy",
                1,
                0,
                skills::SKILL_LOAD_TOOL_NAME,
                serde_json::json!({"name": "incident_triage"}),
            )
            .unwrap();
        assert_eq!(resolved.policy_evaluation().decision, PolicyDecision::Allow);
    }

    #[tokio::test]
    async fn restart_skill_drift_rejects_queued_agent_before_claim() {
        let paths = TestPaths::new("agent-skill-restart-drift");
        let baseline_catalog = test_skill_catalog("# Triage\nUse revision one.");
        let store = DemoStore::from_storage_with_terminal_and_skills(
            SqliteStore::open(&paths.database).await.unwrap(),
            DemoProfile::LocalDevelopment {
                marker_root: paths.marker_root.clone(),
                workspace_root: None,
            },
            false,
            None,
            Some(baseline_catalog),
        )
        .await
        .unwrap();
        bootstrap_test_owner(&store).await;
        let owner = test_authz(TEST_OWNER_ID);
        let manifest = store
            .session_agent_manifest(
                "test-provider",
                Some("test-model".into()),
                AssistantReplyKind::Model,
            )
            .unwrap();
        let turn_id = "turn-skill-restart-drift";
        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner,
                LOCAL_DEMO_SESSION_ID,
                StartTurnRequest {
                    turn_id: turn_id.into(),
                    user_message: "Use the deployment-bound triage skill.".into(),
                    expected_sequence: 2,
                },
                "skill-restart-drift-start",
                AgentTurnSpec {
                    id: "agent-skill-restart-drift".into(),
                    authz: owner.clone(),
                    environment: LOCAL_DEV_ENVIRONMENT.into(),
                    provider_name: "test-provider".into(),
                    model_name: Some("test-model".into()),
                    request_json: agent_request_for_manifest(
                        &manifest,
                        "Use the deployment-bound triage skill.",
                    ),
                    knowledge: agent_knowledge_for_message(
                        "Use the deployment-bound triage skill.",
                    ),
                    manifest: manifest.clone(),
                },
            )
            .await
            .unwrap();
        drop(store);

        let changed_catalog = test_skill_catalog("# Triage\nUse revision two.");
        let reopened = DemoStore::from_storage_with_terminal_and_skills(
            SqliteStore::open(&paths.database).await.unwrap(),
            DemoProfile::LocalDevelopment {
                marker_root: paths.marker_root.clone(),
                workspace_root: None,
            },
            false,
            None,
            Some(changed_catalog),
        )
        .await
        .unwrap();
        let error = reopened
            .prepare_next_agent_model(&manifest, "skill-drift-holder")
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            StoreError::InvalidAgentTransition(message)
                if message.contains("runtime-resolved deployment")
        ));
        let queued = reopened
            .next_agent_model_for_holder("skill-drift-holder")
            .await
            .unwrap()
            .expect("manifest drift must leave the model job queued and unclaimed");
        assert_eq!(queued.status, AgentModelJobStatus::Queued);
        let detail = reopened
            .agent_turn_detail_for_actor(&owner, LOCAL_DEMO_SESSION_ID, turn_id)
            .await
            .unwrap();
        assert_eq!(detail.status, AgentTurnStatus::WaitingModel);
        assert_eq!(detail.model_steps, 0);
        assert_eq!(detail.tool_calls, 0);
        let current = reopened
            .session_agent_manifest(
                "test-provider",
                Some("test-model".into()),
                AssistantReplyKind::Model,
            )
            .unwrap();
        assert_ne!(manifest.digest, current.digest);
    }

    #[tokio::test]
    async fn session_agent_manifest_is_stable_and_secret_free() {
        let paths = TestPaths::new("agent-manifest-stable");
        let store = local_store(&paths, false).await;

        let first = store
            .session_agent_manifest(
                "openai-compatible:route-v1",
                Some("deepseek-chat".into()),
                AssistantReplyKind::Model,
            )
            .unwrap();
        let second = store
            .session_agent_manifest(
                "openai-compatible:route-v1",
                Some("deepseek-chat".into()),
                AssistantReplyKind::Model,
            )
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.digest, first.manifest.digest().unwrap());
        assert_eq!(
            first.manifest.deployment.deployment_id,
            "zeus-session-agent-local-development"
        );
        assert_eq!(first.manifest.deployment.revision, "2");
        assert_eq!(first.manifest.deployment.spec.spec_id, "zeus-session-agent");
        assert_eq!(first.manifest.deployment.spec.revision, "2");
        assert_eq!(first.manifest.deployment.spec.profile, "local-development");
        let prompt = first
            .manifest
            .deployment
            .spec
            .prompt
            .as_ref()
            .expect("the Session Agent deployment binds a system prompt");
        assert_eq!(prompt.prompt_id, SESSION_AGENT_PROMPT_ID);
        assert_eq!(prompt.revision, DEFAULT_SESSION_AGENT_PROMPT_REVISION);
        assert!(prompt.matches_content(store.session_agent_system_prompt()));
        assert_eq!(
            first.manifest.deployment.spec.workflow_schema_version,
            workflows::STATE_SCHEMA_VERSION
        );
        assert_eq!(
            first.manifest.deployment.spec.loop_limits,
            workflows::Limits::default()
        );

        let serialized = String::from_utf8(first.canonical_json_bytes().unwrap()).unwrap();
        for forbidden in [
            "endpoint",
            "api_key",
            "\"secret\"",
            "secret_value",
            DEFAULT_SESSION_AGENT_SYSTEM_PROMPT,
        ] {
            assert!(
                !serialized.contains(forbidden),
                "manifest serialized forbidden field {forbidden}"
            );
        }
        let provider = serde_json::to_value(&first.manifest.deployment.spec.provider).unwrap();
        let provider_keys = provider
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert_eq!(provider_keys, ["model", "provider_id", "reply_kind"]);
    }

    #[tokio::test]
    async fn session_agent_manifest_digest_tracks_profile_tool_and_provider_drift() {
        let paths = TestPaths::new("agent-manifest-drift");
        let store = local_store(&paths, false).await;
        let baseline = store
            .session_agent_manifest(
                "openai-compatible:route-v1",
                Some("deepseek-chat".into()),
                AssistantReplyKind::Model,
            )
            .unwrap();

        let provider_drift = store
            .session_agent_manifest(
                "openai-compatible:route-v1",
                Some("deepseek-reasoner".into()),
                AssistantReplyKind::Model,
            )
            .unwrap();
        assert_ne!(baseline.digest, provider_drift.digest);

        let prompt_revision_drift = manifest_with_spec_mutation(&baseline, |spec| {
            spec.prompt = Some(
                ManifestPromptBinding::from_content(
                    SESSION_AGENT_PROMPT_ID,
                    "2",
                    DEFAULT_SESSION_AGENT_SYSTEM_PROMPT,
                )
                .unwrap(),
            );
        });
        assert_ne!(baseline.digest, prompt_revision_drift.digest);

        let prompt_content_drift = manifest_with_spec_mutation(&baseline, |spec| {
            spec.prompt = Some(
                ManifestPromptBinding::from_content(
                    SESSION_AGENT_PROMPT_ID,
                    DEFAULT_SESSION_AGENT_PROMPT_REVISION,
                    "You are a different execution agent.",
                )
                .unwrap(),
            );
        });
        assert_ne!(baseline.digest, prompt_content_drift.digest);

        let mut profile_drift_store = store.clone();
        profile_drift_store.profile_id = Arc::from("local-development-v2");
        let profile_drift = profile_drift_store
            .session_agent_manifest(
                "openai-compatible:route-v1",
                Some("deepseek-chat".into()),
                AssistantReplyKind::Model,
            )
            .unwrap();
        assert_ne!(baseline.digest, profile_drift.digest);

        let mut descriptor = connectors::dev_marker_descriptor();
        descriptor
            .description
            .push_str(" with a changed provider-visible contract");
        let mut changed_registry = ToolRegistry::new();
        changed_registry
            .register(
                descriptor,
                RecordingExecutor::new(serde_json::json!({"changed": true})),
            )
            .unwrap();
        let mut tool_drift_store = store.clone();
        tool_drift_store.registry = Arc::new(changed_registry);
        let tool_drift = tool_drift_store
            .session_agent_manifest(
                "openai-compatible:route-v1",
                Some("deepseek-chat".into()),
                AssistantReplyKind::Model,
            )
            .unwrap();
        assert_ne!(baseline.digest, tool_drift.digest);
    }

    #[tokio::test]
    async fn session_agent_manifest_tools_match_provider_visible_definitions() {
        let paths = TestPaths::new("agent-manifest-tool-contract");
        let store = local_store(&paths, false).await;
        let definitions = store.session_agent_tool_definitions().unwrap();
        let envelope = store
            .session_agent_manifest(
                "openai-compatible:route-v1",
                Some("deepseek-chat".into()),
                AssistantReplyKind::Model,
            )
            .unwrap();
        let tools = &envelope.manifest.deployment.spec.tools;

        assert_eq!(definitions.len(), tools.len());
        for (definition, tool) in definitions.iter().zip(tools) {
            assert_eq!(definition.name, tool.name);
            assert_eq!(definition.description, tool.description);
            assert_eq!(definition.input_schema, tool.input_schema);
            assert_eq!(tool.executor_status, ToolExecutorStatus::Available);
        }
        assert!(tools.windows(2).all(|pair| pair[0].name < pair[1].name));
    }

    #[tokio::test]
    async fn agent_start_rejects_runtime_binding_drift_before_enqueue() {
        let paths = TestPaths::new("agent-manifest-runtime-binding");
        let store = local_store(&paths, false).await;
        let owner = test_authz(TEST_OWNER_ID);
        let baseline = store
            .session_agent_manifest(
                "test-provider",
                Some("test-model".into()),
                AssistantReplyKind::Model,
            )
            .unwrap();
        let profile_mismatch = manifest_with_spec_mutation(&baseline, |spec| {
            spec.profile = "other-profile".into();
        });
        let environment_mismatch = manifest_with_spec_mutation(&baseline, |spec| {
            spec.environment = "other-environment".into();
        });
        let policy_mismatch = manifest_with_spec_mutation(&baseline, |spec| {
            spec.policy.policy_id = "other-policy".into();
            spec.policy.revision = "2".into();
        });
        let tool_contract_mismatch = manifest_with_spec_mutation(&baseline, |spec| {
            spec.tools[0]
                .description
                .push_str(" with a caller-substituted contract");
        });

        for (label, expected_error, manifest) in [
            ("profile", "profile", profile_mismatch),
            ("environment", "environment", environment_mismatch),
            ("policy", "policy", policy_mismatch),
            (
                "tool-contract",
                "runtime-resolved deployment",
                tool_contract_mismatch,
            ),
        ] {
            let result = store
                .start_turn_and_enqueue_agent_for_actor(
                    &owner,
                    LOCAL_DEMO_SESSION_ID,
                    StartTurnRequest {
                        turn_id: format!("turn-runtime-manifest-{label}"),
                        user_message: "This invalid deployment must not enqueue.".into(),
                        expected_sequence: 2,
                    },
                    &format!("runtime-manifest-{label}"),
                    AgentTurnSpec {
                        id: format!("agent-runtime-manifest-{label}"),
                        authz: owner.clone(),
                        environment: LOCAL_DEV_ENVIRONMENT.into(),
                        provider_name: "test-provider".into(),
                        model_name: Some("test-model".into()),
                        request_json: agent_request_for_manifest(
                            &manifest,
                            "This invalid deployment must not enqueue.",
                        ),
                        knowledge: agent_knowledge_for_message(
                            "This invalid deployment must not enqueue.",
                        ),
                        manifest,
                    },
                )
                .await;
            assert!(
                matches!(
                    result,
                    Err(StoreError::InvalidAgentTransition(message))
                        if message.contains(expected_error)
                ),
                "runtime must reject a valid but mismatched {label} manifest"
            );
            assert_eq!(
                store
                    .get_session_for_actor(
                        &owner,
                        LOCAL_DEMO_SESSION_ID,
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
                2,
                "a rejected {label} manifest must not append a Session turn"
            );
        }
    }

    #[tokio::test]
    async fn actor_manifest_query_is_account_scoped() {
        let paths = TestPaths::new("agent-manifest-actor-scope");
        let store = local_store(&paths, false).await;
        let owner = test_authz(TEST_OWNER_ID);
        let manifest = store
            .session_agent_manifest(
                "test-provider",
                Some("test-model".into()),
                AssistantReplyKind::Model,
            )
            .unwrap();
        let turn_id = "turn-runtime-agent-manifest-scope";
        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner,
                LOCAL_DEMO_SESSION_ID,
                StartTurnRequest {
                    turn_id: turn_id.into(),
                    user_message: "Persist this deployment manifest.".into(),
                    expected_sequence: 2,
                },
                "runtime-agent-manifest-scope",
                AgentTurnSpec {
                    id: "agent-runtime-manifest-scope".into(),
                    authz: owner.clone(),
                    environment: LOCAL_DEV_ENVIRONMENT.into(),
                    provider_name: "test-provider".into(),
                    model_name: Some("test-model".into()),
                    request_json: agent_request_for_manifest(
                        &manifest,
                        "Persist this deployment manifest.",
                    ),
                    knowledge: agent_knowledge_for_message("Persist this deployment manifest."),
                    manifest: manifest.clone(),
                },
            )
            .await
            .unwrap();

        assert_eq!(
            store
                .agent_deployment_manifest_for_actor(&owner, LOCAL_DEMO_SESSION_ID, turn_id,)
                .await
                .unwrap(),
            Some(manifest)
        );

        let foreign = install_foreign_owner_authz(&paths.database);
        assert!(matches!(
            store
                .agent_deployment_manifest_for_actor(
                    &foreign,
                    LOCAL_DEMO_SESSION_ID,
                    turn_id,
                )
                .await,
            Err(StoreError::SessionNotFound(session_id))
                if session_id == LOCAL_DEMO_SESSION_ID
        ));
    }

    #[tokio::test]
    async fn non_model_fallback_manifest_can_enqueue_and_claim() {
        let paths = TestPaths::new("agent-manifest-non-model-fallback");
        let store = local_store(&paths, false).await;
        let owner = test_authz(TEST_OWNER_ID);
        let manifest = store
            .session_agent_manifest("local-fallback", None, AssistantReplyKind::NonModelFallback)
            .unwrap();

        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner,
                LOCAL_DEMO_SESSION_ID,
                StartTurnRequest {
                    turn_id: "turn-runtime-agent-fallback".into(),
                    user_message: "Use the bounded non-model fallback.".into(),
                    expected_sequence: 2,
                },
                "runtime-agent-fallback-start",
                AgentTurnSpec {
                    id: "agent-runtime-fallback".into(),
                    authz: owner.clone(),
                    environment: LOCAL_DEV_ENVIRONMENT.into(),
                    provider_name: "local-fallback".into(),
                    model_name: None,
                    request_json: agent_request_for_manifest(
                        &manifest,
                        "Use the bounded non-model fallback.",
                    ),
                    knowledge: agent_knowledge_for_message("Use the bounded non-model fallback."),
                    manifest: manifest.clone(),
                },
            )
            .await
            .unwrap();

        let AgentModelClaimOutcome::Claimed(job) =
            store.claim_next_agent_model(&manifest).await.unwrap()
        else {
            panic!("the fallback Agent model step must be claimable");
        };
        assert_eq!(job.provider_name, "local-fallback");
        assert_eq!(job.model_name, None);
    }

    #[tokio::test]
    async fn replayed_agent_final_completion_is_broadcast_only_once() {
        let paths = TestPaths::new("agent-final-live-replay");
        let store = local_store(&paths, false).await;
        let owner = test_authz(TEST_OWNER_ID);
        let turn_id = "turn-runtime-agent-final";
        let manifest = store
            .session_agent_manifest(
                "test-provider",
                Some("test-model".into()),
                AssistantReplyKind::Model,
            )
            .unwrap();
        let enqueued = store
            .start_turn_and_enqueue_agent_for_actor(
                &owner,
                LOCAL_DEMO_SESSION_ID,
                StartTurnRequest {
                    turn_id: turn_id.into(),
                    user_message: "Finish this Agent turn exactly once.".into(),
                    expected_sequence: 2,
                },
                "runtime-agent-final-start",
                AgentTurnSpec {
                    id: "agent-runtime-final".into(),
                    authz: owner.clone(),
                    environment: LOCAL_DEV_ENVIRONMENT.into(),
                    provider_name: "test-provider".into(),
                    model_name: Some("test-model".into()),
                    request_json: agent_request_for_manifest(
                        &manifest,
                        "Finish this Agent turn exactly once.",
                    ),
                    knowledge: agent_knowledge_for_message("Finish this Agent turn exactly once."),
                    manifest: manifest.clone(),
                },
            )
            .await
            .unwrap();
        let AgentModelClaimOutcome::Claimed(job) =
            store.claim_next_agent_model(&manifest).await.unwrap()
        else {
            panic!("the first runtime Agent model step must be claimable");
        };
        let mut feed = store
            .session_event_feed_for_actor(
                &owner,
                LOCAL_DEMO_SESSION_ID,
                enqueued.start.event.sequence,
            )
            .await
            .unwrap();
        assert!(feed.replay.is_empty());

        let assistant_message = "The runtime Agent turn completed durably.";
        let commit = AgentModelSuccessCommit {
            job_id: job.id,
            response_json: serde_json::json!({
                "output": {
                    "type": "final",
                    "content": assistant_message,
                },
                "finish_reason": "stop",
                "provider": {
                    "provider_id": "test-provider",
                    "model": "test-model",
                    "reply_kind": "model",
                },
            }),
            resolution: AgentModelResolution::Final {
                assistant_message: assistant_message.into(),
                provenance: protocol::AssistantReplyProvenance {
                    provider_id: "test-provider".into(),
                    model: Some("test-model".into()),
                    reply_kind: protocol::AssistantReplyKind::Model,
                },
            },
        };
        let AgentModelCompletion::Final(first) = store
            .complete_agent_model_success(commit.clone())
            .await
            .unwrap()
        else {
            panic!("the first Agent completion must finalize the Session turn");
        };
        assert!(!first.replayed);
        for expected in &first.events {
            let published = tokio::time::timeout(Duration::from_secs(1), feed.receiver.recv())
                .await
                .expect("fresh Agent finalization must wake the live Session feed")
                .unwrap();
            assert_eq!(published.session_id, LOCAL_DEMO_SESSION_ID);
            assert_eq!(&published.event, expected);
        }

        let AgentModelCompletion::Final(replayed) =
            store.complete_agent_model_success(commit).await.unwrap()
        else {
            panic!("the duplicate Agent completion must replay the durable finalization");
        };
        assert!(replayed.replayed);
        assert_eq!(replayed.events, first.events);
        assert!(matches!(
            feed.receiver.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn session_agent_resolution_owns_the_execution_contract() {
        let paths = TestPaths::new("agent-tool-resolution");
        let store = local_store(&paths, false).await;
        let arguments = serde_json::json!({"marker": "agent safe"});

        let resolved = store
            .resolve_session_agent_tool(
                "agent-turn-7",
                2,
                1,
                connectors::DEV_MARKER_TOOL_NAME,
                arguments.clone(),
            )
            .unwrap();
        let call = resolved.call();
        assert_eq!(
            call.call_id,
            stable_agent_call_id("agent-turn-7", 2, 1).unwrap()
        );
        assert_eq!(call.tool, connectors::DEV_MARKER_TOOL_NAME);
        assert_eq!(call.tool_version, connectors::DEV_MARKER_TOOL_VERSION);
        assert_eq!(call.arguments, arguments);
        assert_eq!(call.arguments_digest, arguments_digest(&call.arguments));
        assert_eq!(call.effect, ToolEffect::LocalWrite);
        assert_eq!(call.sandbox_profile, SandboxProfile::WorkspaceWrite);
        assert_eq!(call.executor_status, ToolExecutorStatus::Available);
        assert_eq!(resolved.environment(), LOCAL_DEV_ENVIRONMENT);
        assert_eq!(
            resolved.policy_evaluation().decision,
            PolicyDecision::RequireApproval
        );
        assert_eq!(
            resolved.policy_evaluation().policy_revision,
            LOCAL_POLICY_REVISION
        );

        let unknown = store
            .resolve_session_agent_tool(
                "agent-turn-7",
                2,
                1,
                "model.supplied.tool",
                serde_json::json!({}),
            )
            .unwrap_err();
        assert!(matches!(
            unknown,
            StoreError::Registry(RegistryError::UnknownTool(name))
                if name == "model.supplied.tool"
        ));

        let injected_execution_fields = store
            .resolve_session_agent_tool(
                "agent-turn-7",
                2,
                1,
                connectors::DEV_MARKER_TOOL_NAME,
                serde_json::json!({
                    "marker": "agent safe",
                    "version": "model-version",
                    "effect": "destructive",
                    "sandbox": "production_guarded"
                }),
            )
            .unwrap_err();
        assert!(matches!(
            injected_execution_fields,
            StoreError::Registry(RegistryError::InvalidArguments(_))
        ));
    }

    #[tokio::test]
    async fn persisted_session_agent_tool_is_rehydrated_before_dispatch() {
        let paths = TestPaths::new("agent-tool-rehydrate");
        let store = local_store(&paths, false).await;
        let agent_id = "agent-turn-rehydrate";
        let resolved = store
            .resolve_session_agent_tool(
                agent_id,
                2,
                1,
                connectors::DEV_MARKER_TOOL_NAME,
                serde_json::json!({"marker": "rehydrated call"}),
            )
            .unwrap();
        let persisted = persisted_agent_tool_call(&resolved, agent_id, 2, 1);

        let rehydrated = store
            .verify_persisted_session_agent_tool(&persisted)
            .unwrap();
        assert_eq!(rehydrated.call(), resolved.call());
        assert_eq!(rehydrated.policy_evaluation(), resolved.policy_evaluation());
        assert_eq!(directory_entries(&paths.marker_root), 0);

        let approval = approval_for_resolved_tool(&rehydrated);
        store
            .dispatch_session_agent_tool_after_checkpoint(
                scoped_resolved_tool(rehydrated, agent_id),
                Some(&approval),
            )
            .await
            .unwrap();
        assert_eq!(directory_entries(&paths.marker_root), 1);
    }

    #[tokio::test]
    async fn persisted_session_agent_tool_drift_fails_closed_before_dispatch() {
        let paths = TestPaths::new("agent-tool-persisted-drift");
        let store = local_store(&paths, false).await;
        let agent_id = "agent-turn-persisted-drift";
        let resolved = store
            .resolve_session_agent_tool(
                agent_id,
                3,
                1,
                connectors::DEV_MARKER_TOOL_NAME,
                serde_json::json!({"marker": "must not execute"}),
            )
            .unwrap();
        let persisted = persisted_agent_tool_call(&resolved, agent_id, 3, 1);

        let mut mismatches = Vec::new();
        let mut changed = persisted.clone();
        changed.call_id.push_str("-changed");
        mismatches.push(("call_id", changed));
        let mut changed = persisted.clone();
        changed.tool_version.push_str("-changed");
        mismatches.push(("tool_version", changed));
        let mut changed = persisted.clone();
        changed.arguments_digest.push_str("-changed");
        mismatches.push(("arguments_digest", changed));
        let mut changed = persisted.clone();
        changed.effect = ToolEffect::ReadOnly;
        mismatches.push(("effect", changed));
        let mut changed = persisted.clone();
        changed.sandbox_profile = SandboxProfile::ReadOnly;
        mismatches.push(("sandbox_profile", changed));
        let mut changed = persisted.clone();
        changed.executor_status = ToolExecutorStatus::Unavailable;
        mismatches.push(("executor_status", changed));
        let mut changed = persisted.clone();
        changed.policy_decision = PolicyDecision::Allow;
        mismatches.push(("policy_decision", changed));
        let mut changed = persisted.clone();
        changed.policy_revision.push_str("-changed");
        mismatches.push(("policy_revision", changed));

        for (field, changed) in mismatches {
            let error = store
                .verify_persisted_session_agent_tool(&changed)
                .unwrap_err();
            assert!(
                matches!(error, StoreError::PolicyChanged(message) if message.contains(field)),
                "{field} drift must fail closed"
            );
        }

        let mut unknown_tool = persisted;
        unknown_tool.tool_name = "model.supplied.unknown".into();
        assert!(matches!(
            store.verify_persisted_session_agent_tool(&unknown_tool),
            Err(StoreError::Registry(RegistryError::UnknownTool(_)))
        ));
        assert_eq!(directory_entries(&paths.marker_root), 0);
    }

    #[tokio::test]
    async fn session_agent_dispatch_rechecks_approval_then_executes_once() {
        let paths = TestPaths::new("agent-tool-dispatch");
        let store = local_store(&paths, false).await;
        let resolve = || {
            store.resolve_session_agent_tool(
                "agent-turn-8",
                3,
                1,
                connectors::DEV_MARKER_TOOL_NAME,
                serde_json::json!({"marker": "approved agent call"}),
            )
        };

        let missing_approval = store
            .dispatch_session_agent_tool_after_checkpoint(
                scoped_resolved_tool(resolve().unwrap(), "agent-turn-8"),
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(missing_approval, StoreError::PolicyChanged(_)));
        assert_eq!(directory_entries(&paths.marker_root), 0);

        let resolved = resolve().unwrap();
        let approval = approval_for_resolved_tool(&resolved);
        let expected_call_id = resolved.call().call_id.clone();
        let output = store
            .dispatch_session_agent_tool_after_checkpoint(
                scoped_resolved_tool(resolved, "agent-turn-8"),
                Some(&approval),
            )
            .await
            .unwrap();
        assert!(!output.replayed);
        assert_eq!(
            output.provider_request_id.as_deref(),
            Some(expected_call_id.as_str())
        );
        assert_eq!(directory_entries(&paths.marker_root), 1);
    }

    #[tokio::test]
    async fn session_agent_dispatch_rejects_a_changed_policy_before_execution() {
        let paths = TestPaths::new("agent-tool-policy-change");
        let mut store = local_store(&paths, false).await;
        let resolved = store
            .resolve_session_agent_tool(
                "agent-turn-9",
                4,
                1,
                connectors::DEV_MARKER_TOOL_NAME,
                serde_json::json!({"marker": "must not execute"}),
            )
            .unwrap();
        let approval = approval_for_resolved_tool(&resolved);
        store.policy = Arc::new(
            PolicyEngine::new(vec![PolicyRule {
                revision: LOCAL_POLICY_REVISION.into(),
                tool: connectors::DEV_MARKER_TOOL_NAME.into(),
                environment: LOCAL_DEV_ENVIRONMENT.into(),
                effect: ToolEffect::LocalWrite,
                sandbox_profile: SandboxProfile::WorkspaceWrite,
                decision: PolicyDecision::Allow,
            }])
            .unwrap(),
        );

        let error = store
            .dispatch_session_agent_tool_after_checkpoint(
                scoped_resolved_tool(resolved, "agent-turn-9"),
                Some(&approval),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            StoreError::PolicyChanged(message) if message.contains("evaluation changed")
        ));
        assert_eq!(directory_entries(&paths.marker_root), 0);
    }

    fn install_foreign_owner_authz(path: &Path) -> AuthzContext {
        const ACCOUNT_ID: &str = "acc_runtime_foreign";
        const USER_ID: &str = "user-runtime-foreign-owner";
        const AUTH_SESSION_ID: &str = "runtime-test-foreign-owner";

        let mut connection = Connection::open(path).unwrap();
        connection
            .busy_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        let transaction = connection.transaction().unwrap();
        let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        transaction
            .execute(
                r#"INSERT INTO accounts(id, name, status, created_at, updated_at)
                   VALUES (?1, 'Runtime foreign account', 'active', ?2, ?2)"#,
                params![ACCOUNT_ID, timestamp],
            )
            .unwrap();
        transaction
            .execute(
                r#"INSERT INTO users(
                       id, username, role, status, password_hash,
                       created_at, updated_at
                   ) VALUES (?1, ?2, 'member', 'active', ?3, ?4, ?4)"#,
                params![
                    USER_ID,
                    "runtime-foreign-owner",
                    "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGlnaWVzdA",
                    timestamp
                ],
            )
            .unwrap();
        transaction
            .execute(
                r#"INSERT INTO account_memberships(
                       account_id, user_id, role, status, revision,
                       created_at, updated_at
                   ) VALUES (?1, ?2, 'owner', 'active', 1, ?3, ?3)"#,
                params![ACCOUNT_ID, USER_ID, timestamp],
            )
            .unwrap();
        transaction
            .execute(
                r#"INSERT INTO auth_sessions(
                       id, token_hash, account_id, user_id,
                       membership_revision, csrf_hash, created_at,
                       expires_at, last_seen_at
                   ) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7, ?6)"#,
                params![
                    AUTH_SESSION_ID,
                    "d".repeat(64),
                    ACCOUNT_ID,
                    USER_ID,
                    "e".repeat(64),
                    timestamp,
                    "2999-01-01T00:00:00.000Z"
                ],
            )
            .unwrap();
        transaction.commit().unwrap();

        AuthzContext {
            account_id: AccountId::from_persistence(ACCOUNT_ID).unwrap(),
            user_id: USER_ID.into(),
            membership_role: MembershipRole::Owner,
            membership_revision: MembershipRevision::new(1).unwrap(),
            auth_session_id: AuthSessionId::from_persistence(AUTH_SESSION_ID).unwrap(),
        }
    }

    struct PanickingExecutor;

    impl ToolExecutor for PanickingExecutor {
        fn execute(&self, _request: ExecutionRequest) -> ExecutionFuture<'_> {
            Box::pin(async { panic!("test connector panic must be isolated") })
        }
    }

    #[test]
    fn worker_wake_state_coalesces_kicks_without_losing_a_pending_cycle() {
        let wake = WorkerWakeState::default();
        assert!(wake.request());
        assert!(!wake.request());
        assert!(!wake.request());
        assert!(wake.complete_cycle());
        assert!(!wake.complete_cycle());
        assert!(wake.request());
        assert!(!wake.complete_cycle());
    }

    #[test]
    fn issued_member_setup_token_has_a_redacted_debug_boundary() {
        let issued = IssuedMemberSetupToken {
            result: "member-created",
            setup_token: "one-time-member-setup-secret".into(),
        };
        let debug = format!("{issued:?}");
        assert!(debug.contains("member-created"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("one-time-member-setup-secret"));
        assert_eq!(issued.expose_secret(), "one-time-member-setup-secret");

        let (result, token) = issued.into_parts();
        assert_eq!(result, "member-created");
        assert_eq!(token, "one-time-member-setup-secret");
    }

    #[tokio::test]
    async fn member_lifecycle_facades_revoke_authority_and_expose_owner_only_audit() {
        let store = production_store(false).await;
        let owner = test_authz(TEST_OWNER_ID);
        let member_user_id = "user-runtime-lifecycle-member";
        let member = provision_runtime_member(&store, member_user_id).await;

        let members = store.list_members(&owner, None, 16).await.unwrap();
        assert_eq!(members.items.len(), 2);
        assert!(
            members
                .items
                .iter()
                .any(|item| item.user_id == member_user_id)
        );
        assert!(matches!(
            store.list_members(&member, None, 16).await,
            Err(StoreError::PermissionDenied)
        ));
        assert!(matches!(
            store.account_audit_state(&member).await,
            Err(StoreError::PermissionDenied)
        ));
        assert!(matches!(
            store
                .create_member(
                    &member,
                    "user-runtime-member-admin-bypass".into(),
                    "member-admin-bypass".into(),
                )
                .await,
            Err(StoreError::PermissionDenied)
        ));
        assert!(matches!(
            store
                .transition_member(
                    &member,
                    TransitionMemberCommit {
                        user_id: TEST_OWNER_ID.into(),
                        expected_revision: owner.membership_revision,
                        expected_role: MembershipRole::Owner,
                        expected_status: StoredMembershipStatus::Active,
                        role: MembershipRole::Owner,
                        status: StoredMembershipStatus::Active,
                    },
                )
                .await,
            Err(StoreError::PermissionDenied)
        ));

        store
            .create_session_for_actor(
                &member,
                CreateSessionRequest {
                    id: "session-runtime-lifecycle-member".into(),
                    title: "Member lifecycle authority".into(),
                },
                "create-runtime-lifecycle-member",
            )
            .await
            .unwrap();

        let transition = store
            .transition_member(
                &owner,
                TransitionMemberCommit {
                    user_id: member_user_id.into(),
                    expected_revision: member.membership_revision,
                    expected_role: MembershipRole::Member,
                    expected_status: StoredMembershipStatus::Active,
                    role: MembershipRole::Member,
                    status: StoredMembershipStatus::Disabled,
                },
            )
            .await
            .unwrap();
        assert_eq!(transition.member.status, StoredMembershipStatus::Disabled);
        assert_eq!(transition.revoked_auth_sessions, 1);
        assert!(transition.in_flight.reply_job_ids.is_empty());
        assert!(transition.in_flight.dispatch_call_ids.is_empty());
        assert!(matches!(
            store
                .create_session_for_actor(
                    &member,
                    CreateSessionRequest {
                        id: "session-runtime-revoked-member".into(),
                        title: "Revoked member must fail".into(),
                    },
                    "create-runtime-revoked-member",
                )
                .await,
            Err(StoreError::AuthSessionNotFound)
        ));

        let audit = store
            .list_account_audit_events(&owner, None, 32)
            .await
            .unwrap();
        let actions = audit
            .items
            .iter()
            .map(|event| event.action.as_str())
            .collect::<Vec<_>>();
        assert!(actions.contains(&"member.created"));
        assert!(actions.contains(&"member.setup_completed"));
        assert!(actions.contains(&"member.disabled"));
        assert!(audit.items.iter().any(|event| {
            event.action == "member.disabled"
                && event.target_id == member_user_id
                && event.outcome == "succeeded"
        }));
    }

    #[tokio::test]
    async fn internal_progress_retry_retries_only_operation_capacity() {
        let capacity_attempts = Arc::new(AtomicU64::new(0));
        let attempts = Arc::clone(&capacity_attempts);
        let value = retry_operation_capacity(|| {
            let attempt = attempts.fetch_add(1, Ordering::SeqCst);
            async move {
                if attempt < 2 {
                    Err(StoreError::OperationCapacityExceeded)
                } else {
                    Ok(7_u8)
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(value, 7);
        assert_eq!(capacity_attempts.load(Ordering::SeqCst), 3);

        let fatal_attempts = Arc::new(AtomicU64::new(0));
        let attempts = Arc::clone(&fatal_attempts);
        let result = retry_operation_capacity(|| {
            attempts.fetch_add(1, Ordering::SeqCst);
            async { Err::<(), _>(StoreError::RunNotFound("fatal".into())) }
        })
        .await;
        assert!(matches!(
            result,
            Err(StoreError::RunNotFound(run_id)) if run_id == "fatal"
        ));
        assert_eq!(fatal_attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn durable_completion_retry_retains_the_exact_result() {
        let attempts = Arc::new(AtomicU64::new(0));
        let observed_result = Arc::new(String::from("exact-dispatch-result"));
        let result = retry_durable_progress("test dispatch", || {
            let attempts = Arc::clone(&attempts);
            let observed_result = Arc::clone(&observed_result);
            async move {
                if attempts.fetch_add(1, Ordering::SeqCst) < 2 {
                    Err(StoreError::ConcurrentModification)
                } else {
                    Ok(observed_result)
                }
            }
        })
        .await
        .unwrap();

        assert!(Arc::ptr_eq(&result, &observed_result));
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn exact_completion_retry_classification_excludes_contract_failures() {
        assert!(StoreError::OperationCapacityExceeded.is_retryable_durable_completion_error());
        assert!(StoreError::PhysicalStorageExhausted.is_retryable_durable_completion_error());
        assert!(StoreError::ConcurrentModification.is_retryable_durable_completion_error());
        assert!(
            StoreError::Storage(StorageError::Io(std::io::Error::other("temporary I/O")))
                .is_retryable_durable_completion_error()
        );

        assert!(
            !StoreError::InvalidAgentTransition("permanent contract failure".into())
                .is_retryable_durable_completion_error()
        );
        assert!(
            !StoreError::ExecutionInvariant("permanent runtime invariant".into())
                .is_retryable_durable_completion_error()
        );
        assert!(
            !StoreError::Storage(StorageError::CorruptData("permanent corruption".into()))
                .is_retryable_durable_completion_error()
        );
    }

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
            .events_after_for_actor(&test_authz(TEST_OWNER_ID), protocol::DEMO_RUN_ID, 4)
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
            .event_page_feed_for_actor(&test_authz(TEST_OWNER_ID), DEMO_RUN_ID, 0, 3)
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
            .run_event_page_for_actor(&test_authz(TEST_OWNER_ID), DEMO_RUN_ID, 3, 5)
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
                .run_event_page_for_actor(&test_authz(TEST_OWNER_ID), DEMO_RUN_ID, 9, 1)
                .await,
            Err(StoreError::EventCursorBeyondHead {
                after: 9,
                head_sequence: 8,
            })
        ));
        assert!(matches!(
            store
                .run_event_page_for_actor(&test_authz(TEST_OWNER_ID), DEMO_RUN_ID, u64::MAX, 1)
                .await,
            Err(StoreError::EventCursorOutOfRange { after }) if after == u64::MAX
        ));
        assert!(matches!(
            store
                .run_event_page_for_actor(&test_authz(TEST_OWNER_ID), DEMO_RUN_ID, 0, 0)
                .await,
            Err(StoreError::Storage(StorageError::InvalidEventPageLimit {
                limit: 0,
                max: protocol::EVENT_PAGE_MAX_LIMIT,
            }))
        ));
        assert!(matches!(
            store
                .run_event_page_for_actor(&test_authz("foreign-user"), DEMO_RUN_ID, 9, 0)
                .await,
            Err(StoreError::AuthSessionNotFound)
        ));

        let mut session_feed = store
            .session_event_page_feed_for_actor(&test_authz(TEST_OWNER_ID), DEMO_SESSION_ID, 2, 1)
            .await
            .unwrap();
        assert!(session_feed.replay.items.is_empty());
        assert_eq!(session_feed.replay.next_after, None);
        assert_eq!(session_feed.replay.head_sequence, 2);
        assert!(!session_feed.replay.has_more);

        let started = store
            .start_turn_for_actor(
                &test_authz(TEST_OWNER_ID),
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
                &test_authz(TEST_OWNER_ID),
                DEMO_RUN_ID,
                None,
                protocol::EVENT_PAGE_DEFAULT_LIMIT,
            )
            .await
            .unwrap();
        let mut session_feed = store
            .session_event_feed_for_actor(&test_authz(TEST_OWNER_ID), DEMO_SESSION_ID, 2)
            .await
            .unwrap();
        let mut run_feed = store
            .event_feed_for_actor(
                &test_authz(TEST_OWNER_ID),
                DEMO_RUN_ID,
                run_before.run.sequence,
            )
            .await
            .unwrap();
        assert!(session_feed.replay.is_empty());
        assert!(run_feed.replay.is_empty());

        let started = store
            .start_turn_for_actor(
                &test_authz(TEST_OWNER_ID),
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
                &test_authz(TEST_OWNER_ID),
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
                &test_authz(TEST_OWNER_ID),
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
                    &test_authz(TEST_OWNER_ID),
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
                &test_authz(TEST_OWNER_ID),
                DEMO_RUN_ID,
                None,
                protocol::EVENT_PAGE_DEFAULT_LIMIT,
            )
            .await
            .unwrap();
        store
            .start_turn_for_actor(
                &test_authz(TEST_OWNER_ID),
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
                &test_authz(TEST_OWNER_ID),
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
                    &test_authz(TEST_OWNER_ID),
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
                &test_authz(TEST_OWNER_ID),
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
                &test_authz(TEST_OWNER_ID),
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
                    &test_authz(TEST_OWNER_ID),
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
                    &test_authz(TEST_OWNER_ID),
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
        let overview = store
            .overview_for_actor(&test_authz(TEST_OWNER_ID))
            .await
            .unwrap();
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
            .run_detail_for_actor(&test_authz(TEST_OWNER_ID), DEMO_RUN_ID, None, 3)
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
                &test_authz(TEST_OWNER_ID),
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
            .list_sessions_for_actor(
                &test_authz(TEST_OWNER_ID),
                None,
                protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
            )
            .await
            .unwrap();
        assert_eq!(sessions.items.len(), 1);
        assert_eq!(sessions.items[0].id, DEMO_SESSION_ID);
        assert!(sessions.next_cursor.is_none());
        let detail = store
            .get_session_for_actor(
                &test_authz(TEST_OWNER_ID),
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
    async fn actor_scoped_queries_and_commands_require_a_current_authenticated_context() {
        const OTHER_ACTOR: &str = "user-other-owner";

        let store = production_store(false).await;
        assert_eq!(
            store
                .current_run_for_actor(&test_authz(TEST_OWNER_ID))
                .await
                .unwrap()
                .id,
            DEMO_RUN_ID
        );
        let mut wrong_account = test_authz(TEST_OWNER_ID);
        wrong_account.account_id = AccountId::from_persistence("acc_foreign").unwrap();
        let mut stale_revision = test_authz(TEST_OWNER_ID);
        stale_revision.membership_revision = MembershipRevision::new(2).unwrap();
        let mut wrong_role = test_authz(TEST_OWNER_ID);
        wrong_role.membership_role = MembershipRole::Member;
        let mut wrong_session = test_authz(TEST_OWNER_ID);
        wrong_session.auth_session_id =
            AuthSessionId::from_persistence("runtime-test-foreign-session").unwrap();
        for invalid_context in [wrong_account, stale_revision, wrong_role, wrong_session] {
            assert!(
                matches!(
                    store.overview_for_actor(&invalid_context).await,
                    Err(StoreError::AuthSessionNotFound)
                ),
                "every component of the authorization context must be isolated"
            );
        }
        assert!(
            matches!(
                store.overview_for_actor(&test_authz(OTHER_ACTOR)).await,
                Err(StoreError::AuthSessionNotFound)
            ),
            "overview must reject an authority without a durable login session"
        );
        assert!(
            matches!(
                store
                    .run_detail_for_actor(
                        &test_authz(OTHER_ACTOR),
                        DEMO_RUN_ID,
                        None,
                        protocol::EVENT_PAGE_DEFAULT_LIMIT,
                    )
                    .await,
                Err(StoreError::AuthSessionNotFound)
            ),
            "run detail must reject an authority without a durable login session"
        );
        assert!(
            matches!(
                store
                    .events_after_for_actor(&test_authz(OTHER_ACTOR), DEMO_RUN_ID, 0)
                    .await,
                Err(StoreError::AuthSessionNotFound)
            ),
            "run replay must reject an authority without a durable login session"
        );
        let run_feed_error = match store
            .event_feed_for_actor(&test_authz(OTHER_ACTOR), DEMO_RUN_ID, 0)
            .await
        {
            Ok(_) => panic!("run feed must conceal another owner's run"),
            Err(error) => error,
        };
        assert!(matches!(run_feed_error, StoreError::AuthSessionNotFound));

        assert!(
            matches!(
                store
                    .get_session_for_actor(
                        &test_authz(OTHER_ACTOR),
                        DEMO_SESSION_ID,
                        None,
                        protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                        None,
                        protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                        None,
                        protocol::EVENT_PAGE_DEFAULT_LIMIT,
                    )
                    .await,
                Err(StoreError::AuthSessionNotFound)
            ),
            "session detail must reject an authority without a durable login session"
        );
        assert!(
            matches!(
                store
                    .session_events_after_for_actor(&test_authz(OTHER_ACTOR), DEMO_SESSION_ID, 0)
                    .await,
                Err(StoreError::AuthSessionNotFound)
            ),
            "session replay must reject an authority without a durable login session"
        );
        let session_feed_error = match store
            .session_event_feed_for_actor(&test_authz(OTHER_ACTOR), DEMO_SESSION_ID, 0)
            .await
        {
            Ok(_) => panic!("session feed must conceal another owner's session"),
            Err(error) => error,
        };
        assert!(matches!(
            session_feed_error,
            StoreError::AuthSessionNotFound
        ));
        assert!(
            matches!(
                store
                    .start_turn_for_actor(
                        &test_authz(OTHER_ACTOR),
                        DEMO_SESSION_ID,
                        StartTurnRequest {
                            turn_id: "turn-other-owner".into(),
                            user_message: "This must remain unauthorized.".into(),
                            expected_sequence: 2,
                        },
                        "runtime-other-owner-start",
                    )
                    .await,
                Err(StoreError::AuthSessionNotFound)
            ),
            "session commands must authorize the resource before transition validation"
        );
        assert!(
            matches!(
                store
                    .attach_run_for_actor(
                        &test_authz(OTHER_ACTOR),
                        DEMO_SESSION_ID,
                        AttachRunRequest {
                            run_id: DEMO_RUN_ID.into(),
                            expected_sequence: 2,
                        },
                        "runtime-other-owner-attach",
                    )
                    .await,
                Err(StoreError::AuthSessionNotFound)
            ),
            "run attachment must authorize the session before checking attachment state"
        );
        assert!(
            matches!(
                store
                    .resume_session_for_actor(
                        &test_authz(OTHER_ACTOR),
                        DEMO_SESSION_ID,
                        ResumeSessionRequest {
                            expected_sequence: 2,
                        },
                        "runtime-other-owner-resume",
                    )
                    .await,
                Err(StoreError::AuthSessionNotFound)
            ),
            "resume must authorize the session before checking its state"
        );
        assert_eq!(
            store
                .get_session_for_actor(
                    &test_authz(TEST_OWNER_ID),
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
    async fn resource_bound_actor_facades_conceal_foreign_resources_before_business_errors() {
        let paths = TestPaths::new("foreign-resource-error-order");
        let store = local_store(&paths, false).await;
        let foreign = install_foreign_owner_authz(&paths.database);

        assert!(matches!(
            store
                .run_detail_for_actor(&foreign, LOCAL_DEMO_RUN_ID, Some("not-a-cursor"), 0)
                .await,
            Err(StoreError::RunNotFound(run_id)) if run_id == LOCAL_DEMO_RUN_ID
        ));
        assert!(matches!(
            store
                .get_session_for_actor(
                    &foreign,
                    LOCAL_DEMO_SESSION_ID,
                    Some("not-a-cursor"),
                    0,
                    Some("not-a-cursor"),
                    0,
                    Some("not-a-cursor"),
                    0,
                )
                .await,
            Err(StoreError::SessionNotFound(session_id))
                if session_id == LOCAL_DEMO_SESSION_ID
        ));
        assert!(matches!(
            store
                .resume_session_for_actor(
                    &foreign,
                    LOCAL_DEMO_SESSION_ID,
                    ResumeSessionRequest {
                        expected_sequence: u64::MAX,
                    },
                    "",
                )
                .await,
            Err(StoreError::SessionNotFound(session_id))
                if session_id == LOCAL_DEMO_SESSION_ID
        ));
        assert!(matches!(
            store
                .start_turn_for_actor(
                    &foreign,
                    LOCAL_DEMO_SESSION_ID,
                    StartTurnRequest {
                        turn_id: "turn-foreign-error-order".into(),
                        user_message: "".into(),
                        expected_sequence: u64::MAX,
                    },
                    "",
                )
                .await,
            Err(StoreError::SessionNotFound(session_id))
                if session_id == LOCAL_DEMO_SESSION_ID
        ));
        assert!(matches!(
            store
                .flush_turn_for_actor(
                    &foreign,
                    LOCAL_DEMO_SESSION_ID,
                    FlushSessionRequest {
                        turn_id: "turn-foreign-error-order".into(),
                        assistant_message: Some("".into()),
                        expected_sequence: u64::MAX,
                    },
                    "",
                )
                .await,
            Err(StoreError::SessionNotFound(session_id))
                if session_id == LOCAL_DEMO_SESSION_ID
        ));
        assert!(matches!(
            store
                .review_for_actor(
                    &foreign,
                    LOCAL_DEMO_RUN_ID,
                    "APR-DEV-1",
                    approval_request(ReviewDecision::Reject),
                    "",
                )
                .await,
            Err(StoreError::RunNotFound(run_id)) if run_id == LOCAL_DEMO_RUN_ID
        ));
    }

    #[tokio::test]
    async fn actor_review_authorizes_the_run_before_receipt_replay() {
        const OTHER_ACTOR: &str = "user-other-owner";

        let store = production_store(false).await;
        let request = approval_request(ReviewDecision::Reject);
        let first = store
            .review_for_actor(
                &test_authz(TEST_OWNER_ID),
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
                &test_authz(TEST_OWNER_ID),
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
                        &test_authz(OTHER_ACTOR),
                        DEMO_RUN_ID,
                        "APR-901",
                        request,
                        "actor-review-replay",
                    )
                    .await,
                Err(StoreError::AuthSessionNotFound)
            ),
            "receipt possession must not bypass run authorization"
        );
    }

    #[tokio::test]
    async fn concurrent_actor_reviews_with_one_key_commit_once_and_replay() {
        const CONCURRENCY: usize = 16;

        let store = DemoStore::from_storage(
            SqliteStore::open_with_limits_and_physical_and_operations(
                ":memory:",
                StorageLimits::default(),
                SqlitePhysicalLimits::default(),
                SqliteOperationLimits {
                    max_concurrent_operations: CONCURRENCY + 1,
                    reserved_progress_operations: 1,
                    ..SqliteOperationLimits::default()
                },
            )
            .await
            .unwrap(),
            DemoProfile::ProductionGuarded,
            false,
        )
        .await
        .unwrap();
        bootstrap_test_owner(&store).await;
        let barrier = Arc::new(tokio::sync::Barrier::new(CONCURRENCY));
        let mut tasks = Vec::with_capacity(CONCURRENCY);
        for _ in 0..CONCURRENCY {
            let store = store.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                store
                    .review_for_actor(
                        &test_authz(TEST_OWNER_ID),
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
                &test_authz(TEST_OWNER_ID),
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
                    &test_authz(TEST_OWNER_ID),
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
                    &test_authz(TEST_OWNER_ID),
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
                &test_authz(TEST_OWNER_ID),
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
                &test_authz(TEST_OWNER_ID),
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
                &test_authz(TEST_OWNER_ID),
                DEMO_RUN_ID,
                None,
                protocol::EVENT_PAGE_DEFAULT_LIMIT,
            )
            .await
            .unwrap();
        assert!(matches!(
            store
                .review_for_actor(
                    &test_authz(TEST_OWNER_ID),
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
                    &test_authz(TEST_OWNER_ID),
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
                .review_receipt_for_actor(
                    &test_authz(TEST_OWNER_ID),
                    DEMO_RUN_ID,
                    "runtime-review-envelope",
                )
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .storage
                .review_receipt_for_actor(
                    &test_authz(TEST_OWNER_ID),
                    DEMO_RUN_ID,
                    "runtime-body-key-envelope",
                )
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .run_detail_for_actor(
                    &test_authz(TEST_OWNER_ID),
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
                    &test_authz(TEST_OWNER_ID),
                    DEMO_RUN_ID,
                    "APR-901",
                    approval_request(ReviewDecision::Reject),
                    "unbootstrapped-review",
                )
                .await,
            Err(StoreError::AuthSessionNotFound)
        ));
    }

    #[tokio::test]
    async fn approval_without_trusted_initiator_is_rejected_before_external_execution() {
        let store = production_store(false).await;
        let owner = test_authz(TEST_OWNER_ID);
        let member = provision_runtime_member(&store, "user-runtime-non-approver").await;
        assert!(matches!(
            store
                .review_for_actor(
                    &member,
                    protocol::DEMO_RUN_ID,
                    "APR-901",
                    approval_request(ReviewDecision::Approve),
                    "member-must-not-approve",
                )
                .await,
            Err(StoreError::PermissionDenied)
        ));
        assert!(
            store
                .storage
                .dispatch_job(PRODUCTION_DEMO_CALL_ID)
                .await
                .unwrap()
                .is_none()
        );

        let response = store
            .review_for_actor(
                &owner,
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
                    reason: NotDispatchedReason::AuthorizationRevoked,
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
        assert_eq!(job.account_id, AccountId::local());
        assert!(job.initiating_actor_user_id.is_none());
        assert_eq!(job.approving_actor_user_id.as_deref(), Some(TEST_OWNER_ID));
        assert!(job.initiating_membership_revision.is_none());
        assert_eq!(
            job.approving_membership_revision
                .map(|revision| revision.get()),
            Some(1)
        );
        assert_eq!(job.status, DispatchStatus::Rejected);
        assert_eq!(job.attempt, 0);
        assert!(job.started_at.is_none());
        assert_eq!(
            job.authorization_error_json
                .as_ref()
                .and_then(|error| error.get("code"))
                .and_then(serde_json::Value::as_str),
            Some("authorization_revoked")
        );
    }

    #[tokio::test]
    async fn local_approval_executes_one_marker_and_replay_does_not_execute_twice() {
        let paths = TestPaths::new("local-success");
        let store = local_store(&paths, false).await;
        let request = approval_request(ReviewDecision::Approve);
        let first = store
            .review_for_actor_with_initiator(
                &test_authz(TEST_OWNER_ID),
                &test_authz(TEST_OWNER_ID),
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
            .review_for_actor_with_initiator(
                &test_authz(TEST_OWNER_ID),
                &test_authz(TEST_OWNER_ID),
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
            .review_for_actor_with_initiator(
                &test_authz(TEST_OWNER_ID),
                &test_authz(TEST_OWNER_ID),
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
            .review_for_actor_with_initiator(
                &test_authz(TEST_OWNER_ID),
                &test_authz(TEST_OWNER_ID),
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
                &test_authz(TEST_OWNER_ID),
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
    async fn disabled_dispatch_initiator_is_rejected_before_the_connector_runs() {
        let paths = TestPaths::new("dispatch-disabled-before-claim");
        let store = local_store(&paths, false).await;
        let owner = test_authz(TEST_OWNER_ID);
        let member_user_id = "user-runtime-disabled-dispatch";
        let member = provision_runtime_member(&store, member_user_id).await;
        let approved = store
            .review_for_actor_with_initiator(
                &owner,
                &member,
                LOCAL_DEMO_RUN_ID,
                "APR-DEV-1",
                approval_request(ReviewDecision::Approve),
                "approve-dispatch-disabled-before-claim",
            )
            .await
            .unwrap();
        assert_eq!(approved.run.status, RunStatus::Queued);
        let mut feed = store
            .event_feed_for_actor(&owner, LOCAL_DEMO_RUN_ID, approved.event.sequence)
            .await
            .unwrap();

        let transition = store
            .transition_member(
                &owner,
                TransitionMemberCommit {
                    user_id: member_user_id.into(),
                    expected_revision: member.membership_revision,
                    expected_role: MembershipRole::Member,
                    expected_status: StoredMembershipStatus::Active,
                    role: MembershipRole::Member,
                    status: StoredMembershipStatus::Disabled,
                },
            )
            .await
            .unwrap();
        assert!(transition.in_flight.reply_job_ids.is_empty());
        assert!(transition.in_flight.dispatch_call_ids.is_empty());
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
        let audit = store
            .list_account_audit_events(&owner, None, 32)
            .await
            .unwrap();
        assert!(audit.items.iter().any(|event| {
            event.action == "member.disabled"
                && event.target_id == member_user_id
                && event.outcome == "succeeded"
        }));
    }

    #[tokio::test]
    async fn claimed_dispatch_completes_after_a_later_initiator_disable() {
        let paths = TestPaths::new("dispatch-revision-after-claim");
        let store = local_store(&paths, false).await;
        let owner = test_authz(TEST_OWNER_ID);
        let member_user_id = "user-runtime-claimed-dispatch";
        let member = provision_runtime_member(&store, member_user_id).await;
        store
            .review_for_actor_with_initiator(
                &owner,
                &member,
                LOCAL_DEMO_RUN_ID,
                "APR-DEV-1",
                approval_request(ReviewDecision::Approve),
                "approve-dispatch-revision-after-claim",
            )
            .await
            .unwrap();
        let claimed = store.claim_next_dispatch().await.unwrap().unwrap();
        assert_eq!(claimed.job.status, DispatchStatus::Started);
        assert_eq!(directory_entries(&paths.marker_root), 0);

        let transition = store
            .transition_member(
                &owner,
                TransitionMemberCommit {
                    user_id: member_user_id.into(),
                    expected_revision: member.membership_revision,
                    expected_role: MembershipRole::Member,
                    expected_status: StoredMembershipStatus::Active,
                    role: MembershipRole::Member,
                    status: StoredMembershipStatus::Disabled,
                },
            )
            .await
            .unwrap();
        assert!(transition.in_flight.reply_job_ids.is_empty());
        assert_eq!(
            transition.in_flight.dispatch_call_ids,
            [LOCAL_MARKER_CALL_ID]
        );

        // The claim is the last authorization boundary before external I/O.
        // Disable after that checkpoint cannot safely cancel an operation that
        // may already have happened, and must not block its one settlement.
        let outcome = store.dispatch_outcome(&claimed).await;
        assert!(matches!(outcome, ToolOutcome::Succeeded { .. }));
        assert_eq!(directory_entries(&paths.marker_root), 1);
        store.complete_dispatch(claimed, outcome).await.unwrap();
        store.dispatch_pending().await.unwrap();
        assert_eq!(
            directory_entries(&paths.marker_root),
            1,
            "a terminal claimed call must not be executed or settled twice"
        );

        let job = store
            .storage
            .dispatch_job(LOCAL_MARKER_CALL_ID)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(job.status, DispatchStatus::Finished);
        assert_eq!(job.attempt, 1);
        assert!(matches!(
            store.current_run_for_actor(&member).await,
            Err(StoreError::AuthSessionNotFound)
        ));
        let audit = store
            .list_account_audit_events(&owner, None, 32)
            .await
            .unwrap();
        assert!(audit.items.iter().any(|event| {
            event.action == "member.disabled"
                && event.target_id == member_user_id
                && event.outcome == "succeeded"
        }));
    }

    #[tokio::test]
    async fn disabled_reply_actor_is_interrupted_without_exposing_a_claimed_job() {
        let paths = TestPaths::new("reply-actor-disabled");
        let store = local_store(&paths, false).await;
        let owner = test_authz(TEST_OWNER_ID);
        let member_user_id = "user-runtime-disabled-reply";
        let member = provision_runtime_member(&store, member_user_id).await;
        let job_id = "reply-runtime-authorization-revoked";
        let enqueued = store
            .start_turn_and_enqueue_reply_for_actor(
                &member,
                LOCAL_DEMO_SESSION_ID,
                StartTurnRequest {
                    turn_id: "turn-runtime-authorization-revoked".into(),
                    user_message: "Do not call a provider after authorization is revoked.".into(),
                    expected_sequence: 2,
                },
                "enqueue-runtime-authorization-revoked",
                ReplyJobSpec {
                    id: job_id.into(),
                    authz: member.clone(),
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
                &member,
                LOCAL_DEMO_SESSION_ID,
                enqueued.start.event.sequence,
            )
            .await
            .unwrap();

        let transition = store
            .transition_member(
                &owner,
                TransitionMemberCommit {
                    user_id: member_user_id.into(),
                    expected_revision: member.membership_revision,
                    expected_role: MembershipRole::Member,
                    expected_status: StoredMembershipStatus::Active,
                    role: MembershipRole::Member,
                    status: StoredMembershipStatus::Disabled,
                },
            )
            .await
            .unwrap();
        assert!(transition.in_flight.reply_job_ids.is_empty());
        assert!(matches!(
            store.claim_next_reply().await.unwrap(),
            ReplyClaimOutcome::NotAvailable
        ));
        assert!(matches!(
            store.reply_job_for_actor(&member, job_id).await,
            Err(StoreError::AuthSessionNotFound)
        ));

        let job = store
            .reply_job_for_actor(&owner, job_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(job.status, ReplyJobStatus::Failed);
        assert_eq!(job.attempt, 1);
        assert_eq!(
            job.error_json
                .as_ref()
                .and_then(|error| error.get("code"))
                .and_then(serde_json::Value::as_str),
            Some("authorization_revoked")
        );
        let detail = store
            .get_session_for_actor(
                &owner,
                LOCAL_DEMO_SESSION_ID,
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
        let audit = store
            .list_account_audit_events(&owner, None, 32)
            .await
            .unwrap();
        assert!(audit.items.iter().any(|event| {
            event.action == "member.disabled"
                && event.target_id == member_user_id
                && event.outcome == "succeeded"
        }));
    }

    #[tokio::test]
    async fn claimed_reply_completion_survives_a_later_member_disable() {
        let paths = TestPaths::new("reply-revision-after-claim");
        let store = local_store(&paths, false).await;
        let owner = test_authz(TEST_OWNER_ID);
        let member_user_id = "user-runtime-claimed-reply";
        let member = provision_runtime_member(&store, member_user_id).await;
        let job_id = "reply-runtime-revision-after-claim";
        store
            .start_turn_and_enqueue_reply_for_actor(
                &member,
                LOCAL_DEMO_SESSION_ID,
                StartTurnRequest {
                    turn_id: "turn-runtime-revision-after-claim".into(),
                    user_message: "A claimed provider call must still settle durably.".into(),
                    expected_sequence: 2,
                },
                "enqueue-runtime-revision-after-claim",
                ReplyJobSpec {
                    id: job_id.into(),
                    authz: member.clone(),
                    provider_name: "test-provider".into(),
                    model_name: Some("test-model".into()),
                    request_json: serde_json::json!({"prompt": "settle after claim"}),
                },
            )
            .await
            .unwrap();
        let ReplyClaimOutcome::Claimed(claimed) = store.claim_next_reply().await.unwrap() else {
            panic!("the active authority must be claimable before revision changes");
        };
        assert_eq!(claimed.status, ReplyJobStatus::Started);

        let transition = store
            .transition_member(
                &owner,
                TransitionMemberCommit {
                    user_id: member_user_id.into(),
                    expected_revision: member.membership_revision,
                    expected_role: MembershipRole::Member,
                    expected_status: StoredMembershipStatus::Active,
                    role: MembershipRole::Member,
                    status: StoredMembershipStatus::Disabled,
                },
            )
            .await
            .unwrap();
        assert_eq!(transition.in_flight.reply_job_ids, [job_id]);
        assert!(transition.in_flight.dispatch_call_ids.is_empty());
        let expected_sequence = store
            .session_summary_for_progress(LOCAL_DEMO_SESSION_ID)
            .await
            .unwrap()
            .sequence;
        let commit = ReplySuccessCommit {
            job_id: job_id.into(),
            expected_sequence,
            assistant_message: "The already-started provider call settled once.".into(),
            provenance: protocol::AssistantReplyProvenance {
                provider_id: "test-provider".into(),
                model: Some("test-model".into()),
                reply_kind: protocol::AssistantReplyKind::Model,
            },
            response_json: serde_json::json!({
                "content": "The already-started provider call settled once.",
                "finish_reason": "stop",
                "provider": {
                    "provider_id": "test-provider",
                    "model": "test-model",
                    "reply_kind": "model"
                }
            }),
        };
        let completion = store.complete_reply_success(commit.clone()).await.unwrap();
        assert_eq!(completion.job.status, ReplyJobStatus::Succeeded);
        assert_eq!(completion.session.status, SessionStatus::Ready);
        assert_eq!(completion.events.len(), 2);
        let replay = store.complete_reply_success(commit).await.unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.events, completion.events);
        assert_eq!(replay.session.sequence, completion.session.sequence);
        assert!(matches!(
            store
                .session_events_after_for_actor(&member, LOCAL_DEMO_SESSION_ID, 0)
                .await,
            Err(StoreError::AuthSessionNotFound)
        ));
        let persisted = store
            .reply_job_for_actor(&owner, job_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(persisted.status, ReplyJobStatus::Succeeded);
        let audit = store
            .list_account_audit_events(&owner, None, 32)
            .await
            .unwrap();
        assert!(audit.items.iter().any(|event| {
            event.action == "member.disabled"
                && event.target_id == member_user_id
                && event.outcome == "succeeded"
        }));
    }

    #[tokio::test]
    async fn started_call_becomes_outcome_unknown_after_restart_and_is_not_retried() {
        let paths = TestPaths::new("recovery");
        let store = local_store(&paths, false).await;
        store
            .review_for_actor_with_initiator(
                &test_authz(TEST_OWNER_ID),
                &test_authz(TEST_OWNER_ID),
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
        // Authorization is consumed by the durable started checkpoint. A
        // later membership revision must not turn recovery into a retry or
        // prevent the outcome_unknown terminal record.
        advance_test_actor_membership_revision(&paths.database);
        drop(store);

        let storage = SqliteStore::open(&paths.database).await.unwrap();
        let reopened = DemoStore::from_storage(
            storage,
            DemoProfile::LocalDevelopment {
                marker_root: paths.marker_root.clone(),
                workspace_root: None,
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
    async fn panicking_connector_settles_outcome_unknown_without_stopping_the_dispatcher() {
        let paths = TestPaths::new("panicking-connector");
        let mut store = local_store(&paths, false).await;
        let descriptor = store
            .registry
            .descriptor("dev_marker_write")
            .unwrap()
            .clone();
        let mut registry = ToolRegistry::new();
        registry.register(descriptor, PanickingExecutor).unwrap();
        store.registry = Arc::new(registry);

        store
            .review_for_actor_with_initiator(
                &test_authz(TEST_OWNER_ID),
                &test_authz(TEST_OWNER_ID),
                LOCAL_DEMO_RUN_ID,
                "APR-DEV-1",
                approval_request(ReviewDecision::Approve),
                "panicking-connector-review",
            )
            .await
            .unwrap();
        store.dispatch_pending().await.unwrap();
        store.dispatch_pending().await.unwrap();

        let detail = store.run_detail(LOCAL_DEMO_RUN_ID).await.unwrap();
        assert!(matches!(
            detail.events.last().and_then(|event| event.data.as_ref()),
            Some(RunEventData::ToolResult {
                outcome: ToolOutcome::OutcomeUnknown { .. },
                status: ToolCallStatus::OutcomeUnknown,
                ..
            })
        ));
        assert_eq!(directory_entries(&paths.marker_root), 0);
    }

    #[tokio::test]
    async fn one_key_cannot_be_reused_for_another_approval_decision() {
        let store = production_store(false).await;
        store
            .review_for_actor(
                &test_authz(TEST_OWNER_ID),
                protocol::DEMO_RUN_ID,
                "APR-901",
                approval_request(ReviewDecision::Approve),
                "same-key",
            )
            .await
            .unwrap();
        let error = store
            .review_for_actor(
                &test_authz(TEST_OWNER_ID),
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
                &test_authz(TEST_OWNER_ID),
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
                        initiating_authz: Some(test_authz(TEST_OWNER_ID)),
                        approving_authz: test_authz(TEST_OWNER_ID),
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
                workspace_root: None,
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
                auth_session_id: test_authz(TEST_OWNER_ID).auth_session_id,
                session_token_hash: "b".repeat(64),
                csrf_hash: "c".repeat(64),
                session_expires_at: expiry.into(),
            })
            .await
            .unwrap();
        assert_eq!(owner.id, TEST_OWNER_ID);
    }

    async fn provision_runtime_member(store: &DemoStore, user_id: &str) -> AuthzContext {
        let issued = store
            .create_member(
                &test_authz(TEST_OWNER_ID),
                user_id.into(),
                "runtime-member".into(),
            )
            .await
            .unwrap();
        assert_eq!(issued.result.member.role, MembershipRole::Member);
        assert_eq!(issued.result.member.status, StoredMembershipStatus::Active);
        assert!(issued.result.member.setup_required);
        assert!(issued.result.member.setup_token_expires_at.is_some());
        let (_, setup_token) = issued.into_parts();
        let result = store
            .complete_member_setup(MemberSetupCommit {
                setup_token: MemberSetupToken::from_presented(setup_token).unwrap(),
                password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGlnaWVzdA".into(),
                auth_session_id: AuthSessionId::from_persistence(format!("runtime-test-{user_id}"))
                    .unwrap(),
                session_token_hash: "7".repeat(64),
                csrf_hash: "8".repeat(64),
                session_expires_at: "2999-01-01T00:00:00.000Z".into(),
            })
            .await
            .unwrap();
        assert_eq!(result.member.user_id, user_id);
        assert!(!result.member.setup_required);
        assert!(result.member.setup_token_expires_at.is_none());
        result.principal.authz
    }

    fn advance_test_actor_membership_revision(path: &Path) {
        let connection = Connection::open(path).unwrap();
        connection
            .busy_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        // Membership revisions may only advance alongside a real authority
        // change, and an account must retain an active owner. Install a backup
        // owner membership before downgrading the test actor so this exercises
        // the production invariant instead of bypassing its triggers.
        connection
            .execute(
                r#"INSERT INTO users(
                       id, username, role, status, password_hash,
                       created_at, updated_at
                   ) VALUES (?1, ?2, 'member', 'active', ?3, ?4, ?4)"#,
                params![
                    "user-runtime-backup-owner",
                    "runtime-backup-owner",
                    "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGlnaWVzdA",
                    timestamp
                ],
            )
            .unwrap();
        connection
            .execute(
                r#"INSERT INTO account_memberships(
                       account_id, user_id, role, status, revision,
                       created_at, updated_at
                   ) VALUES (
                       'acc_local', ?1, 'owner', 'active', 1, ?2, ?2
                   )"#,
                params!["user-runtime-backup-owner", timestamp],
            )
            .unwrap();
        let changed = connection
            .execute(
                r#"UPDATE account_memberships
                   SET role = 'member', revision = revision + 1, updated_at = ?1
                   WHERE account_id = 'acc_local' AND user_id = ?2"#,
                params![timestamp, TEST_OWNER_ID],
            )
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
