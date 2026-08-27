//! Durable SQLite storage for the local Zeus Alpha.
//!
//! Blocking SQLite work is isolated on Tokio's blocking pool. The event ledger
//! is append-only, and review/dispatch state changes commit atomically before
//! callers publish events or invoke external tools.

mod cursor;
mod error;
mod limits;
mod operation;
mod physical;
mod sqlite;

use std::fmt;

use deployment::ManifestEnvelope;
pub use error::StorageError;
pub use limits::{StorageLimits, StorageLimitsError};
pub use operation::{SqliteOperationLimits, SqliteOperationLimitsError};
pub use physical::{SqlitePhysicalLimits, SqlitePhysicalLimitsError};
use protocol::{
    AgentReviewResponse, AgentToolCallStatus, AgentTurnStatus, Approval, AssistantReplyProvenance,
    EvidenceSummary, IncidentSummary, Metric, PolicyDecision, ReadPageInfo, ReviewResponse,
    RunEvent, RunSummary, SandboxProfile, SessionEvent, SessionSummary, SessionTurn,
    StartTurnResponse, ToolCall, ToolEffect, ToolExecutorStatus, ToolPolicySummary,
};
use serde::Serialize;
use serde_json::Value;
pub use sqlite::SqliteStore;
pub use tenancy::{
    AccountId, AuthSessionId, AuthzContext, MemberSetupToken, MembershipRevision, MembershipRole,
};
use workflows::State as AgentWorkflowState;

pub const MEMBER_SETUP_TOKEN_TTL_SECONDS: i64 = 86_400;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoredMembershipStatus {
    Active,
    Disabled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredMember {
    pub account_id: AccountId,
    pub user_id: String,
    pub username: String,
    pub role: MembershipRole,
    pub status: StoredMembershipStatus,
    pub revision: MembershipRevision,
    /// True until the member has durably completed credential setup. This is
    /// independent of whether a current setup token exists.
    pub setup_required: bool,
    /// Present while a current one-time setup token row exists, including an
    /// expired row that an owner may rotate.
    pub setup_token_expires_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredMemberPage {
    pub items: Vec<StoredMember>,
    pub next_cursor: Option<String>,
}

pub struct CreateMemberCommit {
    pub user_id: String,
    pub username: String,
    pub setup_token: MemberSetupToken,
}

impl fmt::Debug for CreateMemberCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreateMemberCommit")
            .field("user_id", &self.user_id)
            .field("username", &self.username)
            .field("setup_token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateMemberResult {
    pub member: StoredMember,
    pub replayed: bool,
}

pub struct RotateMemberSetupTokenCommit {
    pub user_id: String,
    pub expected_revision: MembershipRevision,
    pub setup_token: MemberSetupToken,
}

impl fmt::Debug for RotateMemberSetupTokenCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RotateMemberSetupTokenCommit")
            .field("user_id", &self.user_id)
            .field("expected_revision", &self.expected_revision)
            .field("setup_token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotateMemberSetupTokenResult {
    pub member: StoredMember,
    pub replayed: bool,
}

pub struct MemberSetupCommit {
    pub setup_token: MemberSetupToken,
    pub password_hash: String,
    pub auth_session_id: AuthSessionId,
    pub session_token_hash: String,
    pub csrf_hash: String,
    pub session_expires_at: String,
}

impl fmt::Debug for MemberSetupCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemberSetupCommit")
            .field("setup_token", &"[REDACTED]")
            .field("password_hash", &"[REDACTED]")
            .field("auth_session_id", &self.auth_session_id)
            .field("session_token_hash", &"[REDACTED]")
            .field("csrf_hash", &"[REDACTED]")
            .field("session_expires_at", &self.session_expires_at)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberSetupResult {
    pub principal: AuthPrincipal,
    pub member: StoredMember,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionMemberCommit {
    pub user_id: String,
    pub expected_revision: MembershipRevision,
    pub expected_role: MembershipRole,
    pub expected_status: StoredMembershipStatus,
    pub role: MembershipRole,
    pub status: StoredMembershipStatus,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InFlightWorkSummary {
    pub reply_job_ids: Vec<String>,
    pub dispatch_call_ids: Vec<String>,
    pub agent_model_job_ids: Vec<String>,
    pub agent_tool_call_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberTransitionResult {
    pub member: StoredMember,
    pub replayed: bool,
    pub revoked_auth_sessions: u64,
    pub revoked_setup_tokens: u64,
    pub in_flight: InFlightWorkSummary,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AccountAuditEvent {
    pub account_id: AccountId,
    pub sequence: u64,
    pub actor_user_id: Option<String>,
    pub action: String,
    pub outcome: String,
    pub target_kind: String,
    pub target_id: String,
    pub metadata: Value,
    pub occurred_at: String,
    pub previous_hash: String,
    pub event_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountAuditRollup {
    pub account_id: AccountId,
    pub through_sequence: u64,
    pub event_count: u64,
    pub digest: String,
    pub last_event_hash: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountAuditPolicy {
    pub account_id: AccountId,
    pub detail_rows: u64,
    pub legal_hold: bool,
    pub archive_required: bool,
    pub revision: u64,
    pub updated_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountAuditArchiveState {
    pub account_id: AccountId,
    pub through_sequence: u64,
    pub event_hash: String,
    pub archive_reference: Option<String>,
    pub revision: u64,
    pub updated_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountAuditState {
    pub policy: AccountAuditPolicy,
    pub rollup: AccountAuditRollup,
    pub archive: AccountAuditArchiveState,
    pub detailed_rows: u64,
    pub ordinary_capacity_remaining: u64,
    pub progress_capacity_remaining: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AccountAuditPage {
    pub items: Vec<AccountAuditEvent>,
    pub next_cursor: Option<String>,
    pub state: AccountAuditState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateAccountAuditPolicyCommit {
    pub expected_revision: u64,
    pub detail_rows: u64,
    pub legal_hold: bool,
    pub archive_required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountAuditCheckpointCommit {
    pub expected_revision: u64,
    pub through_sequence: u64,
    pub event_hash: String,
    pub archive_reference: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoredUserRole {
    Owner,
    Member,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoredUserStatus {
    Active,
    Disabled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredUser {
    pub id: String,
    pub username: String,
    pub role: StoredUserRole,
    pub status: StoredUserStatus,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct StoredCredential {
    pub user: StoredUser,
    pub account_id: AccountId,
    pub membership_role: MembershipRole,
    pub membership_revision: MembershipRevision,
    pub password_hash: String,
}

impl fmt::Debug for StoredCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredCredential")
            .field("user", &self.user)
            .field("account_id", &self.account_id)
            .field("membership_role", &self.membership_role)
            .field("membership_revision", &self.membership_revision)
            .field("password_hash", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredPreferences {
    pub user_id: String,
    pub theme: String,
    pub preferred_model: Option<String>,
    pub revision: u64,
    pub updated_at: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct AuthPrincipal {
    pub user: StoredUser,
    pub authz: AuthzContext,
    pub csrf_hash: String,
    pub expires_at: String,
}

impl fmt::Debug for AuthPrincipal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthPrincipal")
            .field("user", &self.user)
            .field("authz", &self.authz)
            .field("csrf_hash", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct BootstrapOwnerCommit {
    pub bootstrap_token_hash: String,
    pub user_id: String,
    pub username: String,
    pub password_hash: String,
    pub auth_session_id: AuthSessionId,
    pub session_token_hash: String,
    pub csrf_hash: String,
    pub session_expires_at: String,
}

impl fmt::Debug for BootstrapOwnerCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootstrapOwnerCommit")
            .field("bootstrap_token_hash", &"[REDACTED]")
            .field("user_id", &self.user_id)
            .field("username", &self.username)
            .field("password_hash", &"[REDACTED]")
            .field("auth_session_id", &self.auth_session_id)
            .field("session_token_hash", &"[REDACTED]")
            .field("csrf_hash", &"[REDACTED]")
            .field("session_expires_at", &self.session_expires_at)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AuthSessionCommit {
    pub authz: AuthzContext,
    pub session_token_hash: String,
    pub csrf_hash: String,
    pub expires_at: String,
}

impl fmt::Debug for AuthSessionCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthSessionCommit")
            .field("authz", &self.authz)
            .field("session_token_hash", &"[REDACTED]")
            .field("csrf_hash", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Immutable inputs for one durable assistant reply.
///
/// The provider request is persisted in the same transaction as the user turn.
/// Provider execution must not begin until a storage claim/start operation
/// returns this exact job as started.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ReplyJobSpec {
    pub id: String,
    pub authz: AuthzContext,
    pub provider_name: String,
    pub model_name: Option<String>,
    /// Server-derived provider context. The first committed value is durable
    /// authority; idempotent replay returns it instead of comparing a freshly
    /// rebuilt context across process upgrades.
    pub request_json: Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplyJobStatus {
    Queued,
    Started,
    Succeeded,
    Failed,
    OutcomeUnknown,
}

/// Durable at-most-once reply queue record.
#[derive(Clone, Debug, PartialEq)]
pub struct ReplyJob {
    pub id: String,
    pub account_id: AccountId,
    pub actor_user_id: String,
    pub actor_membership_revision: MembershipRevision,
    pub session_id: String,
    pub turn_id: String,
    pub provider_name: String,
    pub model_name: Option<String>,
    pub status: ReplyJobStatus,
    pub attempt: u32,
    pub request_json: Value,
    pub response_json: Option<Value>,
    pub error_json: Option<Value>,
    pub queued_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub assistant_event_sequence: Option<u64>,
    pub terminal_event_sequence: Option<u64>,
}

/// Result of atomically appending a user turn and its reply work item.
#[derive(Clone, Debug, PartialEq)]
pub struct ReplyJobEnqueueResponse {
    pub start: StartTurnResponse,
    pub job: ReplyJob,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionSummaryPage {
    pub items: Vec<SessionSummary>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BoundedRunRead {
    pub snapshot: RunSnapshot,
    pub events: Vec<RunEvent>,
    pub events_page: ReadPageInfo,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ReplyClaimOutcome {
    Claimed(Box<ReplyJob>),
    /// The queued job lost authorization before provider execution. Storage
    /// has already failed the job and appended interruption evidence.
    Rejected(Box<ReplyCompletion>),
    NotAvailable,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ReplySuccessCommit {
    pub job_id: String,
    pub expected_sequence: u64,
    pub assistant_message: String,
    pub provenance: protocol::AssistantReplyProvenance,
    pub response_json: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ReplyFailureCommit {
    pub job_id: String,
    pub expected_sequence: u64,
    pub error_json: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ReplyOutcomeUnknownCommit {
    pub job_id: String,
    pub expected_sequence: u64,
    pub error_json: Value,
}

/// Durable terminal result and the exact ledger events committed with it.
#[derive(Clone, Debug, PartialEq)]
pub struct ReplyCompletion {
    pub job: ReplyJob,
    pub session: SessionSummary,
    pub turn: SessionTurn,
    pub events: Vec<SessionEvent>,
    pub replayed: bool,
}

/// Immutable inputs for one durable Session-native agent loop.
///
/// The first provider request is committed atomically with the user turn. The
/// server-derived request body is durable authority and is intentionally not
/// compared when an idempotent client command is replayed after an upgrade.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AgentTurnSpec {
    pub id: String,
    pub authz: AuthzContext,
    pub manifest: ManifestEnvelope,
    pub environment: String,
    pub provider_name: String,
    pub model_name: Option<String>,
    pub request_json: Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentModelJobStatus {
    Queued,
    Started,
    Succeeded,
    Failed,
    OutcomeUnknown,
}

/// Durable at-most-once model step. Each step owns a complete immutable
/// provider request, including every prior tool call and tool result.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentModelJob {
    pub id: String,
    pub agent_id: String,
    pub account_id: AccountId,
    pub actor_user_id: String,
    pub actor_membership_revision: MembershipRevision,
    pub session_id: String,
    pub turn_id: String,
    pub step: u32,
    pub provider_name: String,
    pub model_name: Option<String>,
    pub status: AgentModelJobStatus,
    pub attempt: u32,
    pub request_json: Value,
    pub response_json: Option<Value>,
    pub error_json: Option<Value>,
    pub queued_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

/// Storage projection for one durable Session-native agent loop. Public HTTP
/// callers receive [`AgentTurnDetail`], which adds its bounded tool-call list.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentTurn {
    pub id: String,
    pub account_id: AccountId,
    pub actor_user_id: String,
    pub actor_membership_revision: MembershipRevision,
    pub session_id: String,
    pub turn_id: String,
    pub deployment_manifest_digest: Option<String>,
    pub environment: String,
    pub provider_name: String,
    pub model_name: Option<String>,
    pub status: AgentTurnStatus,
    pub model_steps: u32,
    pub tool_calls: u32,
    pub tool_result_bytes: u64,
    pub revision: u64,
    pub pending_call_id: Option<String>,
    pub workflow_state: AgentWorkflowState,
    pub last_error_json: Option<Value>,
    pub created_at: String,
    pub updated_at: String,
    pub completed_at: Option<String>,
}

/// Result of atomically appending a user turn and its first model step.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentTurnEnqueueResponse {
    pub start: StartTurnResponse,
    pub agent: AgentTurn,
    pub job: AgentModelJob,
}

/// Immutable server-resolved contract for one model-selected tool call.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentToolCallSpec {
    pub call_id: String,
    pub provider_call_id: String,
    pub tool_name: String,
    pub tool_version: String,
    pub arguments_json: Value,
    pub arguments_digest: String,
    pub effect: ToolEffect,
    pub sandbox_profile: SandboxProfile,
    pub executor_status: ToolExecutorStatus,
    pub policy_decision: PolicyDecision,
    pub policy_revision: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AgentToolCall {
    pub call_id: String,
    pub agent_id: String,
    pub account_id: AccountId,
    pub session_id: String,
    pub turn_id: String,
    pub provider_call_id: String,
    pub ordinal: u32,
    pub model_step: u32,
    pub tool_name: String,
    pub tool_version: String,
    pub arguments_json: Value,
    pub arguments_digest: String,
    pub effect: ToolEffect,
    pub sandbox_profile: SandboxProfile,
    pub executor_status: ToolExecutorStatus,
    pub policy_decision: PolicyDecision,
    pub policy_revision: String,
    pub status: AgentToolCallStatus,
    pub approving_actor_user_id: Option<String>,
    pub approving_membership_revision: Option<MembershipRevision>,
    pub review_note: Option<String>,
    pub reviewed_at: Option<String>,
    pub result_json: Option<Value>,
    pub provider_request_id: Option<String>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

/// One successful provider step either finishes the Session turn or admits one
/// server-resolved tool call. Mixed text/tool outputs are rejected by `llm`
/// before this commit can be constructed.
#[derive(Clone, Debug, PartialEq)]
pub enum AgentModelResolution {
    Final {
        assistant_message: String,
        provenance: AssistantReplyProvenance,
    },
    ToolCall {
        call: AgentToolCallSpec,
    },
    /// An exact deny is a known non-dispatch result. The denied result commits
    /// with the audit call row. `next_request_json` is absent only when the
    /// bounded continuation cannot be represented; storage then terminalizes
    /// the loop without misclassifying the known non-dispatch as unknown.
    PolicyDenied {
        call: AgentToolCallSpec,
        result_json: Value,
        next_request_json: Option<Value>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct AgentModelSuccessCommit {
    pub job_id: String,
    pub response_json: Value,
    pub resolution: AgentModelResolution,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AgentModelFailureCommit {
    pub job_id: String,
    pub error_json: Value,
    pub outcome_unknown: bool,
}

/// Durable operation lane protected by one prepared-claim generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentOperationKind {
    Model,
    Tool,
}

/// Single-process durable coordination token between queue preparation and an
/// external-I/O start checkpoint. It is not a distributed lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentOperationClaim {
    pub kind: AgentOperationKind,
    pub operation_id: String,
    pub agent_id: String,
    pub generation: u64,
    pub holder_id: String,
    pub acquired_at: String,
    pub expires_at: String,
}

impl AgentOperationClaim {
    pub(crate) fn validate(&self) -> Result<(), StorageError> {
        fn validate_identity(
            value: &str,
            field: &str,
            max_bytes: usize,
        ) -> Result<(), StorageError> {
            if value.is_empty()
                || value.len() > max_bytes
                || value.trim() != value
                || value.chars().any(char::is_control)
            {
                return Err(StorageError::InvalidAgentTransition(format!(
                    "{field} must be non-empty, canonical, control-free, and at most {max_bytes} UTF-8 bytes"
                )));
            }
            Ok(())
        }

        validate_identity(&self.operation_id, "Agent operation ID", 384)?;
        validate_identity(&self.agent_id, "Agent ID", 384)?;
        validate_identity(&self.holder_id, "Agent operation holder ID", 128)?;
        if self.generation == 0 || self.generation > i64::MAX as u64 {
            return Err(StorageError::InvalidAgentTransition(
                "Agent operation claim generation must be a positive SQLite integer".into(),
            ));
        }
        validate_identity(&self.acquired_at, "Agent operation claim acquired_at", 64)?;
        validate_identity(&self.expires_at, "Agent operation claim expires_at", 64)?;
        let acquired_at =
            chrono::DateTime::parse_from_rfc3339(&self.acquired_at).map_err(|_| {
                StorageError::InvalidAgentTransition(
                    "Agent operation claim acquired_at must be RFC 3339".into(),
                )
            })?;
        let expires_at = chrono::DateTime::parse_from_rfc3339(&self.expires_at).map_err(|_| {
            StorageError::InvalidAgentTransition(
                "Agent operation claim expires_at must be RFC 3339".into(),
            )
        })?;
        if acquired_at >= expires_at {
            return Err(StorageError::InvalidAgentTransition(
                "Agent operation claim must expire after it is acquired".into(),
            ));
        }
        Ok(())
    }
}

/// Immutable model work observed while its operation claim is prepared but
/// before the billable provider start checkpoint is committed.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentPreparedModel {
    pub claim: AgentOperationClaim,
    pub job: AgentModelJob,
}

/// Immutable tool work observed while its operation claim is prepared but
/// before the side-effecting executor start checkpoint is committed.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentPreparedTool {
    pub claim: AgentOperationClaim,
    pub work: AgentToolWork,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AgentModelClaimOutcome {
    Prepared(Box<AgentPreparedModel>),
    /// Compatibility projection for callers that deliberately combine the
    /// prepared and started storage phases. Runtime workers use `Prepared`.
    Claimed(Box<AgentModelJob>),
    Rejected(Box<AgentTerminalCompletion>),
    NotAvailable,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AgentToolClaimOutcome {
    Prepared(Box<AgentPreparedTool>),
    /// Compatibility projection for callers that deliberately combine the
    /// prepared and started storage phases. Runtime workers use `Prepared`.
    Claimed(Box<AgentToolWork>),
    Rejected(Box<AgentTerminalCompletion>),
    NotAvailable,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AgentModelStartOutcome {
    /// The exact claim is durably started. This can be an exact response
    /// replay after an ambiguous commit; a caller must retain one execution
    /// context and invoke provider I/O at most once for the claim.
    Started(Box<AgentModelJob>),
    Rejected(Box<AgentTerminalCompletion>),
}

#[derive(Clone, Debug, PartialEq)]
pub enum AgentToolStartOutcome {
    /// The exact claim is durably started. This can be an exact response
    /// replay after an ambiguous commit; a caller must retain one execution
    /// context and invoke connector I/O at most once for the claim.
    Started(Box<AgentToolWork>),
    Rejected(Box<AgentTerminalCompletion>),
}

/// Complete immutable context required to execute one claimed tool and build
/// the model continuation from the exact provider request/response that
/// proposed it.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentToolWork {
    pub call: AgentToolCall,
    pub model_job: AgentModelJob,
}

/// Authenticated owner-review context. The API derives a rejection
/// continuation from this server-owned transcript; the client never supplies
/// provider messages directly.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentReviewContext {
    pub agent: AgentTurn,
    pub work: AgentToolWork,
}

impl AgentReviewContext {
    /// Predict whether rejecting this exact pending call must enqueue another
    /// model step. The prediction uses the same canonical rejection result and
    /// reducer/limit settlement as the transactional review commit.
    pub fn rejection_requires_continuation(
        &self,
        note: Option<&str>,
    ) -> Result<bool, StorageError> {
        if let Some(note) = note {
            protocol::validate_review_note(note).map_err(|error| {
                StorageError::InvalidResourceEnvelope(format!("agent review note {error}"))
            })?;
        }
        if self.work.call.status != AgentToolCallStatus::WaitingApproval
            || self.agent.status != AgentTurnStatus::WaitingApproval
            || self.agent.pending_call_id.as_deref() != Some(self.work.call.call_id.as_str())
        {
            // An already-reviewed call may be an idempotent receipt replay.
            // Storage owns that decision; the service must not manufacture a
            // now-unused continuation before presenting the receipt key.
            return Ok(false);
        }
        let result = protocol::agent_approval_rejected_result(&self.work.call.call_id, note);
        let result_bytes = u64::try_from(serde_json::to_vec(&result)?.len())
            .map_err(|_| StorageError::IntegerOutOfRange("agent tool result bytes"))?;
        let rejected = workflows::reduce(
            &self.agent.workflow_state,
            workflows::Command::ApprovalRejected { result_bytes },
        )
        .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?
        .into_state();
        let (_, queue_continuation) = settle_agent_continuation_limit(rejected)?;
        Ok(queue_continuation)
    }
}

pub(crate) fn settle_agent_continuation_limit(
    continuation: AgentWorkflowState,
) -> Result<(AgentWorkflowState, bool), StorageError> {
    if continuation.status() != workflows::AgentStatus::ContinuationQueued {
        return Ok((continuation, false));
    }
    let preview = workflows::reduce(&continuation, workflows::Command::StartModel)
        .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?;
    if preview.state().status() == workflows::AgentStatus::Failed {
        Ok((preview.into_state(), false))
    } else {
        Ok((continuation, true))
    }
}

/// Persistence-ready owner decision. `next_request_json` is required only for
/// a rejection that queues another model step and is derived from
/// [`AgentReviewContext`] by the service layer.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentReviewCommit {
    pub call_id: String,
    pub decision: protocol::ReviewDecision,
    pub note: Option<String>,
    pub idempotency_key: String,
    pub next_request_json: Option<Value>,
}

/// Exact result committed after a known connector outcome. `result_json` is
/// both the bounded durable record and the value supplied to the next model
/// step. `next_request_json` is absent only when that bounded continuation
/// cannot be represented. A panic or transport ambiguity uses the separate
/// unknown transition.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentToolCompletionCommit {
    pub call_id: String,
    pub status: AgentToolCallStatus,
    pub result_json: Value,
    pub provider_request_id: Option<String>,
    pub next_request_json: Option<Value>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AgentToolOutcomeUnknownCommit {
    pub call_id: String,
    pub error_json: Value,
}

/// Session finalization caused by a failed, rejected, or indeterminate agent
/// operation. The interruption event is committed in the same transaction.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentTerminalCompletion {
    pub agent: AgentTurn,
    pub session: SessionSummary,
    pub turn: SessionTurn,
    pub event: SessionEvent,
    /// `true` only when storage reconstructed an already-committed terminal
    /// transition. Callers use this as a live-publication guard; the durable
    /// Session ledger remains the source of truth.
    pub replayed: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AgentFinalCompletion {
    pub agent: AgentTurn,
    pub session: SessionSummary,
    pub turn: SessionTurn,
    pub events: Vec<SessionEvent>,
    /// `true` only when storage reconstructed an already-committed final
    /// transition. Fresh commits and restart recovery always return `false`.
    pub replayed: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AgentModelCompletion {
    Final(Box<AgentFinalCompletion>),
    ToolCall {
        agent: Box<AgentTurn>,
        call: Box<AgentToolCall>,
    },
    Terminal(Box<AgentTerminalCompletion>),
}

#[derive(Clone, Debug, PartialEq)]
pub enum AgentToolCompletion {
    ModelQueued {
        agent: Box<AgentTurn>,
        job: Box<AgentModelJob>,
    },
    Terminal(Box<AgentTerminalCompletion>),
}

/// Query/approval projection produced entirely from one authenticated SQLite
/// transaction.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentReviewResult {
    pub response: AgentReviewResponse,
    pub queued_model_job: Option<AgentModelJob>,
    /// Present when a rejection reaches a fixed Agent Loop limit and therefore
    /// interrupts the Session instead of queueing a continuation. Receipt
    /// replay reconstructs this completion with `replayed = true`.
    pub terminal_completion: Option<AgentTerminalCompletion>,
}

/// Immutable runtime boundary attached to one persistent database.
///
/// The binding prevents a database containing approved or started work from
/// being reopened under a different fixture, environment, or policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeIdentity {
    pub profile: String,
    pub environment: String,
    pub primary_session_id: String,
    pub primary_run_id: String,
    pub policy_id: String,
    pub policy_revision: String,
}

/// The query-side state required to render a run without coupling storage to
/// orchestration or kernel business rules.
#[derive(Clone, Debug, PartialEq)]
pub struct RunSnapshot {
    pub incident: IncidentSummary,
    pub run: RunSummary,
    pub metrics: Vec<Metric>,
    pub evidence: Vec<EvidenceSummary>,
    pub tool_policy: Option<ToolPolicySummary>,
}

/// A projection and its complete event ledger observed from one SQLite read
/// transaction.
#[derive(Clone, Debug, PartialEq)]
pub struct StoredRun {
    pub snapshot: RunSnapshot,
    pub events: Vec<RunEvent>,
}

/// Minimal durable state needed to decide one approval command.
///
/// `approval` is absent when the requested pending approval does not exist.
/// `requested_call` remains separate so the runtime can preserve its public
/// distinction between a missing approval and an incomplete approval binding.
#[derive(Clone, Debug, PartialEq)]
pub struct ReviewContext {
    pub snapshot: RunSnapshot,
    pub approval: Option<Approval>,
    pub approval_event_sequence: Option<u64>,
    pub requested_call: Option<ToolCall>,
    pub requested_call_event_sequence: Option<u64>,
}

/// Minimal durable state needed to claim or recover one dispatch job.
///
/// The approval is selected by the immutable sequence stored on the queue
/// record. The requested call is selected by its immutable logical call ID.
#[derive(Clone, Debug, PartialEq)]
pub struct DispatchContext {
    pub snapshot: RunSnapshot,
    pub approval_event: RunEvent,
    pub requested_call: Option<ToolCall>,
    pub requested_call_event_sequence: Option<u64>,
}

/// One startup-recovered turn together with the ledger that owns its event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveredSessionTurn {
    pub session_id: String,
    pub event: SessionEvent,
}

/// The immutable result cached for an idempotent review command.
#[derive(Clone, Debug, PartialEq)]
pub struct ReviewReceipt {
    pub request_fingerprint: String,
    pub response: ReviewResponse,
}

/// Persistence-ready output of a review transition computed by the runtime.
#[derive(Clone, Debug, PartialEq)]
pub struct ReviewCommit {
    pub expected_sequence: u64,
    pub snapshot: RunSnapshot,
    pub event: RunEvent,
    pub idempotency_key: String,
    pub request_fingerprint: String,
    pub response: ReviewResponse,
    /// A policy-authorized tool call to enqueue in the same transaction as
    /// the approval decision. Rejections and approvals without a tool call
    /// leave this as `None`.
    pub dispatch: Option<DispatchJobSpec>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CommitOutcome {
    Committed,
    Replayed(Box<ReviewReceipt>),
}

/// Immutable, policy-bound inputs for one at-most-once tool dispatch.
///
/// Storage does not execute this call. The runtime may only hand the inputs to
/// a connector after [`SqliteStore::claim_next_dispatch`] commits.
#[derive(Clone, Debug, PartialEq)]
pub struct DispatchJobSpec {
    pub call_id: String,
    pub approval_id: String,
    /// The actor whose request initiated this immutable dispatch, when the
    /// durable requested-call provenance actually records one. `None` is
    /// fail-closed at claim time and must never be filled from the approver.
    pub initiating_authz: Option<AuthzContext>,
    /// The owner whose approval authorized this immutable dispatch.
    pub approving_authz: AuthzContext,
    pub tool_name: String,
    pub tool_version: String,
    pub effect: ToolEffect,
    pub args_json: Value,
    pub args_digest: String,
    pub policy_id: String,
    pub policy_revision: String,
    pub sandbox_profile: SandboxProfile,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DispatchStatus {
    Queued,
    Started,
    Finished,
    Rejected,
}

/// Durable queue state returned to the dispatcher.
#[derive(Clone, Debug, PartialEq)]
pub struct DispatchJob {
    pub call_id: String,
    pub account_id: AccountId,
    pub run_id: String,
    pub approval_id: String,
    pub approval_event_sequence: u64,
    pub initiating_actor_user_id: Option<String>,
    pub initiating_membership_revision: Option<MembershipRevision>,
    pub approving_actor_user_id: Option<String>,
    pub approving_membership_revision: Option<MembershipRevision>,
    pub tool_name: String,
    pub tool_version: String,
    pub effect: ToolEffect,
    pub args_json: Value,
    pub args_digest: String,
    pub policy_id: String,
    pub policy_revision: String,
    pub sandbox_profile: SandboxProfile,
    pub status: DispatchStatus,
    pub attempt: u32,
    pub result_json: Option<Value>,
    pub authorization_error_json: Option<Value>,
    pub queued_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub start_event_sequence: Option<u64>,
    pub result_event_sequence: Option<u64>,
}

/// A queued tool call that lost authorization before any connector was
/// invoked. The event and terminal job state were committed atomically.
#[derive(Clone, Debug, PartialEq)]
pub struct DispatchRejection {
    pub job: DispatchJob,
    pub event: RunEvent,
}

/// Caller-computed transition used to claim the current queue head.
///
/// The runtime may inspect the queue first to construct the next projection
/// and event. This commit re-selects the queue head under `BEGIN IMMEDIATE`, so
/// a racing caller cannot claim a later job out of order.
#[derive(Clone, Debug, PartialEq)]
pub struct DispatchStartCommit {
    pub call_id: String,
    pub expected_sequence: u64,
    pub snapshot: RunSnapshot,
    pub event: RunEvent,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ClaimOutcome {
    Claimed(Box<DispatchJob>),
    Rejected(Box<DispatchRejection>),
    NotAvailable,
}

/// Caller-computed tool result transition. Connector execution must finish
/// before this value is passed to storage.
#[derive(Clone, Debug, PartialEq)]
pub struct DispatchCompleteCommit {
    pub call_id: String,
    pub expected_sequence: u64,
    pub snapshot: RunSnapshot,
    pub event: RunEvent,
    pub result_json: Value,
}

/// Startup transition for a call that was durably marked started but has no
/// durable result. It records `outcome_unknown`; it never authorizes a retry.
#[derive(Clone, Debug, PartialEq)]
pub struct DispatchRecoveryCommit {
    pub call_id: String,
    pub expected_sequence: u64,
    pub snapshot: RunSnapshot,
    pub event: RunEvent,
    pub result_json: Value,
}

#[cfg(test)]
mod tests;
