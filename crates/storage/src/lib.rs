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

pub use error::StorageError;
pub use limits::{StorageLimits, StorageLimitsError};
pub use operation::{SqliteOperationLimits, SqliteOperationLimitsError};
pub use physical::{SqlitePhysicalLimits, SqlitePhysicalLimitsError};
use protocol::{
    Approval, EvidenceSummary, IncidentSummary, Metric, ReadPageInfo, ReviewResponse, RunEvent,
    RunSummary, SandboxProfile, SessionEvent, SessionSummary, SessionTurn, StartTurnResponse,
    ToolCall, ToolEffect, ToolPolicySummary,
};
use serde::Serialize;
use serde_json::Value;
pub use sqlite::SqliteStore;
pub use tenancy::{
    AccountId, AuthSessionId, AuthzContext, MemberSetupToken, MembershipRevision, MembershipRole,
};

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
/// Provider execution must not begin until [`SqliteStore::claim_next_reply`]
/// returns this job as claimed.
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
