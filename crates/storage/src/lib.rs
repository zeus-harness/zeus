//! Durable SQLite storage for the local Zeus Alpha.
//!
//! Blocking SQLite work is isolated on Tokio's blocking pool. The event ledger
//! is append-only, and review/dispatch state changes commit atomically before
//! callers publish events or invoke external tools.

mod error;
mod sqlite;

pub use error::StorageError;
use protocol::{
    EvidenceSummary, IncidentSummary, Metric, ReviewResponse, RunEvent, RunSummary, SandboxProfile,
    ToolEffect, ToolPolicySummary,
};
use serde_json::Value;
pub use sqlite::SqliteStore;

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
}

/// Durable queue state returned to the dispatcher.
#[derive(Clone, Debug, PartialEq)]
pub struct DispatchJob {
    pub call_id: String,
    pub run_id: String,
    pub approval_id: String,
    pub approval_event_sequence: u64,
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
    pub queued_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub start_event_sequence: Option<u64>,
    pub result_event_sequence: Option<u64>,
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
