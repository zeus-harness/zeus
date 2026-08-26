//! HTTP-facing contracts shared by the Zeus demo API and its clients.
//!
//! These types deliberately describe the product boundary only. Persistence and
//! orchestration implementations belong in other crates.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const DEMO_RUN_ID: &str = "ZR-1842";
pub const LOCAL_DEMO_RUN_ID: &str = "ZR-DEV-1";
pub const DEMO_SESSION_ID: &str = "session-ZR-1842";
pub const LOCAL_DEMO_SESSION_ID: &str = "session-ZR-DEV-1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    Investigating,
    Mitigating,
    Resolved,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    WaitingForApproval,
    Queued,
    Running,
    Blocked,
    NeedsAttention,
    Active,
    Succeeded,
    Failed,
    Cancelled,
}

/// Durable lifecycle of a conversation session.
///
/// A session is `running` only while it owns an open turn. Startup recovery
/// moves an unclosed turn to `needs_attention`; an explicit resume command is
/// required before another turn can start.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Ready,
    Running,
    NeedsAttention,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionTurnStatus {
    Open,
    Flushed,
    Interrupted,
}

impl RunStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Blocked | Self::NeedsAttention | Self::Succeeded | Self::Failed | Self::Cancelled
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricTone {
    Neutral,
    Positive,
    Warning,
    Critical,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    System,
    User,
    Reasoning,
    Step,
    ToolCall,
    Evidence,
    Approval,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolEffect {
    ReadOnly,
    LocalWrite,
    ProductionWrite,
    Destructive,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxProfile {
    ReadOnly,
    WorkspaceWrite,
    IsolatedContainer,
    ProductionGuarded,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    RequireApproval,
    Deny,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalScope {
    AllowOnce,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolExecutorStatus {
    Available,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCallStatus {
    Requested,
    WaitingForApproval,
    Queued,
    Running,
    NotDispatched,
    Succeeded,
    Failed,
    Cancelled,
    OutcomeUnknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotDispatchedReason {
    ApprovalRejected,
    ExecutorUnavailable,
    SandboxUnavailable,
    PolicyDenied,
    PolicyChanged,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ToolOutcome {
    Succeeded {
        summary: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        output_digest: Option<String>,
    },
    Failed {
        summary: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_code: Option<String>,
    },
    Cancelled {
        summary: String,
    },
    NotDispatched {
        reason: NotDispatchedReason,
        summary: String,
    },
    OutcomeUnknown {
        summary: String,
    },
}

impl ToolOutcome {
    pub fn call_status(&self) -> ToolCallStatus {
        match self {
            Self::Succeeded { .. } => ToolCallStatus::Succeeded,
            Self::Failed { .. } => ToolCallStatus::Failed,
            Self::Cancelled { .. } => ToolCallStatus::Cancelled,
            Self::NotDispatched { .. } => ToolCallStatus::NotDispatched,
            Self::OutcomeUnknown { .. } => ToolCallStatus::OutcomeUnknown,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    pub call_id: String,
    pub tool: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tool_version: String,
    pub arguments: Value,
    pub arguments_digest: String,
    pub effect: ToolEffect,
    pub sandbox_profile: SandboxProfile,
    pub executor_status: ToolExecutorStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentSummary {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub status: IncidentStatus,
    pub service: String,
    pub region: String,
    pub user_impact: String,
    pub since: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunSummary {
    pub id: String,
    pub status: RunStatus,
    pub environment: String,
    pub started_at: String,
    pub duration_seconds: u64,
    pub agent: String,
    pub sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSummary {
    pub id: String,
    pub title: String,
    pub status: SessionStatus,
    pub created_at: String,
    pub updated_at: String,
    pub sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_turn_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTurn {
    pub id: String,
    pub session_id: String,
    pub ordinal: u64,
    pub status: SessionTurnStatus,
    pub user_message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assistant_message: Option<String>,
    pub started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionEventData {
    SessionCreated { title: String },
    RunAttached { run_id: String },
    SessionResumed { from_status: SessionStatus },
    UserMessage { turn_id: String, content: String },
    AssistantMessage { turn_id: String, content: String },
    TurnFlushed { turn_id: String },
    TurnInterrupted { turn_id: String, reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEvent {
    pub sequence: u64,
    pub id: String,
    pub at: String,
    pub data: SessionEventData,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionDetail {
    pub session: SessionSummary,
    pub run_ids: Vec<String>,
    pub turns: Vec<SessionTurn>,
    pub events: Vec<SessionEvent>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateSessionRequest {
    pub id: String,
    pub title: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateSessionResponse {
    pub session: SessionSummary,
    pub event: SessionEvent,
    pub replayed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachRunRequest {
    pub run_id: String,
    pub expected_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachRunResponse {
    pub session: SessionSummary,
    pub event: SessionEvent,
    pub replayed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartTurnRequest {
    pub turn_id: String,
    pub user_message: String,
    pub expected_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartTurnResponse {
    pub session: SessionSummary,
    pub turn: SessionTurn,
    pub event: SessionEvent,
    pub replayed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlushSessionRequest {
    pub turn_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assistant_message: Option<String>,
    pub expected_sequence: u64,
}

/// Commit acknowledgement for the `session/flush` durability barrier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionFlushAck {
    pub session_id: String,
    pub turn_id: String,
    pub durability_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlushSessionResponse {
    pub session: SessionSummary,
    pub turn: SessionTurn,
    pub events: Vec<SessionEvent>,
    pub ack: SessionFlushAck,
    pub replayed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeSessionRequest {
    pub expected_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeSessionResponse {
    pub session: SessionSummary,
    pub event: SessionEvent,
    pub replayed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metric {
    pub label: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tone: Option<MetricTone>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSummary {
    pub id: String,
    pub at: String,
    pub label: String,
    pub source: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolPolicySummary {
    pub name: String,
    pub allows: Vec<String>,
    pub requires_approval: Vec<String>,
    pub denies: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Approval {
    pub id: String,
    pub status: ApprovalStatus,
    pub action: String,
    pub tool: String,
    pub change: String,
    pub requires_approval: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_profile: Option<SandboxProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<ApprovalScope>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RunEventData {
    ToolCallRequested {
        call: ToolCall,
        status: ToolCallStatus,
    },
    ToolPolicyDecided {
        call_id: String,
        decision: PolicyDecision,
        policy_revision: String,
        reason: String,
    },
    ApprovalRequested {
        approval_id: String,
        call_id: String,
        scope: ApprovalScope,
        status: ToolCallStatus,
    },
    ApprovalDecided {
        approval_id: String,
        call_id: String,
        decision: ReviewDecision,
        status: ToolCallStatus,
    },
    ToolDispatchStarted {
        call_id: String,
        executor: String,
        executor_status: ToolExecutorStatus,
        sandbox_profile: SandboxProfile,
        status: ToolCallStatus,
    },
    ToolResult {
        call_id: String,
        outcome: ToolOutcome,
        status: ToolCallStatus,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RunEvent {
    pub sequence: u64,
    pub id: String,
    pub turn: u32,
    pub step: u32,
    #[serde(rename = "type")]
    pub event_type: EventType,
    pub title: String,
    pub at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval: Option<Approval>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<RunEventData>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OverviewResponse {
    pub primary_session_id: String,
    pub incident: IncidentSummary,
    pub run: RunSummary,
    pub metrics: Vec<Metric>,
    pub recent_events: Vec<RunEvent>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<EvidenceSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_policy: Option<ToolPolicySummary>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RunDetail {
    pub incident: IncidentSummary,
    pub run: RunSummary,
    pub events: Vec<RunEvent>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDecision {
    Approve,
    Reject,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewRequest {
    pub decision: ReviewDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReviewResponse {
    pub run: RunSummary,
    pub event: RunEvent,
    pub replayed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub type_url: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
}

impl ProblemDetails {
    pub fn new(
        status: u16,
        code: impl Into<String>,
        title: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        let code = code.into();
        Self {
            type_url: format!("https://zeus.local/problems/{code}"),
            title: title.into(),
            status,
            detail: detail.into(),
            code,
            instance: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn legacy_approval_without_binding_fields_still_deserializes() {
        let legacy = json!({
            "id": "APR-OLD",
            "status": "pending",
            "action": "legacy action",
            "tool": "legacy.tool",
            "change": "legacy change",
            "requires_approval": true
        });

        let approval: Approval = serde_json::from_value(legacy).unwrap();

        assert_eq!(approval.call_id, None);
        assert_eq!(approval.policy_revision, None);
        assert_eq!(approval.arguments_digest, None);
        assert_eq!(approval.sandbox_profile, None);
        assert_eq!(approval.scope, None);
    }

    #[test]
    fn legacy_run_event_without_typed_data_still_deserializes() {
        let legacy = json!({
            "sequence": 1,
            "id": "evt-000001",
            "turn": 0,
            "step": 0,
            "type": "system",
            "title": "legacy",
            "at": "2026-08-26T00:00:00Z",
            "metadata": {}
        });

        let event: RunEvent = serde_json::from_value(legacy).unwrap();
        assert_eq!(event.data, None);
        assert!(
            !serde_json::to_value(event)
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("data")
        );
    }

    #[test]
    fn tool_call_without_version_recovers_but_preserves_missing_version() {
        let value = json!({
            "call_id": "call-old",
            "tool": "legacy.tool",
            "arguments": {},
            "arguments_digest": "sha256:legacy",
            "effect": "read_only",
            "sandbox_profile": "read_only",
            "executor_status": "available"
        });

        let call: ToolCall = serde_json::from_value(value).unwrap();
        assert!(call.tool_version.is_empty());
    }

    #[test]
    fn tagged_event_data_and_outcome_round_trip() {
        let data = RunEventData::ToolResult {
            call_id: "call-1".into(),
            outcome: ToolOutcome::NotDispatched {
                reason: NotDispatchedReason::ExecutorUnavailable,
                summary: "executor is unavailable".into(),
            },
            status: ToolCallStatus::NotDispatched,
        };

        let value = serde_json::to_value(&data).unwrap();
        assert_eq!(value["kind"], "tool_result");
        assert_eq!(value["outcome"]["status"], "not_dispatched");
        assert_eq!(serde_json::from_value::<RunEventData>(value).unwrap(), data);
    }

    #[test]
    fn alpha_run_statuses_use_stable_snake_case_names() {
        assert_eq!(serde_json::to_value(RunStatus::Queued).unwrap(), "queued");
        assert_eq!(serde_json::to_value(RunStatus::Running).unwrap(), "running");
        assert_eq!(serde_json::to_value(RunStatus::Blocked).unwrap(), "blocked");
        assert_eq!(
            serde_json::to_value(RunStatus::NeedsAttention).unwrap(),
            "needs_attention"
        );
        assert!(RunStatus::NeedsAttention.is_terminal());
        assert!(!RunStatus::Queued.is_terminal());
    }

    #[test]
    fn session_protocol_uses_stable_tagged_events_and_flush_ack() {
        let event = SessionEvent {
            sequence: 4,
            id: "session-1:event:4".into(),
            at: "2026-08-26T08:00:00.000Z".into(),
            data: SessionEventData::TurnInterrupted {
                turn_id: "turn-1".into(),
                reason: "restart before flush".into(),
            },
        };
        let value = serde_json::to_value(&event).unwrap();
        assert_eq!(value["data"]["kind"], "turn_interrupted");
        assert_eq!(
            serde_json::from_value::<SessionEvent>(value).unwrap(),
            event
        );

        let request = FlushSessionRequest {
            turn_id: "turn-1".into(),
            assistant_message: Some("done".into()),
            expected_sequence: 2,
        };
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            json!({
                "turn_id": "turn-1",
                "assistant_message": "done",
                "expected_sequence": 2
            })
        );
        assert_eq!(
            serde_json::to_value(SessionStatus::NeedsAttention).unwrap(),
            "needs_attention"
        );
        assert_eq!(
            serde_json::to_value(SessionTurnStatus::Flushed).unwrap(),
            "flushed"
        );
    }
}
