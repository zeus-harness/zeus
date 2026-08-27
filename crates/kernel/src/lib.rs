//! Deterministic product rules for the first Zeus vertical slice.
//!
//! The crate contains no HTTP or persistence code. The demo fixture is kept
//! here so every adapter observes the same pipeline and sequence invariants.

use std::collections::BTreeMap;

use protocol::{
    Approval, ApprovalScope, ApprovalStatus, DEMO_RUN_ID, DEMO_SESSION_ID, EventType,
    EvidenceSummary, IncidentStatus, IncidentSummary, LOCAL_DEMO_RUN_ID, LOCAL_DEMO_SESSION_ID,
    Metric, MetricTone, OverviewResponse, PolicyDecision, ReviewDecision, RunEvent, RunEventData,
    RunStatus, RunSummary, SandboxProfile, Severity, ToolCall, ToolCallStatus, ToolEffect,
    ToolExecutorStatus, ToolOutcome, ToolPolicySummary,
};
use serde_json::json;
use thiserror::Error;

pub const PRODUCTION_DEMO_CALL_ID: &str = "call-rds-limit-001";
pub const LOCAL_MARKER_CALL_ID: &str = "call-local-marker-001";
pub const PRODUCTION_POLICY_REVISION: &str = "production-guarded/v1";
pub const LOCAL_POLICY_REVISION: &str = "local-development/v1";

const PRODUCTION_ARGUMENTS_DIGEST: &str =
    "sha256:1abd923258c2708eff661a7119542a9dade6c48f44e2d13547d4df973ae2b04d";
const LOCAL_MARKER_ARGUMENTS_DIGEST: &str =
    "sha256:dbeb62866b04cc80c571267a18db3de67fda654f2816cb7061a2f6d94ab3db7f";

#[derive(Clone, Debug)]
pub struct DemoScenario {
    pub incident: IncidentSummary,
    pub run: RunSummary,
    pub metrics: Vec<Metric>,
    pub events: Vec<RunEvent>,
    pub evidence: Vec<EvidenceSummary>,
    pub tool_policy: ToolPolicySummary,
}

impl DemoScenario {
    pub fn zr_1842() -> Self {
        let call = production_rds_call();
        let approval = approval_for(
            "APR-901",
            &call,
            PRODUCTION_POLICY_REVISION,
            "update connection ceiling",
            "checkout-api connections: 80 → 120",
        );
        let events = vec![
            event(
                1,
                0,
                0,
                EventType::User,
                "User report received",
                "2026-08-26T01:18:00Z",
                "Customers report slow checkout responses from us-east-1.",
            ),
            event(
                2,
                1,
                0,
                EventType::Reasoning,
                "Zeus Responder formed a hypothesis",
                "2026-08-26T01:18:04Z",
                "Checkout latency may be driven by database connection pressure.",
            ),
            event(
                3,
                1,
                1,
                EventType::Step,
                "Read-only diagnostics selected",
                "2026-08-26T01:18:17Z",
                "The run will inspect RDS connections and request latency without changing production.",
            ),
            event(
                4,
                1,
                2,
                EventType::ToolCall,
                "RDS telemetry collected",
                "2026-08-26T01:18:31Z",
                "The read-only tool found checkout connections at 92% of the RDS limit.",
            ),
            event(
                5,
                1,
                3,
                EventType::Evidence,
                "Connection pressure correlated",
                "2026-08-26T01:18:48Z",
                "Database wait time and checkout latency rise together in us-east-1.",
            ),
            typed_event(
                6,
                1,
                4,
                EventType::ToolCall,
                "Production RDS change proposed",
                "2026-08-26T01:19:00Z",
                "A production write was requested. It has not been dispatched or executed.",
                RunEventData::ToolCallRequested {
                    call: call.clone(),
                    status: ToolCallStatus::Requested,
                },
            ),
            typed_event(
                7,
                1,
                4,
                EventType::System,
                "Production policy requires approval",
                "2026-08-26T01:19:01Z",
                "Policy requires one explicit approval for this exact call and argument digest.",
                RunEventData::ToolPolicyDecided {
                    call_id: call.call_id.clone(),
                    decision: PolicyDecision::RequireApproval,
                    policy_revision: PRODUCTION_POLICY_REVISION.into(),
                    reason: "production_write requires allow-once review".into(),
                },
            ),
            RunEvent {
                sequence: 8,
                id: "evt-000008".into(),
                turn: 1,
                step: 4,
                event_type: EventType::Approval,
                title: "Production change awaiting review".into(),
                at: "2026-08-26T01:19:02Z".into(),
                summary: Some("Approve or reject the guarded RDS connection change.".into()),
                content: Some(
                    "Increase checkout-api's RDS connection ceiling from 80 to 120 in us-east-1."
                        .into(),
                ),
                metadata: BTreeMap::from([
                    ("effect".into(), json!("production_write")),
                    ("executor_status".into(), json!("unavailable")),
                    ("executed".into(), json!(false)),
                    ("region".into(), json!("us-east-1")),
                ]),
                approval: Some(approval.clone()),
                data: Some(RunEventData::ApprovalRequested {
                    approval_id: approval.id.clone(),
                    call_id: call.call_id.clone(),
                    scope: ApprovalScope::AllowOnce,
                    status: ToolCallStatus::WaitingForApproval,
                }),
            },
        ];

        Self {
            incident: IncidentSummary {
                id: "INC-2048".into(),
                title: "Checkout API latency".into(),
                severity: Severity::Critical,
                status: IncidentStatus::Mitigating,
                service: "checkout-api".into(),
                region: "us-east-1".into(),
                user_impact: "Checkout p95 is 4.8 s for 31% of active sessions".into(),
                since: "2026-08-26T01:16:00Z".into(),
            },
            run: RunSummary {
                id: DEMO_RUN_ID.into(),
                status: RunStatus::WaitingForApproval,
                environment: "production".into(),
                started_at: "2026-08-26T01:18:00Z".into(),
                duration_seconds: 62,
                agent: "Zeus Responder".into(),
                sequence: events.last().map_or(0, |event| event.sequence),
            },
            metrics: vec![
                metric(
                    "Checkout p95",
                    "4.8",
                    Some("s"),
                    Some("+3.6 s"),
                    MetricTone::Critical,
                ),
                metric(
                    "RDS connections",
                    "92",
                    Some("%"),
                    Some("+27%"),
                    MetricTone::Warning,
                ),
                metric("Pending approvals", "1", None, None, MetricTone::Warning),
                metric("Evidence collected", "4", None, None, MetricTone::Positive),
            ],
            events,
            evidence: vec![
                EvidenceSummary {
                    id: "EVD-301".into(),
                    at: "01:18:31Z".into(),
                    label: "RDS connections at 92%".into(),
                    source: "aws.rds.describe".into(),
                },
                EvidenceSummary {
                    id: "EVD-302".into(),
                    at: "01:18:48Z".into(),
                    label: "DB wait tracks checkout p95".into(),
                    source: "metrics.correlate".into(),
                },
            ],
            tool_policy: ToolPolicySummary {
                name: "Production guarded".into(),
                allows: vec!["Read metrics".into(), "Inspect RDS".into()],
                requires_approval: vec!["Change RDS limits".into(), "Restart service".into()],
                denies: vec!["Delete database".into(), "Export credentials".into()],
            },
        }
    }

    pub fn local_marker() -> Self {
        let call = local_marker_call();
        let approval = approval_for(
            "APR-DEV-1",
            &call,
            LOCAL_POLICY_REVISION,
            "write local validation marker",
            "write one deterministic marker below the configured local root",
        );
        let events = vec![
            event(
                1,
                0,
                0,
                EventType::User,
                "Local execution validation requested",
                "2026-08-26T02:00:00Z",
                "Validate the local tool loop with a marker inside the development workspace.",
            ),
            typed_event(
                2,
                1,
                1,
                EventType::ToolCall,
                "Local marker write proposed",
                "2026-08-26T02:00:01Z",
                "A workspace-scoped local write was requested. No production resource is targeted.",
                RunEventData::ToolCallRequested {
                    call: call.clone(),
                    status: ToolCallStatus::Requested,
                },
            ),
            typed_event(
                3,
                1,
                1,
                EventType::System,
                "Local policy requires allow-once review",
                "2026-08-26T02:00:02Z",
                "The exact workspace write must be approved once before dispatch.",
                RunEventData::ToolPolicyDecided {
                    call_id: call.call_id.clone(),
                    decision: PolicyDecision::RequireApproval,
                    policy_revision: LOCAL_POLICY_REVISION.into(),
                    reason: "workspace_write requires allow-once review".into(),
                },
            ),
            RunEvent {
                sequence: 4,
                id: "evt-000004".into(),
                turn: 1,
                step: 1,
                event_type: EventType::Approval,
                title: "Local marker write awaiting review".into(),
                at: "2026-08-26T02:00:03Z".into(),
                summary: Some("Approve this exact local-development write once.".into()),
                content: Some(
                    "Write a non-production marker below the configured local root.".into(),
                ),
                metadata: BTreeMap::from([
                    ("effect".into(), json!("local_write")),
                    ("environment".into(), json!("local-development")),
                    ("executed".into(), json!(false)),
                ]),
                approval: Some(approval.clone()),
                data: Some(RunEventData::ApprovalRequested {
                    approval_id: approval.id.clone(),
                    call_id: call.call_id.clone(),
                    scope: ApprovalScope::AllowOnce,
                    status: ToolCallStatus::WaitingForApproval,
                }),
            },
        ];

        Self {
            incident: IncidentSummary {
                id: "INC-DEV-1".into(),
                title: "Local tool-loop validation".into(),
                severity: Severity::Low,
                status: IncidentStatus::Investigating,
                service: "zeus-local".into(),
                region: "local".into(),
                user_impact: "No production impact; local development validation only".into(),
                since: "2026-08-26T02:00:00Z".into(),
            },
            run: RunSummary {
                id: LOCAL_DEMO_RUN_ID.into(),
                status: RunStatus::WaitingForApproval,
                environment: "local-development".into(),
                started_at: "2026-08-26T02:00:00Z".into(),
                duration_seconds: 3,
                agent: "Zeus Local Validator".into(),
                sequence: events.last().map_or(0, |event| event.sequence),
            },
            metrics: vec![
                metric(
                    "Production resources",
                    "0",
                    None,
                    None,
                    MetricTone::Positive,
                ),
                metric("Pending approvals", "1", None, None, MetricTone::Warning),
            ],
            events,
            evidence: Vec::new(),
            tool_policy: ToolPolicySummary {
                name: "Local development guarded".into(),
                allows: vec!["Read local state".into()],
                requires_approval: vec!["Write local marker once".into()],
                denies: vec!["Access production".into(), "Use network credentials".into()],
            },
        }
    }

    pub fn overview(&self) -> OverviewResponse {
        OverviewResponse {
            primary_session_id: if self.run.id == LOCAL_DEMO_RUN_ID {
                LOCAL_DEMO_SESSION_ID.into()
            } else {
                DEMO_SESSION_ID.into()
            },
            incident: self.incident.clone(),
            run: self.run.clone(),
            metrics: self.metrics.clone(),
            recent_events: self.events.clone(),
            evidence: self.evidence.clone(),
            tool_policy: Some(self.tool_policy.clone()),
            recent_events_page: None,
        }
    }
}

pub fn production_rds_call() -> ToolCall {
    ToolCall {
        call_id: PRODUCTION_DEMO_CALL_ID.into(),
        tool: "rds.connection_limit.update".into(),
        tool_version: "1".into(),
        arguments: json!({
            "connections": 120,
            "region": "us-east-1",
            "service": "checkout-api",
        }),
        arguments_digest: PRODUCTION_ARGUMENTS_DIGEST.into(),
        effect: ToolEffect::ProductionWrite,
        sandbox_profile: SandboxProfile::ProductionGuarded,
        executor_status: ToolExecutorStatus::Unavailable,
    }
}

pub fn local_marker_call() -> ToolCall {
    ToolCall {
        call_id: LOCAL_MARKER_CALL_ID.into(),
        tool: "dev_marker_write".into(),
        tool_version: "1".into(),
        arguments: json!({ "marker": "zeus alpha local marker" }),
        arguments_digest: LOCAL_MARKER_ARGUMENTS_DIGEST.into(),
        effect: ToolEffect::LocalWrite,
        sandbox_profile: SandboxProfile::WorkspaceWrite,
        executor_status: ToolExecutorStatus::Available,
    }
}

fn approval_for(
    id: &str,
    call: &ToolCall,
    policy_revision: &str,
    action: &str,
    change: &str,
) -> Approval {
    Approval {
        id: id.into(),
        status: ApprovalStatus::Pending,
        action: action.into(),
        tool: call.tool.clone(),
        change: change.into(),
        requires_approval: true,
        call_id: Some(call.call_id.clone()),
        policy_revision: Some(policy_revision.into()),
        arguments_digest: Some(call.arguments_digest.clone()),
        sandbox_profile: Some(call.sandbox_profile.clone()),
        scope: Some(ApprovalScope::AllowOnce),
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ReviewTransition {
    pub run: RunSummary,
    pub event: RunEvent,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ToolTransition {
    pub run: RunSummary,
    pub event: RunEvent,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KernelError {
    #[error("run is not waiting for a review")]
    ReviewNotPending,
    #[error("approval is missing a complete immutable tool-call binding")]
    ApprovalBindingIncomplete,
    #[error("approval binding does not match the tool call")]
    ApprovalBindingMismatch,
    #[error("approval is not approved")]
    ApprovalNotApproved,
    #[error("tool dispatch can start only from the queued state")]
    DispatchNotQueued,
    #[error("tool result can be recorded only from the running state")]
    ResultNotRunning,
    #[error("tool call descriptor is incomplete or has an invalid digest")]
    InvalidToolCall,
    #[error("executor name must not be empty")]
    InvalidExecutor,
    #[error("tool outcome exceeds the durable resource envelope")]
    InvalidToolOutcome,
    #[error("next event sequence must be exactly one greater than the run sequence")]
    InvalidSequence,
}

pub fn apply_review(
    run: &RunSummary,
    pending: &Approval,
    decision: ReviewDecision,
    note: Option<&str>,
    next_sequence: u64,
    at: impl Into<String>,
) -> Result<ReviewTransition, KernelError> {
    if run.status != RunStatus::WaitingForApproval || pending.status != ApprovalStatus::Pending {
        return Err(KernelError::ReviewNotPending);
    }
    validate_pending_binding(pending)?;
    validate_next_sequence(run, next_sequence)?;

    let (run_status, approval_status, call_status, title, summary) = match decision {
        ReviewDecision::Approve => (
            RunStatus::Queued,
            ApprovalStatus::Approved,
            ToolCallStatus::Queued,
            "Tool call approved and queued",
            "The exact approved call is queued. No tool execution has started.",
        ),
        ReviewDecision::Reject => (
            RunStatus::Blocked,
            ApprovalStatus::Rejected,
            ToolCallStatus::NotDispatched,
            "Tool call rejected",
            "The call was rejected and was not dispatched.",
        ),
    };

    let mut reviewed_approval = pending.clone();
    reviewed_approval.status = approval_status;

    let mut metadata = BTreeMap::new();
    metadata.insert("durable".into(), json!(true));
    metadata.insert("tool_status".into(), json!(call_status));
    if let Some(note) = note.filter(|note| !note.trim().is_empty()) {
        metadata.insert("review_note".into(), json!(note));
    }

    let mut updated_run = run.clone();
    updated_run.status = run_status;
    updated_run.sequence = next_sequence;

    Ok(ReviewTransition {
        run: updated_run,
        event: RunEvent {
            sequence: next_sequence,
            id: format!("evt-{next_sequence:06}"),
            turn: 1,
            step: 4,
            event_type: EventType::Approval,
            title: title.into(),
            at: at.into(),
            summary: Some(summary.into()),
            content: note.map(ToOwned::to_owned),
            metadata,
            approval: Some(reviewed_approval),
            data: Some(RunEventData::ApprovalDecided {
                approval_id: pending.id.clone(),
                call_id: pending.call_id.clone().expect("validated above"),
                decision,
                status: call_status,
            }),
        },
    })
}

pub fn start_tool_dispatch(
    run: &RunSummary,
    approved: &Approval,
    call: &ToolCall,
    executor: impl Into<String>,
    next_sequence: u64,
    at: impl Into<String>,
) -> Result<ToolTransition, KernelError> {
    if run.status != RunStatus::Queued {
        return Err(KernelError::DispatchNotQueued);
    }
    if approved.status != ApprovalStatus::Approved {
        return Err(KernelError::ApprovalNotApproved);
    }
    validate_tool_call(call)?;
    validate_approval_binding(approved, call)?;
    validate_next_sequence(run, next_sequence)?;

    let executor = executor.into();
    if executor.trim().is_empty()
        || executor.trim() != executor
        || executor.len() > 256
        || executor.chars().any(char::is_control)
    {
        return Err(KernelError::InvalidExecutor);
    }

    let summary = match call.executor_status {
        ToolExecutorStatus::Available => {
            "The durable dispatch checkpoint was recorded. A tool result is still required."
        }
        ToolExecutorStatus::Unavailable => {
            "The durable dispatch checkpoint was recorded, but the executor is unavailable; no tool side effect has occurred."
        }
    };

    let mut updated_run = run.clone();
    updated_run.status = RunStatus::Running;
    updated_run.sequence = next_sequence;

    Ok(ToolTransition {
        run: updated_run,
        event: RunEvent {
            sequence: next_sequence,
            id: format!("evt-{next_sequence:06}"),
            turn: 1,
            step: 4,
            event_type: EventType::ToolCall,
            title: "Tool dispatch checkpoint recorded".into(),
            at: at.into(),
            summary: Some(summary.into()),
            content: None,
            metadata: BTreeMap::from([
                ("durable".into(), json!(true)),
                ("side_effect_claimed".into(), json!(false)),
            ]),
            approval: None,
            data: Some(RunEventData::ToolDispatchStarted {
                call_id: call.call_id.clone(),
                executor,
                executor_status: call.executor_status.clone(),
                sandbox_profile: call.sandbox_profile.clone(),
                status: ToolCallStatus::Running,
            }),
        },
    })
}

pub fn apply_tool_result(
    run: &RunSummary,
    call: &ToolCall,
    outcome: ToolOutcome,
    next_sequence: u64,
    at: impl Into<String>,
) -> Result<ToolTransition, KernelError> {
    if run.status != RunStatus::Running {
        return Err(KernelError::ResultNotRunning);
    }
    validate_tool_call(call)?;
    validate_next_sequence(run, next_sequence)?;
    outcome
        .validate_resource_envelope()
        .map_err(|_| KernelError::InvalidToolOutcome)?;

    let (run_status, title, summary) = match &outcome {
        ToolOutcome::Succeeded { summary, .. } => (
            RunStatus::Succeeded,
            "Tool execution succeeded",
            summary.as_str(),
        ),
        ToolOutcome::Failed { summary, .. } => {
            (RunStatus::Failed, "Tool execution failed", summary.as_str())
        }
        ToolOutcome::Cancelled { summary } => (
            RunStatus::Cancelled,
            "Tool execution cancelled",
            summary.as_str(),
        ),
        ToolOutcome::NotDispatched { summary, .. } => (
            RunStatus::NeedsAttention,
            "Tool was not dispatched",
            summary.as_str(),
        ),
        ToolOutcome::OutcomeUnknown { summary } => (
            RunStatus::NeedsAttention,
            "Tool outcome is unknown",
            summary.as_str(),
        ),
    };
    let call_status = outcome.call_status();
    let mut metadata = BTreeMap::from([("durable".into(), json!(true))]);
    match &outcome {
        ToolOutcome::NotDispatched { .. } => {
            metadata.insert("executor_invoked".into(), json!(false));
        }
        ToolOutcome::OutcomeUnknown { .. } => {
            metadata.insert("outcome_known".into(), json!(false));
        }
        _ => {
            metadata.insert("outcome_known".into(), json!(true));
        }
    }

    let mut updated_run = run.clone();
    updated_run.status = run_status;
    updated_run.sequence = next_sequence;

    Ok(ToolTransition {
        run: updated_run,
        event: RunEvent {
            sequence: next_sequence,
            id: format!("evt-{next_sequence:06}"),
            turn: 1,
            step: 4,
            event_type: EventType::ToolCall,
            title: title.into(),
            at: at.into(),
            summary: Some(summary.into()),
            content: None,
            metadata,
            approval: None,
            data: Some(RunEventData::ToolResult {
                call_id: call.call_id.clone(),
                outcome,
                status: call_status,
            }),
        },
    })
}

fn validate_next_sequence(run: &RunSummary, next_sequence: u64) -> Result<(), KernelError> {
    if run.sequence.checked_add(1) != Some(next_sequence) {
        return Err(KernelError::InvalidSequence);
    }
    Ok(())
}

fn validate_pending_binding(approval: &Approval) -> Result<(), KernelError> {
    let complete = approval.requires_approval
        && !approval.tool.trim().is_empty()
        && approval
            .call_id
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        && approval
            .policy_revision
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        && approval
            .arguments_digest
            .as_deref()
            .is_some_and(valid_arguments_digest)
        && approval.sandbox_profile.is_some()
        && approval.scope == Some(ApprovalScope::AllowOnce);
    if !complete {
        return Err(KernelError::ApprovalBindingIncomplete);
    }
    Ok(())
}

fn validate_tool_call(call: &ToolCall) -> Result<(), KernelError> {
    let valid = !call.call_id.trim().is_empty()
        && !call.tool.trim().is_empty()
        && !call.tool_version.trim().is_empty()
        && valid_arguments_digest(&call.arguments_digest);
    if !valid {
        return Err(KernelError::InvalidToolCall);
    }
    Ok(())
}

fn validate_approval_binding(approval: &Approval, call: &ToolCall) -> Result<(), KernelError> {
    validate_pending_binding(approval)?;
    let matches = approval.tool == call.tool
        && approval.call_id.as_deref() == Some(call.call_id.as_str())
        && approval.arguments_digest.as_deref() == Some(call.arguments_digest.as_str())
        && approval.sandbox_profile.as_ref() == Some(&call.sandbox_profile);
    if !matches {
        return Err(KernelError::ApprovalBindingMismatch);
    }
    Ok(())
}

fn valid_arguments_digest(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn event(
    sequence: u64,
    turn: u32,
    step: u32,
    event_type: EventType,
    title: &str,
    at: &str,
    summary: &str,
) -> RunEvent {
    RunEvent {
        sequence,
        id: format!("evt-{sequence:06}"),
        turn,
        step,
        event_type,
        title: title.into(),
        at: at.into(),
        summary: Some(summary.into()),
        content: None,
        metadata: BTreeMap::new(),
        approval: None,
        data: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn typed_event(
    sequence: u64,
    turn: u32,
    step: u32,
    event_type: EventType,
    title: &str,
    at: &str,
    summary: &str,
    data: RunEventData,
) -> RunEvent {
    RunEvent {
        data: Some(data),
        ..event(sequence, turn, step, event_type, title, at, summary)
    }
}

fn metric(
    label: &str,
    value: &str,
    unit: Option<&str>,
    trend: Option<&str>,
    tone: MetricTone,
) -> Metric {
    Metric {
        label: label.into(),
        value: value.into(),
        unit: unit.map(Into::into),
        trend: trend.map(Into::into),
        tone: Some(tone),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::NotDispatchedReason;

    #[test]
    fn demo_sequences_are_contiguous() {
        let demo = DemoScenario::zr_1842();
        let sequences = demo
            .events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>();
        assert_eq!(sequences, (1..=8).collect::<Vec<_>>());
        assert_eq!(demo.run.sequence, 8);

        let local = DemoScenario::local_marker();
        let sequences = local
            .events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>();
        assert_eq!(sequences, (1..=4).collect::<Vec<_>>());
        assert_eq!(local.run.sequence, 4);
    }

    #[test]
    fn production_fixture_requires_approval_and_does_not_claim_execution() {
        let demo = DemoScenario::zr_1842();
        let call = demo
            .events
            .iter()
            .find_map(|event| match &event.data {
                Some(RunEventData::ToolCallRequested { call, .. })
                    if call.call_id == PRODUCTION_DEMO_CALL_ID =>
                {
                    Some(call)
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(call.effect, ToolEffect::ProductionWrite);
        assert_eq!(call.executor_status, ToolExecutorStatus::Unavailable);

        assert!(demo.events.iter().any(|event| matches!(
            &event.data,
            Some(RunEventData::ToolPolicyDecided {
                decision: PolicyDecision::RequireApproval,
                ..
            })
        )));
        assert!(!demo.events.iter().any(|event| matches!(
            event.data,
            Some(RunEventData::ToolDispatchStarted { .. } | RunEventData::ToolResult { .. })
        )));

        let approval = demo.events.last().unwrap().approval.as_ref().unwrap();
        assert_eq!(approval.status, ApprovalStatus::Pending);
        assert_eq!(approval.call_id.as_deref(), Some(PRODUCTION_DEMO_CALL_ID));
        assert_eq!(approval.scope, Some(ApprovalScope::AllowOnce));
    }

    #[test]
    fn local_marker_fixture_is_scoped_and_never_masquerades_as_production() {
        let demo = DemoScenario::local_marker();
        assert_eq!(demo.run.id, LOCAL_DEMO_RUN_ID);
        assert_eq!(demo.run.environment, "local-development");
        assert_eq!(demo.incident.region, "local");

        let call = local_marker_call();
        assert_eq!(call.tool, "dev_marker_write");
        assert_eq!(call.effect, ToolEffect::LocalWrite);
        assert_eq!(call.sandbox_profile, SandboxProfile::WorkspaceWrite);
        assert_eq!(call.executor_status, ToolExecutorStatus::Available);
        assert!(!demo.events.iter().any(|event| {
            matches!(
                &event.data,
                Some(RunEventData::ToolCallRequested { call, .. })
                    if call.effect == ToolEffect::ProductionWrite
            )
        }));
    }

    #[test]
    fn approval_only_queues_the_bound_call() {
        let demo = DemoScenario::zr_1842();
        let pending = demo.events.last().unwrap().approval.as_ref().unwrap();
        let transition = apply_review(
            &demo.run,
            pending,
            ReviewDecision::Approve,
            Some("Reviewed by on-call"),
            9,
            "2026-08-26T01:20:00Z",
        )
        .unwrap();

        assert_eq!(transition.run.status, RunStatus::Queued);
        assert_eq!(transition.run.sequence, 9);
        assert_eq!(transition.event.sequence, 9);
        assert_eq!(
            transition.event.approval.as_ref().unwrap().status,
            ApprovalStatus::Approved
        );
        assert!(matches!(
            transition.event.data,
            Some(RunEventData::ApprovalDecided {
                status: ToolCallStatus::Queued,
                ..
            })
        ));
        assert!(
            transition
                .event
                .summary
                .as_deref()
                .unwrap()
                .contains("No tool execution has started")
        );
    }

    #[test]
    fn rejection_is_a_not_dispatched_terminal_decision() {
        let demo = DemoScenario::zr_1842();
        let pending = demo.events.last().unwrap().approval.as_ref().unwrap();
        let transition = apply_review(
            &demo.run,
            pending,
            ReviewDecision::Reject,
            None,
            9,
            "2026-08-26T01:20:00Z",
        )
        .unwrap();

        assert_eq!(transition.run.status, RunStatus::Blocked);
        assert!(transition.run.status.is_terminal());
        assert!(matches!(
            transition.event.data,
            Some(RunEventData::ApprovalDecided {
                decision: ReviewDecision::Reject,
                status: ToolCallStatus::NotDispatched,
                ..
            })
        ));
    }

    #[test]
    fn review_rejects_a_sequence_gap() {
        let demo = DemoScenario::zr_1842();
        let pending = demo.events.last().unwrap().approval.as_ref().unwrap();
        let error = apply_review(
            &demo.run,
            pending,
            ReviewDecision::Approve,
            None,
            10,
            "2026-08-26T01:20:00Z",
        )
        .unwrap_err();

        assert_eq!(error, KernelError::InvalidSequence);
    }

    #[test]
    fn legacy_unbound_approval_fails_closed() {
        let demo = DemoScenario::zr_1842();
        let mut pending = demo.events.last().unwrap().approval.clone().unwrap();
        pending.call_id = None;

        let error = apply_review(
            &demo.run,
            &pending,
            ReviewDecision::Approve,
            None,
            9,
            "2026-08-26T01:20:00Z",
        )
        .unwrap_err();

        assert_eq!(error, KernelError::ApprovalBindingIncomplete);
    }

    #[test]
    fn dispatch_start_requires_queued_and_an_exact_approval_binding() {
        let demo = DemoScenario::local_marker();
        let pending = demo.events.last().unwrap().approval.as_ref().unwrap();
        let call = local_marker_call();

        let error = start_tool_dispatch(
            &demo.run,
            pending,
            &call,
            "local-marker",
            5,
            "2026-08-26T02:01:00Z",
        )
        .unwrap_err();
        assert_eq!(error, KernelError::DispatchNotQueued);

        let approved = apply_review(
            &demo.run,
            pending,
            ReviewDecision::Approve,
            None,
            5,
            "2026-08-26T02:01:00Z",
        )
        .unwrap();
        let approved_binding = approved.event.approval.as_ref().unwrap();
        let mut mismatched_call = call.clone();
        mismatched_call.arguments_digest = format!("sha256:{}", "0".repeat(64));
        let error = start_tool_dispatch(
            &approved.run,
            approved_binding,
            &mismatched_call,
            "local-marker",
            6,
            "2026-08-26T02:01:01Z",
        )
        .unwrap_err();
        assert_eq!(error, KernelError::ApprovalBindingMismatch);
    }

    #[test]
    fn unavailable_executor_has_a_checkpoint_then_not_dispatched_result() {
        let demo = DemoScenario::zr_1842();
        let pending = demo.events.last().unwrap().approval.as_ref().unwrap();
        let call = production_rds_call();
        let approved = apply_review(
            &demo.run,
            pending,
            ReviewDecision::Approve,
            None,
            9,
            "2026-08-26T01:20:00Z",
        )
        .unwrap();
        let dispatch = start_tool_dispatch(
            &approved.run,
            approved.event.approval.as_ref().unwrap(),
            &call,
            "production-rds",
            10,
            "2026-08-26T01:20:01Z",
        )
        .unwrap();

        assert_eq!(dispatch.run.status, RunStatus::Running);
        assert_eq!(dispatch.event.metadata["side_effect_claimed"], false);
        assert!(
            dispatch
                .event
                .summary
                .as_deref()
                .unwrap()
                .contains("no tool side effect")
        );

        let result = apply_tool_result(
            &dispatch.run,
            &call,
            ToolOutcome::NotDispatched {
                reason: NotDispatchedReason::ExecutorUnavailable,
                summary: "Production RDS executor is not installed.".into(),
            },
            11,
            "2026-08-26T01:20:02Z",
        )
        .unwrap();

        assert_eq!(result.run.status, RunStatus::NeedsAttention);
        assert!(result.run.status.is_terminal());
        assert_eq!(result.event.metadata["executor_invoked"], false);
        assert!(matches!(
            result.event.data,
            Some(RunEventData::ToolResult {
                status: ToolCallStatus::NotDispatched,
                outcome: ToolOutcome::NotDispatched {
                    reason: NotDispatchedReason::ExecutorUnavailable,
                    ..
                },
                ..
            })
        ));
    }

    #[test]
    fn result_only_accepts_running_and_maps_outcome_unknown_fail_closed() {
        let demo = DemoScenario::local_marker();
        let call = local_marker_call();
        let error = apply_tool_result(
            &demo.run,
            &call,
            ToolOutcome::Succeeded {
                summary: "not actually run".into(),
                output_digest: None,
            },
            5,
            "2026-08-26T02:01:00Z",
        )
        .unwrap_err();
        assert_eq!(error, KernelError::ResultNotRunning);

        let pending = demo.events.last().unwrap().approval.as_ref().unwrap();
        let approved = apply_review(
            &demo.run,
            pending,
            ReviewDecision::Approve,
            None,
            5,
            "2026-08-26T02:01:00Z",
        )
        .unwrap();
        let dispatch = start_tool_dispatch(
            &approved.run,
            approved.event.approval.as_ref().unwrap(),
            &call,
            "local-marker",
            6,
            "2026-08-26T02:01:01Z",
        )
        .unwrap();
        let result = apply_tool_result(
            &dispatch.run,
            &call,
            ToolOutcome::OutcomeUnknown {
                summary: "The process restarted after dispatch; no receipt is available.".into(),
            },
            7,
            "2026-08-26T02:01:02Z",
        )
        .unwrap();

        assert_eq!(result.run.status, RunStatus::NeedsAttention);
        assert_eq!(result.event.metadata["outcome_known"], false);
        assert!(matches!(
            result.event.data,
            Some(RunEventData::ToolResult {
                status: ToolCallStatus::OutcomeUnknown,
                ..
            })
        ));
    }
}
