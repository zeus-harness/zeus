use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::CANCELED_TOOL_RESULT_CODE;
use crate::{EventId, RunId, SessionId};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    User,
    ServiceAccount,
    Agent,
    System,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActorRef {
    pub kind: ActorKind,
    pub id: Option<Uuid>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EventEnvelope {
    pub id: EventId,
    pub sequence: i64,
    pub schema_version: u16,
    pub event_type: String,
    pub occurred_at: OffsetDateTime,
    pub actor: ActorRef,
    pub payload: Value,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SessionEvent {
    pub session_id: SessionId,
    pub run_id: Option<RunId>,
    pub envelope: EventEnvelope,
    pub kind: SessionEventKind,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionEventKind {
    UserMessage {
        content: String,
    },
    AssistantMessage {
        content: String,
    },
    ToolCall {
        call_id: String,
        capability: String,
    },
    ToolResult {
        call_id: String,
        result: Value,
        synthetic: bool,
    },
    ApprovalResult {
        approval_id: Uuid,
        approved: bool,
    },
    SteeringMessage {
        content: String,
    },
    FollowUpMessage {
        content: String,
    },
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ToolPairError {
    #[error("tool call {0} appears more than once")]
    DuplicateCall(String),
    #[error("tool result {0} has no preceding call")]
    OrphanResult(String),
    #[error("tool calls have no result: {0:?}")]
    MissingResults(Vec<String>),
}

/// Checks that every tool call has one later result and that call IDs are unique.
///
/// # Errors
///
/// Returns [`ToolPairError`] for duplicate calls, orphan results, or calls that
/// remain open at the end of the event slice.
pub fn validate_tool_pairs(events: &[SessionEvent]) -> Result<(), ToolPairError> {
    let mut seen = HashSet::new();
    let mut pending = HashSet::new();

    for event in events {
        match &event.kind {
            SessionEventKind::ToolCall { call_id, .. } => {
                if !seen.insert(call_id.clone()) {
                    return Err(ToolPairError::DuplicateCall(call_id.clone()));
                }
                pending.insert(call_id.clone());
            }
            SessionEventKind::ToolResult { call_id, .. } if !pending.remove(call_id) => {
                return Err(ToolPairError::OrphanResult(call_id.clone()));
            }
            _ => {}
        }
    }

    if pending.is_empty() {
        return Ok(());
    }

    let mut missing = pending.into_iter().collect::<Vec<_>>();
    missing.sort_unstable();
    Err(ToolPairError::MissingResults(missing))
}

/// Returns synthetic results for calls that are still open when a run is
/// canceled. Existing pairs are left untouched and malformed event slices are
/// rejected, so the returned results can be appended before rebuilding a
/// model context.
///
/// # Errors
///
/// Returns [`ToolPairError`] for duplicate calls or orphan results.
pub fn synthesize_canceled_tool_results(
    events: &[SessionEvent],
) -> Result<Vec<SessionEventKind>, ToolPairError> {
    let mut seen = HashSet::new();
    let mut pending = Vec::new();

    for event in events {
        match &event.kind {
            SessionEventKind::ToolCall { call_id, .. } => {
                if !seen.insert(call_id.clone()) {
                    return Err(ToolPairError::DuplicateCall(call_id.clone()));
                }
                pending.push(call_id.clone());
            }
            SessionEventKind::ToolResult { call_id, .. } => {
                let Some(index) = pending.iter().position(|pending_id| pending_id == call_id)
                else {
                    return Err(ToolPairError::OrphanResult(call_id.clone()));
                };
                pending.remove(index);
            }
            _ => {}
        }
    }

    Ok(pending
        .into_iter()
        .map(|call_id| SessionEventKind::ToolResult {
            call_id,
            result: json!({ "code": CANCELED_TOOL_RESULT_CODE }),
            synthetic: true,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::{
        ActorKind, ActorRef, EventEnvelope, SessionEvent, SessionEventKind, ToolPairError,
        synthesize_canceled_tool_results, validate_tool_pairs,
    };
    use crate::{EventId, SessionId};

    fn event(sequence: i64, kind: SessionEventKind) -> SessionEvent {
        SessionEvent {
            session_id: SessionId::new(),
            run_id: None,
            envelope: EventEnvelope {
                id: EventId::new(),
                sequence,
                schema_version: 1,
                event_type: "test".to_owned(),
                occurred_at: OffsetDateTime::now_utc(),
                actor: ActorRef {
                    kind: ActorKind::System,
                    id: Some(Uuid::now_v7()),
                },
                payload: json!({}),
            },
            kind,
        }
    }

    #[test]
    fn accepts_paired_tool_call_and_result() {
        let events = [
            event(
                1,
                SessionEventKind::ToolCall {
                    call_id: "call-1".to_owned(),
                    capability: "crm.read".to_owned(),
                },
            ),
            event(
                2,
                SessionEventKind::ToolResult {
                    call_id: "call-1".to_owned(),
                    result: json!({ "records": [] }),
                    synthetic: false,
                },
            ),
        ];

        assert_eq!(validate_tool_pairs(&events), Ok(()));
    }

    #[test]
    fn rejects_unfinished_tool_call() {
        let events = [event(
            1,
            SessionEventKind::ToolCall {
                call_id: "call-1".to_owned(),
                capability: "crm.read".to_owned(),
            },
        )];

        assert_eq!(
            validate_tool_pairs(&events),
            Err(ToolPairError::MissingResults(vec!["call-1".to_owned()]))
        );
    }

    #[test]
    fn synthetic_result_closes_a_canceled_tool_call() {
        let events = [
            event(
                1,
                SessionEventKind::ToolCall {
                    call_id: "call-1".to_owned(),
                    capability: "crm.write".to_owned(),
                },
            ),
            event(
                2,
                SessionEventKind::ToolResult {
                    call_id: "call-1".to_owned(),
                    result: json!({ "code": "run_canceled" }),
                    synthetic: true,
                },
            ),
        ];

        assert_eq!(validate_tool_pairs(&events), Ok(()));
    }

    #[test]
    fn cancellation_synthesizes_results_for_only_open_calls() {
        let events = [
            event(
                1,
                SessionEventKind::ToolCall {
                    call_id: "call-1".to_owned(),
                    capability: "crm.read".to_owned(),
                },
            ),
            event(
                2,
                SessionEventKind::ToolCall {
                    call_id: "call-2".to_owned(),
                    capability: "crm.write".to_owned(),
                },
            ),
            event(
                3,
                SessionEventKind::ToolResult {
                    call_id: "call-1".to_owned(),
                    result: json!({ "ok": true }),
                    synthetic: false,
                },
            ),
        ];

        let synthetic = synthesize_canceled_tool_results(&events)
            .expect("only the open call needs a synthetic result");

        assert_eq!(
            synthetic,
            vec![SessionEventKind::ToolResult {
                call_id: "call-2".to_owned(),
                result: json!({ "code": "run_canceled" }),
                synthetic: true,
            }]
        );
    }
}
