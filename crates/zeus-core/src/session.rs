use std::collections::{HashSet, VecDeque};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    ModelMessage, SessionEvent, SessionEventKind, ToolCall, ToolPairError, ToolResult,
    validate_tool_pairs,
};

/// The model context reconstructed from append-only Session events.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionContext {
    messages: Vec<ModelMessage>,
}

impl SessionContext {
    /// Reconstructs model messages and consumes steering at the next tool
    /// boundary.
    ///
    /// A context is only valid when every tool call has a later result. A
    /// caller recovering a canceled run should first append the synthetic
    /// results returned by [`crate::synthesize_canceled_tool_results`].
    ///
    /// # Errors
    ///
    /// Returns [`SessionContextError::ToolPairs`] when the event slice has an
    /// orphan, duplicate, or unfinished tool call.
    pub fn from_events(events: &[SessionEvent]) -> Result<Self, SessionContextError> {
        validate_tool_pairs(events)?;

        let mut messages = Vec::new();
        let mut open_tool_calls = Vec::new();
        let mut pending_call_ids = HashSet::new();
        let mut queued_steering = VecDeque::new();

        for event in events {
            match &event.kind {
                SessionEventKind::UserMessage { content } => {
                    flush_tool_calls(&mut messages, &mut open_tool_calls);
                    if pending_call_ids.is_empty() {
                        flush_steering(&mut messages, &mut queued_steering);
                    }
                    messages.push(ModelMessage::user(content.clone()));
                }
                SessionEventKind::AssistantMessage { content } => {
                    flush_tool_calls(&mut messages, &mut open_tool_calls);
                    if pending_call_ids.is_empty() {
                        flush_steering(&mut messages, &mut queued_steering);
                    }
                    messages.push(ModelMessage::assistant(content.clone()));
                }
                SessionEventKind::ToolCall {
                    call_id,
                    capability,
                } => {
                    if pending_call_ids.is_empty() {
                        flush_steering(&mut messages, &mut queued_steering);
                    }
                    open_tool_calls.push(ToolCall::new(
                        call_id.clone(),
                        capability.clone(),
                        event
                            .envelope
                            .payload
                            .get("arguments")
                            .cloned()
                            .unwrap_or(Value::Null),
                    ));
                    pending_call_ids.insert(call_id.clone());
                }
                SessionEventKind::ToolResult {
                    call_id,
                    result,
                    synthetic,
                } => {
                    flush_tool_calls(&mut messages, &mut open_tool_calls);
                    messages.push(ModelMessage::tool(ToolResult {
                        call_id: call_id.clone(),
                        content: result.clone(),
                        synthetic: *synthetic,
                    }));
                    pending_call_ids.remove(call_id);
                    if pending_call_ids.is_empty() {
                        flush_steering(&mut messages, &mut queued_steering);
                    }
                }
                SessionEventKind::SteeringMessage { content } => {
                    queued_steering.push_back(content.clone());
                    if pending_call_ids.is_empty() {
                        flush_steering(&mut messages, &mut queued_steering);
                    }
                }
                SessionEventKind::ApprovalResult { .. }
                | SessionEventKind::FollowUpMessage { .. } => {
                    flush_tool_calls(&mut messages, &mut open_tool_calls);
                    if pending_call_ids.is_empty() {
                        flush_steering(&mut messages, &mut queued_steering);
                    }
                }
            }
        }

        flush_tool_calls(&mut messages, &mut open_tool_calls);
        flush_steering(&mut messages, &mut queued_steering);

        Ok(Self { messages })
    }

    /// Reconstructs a context with a system message at the front.
    ///
    /// # Errors
    ///
    /// Returns [`SessionContextError::ToolPairs`] when the event slice has an
    /// invalid tool-call/result pairing.
    pub fn from_events_with_system_prompt(
        events: &[SessionEvent],
        system_prompt: impl Into<String>,
    ) -> Result<Self, SessionContextError> {
        let mut context = Self::from_events(events)?;
        context
            .messages
            .insert(0, ModelMessage::system(system_prompt));
        Ok(context)
    }

    #[must_use]
    pub const fn messages(&self) -> &[ModelMessage] {
        self.messages.as_slice()
    }
}

/// Small value builder for callers that need an optional system prompt.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionContextBuilder {
    system_prompt: Option<String>,
}

impl SessionContextBuilder {
    #[must_use]
    pub fn with_system_prompt(mut self, system_prompt: impl Into<String>) -> Self {
        self.system_prompt = Some(system_prompt.into());
        self
    }

    /// Builds a context without performing IO or consulting a persistence
    /// layer.
    /// # Errors
    ///
    /// Returns [`SessionContextError::ToolPairs`] when the event slice has an
    /// invalid tool-call/result pairing.
    pub fn build(self, events: &[SessionEvent]) -> Result<SessionContext, SessionContextError> {
        match self.system_prompt {
            Some(prompt) => SessionContext::from_events_with_system_prompt(events, prompt),
            None => SessionContext::from_events(events),
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SessionContextError {
    #[error(transparent)]
    ToolPairs(#[from] ToolPairError),
}

fn flush_tool_calls(messages: &mut Vec<ModelMessage>, open_tool_calls: &mut Vec<ToolCall>) {
    if !open_tool_calls.is_empty() {
        messages.push(ModelMessage::assistant_with_tool_calls(std::mem::take(
            open_tool_calls,
        )));
    }
}

fn flush_steering(messages: &mut Vec<ModelMessage>, queued_steering: &mut VecDeque<String>) {
    messages.extend(queued_steering.drain(..).map(ModelMessage::steering));
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::{SessionContext, SessionContextBuilder};
    use crate::{
        ActorKind, ActorRef, EventEnvelope, EventId, ModelMessage, SessionEvent, SessionEventKind,
        SessionId,
    };

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
    fn steering_waits_until_the_current_tool_boundary() {
        let context = SessionContext::from_events(&[
            event(
                1,
                SessionEventKind::UserMessage {
                    content: "start".to_owned(),
                },
            ),
            event(
                2,
                SessionEventKind::ToolCall {
                    call_id: "call-1".to_owned(),
                    capability: "crm.read".to_owned(),
                },
            ),
            event(
                3,
                SessionEventKind::SteeringMessage {
                    content: "stop after this tool".to_owned(),
                },
            ),
            event(
                4,
                SessionEventKind::ToolResult {
                    call_id: "call-1".to_owned(),
                    result: json!({ "records": [] }),
                    synthetic: false,
                },
            ),
            event(
                5,
                SessionEventKind::AssistantMessage {
                    content: "done".to_owned(),
                },
            ),
        ])
        .expect("paired events produce a context");

        assert!(matches!(context.messages()[0], ModelMessage::User { .. }));
        assert!(matches!(
            context.messages()[1],
            ModelMessage::Assistant { ref tool_calls, .. }
                if tool_calls.len() == 1
                    && tool_calls[0].arguments == Value::Null
        ));
        assert!(matches!(context.messages()[2], ModelMessage::Tool { .. }));
        assert!(matches!(
            context.messages()[3],
            ModelMessage::Steering { ref content } if content == "stop after this tool"
        ));
        assert!(matches!(
            context.messages()[4],
            ModelMessage::Assistant { ref content, .. } if content.as_deref() == Some("done")
        ));
    }

    #[test]
    fn tool_call_arguments_are_reconstructed_from_event_payload() {
        let mut call = event(
            1,
            SessionEventKind::ToolCall {
                call_id: "call-1".to_owned(),
                capability: "crm.read".to_owned(),
            },
        );
        call.envelope.payload = json!({ "arguments": { "customer_id": 7 } });
        let result = event(
            2,
            SessionEventKind::ToolResult {
                call_id: "call-1".to_owned(),
                result: json!({ "ok": true }),
                synthetic: false,
            },
        );

        let context = SessionContext::from_events(&[call, result]).expect("paired call");

        assert!(matches!(
            &context.messages()[0],
            ModelMessage::Assistant { tool_calls, .. }
                if tool_calls[0].arguments == json!({ "customer_id": 7 })
        ));
    }

    #[test]
    fn builder_prepends_a_system_prompt() {
        let context = SessionContextBuilder::default()
            .with_system_prompt("be concise")
            .build(&[])
            .expect("empty session is valid");

        assert!(matches!(
            context.messages().first(),
            Some(ModelMessage::System { content }) if content == "be concise"
        ));
    }
}
