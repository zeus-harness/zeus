//! Durable Session-child discovery and its model-facing tool contract.
//!
//! This first seam is deliberately read-only: the runtime resolves the exact
//! started Agent scope and reads direct children from SQLite. Spawn, delivery,
//! and interruption remain separate future capabilities instead of being
//! implied by a catalog row.

use std::collections::BTreeMap;

use protocol::{SandboxProfile, SessionForkSummary, ToolEffect};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tools::{
    ExecutionFuture, ExecutionRequest, ExecutorError, ObjectSchema, ParameterSpec, ParameterType,
    RegistryError, TOOL_OUTPUT_MAX_SERIALIZED_BYTES, ToolDescriptor, ToolExecutor, ToolRegistry,
};

pub const LIST_AGENTS_TOOL_NAME: &str = "list_agents";
pub const LIST_AGENTS_TOOL_VERSION: &str = "1-direct-session-forks";
pub const LIST_AGENTS_DEFAULT_LIMIT: usize = 16;
pub const LIST_AGENTS_MAX_LIMIT: usize = 32;
pub const LIST_AGENTS_CURSOR_MAX_BYTES: usize = 4 * 1024;
pub const LIST_AGENTS_ARGUMENTS_MAX_BYTES: usize = 8 * 1024;

const LIST_AGENTS_DESCRIPTION: &str = "List this Session's durable direct child branches by stable child Session ID and immutable fork boundary. This is a bounded read, not completion polling: use the opaque next_cursor to continue when present. A returned child is independently continuable, but this tool does not send it work, interrupt it, or claim that it is currently executing.";

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum SubagentError {
    #[error("list_agents arguments are not a strict bounded object")]
    InvalidArguments,
    #[error("list_agents limit must be between 1 and {LIST_AGENTS_MAX_LIMIT}")]
    InvalidLimit,
    #[error("list_agents cursor is not a canonical bounded opaque value")]
    InvalidCursor,
    #[error("list_agents result exceeds its bounded output contract")]
    InvalidResult,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawListAgentsRequest {
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListAgentsRequest {
    cursor: Option<String>,
    limit: usize,
}

impl ListAgentsRequest {
    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }

    pub const fn limit(&self) -> usize {
        self.limit
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListAgentsResult {
    pub agents: Vec<SessionForkSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

impl ListAgentsResult {
    pub fn new(
        agents: Vec<SessionForkSummary>,
        next_cursor: Option<String>,
    ) -> Result<Self, SubagentError> {
        if agents.len() > LIST_AGENTS_MAX_LIMIT
            || (next_cursor.is_some() && agents.is_empty())
            || next_cursor
                .as_deref()
                .is_some_and(|cursor| !valid_cursor(cursor))
        {
            return Err(SubagentError::InvalidResult);
        }
        let result = Self {
            agents,
            next_cursor,
        };
        let encoded = serde_json::to_vec(&result).map_err(|_| SubagentError::InvalidResult)?;
        if encoded.len() > TOOL_OUTPUT_MAX_SERIALIZED_BYTES {
            return Err(SubagentError::InvalidResult);
        }
        Ok(result)
    }
}

pub fn prepare_list_agents(arguments: &Value) -> Result<ListAgentsRequest, SubagentError> {
    let encoded = serde_json::to_vec(arguments).map_err(|_| SubagentError::InvalidArguments)?;
    if encoded.len() > LIST_AGENTS_ARGUMENTS_MAX_BYTES {
        return Err(SubagentError::InvalidArguments);
    }
    let raw: RawListAgentsRequest =
        serde_json::from_value(arguments.clone()).map_err(|_| SubagentError::InvalidArguments)?;
    let limit = raw.limit.unwrap_or(LIST_AGENTS_DEFAULT_LIMIT);
    if !(1..=LIST_AGENTS_MAX_LIMIT).contains(&limit) {
        return Err(SubagentError::InvalidLimit);
    }
    if raw
        .cursor
        .as_deref()
        .is_some_and(|cursor| !valid_cursor(cursor))
    {
        return Err(SubagentError::InvalidCursor);
    }
    Ok(ListAgentsRequest {
        cursor: raw.cursor,
        limit,
    })
}

fn valid_cursor(cursor: &str) -> bool {
    !cursor.is_empty()
        && cursor.len() <= LIST_AGENTS_CURSOR_MAX_BYTES
        && cursor.trim() == cursor
        && !cursor.chars().any(char::is_control)
}

pub fn list_agents_descriptor() -> ToolDescriptor {
    ToolDescriptor {
        name: LIST_AGENTS_TOOL_NAME.into(),
        version: LIST_AGENTS_TOOL_VERSION.into(),
        description: LIST_AGENTS_DESCRIPTION.into(),
        effect: ToolEffect::ReadOnly,
        sandbox_profile: SandboxProfile::ReadOnly,
        input_schema: ObjectSchema {
            max_serialized_bytes: LIST_AGENTS_ARGUMENTS_MAX_BYTES,
            properties: BTreeMap::from([
                (
                    "cursor".into(),
                    ParameterSpec {
                        parameter_type: ParameterType::String,
                        required: false,
                        min_length: Some(1),
                        max_length: Some(LIST_AGENTS_CURSOR_MAX_BYTES),
                    },
                ),
                (
                    "limit".into(),
                    ParameterSpec {
                        parameter_type: ParameterType::Integer,
                        required: false,
                        min_length: None,
                        max_length: None,
                    },
                ),
            ]),
        },
    }
}

pub fn register_subagent_tools(registry: &mut ToolRegistry) -> Result<(), RegistryError> {
    registry.register(list_agents_descriptor(), RuntimeSubagentExecutor)
}

#[derive(Clone, Copy)]
struct RuntimeSubagentExecutor;

impl ToolExecutor for RuntimeSubagentExecutor {
    fn execute(&self, _request: ExecutionRequest) -> ExecutionFuture<'_> {
        Box::pin(async {
            Err(ExecutorError::Failed {
                code: "subagent_runtime_required".into(),
                message: "list_agents requires the Zeus durable Session runtime".into(),
                retryable: false,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::{SessionFork, SessionStatus, SessionSummary};

    fn fork(index: usize) -> SessionForkSummary {
        SessionForkSummary {
            session: SessionSummary {
                id: format!("session-child-{index:02}"),
                title: format!("Child {index:02}"),
                status: SessionStatus::Ready,
                created_at: "2026-08-28T00:00:00.000Z".into(),
                updated_at: "2026-08-28T00:00:00.000Z".into(),
                sequence: 1,
                active_turn_id: None,
            },
            fork: SessionFork {
                parent_session_id: "session-parent".into(),
                parent_sequence: 1,
                inherited_turns: 0,
                created_at: "2026-08-28T00:00:00.000Z".into(),
            },
        }
    }

    #[test]
    fn request_is_strict_defaulted_and_bounded() {
        let defaulted = prepare_list_agents(&serde_json::json!({})).unwrap();
        assert_eq!(defaulted.limit(), LIST_AGENTS_DEFAULT_LIMIT);
        assert_eq!(defaulted.cursor(), None);
        let explicit = prepare_list_agents(&serde_json::json!({
            "cursor": "opaque-page",
            "limit": LIST_AGENTS_MAX_LIMIT,
        }))
        .unwrap();
        assert_eq!(explicit.cursor(), Some("opaque-page"));
        assert_eq!(explicit.limit(), LIST_AGENTS_MAX_LIMIT);
        for invalid in [
            serde_json::json!({"limit": 0}),
            serde_json::json!({"limit": LIST_AGENTS_MAX_LIMIT + 1}),
            serde_json::json!({"cursor": " bad"}),
            serde_json::json!({"unknown": true}),
        ] {
            assert!(prepare_list_agents(&invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn descriptor_is_read_only_closed_and_registry_stable() {
        let descriptor = list_agents_descriptor();
        assert_eq!(descriptor.name, LIST_AGENTS_TOOL_NAME);
        assert_eq!(descriptor.version, LIST_AGENTS_TOOL_VERSION);
        assert_eq!(descriptor.effect, ToolEffect::ReadOnly);
        let schema = descriptor.input_schema.provider_json_schema().unwrap();
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["properties"]["cursor"]["maxLength"], 4096);
        let mut registry = ToolRegistry::new();
        register_subagent_tools(&mut registry).unwrap();
        assert!(registry.descriptor(LIST_AGENTS_TOOL_NAME).is_some());
    }

    #[test]
    fn result_is_typed_page_bounded_and_output_safe() {
        let result = ListAgentsResult::new(vec![fork(0)], Some("opaque-next".into())).unwrap();
        assert_eq!(result.agents[0].session.id, "session-child-00");
        assert!(serde_json::to_vec(&result).unwrap().len() <= TOOL_OUTPUT_MAX_SERIALIZED_BYTES);
        assert!(
            ListAgentsResult::new((0..=LIST_AGENTS_MAX_LIMIT).map(fork).collect(), None).is_err()
        );
        assert!(ListAgentsResult::new(Vec::new(), Some("cursor".into())).is_err());
    }
}
