use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Roles understood by a model adapter.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelRole {
    System,
    User,
    Assistant,
    Tool,
}

/// A tool invocation emitted by the model.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ToolCall {
    pub call_id: String,
    pub capability: String,
    pub arguments: Value,
}

impl ToolCall {
    #[must_use]
    pub fn new(
        call_id: impl Into<String>,
        capability: impl Into<String>,
        arguments: Value,
    ) -> Self {
        Self {
            call_id: call_id.into(),
            capability: capability.into(),
            arguments,
        }
    }
}

/// A result which closes one model tool invocation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ToolResult {
    pub call_id: String,
    pub content: Value,
    pub synthetic: bool,
}

impl ToolResult {
    #[must_use]
    pub fn new(call_id: impl Into<String>, content: Value) -> Self {
        Self {
            call_id: call_id.into(),
            content,
            synthetic: false,
        }
    }

    #[must_use]
    pub fn canceled(call_id: impl Into<String>) -> Self {
        Self {
            call_id: call_id.into(),
            content: json!({ "code": CANCELED_TOOL_RESULT_CODE }),
            synthetic: true,
        }
    }
}

pub const CANCELED_TOOL_RESULT_CODE: &str = "run_canceled";

/// A model-visible message reconstructed from the append-only Session log.
///
/// `Steering` is represented separately in the domain so callers can preserve
/// its origin while model adapters can map it to the user role through
/// [`ModelMessage::role`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ModelMessage {
    System {
        content: String,
    },
    User {
        content: String,
    },
    Assistant {
        content: Option<String>,
        tool_calls: Vec<ToolCall>,
    },
    Tool {
        call_id: String,
        content: Value,
        synthetic: bool,
    },
    Steering {
        content: String,
    },
}

impl ModelMessage {
    #[must_use]
    pub fn system(content: impl Into<String>) -> Self {
        Self::System {
            content: content.into(),
        }
    }

    #[must_use]
    pub fn user(content: impl Into<String>) -> Self {
        Self::User {
            content: content.into(),
        }
    }

    #[must_use]
    pub fn assistant(content: impl Into<String>) -> Self {
        Self::Assistant {
            content: Some(content.into()),
            tool_calls: Vec::new(),
        }
    }

    #[must_use]
    pub fn assistant_with_tool_calls(tool_calls: Vec<ToolCall>) -> Self {
        Self::Assistant {
            content: None,
            tool_calls,
        }
    }

    #[must_use]
    pub fn tool(result: ToolResult) -> Self {
        Self::Tool {
            call_id: result.call_id,
            content: result.content,
            synthetic: result.synthetic,
        }
    }

    #[must_use]
    pub fn steering(content: impl Into<String>) -> Self {
        Self::Steering {
            content: content.into(),
        }
    }

    #[must_use]
    pub const fn role(&self) -> ModelRole {
        match self {
            Self::System { .. } => ModelRole::System,
            Self::User { .. } | Self::Steering { .. } => ModelRole::User,
            Self::Assistant { .. } => ModelRole::Assistant,
            Self::Tool { .. } => ModelRole::Tool,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{CANCELED_TOOL_RESULT_CODE, ModelMessage, ModelRole, ToolResult};

    #[test]
    fn canceled_tool_result_is_explicitly_synthetic() {
        let result = ToolResult::canceled("call-1");

        assert!(result.synthetic);
        assert_eq!(result.content, json!({ "code": CANCELED_TOOL_RESULT_CODE }));
        assert_eq!(ModelMessage::tool(result).role(), ModelRole::Tool);
    }
}
