//! Reply-provider boundary for Zeus Harness.
//!
//! Providers admit one bounded model-step transcript and return either final
//! text or one server-defined tool call. A provider failure is never converted
//! into a successful fallback reply: the caller must select
//! [`LocalFallbackProvider`] explicitly when it wants the non-model experience.

mod openai_compatible;

use std::{
    collections::HashSet,
    future::Future,
    io::{self, Write},
    pin::Pin,
};

use protocol::{SessionTurn, SessionTurnStatus};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use openai_compatible::{
    DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_REQUEST_TIMEOUT, OpenAiCompatibleProvider,
};

/// Maximum serialized size of a typed reply admitted to durable storage.
pub const REPLY_RESPONSE_MAX_SERIALIZED_BYTES: usize = 512 * 1024;
/// Maximum compact-JSON size of one immutable Agent provider request.
pub const AGENT_REQUEST_MAX_SERIALIZED_BYTES: usize = 512 * 1024;
/// Maximum number of ordered messages in one durable provider request.
pub const REPLY_REQUEST_MAX_MESSAGES: usize = 64;
/// Maximum number of complete historical user/assistant pairs in one request.
pub const REPLY_REQUEST_MAX_HISTORY_PAIRS: usize = (REPLY_REQUEST_MAX_MESSAGES - 1) / 2;
/// Maximum historical pairs admitted when a request can enter the Agent loop.
///
/// A prompt-bound request contains at most 56 initial messages (one system
/// message, 27 pairs, and the current user message), reserving eight message
/// slots for the four fixed tool-call/result pairs.
pub const AGENT_REQUEST_MAX_HISTORY_PAIRS: usize = 27;
/// Maximum aggregate transcript bytes admitted to one durable provider request.
///
/// Individual user, assistant, and tool-result messages remain capped at
/// 64 KiB. The larger aggregate admits two persisted maximum-size tool results
/// alongside bounded ordinary conversation context.
pub const REPLY_REQUEST_MAX_CONTENT_BYTES: usize = 256 * 1024;
/// Initial conversation bytes admitted before an Agent may append tool steps.
///
/// Together with four 16 KiB argument objects and the workflow's 128 KiB
/// aggregate known-result limit, this fits the complete 256 KiB transcript
/// envelope without relying on best-effort truncation after a tool executes.
pub const AGENT_REQUEST_INITIAL_CONTENT_MAX_BYTES: usize = 64 * 1024;
/// Maximum number of server-defined tools admitted to one provider request.
pub const REPLY_REQUEST_MAX_TOOLS: usize = 32;
/// Maximum aggregate serialized bytes for server-defined tool definitions.
pub const REPLY_REQUEST_MAX_TOOL_DEFINITION_BYTES: usize = 64 * 1024;
/// Maximum serialized JSON bytes in one tool call's arguments object.
pub const REPLY_TOOL_ARGUMENTS_MAX_BYTES: usize = 64 * 1024;
/// Maximum serialized JSON bytes in one Agent-loop tool call's arguments.
pub const AGENT_TOOL_ARGUMENTS_MAX_BYTES: usize = 16 * 1024;
/// Maximum UTF-8 bytes in one persisted tool result.
pub const REPLY_TOOL_RESULT_MAX_BYTES: usize = 64 * 1024;
/// Maximum UTF-8 bytes in one function name.
pub const REPLY_TOOL_NAME_MAX_BYTES: usize = 64;
/// Maximum UTF-8 bytes in one provider-issued tool call ID.
pub const REPLY_TOOL_CALL_ID_MAX_BYTES: usize = 128;
/// Maximum UTF-8 bytes in one tool description.
pub const REPLY_TOOL_DESCRIPTION_MAX_BYTES: usize = 4 * 1024;
/// Maximum UTF-8 byte length of a provider finish reason.
pub const FINISH_REASON_MAX_BYTES: usize = protocol::REPLY_FINISH_REASON_MAX_BYTES;

/// Boxed reply operation used by the object-safe provider interface.
pub type ReplyFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ReplyResponse, ProviderError>> + Send + 'a>>;

/// Role of one message admitted to a reply provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReplyRole {
    /// Instructions supplied by the application.
    System,
    /// Human-authored input.
    User,
    /// Prior model output included for conversational context.
    Assistant,
    /// Result returned for the immediately preceding assistant tool call.
    Tool,
}

/// One server-defined function available to a model step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyToolDefinition {
    /// Stable function name exposed to the provider.
    pub name: String,
    /// Optional bounded human-readable guidance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON Schema object for function arguments.
    pub parameters: serde_json::Value,
}

impl ReplyToolDefinition {
    /// Construct one server-defined function.
    pub fn new(name: impl Into<String>, parameters: serde_json::Value) -> Self {
        Self {
            name: name.into(),
            description: None,
            parameters,
        }
    }

    /// Attach bounded human-readable guidance.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
}

/// Exactly one function call emitted by an assistant model step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyToolCall {
    /// Provider-issued identifier bound to the subsequent tool result.
    pub id: String,
    /// Server-defined function name.
    pub name: String,
    /// Parsed JSON object passed to the function.
    pub arguments: serde_json::Value,
}

impl ReplyToolCall {
    /// Construct one typed tool call.
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        arguments: serde_json::Value,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            arguments,
        }
    }
}

/// One ordered message in a reply request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyMessage {
    /// Message role.
    pub role: ReplyRole,
    /// Plain text content sent to the selected provider.
    pub content: String,
    /// Function call emitted by an assistant message. Its text content must be
    /// empty and it must be followed immediately by a matching tool result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call: Option<ReplyToolCall>,
    /// Call ID bound to a tool-result message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

impl ReplyMessage {
    /// Construct a message with the supplied role and text.
    pub fn new(role: ReplyRole, content: impl Into<String>) -> Self {
        Self {
            role,
            content: content.into(),
            tool_call: None,
            tool_call_id: None,
        }
    }

    /// Construct an assistant message containing exactly one tool call.
    pub fn assistant_tool_call(call: ReplyToolCall) -> Self {
        Self {
            role: ReplyRole::Assistant,
            content: String::new(),
            tool_call: Some(call),
            tool_call_id: None,
        }
    }

    /// Construct the result for an immediately preceding assistant tool call.
    pub fn tool_result(call_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: ReplyRole::Tool,
            content: content.into(),
            tool_call: None,
            tool_call_id: Some(call_id.into()),
        }
    }
}

/// Complete ordered context for one provider reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyRequest {
    /// Messages in provider-visible order.
    pub messages: Vec<ReplyMessage>,
    /// Server-defined tools. The default preserves messages-only queued JSON.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ReplyToolDefinition>,
}

impl ReplyRequest {
    /// Construct a request from ordered messages.
    pub fn new(messages: impl IntoIterator<Item = ReplyMessage>) -> Self {
        Self {
            messages: messages.into_iter().collect(),
            tools: Vec::new(),
        }
    }

    /// Construct a request with a bounded server-defined tool set.
    pub fn with_tools(
        messages: impl IntoIterator<Item = ReplyMessage>,
        tools: impl IntoIterator<Item = ReplyToolDefinition>,
    ) -> Self {
        Self {
            messages: messages.into_iter().collect(),
            tools: tools.into_iter().collect(),
        }
    }

    /// Build a bounded conversational request from the latest durable turns.
    ///
    /// Only complete user/assistant pairs are eligible. The newest valid
    /// history that fits the aggregate byte and message envelopes is retained,
    /// then the new user message is appended. Legacy rows outside today's
    /// per-message envelope are skipped so an upgrade cannot strand a Session.
    pub fn from_session_history(
        turns: &[SessionTurn],
        user_message: impl Into<String>,
    ) -> Result<Self, ProviderError> {
        Self::from_session_history_with_limits(
            turns,
            user_message.into(),
            REPLY_REQUEST_MAX_HISTORY_PAIRS,
            REPLY_REQUEST_MAX_CONTENT_BYTES,
        )
    }

    /// Build the initial request for a durable Agent loop while reserving the
    /// complete fixed tool-step budget.
    pub fn from_session_history_for_agent(
        turns: &[SessionTurn],
        user_message: impl Into<String>,
    ) -> Result<Self, ProviderError> {
        let request = Self::from_session_history_with_limits(
            turns,
            user_message.into(),
            AGENT_REQUEST_MAX_HISTORY_PAIRS,
            AGENT_REQUEST_INITIAL_CONTENT_MAX_BYTES,
        )?;
        validate_initial_agent_reply_request(&request)?;
        Ok(request)
    }

    /// Build a prompt-bound initial Agent request while reserving the complete
    /// fixed tool-step budget. The system prompt is counted inside the same
    /// initial content envelope as conversation history.
    pub fn from_session_history_for_agent_with_system_prompt(
        turns: &[SessionTurn],
        user_message: impl Into<String>,
        system_prompt: impl Into<String>,
    ) -> Result<Self, ProviderError> {
        let system_prompt = system_prompt.into();
        protocol::validate_user_message(&system_prompt)
            .map_err(|_| ProviderError::InvalidRequest("invalid system prompt"))?;
        let conversation_budget = AGENT_REQUEST_INITIAL_CONTENT_MAX_BYTES
            .checked_sub(system_prompt.len())
            .ok_or(ProviderError::InvalidRequest(
                "system prompt exceeds the initial Agent content budget",
            ))?;
        let mut request = Self::from_session_history_with_limits(
            turns,
            user_message.into(),
            AGENT_REQUEST_MAX_HISTORY_PAIRS,
            conversation_budget,
        )?;
        request
            .messages
            .insert(0, ReplyMessage::new(ReplyRole::System, system_prompt));
        validate_initial_agent_reply_request(&request)?;
        Ok(request)
    }

    fn from_session_history_with_limits(
        turns: &[SessionTurn],
        user_message: String,
        max_history_pairs: usize,
        max_content_bytes: usize,
    ) -> Result<Self, ProviderError> {
        protocol::validate_user_message(&user_message)
            .map_err(|_| ProviderError::InvalidRequest("invalid user message"))?;
        if user_message.len() > max_content_bytes {
            return Err(ProviderError::InvalidRequest(
                "conversation context is too large",
            ));
        }

        let mut retained = Vec::new();
        let mut content_bytes = user_message.len();
        for turn in turns.iter().rev() {
            if retained.len() >= max_history_pairs {
                break;
            }
            if turn.status != SessionTurnStatus::Flushed {
                continue;
            }
            let Some(assistant_message) = turn.assistant_message.as_ref() else {
                continue;
            };
            if protocol::validate_user_message(&turn.user_message).is_err()
                || protocol::validate_assistant_message(assistant_message).is_err()
            {
                continue;
            }
            let pair_bytes = turn
                .user_message
                .len()
                .checked_add(assistant_message.len())
                .ok_or(ProviderError::InvalidRequest(
                    "conversation context is too large",
                ))?;
            let Some(next_bytes) = content_bytes.checked_add(pair_bytes) else {
                return Err(ProviderError::InvalidRequest(
                    "conversation context is too large",
                ));
            };
            if next_bytes > max_content_bytes {
                break;
            }
            content_bytes = next_bytes;
            retained.push((turn.user_message.clone(), assistant_message.clone()));
        }

        retained.reverse();
        let mut messages = Vec::with_capacity(retained.len() * 2 + 1);
        for (user, assistant) in retained {
            messages.push(ReplyMessage::new(ReplyRole::User, user));
            messages.push(ReplyMessage::new(ReplyRole::Assistant, assistant));
        }
        messages.push(ReplyMessage::new(ReplyRole::User, user_message));
        let request = Self {
            messages,
            tools: Vec::new(),
        };
        validate_reply_request(&request)?;
        Ok(request)
    }
}

/// Provenance class attached to every successful reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplyKind {
    /// Content returned by a configured model endpoint.
    Model,
    /// Static local product copy; it is not model-generated content.
    NonModelFallback,
}

/// Stable provider facts safe to expose to the product surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderMetadata {
    /// Stable, secret-free implementation and configuration identifier.
    ///
    /// Remote providers include a digest of execution-relevant configuration
    /// so durable queued work cannot silently move to a different endpoint.
    pub provider_id: String,
    /// Configured model identifier, absent for a non-model provider.
    pub model: Option<String>,
    /// Whether replies are model-generated or local fallback copy.
    pub reply_kind: ReplyKind,
}

impl ProviderMetadata {
    /// Return whether this metadata identifies a model-generated reply.
    pub fn is_model_reply(&self) -> bool {
        self.reply_kind == ReplyKind::Model
    }
}

/// Explicit output of one provider model step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ReplyOutput {
    /// Terminal assistant text.
    Final { content: String },
    /// Exactly one server-defined function call.
    ToolCall { call: ReplyToolCall },
}

impl ReplyOutput {
    /// Return final text, or `None` for a tool call.
    pub fn final_text(&self) -> Option<&str> {
        match self {
            Self::Final { content } => Some(content),
            Self::ToolCall { .. } => None,
        }
    }

    /// Return the tool call, or `None` for final text.
    pub fn tool_call(&self) -> Option<&ReplyToolCall> {
        match self {
            Self::Final { .. } => None,
            Self::ToolCall { call } => Some(call),
        }
    }
}

/// One accepted provider reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyResponse {
    /// Unambiguous final-text or single-tool-call output.
    pub output: ReplyOutput,
    /// Provider-specific terminal reason when one was supplied.
    pub finish_reason: Option<String>,
    /// Provenance repeated on the response so callers cannot lose it by
    /// looking up a different provider after an asynchronous operation.
    pub provider: ProviderMetadata,
}

/// Controlled failures at the reply-provider boundary.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProviderError {
    /// Provider construction rejected an unsafe or incomplete value.
    #[error("invalid provider configuration: {0}")]
    InvalidConfiguration(&'static str),
    /// A request cannot be represented by the provider contract.
    #[error("invalid reply request: {0}")]
    InvalidRequest(&'static str),
    /// The complete request exceeded its deadline.
    #[error("provider request timed out")]
    Timeout,
    /// The HTTP operation failed without a trustworthy provider response.
    #[error("provider transport failed")]
    Transport,
    /// A non-success status was returned. The body is deliberately omitted
    /// because compatible gateways can include credentials or prompt data in
    /// diagnostics.
    #[error("provider returned HTTP status {status}")]
    HttpStatus { status: u16 },
    /// The response exceeded the configured byte budget.
    #[error("provider response exceeded the {limit_bytes}-byte limit")]
    ResponseTooLarge { limit_bytes: usize },
    /// A decoded reply exceeded the durable terminal envelope.
    #[error("provider reply exceeded the {limit_bytes}-byte terminal limit")]
    TerminalPayloadTooLarge { limit_bytes: usize },
    /// A successful HTTP response did not contain a usable text choice.
    #[error("provider returned an invalid response")]
    InvalidResponse,
}

/// Object-safe asynchronous source of assistant replies.
pub trait ReplyProvider: Send + Sync {
    /// Return stable, secret-free provider metadata.
    fn metadata(&self) -> &ProviderMetadata;

    /// Request one assistant reply.
    fn reply(&self, request: ReplyRequest) -> ReplyFuture<'_>;
}

/// Validate the complete provider-visible request and its aggregate envelope.
pub fn validate_reply_request(request: &ReplyRequest) -> Result<(), ProviderError> {
    if request.messages.is_empty() || request.messages.len() > REPLY_REQUEST_MAX_MESSAGES {
        return Err(ProviderError::InvalidRequest(
            "request must contain between 1 and 64 messages",
        ));
    }

    validate_reply_tools(&request.tools)?;
    let mut total_bytes = 0usize;
    let mut index = 0usize;
    if request.messages[0].role == ReplyRole::System {
        let message = &request.messages[0];
        require_plain_message(message, ReplyRole::System)?;
        require_user_content(&message.content)?;
        add_request_bytes(&mut total_bytes, message.content.len())?;
        index = 1;
    }
    if index == request.messages.len() {
        return Err(ProviderError::InvalidRequest(
            "request must contain a conversation after system instructions",
        ));
    }

    enum TranscriptState<'a> {
        ExpectUser,
        AfterUser,
        AfterAssistantFinal,
        AfterAssistantTool(&'a str),
        AfterTool,
    }

    let mut state = TranscriptState::ExpectUser;
    let mut call_ids = HashSet::new();
    for message in &request.messages[index..] {
        state = match (&state, message.role) {
            (TranscriptState::ExpectUser, ReplyRole::User)
            | (TranscriptState::AfterAssistantFinal, ReplyRole::User) => {
                require_plain_message(message, ReplyRole::User)?;
                require_user_content(&message.content)?;
                add_request_bytes(&mut total_bytes, message.content.len())?;
                TranscriptState::AfterUser
            }
            (TranscriptState::AfterUser, ReplyRole::Assistant)
            | (TranscriptState::AfterTool, ReplyRole::Assistant) => {
                if let Some(call) = &message.tool_call {
                    if !message.content.is_empty() || message.tool_call_id.is_some() {
                        return Err(ProviderError::InvalidRequest(
                            "assistant tool calls must not include text or a result ID",
                        ));
                    }
                    validate_tool_call(call, ProviderError::InvalidRequest("invalid tool call"))?;
                    if !request.tools.iter().any(|tool| tool.name == call.name) {
                        return Err(ProviderError::InvalidRequest(
                            "assistant tool call is not server-defined",
                        ));
                    }
                    if !call_ids.insert(call.id.as_str()) {
                        return Err(ProviderError::InvalidRequest(
                            "tool call IDs must be unique within a transcript",
                        ));
                    }
                    let argument_bytes =
                        bounded_json_len(&call.arguments, REPLY_TOOL_ARGUMENTS_MAX_BYTES).ok_or(
                            ProviderError::InvalidRequest("tool call arguments are too large"),
                        )?;
                    add_request_bytes(&mut total_bytes, argument_bytes)?;
                    TranscriptState::AfterAssistantTool(&call.id)
                } else {
                    if message.tool_call_id.is_some() {
                        return Err(ProviderError::InvalidRequest(
                            "assistant text must not include a tool result ID",
                        ));
                    }
                    require_assistant_content(&message.content)?;
                    add_request_bytes(&mut total_bytes, message.content.len())?;
                    TranscriptState::AfterAssistantFinal
                }
            }
            (TranscriptState::AfterAssistantTool(expected_id), ReplyRole::Tool) => {
                if message.tool_call.is_some()
                    || message.tool_call_id.as_deref() != Some(*expected_id)
                    || !valid_tool_result(&message.content)
                {
                    return Err(ProviderError::InvalidRequest(
                        "tool result must immediately match the preceding call",
                    ));
                }
                add_request_bytes(&mut total_bytes, message.content.len())?;
                TranscriptState::AfterTool
            }
            _ => {
                return Err(ProviderError::InvalidRequest(
                    "invalid model-step transcript sequence",
                ));
            }
        };
    }
    if !matches!(
        state,
        TranscriptState::AfterUser | TranscriptState::AfterTool
    ) {
        return Err(ProviderError::InvalidRequest(
            "request must end with a user message or tool result",
        ));
    }
    Ok(())
}

fn validate_reply_tools(tools: &[ReplyToolDefinition]) -> Result<(), ProviderError> {
    if tools.len() > REPLY_REQUEST_MAX_TOOLS {
        return Err(ProviderError::InvalidRequest(
            "request cannot contain more than 32 tools",
        ));
    }
    if bounded_json_len(tools, REPLY_REQUEST_MAX_TOOL_DEFINITION_BYTES).is_none() {
        return Err(ProviderError::InvalidRequest(
            "tool definitions are too large",
        ));
    }
    let mut names = HashSet::new();
    for tool in tools {
        if !valid_tool_name(&tool.name)
            || !tool.parameters.is_object()
            || tool
                .description
                .as_ref()
                .is_some_and(|description| description.len() > REPLY_TOOL_DESCRIPTION_MAX_BYTES)
            || !names.insert(tool.name.as_str())
        {
            return Err(ProviderError::InvalidRequest(
                "invalid or duplicate tool definition",
            ));
        }
    }
    Ok(())
}

fn require_plain_message(message: &ReplyMessage, role: ReplyRole) -> Result<(), ProviderError> {
    if message.role != role || message.tool_call.is_some() || message.tool_call_id.is_some() {
        return Err(ProviderError::InvalidRequest(
            "plain messages cannot contain tool fields",
        ));
    }
    Ok(())
}

fn require_user_content(content: &str) -> Result<(), ProviderError> {
    protocol::validate_user_message(content)
        .map_err(|_| ProviderError::InvalidRequest("invalid user or system content"))
}

fn require_assistant_content(content: &str) -> Result<(), ProviderError> {
    protocol::validate_assistant_message(content)
        .map_err(|_| ProviderError::InvalidRequest("invalid assistant content"))
}

fn valid_tool_result(content: &str) -> bool {
    !content.trim().is_empty() && content.len() <= REPLY_TOOL_RESULT_MAX_BYTES
}

fn add_request_bytes(total: &mut usize, added: usize) -> Result<(), ProviderError> {
    *total = total
        .checked_add(added)
        .ok_or(ProviderError::InvalidRequest(
            "request content is too large",
        ))?;
    if *total > REPLY_REQUEST_MAX_CONTENT_BYTES {
        return Err(ProviderError::InvalidRequest(
            "request content is too large",
        ));
    }
    Ok(())
}

fn valid_tool_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= REPLY_TOOL_NAME_MAX_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_tool_call_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= REPLY_TOOL_CALL_ID_MAX_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn validate_tool_call(call: &ReplyToolCall, error: ProviderError) -> Result<(), ProviderError> {
    if !valid_tool_call_id(&call.id)
        || !valid_tool_name(&call.name)
        || !call.arguments.is_object()
        || bounded_json_len(&call.arguments, REPLY_TOOL_ARGUMENTS_MAX_BYTES).is_none()
    {
        return Err(error);
    }
    Ok(())
}

struct BoundedJsonWriter {
    written: usize,
    limit: usize,
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .written
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("serialized JSON exceeds its byte limit"))?;
        if next > self.limit {
            return Err(io::Error::other("serialized JSON exceeds its byte limit"));
        }
        self.written = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn bounded_json_len(value: &(impl Serialize + ?Sized), limit: usize) -> Option<usize> {
    let mut writer = BoundedJsonWriter { written: 0, limit };
    serde_json::to_writer(&mut writer, value).ok()?;
    Some(writer.written)
}

/// Validates stable provider metadata before it can be copied into a queued
/// job or durable provenance record.
pub fn validate_provider_metadata(metadata: &ProviderMetadata) -> Result<(), ProviderError> {
    protocol::validate_reply_provider_id(&metadata.provider_id).map_err(|_| {
        ProviderError::InvalidConfiguration("provider ID exceeds the durable resource envelope")
    })?;
    match (&metadata.reply_kind, &metadata.model) {
        (ReplyKind::Model, Some(model)) => {
            protocol::validate_reply_model_id(model).map_err(|_| {
                ProviderError::InvalidConfiguration(
                    "model identifier exceeds the durable resource envelope",
                )
            })?;
        }
        (ReplyKind::Model, None) => {
            return Err(ProviderError::InvalidConfiguration(
                "model providers must declare a model identifier",
            ));
        }
        (ReplyKind::NonModelFallback, None) => {}
        (ReplyKind::NonModelFallback, Some(_)) => {
            return Err(ProviderError::InvalidConfiguration(
                "non-model providers must not declare a model identifier",
            ));
        }
    }
    Ok(())
}

/// Validates a provider result before callers serialize or persist it.
///
/// The content check runs before JSON serialization so an untrusted custom
/// provider cannot cause another allocation proportional to an oversized
/// reply.
pub fn validate_reply_response(response: &ReplyResponse) -> Result<(), ProviderError> {
    match &response.output {
        ReplyOutput::Final { content } => match protocol::validate_assistant_message(content) {
            Ok(()) => {}
            Err(protocol::ResourceEnvelopeError::TooLong { .. }) => {
                return Err(ProviderError::TerminalPayloadTooLarge {
                    limit_bytes: protocol::ASSISTANT_MESSAGE_MAX_BYTES,
                });
            }
            Err(_) => return Err(ProviderError::InvalidResponse),
        },
        ReplyOutput::ToolCall { call } => {
            validate_tool_call(call, ProviderError::InvalidResponse)?;
        }
    }
    if let Some(finish_reason) = &response.finish_reason
        && let Err(error) = protocol::validate_reply_finish_reason(finish_reason)
    {
        return Err(
            if matches!(error, protocol::ResourceEnvelopeError::TooLong { .. }) {
                ProviderError::TerminalPayloadTooLarge {
                    limit_bytes: FINISH_REASON_MAX_BYTES,
                }
            } else {
                ProviderError::InvalidResponse
            },
        );
    }
    if validate_provider_metadata(&response.provider).is_err() {
        return Err(ProviderError::InvalidResponse);
    }
    let serialized = serde_json::to_vec(response).map_err(|_| ProviderError::InvalidResponse)?;
    if serialized.len() > REPLY_RESPONSE_MAX_SERIALIZED_BYTES {
        return Err(ProviderError::TerminalPayloadTooLarge {
            limit_bytes: REPLY_RESPONSE_MAX_SERIALIZED_BYTES,
        });
    }
    Ok(())
}

/// Validate a provider result against the server-defined tools in its request.
pub fn validate_reply_response_for_request(
    request: &ReplyRequest,
    response: &ReplyResponse,
) -> Result<(), ProviderError> {
    validate_reply_response(response)?;
    if let ReplyOutput::ToolCall { call } = &response.output
        && !request.tools.iter().any(|tool| tool.name == call.name)
    {
        return Err(ProviderError::InvalidResponse);
    }
    Ok(())
}

/// Validate a durable Agent request, including the stricter per-step argument
/// budget reserved by [`ReplyRequest::from_session_history_for_agent`].
pub fn validate_agent_reply_request(request: &ReplyRequest) -> Result<(), ProviderError> {
    validate_reply_request(request)?;
    for message in &request.messages {
        if let Some(call) = &message.tool_call
            && bounded_json_len(&call.arguments, AGENT_TOOL_ARGUMENTS_MAX_BYTES).is_none()
        {
            return Err(ProviderError::InvalidRequest(
                "Agent tool call arguments are too large",
            ));
        }
    }
    Ok(())
}

/// Validate the first request in a durable Agent turn.
///
/// Initial requests may contain only a system prompt plus complete historical
/// user/assistant pairs and the current user message. The tighter message and
/// content envelopes reserve room for every fixed tool-call/result step.
pub fn validate_initial_agent_reply_request(request: &ReplyRequest) -> Result<(), ProviderError> {
    validate_agent_reply_request(request)?;
    let system_messages = usize::from(
        request
            .messages
            .first()
            .is_some_and(|message| message.role == ReplyRole::System),
    );
    let max_messages = AGENT_REQUEST_MAX_HISTORY_PAIRS * 2 + 1 + system_messages;
    if request.messages.len() > max_messages {
        return Err(ProviderError::InvalidRequest(
            "initial Agent request does not reserve the fixed tool-step message budget",
        ));
    }
    if request.messages.iter().any(|message| {
        message.role == ReplyRole::Tool
            || message.tool_call.is_some()
            || message.tool_call_id.is_some()
    }) {
        return Err(ProviderError::InvalidRequest(
            "initial Agent request cannot contain a tool transcript",
        ));
    }
    let content_bytes = request.messages.iter().try_fold(0usize, |total, message| {
        total.checked_add(message.content.len())
    });
    if !matches!(content_bytes, Some(bytes) if bytes <= AGENT_REQUEST_INITIAL_CONTENT_MAX_BYTES) {
        return Err(ProviderError::InvalidRequest(
            "initial Agent request exceeds the reserved content budget",
        ));
    }
    Ok(())
}

/// Validate one provider response against the durable Agent request and its
/// reserved per-step argument budget.
pub fn validate_agent_reply_response_for_request(
    request: &ReplyRequest,
    response: &ReplyResponse,
) -> Result<(), ProviderError> {
    validate_reply_response_for_request(request, response)?;
    if let ReplyOutput::ToolCall { call } = &response.output
        && bounded_json_len(&call.arguments, AGENT_TOOL_ARGUMENTS_MAX_BYTES).is_none()
    {
        return Err(ProviderError::InvalidResponse);
    }
    Ok(())
}

/// Convert one validated Agent request into its durable JSON value while
/// enforcing the storage envelope after JSON escaping.
///
/// Transcript content limits alone are insufficient here: control characters
/// and nested serialized tool results can expand when the complete request is
/// encoded. Callers must treat this error as an unavailable continuation, not
/// as an unknown tool outcome.
pub fn persisted_agent_reply_request(
    request: &ReplyRequest,
) -> Result<serde_json::Value, ProviderError> {
    validate_agent_reply_request(request)?;
    let value = serde_json::to_value(request)
        .map_err(|_| ProviderError::InvalidRequest("Agent request cannot be serialized"))?;
    if bounded_json_len(&value, AGENT_REQUEST_MAX_SERIALIZED_BYTES).is_none() {
        return Err(ProviderError::InvalidRequest(
            "serialized Agent request is too large",
        ));
    }
    Ok(value)
}

/// Explicit non-model experience used when no remote provider is configured.
///
/// Its output is static product copy. It never interpolates request content,
/// so secrets in a prompt cannot be reflected into the Session ledger or UI.
#[derive(Debug, Clone)]
pub struct LocalFallbackProvider {
    metadata: ProviderMetadata,
}

impl LocalFallbackProvider {
    /// Construct the local non-model provider.
    pub fn new() -> Self {
        Self {
            metadata: ProviderMetadata {
                provider_id: "local-fallback".to_owned(),
                model: None,
                reply_kind: ReplyKind::NonModelFallback,
            },
        }
    }
}

impl Default for LocalFallbackProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplyProvider for LocalFallbackProvider {
    fn metadata(&self) -> &ProviderMetadata {
        &self.metadata
    }

    fn reply(&self, request: ReplyRequest) -> ReplyFuture<'_> {
        let provider = self.metadata.clone();
        Box::pin(async move {
            validate_reply_request(&request)?;
            Ok(ReplyResponse {
                output: ReplyOutput::Final {
                    content: "Your message was saved, but no model provider is configured."
                        .to_owned(),
                },
                finish_reason: Some("local_fallback".to_owned()),
                provider,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn turn(
        ordinal: u64,
        status: SessionTurnStatus,
        user: impl Into<String>,
        assistant: Option<String>,
    ) -> SessionTurn {
        SessionTurn {
            id: format!("turn-{ordinal}"),
            session_id: "session-context".into(),
            ordinal,
            status,
            user_message: user.into(),
            assistant_message: assistant,
            started_at: "2026-08-27T00:00:00.000Z".into(),
            completed_at: Some("2026-08-27T00:00:01.000Z".into()),
        }
    }

    fn response(content: String) -> ReplyResponse {
        ReplyResponse {
            output: ReplyOutput::Final { content },
            finish_reason: Some("stop".into()),
            provider: ProviderMetadata {
                provider_id: "test-provider".into(),
                model: Some("test-model".into()),
                reply_kind: ReplyKind::Model,
            },
        }
    }

    #[test]
    fn typed_reply_content_uses_utf8_byte_limits() {
        let exact = response("🙂".repeat(protocol::ASSISTANT_MESSAGE_MAX_BYTES / 4));
        assert!(validate_reply_response(&exact).is_ok());

        let oversized = response("🙂".repeat(protocol::ASSISTANT_MESSAGE_MAX_BYTES / 4 + 1));
        assert_eq!(
            validate_reply_response(&oversized),
            Err(ProviderError::TerminalPayloadTooLarge {
                limit_bytes: protocol::ASSISTANT_MESSAGE_MAX_BYTES,
            })
        );
    }

    #[test]
    fn typed_reply_metadata_and_finish_reason_are_bounded() {
        let mut exact = response("ok".into());
        exact.finish_reason = Some("f".repeat(FINISH_REASON_MAX_BYTES));
        exact.provider.model = Some("m".repeat(protocol::REPLY_MODEL_ID_MAX_BYTES));
        assert!(validate_reply_response(&exact).is_ok());

        let mut oversized_finish = exact.clone();
        oversized_finish.finish_reason = Some("f".repeat(FINISH_REASON_MAX_BYTES + 1));
        assert_eq!(
            validate_reply_response(&oversized_finish),
            Err(ProviderError::TerminalPayloadTooLarge {
                limit_bytes: FINISH_REASON_MAX_BYTES,
            })
        );

        let mut invalid_metadata = exact;
        invalid_metadata.provider.provider_id =
            "p".repeat(protocol::REPLY_PROVIDER_ID_MAX_BYTES + 1);
        assert_eq!(
            validate_reply_response(&invalid_metadata),
            Err(ProviderError::InvalidResponse)
        );
    }

    #[test]
    fn escape_heavy_valid_reply_fits_the_typed_serialized_budget() {
        let response = response("\0\n\\\"".repeat(protocol::ASSISTANT_MESSAGE_MAX_BYTES / 4));
        assert!(validate_reply_response(&response).is_ok());
        assert!(
            serde_json::to_vec(&response).unwrap().len() <= REPLY_RESPONSE_MAX_SERIALIZED_BYTES
        );
    }

    #[test]
    fn session_history_becomes_chronological_provider_context() {
        let turns = vec![
            turn(1, SessionTurnStatus::Flushed, "first", Some("one".into())),
            turn(2, SessionTurnStatus::Interrupted, "failed", None),
            turn(3, SessionTurnStatus::Flushed, "second", Some("two".into())),
        ];

        let request = ReplyRequest::from_session_history(&turns, "third").unwrap();
        assert_eq!(
            request.messages,
            vec![
                ReplyMessage::new(ReplyRole::User, "first"),
                ReplyMessage::new(ReplyRole::Assistant, "one"),
                ReplyMessage::new(ReplyRole::User, "second"),
                ReplyMessage::new(ReplyRole::Assistant, "two"),
                ReplyMessage::new(ReplyRole::User, "third"),
            ]
        );
    }

    #[test]
    fn session_history_is_bounded_to_the_latest_complete_pairs() {
        let turns = (0..40)
            .map(|ordinal| {
                turn(
                    ordinal,
                    SessionTurnStatus::Flushed,
                    format!("user-{ordinal}"),
                    Some(format!("assistant-{ordinal}")),
                )
            })
            .collect::<Vec<_>>();

        let request = ReplyRequest::from_session_history(&turns, "current").unwrap();
        assert_eq!(request.messages.len(), REPLY_REQUEST_MAX_MESSAGES - 1);
        assert_eq!(request.messages[0].content, "user-9");
        assert_eq!(request.messages.last().unwrap().content, "current");
    }

    #[test]
    fn agent_history_reserves_all_four_tool_step_pairs() {
        let turns = (0..40)
            .map(|ordinal| {
                turn(
                    ordinal,
                    SessionTurnStatus::Flushed,
                    format!("user-{ordinal}"),
                    Some(format!("assistant-{ordinal}")),
                )
            })
            .collect::<Vec<_>>();

        let mut request = ReplyRequest::from_session_history_for_agent_with_system_prompt(
            &turns,
            "current",
            "You are Zeus.",
        )
        .unwrap();
        request.tools = vec![lookup_tool()];
        assert_eq!(request.messages.len(), 56);
        assert_eq!(request.messages[0].role, ReplyRole::System);
        assert_eq!(request.messages[0].content, "You are Zeus.");
        assert_eq!(request.messages[1].content, "user-13");

        for index in 0..4 {
            let call_id = format!("call_{index}");
            request
                .messages
                .push(ReplyMessage::assistant_tool_call(ReplyToolCall::new(
                    &call_id,
                    "lookup_order",
                    serde_json::json!({ "step": index }),
                )));
            request
                .messages
                .push(ReplyMessage::tool_result(call_id, "known result"));
        }

        assert_eq!(request.messages.len(), 64);
        assert!(validate_agent_reply_request(&request).is_ok());
    }

    #[test]
    fn agent_system_prompt_shares_the_reserved_initial_content_budget() {
        let turns = vec![turn(
            1,
            SessionTurnStatus::Flushed,
            "u".repeat(20 * 1024),
            Some("a".repeat(20 * 1024)),
        )];
        let system_prompt = "system";
        let request = ReplyRequest::from_session_history_for_agent_with_system_prompt(
            &turns,
            "c".repeat(AGENT_REQUEST_INITIAL_CONTENT_MAX_BYTES - system_prompt.len()),
            system_prompt,
        )
        .unwrap();
        assert_eq!(request.messages.len(), 2);
        assert_eq!(request.messages[0].role, ReplyRole::System);
        assert_eq!(request.messages[0].content, system_prompt);
        assert_eq!(
            request.messages[1].content.len(),
            AGENT_REQUEST_INITIAL_CONTENT_MAX_BYTES - system_prompt.len()
        );
    }

    #[test]
    fn initial_agent_validator_rejects_full_loop_envelopes() {
        let mut too_many_messages = vec![ReplyMessage::new(ReplyRole::System, "system")];
        for index in 0..28 {
            too_many_messages.push(ReplyMessage::new(ReplyRole::User, format!("user-{index}")));
            too_many_messages.push(ReplyMessage::new(
                ReplyRole::Assistant,
                format!("assistant-{index}"),
            ));
        }
        too_many_messages.push(ReplyMessage::new(ReplyRole::User, "current"));
        let too_many = ReplyRequest::new(too_many_messages);
        assert_eq!(too_many.messages.len(), 58);
        assert!(validate_agent_reply_request(&too_many).is_ok());
        assert!(validate_initial_agent_reply_request(&too_many).is_err());

        let too_much_content = ReplyRequest::new([
            ReplyMessage::new(ReplyRole::System, "system"),
            ReplyMessage::new(ReplyRole::User, "u".repeat(30 * 1024)),
            ReplyMessage::new(ReplyRole::Assistant, "a".repeat(30 * 1024)),
            ReplyMessage::new(ReplyRole::User, "u".repeat(10 * 1024)),
        ]);
        assert!(validate_agent_reply_request(&too_much_content).is_ok());
        assert!(validate_initial_agent_reply_request(&too_much_content).is_err());

        let tool = lookup_tool();
        let tool_transcript = ReplyRequest::with_tools(
            [
                ReplyMessage::new(ReplyRole::User, "lookup"),
                ReplyMessage::assistant_tool_call(ReplyToolCall::new(
                    "call_initial",
                    tool.name.clone(),
                    serde_json::json!({"query": "zeus"}),
                )),
                ReplyMessage::tool_result("call_initial", "known result"),
            ],
            [tool],
        );
        assert!(validate_agent_reply_request(&tool_transcript).is_ok());
        assert!(validate_initial_agent_reply_request(&tool_transcript).is_err());
    }

    #[test]
    fn agent_history_reserves_the_content_budget_before_tool_execution() {
        let turns = vec![turn(
            1,
            SessionTurnStatus::Flushed,
            "u".repeat(20 * 1024),
            Some("a".repeat(20 * 1024)),
        )];

        let request = ReplyRequest::from_session_history_for_agent(
            &turns,
            "c".repeat(AGENT_REQUEST_INITIAL_CONTENT_MAX_BYTES - 20 * 1024),
        )
        .unwrap();
        assert_eq!(request.messages.len(), 1);
        assert_eq!(
            request.messages[0].content.len(),
            AGENT_REQUEST_INITIAL_CONTENT_MAX_BYTES - 20 * 1024
        );
    }

    #[test]
    fn legacy_oversized_history_is_skipped_without_stranding_a_new_turn() {
        let turns = vec![
            turn(1, SessionTurnStatus::Flushed, "kept", Some("answer".into())),
            turn(
                2,
                SessionTurnStatus::Flushed,
                "x".repeat(protocol::USER_MESSAGE_MAX_BYTES + 1),
                Some("legacy".into()),
            ),
        ];

        let request = ReplyRequest::from_session_history(&turns, "continue").unwrap();
        assert_eq!(
            request.messages,
            vec![
                ReplyMessage::new(ReplyRole::User, "kept"),
                ReplyMessage::new(ReplyRole::Assistant, "answer"),
                ReplyMessage::new(ReplyRole::User, "continue"),
            ]
        );
    }

    #[test]
    fn provider_requests_reject_non_conversational_role_shapes() {
        let adjacent_users = ReplyRequest::new([
            ReplyMessage::new(ReplyRole::User, "one"),
            ReplyMessage::new(ReplyRole::User, "two"),
        ]);
        assert!(validate_reply_request(&adjacent_users).is_err());

        let assistant_last = ReplyRequest::new([
            ReplyMessage::new(ReplyRole::System, "Be concise"),
            ReplyMessage::new(ReplyRole::User, "question"),
            ReplyMessage::new(ReplyRole::Assistant, "answer"),
        ]);
        assert!(validate_reply_request(&assistant_last).is_err());

        let valid = ReplyRequest::new([
            ReplyMessage::new(ReplyRole::System, "Be concise"),
            ReplyMessage::new(ReplyRole::User, "question"),
        ]);
        assert!(validate_reply_request(&valid).is_ok());
    }

    fn lookup_tool() -> ReplyToolDefinition {
        ReplyToolDefinition::new(
            "lookup_order",
            serde_json::json!({
                "type": "object",
                "properties": { "order_id": { "type": "string" } },
                "required": ["order_id"],
                "additionalProperties": false,
            }),
        )
        .with_description("Look up one order")
    }

    fn tool_result_chain(result_count: usize, result_bytes: usize) -> ReplyRequest {
        let mut messages = vec![ReplyMessage::new(ReplyRole::User, "start the workflow")];
        for index in 0..result_count {
            let call_id = format!("call_{index}");
            messages.push(ReplyMessage::assistant_tool_call(ReplyToolCall::new(
                &call_id,
                "lookup_order",
                serde_json::json!({ "step": index }),
            )));
            messages.push(ReplyMessage::tool_result(call_id, "x".repeat(result_bytes)));
        }
        ReplyRequest::with_tools(messages, [lookup_tool()])
    }

    #[test]
    fn messages_only_queued_json_defaults_to_no_tools() {
        let request: ReplyRequest = serde_json::from_value(serde_json::json!({
            "messages": [{ "role": "user", "content": "legacy request" }]
        }))
        .unwrap();

        assert!(request.tools.is_empty());
        assert!(validate_reply_request(&request).is_ok());
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            serde_json::json!({
                "messages": [{ "role": "user", "content": "legacy request" }]
            })
        );
    }

    #[test]
    fn tool_transcript_requires_immediate_matching_result() {
        let call = ReplyToolCall::new(
            "call_123",
            "lookup_order",
            serde_json::json!({ "order_id": "A-42" }),
        );
        let valid = ReplyRequest::with_tools(
            [
                ReplyMessage::new(ReplyRole::User, "Find the order"),
                ReplyMessage::assistant_tool_call(call.clone()),
                ReplyMessage::tool_result("call_123", r#"{"status":"shipped"}"#),
            ],
            [lookup_tool()],
        );
        assert!(validate_reply_request(&valid).is_ok());

        let mismatched = ReplyRequest::with_tools(
            [
                ReplyMessage::new(ReplyRole::User, "Find the order"),
                ReplyMessage::assistant_tool_call(call.clone()),
                ReplyMessage::tool_result("call_other", "not bound"),
            ],
            [lookup_tool()],
        );
        assert!(validate_reply_request(&mismatched).is_err());

        let mixed = ReplyRequest::with_tools(
            [
                ReplyMessage::new(ReplyRole::User, "Find the order"),
                {
                    let mut message = ReplyMessage::assistant_tool_call(call);
                    message.content = "I will call a tool".into();
                    message
                },
                ReplyMessage::tool_result("call_123", "result"),
            ],
            [lookup_tool()],
        );
        assert!(validate_reply_request(&mixed).is_err());
    }

    #[test]
    fn tools_and_transcript_share_strict_resource_envelopes() {
        let tools = (0..REPLY_REQUEST_MAX_TOOLS)
            .map(|index| {
                ReplyToolDefinition::new(
                    format!("tool_{index}"),
                    serde_json::json!({ "type": "object" }),
                )
            })
            .collect::<Vec<_>>();
        let exact_count = ReplyRequest::with_tools(
            [ReplyMessage::new(ReplyRole::User, "use a tool")],
            tools.clone(),
        );
        assert!(validate_reply_request(&exact_count).is_ok());

        let mut too_many = exact_count;
        too_many.tools.push(ReplyToolDefinition::new(
            "tool_overflow",
            serde_json::json!({ "type": "object" }),
        ));
        assert!(validate_reply_request(&too_many).is_err());

        let oversized_arguments = ReplyRequest::with_tools(
            [
                ReplyMessage::new(ReplyRole::User, "use a tool"),
                ReplyMessage::assistant_tool_call(ReplyToolCall::new(
                    "call_big",
                    "tool_0",
                    serde_json::json!({ "blob": "x".repeat(REPLY_TOOL_ARGUMENTS_MAX_BYTES) }),
                )),
                ReplyMessage::tool_result("call_big", "result"),
            ],
            tools,
        );
        assert!(validate_reply_request(&oversized_arguments).is_err());
    }

    #[test]
    fn transcript_aggregate_admits_two_full_tool_results_but_keeps_per_item_limits() {
        let mut two_results = tool_result_chain(2, REPLY_TOOL_RESULT_MAX_BYTES);
        two_results.messages.push(ReplyMessage::new(
            ReplyRole::Assistant,
            "Both lookups completed",
        ));
        two_results.messages.push(ReplyMessage::new(
            ReplyRole::User,
            "Continue with the ordinary conversation",
        ));
        assert!(validate_reply_request(&two_results).is_ok());

        let oversized_result = tool_result_chain(1, REPLY_TOOL_RESULT_MAX_BYTES + 1);
        assert!(validate_reply_request(&oversized_result).is_err());

        let aggregate_overflow = tool_result_chain(4, REPLY_TOOL_RESULT_MAX_BYTES);
        assert!(validate_reply_request(&aggregate_overflow).is_err());
    }

    #[test]
    fn transcript_message_count_remains_capped_at_64() {
        let mut messages = vec![ReplyMessage::new(ReplyRole::System, "Be concise")];
        for index in 0..31 {
            messages.push(ReplyMessage::new(ReplyRole::User, format!("user-{index}")));
            messages.push(ReplyMessage::new(
                ReplyRole::Assistant,
                format!("assistant-{index}"),
            ));
        }
        messages.push(ReplyMessage::new(ReplyRole::User, "current"));
        assert_eq!(messages.len(), REPLY_REQUEST_MAX_MESSAGES);
        assert!(validate_reply_request(&ReplyRequest::new(messages.clone())).is_ok());

        messages.push(ReplyMessage::new(ReplyRole::Assistant, "overflow"));
        assert!(validate_reply_request(&ReplyRequest::new(messages)).is_err());
    }

    #[test]
    fn typed_tool_call_response_rejects_invalid_fields_and_arguments() {
        let mut response = ReplyResponse {
            output: ReplyOutput::ToolCall {
                call: ReplyToolCall::new(
                    "call_123",
                    "lookup_order",
                    serde_json::json!({ "order_id": "A-42" }),
                ),
            },
            finish_reason: Some("tool_calls".into()),
            provider: ProviderMetadata {
                provider_id: "test-provider".into(),
                model: Some("test-model".into()),
                reply_kind: ReplyKind::Model,
            },
        };
        assert!(validate_reply_response(&response).is_ok());

        let mut invalid = response.clone();
        let ReplyOutput::ToolCall { call } = &mut invalid.output else {
            unreachable!()
        };
        call.name = "bad tool name".into();
        assert_eq!(
            validate_reply_response(&invalid),
            Err(ProviderError::InvalidResponse)
        );
        let mut invalid = response.clone();
        let ReplyOutput::ToolCall { call } = &mut invalid.output else {
            unreachable!()
        };
        call.id.clear();
        assert_eq!(
            validate_reply_response(&invalid),
            Err(ProviderError::InvalidResponse)
        );
        let mut invalid = response.clone();
        let ReplyOutput::ToolCall { call } = &mut invalid.output else {
            unreachable!()
        };
        call.arguments = serde_json::json!(["not", "an", "object"]);
        assert_eq!(
            validate_reply_response(&invalid),
            Err(ProviderError::InvalidResponse)
        );
        let ReplyOutput::ToolCall { call } = &mut response.output else {
            unreachable!()
        };
        call.arguments = serde_json::json!({ "blob": "x".repeat(REPLY_TOOL_ARGUMENTS_MAX_BYTES) });
        assert_eq!(
            validate_reply_response(&response),
            Err(ProviderError::InvalidResponse)
        );
    }

    #[test]
    fn agent_response_uses_the_reserved_tool_argument_budget() {
        let request = ReplyRequest::with_tools(
            [ReplyMessage::new(ReplyRole::User, "Run the tool")],
            [lookup_tool()],
        );
        let response = ReplyResponse {
            output: ReplyOutput::ToolCall {
                call: ReplyToolCall::new(
                    "call_large",
                    "lookup_order",
                    serde_json::json!({
                        "order_id": "x".repeat(AGENT_TOOL_ARGUMENTS_MAX_BYTES)
                    }),
                ),
            },
            finish_reason: Some("tool_calls".into()),
            provider: ProviderMetadata {
                provider_id: "test-provider".into(),
                model: Some("test-model".into()),
                reply_kind: ReplyKind::Model,
            },
        };

        assert!(validate_reply_response_for_request(&request, &response).is_ok());
        assert_eq!(
            validate_agent_reply_response_for_request(&request, &response),
            Err(ProviderError::InvalidResponse)
        );
    }

    #[test]
    fn persisted_agent_request_rechecks_json_escape_expansion() {
        let escaped_result = serde_json::to_string(&"\0".repeat(10_920)).unwrap();
        assert!(escaped_result.len() <= REPLY_TOOL_RESULT_MAX_BYTES);
        let request = ReplyRequest::with_tools(
            [
                ReplyMessage::new(
                    ReplyRole::User,
                    "\0".repeat(AGENT_REQUEST_INITIAL_CONTENT_MAX_BYTES),
                ),
                ReplyMessage::assistant_tool_call(ReplyToolCall::new(
                    "call_escape_1",
                    "lookup_order",
                    serde_json::json!({}),
                )),
                ReplyMessage::tool_result("call_escape_1", &escaped_result),
                ReplyMessage::assistant_tool_call(ReplyToolCall::new(
                    "call_escape_2",
                    "lookup_order",
                    serde_json::json!({}),
                )),
                ReplyMessage::tool_result("call_escape_2", escaped_result),
            ],
            [lookup_tool()],
        );

        assert!(validate_agent_reply_request(&request).is_ok());
        assert_eq!(
            persisted_agent_reply_request(&request),
            Err(ProviderError::InvalidRequest(
                "serialized Agent request is too large"
            ))
        );
    }
}
