//! Durable Session-child admission, discovery, and model-facing contracts.
//!
//! The runtime resolves the exact started Agent scope. Storage atomically
//! admits a background child for `spawn_agent`, lists only those bound
//! children for `list_agents`, exposes a bounded terminal-result snapshot for
//! `get_agent_result`, and gates durable direct-child continuation and
//! interruption through exact started parent tool scopes.

use std::collections::BTreeMap;

use protocol::{SandboxProfile, SessionForkSummary, ToolEffect};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
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
pub const GET_AGENT_RESULT_TOOL_NAME: &str = "get_agent_result";
pub const GET_AGENT_RESULT_TOOL_VERSION: &str = "1-direct-child-snapshot";
pub const GET_AGENT_RESULT_ARGUMENTS_MAX_BYTES: usize = 1024;
pub const GET_AGENT_RESULT_DEFAULT_MAX_BYTES: usize = 8 * 1024;
pub const GET_AGENT_RESULT_MAX_BYTES: usize = 8 * 1024;
pub const INTERRUPT_AGENT_TOOL_NAME: &str = "interrupt_agent";
pub const INTERRUPT_AGENT_TOOL_VERSION: &str = "1-direct-child-cancel";
pub const INTERRUPT_AGENT_ARGUMENTS_MAX_BYTES: usize = 1024;
pub const SEND_MESSAGE_TOOL_NAME: &str = "send_message";
pub const SEND_MESSAGE_TOOL_VERSION: &str = "1-direct-child-followup";
pub const SEND_MESSAGE_MAX_BYTES: usize = 12 * 1024;
pub const SEND_MESSAGE_ARGUMENTS_MAX_BYTES: usize = 16 * 1024;
pub const WAIT_AGENT_TOOL_NAME: &str = "wait_agent";
pub const WAIT_AGENT_TOOL_VERSION: &str = "1-direct-child-activity";
pub const WAIT_AGENT_DEFAULT_TIMEOUT_MS: u64 = 30_000;
pub const WAIT_AGENT_MIN_TIMEOUT_MS: u64 = 10_000;
pub const WAIT_AGENT_MAX_TIMEOUT_MS: u64 = 3_600_000;
pub const WAIT_AGENT_ARGUMENTS_MAX_BYTES: usize = 128;
pub const SPAWN_AGENT_TOOL_NAME: &str = "spawn_agent";
pub const SPAWN_AGENT_TOOL_VERSION: &str = "1-durable-session-fork";
pub const SPAWN_AGENT_DESCRIPTION_MAX_BYTES: usize = 256;
pub const SPAWN_AGENT_PROMPT_MAX_BYTES: usize = 12 * 1024;
pub const SPAWN_AGENT_ARGUMENTS_MAX_BYTES: usize = 16 * 1024;
pub const SPAWN_AGENT_MAX_DEPTH: usize = 3;
pub const SPAWN_AGENT_MAX_DIRECT_CHILDREN: usize = 8;

const LIST_AGENTS_DESCRIPTION: &str = "List this Session's durable direct child branches by stable child Session ID and immutable fork boundary. This is a bounded read, not completion polling: use the opaque next_cursor to continue when present. Use send_message to continue a child, interrupt_agent to stop active work, and get_agent_result to read terminal output.";
const GET_AGENT_RESULT_DESCRIPTION: &str = "Read one durable direct child's current status and, after successful completion, a bounded page of its final assistant output. The child must have been created by this parent Session's spawn_agent call. Failed or indeterminate children never expose partial output. Continue a large successful result with next_after_byte.";
const INTERRUPT_AGENT_DESCRIPTION: &str = "Durably interrupt one currently active direct child created by this parent Session's spawn_agent call. Queued or running model work and tools that have not crossed their durable started checkpoint can be cancelled. A tool that is already running is outcome-sensitive and will not be reported as cancelled.";
const SEND_MESSAGE_DESCRIPTION: &str = "Durably enqueue one follow-up message for a direct child created by this parent Session's spawn_agent call. The stable message_id acknowledges FIFO admission, not child completion. A ready child is scheduled and a running child consumes the message after its current turn; use get_agent_result to read completed output.";
const WAIT_AGENT_DESCRIPTION: &str = "Wait for the next durable Session activity from any currently running direct child created by this parent Session's spawn_agent calls. This never wakes an inactive child. It returns no_progress immediately when no direct child can produce an event; after activity or timeout, call list_agents or get_agent_result for the authoritative durable state.";
const SPAWN_AGENT_DESCRIPTION: &str = "Start one durable background child Agent that inherits this Session's completed turns before the current in-flight turn. The call returns after the child Session, initial prompt, and first model job are atomically admitted; it does not wait for the child result. Use list_agents to rediscover the stable child ID, send_message to continue it, interrupt_agent to stop active work, and get_agent_result to read terminal output.";

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
    #[error("get_agent_result arguments are not a strict bounded object")]
    InvalidResultArguments,
    #[error("get_agent_result subagent_id is not a canonical bounded identifier")]
    InvalidResultSubagentId,
    #[error("get_agent_result byte range is outside the bounded result contract")]
    InvalidResultRange,
    #[error("get_agent_result result exceeds its bounded output contract")]
    InvalidAgentResult,
    #[error("interrupt_agent arguments are not a strict bounded object")]
    InvalidInterruptArguments,
    #[error("interrupt_agent subagent_id is not a canonical bounded identifier")]
    InvalidInterruptSubagentId,
    #[error("interrupt_agent result exceeds its bounded output contract")]
    InvalidInterruptResult,
    #[error("send_message arguments are not a strict bounded object")]
    InvalidSendArguments,
    #[error("send_message subagent_id is not a canonical bounded identifier")]
    InvalidSendSubagentId,
    #[error("send_message message is not a non-empty bounded user message")]
    InvalidSendMessage,
    #[error("send_message durable identity input is invalid")]
    InvalidSendIdentity,
    #[error("send_message result exceeds its bounded output contract")]
    InvalidSendResult,
    #[error("wait_agent arguments are not a strict bounded object")]
    InvalidWaitArguments,
    #[error(
        "wait_agent timeout must be between {WAIT_AGENT_MIN_TIMEOUT_MS} and {WAIT_AGENT_MAX_TIMEOUT_MS} milliseconds"
    )]
    InvalidWaitTimeout,
    #[error("wait_agent result exceeds its bounded output contract")]
    InvalidWaitResult,
    #[error("spawn_agent arguments are not a strict bounded object")]
    InvalidSpawnArguments,
    #[error("spawn_agent description is not a non-empty bounded display label")]
    InvalidSpawnDescription,
    #[error("spawn_agent prompt is not a non-empty bounded message")]
    InvalidSpawnPrompt,
    #[error("spawn_agent durable identity input is invalid")]
    InvalidSpawnIdentity,
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

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGetAgentResultRequest {
    subagent_id: String,
    #[serde(default)]
    after_byte: Option<usize>,
    #[serde(default)]
    max_bytes: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetAgentResultRequest {
    subagent_id: String,
    after_byte: usize,
    max_bytes: usize,
}

impl GetAgentResultRequest {
    pub fn subagent_id(&self) -> &str {
        &self.subagent_id
    }

    pub const fn after_byte(&self) -> usize {
        self.after_byte
    }

    pub const fn max_bytes(&self) -> usize {
        self.max_bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GetAgentResultStatus {
    Running,
    Completed,
    Failed,
    NeedsAttention,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetAgentResult {
    pub subagent_id: String,
    pub status: GetAgentResultStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_start_byte: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_end_byte: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_total_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_after_byte: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSendMessageRequest {
    subagent_id: String,
    message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendMessageRequest {
    subagent_id: String,
    message: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInterruptAgentRequest {
    subagent_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWaitAgentRequest {
    #[serde(default)]
    timeout_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WaitAgentRequest {
    timeout_ms: u64,
}

impl WaitAgentRequest {
    pub const fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaitAgentNoProgressReason {
    NoActiveChild,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WaitAgentNoProgress {
    pub reason: WaitAgentNoProgressReason,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WaitAgentResult {
    pub timed_out: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_progress: Option<WaitAgentNoProgress>,
}

impl WaitAgentResult {
    pub fn activity() -> Result<Self, SubagentError> {
        Self::validated(Self {
            timed_out: false,
            no_progress: None,
        })
    }

    pub fn timed_out() -> Result<Self, SubagentError> {
        Self::validated(Self {
            timed_out: true,
            no_progress: None,
        })
    }

    pub fn no_active_child() -> Result<Self, SubagentError> {
        Self::validated(Self {
            timed_out: false,
            no_progress: Some(WaitAgentNoProgress {
                reason: WaitAgentNoProgressReason::NoActiveChild,
                message: "No direct child has active or queued work. Re-list the durable child catalog and send a follow-up before waiting again.".into(),
            }),
        })
    }

    fn validated(result: Self) -> Result<Self, SubagentError> {
        if result.timed_out && result.no_progress.is_some() {
            return Err(SubagentError::InvalidWaitResult);
        }
        let encoded = serde_json::to_vec(&result).map_err(|_| SubagentError::InvalidWaitResult)?;
        if encoded.len() > TOOL_OUTPUT_MAX_SERIALIZED_BYTES {
            return Err(SubagentError::InvalidWaitResult);
        }
        Ok(result)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterruptAgentRequest {
    subagent_id: String,
}

impl InterruptAgentRequest {
    pub fn subagent_id(&self) -> &str {
        &self.subagent_id
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterruptAgentStatus {
    Interrupted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterruptAgentResult {
    pub subagent_id: String,
    pub turn_id: String,
    pub status: InterruptAgentStatus,
}

impl InterruptAgentResult {
    pub fn new(subagent_id: String, turn_id: String) -> Result<Self, SubagentError> {
        if protocol::validate_session_id(&subagent_id).is_err()
            || protocol::validate_turn_id(&turn_id).is_err()
        {
            return Err(SubagentError::InvalidInterruptResult);
        }
        let result = Self {
            subagent_id,
            turn_id,
            status: InterruptAgentStatus::Interrupted,
        };
        let encoded =
            serde_json::to_vec(&result).map_err(|_| SubagentError::InvalidInterruptResult)?;
        if encoded.len() > TOOL_OUTPUT_MAX_SERIALIZED_BYTES {
            return Err(SubagentError::InvalidInterruptResult);
        }
        Ok(result)
    }
}

impl SendMessageRequest {
    pub fn subagent_id(&self) -> &str {
        &self.subagent_id
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendMessageResult {
    pub subagent_id: String,
    pub message_id: String,
}

impl SendMessageResult {
    pub fn new(subagent_id: String, message_id: String) -> Result<Self, SubagentError> {
        if protocol::validate_session_id(&subagent_id).is_err()
            || protocol::validate_turn_id(&message_id).is_err()
        {
            return Err(SubagentError::InvalidSendResult);
        }
        let result = Self {
            subagent_id,
            message_id,
        };
        let encoded = serde_json::to_vec(&result).map_err(|_| SubagentError::InvalidSendResult)?;
        if encoded.len() > TOOL_OUTPUT_MAX_SERIALIZED_BYTES {
            return Err(SubagentError::InvalidSendResult);
        }
        Ok(result)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendMessageIdentity {
    pub turn_id: String,
    pub idempotency_key: String,
}

impl GetAgentResult {
    pub fn running(subagent_id: String) -> Result<Self, SubagentError> {
        Self::validated(Self {
            subagent_id,
            status: GetAgentResultStatus::Running,
            output: None,
            output_start_byte: None,
            output_end_byte: None,
            output_total_bytes: None,
            next_after_byte: None,
            completed_at: None,
        })
    }

    pub fn failed(
        subagent_id: String,
        status: GetAgentResultStatus,
        completed_at: String,
    ) -> Result<Self, SubagentError> {
        if !matches!(
            status,
            GetAgentResultStatus::Failed | GetAgentResultStatus::NeedsAttention
        ) {
            return Err(SubagentError::InvalidAgentResult);
        }
        Self::validated(Self {
            subagent_id,
            status,
            output: None,
            output_start_byte: None,
            output_end_byte: None,
            output_total_bytes: None,
            next_after_byte: None,
            completed_at: Some(completed_at),
        })
    }

    pub fn completed(
        subagent_id: String,
        output: &str,
        completed_at: String,
        after_byte: usize,
        max_bytes: usize,
    ) -> Result<Self, SubagentError> {
        if max_bytes == 0
            || max_bytes > GET_AGENT_RESULT_MAX_BYTES
            || after_byte > output.len()
            || !output.is_char_boundary(after_byte)
        {
            return Err(SubagentError::InvalidResultRange);
        }
        let mut end = output.len().min(after_byte.saturating_add(max_bytes));
        while end > after_byte && !output.is_char_boundary(end) {
            end -= 1;
        }
        let next_after_byte = (end < output.len()).then_some(end);
        Self::validated(Self {
            subagent_id,
            status: GetAgentResultStatus::Completed,
            output: Some(output[after_byte..end].to_owned()),
            output_start_byte: Some(after_byte),
            output_end_byte: Some(end),
            output_total_bytes: Some(output.len()),
            next_after_byte,
            completed_at: Some(completed_at),
        })
    }

    fn validated(result: Self) -> Result<Self, SubagentError> {
        if protocol::validate_session_id(&result.subagent_id).is_err()
            || result
                .completed_at
                .as_deref()
                .is_some_and(|value| value.is_empty() || value.len() > 128 || value.trim() != value)
        {
            return Err(SubagentError::InvalidAgentResult);
        }
        let encoded = serde_json::to_vec(&result).map_err(|_| SubagentError::InvalidAgentResult)?;
        if encoded.len() > TOOL_OUTPUT_MAX_SERIALIZED_BYTES {
            return Err(SubagentError::InvalidAgentResult);
        }
        Ok(result)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSpawnAgentRequest {
    description: String,
    prompt: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpawnAgentRequest {
    description: String,
    prompt: String,
}

impl SpawnAgentRequest {
    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn prompt(&self) -> &str {
        &self.prompt
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpawnAgentResult {
    pub subagent_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpawnAgentIdentity {
    pub session_id: String,
    pub turn_id: String,
    pub agent_id: String,
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

pub fn prepare_get_agent_result(arguments: &Value) -> Result<GetAgentResultRequest, SubagentError> {
    let encoded =
        serde_json::to_vec(arguments).map_err(|_| SubagentError::InvalidResultArguments)?;
    if encoded.len() > GET_AGENT_RESULT_ARGUMENTS_MAX_BYTES {
        return Err(SubagentError::InvalidResultArguments);
    }
    let raw: RawGetAgentResultRequest = serde_json::from_value(arguments.clone())
        .map_err(|_| SubagentError::InvalidResultArguments)?;
    if protocol::validate_session_id(&raw.subagent_id).is_err() {
        return Err(SubagentError::InvalidResultSubagentId);
    }
    let after_byte = raw.after_byte.unwrap_or(0);
    let max_bytes = raw.max_bytes.unwrap_or(GET_AGENT_RESULT_DEFAULT_MAX_BYTES);
    if after_byte > protocol::ASSISTANT_MESSAGE_MAX_BYTES
        || !(1..=GET_AGENT_RESULT_MAX_BYTES).contains(&max_bytes)
    {
        return Err(SubagentError::InvalidResultRange);
    }
    Ok(GetAgentResultRequest {
        subagent_id: raw.subagent_id,
        after_byte,
        max_bytes,
    })
}

pub fn prepare_spawn_agent(arguments: &Value) -> Result<SpawnAgentRequest, SubagentError> {
    let encoded =
        serde_json::to_vec(arguments).map_err(|_| SubagentError::InvalidSpawnArguments)?;
    if encoded.len() > SPAWN_AGENT_ARGUMENTS_MAX_BYTES {
        return Err(SubagentError::InvalidSpawnArguments);
    }
    let raw: RawSpawnAgentRequest = serde_json::from_value(arguments.clone())
        .map_err(|_| SubagentError::InvalidSpawnArguments)?;
    if !valid_display_label(&raw.description) {
        return Err(SubagentError::InvalidSpawnDescription);
    }
    if raw.prompt.is_empty()
        || raw.prompt.len() > SPAWN_AGENT_PROMPT_MAX_BYTES
        || raw.prompt.chars().all(char::is_whitespace)
        || raw
            .prompt
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(SubagentError::InvalidSpawnPrompt);
    }
    Ok(SpawnAgentRequest {
        description: raw.description,
        prompt: raw.prompt,
    })
}

pub fn prepare_send_message(arguments: &Value) -> Result<SendMessageRequest, SubagentError> {
    let encoded = serde_json::to_vec(arguments).map_err(|_| SubagentError::InvalidSendArguments)?;
    if encoded.len() > SEND_MESSAGE_ARGUMENTS_MAX_BYTES {
        return Err(SubagentError::InvalidSendArguments);
    }
    let raw: RawSendMessageRequest = serde_json::from_value(arguments.clone())
        .map_err(|_| SubagentError::InvalidSendArguments)?;
    if protocol::validate_session_id(&raw.subagent_id).is_err() {
        return Err(SubagentError::InvalidSendSubagentId);
    }
    if raw.message.len() > SEND_MESSAGE_MAX_BYTES
        || protocol::validate_user_message(&raw.message).is_err()
    {
        return Err(SubagentError::InvalidSendMessage);
    }
    Ok(SendMessageRequest {
        subagent_id: raw.subagent_id,
        message: raw.message,
    })
}

pub fn prepare_interrupt_agent(arguments: &Value) -> Result<InterruptAgentRequest, SubagentError> {
    let encoded =
        serde_json::to_vec(arguments).map_err(|_| SubagentError::InvalidInterruptArguments)?;
    if encoded.len() > INTERRUPT_AGENT_ARGUMENTS_MAX_BYTES {
        return Err(SubagentError::InvalidInterruptArguments);
    }
    let raw: RawInterruptAgentRequest = serde_json::from_value(arguments.clone())
        .map_err(|_| SubagentError::InvalidInterruptArguments)?;
    if protocol::validate_session_id(&raw.subagent_id).is_err() {
        return Err(SubagentError::InvalidInterruptSubagentId);
    }
    Ok(InterruptAgentRequest {
        subagent_id: raw.subagent_id,
    })
}

pub fn prepare_wait_agent(arguments: &Value) -> Result<WaitAgentRequest, SubagentError> {
    let encoded = serde_json::to_vec(arguments).map_err(|_| SubagentError::InvalidWaitArguments)?;
    if encoded.len() > WAIT_AGENT_ARGUMENTS_MAX_BYTES {
        return Err(SubagentError::InvalidWaitArguments);
    }
    let raw: RawWaitAgentRequest = serde_json::from_value(arguments.clone())
        .map_err(|_| SubagentError::InvalidWaitArguments)?;
    let timeout_ms = raw.timeout_ms.unwrap_or(WAIT_AGENT_DEFAULT_TIMEOUT_MS);
    if !(WAIT_AGENT_MIN_TIMEOUT_MS..=WAIT_AGENT_MAX_TIMEOUT_MS).contains(&timeout_ms) {
        return Err(SubagentError::InvalidWaitTimeout);
    }
    Ok(WaitAgentRequest { timeout_ms })
}

pub fn send_message_identity(
    parent_session_id: &str,
    call_id: &str,
    child_session_id: &str,
) -> Result<SendMessageIdentity, SubagentError> {
    if !valid_identity_input(parent_session_id)
        || !valid_identity_input(call_id)
        || protocol::validate_session_id(child_session_id).is_err()
    {
        return Err(SubagentError::InvalidSendIdentity);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"zeus.subagent-message.v1\0");
    hash_field(&mut hasher, parent_session_id.as_bytes());
    hash_field(&mut hasher, call_id.as_bytes());
    hash_field(&mut hasher, child_session_id.as_bytes());
    let digest = format!("{:x}", hasher.finalize());
    Ok(SendMessageIdentity {
        turn_id: format!("subagent-message-{digest}"),
        idempotency_key: format!("subagent-message-{digest}"),
    })
}

pub fn spawn_agent_identity(
    parent_session_id: &str,
    call_id: &str,
) -> Result<SpawnAgentIdentity, SubagentError> {
    if !valid_identity_input(parent_session_id) || !valid_identity_input(call_id) {
        return Err(SubagentError::InvalidSpawnIdentity);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"zeus.subagent-spawn.v1\0");
    hash_field(&mut hasher, parent_session_id.as_bytes());
    hash_field(&mut hasher, call_id.as_bytes());
    let digest = format!("{:x}", hasher.finalize());
    Ok(SpawnAgentIdentity {
        session_id: format!("subagent-{digest}"),
        turn_id: format!("subagent-turn-{digest}"),
        agent_id: format!("subagent-agent-{digest}"),
    })
}

pub fn spawn_prompt_digest(prompt: &str) -> Result<String, SubagentError> {
    if prompt.is_empty() || prompt.len() > SPAWN_AGENT_PROMPT_MAX_BYTES {
        return Err(SubagentError::InvalidSpawnPrompt);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"zeus.subagent-prompt.v1\0");
    hash_field(&mut hasher, prompt.as_bytes());
    Ok(format!("{:x}", hasher.finalize()))
}

fn valid_cursor(cursor: &str) -> bool {
    !cursor.is_empty()
        && cursor.len() <= LIST_AGENTS_CURSOR_MAX_BYTES
        && cursor.trim() == cursor
        && !cursor.chars().any(char::is_control)
}

fn valid_display_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= SPAWN_AGENT_DESCRIPTION_MAX_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_identity_input(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
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

pub fn get_agent_result_descriptor() -> ToolDescriptor {
    ToolDescriptor {
        name: GET_AGENT_RESULT_TOOL_NAME.into(),
        version: GET_AGENT_RESULT_TOOL_VERSION.into(),
        description: GET_AGENT_RESULT_DESCRIPTION.into(),
        effect: ToolEffect::ReadOnly,
        sandbox_profile: SandboxProfile::ReadOnly,
        input_schema: ObjectSchema {
            max_serialized_bytes: GET_AGENT_RESULT_ARGUMENTS_MAX_BYTES,
            properties: BTreeMap::from([
                (
                    "subagent_id".into(),
                    ParameterSpec::required_string(protocol::SESSION_ID_MAX_BYTES),
                ),
                (
                    "after_byte".into(),
                    ParameterSpec {
                        parameter_type: ParameterType::Integer,
                        required: false,
                        min_length: None,
                        max_length: None,
                    },
                ),
                (
                    "max_bytes".into(),
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

pub fn spawn_agent_descriptor() -> ToolDescriptor {
    ToolDescriptor {
        name: SPAWN_AGENT_TOOL_NAME.into(),
        version: SPAWN_AGENT_TOOL_VERSION.into(),
        description: SPAWN_AGENT_DESCRIPTION.into(),
        effect: ToolEffect::LocalWrite,
        sandbox_profile: SandboxProfile::ReadOnly,
        input_schema: ObjectSchema {
            max_serialized_bytes: SPAWN_AGENT_ARGUMENTS_MAX_BYTES,
            properties: BTreeMap::from([
                (
                    "description".into(),
                    ParameterSpec::required_string(SPAWN_AGENT_DESCRIPTION_MAX_BYTES),
                ),
                (
                    "prompt".into(),
                    ParameterSpec::required_string(SPAWN_AGENT_PROMPT_MAX_BYTES),
                ),
            ]),
        },
    }
}

pub fn send_message_descriptor() -> ToolDescriptor {
    ToolDescriptor {
        name: SEND_MESSAGE_TOOL_NAME.into(),
        version: SEND_MESSAGE_TOOL_VERSION.into(),
        description: SEND_MESSAGE_DESCRIPTION.into(),
        effect: ToolEffect::LocalWrite,
        sandbox_profile: SandboxProfile::ReadOnly,
        input_schema: ObjectSchema {
            max_serialized_bytes: SEND_MESSAGE_ARGUMENTS_MAX_BYTES,
            properties: BTreeMap::from([
                (
                    "subagent_id".into(),
                    ParameterSpec::required_string(protocol::SESSION_ID_MAX_BYTES),
                ),
                (
                    "message".into(),
                    ParameterSpec::required_string(SEND_MESSAGE_MAX_BYTES),
                ),
            ]),
        },
    }
}

pub fn interrupt_agent_descriptor() -> ToolDescriptor {
    ToolDescriptor {
        name: INTERRUPT_AGENT_TOOL_NAME.into(),
        version: INTERRUPT_AGENT_TOOL_VERSION.into(),
        description: INTERRUPT_AGENT_DESCRIPTION.into(),
        effect: ToolEffect::LocalWrite,
        sandbox_profile: SandboxProfile::ReadOnly,
        input_schema: ObjectSchema {
            max_serialized_bytes: INTERRUPT_AGENT_ARGUMENTS_MAX_BYTES,
            properties: BTreeMap::from([(
                "subagent_id".into(),
                ParameterSpec::required_string(protocol::SESSION_ID_MAX_BYTES),
            )]),
        },
    }
}

pub fn wait_agent_descriptor() -> ToolDescriptor {
    ToolDescriptor {
        name: WAIT_AGENT_TOOL_NAME.into(),
        version: WAIT_AGENT_TOOL_VERSION.into(),
        description: WAIT_AGENT_DESCRIPTION.into(),
        effect: ToolEffect::ReadOnly,
        sandbox_profile: SandboxProfile::ReadOnly,
        input_schema: ObjectSchema {
            max_serialized_bytes: WAIT_AGENT_ARGUMENTS_MAX_BYTES,
            properties: BTreeMap::from([(
                "timeout_ms".into(),
                ParameterSpec {
                    parameter_type: ParameterType::Integer,
                    required: false,
                    min_length: None,
                    max_length: None,
                },
            )]),
        },
    }
}

pub fn register_subagent_tools(registry: &mut ToolRegistry) -> Result<(), RegistryError> {
    registry.register(get_agent_result_descriptor(), RuntimeSubagentExecutor)?;
    registry.register(interrupt_agent_descriptor(), RuntimeSubagentExecutor)?;
    registry.register(list_agents_descriptor(), RuntimeSubagentExecutor)?;
    registry.register(send_message_descriptor(), RuntimeSubagentExecutor)?;
    registry.register(spawn_agent_descriptor(), RuntimeSubagentExecutor)?;
    registry.register(wait_agent_descriptor(), RuntimeSubagentExecutor)
}

#[derive(Clone, Copy)]
struct RuntimeSubagentExecutor;

impl ToolExecutor for RuntimeSubagentExecutor {
    fn execute(&self, _request: ExecutionRequest) -> ExecutionFuture<'_> {
        Box::pin(async {
            Err(ExecutorError::Failed {
                code: "subagent_runtime_required".into(),
                message: "subagent tools require the Zeus durable Session runtime".into(),
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
        assert!(registry.descriptor(GET_AGENT_RESULT_TOOL_NAME).is_some());
        assert!(registry.descriptor(INTERRUPT_AGENT_TOOL_NAME).is_some());
        assert!(registry.descriptor(SEND_MESSAGE_TOOL_NAME).is_some());
        assert!(registry.descriptor(WAIT_AGENT_TOOL_NAME).is_some());
    }

    #[test]
    fn get_result_request_is_strict_defaulted_and_bounded() {
        let request = prepare_get_agent_result(&serde_json::json!({
            "subagent_id": "subagent-child",
        }))
        .unwrap();
        assert_eq!(request.subagent_id(), "subagent-child");
        assert_eq!(request.after_byte(), 0);
        assert_eq!(request.max_bytes(), GET_AGENT_RESULT_DEFAULT_MAX_BYTES);

        let request = prepare_get_agent_result(&serde_json::json!({
            "subagent_id": "subagent-child",
            "after_byte": 12,
            "max_bytes": 1024,
        }))
        .unwrap();
        assert_eq!(request.after_byte(), 12);
        assert_eq!(request.max_bytes(), 1024);

        for invalid in [
            serde_json::json!({}),
            serde_json::json!({"subagent_id": " bad"}),
            serde_json::json!({"subagent_id": "child", "max_bytes": 0}),
            serde_json::json!({"subagent_id": "child", "max_bytes": GET_AGENT_RESULT_MAX_BYTES + 1}),
            serde_json::json!({"subagent_id": "child", "unknown": true}),
        ] {
            assert!(prepare_get_agent_result(&invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn get_result_is_terminal_safe_utf8_paged_and_output_bounded() {
        let output = format!("{}tail", "🙂".repeat(GET_AGENT_RESULT_MAX_BYTES / 4));
        let first = GetAgentResult::completed(
            "subagent-child".into(),
            &output,
            "2026-08-28T00:00:00.000Z".into(),
            0,
            GET_AGENT_RESULT_MAX_BYTES - 1,
        )
        .unwrap();
        assert_eq!(first.status, GetAgentResultStatus::Completed);
        assert_eq!(first.output_start_byte, Some(0));
        assert_eq!(first.output_end_byte, Some(GET_AGENT_RESULT_MAX_BYTES - 4));
        assert_eq!(first.next_after_byte, first.output_end_byte);
        assert!(serde_json::to_vec(&first).unwrap().len() <= TOOL_OUTPUT_MAX_SERIALIZED_BYTES);

        assert!(
            GetAgentResult::completed(
                "subagent-child".into(),
                &output,
                "2026-08-28T00:00:00.000Z".into(),
                1,
                1024,
            )
            .is_err()
        );
        let escaped = GetAgentResult::completed(
            "subagent-child".into(),
            &"\0".repeat(GET_AGENT_RESULT_MAX_BYTES),
            "2026-08-28T00:00:00.000Z".into(),
            0,
            GET_AGENT_RESULT_MAX_BYTES,
        )
        .unwrap();
        assert!(serde_json::to_vec(&escaped).unwrap().len() <= TOOL_OUTPUT_MAX_SERIALIZED_BYTES);

        let failed = GetAgentResult::failed(
            "subagent-child".into(),
            GetAgentResultStatus::Failed,
            "2026-08-28T00:00:00.000Z".into(),
        )
        .unwrap();
        assert!(failed.output.is_none());
        assert!(failed.next_after_byte.is_none());
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

    #[test]
    fn spawn_request_is_strict_control_safe_and_bounded() {
        let request = prepare_spawn_agent(&serde_json::json!({
            "description": "Review storage",
            "prompt": "Inspect the durable transaction boundary.\nReturn risks.",
        }))
        .unwrap();
        assert_eq!(request.description(), "Review storage");
        assert!(request.prompt().contains("transaction"));
        for invalid in [
            serde_json::json!({"description": "", "prompt": "work"}),
            serde_json::json!({"description": " padded ", "prompt": "work"}),
            serde_json::json!({"description": "work", "prompt": "  "}),
            serde_json::json!({"description": "work", "prompt": "task", "extra": true}),
        ] {
            assert!(prepare_spawn_agent(&invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn send_message_request_and_identity_are_strict_bounded_and_scope_bound() {
        let request = prepare_send_message(&serde_json::json!({
            "subagent_id": "subagent-child",
            "message": "Continue with the second bounded task.",
        }))
        .unwrap();
        assert_eq!(request.subagent_id(), "subagent-child");
        assert!(request.message().contains("second"));
        for invalid in [
            serde_json::json!({"subagent_id": " bad", "message": "work"}),
            serde_json::json!({"subagent_id": "child", "message": "  "}),
            serde_json::json!({"subagent_id": "child", "message": "work", "extra": true}),
        ] {
            assert!(prepare_send_message(&invalid).is_err(), "{invalid}");
        }

        let first = send_message_identity("parent", "call-1", "subagent-child").unwrap();
        assert_eq!(
            first,
            send_message_identity("parent", "call-1", "subagent-child").unwrap()
        );
        assert_ne!(
            first,
            send_message_identity("parent", "call-2", "subagent-child").unwrap()
        );
        assert_ne!(
            first,
            send_message_identity("parent", "call-1", "subagent-other").unwrap()
        );
        protocol::validate_turn_id(&first.turn_id).unwrap();
        protocol::validate_idempotency_key(&first.idempotency_key).unwrap();
    }

    #[test]
    fn send_message_descriptor_and_result_are_closed_and_bounded() {
        let descriptor = send_message_descriptor();
        assert_eq!(descriptor.effect, ToolEffect::LocalWrite);
        assert_eq!(descriptor.sandbox_profile, SandboxProfile::ReadOnly);
        let schema = descriptor.input_schema.provider_json_schema().unwrap();
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["properties"]["message"]["maxLength"],
            SEND_MESSAGE_MAX_BYTES
        );
        let result =
            SendMessageResult::new("subagent-child".into(), "subagent-message-1".into()).unwrap();
        assert!(serde_json::to_vec(&result).unwrap().len() <= TOOL_OUTPUT_MAX_SERIALIZED_BYTES);
    }

    #[test]
    fn interrupt_agent_request_descriptor_and_result_are_strict() {
        let request = prepare_interrupt_agent(&serde_json::json!({
            "subagent_id": "subagent-child",
        }))
        .unwrap();
        assert_eq!(request.subagent_id(), "subagent-child");
        for invalid in [
            serde_json::json!({"subagent_id": " bad"}),
            serde_json::json!({"subagent_id": "child", "extra": true}),
            serde_json::json!({}),
        ] {
            assert!(prepare_interrupt_agent(&invalid).is_err(), "{invalid}");
        }
        let descriptor = interrupt_agent_descriptor();
        assert_eq!(descriptor.effect, ToolEffect::LocalWrite);
        assert_eq!(descriptor.sandbox_profile, SandboxProfile::ReadOnly);
        assert_eq!(
            descriptor.input_schema.provider_json_schema().unwrap()["additionalProperties"],
            false
        );
        let result =
            InterruptAgentResult::new("subagent-child".into(), "turn-child".into()).unwrap();
        assert_eq!(result.status, InterruptAgentStatus::Interrupted);
    }

    #[test]
    fn wait_agent_request_descriptor_and_results_are_strict() {
        let defaulted = prepare_wait_agent(&serde_json::json!({})).unwrap();
        assert_eq!(defaulted.timeout_ms(), WAIT_AGENT_DEFAULT_TIMEOUT_MS);
        let explicit = prepare_wait_agent(&serde_json::json!({
            "timeout_ms": WAIT_AGENT_MAX_TIMEOUT_MS,
        }))
        .unwrap();
        assert_eq!(explicit.timeout_ms(), WAIT_AGENT_MAX_TIMEOUT_MS);
        for invalid in [
            serde_json::json!({"timeout_ms": WAIT_AGENT_MIN_TIMEOUT_MS - 1}),
            serde_json::json!({"timeout_ms": WAIT_AGENT_MAX_TIMEOUT_MS + 1}),
            serde_json::json!({"timeout_ms": "30000"}),
            serde_json::json!({"unknown": true}),
        ] {
            assert!(prepare_wait_agent(&invalid).is_err(), "{invalid}");
        }

        let descriptor = wait_agent_descriptor();
        assert_eq!(descriptor.effect, ToolEffect::ReadOnly);
        assert_eq!(descriptor.sandbox_profile, SandboxProfile::ReadOnly);
        assert_eq!(
            descriptor.input_schema.provider_json_schema().unwrap()["additionalProperties"],
            false
        );
        assert!(WaitAgentResult::activity().unwrap().no_progress.is_none());
        assert!(WaitAgentResult::timed_out().unwrap().timed_out);
        assert_eq!(
            WaitAgentResult::no_active_child()
                .unwrap()
                .no_progress
                .unwrap()
                .reason,
            WaitAgentNoProgressReason::NoActiveChild
        );
    }

    #[test]
    fn spawn_identity_and_prompt_digest_are_stable_and_scope_bound() {
        let first = spawn_agent_identity("session-parent", "call-1").unwrap();
        assert_eq!(
            first,
            spawn_agent_identity("session-parent", "call-1").unwrap()
        );
        assert_ne!(
            first,
            spawn_agent_identity("session-parent", "call-2").unwrap()
        );
        assert_ne!(
            first,
            spawn_agent_identity("session-other", "call-1").unwrap()
        );
        assert!(first.session_id.starts_with("subagent-"));
        assert_ne!(
            spawn_prompt_digest("alpha").unwrap(),
            spawn_prompt_digest("beta").unwrap()
        );
    }

    #[test]
    fn spawn_descriptor_is_local_write_closed_and_registered() {
        let descriptor = spawn_agent_descriptor();
        assert_eq!(descriptor.effect, ToolEffect::LocalWrite);
        assert_eq!(descriptor.sandbox_profile, SandboxProfile::ReadOnly);
        let schema = descriptor.input_schema.provider_json_schema().unwrap();
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["properties"]["prompt"]["maxLength"],
            SPAWN_AGENT_PROMPT_MAX_BYTES
        );
        let mut registry = ToolRegistry::new();
        register_subagent_tools(&mut registry).unwrap();
        assert!(registry.descriptor(SPAWN_AGENT_TOOL_NAME).is_some());
    }
}
