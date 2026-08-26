//! HTTP-facing contracts shared by the Zeus demo API and its clients.
//!
//! These types deliberately describe the product boundary only. Persistence and
//! orchestration implementations belong in other crates.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const DEMO_RUN_ID: &str = "ZR-1842";
pub const LOCAL_DEMO_RUN_ID: &str = "ZR-DEV-1";
pub const DEMO_SESSION_ID: &str = "session-ZR-1842";
pub const LOCAL_DEMO_SESSION_ID: &str = "session-ZR-DEV-1";

/// Maximum UTF-8 byte length of a Session identifier.
pub const SESSION_ID_MAX_BYTES: usize = 128;
/// Maximum UTF-8 byte length of a turn identifier.
pub const TURN_ID_MAX_BYTES: usize = 128;
/// Maximum UTF-8 byte length of any other API resource identifier.
pub const RESOURCE_ID_MAX_BYTES: usize = 128;
/// Maximum UTF-8 byte length of a Session title.
pub const SESSION_TITLE_MAX_BYTES: usize = 256;
/// Maximum UTF-8 byte length of one user-authored Session message.
pub const USER_MESSAGE_MAX_BYTES: usize = 64 * 1024;
/// Maximum UTF-8 byte length of one durable assistant message.
///
/// Terminal reply reservation uses this hard envelope rather than assuming an
/// HTTP response-body limit equals the bytes duplicated across durable rows.
pub const ASSISTANT_MESSAGE_MAX_BYTES: usize = 64 * 1024;
/// Maximum UTF-8 byte length of a durable reply provider identifier.
pub const REPLY_PROVIDER_ID_MAX_BYTES: usize = 128;
/// Maximum UTF-8 byte length of a durable reply model identifier.
pub const REPLY_MODEL_ID_MAX_BYTES: usize = 128;
/// Maximum UTF-8 byte length of a durable provider finish reason.
pub const REPLY_FINISH_REASON_MAX_BYTES: usize = 128;
/// Maximum byte length of a durable reply failure code.
pub const REPLY_ERROR_CODE_MAX_BYTES: usize = 128;
/// Maximum UTF-8 byte length of a durable reply failure message.
pub const REPLY_ERROR_MESSAGE_MAX_BYTES: usize = 4 * 1024;
/// Maximum UTF-8 byte length of a durable tool-outcome summary.
pub const TOOL_OUTCOME_SUMMARY_MAX_BYTES: usize = 4 * 1024;
/// Maximum byte length of a durable tool error code or output digest.
pub const TOOL_OUTCOME_CODE_MAX_BYTES: usize = 128;
/// Maximum UTF-8 byte length of an approval review note.
pub const REVIEW_NOTE_MAX_BYTES: usize = 8 * 1024;
/// Maximum byte length of an idempotency key.
pub const IDEMPOTENCY_KEY_MAX_BYTES: usize = 128;
/// Default number of durable ledger events returned by one event page.
pub const EVENT_PAGE_DEFAULT_LIMIT: usize = 128;
/// Maximum number of durable ledger events returned by one event page.
pub const EVENT_PAGE_MAX_LIMIT: usize = 256;
/// Default number of non-event read-model rows returned by one page.
pub const COLLECTION_PAGE_DEFAULT_LIMIT: usize = 50;
/// Maximum number of non-event read-model rows returned by one page.
pub const COLLECTION_PAGE_MAX_LIMIT: usize = 100;

/// A pure Resource Envelope validation failure shared by every application
/// boundary. All length checks refer to UTF-8 bytes, not Unicode scalar values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceEnvelopeError {
    Empty,
    Blank,
    NotCanonical,
    TooLong { max_bytes: usize },
    NotAsciiGraphic,
    ContainsWhitespace,
    ContainsControl,
}

impl fmt::Display for ResourceEnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("cannot be empty"),
            Self::Blank => formatter.write_str("cannot be blank"),
            Self::NotCanonical => formatter.write_str("must not have surrounding whitespace"),
            Self::TooLong { max_bytes } => {
                write!(formatter, "cannot exceed {max_bytes} UTF-8 bytes")
            }
            Self::NotAsciiGraphic => {
                formatter.write_str("must contain only ASCII graphic characters")
            }
            Self::ContainsWhitespace => formatter.write_str("cannot contain whitespace"),
            Self::ContainsControl => formatter.write_str("cannot contain control characters"),
        }
    }
}

impl std::error::Error for ResourceEnvelopeError {}

/// Validates a canonical, non-empty Session identifier.
pub fn validate_session_id(value: &str) -> Result<(), ResourceEnvelopeError> {
    validate_identifier_bounded(value, SESSION_ID_MAX_BYTES)
}

/// Validates a canonical, non-empty turn identifier.
pub fn validate_turn_id(value: &str) -> Result<(), ResourceEnvelopeError> {
    validate_identifier_bounded(value, TURN_ID_MAX_BYTES)
}

/// Validates a canonical, non-empty non-Session resource identifier.
pub fn validate_resource_id(value: &str) -> Result<(), ResourceEnvelopeError> {
    validate_identifier_bounded(value, RESOURCE_ID_MAX_BYTES)
}

/// Validates a canonical, non-empty Session title.
pub fn validate_session_title(value: &str) -> Result<(), ResourceEnvelopeError> {
    validate_canonical_bounded(value, SESSION_TITLE_MAX_BYTES)?;
    if value.chars().any(char::is_control) {
        return Err(ResourceEnvelopeError::ContainsControl);
    }
    Ok(())
}

/// Validates a non-blank user message without altering its contents.
pub fn validate_user_message(value: &str) -> Result<(), ResourceEnvelopeError> {
    if value.len() > USER_MESSAGE_MAX_BYTES {
        return Err(ResourceEnvelopeError::TooLong {
            max_bytes: USER_MESSAGE_MAX_BYTES,
        });
    }
    if value.trim().is_empty() {
        return Err(ResourceEnvelopeError::Blank);
    }
    Ok(())
}

/// Validates a non-blank assistant message before it crosses the durable
/// terminal boundary.
pub fn validate_assistant_message(value: &str) -> Result<(), ResourceEnvelopeError> {
    if value.len() > ASSISTANT_MESSAGE_MAX_BYTES {
        return Err(ResourceEnvelopeError::TooLong {
            max_bytes: ASSISTANT_MESSAGE_MAX_BYTES,
        });
    }
    if value.trim().is_empty() {
        return Err(ResourceEnvelopeError::Blank);
    }
    Ok(())
}

/// Validates the stable, secret-free provider identifier copied into jobs and
/// assistant-message provenance.
pub fn validate_reply_provider_id(value: &str) -> Result<(), ResourceEnvelopeError> {
    validate_canonical_bounded(value, REPLY_PROVIDER_ID_MAX_BYTES)?;
    if value.chars().any(char::is_control) {
        return Err(ResourceEnvelopeError::ContainsControl);
    }
    Ok(())
}

/// Validates a model identifier copied into durable reply provenance.
pub fn validate_reply_model_id(value: &str) -> Result<(), ResourceEnvelopeError> {
    validate_canonical_bounded(value, REPLY_MODEL_ID_MAX_BYTES)?;
    if value.chars().any(char::is_control) {
        return Err(ResourceEnvelopeError::ContainsControl);
    }
    Ok(())
}

/// Validates a provider finish reason copied into the typed reply receipt.
pub fn validate_reply_finish_reason(value: &str) -> Result<(), ResourceEnvelopeError> {
    validate_canonical_bounded(value, REPLY_FINISH_REASON_MAX_BYTES)?;
    if value.chars().any(char::is_control) {
        return Err(ResourceEnvelopeError::ContainsControl);
    }
    Ok(())
}

/// Validates a compact ASCII reply failure code.
pub fn validate_reply_error_code(value: &str) -> Result<(), ResourceEnvelopeError> {
    validate_ascii_graphic_bounded(value, REPLY_ERROR_CODE_MAX_BYTES)
}

/// Validates a non-blank diagnostic admitted to a durable reply failure.
pub fn validate_reply_error_message(value: &str) -> Result<(), ResourceEnvelopeError> {
    if value.len() > REPLY_ERROR_MESSAGE_MAX_BYTES {
        return Err(ResourceEnvelopeError::TooLong {
            max_bytes: REPLY_ERROR_MESSAGE_MAX_BYTES,
        });
    }
    if value.trim().is_empty() {
        return Err(ResourceEnvelopeError::Blank);
    }
    Ok(())
}

/// Validates a non-blank terminal tool summary without altering its contents.
pub fn validate_tool_outcome_summary(value: &str) -> Result<(), ResourceEnvelopeError> {
    if value.len() > TOOL_OUTCOME_SUMMARY_MAX_BYTES {
        return Err(ResourceEnvelopeError::TooLong {
            max_bytes: TOOL_OUTCOME_SUMMARY_MAX_BYTES,
        });
    }
    if value.trim().is_empty() {
        return Err(ResourceEnvelopeError::Blank);
    }
    Ok(())
}

/// Validates a compact ASCII code or digest copied into a tool outcome.
pub fn validate_tool_outcome_code(value: &str) -> Result<(), ResourceEnvelopeError> {
    validate_ascii_graphic_bounded(value, TOOL_OUTCOME_CODE_MAX_BYTES)
}

/// Validates an optional review note's contents without trimming or otherwise
/// normalizing it. Empty notes remain compatible with the existing protocol.
pub fn validate_review_note(value: &str) -> Result<(), ResourceEnvelopeError> {
    if value.len() > REVIEW_NOTE_MAX_BYTES {
        Err(ResourceEnvelopeError::TooLong {
            max_bytes: REVIEW_NOTE_MAX_BYTES,
        })
    } else {
        Ok(())
    }
}

/// Validates an exactly canonical idempotency key.
///
/// The accepted alphabet is ASCII `!` through `~`. In particular, this rejects
/// spaces, all other whitespace, control bytes, and non-ASCII input. Callers
/// must never trim or otherwise reinterpret a rejected key.
pub fn validate_idempotency_key(value: &str) -> Result<(), ResourceEnvelopeError> {
    if value.is_empty() {
        return Err(ResourceEnvelopeError::Empty);
    }
    if value.len() > IDEMPOTENCY_KEY_MAX_BYTES {
        return Err(ResourceEnvelopeError::TooLong {
            max_bytes: IDEMPOTENCY_KEY_MAX_BYTES,
        });
    }
    if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(ResourceEnvelopeError::NotAsciiGraphic);
    }
    Ok(())
}

fn validate_canonical_bounded(value: &str, max_bytes: usize) -> Result<(), ResourceEnvelopeError> {
    if value.is_empty() {
        return Err(ResourceEnvelopeError::Empty);
    }
    if value.len() > max_bytes {
        return Err(ResourceEnvelopeError::TooLong { max_bytes });
    }
    if value.trim() != value {
        return Err(ResourceEnvelopeError::NotCanonical);
    }
    Ok(())
}

fn validate_ascii_graphic_bounded(
    value: &str,
    max_bytes: usize,
) -> Result<(), ResourceEnvelopeError> {
    if value.is_empty() {
        return Err(ResourceEnvelopeError::Empty);
    }
    if value.len() > max_bytes {
        return Err(ResourceEnvelopeError::TooLong { max_bytes });
    }
    if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(ResourceEnvelopeError::NotAsciiGraphic);
    }
    Ok(())
}

fn validate_identifier_bounded(value: &str, max_bytes: usize) -> Result<(), ResourceEnvelopeError> {
    validate_canonical_bounded(value, max_bytes)?;
    if value.chars().any(char::is_control) {
        return Err(ResourceEnvelopeError::ContainsControl);
    }
    if value.chars().any(char::is_whitespace) {
        return Err(ResourceEnvelopeError::ContainsWhitespace);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountRole {
    Owner,
    Member,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    Active,
    Disabled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountUser {
    pub id: String,
    pub username: String,
    pub role: AccountRole,
    pub status: AccountStatus,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemePreference {
    System,
    Light,
    Dark,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserPreferences {
    pub theme: ThemePreference,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_model: Option<String>,
    pub revision: u64,
    pub updated_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthStatusResponse {
    pub configured: bool,
    pub authenticated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<AccountUser>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferences: Option<UserPreferences>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapRequest {
    pub bootstrap_token: String,
    pub username: String,
    pub password: String,
}

impl fmt::Debug for BootstrapRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootstrapRequest")
            .field("bootstrap_token", &"[REDACTED]")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

impl fmt::Debug for LoginRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoginRequest")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticationResponse {
    pub user: AccountUser,
    pub preferences: UserPreferences,
    pub csrf_token: String,
    pub expires_at: String,
}

impl fmt::Debug for AuthenticationResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticationResponse")
            .field("user", &self.user)
            .field("preferences", &self.preferences)
            .field("csrf_token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdatePreferencesRequest {
    pub theme: ThemePreference,
    #[serde(default)]
    pub preferred_model: Option<String>,
    pub expected_revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogoutResponse {
    pub status: String,
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
    AuthorizationRevoked,
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

    /// Validates every string copied into the durable Run ledger.
    pub fn validate_resource_envelope(&self) -> Result<(), ResourceEnvelopeError> {
        let summary = match self {
            Self::Succeeded {
                summary,
                output_digest,
            } => {
                if let Some(output_digest) = output_digest {
                    validate_tool_outcome_code(output_digest)?;
                }
                summary
            }
            Self::Failed {
                summary,
                error_code,
            } => {
                if let Some(error_code) = error_code {
                    validate_tool_outcome_code(error_code)?;
                }
                summary
            }
            Self::Cancelled { summary }
            | Self::NotDispatched { summary, .. }
            | Self::OutcomeUnknown { summary } => summary,
        };
        validate_tool_outcome_summary(summary)
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
#[serde(rename_all = "snake_case")]
pub enum AssistantReplyKind {
    Model,
    NonModelFallback,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssistantReplyProvenance {
    pub provider_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub reply_kind: AssistantReplyKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionEventData {
    SessionCreated {
        title: String,
    },
    RunAttached {
        run_id: String,
    },
    SessionResumed {
        from_status: SessionStatus,
    },
    UserMessage {
        turn_id: String,
        content: String,
    },
    AssistantMessage {
        turn_id: String,
        content: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provenance: Option<AssistantReplyProvenance>,
    },
    TurnFlushed {
        turn_id: String,
    },
    TurnInterrupted {
        turn_id: String,
        reason: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEvent {
    pub sequence: u64,
    pub id: String,
    pub at: String,
    pub data: SessionEventData,
}

/// One bounded, strictly ordered page from a Session event ledger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEventPage {
    pub items: Vec<SessionEvent>,
    /// The last returned sequence when another page exists; otherwise `None`.
    pub next_after: Option<u64>,
    /// The durable ledger head observed in the same read transaction.
    pub head_sequence: u64,
    pub has_more: bool,
}

/// Opaque backward-pagination state for one bounded history collection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadPageInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_before: Option<String>,
    pub has_more: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionDetailPagination {
    pub run_ids: ReadPageInfo,
    pub turns: ReadPageInfo,
    pub events: ReadPageInfo,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionDetail {
    pub session: SessionSummary,
    pub run_ids: Vec<String>,
    pub turns: Vec<SessionTurn>,
    pub events: Vec<SessionEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pagination: Option<SessionDetailPagination>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

/// One bounded, strictly ordered page from a Run event ledger.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RunEventPage {
    pub items: Vec<RunEvent>,
    /// The last returned sequence when another page exists; otherwise `None`.
    pub next_after: Option<u64>,
    /// The durable ledger head observed in the same read transaction.
    pub head_sequence: u64,
    pub has_more: bool,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recent_events_page: Option<ReadPageInfo>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunDetailPagination {
    pub events: ReadPageInfo,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RunDetail {
    pub incident: IncidentSummary,
    pub run: RunSummary,
    pub events: Vec<RunEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pagination: Option<RunDetailPagination>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDecision {
    Approve,
    Reject,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    fn resource_envelope_limits_count_utf8_bytes() {
        assert!(validate_session_id(&"界".repeat(42)).is_ok());
        assert_eq!(
            validate_session_id(&"界".repeat(43)),
            Err(ResourceEnvelopeError::TooLong {
                max_bytes: SESSION_ID_MAX_BYTES,
            })
        );

        assert!(validate_turn_id(&"🙂".repeat(32)).is_ok());
        assert!(validate_resource_id(&"🙂".repeat(32)).is_ok());
        assert_eq!(
            validate_turn_id(&"🙂".repeat(33)),
            Err(ResourceEnvelopeError::TooLong {
                max_bytes: TURN_ID_MAX_BYTES,
            })
        );

        assert!(validate_session_title(&"🙂".repeat(64)).is_ok());
        assert_eq!(
            validate_session_title(&"🙂".repeat(65)),
            Err(ResourceEnvelopeError::TooLong {
                max_bytes: SESSION_TITLE_MAX_BYTES,
            })
        );

        assert!(validate_user_message(&"🙂".repeat(USER_MESSAGE_MAX_BYTES / 4)).is_ok());
        assert_eq!(
            validate_user_message(&"🙂".repeat(USER_MESSAGE_MAX_BYTES / 4 + 1)),
            Err(ResourceEnvelopeError::TooLong {
                max_bytes: USER_MESSAGE_MAX_BYTES,
            })
        );

        assert!(validate_assistant_message(&"🙂".repeat(ASSISTANT_MESSAGE_MAX_BYTES / 4)).is_ok());
        assert_eq!(
            validate_assistant_message(&"🙂".repeat(ASSISTANT_MESSAGE_MAX_BYTES / 4 + 1)),
            Err(ResourceEnvelopeError::TooLong {
                max_bytes: ASSISTANT_MESSAGE_MAX_BYTES,
            })
        );

        assert!(
            validate_tool_outcome_summary(&"🙂".repeat(TOOL_OUTCOME_SUMMARY_MAX_BYTES / 4)).is_ok()
        );
        assert_eq!(
            validate_tool_outcome_summary(&"🙂".repeat(TOOL_OUTCOME_SUMMARY_MAX_BYTES / 4 + 1)),
            Err(ResourceEnvelopeError::TooLong {
                max_bytes: TOOL_OUTCOME_SUMMARY_MAX_BYTES,
            })
        );

        assert!(validate_review_note(&"🙂".repeat(REVIEW_NOTE_MAX_BYTES / 4)).is_ok());
        assert_eq!(
            validate_review_note(&"🙂".repeat(REVIEW_NOTE_MAX_BYTES / 4 + 1)),
            Err(ResourceEnvelopeError::TooLong {
                max_bytes: REVIEW_NOTE_MAX_BYTES,
            })
        );
    }

    #[test]
    fn identifiers_and_titles_reject_ambiguous_control_or_whitespace() {
        assert_eq!(
            validate_session_id("session with space"),
            Err(ResourceEnvelopeError::ContainsWhitespace)
        );
        assert_eq!(
            validate_turn_id("turn\0id"),
            Err(ResourceEnvelopeError::ContainsControl)
        );
        assert_eq!(
            validate_session_title("two\nlines"),
            Err(ResourceEnvelopeError::ContainsControl)
        );
        assert!(validate_session_title("Normal title 🙂").is_ok());
    }

    #[test]
    fn reply_provenance_and_tool_codes_are_canonical_and_bounded() {
        assert!(validate_reply_provider_id(&"p".repeat(REPLY_PROVIDER_ID_MAX_BYTES)).is_ok());
        assert!(validate_reply_model_id(&"m".repeat(REPLY_MODEL_ID_MAX_BYTES)).is_ok());
        assert_eq!(
            validate_reply_provider_id(&"p".repeat(REPLY_PROVIDER_ID_MAX_BYTES + 1)),
            Err(ResourceEnvelopeError::TooLong {
                max_bytes: REPLY_PROVIDER_ID_MAX_BYTES,
            })
        );
        assert_eq!(
            validate_reply_model_id(" model "),
            Err(ResourceEnvelopeError::NotCanonical)
        );
        assert_eq!(
            validate_reply_model_id("model\nname"),
            Err(ResourceEnvelopeError::ContainsControl)
        );
        assert!(validate_reply_finish_reason(&"f".repeat(REPLY_FINISH_REASON_MAX_BYTES)).is_ok());
        assert_eq!(
            validate_reply_finish_reason(&"f".repeat(REPLY_FINISH_REASON_MAX_BYTES + 1)),
            Err(ResourceEnvelopeError::TooLong {
                max_bytes: REPLY_FINISH_REASON_MAX_BYTES,
            })
        );
        assert!(validate_reply_error_code(&"e".repeat(REPLY_ERROR_CODE_MAX_BYTES)).is_ok());
        assert_eq!(
            validate_reply_error_code(&"e".repeat(REPLY_ERROR_CODE_MAX_BYTES + 1)),
            Err(ResourceEnvelopeError::TooLong {
                max_bytes: REPLY_ERROR_CODE_MAX_BYTES,
            })
        );
        assert!(validate_reply_error_message(&"m".repeat(REPLY_ERROR_MESSAGE_MAX_BYTES)).is_ok());
        assert_eq!(
            validate_reply_error_message(&"m".repeat(REPLY_ERROR_MESSAGE_MAX_BYTES + 1)),
            Err(ResourceEnvelopeError::TooLong {
                max_bytes: REPLY_ERROR_MESSAGE_MAX_BYTES,
            })
        );

        assert!(validate_tool_outcome_code(&"x".repeat(TOOL_OUTCOME_CODE_MAX_BYTES)).is_ok());
        assert_eq!(
            validate_tool_outcome_code(&"x".repeat(TOOL_OUTCOME_CODE_MAX_BYTES + 1)),
            Err(ResourceEnvelopeError::TooLong {
                max_bytes: TOOL_OUTCOME_CODE_MAX_BYTES,
            })
        );
        for rejected in ["", "two words", "line\n", "clé"] {
            assert!(validate_tool_outcome_code(rejected).is_err());
        }
    }

    #[test]
    fn every_tool_outcome_variant_enforces_the_terminal_envelope() {
        let summary = "x".repeat(TOOL_OUTCOME_SUMMARY_MAX_BYTES);
        for valid in [
            ToolOutcome::Succeeded {
                summary: summary.clone(),
                output_digest: Some("sha256:output".into()),
            },
            ToolOutcome::Failed {
                summary: summary.clone(),
                error_code: Some("executor_failed".into()),
            },
            ToolOutcome::Cancelled {
                summary: summary.clone(),
            },
            ToolOutcome::NotDispatched {
                reason: NotDispatchedReason::PolicyDenied,
                summary: summary.clone(),
            },
            ToolOutcome::OutcomeUnknown {
                summary: summary.clone(),
            },
        ] {
            assert!(valid.validate_resource_envelope().is_ok());
        }

        let oversized = ToolOutcome::OutcomeUnknown {
            summary: "x".repeat(TOOL_OUTCOME_SUMMARY_MAX_BYTES + 1),
        };
        assert_eq!(
            oversized.validate_resource_envelope(),
            Err(ResourceEnvelopeError::TooLong {
                max_bytes: TOOL_OUTCOME_SUMMARY_MAX_BYTES,
            })
        );

        for invalid_code in [
            ToolOutcome::Succeeded {
                summary: "bounded".into(),
                output_digest: Some("x".repeat(TOOL_OUTCOME_CODE_MAX_BYTES + 1)),
            },
            ToolOutcome::Failed {
                summary: "bounded".into(),
                error_code: Some("x".repeat(TOOL_OUTCOME_CODE_MAX_BYTES + 1)),
            },
        ] {
            assert_eq!(
                invalid_code.validate_resource_envelope(),
                Err(ResourceEnvelopeError::TooLong {
                    max_bytes: TOOL_OUTCOME_CODE_MAX_BYTES,
                })
            );
        }
    }

    #[test]
    fn idempotency_keys_are_exact_ascii_graphic_values() {
        assert!(validate_idempotency_key("a").is_ok());
        assert!(validate_idempotency_key(&"x".repeat(IDEMPOTENCY_KEY_MAX_BYTES)).is_ok());
        for rejected in ["", " key", "key ", "two keys", "key\n", "clé"] {
            assert!(
                validate_idempotency_key(rejected).is_err(),
                "`{rejected:?}` must be rejected"
            );
        }
        assert_eq!(
            validate_idempotency_key(&"x".repeat(IDEMPOTENCY_KEY_MAX_BYTES + 1)),
            Err(ResourceEnvelopeError::TooLong {
                max_bytes: IDEMPOTENCY_KEY_MAX_BYTES,
            })
        );
    }

    #[test]
    fn resource_envelope_requests_reject_unknown_fields() {
        assert!(
            serde_json::from_value::<CreateSessionRequest>(json!({
                "id": "session-1",
                "title": "Session",
                "unexpected": true
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<StartTurnRequest>(json!({
                "turn_id": "turn-1",
                "user_message": "Hello",
                "expected_sequence": 1,
                "unexpected": true
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ResumeSessionRequest>(json!({
                "expected_sequence": 1,
                "unexpected": true
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ReviewRequest>(json!({
                "decision": "approve",
                "unexpected": true
            }))
            .is_err()
        );
    }

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
    fn legacy_assistant_message_without_provenance_still_deserializes() {
        let legacy = json!({
            "kind": "assistant_message",
            "turn_id": "turn-old",
            "content": "legacy reply"
        });

        let event: SessionEventData = serde_json::from_value(legacy).unwrap();

        assert_eq!(
            event,
            SessionEventData::AssistantMessage {
                turn_id: "turn-old".into(),
                content: "legacy reply".into(),
                provenance: None,
            }
        );
        let value = serde_json::to_value(event).unwrap();
        assert!(!value.as_object().unwrap().contains_key("provenance"));
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
                reason: NotDispatchedReason::AuthorizationRevoked,
                summary: "actor authorization was revoked".into(),
            },
            status: ToolCallStatus::NotDispatched,
        };

        let value = serde_json::to_value(&data).unwrap();
        assert_eq!(value["kind"], "tool_result");
        assert_eq!(value["outcome"]["status"], "not_dispatched");
        assert_eq!(value["outcome"]["reason"], "authorization_revoked");
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
    fn authentication_debug_output_redacts_bearer_and_password_values() {
        let bootstrap = BootstrapRequest {
            bootstrap_token: "raw-bootstrap-secret".into(),
            username: "owner".into(),
            password: "raw-password-secret".into(),
        };
        let login = LoginRequest {
            username: "owner".into(),
            password: "raw-password-secret".into(),
        };

        let bootstrap_debug = format!("{bootstrap:?}");
        let login_debug = format!("{login:?}");
        assert!(!bootstrap_debug.contains("raw-bootstrap-secret"));
        assert!(!bootstrap_debug.contains("raw-password-secret"));
        assert!(!login_debug.contains("raw-password-secret"));
        assert!(bootstrap_debug.contains("[REDACTED]"));
        assert!(login_debug.contains("[REDACTED]"));
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

    #[test]
    fn bounded_event_page_contract_keeps_all_cursor_fields() {
        let run_page = RunEventPage {
            items: Vec::new(),
            next_after: None,
            head_sequence: 0,
            has_more: false,
        };
        let session_page = SessionEventPage {
            items: Vec::new(),
            next_after: None,
            head_sequence: 0,
            has_more: false,
        };

        assert_eq!(
            serde_json::to_value(run_page).unwrap(),
            json!({
                "items": [],
                "next_after": null,
                "head_sequence": 0,
                "has_more": false,
            })
        );
        assert_eq!(
            serde_json::to_value(session_page).unwrap(),
            json!({
                "items": [],
                "next_after": null,
                "head_sequence": 0,
                "has_more": false,
            })
        );
        assert_eq!(EVENT_PAGE_DEFAULT_LIMIT, 128);
        assert_eq!(EVENT_PAGE_MAX_LIMIT, 256);
    }
}
