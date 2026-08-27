//! Reply-provider boundary for Zeus Harness.
//!
//! Providers admit a complete message list and return one text reply. A
//! provider failure is never converted into a successful fallback reply: the
//! caller must select [`LocalFallbackProvider`] explicitly when it wants the
//! non-model experience.

mod openai_compatible;

use std::{future::Future, pin::Pin};

use protocol::{SessionTurn, SessionTurnStatus};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use openai_compatible::{
    DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_REQUEST_TIMEOUT, OpenAiCompatibleProvider,
};

/// Maximum serialized size of a typed reply admitted to durable storage.
pub const REPLY_RESPONSE_MAX_SERIALIZED_BYTES: usize = 512 * 1024;
/// Maximum number of ordered messages in one durable provider request.
pub const REPLY_REQUEST_MAX_MESSAGES: usize = 64;
/// Maximum number of complete historical user/assistant pairs in one request.
pub const REPLY_REQUEST_MAX_HISTORY_PAIRS: usize = (REPLY_REQUEST_MAX_MESSAGES - 1) / 2;
/// Maximum aggregate UTF-8 content admitted to one durable provider request.
pub const REPLY_REQUEST_MAX_CONTENT_BYTES: usize = protocol::USER_MESSAGE_MAX_BYTES;
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
}

/// One ordered message in a reply request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyMessage {
    /// Message role.
    pub role: ReplyRole,
    /// Plain text content sent to the selected provider.
    pub content: String,
}

impl ReplyMessage {
    /// Construct a message with the supplied role and text.
    pub fn new(role: ReplyRole, content: impl Into<String>) -> Self {
        Self {
            role,
            content: content.into(),
        }
    }
}

/// Complete ordered context for one provider reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyRequest {
    /// Messages in provider-visible order.
    pub messages: Vec<ReplyMessage>,
}

impl ReplyRequest {
    /// Construct a request from ordered messages.
    pub fn new(messages: impl IntoIterator<Item = ReplyMessage>) -> Self {
        Self {
            messages: messages.into_iter().collect(),
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
        let user_message = user_message.into();
        protocol::validate_user_message(&user_message)
            .map_err(|_| ProviderError::InvalidRequest("invalid user message"))?;

        let mut retained = Vec::new();
        let mut content_bytes = user_message.len();
        for turn in turns.iter().rev() {
            if retained.len() >= REPLY_REQUEST_MAX_HISTORY_PAIRS {
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
            if next_bytes > REPLY_REQUEST_MAX_CONTENT_BYTES {
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
        let request = Self { messages };
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

/// One accepted provider reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyResponse {
    /// Assistant text to append to the Session ledger.
    pub content: String,
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

    let conversation_start = usize::from(
        request
            .messages
            .first()
            .is_some_and(|message| message.role == ReplyRole::System),
    );
    let conversation = &request.messages[conversation_start..];
    if conversation.is_empty() || conversation.len().is_multiple_of(2) {
        return Err(ProviderError::InvalidRequest(
            "request must end with a user message",
        ));
    }
    for (index, message) in conversation.iter().enumerate() {
        let expected = if index.is_multiple_of(2) {
            ReplyRole::User
        } else {
            ReplyRole::Assistant
        };
        if message.role != expected {
            return Err(ProviderError::InvalidRequest(
                "request roles must alternate user and assistant",
            ));
        }
    }

    let mut total_bytes = 0usize;
    for message in &request.messages {
        let valid = match message.role {
            ReplyRole::Assistant => protocol::validate_assistant_message(&message.content),
            ReplyRole::System | ReplyRole::User => {
                protocol::validate_user_message(&message.content)
            }
        };
        if valid.is_err() {
            return Err(ProviderError::InvalidRequest("invalid message content"));
        }
        total_bytes =
            total_bytes
                .checked_add(message.content.len())
                .ok_or(ProviderError::InvalidRequest(
                    "request content is too large",
                ))?;
        if total_bytes > REPLY_REQUEST_MAX_CONTENT_BYTES {
            return Err(ProviderError::InvalidRequest(
                "request content is too large",
            ));
        }
    }
    Ok(())
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
    match protocol::validate_assistant_message(&response.content) {
        Ok(()) => {}
        Err(protocol::ResourceEnvelopeError::TooLong { .. }) => {
            return Err(ProviderError::TerminalPayloadTooLarge {
                limit_bytes: protocol::ASSISTANT_MESSAGE_MAX_BYTES,
            });
        }
        Err(_) => return Err(ProviderError::InvalidResponse),
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
                content: "Your message was saved, but no model provider is configured.".to_owned(),
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
            content,
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
}
