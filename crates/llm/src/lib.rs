//! Reply-provider boundary for Zeus Harness.
//!
//! Providers admit a complete message list and return one text reply. A
//! provider failure is never converted into a successful fallback reply: the
//! caller must select [`LocalFallbackProvider`] explicitly when it wants the
//! non-model experience.

mod openai_compatible;

use std::{future::Future, pin::Pin};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use openai_compatible::{
    DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_REQUEST_TIMEOUT, OpenAiCompatibleProvider,
};

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

    fn reply(&self, _request: ReplyRequest) -> ReplyFuture<'_> {
        let provider = self.metadata.clone();
        Box::pin(async move {
            Ok(ReplyResponse {
                content: "Your message was saved, but no model provider is configured.".to_owned(),
                finish_reason: Some("local_fallback".to_owned()),
                provider,
            })
        })
    }
}
