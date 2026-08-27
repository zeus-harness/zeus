//! Bounded OpenAI-compatible Chat Completions provider.

use std::{fmt::Write as _, net::IpAddr, time::Duration};

use reqwest::{
    Client, Url,
    header::{AUTHORIZATION, HeaderValue},
    redirect::Policy,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    ProviderError, ProviderMetadata, ReplyFuture, ReplyKind, ReplyMessage, ReplyProvider,
    ReplyRequest, ReplyResponse, validate_provider_metadata, validate_reply_request,
    validate_reply_response,
};

/// Default deadline for connection, upload, and response download.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Default maximum Chat Completions response body.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 1024 * 1024;

const MAX_CONFIGURABLE_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_CONFIGURABLE_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// OpenAI-compatible `/chat/completions` provider.
///
/// `endpoint` is the complete Chat Completions URL. Redirects are disabled,
/// the complete operation has a deadline, and response bytes are bounded
/// before JSON parsing. Provider failures never select another provider.
pub struct OpenAiCompatibleProvider {
    client: Client,
    endpoint: Url,
    authorization: HeaderValue,
    model: String,
    max_response_bytes: usize,
    metadata: ProviderMetadata,
}

impl OpenAiCompatibleProvider {
    /// Construct a provider with production defaults.
    pub fn new(
        endpoint: impl Into<String>,
        model: impl Into<String>,
        api_key: impl Into<String>,
    ) -> Result<Self, ProviderError> {
        Self::with_limits(
            endpoint,
            model,
            api_key,
            DEFAULT_REQUEST_TIMEOUT,
            DEFAULT_MAX_RESPONSE_BYTES,
        )
    }

    /// Construct a provider with explicit bounded limits.
    ///
    /// This is primarily useful for deployments with a tighter latency or
    /// memory budget and for deterministic contract tests. It refuses values
    /// that would remove the boundary or exceed its absolute ceiling.
    pub fn with_limits(
        endpoint: impl Into<String>,
        model: impl Into<String>,
        api_key: impl Into<String>,
        timeout: Duration,
        max_response_bytes: usize,
    ) -> Result<Self, ProviderError> {
        if timeout.is_zero() || timeout > MAX_CONFIGURABLE_TIMEOUT {
            return Err(ProviderError::InvalidConfiguration(
                "timeout must be between 1ns and 120s",
            ));
        }
        if max_response_bytes == 0 || max_response_bytes > MAX_CONFIGURABLE_RESPONSE_BYTES {
            return Err(ProviderError::InvalidConfiguration(
                "response limit must be between 1 byte and 8 MiB",
            ));
        }

        let endpoint = Url::parse(&endpoint.into())
            .map_err(|_| ProviderError::InvalidConfiguration("endpoint must be a valid URL"))?;
        if !matches!(endpoint.scheme(), "http" | "https") {
            return Err(ProviderError::InvalidConfiguration(
                "endpoint scheme must be http or https",
            ));
        }
        if endpoint.scheme() == "http" && !endpoint_is_loopback(&endpoint) {
            return Err(ProviderError::InvalidConfiguration(
                "plain HTTP endpoints must use a loopback host",
            ));
        }
        if !endpoint.username().is_empty() || endpoint.password().is_some() {
            return Err(ProviderError::InvalidConfiguration(
                "endpoint must not contain credentials",
            ));
        }

        let model = model.into();
        let api_key = Zeroizing::new(api_key.into());
        if api_key.trim().is_empty() {
            return Err(ProviderError::InvalidConfiguration(
                "API key must not be blank",
            ));
        }
        let bearer = Zeroizing::new(format!("Bearer {}", api_key.as_str()));
        let mut authorization = HeaderValue::from_str(bearer.as_str())
            .map_err(|_| ProviderError::InvalidConfiguration("API key is not header-safe"))?;
        authorization.set_sensitive(true);

        let client = Client::builder()
            .redirect(Policy::none())
            .connect_timeout(timeout.min(MAX_CONNECT_TIMEOUT))
            .timeout(timeout)
            .build()
            .map_err(|_| ProviderError::InvalidConfiguration("HTTP client could not be built"))?;
        let metadata = ProviderMetadata {
            provider_id: configuration_provider_id(&endpoint, &model, timeout, max_response_bytes),
            model: Some(model.clone()),
            reply_kind: ReplyKind::Model,
        };
        validate_provider_metadata(&metadata)?;

        Ok(Self {
            client,
            endpoint,
            authorization,
            model,
            max_response_bytes,
            metadata,
        })
    }

    async fn request(&self, request: ReplyRequest) -> Result<ReplyResponse, ProviderError> {
        validate_reply_request(&request)?;
        let wire_request = ChatCompletionRequest {
            model: &self.model,
            messages: &request.messages,
        };
        let response = self
            .client
            .post(self.endpoint.clone())
            .header(AUTHORIZATION, self.authorization.clone())
            .json(&wire_request)
            .send()
            .await
            .map_err(map_transport_error)?;

        let status = response.status();
        if !status.is_success() {
            return Err(ProviderError::HttpStatus {
                status: status.as_u16(),
            });
        }
        if response
            .content_length()
            .is_some_and(|length| length > self.max_response_bytes as u64)
        {
            return Err(ProviderError::ResponseTooLarge {
                limit_bytes: self.max_response_bytes,
            });
        }

        let mut response = response;
        let mut body = Zeroizing::new(Vec::with_capacity(
            response
                .content_length()
                .unwrap_or(0)
                .min(self.max_response_bytes as u64) as usize,
        ));
        while let Some(chunk) = response.chunk().await.map_err(map_transport_error)? {
            let next_len =
                body.len()
                    .checked_add(chunk.len())
                    .ok_or(ProviderError::ResponseTooLarge {
                        limit_bytes: self.max_response_bytes,
                    })?;
            if next_len > self.max_response_bytes {
                return Err(ProviderError::ResponseTooLarge {
                    limit_bytes: self.max_response_bytes,
                });
            }
            body.extend_from_slice(&chunk);
        }

        let decoded: ChatCompletionResponse =
            serde_json::from_slice(&body).map_err(|_| ProviderError::InvalidResponse)?;
        let choice = decoded
            .choices
            .into_iter()
            .next()
            .ok_or(ProviderError::InvalidResponse)?;
        if choice.message.content.trim().is_empty() {
            return Err(ProviderError::InvalidResponse);
        }
        let response = ReplyResponse {
            content: choice.message.content,
            finish_reason: choice.finish_reason,
            provider: self.metadata.clone(),
        };
        validate_reply_response(&response)?;
        Ok(response)
    }
}

fn endpoint_is_loopback(endpoint: &Url) -> bool {
    endpoint.host_str().is_some_and(|host| {
        if host.eq_ignore_ascii_case("localhost") {
            return true;
        }
        let host = host.trim_start_matches('[').trim_end_matches(']');
        host.parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
    })
}

fn configuration_provider_id(
    endpoint: &Url,
    model: &str,
    timeout: Duration,
    max_response_bytes: usize,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"zeus:openai-compatible-config:v1\0");
    update_digest_field(&mut digest, endpoint.as_str().as_bytes());
    update_digest_field(&mut digest, model.as_bytes());
    update_digest_field(&mut digest, &timeout.as_nanos().to_le_bytes());
    update_digest_field(
        &mut digest,
        &u64::try_from(max_response_bytes)
            .expect("the configured response limit is bounded below u64::MAX")
            .to_le_bytes(),
    );
    let digest = digest.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing hexadecimal to a String cannot fail");
    }
    format!("openai-compatible:{encoded}")
}

fn update_digest_field(digest: &mut Sha256, value: &[u8]) {
    digest.update(
        u64::try_from(value.len())
            .expect("provider configuration fields fit in u64")
            .to_le_bytes(),
    );
    digest.update(value);
}

impl ReplyProvider for OpenAiCompatibleProvider {
    fn metadata(&self) -> &ProviderMetadata {
        &self.metadata
    }

    fn reply(&self, request: ReplyRequest) -> ReplyFuture<'_> {
        Box::pin(self.request(request))
    }
}

fn map_transport_error(error: reqwest::Error) -> ProviderError {
    if error.is_timeout() {
        ProviderError::Timeout
    } else {
        ProviderError::Transport
    }
}

#[derive(Serialize)]
struct ChatCompletionRequest<'a> {
    model: &'a str,
    messages: &'a [ReplyMessage],
}

#[derive(Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<ChatCompletionChoice>,
}

#[derive(Deserialize)]
struct ChatCompletionChoice {
    message: ChatCompletionMessage,
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct ChatCompletionMessage {
    content: String,
}
