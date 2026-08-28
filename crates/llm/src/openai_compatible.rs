//! Bounded OpenAI-compatible Chat Completions provider.

use std::{fmt::Write as _, net::IpAddr, sync::Arc, time::Duration};

use reqwest::{
    Client, Url,
    header::{AUTHORIZATION, HeaderValue},
    redirect::Policy,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    ProviderError, ProviderMetadata, REPLY_STREAM_TEXT_DELTA_MAX_BYTES,
    REPLY_TOOL_ARGUMENTS_MAX_BYTES, ReplyFuture, ReplyKind, ReplyMessage, ReplyOutput,
    ReplyProvider, ReplyRequest, ReplyResponse, ReplyRole, ReplyStream, ReplyStreamEvent,
    ReplyToolCall, ReplyToolDefinition, SecretRef, SecretResolveError, SecretResolver,
    validate_provider_metadata, validate_reply_request, validate_reply_response_for_request,
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
    api_key: ApiKeySource,
    model: String,
    max_response_bytes: usize,
    metadata: ProviderMetadata,
}

enum ApiKeySource {
    Inline(HeaderValue),
    SecretRef {
        reference: SecretRef,
        resolver: Arc<dyn SecretResolver>,
    },
}

impl ApiKeySource {
    fn secret_ref(&self) -> Option<&SecretRef> {
        match self {
            Self::Inline(_) => None,
            Self::SecretRef { reference, .. } => Some(reference),
        }
    }
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
        let api_key = Zeroizing::new(api_key.into());
        let authorization = authorization_header(api_key.as_str())?;
        Self::with_api_key_source(
            endpoint,
            model,
            ApiKeySource::Inline(authorization),
            timeout,
            max_response_bytes,
        )
    }

    /// Construct a provider that resolves its API key for every operation.
    /// The non-secret reference participates in durable provider identity,
    /// while rotating the value behind the same reference does not.
    pub fn with_secret_resolver(
        endpoint: impl Into<String>,
        model: impl Into<String>,
        secret_ref: SecretRef,
        resolver: Arc<dyn SecretResolver>,
    ) -> Result<Self, ProviderError> {
        Self::with_secret_resolver_and_limits(
            endpoint,
            model,
            secret_ref,
            resolver,
            DEFAULT_REQUEST_TIMEOUT,
            DEFAULT_MAX_RESPONSE_BYTES,
        )
    }

    pub fn with_secret_resolver_and_limits(
        endpoint: impl Into<String>,
        model: impl Into<String>,
        secret_ref: SecretRef,
        resolver: Arc<dyn SecretResolver>,
        timeout: Duration,
        max_response_bytes: usize,
    ) -> Result<Self, ProviderError> {
        Self::with_api_key_source(
            endpoint,
            model,
            ApiKeySource::SecretRef {
                reference: secret_ref,
                resolver,
            },
            timeout,
            max_response_bytes,
        )
    }

    fn with_api_key_source(
        endpoint: impl Into<String>,
        model: impl Into<String>,
        api_key: ApiKeySource,
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
        let client = Client::builder()
            .redirect(Policy::none())
            .connect_timeout(timeout.min(MAX_CONNECT_TIMEOUT))
            .timeout(timeout)
            .build()
            .map_err(|_| ProviderError::InvalidConfiguration("HTTP client could not be built"))?;
        let metadata = ProviderMetadata {
            provider_id: configuration_provider_id(
                &endpoint,
                &model,
                timeout,
                max_response_bytes,
                api_key.secret_ref(),
            ),
            model: Some(model.clone()),
            reply_kind: ReplyKind::Model,
        };
        validate_provider_metadata(&metadata)?;

        Ok(Self {
            client,
            endpoint,
            api_key,
            model,
            max_response_bytes,
            metadata,
        })
    }

    /// Return the configured non-secret credential reference, if this provider
    /// resolves credentials per operation.
    pub fn secret_ref(&self) -> Option<&SecretRef> {
        self.api_key.secret_ref()
    }

    /// Resolve and validate the current credential without sending a provider
    /// request. Startup uses this to fail before opening durable state.
    pub async fn validate_secret_source(&self) -> Result<(), ProviderError> {
        self.authorization_header().await.map(drop)
    }

    async fn authorization_header(&self) -> Result<HeaderValue, ProviderError> {
        match &self.api_key {
            ApiKeySource::Inline(authorization) => Ok(authorization.clone()),
            ApiKeySource::SecretRef {
                reference,
                resolver,
            } => {
                let secret = resolver
                    .resolve(reference)
                    .await
                    .map_err(|error| match error {
                        SecretResolveError::Unavailable => ProviderError::SecretUnavailable,
                    })?;
                authorization_header(secret.expose_secret())
            }
        }
    }

    async fn request(&self, request: ReplyRequest) -> Result<ReplyResponse, ProviderError> {
        validate_reply_request(&request)?;
        let messages = request
            .messages
            .iter()
            .map(ChatCompletionRequestMessage::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let tools = request
            .tools
            .iter()
            .map(ChatCompletionToolDefinition::from)
            .collect::<Vec<_>>();
        let wire_request = ChatCompletionRequest {
            model: &self.model,
            messages,
            tool_choice: (!tools.is_empty()).then_some("auto"),
            tools,
            stream: false,
        };
        let authorization = self.authorization_header().await?;
        let response = self
            .client
            .post(self.endpoint.clone())
            .header(AUTHORIZATION, authorization)
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
        let output = decode_output(choice.message)?;
        let response = ReplyResponse {
            output,
            finish_reason: choice.finish_reason,
            provider: self.metadata.clone(),
        };
        validate_reply_response_for_request(&request, &response)?;
        Ok(response)
    }

    fn request_stream(&self, request: ReplyRequest) -> ReplyStream<'_> {
        Box::pin(async_stream::try_stream! {
            validate_reply_request(&request)?;
            let messages = request
                .messages
                .iter()
                .map(ChatCompletionRequestMessage::try_from)
                .collect::<Result<Vec<_>, _>>()?;
            let tools = request
                .tools
                .iter()
                .map(ChatCompletionToolDefinition::from)
                .collect::<Vec<_>>();
            let wire_request = ChatCompletionRequest {
                model: &self.model,
                messages,
                tool_choice: (!tools.is_empty()).then_some("auto"),
                tools,
                stream: true,
            };
            let authorization = self.authorization_header().await?;
            let response = self
                .client
                .post(self.endpoint.clone())
                .header(AUTHORIZATION, authorization)
                .json(&wire_request)
                .send()
                .await
                .map_err(map_transport_error)?;
            let status = response.status();
            if !status.is_success() {
                Err(ProviderError::HttpStatus { status: status.as_u16() })?;
            }
            if response
                .content_length()
                .is_some_and(|length| length > self.max_response_bytes as u64)
            {
                Err(ProviderError::ResponseTooLarge {
                    limit_bytes: self.max_response_bytes,
                })?;
            }

            let mut response = response;
            let mut pending = Vec::new();
            let mut received_bytes = 0usize;
            let mut accumulator = ChatCompletionStreamAccumulator::default();
            let mut done = false;
            while let Some(chunk) = response.chunk().await.map_err(map_transport_error)? {
                received_bytes = received_bytes
                    .checked_add(chunk.len())
                    .ok_or(ProviderError::ResponseTooLarge {
                        limit_bytes: self.max_response_bytes,
                    })?;
                if received_bytes > self.max_response_bytes {
                    Err(ProviderError::ResponseTooLarge {
                        limit_bytes: self.max_response_bytes,
                    })?;
                }
                pending.extend_from_slice(&chunk);
                while let Some(newline) = pending.iter().position(|byte| *byte == b'\n') {
                    let mut line = pending.drain(..=newline).collect::<Vec<_>>();
                    line.pop();
                    if line.last() == Some(&b'\r') {
                        line.pop();
                    }
                    let line = std::str::from_utf8(&line)
                        .map_err(|_| ProviderError::InvalidResponse)?;
                    let data = match line.strip_prefix("data:") {
                        Some(data) => data,
                        None
                            if line.is_empty()
                                || line.starts_with(':')
                                || line.starts_with("event:")
                                || line.starts_with("id:")
                                || line.starts_with("retry:") =>
                        {
                            continue;
                        }
                        None => Err(ProviderError::InvalidResponse)?,
                    };
                    let data = data.strip_prefix(' ').unwrap_or(data);
                    if data == "[DONE]" {
                        done = true;
                        break;
                    }
                    let event: ChatCompletionStreamResponse =
                        serde_json::from_str(data).map_err(|_| ProviderError::InvalidResponse)?;
                    if let Some(delta) = accumulator.apply(event)? {
                        yield ReplyStreamEvent::TextDelta(delta);
                    }
                }
                if done {
                    break;
                }
            }
            if !done || !pending.iter().all(u8::is_ascii_whitespace) {
                Err(ProviderError::Transport)?;
            }
            let completed = accumulator.finish(self.metadata.clone())?;
            validate_reply_response_for_request(&request, &completed)?;
            yield ReplyStreamEvent::Completed(completed);
        })
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

fn authorization_header(api_key: &str) -> Result<HeaderValue, ProviderError> {
    if api_key.trim().is_empty() {
        return Err(ProviderError::InvalidConfiguration(
            "API key must not be blank",
        ));
    }
    let bearer = Zeroizing::new(format!("Bearer {api_key}"));
    let mut authorization = HeaderValue::from_str(bearer.as_str())
        .map_err(|_| ProviderError::InvalidConfiguration("API key is not header-safe"))?;
    authorization.set_sensitive(true);
    Ok(authorization)
}

fn configuration_provider_id(
    endpoint: &Url,
    model: &str,
    timeout: Duration,
    max_response_bytes: usize,
    secret_ref: Option<&SecretRef>,
) -> String {
    let mut digest = Sha256::new();
    digest.update(if secret_ref.is_some() {
        b"zeus:openai-compatible-config:v2\0".as_slice()
    } else {
        b"zeus:openai-compatible-config:v1\0".as_slice()
    });
    update_digest_field(&mut digest, endpoint.as_str().as_bytes());
    update_digest_field(&mut digest, model.as_bytes());
    update_digest_field(&mut digest, &timeout.as_nanos().to_le_bytes());
    update_digest_field(
        &mut digest,
        &u64::try_from(max_response_bytes)
            .expect("the configured response limit is bounded below u64::MAX")
            .to_le_bytes(),
    );
    if let Some(secret_ref) = secret_ref {
        update_digest_field(&mut digest, secret_ref.as_str().as_bytes());
    }
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

    fn stream_reply(&self, request: ReplyRequest) -> ReplyStream<'_> {
        self.request_stream(request)
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
    messages: Vec<ChatCompletionRequestMessage<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<ChatCompletionToolDefinition<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_choice: Option<&'static str>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    stream: bool,
}

#[derive(Serialize)]
struct ChatCompletionRequestMessage<'a> {
    role: &'static str,
    content: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_calls: Option<Vec<ChatCompletionRequestToolCall<'a>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<&'a str>,
}

impl<'a> TryFrom<&'a ReplyMessage> for ChatCompletionRequestMessage<'a> {
    type Error = ProviderError;

    fn try_from(message: &'a ReplyMessage) -> Result<Self, Self::Error> {
        let (role, content, tool_calls, tool_call_id) = match message.role {
            ReplyRole::System => ("system", Some(message.content.as_str()), None, None),
            ReplyRole::User => ("user", Some(message.content.as_str()), None, None),
            ReplyRole::Checkpoint => ("user", Some(message.content.as_str()), None, None),
            ReplyRole::Context => ("user", Some(message.content.as_str()), None, None),
            ReplyRole::Assistant => {
                if let Some(call) = &message.tool_call {
                    (
                        "assistant",
                        None,
                        Some(vec![ChatCompletionRequestToolCall::try_from(call)?]),
                        None,
                    )
                } else {
                    ("assistant", Some(message.content.as_str()), None, None)
                }
            }
            ReplyRole::Tool => (
                "tool",
                Some(message.content.as_str()),
                None,
                message.tool_call_id.as_deref(),
            ),
        };
        Ok(Self {
            role,
            content,
            tool_calls,
            tool_call_id,
        })
    }
}

#[derive(Serialize)]
struct ChatCompletionRequestToolCall<'a> {
    id: &'a str,
    #[serde(rename = "type")]
    kind: &'static str,
    function: ChatCompletionRequestFunction<'a>,
}

impl<'a> TryFrom<&'a ReplyToolCall> for ChatCompletionRequestToolCall<'a> {
    type Error = ProviderError;

    fn try_from(call: &'a ReplyToolCall) -> Result<Self, Self::Error> {
        Ok(Self {
            id: &call.id,
            kind: "function",
            function: ChatCompletionRequestFunction {
                name: &call.name,
                arguments: serde_json::to_string(&call.arguments)
                    .map_err(|_| ProviderError::InvalidRequest("invalid tool call arguments"))?,
            },
        })
    }
}

#[derive(Serialize)]
struct ChatCompletionRequestFunction<'a> {
    name: &'a str,
    arguments: String,
}

#[derive(Serialize)]
struct ChatCompletionToolDefinition<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    function: ChatCompletionFunctionDefinition<'a>,
}

impl<'a> From<&'a ReplyToolDefinition> for ChatCompletionToolDefinition<'a> {
    fn from(tool: &'a ReplyToolDefinition) -> Self {
        Self {
            kind: "function",
            function: ChatCompletionFunctionDefinition {
                name: &tool.name,
                description: tool.description.as_deref(),
                parameters: &tool.parameters,
            },
        }
    }
}

#[derive(Serialize)]
struct ChatCompletionFunctionDefinition<'a> {
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
    parameters: &'a serde_json::Value,
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
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Vec<ChatCompletionResponseToolCall>,
}

#[derive(Deserialize)]
struct ChatCompletionResponseToolCall {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    function: ChatCompletionResponseFunction,
}

#[derive(Deserialize)]
struct ChatCompletionResponseFunction {
    name: String,
    arguments: String,
}

#[derive(Deserialize)]
struct ChatCompletionStreamResponse {
    choices: Vec<ChatCompletionStreamChoice>,
}

#[derive(Deserialize)]
struct ChatCompletionStreamChoice {
    #[serde(default)]
    index: u32,
    delta: ChatCompletionStreamDelta,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Default, Deserialize)]
struct ChatCompletionStreamDelta {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Vec<ChatCompletionStreamToolCall>,
}

#[derive(Deserialize)]
struct ChatCompletionStreamToolCall {
    #[serde(default)]
    index: u32,
    #[serde(default)]
    id: Option<String>,
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    function: Option<ChatCompletionStreamFunction>,
}

#[derive(Default, Deserialize)]
struct ChatCompletionStreamFunction {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    arguments: Option<String>,
}

#[derive(Default)]
struct ChatCompletionStreamAccumulator {
    text: String,
    tool_id: String,
    tool_name: String,
    tool_arguments: String,
    finish_reason: Option<String>,
    saw_text: bool,
    saw_tool: bool,
    saw_finish: bool,
}

impl ChatCompletionStreamAccumulator {
    fn apply(
        &mut self,
        response: ChatCompletionStreamResponse,
    ) -> Result<Option<String>, ProviderError> {
        if response.choices.is_empty() {
            return Ok(None);
        }
        if response.choices.len() != 1 {
            return Err(ProviderError::InvalidResponse);
        }
        let choice = response
            .choices
            .into_iter()
            .next()
            .expect("one streaming choice was checked above");
        if choice.index != 0 || self.saw_finish {
            return Err(ProviderError::InvalidResponse);
        }
        if let Some(reason) = choice.finish_reason {
            if reason.is_empty() || self.finish_reason.replace(reason).is_some() {
                return Err(ProviderError::InvalidResponse);
            }
            self.saw_finish = true;
        }
        let mut emitted = None;
        if let Some(content) = choice.delta.content.filter(|content| !content.is_empty()) {
            if self.saw_tool || content.len() > REPLY_STREAM_TEXT_DELTA_MAX_BYTES {
                return Err(ProviderError::InvalidResponse);
            }
            self.saw_text = true;
            let next_len = self
                .text
                .len()
                .checked_add(content.len())
                .ok_or(ProviderError::InvalidResponse)?;
            if next_len > protocol::ASSISTANT_MESSAGE_MAX_BYTES {
                return Err(ProviderError::TerminalPayloadTooLarge {
                    limit_bytes: protocol::ASSISTANT_MESSAGE_MAX_BYTES,
                });
            }
            self.text.push_str(&content);
            emitted = Some(content);
        }
        if !choice.delta.tool_calls.is_empty() {
            if self.saw_text || choice.delta.tool_calls.len() != 1 {
                return Err(ProviderError::InvalidResponse);
            }
            self.saw_tool = true;
            let call = choice
                .delta
                .tool_calls
                .into_iter()
                .next()
                .expect("one streaming tool call was checked above");
            if call.index != 0 || call.kind.as_deref().is_some_and(|kind| kind != "function") {
                return Err(ProviderError::InvalidResponse);
            }
            if let Some(id) = call.id {
                if (!self.tool_id.is_empty() && self.tool_id != id)
                    || id.len() > crate::REPLY_TOOL_CALL_ID_MAX_BYTES
                {
                    return Err(ProviderError::InvalidResponse);
                }
                self.tool_id = id;
            }
            if let Some(function) = call.function {
                if let Some(name) = function.name {
                    self.tool_name.push_str(&name);
                    if self.tool_name.len() > crate::REPLY_TOOL_NAME_MAX_BYTES {
                        return Err(ProviderError::InvalidResponse);
                    }
                }
                if let Some(arguments) = function.arguments {
                    self.tool_arguments.push_str(&arguments);
                    if self.tool_arguments.len() > REPLY_TOOL_ARGUMENTS_MAX_BYTES {
                        return Err(ProviderError::InvalidResponse);
                    }
                }
            }
        }
        Ok(emitted)
    }

    fn finish(self, metadata: ProviderMetadata) -> Result<ReplyResponse, ProviderError> {
        if !self.saw_finish || self.saw_text == self.saw_tool {
            return Err(ProviderError::InvalidResponse);
        }
        let output = if self.saw_text {
            if self.text.trim().is_empty() {
                return Err(ProviderError::InvalidResponse);
            }
            ReplyOutput::Final { content: self.text }
        } else {
            if self.tool_id.is_empty() || self.tool_name.is_empty() {
                return Err(ProviderError::InvalidResponse);
            }
            let arguments = serde_json::from_str(&self.tool_arguments)
                .map_err(|_| ProviderError::InvalidResponse)?;
            ReplyOutput::ToolCall {
                call: ReplyToolCall::new(self.tool_id, self.tool_name, arguments),
            }
        };
        Ok(ReplyResponse {
            output,
            finish_reason: self.finish_reason,
            provider: metadata,
        })
    }
}

fn decode_output(message: ChatCompletionMessage) -> Result<ReplyOutput, ProviderError> {
    if message.tool_calls.is_empty() {
        let content = message.content.ok_or(ProviderError::InvalidResponse)?;
        if content.trim().is_empty() {
            return Err(ProviderError::InvalidResponse);
        }
        return Ok(ReplyOutput::Final { content });
    }
    if message.tool_calls.len() != 1
        || message
            .content
            .as_ref()
            .is_some_and(|content| !content.is_empty())
    {
        return Err(ProviderError::InvalidResponse);
    }
    let call = message
        .tool_calls
        .into_iter()
        .next()
        .expect("the single tool call was checked above");
    if call.kind != "function" || call.function.arguments.len() > REPLY_TOOL_ARGUMENTS_MAX_BYTES {
        return Err(ProviderError::InvalidResponse);
    }
    let arguments = serde_json::from_str(&call.function.arguments)
        .map_err(|_| ProviderError::InvalidResponse)?;
    Ok(ReplyOutput::ToolCall {
        call: ReplyToolCall::new(call.id, call.function.name, arguments),
    })
}
