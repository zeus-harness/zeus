use std::{fmt, time::Duration};

use eventsource_stream::{EventStreamError, Eventsource};
use futures_util::StreamExt;
use reqwest::{
    Client, StatusCode, Url,
    header::{AUTHORIZATION, HeaderValue, RETRY_AFTER},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeus_core::{ModelMessage, TokenUsage, ToolCall};

/// Default deadline for one Chat Completions request.
pub const DEFAULT_MODEL_TIMEOUT: Duration = Duration::from_mins(1);

const MAX_TOOL_CALLS: usize = 128;

/// Stable failures returned by the model adapter.
///
/// The variants deliberately do not retain provider response bodies or
/// transport errors. That keeps provider details out of durable errors and
/// makes retry decisions independent of provider-specific error text.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("invalid model configuration")]
    InvalidConfiguration,
    #[error("model request was canceled")]
    Canceled,
    #[error("model request timed out")]
    Timeout,
    #[error("model provider rate limited the request")]
    RateLimited { retry_after: Option<Duration> },
    #[error("model provider returned server status {status}")]
    Server { status: u16 },
    #[error("model provider rejected the request with status {status}")]
    HttpStatus { status: u16 },
    #[error("model provider returned an invalid response")]
    InvalidResponse,
    #[error("model response stream was interrupted")]
    StreamInterrupted,
    #[error("model transport failed")]
    Transport,
}

impl ModelError {
    /// Whether retrying the same model request can reasonably succeed later.
    #[must_use]
    pub const fn is_transient(&self) -> bool {
        match self {
            Self::RateLimited { .. }
            | Self::Server { .. }
            | Self::Timeout
            | Self::StreamInterrupted
            | Self::Transport => true,
            Self::HttpStatus { status } => matches!(*status, 408 | 425),
            Self::InvalidConfiguration | Self::Canceled | Self::InvalidResponse => false,
        }
    }

    /// Alias for callers whose retry policy uses the term “retryable”.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        self.is_transient()
    }
}

/// A server-defined Capability exposed as an `OpenAI` function tool.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: Value,
}

impl ToolDefinition {
    #[must_use]
    pub fn new(name: impl Into<String>, description: impl Into<String>, parameters: Value) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            parameters,
        }
    }
}

/// Names used by older call sites for the same wire-level tool definition.
pub type ModelToolDefinition = ToolDefinition;
pub type OpenAiToolDefinition = ToolDefinition;

/// The complete assistant result collected from a streamed response.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModelCompletion {
    pub assistant_text: String,
    pub tool_calls: Vec<ToolCall>,
    pub usage: TokenUsage,
    pub provider_request_id: String,
}

pub type ModelResponse = ModelCompletion;

/// Minimal OpenAI-compatible Chat Completions adapter.
///
/// The API key is write-only from this type: it is accepted by the
/// constructor and used to build an Authorization header, but there is no
/// accessor or serialization path for it.
#[derive(Clone)]
pub struct OpenAiCompatibleAdapter {
    client: Client,
    endpoint: Url,
    model: String,
    api_key: SecretString,
    configuration: Value,
}

impl fmt::Debug for OpenAiCompatibleAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAiCompatibleAdapter")
            .field("endpoint", &self.endpoint)
            .field("model", &self.model)
            .field("configuration", &self.configuration)
            .finish_non_exhaustive()
    }
}

pub type OpenAiCompatibleModel = OpenAiCompatibleAdapter;

impl OpenAiCompatibleAdapter {
    /// Constructs an adapter from a base URL such as `https://api.example/v1`.
    /// The `/chat/completions` path is appended unless it is already present.
    ///
    /// `timeout_ms`, `request_timeout_ms`, and `timeout_seconds` are local
    /// configuration keys. Other configuration keys are passed through to
    /// the Chat Completions request.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid URL, model, API key, or configuration.
    pub fn new(
        base_url: impl AsRef<str>,
        model: impl Into<String>,
        api_key: impl Into<SecretString>,
        configuration: Value,
    ) -> Result<Self, ModelError> {
        let endpoint = chat_completions_endpoint(base_url.as_ref())?;
        let model = model.into();
        if model.trim().is_empty() {
            return Err(ModelError::InvalidConfiguration);
        }

        let Value::Object(configuration) = configuration else {
            return Err(ModelError::InvalidConfiguration);
        };
        let timeout = configured_timeout(&configuration)?;
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(timeout)
            .timeout(timeout)
            .build()
            .map_err(|_| ModelError::InvalidConfiguration)?;
        let api_key = api_key.into();
        authorization_header(&api_key)?;

        Ok(Self {
            client,
            endpoint,
            model,
            api_key,
            configuration: Value::Object(configuration),
        })
    }

    #[must_use]
    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    #[must_use]
    pub fn configuration(&self) -> &Value {
        &self.configuration
    }

    /// Sends one streamed Chat Completions request and collects its result.
    ///
    /// # Errors
    ///
    /// Returns a stable model error when the request, provider, or stream fails.
    pub async fn complete(
        &self,
        messages: &[ModelMessage],
        tools: &[ToolDefinition],
        cancellation: CancellationToken,
    ) -> Result<ModelCompletion, ModelError> {
        self.complete_with_cancellation(messages, tools, &cancellation)
            .await
    }

    /// Reference-based form for callers that own a shared cancellation token.
    ///
    /// # Errors
    ///
    /// Returns a stable model error when the request, provider, or stream fails.
    pub async fn complete_with_cancellation(
        &self,
        messages: &[ModelMessage],
        tools: &[ToolDefinition],
        cancellation: &CancellationToken,
    ) -> Result<ModelCompletion, ModelError> {
        if cancellation.is_cancelled() {
            return Err(ModelError::Canceled);
        }

        let request_body =
            serialize_chat_completions_request(&self.model, messages, tools, &self.configuration)?;
        let authorization = authorization_header(&self.api_key)?;
        let request = self
            .client
            .post(self.endpoint.clone())
            .header(AUTHORIZATION, authorization)
            .json(&request_body);
        let response = tokio::select! {
            () = cancellation.cancelled() => return Err(ModelError::Canceled),
            result = request.send() => result.map_err(|error| map_transport_error(&error))?,
        };

        let provider_request_id = provider_request_id(&response);
        let status = response.status();
        if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(ModelError::RateLimited {
                retry_after: retry_after(response.headers()),
            });
        }
        if status.is_server_error() {
            return Err(ModelError::Server {
                status: status.as_u16(),
            });
        }
        if !status.is_success() {
            return Err(ModelError::HttpStatus {
                status: status.as_u16(),
            });
        }

        let mut events = response.bytes_stream().eventsource();
        let mut accumulator = CompletionAccumulator::default();
        let mut done = false;
        while let Some(event) = tokio::select! {
            () = cancellation.cancelled() => return Err(ModelError::Canceled),
            event = events.next() => event,
        } {
            let event = event.map_err(map_stream_error)?;
            if event.event == "error" {
                return Err(ModelError::InvalidResponse);
            }
            if event.data.trim() == "[DONE]" {
                done = true;
                break;
            }
            let chunk = serde_json::from_str::<ChatCompletionChunk>(&event.data)
                .map_err(|_| ModelError::InvalidResponse)?;
            accumulator.apply(chunk)?;
        }

        if !done {
            return Err(ModelError::StreamInterrupted);
        }
        accumulator.finish(provider_request_id)
    }

    /// Short alias for the reference-based completion method.
    ///
    /// # Errors
    ///
    /// Returns a stable model error when the request, provider, or stream fails.
    pub async fn chat(
        &self,
        messages: &[ModelMessage],
        tools: &[ToolDefinition],
        cancellation: &CancellationToken,
    ) -> Result<ModelCompletion, ModelError> {
        self.complete_with_cancellation(messages, tools, cancellation)
            .await
    }
}

/// Serializes domain messages into `OpenAI` Chat Completions message objects.
///
/// # Errors
///
/// Returns an error when a domain message cannot be represented on the wire.
pub fn serialize_model_messages(messages: &[ModelMessage]) -> Result<Vec<Value>, ModelError> {
    messages.iter().map(serialize_model_message).collect()
}

/// Serializes Capability definitions into `OpenAI` function tools.
///
/// # Errors
///
/// Returns an error when a tool name or parameter schema is invalid.
pub fn serialize_tool_definitions(tools: &[ToolDefinition]) -> Result<Vec<Value>, ModelError> {
    tools
        .iter()
        .map(|tool| {
            if tool.name.trim().is_empty() || !tool.parameters.is_object() {
                return Err(ModelError::InvalidConfiguration);
            }
            Ok(json!({
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.parameters,
                }
            }))
        })
        .collect()
}

/// Builds the complete streaming Chat Completions request body.
///
/// # Errors
///
/// Returns an error when the request configuration or messages are invalid.
pub fn serialize_chat_completions_request(
    model: &str,
    messages: &[ModelMessage],
    tools: &[ToolDefinition],
    configuration: &Value,
) -> Result<Value, ModelError> {
    if model.trim().is_empty() || messages.is_empty() {
        return Err(ModelError::InvalidConfiguration);
    }

    let mut object = configuration
        .as_object()
        .cloned()
        .ok_or(ModelError::InvalidConfiguration)?;
    let messages = serialize_model_messages(messages)?;
    let tools = serialize_tool_definitions(tools)?;

    for key in ["timeout_ms", "request_timeout_ms", "timeout_seconds"] {
        object.remove(key);
    }

    let stream_options = match object.remove("stream_options") {
        Some(Value::Object(mut options)) => {
            options.insert("include_usage".to_owned(), Value::Bool(true));
            Value::Object(options)
        }
        Some(_) => return Err(ModelError::InvalidConfiguration),
        None => json!({ "include_usage": true }),
    };

    object.insert("model".to_owned(), Value::String(model.to_owned()));
    object.insert("messages".to_owned(), Value::Array(messages));
    object.insert("stream".to_owned(), Value::Bool(true));
    object.insert("stream_options".to_owned(), stream_options);
    if tools.is_empty() {
        object.remove("tools");
        object.remove("tool_choice");
    } else {
        object.insert("tools".to_owned(), Value::Array(tools));
    }

    Ok(Value::Object(object))
}

fn serialize_model_message(message: &ModelMessage) -> Result<Value, ModelError> {
    match message {
        ModelMessage::System { content } => Ok(json!({
            "role": "system",
            "content": content,
        })),
        ModelMessage::User { content } | ModelMessage::Steering { content } => Ok(json!({
            "role": "user",
            "content": content,
        })),
        ModelMessage::Assistant {
            content,
            tool_calls,
        } => {
            let mut message = json!({
                "role": "assistant",
                "content": content,
            });
            if !tool_calls.is_empty() {
                let serialized_calls = tool_calls
                    .iter()
                    .map(serialize_tool_call)
                    .collect::<Result<Vec<_>, _>>()?;
                message["tool_calls"] = Value::Array(serialized_calls);
            }
            Ok(message)
        }
        ModelMessage::Tool {
            call_id, content, ..
        } => Ok(json!({
            "role": "tool",
            "tool_call_id": call_id,
            "content": tool_content(content)?,
        })),
    }
}

fn serialize_tool_call(call: &ToolCall) -> Result<Value, ModelError> {
    let arguments =
        serde_json::to_string(&call.arguments).map_err(|_| ModelError::InvalidConfiguration)?;
    Ok(json!({
        "id": call.call_id,
        "type": "function",
        "function": {
            "name": call.capability,
            "arguments": arguments,
        }
    }))
}

fn tool_content(content: &Value) -> Result<String, ModelError> {
    match content {
        Value::String(content) => Ok(content.clone()),
        content => serde_json::to_string(content).map_err(|_| ModelError::InvalidConfiguration),
    }
}

fn chat_completions_endpoint(base_url: &str) -> Result<Url, ModelError> {
    let mut endpoint = Url::parse(base_url).map_err(|_| ModelError::InvalidConfiguration)?;
    if !matches!(endpoint.scheme(), "http" | "https")
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(ModelError::InvalidConfiguration);
    }

    let path = endpoint.path().trim_end_matches('/');
    let path = if path.ends_with("/chat/completions") {
        path.to_owned()
    } else if path.is_empty() {
        "/chat/completions".to_owned()
    } else {
        format!("{path}/chat/completions")
    };
    endpoint.set_path(&path);
    Ok(endpoint)
}

fn configured_timeout(configuration: &Map<String, Value>) -> Result<Duration, ModelError> {
    if let Some(value) = configuration
        .get("timeout_ms")
        .or_else(|| configuration.get("request_timeout_ms"))
    {
        let milliseconds = value
            .as_u64()
            .filter(|milliseconds| *milliseconds > 0)
            .ok_or(ModelError::InvalidConfiguration)?;
        return Ok(Duration::from_millis(milliseconds));
    }
    if let Some(value) = configuration.get("timeout_seconds") {
        let seconds = value
            .as_u64()
            .filter(|seconds| *seconds > 0)
            .ok_or(ModelError::InvalidConfiguration)?;
        return Ok(Duration::from_secs(seconds));
    }
    Ok(DEFAULT_MODEL_TIMEOUT)
}

fn authorization_header(api_key: &SecretString) -> Result<HeaderValue, ModelError> {
    let mut value = String::from("Bearer ");
    value.push_str(api_key.expose_secret());
    HeaderValue::from_str(&value).map_err(|_| ModelError::InvalidConfiguration)
}

fn provider_request_id(response: &reqwest::Response) -> String {
    response
        .headers()
        .get("x-request-id")
        .or_else(|| response.headers().get("request-id"))
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map_or_else(|| Uuid::now_v7().to_string(), ToOwned::to_owned)
}

fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

fn map_transport_error(error: &reqwest::Error) -> ModelError {
    if error.is_timeout() {
        ModelError::Timeout
    } else {
        ModelError::Transport
    }
}

fn map_stream_error(error: EventStreamError<reqwest::Error>) -> ModelError {
    match error {
        EventStreamError::Transport(error) if error.is_timeout() => ModelError::Timeout,
        EventStreamError::Transport(_) => ModelError::StreamInterrupted,
        EventStreamError::Utf8(_) | EventStreamError::Parser(_) => ModelError::InvalidResponse,
    }
}

#[derive(Debug, Deserialize)]
struct ChatCompletionChunk {
    #[serde(default)]
    choices: Vec<ChatCompletionChoice>,
    #[serde(default)]
    usage: Option<ChatCompletionUsage>,
}

#[derive(Debug, Default, Deserialize)]
struct ChatCompletionChoice {
    #[serde(default)]
    index: usize,
    #[serde(default)]
    delta: ChatCompletionDelta,
}

#[derive(Debug, Default, Deserialize)]
struct ChatCompletionDelta {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Vec<ChatCompletionToolCallDelta>,
}

#[derive(Debug, Deserialize)]
struct ChatCompletionToolCallDelta {
    #[serde(default)]
    index: Option<usize>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    function: Option<ChatCompletionFunctionDelta>,
}

#[derive(Debug, Default, Deserialize)]
struct ChatCompletionFunctionDelta {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    arguments: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ChatCompletionUsage {
    #[serde(default)]
    prompt_tokens: u64,
    #[serde(default)]
    completion_tokens: u64,
    #[serde(default)]
    cache_read_tokens: Option<u64>,
    #[serde(default)]
    cache_write_tokens: Option<u64>,
    #[serde(default)]
    cache_tokens: Option<u64>,
    #[serde(default)]
    cached_tokens: Option<u64>,
    #[serde(default)]
    cache_creation_input_tokens: Option<u64>,
    #[serde(default)]
    prompt_tokens_details: Option<ChatCompletionTokenDetails>,
}

#[derive(Debug, Default, Deserialize)]
#[allow(clippy::struct_field_names)] // Names match provider usage payload fields.
struct ChatCompletionTokenDetails {
    #[serde(default)]
    cached_tokens: Option<u64>,
    #[serde(default)]
    cache_read_tokens: Option<u64>,
    #[serde(default)]
    cache_write_tokens: Option<u64>,
}

impl ChatCompletionUsage {
    fn into_token_usage(self) -> TokenUsage {
        let cache_read_tokens = self
            .cache_read_tokens
            .or(self.cached_tokens)
            .or(self.cache_tokens)
            .or_else(|| {
                self.prompt_tokens_details
                    .as_ref()
                    .and_then(|details| details.cache_read_tokens)
            })
            .or_else(|| {
                self.prompt_tokens_details
                    .as_ref()
                    .and_then(|details| details.cached_tokens)
            })
            .unwrap_or_default();
        let cache_write_tokens = self
            .cache_write_tokens
            .or(self.cache_creation_input_tokens)
            .or_else(|| {
                self.prompt_tokens_details
                    .as_ref()
                    .and_then(|details| details.cache_write_tokens)
            })
            .unwrap_or_default();
        TokenUsage {
            prompt_tokens: self.prompt_tokens,
            completion_tokens: self.completion_tokens,
            cache_read_tokens,
            cache_write_tokens,
            cost_micros: 0,
        }
    }
}

#[derive(Default)]
struct CompletionAccumulator {
    assistant_text: String,
    tool_calls: Vec<PartialToolCall>,
    usage: Option<TokenUsage>,
}

#[derive(Default)]
struct PartialToolCall {
    call_id: Option<String>,
    capability: String,
    arguments: String,
}

impl CompletionAccumulator {
    fn apply(&mut self, chunk: ChatCompletionChunk) -> Result<(), ModelError> {
        if let Some(usage) = chunk.usage {
            self.usage = Some(usage.into_token_usage());
        }
        for choice in chunk.choices {
            if choice.index != 0 {
                continue;
            }
            if let Some(content) = choice.delta.content {
                self.assistant_text.push_str(&content);
            }
            for tool_call in choice.delta.tool_calls {
                self.apply_tool_call(tool_call)?;
            }
        }
        Ok(())
    }

    fn apply_tool_call(
        &mut self,
        tool_call: ChatCompletionToolCallDelta,
    ) -> Result<(), ModelError> {
        let index = tool_call.index.unwrap_or(0);
        if index >= MAX_TOOL_CALLS {
            return Err(ModelError::InvalidResponse);
        }
        if self.tool_calls.len() <= index {
            self.tool_calls
                .resize_with(index + 1, PartialToolCall::default);
        }
        let partial = &mut self.tool_calls[index];
        if let Some(call_id) = tool_call.id {
            if let Some(existing) = &partial.call_id {
                if existing != &call_id {
                    return Err(ModelError::InvalidResponse);
                }
            } else {
                partial.call_id = Some(call_id);
            }
        }
        if let Some(function) = tool_call.function {
            if let Some(name) = function.name {
                partial.capability.push_str(&name);
            }
            if let Some(arguments) = function.arguments {
                partial.arguments.push_str(&arguments);
            }
        }
        Ok(())
    }

    fn finish(self, provider_request_id: String) -> Result<ModelCompletion, ModelError> {
        let mut tool_calls = Vec::with_capacity(self.tool_calls.len());
        for partial in self.tool_calls {
            let call_id = partial
                .call_id
                .filter(|call_id| !call_id.trim().is_empty())
                .ok_or(ModelError::InvalidResponse)?;
            if partial.capability.trim().is_empty() {
                return Err(ModelError::InvalidResponse);
            }
            let arguments = if partial.arguments.trim().is_empty() {
                json!({})
            } else {
                serde_json::from_str(&partial.arguments).map_err(|_| ModelError::InvalidResponse)?
            };
            tool_calls.push(ToolCall::new(call_id, partial.capability, arguments));
        }

        Ok(ModelCompletion {
            assistant_text: self.assistant_text,
            tool_calls,
            usage: self.usage.unwrap_or_default(),
            provider_request_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use zeus_core::{ModelMessage, ToolCall, ToolResult};

    use super::{
        ChatCompletionChunk, CompletionAccumulator, ModelError, ToolDefinition,
        serialize_chat_completions_request, serialize_model_messages, serialize_tool_definitions,
    };

    #[test]
    fn serializes_messages_and_tools_for_chat_completions() {
        let messages = vec![
            ModelMessage::system("You are concise."),
            ModelMessage::user("Look up order 42."),
            ModelMessage::assistant_with_tool_calls(vec![ToolCall::new(
                "call_1",
                "orders.lookup",
                json!({ "order_id": 42 }),
            )]),
            ModelMessage::tool(ToolResult::new("call_1", json!({ "status": "shipped" }))),
            ModelMessage::steering("Use the result."),
        ];
        let tools = vec![ToolDefinition::new(
            "orders.lookup",
            "Look up an order.",
            json!({
                "type": "object",
                "properties": { "order_id": { "type": "integer" } },
                "required": ["order_id"]
            }),
        )];

        let serialized_messages = serialize_model_messages(&messages).expect("messages serialize");
        assert_eq!(
            serialized_messages[2],
            json!({
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {
                        "name": "orders.lookup",
                        "arguments": "{\"order_id\":42}"
                    }
                }]
            })
        );
        assert_eq!(
            serialized_messages[3],
            json!({
                "role": "tool",
                "tool_call_id": "call_1",
                "content": "{\"status\":\"shipped\"}"
            })
        );
        assert_eq!(
            serialized_messages[4],
            json!({ "role": "user", "content": "Use the result." })
        );

        let serialized_tools = serialize_tool_definitions(&tools).expect("tools serialize");
        assert_eq!(
            serialized_tools[0],
            json!({
                "type": "function",
                "function": {
                    "name": "orders.lookup",
                    "description": "Look up an order.",
                    "parameters": {
                        "type": "object",
                        "properties": { "order_id": { "type": "integer" } },
                        "required": ["order_id"]
                    }
                }
            })
        );

        let request = serialize_chat_completions_request(
            "gpt-test",
            &messages,
            &tools,
            &json!({ "temperature": 0.2 }),
        )
        .expect("request serializes");
        assert_eq!(request["model"], "gpt-test");
        assert_eq!(request["stream"], true);
        assert_eq!(request["stream_options"]["include_usage"], true);
        assert_eq!(request["temperature"], 0.2);
        assert_eq!(request["tools"], json!(serialized_tools));
    }

    #[test]
    fn accumulates_fragmented_tool_call_and_usage() {
        let first = serde_json::from_value::<ChatCompletionChunk>(json!({
            "choices": [{
                "index": 0,
                "delta": {
                    "tool_calls": [{
                        "index": 0,
                        "id": "call_1",
                        "type": "function",
                        "function": { "name": "orders.lookup", "arguments": "{\"city\":\"" }
                    }]
                }
            }]
        }))
        .expect("first chunk");
        let second = serde_json::from_value::<ChatCompletionChunk>(json!({
            "choices": [{
                "index": 0,
                "delta": {
                    "content": "Checking.",
                    "tool_calls": [{
                        "index": 0,
                        "function": { "arguments": "Paris\"}" }
                    }]
                }
            }]
        }))
        .expect("second chunk");
        let usage = serde_json::from_value::<ChatCompletionChunk>(json!({
            "choices": [],
            "usage": {
                "prompt_tokens": 11,
                "completion_tokens": 7,
                "prompt_tokens_details": { "cached_tokens": 3 }
            }
        }))
        .expect("usage chunk");

        let mut accumulator = CompletionAccumulator::default();
        accumulator.apply(first).expect("first applies");
        accumulator.apply(second).expect("second applies");
        accumulator.apply(usage).expect("usage applies");
        let completion = accumulator
            .finish("provider-request".to_owned())
            .expect("completion finishes");

        assert_eq!(completion.assistant_text, "Checking.");
        assert_eq!(completion.tool_calls.len(), 1);
        assert_eq!(completion.tool_calls[0].call_id, "call_1");
        assert_eq!(completion.tool_calls[0].capability, "orders.lookup");
        assert_eq!(
            completion.tool_calls[0].arguments,
            json!({ "city": "Paris" })
        );
        assert_eq!(completion.usage.prompt_tokens, 11);
        assert_eq!(completion.usage.completion_tokens, 7);
        assert_eq!(completion.usage.cache_read_tokens, 3);
        assert_eq!(completion.provider_request_id, "provider-request");
    }

    #[test]
    fn transient_classification_is_stable() {
        assert!(ModelError::RateLimited { retry_after: None }.is_transient());
        assert!(ModelError::Server { status: 503 }.is_retryable());
        assert!(ModelError::Timeout.is_transient());
        assert!(ModelError::StreamInterrupted.is_transient());
        assert!(!ModelError::InvalidResponse.is_transient());
    }
}
