//! Fail-closed tool registration and dispatch primitives.
//!
//! This crate deliberately does not make authorization decisions. A caller must
//! obtain and re-check an authorization guard before calling [`ToolRegistry::dispatch`].
//! The registry then enforces the immutable execution contract (tool name,
//! effect, sandbox, arguments, digest, and executor availability) before an
//! executor can observe the request.

use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

use protocol::{SandboxProfile, ToolCall, ToolEffect, ToolExecutorStatus};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

const MAX_TOOL_NAME_BYTES: usize = 96;
const MAX_CALL_ID_BYTES: usize = 160;
const MAX_ENVIRONMENT_BYTES: usize = 64;

/// The JSON value type accepted for a declared argument.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParameterType {
    String,
    Boolean,
    Integer,
    Number,
    Object,
    Array,
}

/// A single, closed-schema tool parameter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParameterSpec {
    pub parameter_type: ParameterType,
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_length: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_length: Option<usize>,
}

impl ParameterSpec {
    pub fn required_string(max_length: usize) -> Self {
        Self {
            parameter_type: ParameterType::String,
            required: true,
            min_length: Some(1),
            max_length: Some(max_length),
        }
    }
}

/// A bounded JSON-object input schema. Unknown keys are always rejected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectSchema {
    pub max_serialized_bytes: usize,
    pub properties: BTreeMap<String, ParameterSpec>,
}

impl ObjectSchema {
    pub fn empty() -> Self {
        Self {
            max_serialized_bytes: 2,
            properties: BTreeMap::new(),
        }
    }

    fn validate_definition(&self) -> Result<(), RegistryError> {
        if self.max_serialized_bytes == 0 {
            return Err(RegistryError::InvalidDescriptor(
                "input schema max_serialized_bytes must be greater than zero".into(),
            ));
        }

        for (name, spec) in &self.properties {
            validate_parameter_name(name)?;
            if let (Some(min), Some(max)) = (spec.min_length, spec.max_length)
                && min > max
            {
                return Err(RegistryError::InvalidDescriptor(format!(
                    "parameter `{name}` has min_length greater than max_length"
                )));
            }
            if spec.parameter_type != ParameterType::String
                && (spec.min_length.is_some() || spec.max_length.is_some())
            {
                return Err(RegistryError::InvalidDescriptor(format!(
                    "parameter `{name}` has string length limits but is not a string"
                )));
            }
        }
        Ok(())
    }

    fn validate_arguments(&self, value: &Value) -> Result<(), RegistryError> {
        let object = value.as_object().ok_or_else(|| {
            RegistryError::InvalidArguments("tool arguments must be a JSON object".into())
        })?;
        let serialized_len = canonical_json(value).len();
        if serialized_len > self.max_serialized_bytes {
            return Err(RegistryError::InvalidArguments(format!(
                "tool arguments are {serialized_len} bytes; limit is {} bytes",
                self.max_serialized_bytes
            )));
        }

        for key in object.keys() {
            if !self.properties.contains_key(key) {
                return Err(RegistryError::InvalidArguments(format!(
                    "unknown tool argument `{key}`"
                )));
            }
        }

        for (name, spec) in &self.properties {
            let Some(argument) = object.get(name) else {
                if spec.required {
                    return Err(RegistryError::InvalidArguments(format!(
                        "missing required tool argument `{name}`"
                    )));
                }
                continue;
            };
            validate_parameter_value(name, spec, argument)?;
        }
        Ok(())
    }
}

/// Static metadata for a registered executor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolDescriptor {
    pub name: String,
    /// Explicit contract version persisted with every call.
    pub version: String,
    pub description: String,
    pub effect: ToolEffect,
    pub sandbox_profile: SandboxProfile,
    pub input_schema: ObjectSchema,
}

impl ToolDescriptor {
    fn validate(&self) -> Result<(), RegistryError> {
        validate_tool_name(&self.name)?;
        validate_id_component(&self.version, "tool version").map_err(|error| {
            RegistryError::InvalidDescriptor(format!("invalid tool version: {error}"))
        })?;
        if self.description.trim().is_empty() || self.description.len() > 512 {
            return Err(RegistryError::InvalidDescriptor(
                "tool description must contain 1..=512 bytes".into(),
            ));
        }
        self.input_schema.validate_definition()
    }
}

/// The request visible to a provider after all registry checks have passed.
#[derive(Clone, Debug, PartialEq)]
pub struct ExecutionRequest {
    pub call: ToolCall,
    pub environment: String,
    /// Deterministic per logical call. Providers should use it for retries.
    pub provider_idempotency_key: String,
}

/// A provider-neutral execution result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolOutput {
    pub value: Value,
    #[serde(default)]
    pub replayed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_request_id: Option<String>,
}

/// Errors produced only after dispatch reaches an executor.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ExecutorError {
    #[error("tool executor is unavailable: {reason}")]
    Unavailable { reason: String },
    #[error("tool execution failed ({code}): {message}")]
    Failed {
        code: String,
        message: String,
        retryable: bool,
    },
}

/// Registration and pre-dispatch errors. Every variant fails closed.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum RegistryError {
    #[error("invalid tool descriptor: {0}")]
    InvalidDescriptor(String),
    #[error("tool `{0}` is already registered")]
    DuplicateTool(String),
    #[error("unknown tool `{0}`")]
    UnknownTool(String),
    #[error("invalid tool call: {0}")]
    InvalidCall(String),
    #[error("invalid tool arguments: {0}")]
    InvalidArguments(String),
    #[error("tool call contract mismatch for `{field}`")]
    ContractMismatch { field: &'static str },
    #[error("tool `{0}` is marked unavailable")]
    ExecutorUnavailable(String),
    #[error(transparent)]
    Executor(#[from] ExecutorError),
}

/// Boxed future used to keep [`ToolExecutor`] object-safe without a macro.
pub type ExecutionFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ToolOutput, ExecutorError>> + Send + 'a>>;

/// A provider implementation. It only receives already validated requests.
pub trait ToolExecutor: Send + Sync {
    fn execute(&self, request: ExecutionRequest) -> ExecutionFuture<'_>;
}

struct RegisteredTool {
    descriptor: ToolDescriptor,
    executor: Arc<dyn ToolExecutor>,
}

/// A closed registry: unknown and mismatched calls never reach an executor.
#[derive(Default)]
pub struct ToolRegistry {
    entries: BTreeMap<String, RegisteredTool>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<E>(
        &mut self,
        descriptor: ToolDescriptor,
        executor: E,
    ) -> Result<(), RegistryError>
    where
        E: ToolExecutor + 'static,
    {
        self.register_shared(descriptor, Arc::new(executor))
    }

    pub fn register_shared(
        &mut self,
        descriptor: ToolDescriptor,
        executor: Arc<dyn ToolExecutor>,
    ) -> Result<(), RegistryError> {
        descriptor.validate()?;
        if self.entries.contains_key(&descriptor.name) {
            return Err(RegistryError::DuplicateTool(descriptor.name));
        }
        self.entries.insert(
            descriptor.name.clone(),
            RegisteredTool {
                descriptor,
                executor,
            },
        );
        Ok(())
    }

    pub fn descriptor(&self, name: &str) -> Option<&ToolDescriptor> {
        self.entries.get(name).map(|entry| &entry.descriptor)
    }

    pub fn descriptors(&self) -> impl Iterator<Item = &ToolDescriptor> {
        self.entries.values().map(|entry| &entry.descriptor)
    }

    /// Validates the complete persisted call contract immediately before the
    /// provider is invoked. Authorization must be re-checked by the caller
    /// immediately before this method.
    pub async fn dispatch(
        &self,
        call: ToolCall,
        environment: &str,
    ) -> Result<ToolOutput, RegistryError> {
        validate_call_id(&call.call_id)?;
        validate_environment(environment)?;

        let entry = self
            .entries
            .get(&call.tool)
            .ok_or_else(|| RegistryError::UnknownTool(call.tool.clone()))?;

        if call.executor_status != ToolExecutorStatus::Available {
            return Err(RegistryError::ExecutorUnavailable(call.tool));
        }
        if call.tool_version != entry.descriptor.version {
            return Err(RegistryError::ContractMismatch {
                field: "tool_version",
            });
        }
        if call.effect != entry.descriptor.effect {
            return Err(RegistryError::ContractMismatch { field: "effect" });
        }
        if call.sandbox_profile != entry.descriptor.sandbox_profile {
            return Err(RegistryError::ContractMismatch {
                field: "sandbox_profile",
            });
        }
        entry
            .descriptor
            .input_schema
            .validate_arguments(&call.arguments)?;

        let expected_digest = arguments_digest(&call.arguments);
        if call.arguments_digest != expected_digest {
            return Err(RegistryError::ContractMismatch {
                field: "arguments_digest",
            });
        }

        let provider_idempotency_key = provider_idempotency_key(&call.call_id)?;
        entry
            .executor
            .execute(ExecutionRequest {
                call,
                environment: environment.to_owned(),
                provider_idempotency_key,
            })
            .await
            .map_err(RegistryError::from)
    }
}

/// Deterministically identifies a logical run step. Retries must reuse it.
pub fn stable_call_id(
    run_id: &str,
    turn: u32,
    step: u32,
    tool_name: &str,
) -> Result<String, RegistryError> {
    validate_id_component(run_id, "run id")?;
    validate_tool_name(tool_name)?;
    let mut input = Vec::with_capacity(run_id.len() + tool_name.len() + 32);
    input.extend_from_slice(b"zeus-tool-call-v1\0");
    input.extend_from_slice(run_id.as_bytes());
    input.push(0);
    input.extend_from_slice(&turn.to_be_bytes());
    input.extend_from_slice(&step.to_be_bytes());
    input.extend_from_slice(tool_name.as_bytes());
    let call_id = format!("call-{}", sha256_hex(&input));
    validate_call_id(&call_id)?;
    Ok(call_id)
}

/// Returns the retry key handed to the provider for a persisted call id.
pub fn provider_idempotency_key(call_id: &str) -> Result<String, RegistryError> {
    validate_call_id(call_id)?;
    Ok(format!("zeus-tool:{call_id}"))
}

/// Canonical JSON bytes: recursively sorted object keys and no whitespace.
pub fn canonical_json(value: &Value) -> Vec<u8> {
    let mut output = Vec::new();
    write_canonical(value, &mut output);
    output
}

/// SHA-256 binding used by approvals and persisted tool calls.
pub fn arguments_digest(value: &Value) -> String {
    format!("sha256:{}", sha256_hex(&canonical_json(value)))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

/// An executor used when configuration intentionally has no provider.
#[derive(Clone, Debug)]
pub struct UnavailableExecutor {
    reason: String,
}

impl UnavailableExecutor {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl ToolExecutor for UnavailableExecutor {
    fn execute(&self, _request: ExecutionRequest) -> ExecutionFuture<'_> {
        let error = ExecutorError::Unavailable {
            reason: self.reason.clone(),
        };
        Box::pin(async move { Err(error) })
    }
}

/// Test/local executor that records exactly the calls which passed the registry.
#[derive(Clone)]
pub struct RecordingExecutor {
    calls: Arc<Mutex<Vec<ExecutionRequest>>>,
    output: ToolOutput,
}

impl RecordingExecutor {
    pub fn new(output: Value) -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            output: ToolOutput {
                value: output,
                replayed: false,
                provider_request_id: None,
            },
        }
    }

    pub fn calls(&self) -> Vec<ExecutionRequest> {
        self.calls
            .lock()
            .expect("recording executor mutex poisoned")
            .clone()
    }
}

impl ToolExecutor for RecordingExecutor {
    fn execute(&self, request: ExecutionRequest) -> ExecutionFuture<'_> {
        let calls = Arc::clone(&self.calls);
        let output = self.output.clone();
        Box::pin(async move {
            calls
                .lock()
                .map_err(|_| ExecutorError::Failed {
                    code: "recording_executor_poisoned".into(),
                    message: "recording executor mutex is poisoned".into(),
                    retryable: false,
                })?
                .push(request);
            Ok(output)
        })
    }
}

fn validate_tool_name(name: &str) -> Result<(), RegistryError> {
    if name.is_empty()
        || name.len() > MAX_TOOL_NAME_BYTES
        || name.starts_with('.')
        || name.ends_with('.')
        || name.split('.').any(|segment| segment.is_empty())
        || !name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
    {
        return Err(RegistryError::InvalidDescriptor(format!(
            "tool name `{name}` must be lowercase ASCII segments separated by dots"
        )));
    }
    Ok(())
}

fn validate_parameter_name(name: &str) -> Result<(), RegistryError> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(RegistryError::InvalidDescriptor(format!(
            "invalid parameter name `{name}`"
        )));
    }
    Ok(())
}

fn validate_id_component(value: &str, label: &str) -> Result<(), RegistryError> {
    if value.is_empty()
        || value.len() > 64
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
        })
    {
        return Err(RegistryError::InvalidCall(format!(
            "{label} contains unsupported characters or is too long"
        )));
    }
    Ok(())
}

fn validate_call_id(value: &str) -> Result<(), RegistryError> {
    if value.is_empty()
        || value.len() > MAX_CALL_ID_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
        })
    {
        return Err(RegistryError::InvalidCall(
            "call id contains unsupported characters or is too long".into(),
        ));
    }
    Ok(())
}

fn validate_environment(value: &str) -> Result<(), RegistryError> {
    if value.is_empty()
        || value.len() > MAX_ENVIRONMENT_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
    {
        return Err(RegistryError::InvalidCall(
            "environment contains unsupported characters or is too long".into(),
        ));
    }
    Ok(())
}

fn validate_parameter_value(
    name: &str,
    spec: &ParameterSpec,
    value: &Value,
) -> Result<(), RegistryError> {
    let type_matches = match spec.parameter_type {
        ParameterType::String => value.is_string(),
        ParameterType::Boolean => value.is_boolean(),
        ParameterType::Integer => value.as_i64().is_some() || value.as_u64().is_some(),
        ParameterType::Number => value.is_number(),
        ParameterType::Object => value.is_object(),
        ParameterType::Array => value.is_array(),
    };
    if !type_matches {
        return Err(RegistryError::InvalidArguments(format!(
            "tool argument `{name}` has the wrong JSON type"
        )));
    }
    if let Some(string) = value.as_str() {
        let length = string.chars().count();
        if spec.min_length.is_some_and(|minimum| length < minimum) {
            return Err(RegistryError::InvalidArguments(format!(
                "tool argument `{name}` is shorter than allowed"
            )));
        }
        if spec.max_length.is_some_and(|maximum| length > maximum) {
            return Err(RegistryError::InvalidArguments(format!(
                "tool argument `{name}` is longer than allowed"
            )));
        }
    }
    Ok(())
}

fn write_canonical(value: &Value, output: &mut Vec<u8>) {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => output.extend_from_slice(number.to_string().as_bytes()),
        Value::String(string) => output.extend_from_slice(
            serde_json::to_string(string)
                .expect("serializing a JSON string cannot fail")
                .as_bytes(),
        ),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical(value, output);
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_unstable_by_key(|(key, _)| *key);
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                output.extend_from_slice(
                    serde_json::to_string(key)
                        .expect("serializing a JSON key cannot fail")
                        .as_bytes(),
                );
                output.push(b':');
                write_canonical(value, output);
            }
            output.push(b'}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn descriptor(name: &str) -> ToolDescriptor {
        ToolDescriptor {
            name: name.into(),
            version: "1".into(),
            description: "test tool".into(),
            effect: ToolEffect::ReadOnly,
            sandbox_profile: SandboxProfile::ReadOnly,
            input_schema: ObjectSchema {
                max_serialized_bytes: 128,
                properties: BTreeMap::from([("query".into(), ParameterSpec::required_string(16))]),
            },
        }
    }

    fn call(name: &str, arguments: Value) -> ToolCall {
        ToolCall {
            call_id: stable_call_id("run-1", 2, 3, name).unwrap(),
            tool: name.into(),
            tool_version: "1".into(),
            arguments_digest: arguments_digest(&arguments),
            arguments,
            effect: ToolEffect::ReadOnly,
            sandbox_profile: SandboxProfile::ReadOnly,
            executor_status: ToolExecutorStatus::Available,
        }
    }

    #[test]
    fn canonical_digest_is_key_order_independent_and_sha256() {
        let left = json!({"z": [3, {"b": true, "a": null}], "a": "hello"});
        let right: Value =
            serde_json::from_str(r#"{"a":"hello","z":[3,{"a":null,"b":true}]}"#).unwrap();

        assert_eq!(canonical_json(&left), canonical_json(&right));
        let digest = arguments_digest(&left);
        assert!(digest.starts_with("sha256:"));
        assert_eq!(digest.len(), 71);
        assert_eq!(
            digest,
            "sha256:114396316613b51ec664ae1a95a3ca0a409c572714125be23fd285b08fc7a8dd"
        );
        assert_eq!(digest, arguments_digest(&right));
    }

    #[test]
    fn stable_ids_and_provider_keys_survive_retries() {
        let first = stable_call_id("ZR-1842", 7, 11, "telemetry.query").unwrap();
        let retry = stable_call_id("ZR-1842", 7, 11, "telemetry.query").unwrap();
        assert_eq!(first, retry);
        assert_eq!(
            provider_idempotency_key(&first).unwrap(),
            provider_idempotency_key(&retry).unwrap()
        );
    }

    #[tokio::test]
    async fn unknown_tool_never_calls_a_registered_executor() {
        let recorder = RecordingExecutor::new(json!({"ok": true}));
        let mut registry = ToolRegistry::new();
        registry
            .register(descriptor("known.query"), recorder.clone())
            .unwrap();

        let error = registry
            .dispatch(
                call("unknown.query", json!({"query": "safe"})),
                "local-development",
            )
            .await
            .unwrap_err();
        assert_eq!(error, RegistryError::UnknownTool("unknown.query".into()));
        assert!(recorder.calls().is_empty());
    }

    #[tokio::test]
    async fn invalid_contract_and_parameters_never_reach_executor() {
        let recorder = RecordingExecutor::new(json!({"ok": true}));
        let mut registry = ToolRegistry::new();
        registry
            .register(descriptor("known.query"), recorder.clone())
            .unwrap();

        let mut wrong_digest = call("known.query", json!({"query": "safe"}));
        wrong_digest.arguments_digest = arguments_digest(&json!({"query": "changed"}));
        assert!(matches!(
            registry.dispatch(wrong_digest, "local-development").await,
            Err(RegistryError::ContractMismatch {
                field: "arguments_digest"
            })
        ));

        let unknown_argument = call(
            "known.query",
            json!({"query": "safe", "path": "/etc/passwd"}),
        );
        assert!(matches!(
            registry
                .dispatch(unknown_argument, "local-development")
                .await,
            Err(RegistryError::InvalidArguments(_))
        ));
        assert!(recorder.calls().is_empty());
    }

    #[tokio::test]
    async fn valid_dispatch_supplies_stable_provider_key() {
        let recorder = RecordingExecutor::new(json!({"ok": true}));
        let mut registry = ToolRegistry::new();
        registry
            .register(descriptor("known.query"), recorder.clone())
            .unwrap();
        let call = call("known.query", json!({"query": "safe"}));
        let expected_key = provider_idempotency_key(&call.call_id).unwrap();

        registry.dispatch(call, "local-development").await.unwrap();

        let calls = recorder.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].provider_idempotency_key, expected_key);
    }

    #[tokio::test]
    async fn unavailable_executor_is_explicit() {
        let mut registry = ToolRegistry::new();
        registry
            .register(
                descriptor("offline.query"),
                UnavailableExecutor::new("provider is not configured"),
            )
            .unwrap();
        let error = registry
            .dispatch(
                call("offline.query", json!({"query": "safe"})),
                "local-development",
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            RegistryError::Executor(ExecutorError::Unavailable { .. })
        ));
    }
}
