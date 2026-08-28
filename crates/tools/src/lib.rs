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
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

const MAX_TOOL_NAME_BYTES: usize = 64;
const MAX_CALL_ID_BYTES: usize = 160;
const MAX_ENVIRONMENT_BYTES: usize = 64;
const MAX_EXECUTION_SCOPE_FIELD_BYTES: usize = 384;
/// Maximum compact-JSON bytes accepted from one executor result value.
pub const TOOL_OUTPUT_MAX_SERIALIZED_BYTES: usize = 64 * 1024;
/// Maximum bytes accepted for an opaque executor request identifier.
pub const PROVIDER_REQUEST_ID_MAX_BYTES: usize = 128;

/// The JSON value type accepted for a declared argument.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParameterType {
    String,
    StringEnum {
        values: Vec<String>,
    },
    Boolean,
    Integer,
    Number,
    Object,
    Array,
    ArrayOfObjects {
        min_items: usize,
        max_items: usize,
        properties: BTreeMap<String, ParameterSpec>,
    },
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
            validate_parameter_definition(name, spec, 0)?;
        }
        Ok(())
    }

    /// Convert the closed server-side contract into the JSON Schema fragment
    /// exposed to a model provider. The byte limit remains a Zeus extension;
    /// it is always re-enforced by [`Self::validate_arguments`].
    pub fn provider_json_schema(&self) -> Result<Value, RegistryError> {
        self.validate_definition()?;
        let mut properties = Map::new();
        let mut required = Vec::new();
        for (name, spec) in &self.properties {
            let property = provider_parameter_json_schema(spec)?;
            if spec.required {
                required.push(Value::String(name.clone()));
            }
            properties.insert(name.clone(), property);
        }

        let max_serialized_bytes = u64::try_from(self.max_serialized_bytes).map_err(|_| {
            RegistryError::InvalidDescriptor(
                "input schema byte limit cannot be represented in provider JSON".into(),
            )
        })?;
        Ok(Value::Object(Map::from_iter([
            ("type".into(), Value::String("object".into())),
            ("properties".into(), Value::Object(properties)),
            ("required".into(), Value::Array(required)),
            ("additionalProperties".into(), Value::Bool(false)),
            (
                "x-zeus-max-serialized-bytes".into(),
                Value::from(max_serialized_bytes),
            ),
        ])))
    }

    /// Validate model-supplied arguments against the closed server contract.
    pub fn validate_arguments(&self, value: &Value) -> Result<(), RegistryError> {
        let object = value.as_object().ok_or_else(|| {
            RegistryError::InvalidArguments("tool arguments must be a JSON object".into())
        })?;
        if serialized_json_len_bounded(value, self.max_serialized_bytes).is_none() {
            return Err(RegistryError::InvalidArguments(format!(
                "tool arguments exceed the {}-byte limit",
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

fn parameter_type_name(parameter_type: &ParameterType) -> &'static str {
    match parameter_type {
        ParameterType::String | ParameterType::StringEnum { .. } => "string",
        ParameterType::Boolean => "boolean",
        ParameterType::Integer => "integer",
        ParameterType::Number => "number",
        ParameterType::Object => "object",
        ParameterType::Array | ParameterType::ArrayOfObjects { .. } => "array",
    }
}

const MAX_PARAMETER_NESTING_DEPTH: usize = 4;
const MAX_PARAMETER_ENUM_VALUES: usize = 32;
const MAX_PARAMETER_ENUM_VALUE_BYTES: usize = 64;
const MAX_ARRAY_OBJECT_PROPERTIES: usize = 16;
const MAX_ARRAY_OBJECT_ITEMS: usize = 64;

fn validate_parameter_definition(
    name: &str,
    spec: &ParameterSpec,
    depth: usize,
) -> Result<(), RegistryError> {
    if depth > MAX_PARAMETER_NESTING_DEPTH {
        return Err(RegistryError::InvalidDescriptor(format!(
            "parameter `{name}` exceeds the nested schema depth limit"
        )));
    }
    if let (Some(min), Some(max)) = (spec.min_length, spec.max_length)
        && min > max
    {
        return Err(RegistryError::InvalidDescriptor(format!(
            "parameter `{name}` has min_length greater than max_length"
        )));
    }
    if !matches!(
        spec.parameter_type,
        ParameterType::String | ParameterType::StringEnum { .. }
    ) && (spec.min_length.is_some() || spec.max_length.is_some())
    {
        return Err(RegistryError::InvalidDescriptor(format!(
            "parameter `{name}` has string length limits but is not a string"
        )));
    }

    match &spec.parameter_type {
        ParameterType::StringEnum { values } => {
            if values.is_empty() || values.len() > MAX_PARAMETER_ENUM_VALUES {
                return Err(RegistryError::InvalidDescriptor(format!(
                    "parameter `{name}` must declare 1..={MAX_PARAMETER_ENUM_VALUES} enum values"
                )));
            }
            let mut unique = std::collections::BTreeSet::new();
            for value in values {
                if value.is_empty()
                    || value.len() > MAX_PARAMETER_ENUM_VALUE_BYTES
                    || value.chars().any(char::is_control)
                    || !unique.insert(value)
                {
                    return Err(RegistryError::InvalidDescriptor(format!(
                        "parameter `{name}` has an invalid or duplicate enum value"
                    )));
                }
            }
        }
        ParameterType::ArrayOfObjects {
            min_items,
            max_items,
            properties,
        } => {
            if min_items > max_items || *max_items == 0 || *max_items > MAX_ARRAY_OBJECT_ITEMS {
                return Err(RegistryError::InvalidDescriptor(format!(
                    "parameter `{name}` must allow at most {MAX_ARRAY_OBJECT_ITEMS} array items with min_items <= max_items"
                )));
            }
            if properties.is_empty() || properties.len() > MAX_ARRAY_OBJECT_PROPERTIES {
                return Err(RegistryError::InvalidDescriptor(format!(
                    "parameter `{name}` array items must declare 1..={MAX_ARRAY_OBJECT_PROPERTIES} properties"
                )));
            }
            for (child_name, child_spec) in properties {
                validate_parameter_name(child_name)?;
                validate_parameter_definition(child_name, child_spec, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn provider_parameter_json_schema(spec: &ParameterSpec) -> Result<Value, RegistryError> {
    let mut property = Map::new();
    property.insert(
        "type".into(),
        Value::String(parameter_type_name(&spec.parameter_type).into()),
    );
    if let Some(minimum) = spec.min_length {
        property.insert(
            "minLength".into(),
            Value::from(u64::try_from(minimum).map_err(|_| {
                RegistryError::InvalidDescriptor(
                    "parameter min_length cannot be represented in JSON Schema".into(),
                )
            })?),
        );
    }
    if let Some(maximum) = spec.max_length {
        property.insert(
            "maxLength".into(),
            Value::from(u64::try_from(maximum).map_err(|_| {
                RegistryError::InvalidDescriptor(
                    "parameter max_length cannot be represented in JSON Schema".into(),
                )
            })?),
        );
    }
    match &spec.parameter_type {
        ParameterType::StringEnum { values } => {
            property.insert(
                "enum".into(),
                Value::Array(values.iter().cloned().map(Value::String).collect()),
            );
        }
        ParameterType::ArrayOfObjects {
            min_items,
            max_items,
            properties,
        } => {
            property.insert(
                "minItems".into(),
                Value::from(u64::try_from(*min_items).map_err(|_| {
                    RegistryError::InvalidDescriptor(
                        "array min_items cannot be represented in provider JSON".into(),
                    )
                })?),
            );
            property.insert(
                "maxItems".into(),
                Value::from(u64::try_from(*max_items).map_err(|_| {
                    RegistryError::InvalidDescriptor(
                        "array max_items cannot be represented in provider JSON".into(),
                    )
                })?),
            );
            let mut item_properties = Map::new();
            let mut required = Vec::new();
            for (name, child) in properties {
                item_properties.insert(name.clone(), provider_parameter_json_schema(child)?);
                if child.required {
                    required.push(Value::String(name.clone()));
                }
            }
            property.insert(
                "items".into(),
                Value::Object(Map::from_iter([
                    ("type".into(), Value::String("object".into())),
                    ("properties".into(), Value::Object(item_properties)),
                    ("required".into(), Value::Array(required)),
                    ("additionalProperties".into(), Value::Bool(false)),
                ])),
            );
        }
        _ => {}
    }
    Ok(Value::Object(property))
}

/// Static metadata for a registered executor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolDescriptor {
    /// Provider-safe function identifier shared by the registry, manifest,
    /// and model request contracts.
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

/// Server-derived ownership context for one Agent tool execution.
///
/// These fields never come from model arguments. Stateful executors use the
/// complete scope to prevent resources such as terminal sessions from being
/// observed or controlled by another account, actor, Session, turn, or Agent.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExecutionScope {
    pub account_id: String,
    pub actor_id: String,
    pub session_id: String,
    pub turn_id: String,
    pub agent_id: String,
}

impl ExecutionScope {
    pub fn new(
        account_id: impl Into<String>,
        actor_id: impl Into<String>,
        session_id: impl Into<String>,
        turn_id: impl Into<String>,
        agent_id: impl Into<String>,
    ) -> Result<Self, RegistryError> {
        let scope = Self {
            account_id: account_id.into(),
            actor_id: actor_id.into(),
            session_id: session_id.into(),
            turn_id: turn_id.into(),
            agent_id: agent_id.into(),
        };
        scope.validate()?;
        Ok(scope)
    }

    fn validate(&self) -> Result<(), RegistryError> {
        for (field, value) in [
            ("account_id", self.account_id.as_str()),
            ("actor_id", self.actor_id.as_str()),
            ("session_id", self.session_id.as_str()),
            ("turn_id", self.turn_id.as_str()),
            ("agent_id", self.agent_id.as_str()),
        ] {
            if value.is_empty()
                || value.len() > MAX_EXECUTION_SCOPE_FIELD_BYTES
                || value.trim() != value
                || value.chars().any(char::is_control)
            {
                return Err(RegistryError::InvalidExecutionScope(format!(
                    "{field} must be non-empty, canonical, control-free, and at most {MAX_EXECUTION_SCOPE_FIELD_BYTES} UTF-8 bytes"
                )));
            }
        }
        Ok(())
    }
}

/// The request visible to an executor after all registry checks have passed.
#[derive(Clone, Debug, PartialEq)]
pub struct ExecutionRequest {
    pub call: ToolCall,
    pub environment: String,
    /// Present only for a server-owned Agent execution path. Legacy Run tools
    /// remain explicitly unscoped and cannot use stateful Agent resources.
    pub scope: Option<ExecutionScope>,
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
    /// The executor crossed its side-effect boundary but could not determine
    /// whether the operation completed. Callers must never turn this into a
    /// retryable known failure.
    #[error("tool execution outcome is unknown: {message}")]
    OutcomeUnknown { message: String },
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
    #[error("invalid tool execution scope: {0}")]
    InvalidExecutionScope(String),
    #[error("invalid tool arguments: {0}")]
    InvalidArguments(String),
    #[error("tool call contract mismatch for `{field}`")]
    ContractMismatch { field: &'static str },
    #[error("tool `{0}` is marked unavailable")]
    ExecutorUnavailable(String),
    #[error("tool executor output exceeded the {limit_bytes}-byte limit")]
    ExecutorOutputTooLarge { limit_bytes: usize },
    #[error("tool executor output contains an invalid {field}")]
    InvalidExecutorOutput { field: &'static str },
    #[error("tool executor diagnostic contains an invalid {field}")]
    InvalidExecutorDiagnostic { field: &'static str },
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
        self.dispatch_inner(call, environment, None).await
    }

    /// Dispatch a tool with server-derived Agent ownership context.
    ///
    /// The scope is validated before the executor can observe the request.
    pub async fn dispatch_scoped(
        &self,
        call: ToolCall,
        environment: &str,
        scope: ExecutionScope,
    ) -> Result<ToolOutput, RegistryError> {
        scope.validate()?;
        self.dispatch_inner(call, environment, Some(scope)).await
    }

    async fn dispatch_inner(
        &self,
        call: ToolCall,
        environment: &str,
        scope: Option<ExecutionScope>,
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
        let result = entry
            .executor
            .execute(ExecutionRequest {
                call,
                environment: environment.to_owned(),
                scope,
                provider_idempotency_key,
            })
            .await;
        match result {
            Ok(output) => {
                validate_tool_output(&output)?;
                Ok(output)
            }
            Err(error) => {
                validate_executor_error(&error)?;
                Err(RegistryError::Executor(error))
            }
        }
    }
}

fn validate_tool_output(output: &ToolOutput) -> Result<(), RegistryError> {
    if serialized_json_len_bounded(&output.value, TOOL_OUTPUT_MAX_SERIALIZED_BYTES).is_none() {
        return Err(RegistryError::ExecutorOutputTooLarge {
            limit_bytes: TOOL_OUTPUT_MAX_SERIALIZED_BYTES,
        });
    }
    if let Some(provider_request_id) = &output.provider_request_id
        && protocol::validate_tool_outcome_code(provider_request_id).is_err()
    {
        return Err(RegistryError::InvalidExecutorOutput {
            field: "provider_request_id",
        });
    }
    Ok(())
}

fn validate_executor_error(error: &ExecutorError) -> Result<(), RegistryError> {
    match error {
        ExecutorError::Unavailable { reason } => {
            protocol::validate_tool_outcome_summary(reason).map_err(|_| {
                RegistryError::InvalidExecutorDiagnostic {
                    field: "unavailable reason",
                }
            })?;
        }
        ExecutorError::OutcomeUnknown { message } => {
            protocol::validate_tool_outcome_summary(message).map_err(|_| {
                RegistryError::InvalidExecutorDiagnostic {
                    field: "outcome-unknown message",
                }
            })?;
        }
        ExecutorError::Failed { code, message, .. } => {
            protocol::validate_tool_outcome_code(code).map_err(|_| {
                RegistryError::InvalidExecutorDiagnostic {
                    field: "failure code",
                }
            })?;
            protocol::validate_tool_outcome_summary(message).map_err(|_| {
                RegistryError::InvalidExecutorDiagnostic {
                    field: "failure message",
                }
            })?;
        }
    }
    Ok(())
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

/// Deterministically identify one logical tool position in a durable agent
/// turn. Model-selected tool names and arguments are deliberately excluded: a
/// persisted `(agent_id, model_step, call_ordinal)` can own only one call
/// contract, and a retry must reuse this ID.
pub fn stable_agent_call_id(
    agent_id: &str,
    model_step: u32,
    call_ordinal: u32,
) -> Result<String, RegistryError> {
    validate_agent_id_component(agent_id)?;
    let mut input = Vec::with_capacity(agent_id.len() + 40);
    input.extend_from_slice(b"zeus-agent-tool-call-v1\0");
    input.extend_from_slice(
        &u64::try_from(agent_id.len())
            .expect("validated agent IDs fit in u64")
            .to_be_bytes(),
    );
    input.extend_from_slice(agent_id.as_bytes());
    input.extend_from_slice(&model_step.to_be_bytes());
    input.extend_from_slice(&call_ordinal.to_be_bytes());
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

fn serialized_json_len_bounded(value: &Value, max_bytes: usize) -> Option<usize> {
    fn add(total: &mut usize, amount: usize, max_bytes: usize) -> Option<()> {
        *total = total.checked_add(amount)?;
        (*total <= max_bytes).then_some(())
    }

    fn string_len(value: &str) -> Option<usize> {
        let mut length = 2usize;
        for character in value.chars() {
            let encoded = match character {
                '"' | '\\' | '\u{8}' | '\t' | '\n' | '\u{c}' | '\r' => 2,
                character if character <= '\u{1f}' => 6,
                character => character.len_utf8(),
            };
            length = length.checked_add(encoded)?;
        }
        Some(length)
    }

    let mut total = 0usize;
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::Null => add(&mut total, 4, max_bytes)?,
            Value::Bool(true) => add(&mut total, 4, max_bytes)?,
            Value::Bool(false) => add(&mut total, 5, max_bytes)?,
            Value::Number(number) => add(&mut total, number.to_string().len(), max_bytes)?,
            Value::String(string) => add(&mut total, string_len(string)?, max_bytes)?,
            Value::Array(values) => {
                add(
                    &mut total,
                    2usize.checked_add(values.len().saturating_sub(1))?,
                    max_bytes,
                )?;
                pending.extend(values);
            }
            Value::Object(values) => {
                add(
                    &mut total,
                    2usize.checked_add(values.len().saturating_sub(1))?,
                    max_bytes,
                )?;
                for (key, value) in values {
                    add(&mut total, string_len(key)?.checked_add(1)?, max_bytes)?;
                    pending.push(value);
                }
            }
        }
    }
    Some(total)
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
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte))
    {
        return Err(RegistryError::InvalidDescriptor(format!(
            "tool name `{name}` must be at most {MAX_TOOL_NAME_BYTES} lowercase ASCII letters, digits, underscores, or hyphens"
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

fn validate_agent_id_component(value: &str) -> Result<(), RegistryError> {
    if value.is_empty()
        || value.len() > MAX_EXECUTION_SCOPE_FIELD_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
        })
    {
        return Err(RegistryError::InvalidCall(format!(
            "agent id contains unsupported characters or is longer than {MAX_EXECUTION_SCOPE_FIELD_BYTES} bytes"
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
    let type_matches = match &spec.parameter_type {
        ParameterType::String | ParameterType::StringEnum { .. } => value.is_string(),
        ParameterType::Boolean => value.is_boolean(),
        ParameterType::Integer => value.as_i64().is_some() || value.as_u64().is_some(),
        ParameterType::Number => value.is_number(),
        ParameterType::Object => value.is_object(),
        ParameterType::Array | ParameterType::ArrayOfObjects { .. } => value.is_array(),
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
    match &spec.parameter_type {
        ParameterType::StringEnum { values } => {
            let string = value
                .as_str()
                .expect("the parameter type check accepted a string");
            if !values.iter().any(|candidate| candidate == string) {
                return Err(RegistryError::InvalidArguments(format!(
                    "tool argument `{name}` is not one of the declared enum values"
                )));
            }
        }
        ParameterType::ArrayOfObjects {
            min_items,
            max_items,
            properties,
        } => {
            let values = value
                .as_array()
                .expect("the parameter type check accepted an array");
            if values.len() < *min_items || values.len() > *max_items {
                return Err(RegistryError::InvalidArguments(format!(
                    "tool argument `{name}` must contain {min_items}..={max_items} items"
                )));
            }
            for (index, item) in values.iter().enumerate() {
                let object = item.as_object().ok_or_else(|| {
                    RegistryError::InvalidArguments(format!(
                        "tool argument `{name}[{index}]` must be a JSON object"
                    ))
                })?;
                for key in object.keys() {
                    if !properties.contains_key(key) {
                        return Err(RegistryError::InvalidArguments(format!(
                            "unknown tool argument `{name}[{index}].{key}`"
                        )));
                    }
                }
                for (child_name, child_spec) in properties {
                    let path = format!("{name}[{index}].{child_name}");
                    let Some(child) = object.get(child_name) else {
                        if child_spec.required {
                            return Err(RegistryError::InvalidArguments(format!(
                                "missing required tool argument `{path}`"
                            )));
                        }
                        continue;
                    };
                    validate_parameter_value(&path, child_spec, child)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn write_canonical(value: &Value, output: &mut Vec<u8>) {
    enum Token<'a> {
        Value(&'a Value),
        Byte(u8),
        String(&'a str),
    }

    fn write_string(value: &str, output: &mut Vec<u8>) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        output.push(b'"');
        for character in value.chars() {
            match character {
                '"' => output.extend_from_slice(br#"\""#),
                '\\' => output.extend_from_slice(br#"\\"#),
                '\u{8}' => output.extend_from_slice(br"\b"),
                '\t' => output.extend_from_slice(br"\t"),
                '\n' => output.extend_from_slice(br"\n"),
                '\u{c}' => output.extend_from_slice(br"\f"),
                '\r' => output.extend_from_slice(br"\r"),
                character if character <= '\u{1f}' => {
                    let byte = character as u8;
                    output.extend_from_slice(br"\u00");
                    output.push(HEX[(byte >> 4) as usize]);
                    output.push(HEX[(byte & 0x0f) as usize]);
                }
                character => {
                    let mut encoded = [0u8; 4];
                    output.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
                }
            }
        }
        output.push(b'"');
    }

    let mut pending = vec![Token::Value(value)];
    while let Some(token) = pending.pop() {
        match token {
            Token::Byte(byte) => output.push(byte),
            Token::String(string) => write_string(string, output),
            Token::Value(Value::Null) => output.extend_from_slice(b"null"),
            Token::Value(Value::Bool(true)) => output.extend_from_slice(b"true"),
            Token::Value(Value::Bool(false)) => output.extend_from_slice(b"false"),
            Token::Value(Value::Number(number)) => {
                output.extend_from_slice(number.to_string().as_bytes());
            }
            Token::Value(Value::String(string)) => write_string(string, output),
            Token::Value(Value::Array(values)) => {
                output.push(b'[');
                pending.push(Token::Byte(b']'));
                for index in (0..values.len()).rev() {
                    if index < values.len() - 1 {
                        pending.push(Token::Byte(b','));
                    }
                    pending.push(Token::Value(&values[index]));
                }
            }
            Token::Value(Value::Object(values)) => {
                output.push(b'{');
                pending.push(Token::Byte(b'}'));
                let mut entries = values.iter().collect::<Vec<_>>();
                entries.sort_unstable_by_key(|(key, _)| *key);
                for index in (0..entries.len()).rev() {
                    if index < entries.len() - 1 {
                        pending.push(Token::Byte(b','));
                    }
                    let (key, value) = entries[index];
                    pending.push(Token::Value(value));
                    pending.push(Token::Byte(b':'));
                    pending.push(Token::String(key));
                }
            }
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

    #[derive(Clone)]
    struct FailingExecutor(ExecutorError);

    impl ToolExecutor for FailingExecutor {
        fn execute(&self, _request: ExecutionRequest) -> ExecutionFuture<'_> {
            let error = self.0.clone();
            Box::pin(async move { Err(error) })
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
        let first = stable_call_id("ZR-1842", 7, 11, "telemetry_query").unwrap();
        let retry = stable_call_id("ZR-1842", 7, 11, "telemetry_query").unwrap();
        assert_eq!(first, retry);
        assert_eq!(
            provider_idempotency_key(&first).unwrap(),
            provider_idempotency_key(&retry).unwrap()
        );
    }

    #[test]
    fn agent_call_ids_depend_only_on_the_durable_logical_position() {
        let first = stable_agent_call_id("agent-turn-7", 3, 1).unwrap();
        let retry = stable_agent_call_id("agent-turn-7", 3, 1).unwrap();
        assert_eq!(first, retry);
        assert_eq!(first.len(), "call-".len() + 64);
        assert_ne!(first, stable_agent_call_id("agent-turn-8", 3, 1).unwrap());
        assert_ne!(first, stable_agent_call_id("agent-turn-7", 4, 1).unwrap());
        assert_ne!(first, stable_agent_call_id("agent-turn-7", 3, 2).unwrap());
        assert!(stable_agent_call_id("model supplied/tool", 3, 1).is_err());
        assert!(stable_agent_call_id(&"a".repeat(MAX_EXECUTION_SCOPE_FIELD_BYTES), 3, 1).is_ok());
        assert!(
            stable_agent_call_id(&"a".repeat(MAX_EXECUTION_SCOPE_FIELD_BYTES + 1), 3, 1).is_err()
        );
    }

    #[test]
    fn execution_scope_is_complete_bounded_and_control_free() {
        let scope =
            ExecutionScope::new("account-1", "user-1", "session-1", "turn-1", "agent-1").unwrap();
        assert_eq!(scope.account_id, "account-1");
        assert_eq!(scope.actor_id, "user-1");

        for invalid in ["", " leading", "trailing ", "line\nbreak"] {
            assert!(matches!(
                ExecutionScope::new(invalid, "user", "session", "turn", "agent"),
                Err(RegistryError::InvalidExecutionScope(_))
            ));
        }
        assert!(matches!(
            ExecutionScope::new(
                "a".repeat(MAX_EXECUTION_SCOPE_FIELD_BYTES + 1),
                "user",
                "session",
                "turn",
                "agent",
            ),
            Err(RegistryError::InvalidExecutionScope(_))
        ));
    }

    #[test]
    fn provider_json_schema_is_closed_typed_and_deterministic() {
        let schema = ObjectSchema {
            max_serialized_bytes: 512,
            properties: BTreeMap::from([
                (
                    "count".into(),
                    ParameterSpec {
                        parameter_type: ParameterType::Integer,
                        required: false,
                        min_length: None,
                        max_length: None,
                    },
                ),
                (
                    "query".into(),
                    ParameterSpec {
                        parameter_type: ParameterType::String,
                        required: true,
                        min_length: Some(1),
                        max_length: Some(16),
                    },
                ),
                (
                    "tags".into(),
                    ParameterSpec {
                        parameter_type: ParameterType::Array,
                        required: false,
                        min_length: None,
                        max_length: None,
                    },
                ),
            ]),
        };

        assert_eq!(
            schema.provider_json_schema().unwrap(),
            json!({
                "type": "object",
                "properties": {
                    "count": { "type": "integer" },
                    "query": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 16
                    },
                    "tags": { "type": "array" }
                },
                "required": ["query"],
                "additionalProperties": false,
                "x-zeus-max-serialized-bytes": 512
            })
        );
        assert!(schema.validate_arguments(&json!({"query": "safe"})).is_ok());
        assert!(
            schema
                .validate_arguments(&json!({"query": "safe", "effect": "destructive"}))
                .is_err()
        );
    }

    #[test]
    fn nested_array_object_schema_is_closed_bounded_and_enum_aware() {
        let schema = ObjectSchema {
            max_serialized_bytes: 1024,
            properties: BTreeMap::from([(
                "items".into(),
                ParameterSpec {
                    parameter_type: ParameterType::ArrayOfObjects {
                        min_items: 0,
                        max_items: 2,
                        properties: BTreeMap::from([
                            ("content".into(), ParameterSpec::required_string(32)),
                            (
                                "status".into(),
                                ParameterSpec {
                                    parameter_type: ParameterType::StringEnum {
                                        values: vec!["pending".into(), "completed".into()],
                                    },
                                    required: true,
                                    min_length: None,
                                    max_length: None,
                                },
                            ),
                        ]),
                    },
                    required: true,
                    min_length: None,
                    max_length: None,
                },
            )]),
        };

        assert_eq!(
            schema.provider_json_schema().unwrap(),
            json!({
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "minItems": 0,
                        "maxItems": 2,
                        "items": {
                            "type": "object",
                            "properties": {
                                "content": {"type": "string", "minLength": 1, "maxLength": 32},
                                "status": {"type": "string", "enum": ["pending", "completed"]}
                            },
                            "required": ["content", "status"],
                            "additionalProperties": false
                        }
                    }
                },
                "required": ["items"],
                "additionalProperties": false,
                "x-zeus-max-serialized-bytes": 1024
            })
        );
        assert!(
            schema
                .validate_arguments(&json!({"items": [{"content": "ship", "status": "pending"}]}))
                .is_ok()
        );
        for invalid in [
            json!({"items": [{"content": "ship", "status": "unknown"}]}),
            json!({"items": [{"content": "ship", "status": "pending", "extra": true}]}),
            json!({"items": [{"content": "ship"}]}),
            json!({"items": ["ship"]}),
            json!({"items": [{"content": "a", "status": "pending"}, {"content": "b", "status": "pending"}, {"content": "c", "status": "pending"}]}),
        ] {
            assert!(schema.validate_arguments(&invalid).is_err());
        }
    }

    #[test]
    fn registry_rejects_names_that_cannot_be_exposed_to_model_providers() {
        for name in [
            "known.query".to_owned(),
            "a".repeat(MAX_TOOL_NAME_BYTES + 1),
        ] {
            let mut registry = ToolRegistry::new();
            assert!(matches!(
                registry.register(
                    descriptor(&name),
                    RecordingExecutor::new(json!({"ok": true}))
                ),
                Err(RegistryError::InvalidDescriptor(_))
            ));
        }
    }

    #[tokio::test]
    async fn unknown_tool_never_calls_a_registered_executor() {
        let recorder = RecordingExecutor::new(json!({"ok": true}));
        let mut registry = ToolRegistry::new();
        registry
            .register(descriptor("known_query"), recorder.clone())
            .unwrap();

        let error = registry
            .dispatch(
                call("unknown_query", json!({"query": "safe"})),
                "local-development",
            )
            .await
            .unwrap_err();
        assert_eq!(error, RegistryError::UnknownTool("unknown_query".into()));
        assert!(recorder.calls().is_empty());
    }

    #[tokio::test]
    async fn invalid_contract_and_parameters_never_reach_executor() {
        let recorder = RecordingExecutor::new(json!({"ok": true}));
        let mut registry = ToolRegistry::new();
        registry
            .register(descriptor("known_query"), recorder.clone())
            .unwrap();

        let mut wrong_digest = call("known_query", json!({"query": "safe"}));
        wrong_digest.arguments_digest = arguments_digest(&json!({"query": "changed"}));
        assert!(matches!(
            registry.dispatch(wrong_digest, "local-development").await,
            Err(RegistryError::ContractMismatch {
                field: "arguments_digest"
            })
        ));

        let unknown_argument = call(
            "known_query",
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
            .register(descriptor("known_query"), recorder.clone())
            .unwrap();
        let call = call("known_query", json!({"query": "safe"}));
        let expected_key = provider_idempotency_key(&call.call_id).unwrap();

        registry.dispatch(call, "local-development").await.unwrap();

        let calls = recorder.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].provider_idempotency_key, expected_key);
        assert!(calls[0].scope.is_none());
    }

    #[tokio::test]
    async fn scoped_dispatch_supplies_exact_server_owned_context() {
        let recorder = RecordingExecutor::new(json!({"ok": true}));
        let mut registry = ToolRegistry::new();
        registry
            .register(descriptor("known_query"), recorder.clone())
            .unwrap();
        let scope =
            ExecutionScope::new("account-1", "user-1", "session-1", "turn-1", "agent-1").unwrap();

        registry
            .dispatch_scoped(
                call("known_query", json!({"query": "safe"})),
                "local-development",
                scope.clone(),
            )
            .await
            .unwrap();

        let calls = recorder.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].scope.as_ref(), Some(&scope));
    }

    #[tokio::test]
    async fn unavailable_executor_is_explicit() {
        let mut registry = ToolRegistry::new();
        registry
            .register(
                descriptor("offline_query"),
                UnavailableExecutor::new("provider is not configured"),
            )
            .unwrap();
        let error = registry
            .dispatch(
                call("offline_query", json!({"query": "safe"})),
                "local-development",
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            RegistryError::Executor(ExecutorError::Unavailable { .. })
        ));
    }

    #[tokio::test]
    async fn executor_output_is_bounded_before_digest_or_persistence() {
        let exact = RecordingExecutor::new(Value::String(
            "x".repeat(TOOL_OUTPUT_MAX_SERIALIZED_BYTES - 2),
        ));
        let mut registry = ToolRegistry::new();
        registry
            .register(descriptor("exact_query"), exact.clone())
            .unwrap();
        registry
            .dispatch(
                call("exact_query", json!({"query": "safe"})),
                "local-development",
            )
            .await
            .unwrap();
        assert_eq!(exact.calls().len(), 1);

        let oversized = RecordingExecutor::new(Value::String(
            "x".repeat(TOOL_OUTPUT_MAX_SERIALIZED_BYTES - 1),
        ));
        registry
            .register(descriptor("large_query"), oversized.clone())
            .unwrap();
        assert_eq!(
            registry
                .dispatch(
                    call("large_query", json!({"query": "safe"})),
                    "local-development",
                )
                .await,
            Err(RegistryError::ExecutorOutputTooLarge {
                limit_bytes: TOOL_OUTPUT_MAX_SERIALIZED_BYTES,
            })
        );
        assert_eq!(oversized.calls().len(), 1);
    }

    #[tokio::test]
    async fn executor_diagnostics_are_bounded_after_invocation() {
        let mut registry = ToolRegistry::new();
        registry
            .register(
                descriptor("bad_query"),
                FailingExecutor(ExecutorError::Failed {
                    code: "executor_failed".into(),
                    message: "x".repeat(protocol::TOOL_OUTCOME_SUMMARY_MAX_BYTES + 1),
                    retryable: false,
                }),
            )
            .unwrap();
        assert_eq!(
            registry
                .dispatch(
                    call("bad_query", json!({"query": "safe"})),
                    "local-development",
                )
                .await,
            Err(RegistryError::InvalidExecutorDiagnostic {
                field: "failure message",
            })
        );

        registry
            .register(
                descriptor("bad-code_query"),
                FailingExecutor(ExecutorError::Failed {
                    code: "x".repeat(protocol::TOOL_OUTCOME_CODE_MAX_BYTES + 1),
                    message: "bounded failure".into(),
                    retryable: false,
                }),
            )
            .unwrap();
        assert_eq!(
            registry
                .dispatch(
                    call("bad-code_query", json!({"query": "safe"})),
                    "local-development",
                )
                .await,
            Err(RegistryError::InvalidExecutorDiagnostic {
                field: "failure code",
            })
        );
    }

    #[tokio::test]
    async fn provider_request_id_is_bounded_and_ascii_graphic() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let exact = RecordingExecutor {
            calls: Arc::clone(&calls),
            output: ToolOutput {
                value: json!({"ok": true}),
                replayed: false,
                provider_request_id: Some("x".repeat(PROVIDER_REQUEST_ID_MAX_BYTES)),
            },
        };
        let mut registry = ToolRegistry::new();
        registry
            .register(descriptor("request-id_query"), exact)
            .unwrap();
        registry
            .dispatch(
                call("request-id_query", json!({"query": "safe"})),
                "local-development",
            )
            .await
            .unwrap();

        let oversized = RecordingExecutor {
            calls,
            output: ToolOutput {
                value: json!({"ok": true}),
                replayed: false,
                provider_request_id: Some("x".repeat(PROVIDER_REQUEST_ID_MAX_BYTES + 1)),
            },
        };
        registry
            .register(descriptor("large-request-id_query"), oversized)
            .unwrap();
        assert_eq!(
            registry
                .dispatch(
                    call("large-request-id_query", json!({"query": "safe"})),
                    "local-development",
                )
                .await,
            Err(RegistryError::InvalidExecutorOutput {
                field: "provider_request_id",
            })
        );
    }

    #[test]
    fn iterative_json_length_matches_compact_serde_for_escape_heavy_values() {
        let value = json!({
            "quote\"": ["\0\n\\\"", true, false, null, 123],
            "unicode": "界🙂",
        });
        let expected = serde_json::to_vec(&value).unwrap().len();
        assert_eq!(
            serialized_json_len_bounded(&value, expected),
            Some(expected)
        );
        assert_eq!(serialized_json_len_bounded(&value, expected - 1), None);
    }
}
