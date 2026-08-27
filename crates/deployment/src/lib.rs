//! Versioned, secret-free Agent deployment manifests.
//!
//! A manifest is the immutable configuration identity for one Agent execution.
//! It records only durable, non-secret bindings. Provider endpoints, API keys,
//! resolved secret values, and other credentials deliberately have no field in
//! these types.

use std::collections::{BTreeMap, BTreeSet};

use protocol::{AssistantReplyKind, SandboxProfile, ToolEffect, ToolExecutorStatus};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const AGENT_SPEC_SCHEMA_VERSION: u16 = 1;
pub const AGENT_DEPLOYMENT_SCHEMA_VERSION: u16 = 1;
pub const DEPLOYMENT_MANIFEST_SCHEMA_VERSION: u16 = 1;
pub const MANIFEST_ENVELOPE_SCHEMA_VERSION: u16 = 1;

pub const MAX_MANIFEST_TOOLS: usize = 32;
pub const MAX_TOOL_NAME_BYTES: usize = 64;
pub const MAX_TOOL_DESCRIPTION_BYTES: usize = 4 * 1024;
pub const MAX_TOOL_SCHEMA_BYTES: usize = 64 * 1024;
pub const MAX_AGGREGATE_TOOL_SCHEMA_BYTES: usize = 64 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 256 * 1024;

const MAX_PROFILE_BYTES: usize = 64;
const MAX_ENVIRONMENT_BYTES: usize = 64;
const MAX_TOOL_VERSION_BYTES: usize = 64;
const SHA256_HEX_BYTES: usize = 64;
const MANIFEST_DIGEST_DOMAIN: &[u8] = b"zeus.deployment-manifest.sha256.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ManifestProvider {
    pub provider_id: String,
    pub model: Option<String>,
    pub reply_kind: AssistantReplyKind,
}

impl ManifestProvider {
    pub fn new(
        provider_id: impl Into<String>,
        model: Option<String>,
        reply_kind: AssistantReplyKind,
    ) -> Result<Self, ManifestError> {
        let provider = Self {
            provider_id: provider_id.into(),
            model,
            reply_kind,
        };
        provider.validate()?;
        Ok(provider)
    }

    pub fn validate(&self) -> Result<(), ManifestError> {
        protocol::validate_reply_provider_id(&self.provider_id)
            .map_err(|error| invalid_field("provider.provider_id", error))?;
        match (&self.reply_kind, &self.model) {
            (AssistantReplyKind::Model, Some(model)) => {
                protocol::validate_reply_model_id(model)
                    .map_err(|error| invalid_field("provider.model", error))?;
            }
            (AssistantReplyKind::Model, None) => {
                return Err(ManifestError::InvalidField {
                    field: "provider.model",
                    reason: "a model reply provider must bind a model".into(),
                });
            }
            (AssistantReplyKind::NonModelFallback, None) => {}
            (AssistantReplyKind::NonModelFallback, Some(_)) => {
                return Err(ManifestError::InvalidField {
                    field: "provider.model",
                    reason: "a non-model fallback must not bind a model".into(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ManifestPolicy {
    pub policy_id: String,
    pub revision: String,
}

impl ManifestPolicy {
    pub fn new(
        policy_id: impl Into<String>,
        revision: impl Into<String>,
    ) -> Result<Self, ManifestError> {
        let policy = Self {
            policy_id: policy_id.into(),
            revision: revision.into(),
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), ManifestError> {
        validate_resource_identifier("policy.policy_id", &self.policy_id)?;
        validate_resource_identifier("policy.revision", &self.revision)
    }
}

/// Optional prompt identity. Prompt content is intentionally excluded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ManifestPromptBinding {
    pub prompt_id: String,
    pub revision: String,
    pub content_digest: String,
}

impl ManifestPromptBinding {
    pub fn new(
        prompt_id: impl Into<String>,
        revision: impl Into<String>,
        content_digest: impl Into<String>,
    ) -> Result<Self, ManifestError> {
        let prompt = Self {
            prompt_id: prompt_id.into(),
            revision: revision.into(),
            content_digest: content_digest.into(),
        };
        prompt.validate()?;
        Ok(prompt)
    }

    pub fn validate(&self) -> Result<(), ManifestError> {
        validate_resource_identifier("prompt.prompt_id", &self.prompt_id)?;
        validate_resource_identifier("prompt.revision", &self.revision)?;
        validate_sha256_hex("prompt.content_digest", &self.content_digest)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ManifestTool {
    pub name: String,
    pub version: String,
    pub description: String,
    pub input_schema: Value,
    pub effect: ToolEffect,
    pub sandbox_profile: SandboxProfile,
    pub executor_status: ToolExecutorStatus,
}

impl ManifestTool {
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        description: impl Into<String>,
        input_schema: Value,
        effect: ToolEffect,
        sandbox_profile: SandboxProfile,
        executor_status: ToolExecutorStatus,
    ) -> Result<Self, ManifestError> {
        let tool = Self {
            name: name.into(),
            version: version.into(),
            description: description.into(),
            input_schema: canonicalize_json(input_schema),
            effect,
            sandbox_profile,
            executor_status,
        };
        tool.validate()?;
        Ok(tool)
    }

    pub fn validate(&self) -> Result<(), ManifestError> {
        validate_tool_name(&self.name)?;
        validate_tool_version(&self.version)?;
        validate_tool_description(&self.description)?;
        let schema = self
            .input_schema
            .as_object()
            .ok_or_else(|| ManifestError::InvalidField {
                field: "tool.input_schema",
                reason: "the tool schema must be a JSON object".into(),
            })?;
        if schema.get("type") != Some(&Value::String("object".into())) {
            return Err(ManifestError::InvalidField {
                field: "tool.input_schema.type",
                reason: "the top-level tool schema type must be object".into(),
            });
        }
        let bytes = canonical_json_bytes_for_value(&self.input_schema)?;
        if bytes.len() > MAX_TOOL_SCHEMA_BYTES {
            return Err(ManifestError::ToolSchemaTooLarge {
                tool: self.name.clone(),
                max_bytes: MAX_TOOL_SCHEMA_BYTES,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct AgentSpec {
    pub schema_version: u16,
    pub spec_id: String,
    pub revision: String,
    pub profile: String,
    pub environment: String,
    pub provider: ManifestProvider,
    pub policy: ManifestPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<ManifestPromptBinding>,
    pub workflow_schema_version: u16,
    pub loop_limits: workflows::Limits,
    pub tools: Vec<ManifestTool>,
}

impl AgentSpec {
    pub fn new(
        spec_id: impl Into<String>,
        revision: impl Into<String>,
        profile: impl Into<String>,
        environment: impl Into<String>,
        provider: ManifestProvider,
        policy: ManifestPolicy,
    ) -> Result<Self, ManifestError> {
        let spec = Self {
            schema_version: AGENT_SPEC_SCHEMA_VERSION,
            spec_id: spec_id.into(),
            revision: revision.into(),
            profile: profile.into(),
            environment: environment.into(),
            provider,
            policy,
            prompt: None,
            workflow_schema_version: workflows::STATE_SCHEMA_VERSION,
            loop_limits: workflows::Limits::default(),
            tools: Vec::new(),
        };
        spec.validate()?;
        Ok(spec)
    }

    pub fn with_prompt(mut self, prompt: ManifestPromptBinding) -> Result<Self, ManifestError> {
        self.prompt = Some(prompt);
        self.validate()?;
        Ok(self)
    }

    pub fn with_workflow(
        mut self,
        workflow_schema_version: u16,
        loop_limits: workflows::Limits,
    ) -> Result<Self, ManifestError> {
        self.workflow_schema_version = workflow_schema_version;
        self.loop_limits = loop_limits;
        self.validate()?;
        Ok(self)
    }

    /// Installs a canonical, name-sorted tool set.
    pub fn with_tools(mut self, mut tools: Vec<ManifestTool>) -> Result<Self, ManifestError> {
        tools.sort_by(|left, right| left.name.cmp(&right.name));
        self.tools = tools;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), ManifestError> {
        validate_schema_version("agent_spec", self.schema_version, AGENT_SPEC_SCHEMA_VERSION)?;
        validate_resource_identifier("spec.spec_id", &self.spec_id)?;
        validate_resource_identifier("spec.revision", &self.revision)?;
        validate_runtime_label("spec.profile", &self.profile, MAX_PROFILE_BYTES)?;
        validate_runtime_label("spec.environment", &self.environment, MAX_ENVIRONMENT_BYTES)?;
        self.provider.validate()?;
        self.policy.validate()?;
        if let Some(prompt) = &self.prompt {
            prompt.validate()?;
        }
        validate_schema_version(
            "workflow_state",
            self.workflow_schema_version,
            workflows::STATE_SCHEMA_VERSION,
        )?;
        workflows::State::new(self.loop_limits.clone())
            .map_err(|error| ManifestError::InvalidWorkflowLimits(error.to_string()))?;
        if self.tools.len() > MAX_MANIFEST_TOOLS {
            return Err(ManifestError::TooManyTools {
                max: MAX_MANIFEST_TOOLS,
            });
        }

        let mut aggregate_schema_bytes = 0usize;
        let mut previous_name: Option<&str> = None;
        for tool in &self.tools {
            tool.validate()?;
            if let Some(previous) = previous_name {
                if previous == tool.name {
                    return Err(ManifestError::DuplicateTool(tool.name.clone()));
                }
                if previous > tool.name.as_str() {
                    return Err(ManifestError::NonCanonicalToolOrder);
                }
            }
            previous_name = Some(&tool.name);
            aggregate_schema_bytes = aggregate_schema_bytes
                .checked_add(canonical_json_bytes_for_value(&tool.input_schema)?.len())
                .ok_or(ManifestError::AggregateToolSchemasTooLarge {
                    max_bytes: MAX_AGGREGATE_TOOL_SCHEMA_BYTES,
                })?;
            if aggregate_schema_bytes > MAX_AGGREGATE_TOOL_SCHEMA_BYTES {
                return Err(ManifestError::AggregateToolSchemasTooLarge {
                    max_bytes: MAX_AGGREGATE_TOOL_SCHEMA_BYTES,
                });
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct AgentDeployment {
    pub schema_version: u16,
    pub deployment_id: String,
    pub revision: String,
    pub spec: AgentSpec,
}

impl AgentDeployment {
    pub fn new(
        deployment_id: impl Into<String>,
        revision: impl Into<String>,
        spec: AgentSpec,
    ) -> Result<Self, ManifestError> {
        let deployment = Self {
            schema_version: AGENT_DEPLOYMENT_SCHEMA_VERSION,
            deployment_id: deployment_id.into(),
            revision: revision.into(),
            spec,
        };
        deployment.validate()?;
        Ok(deployment)
    }

    pub fn validate(&self) -> Result<(), ManifestError> {
        validate_schema_version(
            "agent_deployment",
            self.schema_version,
            AGENT_DEPLOYMENT_SCHEMA_VERSION,
        )?;
        validate_resource_identifier("deployment.deployment_id", &self.deployment_id)?;
        validate_resource_identifier("deployment.revision", &self.revision)?;
        self.spec.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct DeploymentManifest {
    pub schema_version: u16,
    pub deployment: AgentDeployment,
}

impl DeploymentManifest {
    pub fn new(deployment: AgentDeployment) -> Result<Self, ManifestError> {
        let manifest = Self {
            schema_version: DEPLOYMENT_MANIFEST_SCHEMA_VERSION,
            deployment,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), ManifestError> {
        validate_schema_version(
            "deployment_manifest",
            self.schema_version,
            DEPLOYMENT_MANIFEST_SCHEMA_VERSION,
        )?;
        self.deployment.validate()?;
        let bytes = canonical_json_bytes_unchecked(self)?;
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ManifestError::ManifestTooLarge {
                max_bytes: MAX_MANIFEST_BYTES,
            });
        }
        Ok(())
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, ManifestError> {
        self.validate()?;
        canonical_json_bytes_unchecked(self)
    }

    /// Computes a domain-separated SHA-256 over canonical manifest JSON.
    pub fn digest(&self) -> Result<String, ManifestError> {
        let bytes = self.canonical_json_bytes()?;
        let mut digest = Sha256::new();
        digest.update(
            u64::try_from(MANIFEST_DIGEST_DOMAIN.len())
                .expect("the digest domain length fits in u64")
                .to_be_bytes(),
        );
        digest.update(MANIFEST_DIGEST_DOMAIN);
        digest.update(
            u64::try_from(bytes.len())
                .expect("the bounded manifest length fits in u64")
                .to_be_bytes(),
        );
        digest.update(bytes);
        Ok(format!("{:x}", digest.finalize()))
    }

    /// Returns a stable JSON-pointer diff ordered by object key and array index.
    pub fn diff(&self, other: &Self) -> Result<ManifestDiff, ManifestError> {
        self.validate()?;
        other.validate()?;
        let before = canonicalize_json(
            serde_json::to_value(self)
                .map_err(|error| ManifestError::Serialization(error.to_string()))?,
        );
        let after = canonicalize_json(
            serde_json::to_value(other)
                .map_err(|error| ManifestError::Serialization(error.to_string()))?,
        );
        let mut changes = Vec::new();
        diff_value("", &before, &after, &mut changes);
        Ok(ManifestDiff { changes })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ManifestEnvelope {
    pub schema_version: u16,
    pub digest: String,
    pub manifest: DeploymentManifest,
}

impl ManifestEnvelope {
    pub fn new(manifest: DeploymentManifest) -> Result<Self, ManifestError> {
        let digest = manifest.digest()?;
        let envelope = Self {
            schema_version: MANIFEST_ENVELOPE_SCHEMA_VERSION,
            digest,
            manifest,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn from_deployment(deployment: AgentDeployment) -> Result<Self, ManifestError> {
        Self::new(DeploymentManifest::new(deployment)?)
    }

    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, ManifestError> {
        let envelope: Self = serde_json::from_slice(bytes)
            .map_err(|error| ManifestError::InvalidJson(error.to_string()))?;
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn validate(&self) -> Result<(), ManifestError> {
        validate_schema_version(
            "manifest_envelope",
            self.schema_version,
            MANIFEST_ENVELOPE_SCHEMA_VERSION,
        )?;
        validate_sha256_hex("envelope.digest", &self.digest)?;
        self.manifest.validate()?;
        let expected = self.manifest.digest()?;
        if self.digest != expected {
            return Err(ManifestError::DigestMismatch);
        }
        Ok(())
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, ManifestError> {
        self.validate()?;
        canonical_json_bytes_unchecked(self)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ManifestDiff {
    pub changes: Vec<ManifestChange>,
}

impl ManifestDiff {
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ManifestChange {
    pub path: String,
    pub before: Option<Value>,
    pub after: Option<Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ManifestError {
    #[error("unsupported {kind} schema version {actual}; expected {expected}")]
    UnsupportedSchemaVersion {
        kind: &'static str,
        expected: u16,
        actual: u16,
    },
    #[error("invalid manifest field `{field}`: {reason}")]
    InvalidField { field: &'static str, reason: String },
    #[error("invalid Agent workflow limits: {0}")]
    InvalidWorkflowLimits(String),
    #[error("a deployment manifest cannot contain more than {max} tools")]
    TooManyTools { max: usize },
    #[error("duplicate manifest tool `{0}`")]
    DuplicateTool(String),
    #[error("manifest tools must be ordered by name")]
    NonCanonicalToolOrder,
    #[error("tool `{tool}` schema exceeds the {max_bytes}-byte limit")]
    ToolSchemaTooLarge { tool: String, max_bytes: usize },
    #[error("aggregate tool schemas exceed the {max_bytes}-byte limit")]
    AggregateToolSchemasTooLarge { max_bytes: usize },
    #[error("deployment manifest exceeds the {max_bytes}-byte limit")]
    ManifestTooLarge { max_bytes: usize },
    #[error("manifest digest does not match its canonical payload")]
    DigestMismatch,
    #[error("invalid manifest JSON: {0}")]
    InvalidJson(String),
    #[error("manifest serialization failed: {0}")]
    Serialization(String),
}

fn invalid_field(field: &'static str, error: impl std::fmt::Display) -> ManifestError {
    ManifestError::InvalidField {
        field,
        reason: error.to_string(),
    }
}

fn validate_schema_version(
    kind: &'static str,
    actual: u16,
    expected: u16,
) -> Result<(), ManifestError> {
    if actual != expected {
        return Err(ManifestError::UnsupportedSchemaVersion {
            kind,
            expected,
            actual,
        });
    }
    Ok(())
}

fn validate_resource_identifier(field: &'static str, value: &str) -> Result<(), ManifestError> {
    protocol::validate_resource_id(value).map_err(|error| invalid_field(field, error))
}

fn validate_runtime_label(
    field: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), ManifestError> {
    if value.is_empty()
        || value.len() > max_bytes
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || byte == b'-'
                || byte == b'_'
                || byte == b'.'
        })
    {
        return Err(ManifestError::InvalidField {
            field,
            reason: format!(
                "must contain 1..={max_bytes} lowercase ASCII letters, digits, dots, dashes, or underscores"
            ),
        });
    }
    Ok(())
}

fn validate_tool_name(name: &str) -> Result<(), ManifestError> {
    if name.is_empty()
        || name.len() > MAX_TOOL_NAME_BYTES
        || name.starts_with('.')
        || name.ends_with('.')
        || name.split('.').any(str::is_empty)
        || !name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
    {
        return Err(ManifestError::InvalidField {
            field: "tool.name",
            reason: "must be lowercase ASCII segments separated by dots".into(),
        });
    }
    Ok(())
}

fn validate_tool_version(version: &str) -> Result<(), ManifestError> {
    if version.is_empty()
        || version.len() > MAX_TOOL_VERSION_BYTES
        || !version.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
        })
    {
        return Err(ManifestError::InvalidField {
            field: "tool.version",
            reason: format!(
                "must contain 1..={MAX_TOOL_VERSION_BYTES} ASCII letters, digits, dots, dashes, or underscores"
            ),
        });
    }
    Ok(())
}

fn validate_tool_description(description: &str) -> Result<(), ManifestError> {
    if description.trim().is_empty() || description.len() > MAX_TOOL_DESCRIPTION_BYTES {
        return Err(ManifestError::InvalidField {
            field: "tool.description",
            reason: format!(
                "must contain 1..={MAX_TOOL_DESCRIPTION_BYTES} UTF-8 bytes and cannot be blank"
            ),
        });
    }
    if description.chars().any(char::is_control) {
        return Err(ManifestError::InvalidField {
            field: "tool.description",
            reason: "must not contain control characters".into(),
        });
    }
    Ok(())
}

fn validate_sha256_hex(field: &'static str, value: &str) -> Result<(), ManifestError> {
    if value.len() != SHA256_HEX_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ManifestError::InvalidField {
            field,
            reason: "must be a 64-character lowercase SHA-256 hex digest".into(),
        });
    }
    Ok(())
}

fn canonicalize_json(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let sorted = object
                .into_iter()
                .map(|(key, value)| (key, canonicalize_json(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_json).collect()),
        scalar => scalar,
    }
}

fn canonical_json_bytes_for_value(value: &Value) -> Result<Vec<u8>, ManifestError> {
    serde_json::to_vec(&canonicalize_json(value.clone()))
        .map_err(|error| ManifestError::Serialization(error.to_string()))
}

fn canonical_json_bytes_unchecked(value: &impl Serialize) -> Result<Vec<u8>, ManifestError> {
    let value = serde_json::to_value(value)
        .map_err(|error| ManifestError::Serialization(error.to_string()))?;
    canonical_json_bytes_for_value(&value)
}

fn diff_value(path: &str, before: &Value, after: &Value, changes: &mut Vec<ManifestChange>) {
    if before == after {
        return;
    }
    match (before, after) {
        (Value::Object(before), Value::Object(after)) => {
            let keys = before
                .keys()
                .chain(after.keys())
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            for key in keys {
                let child_path = format!("{path}/{}", escape_json_pointer(key));
                match (before.get(key), after.get(key)) {
                    (Some(before), Some(after)) => {
                        diff_value(&child_path, before, after, changes);
                    }
                    (before, after) => changes.push(ManifestChange {
                        path: child_path,
                        before: before.cloned(),
                        after: after.cloned(),
                    }),
                }
            }
        }
        (Value::Array(before), Value::Array(after)) => {
            let common = before.len().min(after.len());
            for index in 0..common {
                diff_value(
                    &format!("{path}/{index}"),
                    &before[index],
                    &after[index],
                    changes,
                );
            }
            for (index, value) in before.iter().enumerate().skip(common) {
                changes.push(ManifestChange {
                    path: format!("{path}/{index}"),
                    before: Some(value.clone()),
                    after: None,
                });
            }
            for (index, value) in after.iter().enumerate().skip(common) {
                changes.push(ManifestChange {
                    path: format!("{path}/{index}"),
                    before: None,
                    after: Some(value.clone()),
                });
            }
        }
        _ => changes.push(ManifestChange {
            path: path.to_owned(),
            before: Some(before.clone()),
            after: Some(after.clone()),
        }),
    }
}

fn escape_json_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn provider(model: &str) -> ManifestProvider {
        ManifestProvider::new(
            "openai-compatible:route-digest",
            Some(model.into()),
            AssistantReplyKind::Model,
        )
        .unwrap()
    }

    fn policy() -> ManifestPolicy {
        ManifestPolicy::new("incident-policy", "production-guarded/v1").unwrap()
    }

    fn tool(name: &str, schema: Value) -> ManifestTool {
        ManifestTool::new(
            name,
            "1.0.0",
            format!("Execute the declared {name} operation"),
            schema,
            ToolEffect::ReadOnly,
            SandboxProfile::ReadOnly,
            ToolExecutorStatus::Available,
        )
        .unwrap()
    }

    fn manifest(model: &str, schemas_reversed: bool, tools_reversed: bool) -> DeploymentManifest {
        let alpha_schema = if schemas_reversed {
            serde_json::from_str(
                r#"{"type":"object","required":["path"],"properties":{"path":{"type":"string","maxLength":128}},"additionalProperties":false}"#,
            )
            .unwrap()
        } else {
            serde_json::from_str(
                r#"{"additionalProperties":false,"properties":{"path":{"maxLength":128,"type":"string"}},"required":["path"],"type":"object"}"#,
            )
            .unwrap()
        };
        let mut tools = vec![
            tool(
                "workspace.search",
                json!({
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                    "additionalProperties": false
                }),
            ),
            tool("workspace.read", alpha_schema),
        ];
        if tools_reversed {
            tools.reverse();
        }
        let prompt = ManifestPromptBinding::new(
            "incident-system-prompt",
            "7",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let spec = AgentSpec::new(
            "incident-agent",
            "12",
            "production-guarded",
            "production",
            provider(model),
            policy(),
        )
        .unwrap()
        .with_prompt(prompt)
        .unwrap()
        .with_tools(tools)
        .unwrap();
        let deployment = AgentDeployment::new("incident-agent-prod", "3", spec).unwrap();
        DeploymentManifest::new(deployment).unwrap()
    }

    fn assert_no_secret_fields(value: &Value) {
        match value {
            Value::Object(object) => {
                for (key, value) in object {
                    assert!(
                        !matches!(
                            key.as_str(),
                            "endpoint" | "api_key" | "secret" | "secret_value"
                        ),
                        "secret-bearing field `{key}` appeared in a manifest"
                    );
                    assert_no_secret_fields(value);
                }
            }
            Value::Array(values) => values.iter().for_each(assert_no_secret_fields),
            _ => {}
        }
    }

    #[test]
    fn canonical_key_and_tool_order_produce_one_digest() {
        let first = manifest("deepseek-chat", false, false);
        let second = manifest("deepseek-chat", true, true);

        assert_eq!(
            first.canonical_json_bytes().unwrap(),
            second.canonical_json_bytes().unwrap()
        );
        assert_eq!(first.digest().unwrap(), second.digest().unwrap());
        let names = first
            .deployment
            .spec
            .tools
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, ["workspace.read", "workspace.search"]);

        let canonical = String::from_utf8(first.canonical_json_bytes().unwrap()).unwrap();
        let additional = canonical.find("additionalProperties").unwrap();
        let properties = canonical.find("properties").unwrap();
        let required = canonical.find("required").unwrap();
        assert!(additional < properties && properties < required);
    }

    #[test]
    fn digest_has_a_locked_domain_separated_vector() {
        assert_eq!(
            manifest("deepseek-chat", false, false).digest().unwrap(),
            "1ad6155841680c4831208a2d78935de89190573c8cc83c47fe3f44b088d0a44b"
        );
    }

    #[test]
    fn deterministic_diff_reports_one_changed_field() {
        let before = manifest("deepseek-chat", false, false);
        let after = manifest("deepseek-reasoner", true, true);

        let diff = before.diff(&after).unwrap();
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].path, "/deployment/spec/provider/model");
        assert_eq!(diff.changes[0].before, Some(json!("deepseek-chat")));
        assert_eq!(diff.changes[0].after, Some(json!("deepseek-reasoner")));
    }

    #[test]
    fn construction_rejects_duplicate_invalid_and_oversize_tools() {
        let base = AgentSpec::new(
            "agent",
            "1",
            "production-guarded",
            "production",
            provider("deepseek-chat"),
            policy(),
        )
        .unwrap();
        let schema = json!({"type": "object", "properties": {}});
        let duplicate = vec![
            tool("workspace.read", schema.clone()),
            tool("workspace.read", schema),
        ];
        assert!(matches!(
            base.clone().with_tools(duplicate),
            Err(ManifestError::DuplicateTool(name)) if name == "workspace.read"
        ));

        assert!(matches!(
            ManifestTool::new(
                "Workspace Read",
                "1",
                "Read a bounded workspace file",
                json!({"type": "object"}),
                ToolEffect::ReadOnly,
                SandboxProfile::ReadOnly,
                ToolExecutorStatus::Available,
            ),
            Err(ManifestError::InvalidField {
                field: "tool.name",
                ..
            })
        ));
        assert!(matches!(
            ManifestTool::new(
                "a".repeat(MAX_TOOL_NAME_BYTES + 1),
                "1",
                "Read a bounded workspace file",
                json!({"type": "object"}),
                ToolEffect::ReadOnly,
                SandboxProfile::ReadOnly,
                ToolExecutorStatus::Available,
            ),
            Err(ManifestError::InvalidField {
                field: "tool.name",
                ..
            })
        ));

        assert!(matches!(
            ManifestTool::new(
                "workspace.read",
                "1",
                "Read a bounded workspace file",
                json!({"type": "object", "description": "x".repeat(MAX_TOOL_SCHEMA_BYTES)}),
                ToolEffect::ReadOnly,
                SandboxProfile::ReadOnly,
                ToolExecutorStatus::Available,
            ),
            Err(ManifestError::ToolSchemaTooLarge { .. })
        ));

        assert!(matches!(
            ManifestTool::new(
                "workspace.read",
                "1",
                "x".repeat(MAX_TOOL_DESCRIPTION_BYTES + 1),
                json!({"type": "object"}),
                ToolEffect::ReadOnly,
                SandboxProfile::ReadOnly,
                ToolExecutorStatus::Available,
            ),
            Err(ManifestError::InvalidField {
                field: "tool.description",
                ..
            })
        ));
    }

    #[test]
    fn construction_rejects_invalid_versions_limits_and_provider_shape() {
        assert!(matches!(
            ManifestProvider::new(
                "fallback",
                Some("must-not-exist".into()),
                AssistantReplyKind::NonModelFallback,
            ),
            Err(ManifestError::InvalidField {
                field: "provider.model",
                ..
            })
        ));

        let mut manifest = manifest("deepseek-chat", false, false);
        manifest.schema_version = DEPLOYMENT_MANIFEST_SCHEMA_VERSION + 1;
        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::UnsupportedSchemaVersion {
                kind: "deployment_manifest",
                ..
            })
        ));

        let spec = AgentSpec::new(
            "agent",
            "1",
            "production-guarded",
            "production",
            provider("deepseek-chat"),
            policy(),
        )
        .unwrap();
        let invalid_limits = workflows::Limits {
            max_model_steps: 0,
            ..workflows::Limits::default()
        };
        assert!(matches!(
            spec.with_workflow(workflows::STATE_SCHEMA_VERSION, invalid_limits),
            Err(ManifestError::InvalidWorkflowLimits(_))
        ));
    }

    #[test]
    fn envelope_round_trip_is_strict_and_secret_free() {
        let envelope = ManifestEnvelope::new(manifest("deepseek-chat", false, false)).unwrap();
        let bytes = envelope.canonical_json_bytes().unwrap();
        let serialized = String::from_utf8(bytes.clone()).unwrap();

        assert!(!serialized.contains("endpoint"));
        assert!(!serialized.contains("api_key"));
        assert!(!serialized.contains("\"secret\""));
        assert!(!serialized.contains("secret_value"));
        assert!(!serialized.contains("sk-test-never-persist"));
        assert_no_secret_fields(&serde_json::from_slice(&bytes).unwrap());
        assert_eq!(ManifestEnvelope::from_json_slice(&bytes).unwrap(), envelope);

        let mut value = serde_json::to_value(&envelope).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("api_key".into(), json!("sk-test-never-persist"));
        assert!(matches!(
            ManifestEnvelope::from_json_slice(&serde_json::to_vec(&value).unwrap()),
            Err(ManifestError::InvalidJson(_))
        ));
    }

    #[test]
    fn envelope_detects_digest_tampering() {
        let mut envelope = ManifestEnvelope::new(manifest("deepseek-chat", false, false)).unwrap();
        envelope.digest.replace_range(0..1, "f");
        assert!(matches!(
            envelope.validate(),
            Err(ManifestError::DigestMismatch)
        ));
    }
}
