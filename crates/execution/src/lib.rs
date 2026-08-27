//! Secret-free execution authority and append-only Agent execution facts.
//!
//! A [`RunEpoch`] records the exact immutable, per-operation authority observed
//! at a claim boundary. An [`ExecutionFact`] records a small typed workflow
//! fact and references request, response, result, error, manifest, and epoch
//! content only by digest. The durable authority types never represent raw
//! prompts, provider responses, tool output, credentials, endpoints, or
//! resolved secret values. Actor-scoped explain read models can carry exact
//! persisted request/outcome JSON; HTTP callers must therefore return them
//! with `Cache-Control: no-store` and must never treat reconstruction as
//! authorization to re-execute external work.

use std::{collections::BTreeMap, fmt};

use chrono::{DateTime, SecondsFormat, Utc};
use deployment::ManifestEnvelope;
use protocol::{
    AgentToolCallDetail, AgentTurnDetail, AssistantReplyProvenance, SandboxProfile, ToolEffect,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use workflows::{
    AgentStatus, Command, ExternalCall, KnownToolResult, State as WorkflowState, TerminalReason,
};

pub const RUN_EPOCH_SCHEMA_VERSION: u16 = 1;
pub const RUN_EPOCH_ENVELOPE_SCHEMA_VERSION: u16 = 1;
pub const EXECUTION_FACT_SCHEMA_VERSION: u16 = 1;
pub const EXECUTION_FACT_ENVELOPE_SCHEMA_VERSION: u16 = 1;
pub const AGENT_EXECUTION_EXPLAIN_SCHEMA_VERSION: u16 = 1;
pub const AGENT_RUN_EPOCH_EXPLAIN_SCHEMA_VERSION: u16 = 1;

pub const MAX_RUN_EPOCH_BYTES: usize = 32 * 1024;
pub const MAX_EXECUTION_FACT_BYTES: usize = 32 * 1024;

const MAX_AGENT_ID_BYTES: usize = 384;
const MAX_RESOURCE_ID_BYTES: usize = 128;
// Session and turn references can point at durable rows created before the
// current 128-byte resource envelope was introduced. Keep those references
// bounded without making a legacy row impossible to execute after upgrade.
const MAX_DURABLE_RESOURCE_ID_BYTES: usize = 384;
const MAX_TOOL_NAME_BYTES: usize = 96;
const MAX_TOOL_VERSION_BYTES: usize = 64;
const MAX_TIMESTAMP_BYTES: usize = 32;
const SHA256_HEX_BYTES: usize = 64;
const ENVELOPE_OVERHEAD_BYTES: usize = 256;

/// A fixed domain for a canonical JSON digest.
///
/// Callers cannot supply arbitrary domain strings, preventing two independent
/// durable concepts from accidentally sharing a hash namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DigestDomain {
    RunEpoch,
    ExecutionFact,
    ModelRequest,
    ModelResponse,
    ToolResult,
    ExecutionError,
}

impl DigestDomain {
    const fn bytes(self) -> &'static [u8] {
        match self {
            Self::RunEpoch => b"zeus.run-epoch.sha256.v1",
            Self::ExecutionFact => b"zeus.execution-fact.sha256.v1",
            Self::ModelRequest => b"zeus.model-request.sha256.v1",
            Self::ModelResponse => b"zeus.model-response.sha256.v1",
            Self::ToolResult => b"zeus.tool-result.sha256.v1",
            Self::ExecutionError => b"zeus.execution-error.sha256.v1",
        }
    }
}

/// A canonical lowercase SHA-256 digest without an algorithm prefix.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    pub fn from_hex(value: impl Into<String>) -> Result<Self, ExecutionError> {
        let value = value.into();
        validate_sha256_hex("SHA-256 digest", &value)?;
        Ok(Self(value))
    }

    /// Parses either canonical hexadecimal form or the existing
    /// `sha256:<hex>` reference form used by tool argument bindings. The
    /// serialized representation is always canonical hexadecimal form.
    pub fn from_reference(value: impl AsRef<str>) -> Result<Self, ExecutionError> {
        let value = value.as_ref();
        Self::from_hex(value.strip_prefix("sha256:").unwrap_or(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_hex(value).map_err(serde::de::Error::custom)
    }
}

/// Canonical UTC millisecond timestamp used only for fact ordering metadata.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct RecordedAt(String);

impl RecordedAt {
    pub fn parse(value: impl Into<String>) -> Result<Self, ExecutionError> {
        let value = value.into();
        if value.len() > MAX_TIMESTAMP_BYTES {
            return Err(invalid_field(
                "recorded_at",
                format!("cannot exceed {MAX_TIMESTAMP_BYTES} bytes"),
            ));
        }
        let parsed = DateTime::parse_from_rfc3339(&value)
            .map_err(|error| invalid_field("recorded_at", error))?;
        let canonical = parsed
            .with_timezone(&Utc)
            .to_rfc3339_opts(SecondsFormat::Millis, true);
        if value != canonical {
            return Err(invalid_field(
                "recorded_at",
                "must be canonical UTC RFC 3339 with millisecond precision",
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RecordedAt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RecordedAt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

/// Immutable actor revision observed at one operation claim boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorRevision {
    pub user_id: String,
    pub membership_revision: u64,
}

impl ActorRevision {
    pub fn new(
        user_id: impl Into<String>,
        membership_revision: u64,
    ) -> Result<Self, ExecutionError> {
        let actor = Self {
            user_id: user_id.into(),
            membership_revision,
        };
        actor.validate()?;
        Ok(actor)
    }

    pub fn validate(&self) -> Result<(), ExecutionError> {
        validate_identifier("actor.user_id", &self.user_id, MAX_RESOURCE_ID_BYTES)?;
        validate_positive("actor.membership_revision", self.membership_revision)
    }
}

/// A RunEpoch exists only after its durable deployment binding has matched the
/// runtime observed at the claim boundary. Rejected checks are execution facts,
/// never release authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentCheck {
    Matched,
}

/// Exact immutable external operation inputs represented only by identifiers
/// and digests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RunOperation {
    Model {
        job_id: String,
        step: u32,
        request_digest: Sha256Digest,
    },
    Tool {
        call_id: String,
        ordinal: u32,
        model_step: u32,
        tool_name: String,
        tool_version: String,
        arguments_digest: Sha256Digest,
        effect: ToolEffect,
        sandbox_profile: SandboxProfile,
        policy_revision: String,
    },
}

impl RunOperation {
    pub fn model(
        job_id: impl Into<String>,
        step: u32,
        request_digest: Sha256Digest,
    ) -> Result<Self, ExecutionError> {
        let operation = Self::Model {
            job_id: job_id.into(),
            step,
            request_digest,
        };
        operation.validate()?;
        Ok(operation)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn tool(
        call_id: impl Into<String>,
        ordinal: u32,
        model_step: u32,
        tool_name: impl Into<String>,
        tool_version: impl Into<String>,
        arguments_digest: Sha256Digest,
        effect: ToolEffect,
        sandbox_profile: SandboxProfile,
        policy_revision: impl Into<String>,
    ) -> Result<Self, ExecutionError> {
        let operation = Self::Tool {
            call_id: call_id.into(),
            ordinal,
            model_step,
            tool_name: tool_name.into(),
            tool_version: tool_version.into(),
            arguments_digest,
            effect,
            sandbox_profile,
            policy_revision: policy_revision.into(),
        };
        operation.validate()?;
        Ok(operation)
    }

    pub fn validate(&self) -> Result<(), ExecutionError> {
        match self {
            Self::Model { job_id, step, .. } => {
                validate_identifier("operation.job_id", job_id, MAX_AGENT_ID_BYTES)?;
                validate_positive("operation.step", u64::from(*step))
            }
            Self::Tool {
                call_id,
                ordinal,
                model_step,
                tool_name,
                tool_version,
                policy_revision,
                ..
            } => {
                validate_identifier("operation.call_id", call_id, MAX_AGENT_ID_BYTES)?;
                validate_positive("operation.ordinal", u64::from(*ordinal))?;
                validate_positive("operation.model_step", u64::from(*model_step))?;
                validate_identifier("operation.tool_name", tool_name, MAX_TOOL_NAME_BYTES)?;
                validate_identifier(
                    "operation.tool_version",
                    tool_version,
                    MAX_TOOL_VERSION_BYTES,
                )?;
                validate_identifier(
                    "operation.policy_revision",
                    policy_revision,
                    MAX_RESOURCE_ID_BYTES,
                )
            }
        }
    }

    pub fn reference(&self) -> OperationRef {
        match self {
            Self::Model { job_id, step, .. } => OperationRef::Model {
                job_id: job_id.clone(),
                step: *step,
            },
            Self::Tool {
                call_id,
                ordinal,
                model_step,
                ..
            } => OperationRef::Tool {
                call_id: call_id.clone(),
                ordinal: *ordinal,
                model_step: *model_step,
            },
        }
    }

    pub fn input_digest(&self) -> &Sha256Digest {
        match self {
            Self::Model { request_digest, .. } => request_digest,
            Self::Tool {
                arguments_digest, ..
            } => arguments_digest,
        }
    }
}

/// Immutable per-operation authority snapshot. It has no mutable execution
/// status; lifecycle is represented by [`ExecutionFact`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunEpoch {
    pub schema_version: u16,
    pub agent_id: String,
    pub account_id: String,
    pub session_id: String,
    pub turn_id: String,
    pub workflow_revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_manifest_digest: Option<Sha256Digest>,
    pub observed_manifest_digest: Sha256Digest,
    pub deployment_check: DeploymentCheck,
    pub operation: RunOperation,
    pub initiator: ActorRevision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver: Option<ActorRevision>,
    pub created_at: RecordedAt,
}

impl RunEpoch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        agent_id: impl Into<String>,
        account_id: impl Into<String>,
        session_id: impl Into<String>,
        turn_id: impl Into<String>,
        workflow_revision: u64,
        bound_manifest_digest: Option<Sha256Digest>,
        observed_manifest_digest: Sha256Digest,
        operation: RunOperation,
        initiator: ActorRevision,
        approver: Option<ActorRevision>,
        created_at: RecordedAt,
    ) -> Result<Self, ExecutionError> {
        let epoch = Self {
            schema_version: RUN_EPOCH_SCHEMA_VERSION,
            agent_id: agent_id.into(),
            account_id: account_id.into(),
            session_id: session_id.into(),
            turn_id: turn_id.into(),
            workflow_revision,
            bound_manifest_digest,
            observed_manifest_digest,
            deployment_check: DeploymentCheck::Matched,
            operation,
            initiator,
            approver,
            created_at,
        };
        epoch.validate()?;
        Ok(epoch)
    }

    pub fn validate(&self) -> Result<(), ExecutionError> {
        validate_schema_version("run_epoch", self.schema_version, RUN_EPOCH_SCHEMA_VERSION)?;
        validate_identifier("epoch.agent_id", &self.agent_id, MAX_AGENT_ID_BYTES)?;
        validate_identifier("epoch.account_id", &self.account_id, MAX_RESOURCE_ID_BYTES)?;
        validate_identifier(
            "epoch.session_id",
            &self.session_id,
            MAX_DURABLE_RESOURCE_ID_BYTES,
        )?;
        validate_identifier(
            "epoch.turn_id",
            &self.turn_id,
            MAX_DURABLE_RESOURCE_ID_BYTES,
        )?;
        validate_positive("epoch.workflow_revision", self.workflow_revision)?;
        self.operation.validate()?;
        self.initiator.validate()?;
        if let Some(approver) = &self.approver {
            approver.validate()?;
        }
        let bound = self.bound_manifest_digest.as_ref().ok_or_else(|| {
            invalid_field(
                "epoch.bound_manifest_digest",
                "a released operation requires a matched bound manifest",
            )
        })?;
        if bound != &self.observed_manifest_digest {
            return Err(invalid_field(
                "epoch.deployment_check",
                "released deployment digests must be equal",
            ));
        }
        ensure_bounded_canonical("run epoch", self, MAX_RUN_EPOCH_BYTES)?;
        Ok(())
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, ExecutionError> {
        self.validate()?;
        canonical_json_bytes(self)
    }

    pub fn digest(&self) -> Result<Sha256Digest, ExecutionError> {
        self.validate()?;
        canonical_sha256(DigestDomain::RunEpoch, self)
    }
}

/// Digest-bearing, self-validating persistence envelope for one epoch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunEpochEnvelope {
    pub schema_version: u16,
    pub digest: Sha256Digest,
    pub epoch: RunEpoch,
}

impl RunEpochEnvelope {
    pub fn new(epoch: RunEpoch) -> Result<Self, ExecutionError> {
        let digest = epoch.digest()?;
        let envelope = Self {
            schema_version: RUN_EPOCH_ENVELOPE_SCHEMA_VERSION,
            digest,
            epoch,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, ExecutionError> {
        reject_oversize_input(
            "run epoch envelope",
            bytes,
            MAX_RUN_EPOCH_BYTES + ENVELOPE_OVERHEAD_BYTES,
        )?;
        let envelope: Self = serde_json::from_slice(bytes)
            .map_err(|error| ExecutionError::InvalidJson(error.to_string()))?;
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn validate(&self) -> Result<(), ExecutionError> {
        validate_schema_version(
            "run_epoch_envelope",
            self.schema_version,
            RUN_EPOCH_ENVELOPE_SCHEMA_VERSION,
        )?;
        self.epoch.validate()?;
        if self.digest != self.epoch.digest()? {
            return Err(ExecutionError::DigestMismatch { kind: "run epoch" });
        }
        Ok(())
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, ExecutionError> {
        self.validate()?;
        canonical_json_bytes(self)
    }
}

/// Stable reference to the durable operation involved in a workflow fact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperationRef {
    Model {
        job_id: String,
        step: u32,
    },
    Tool {
        call_id: String,
        ordinal: u32,
        model_step: u32,
    },
}

impl OperationRef {
    pub fn validate(&self) -> Result<(), ExecutionError> {
        match self {
            Self::Model { job_id, step } => {
                validate_identifier("subject.job_id", job_id, MAX_AGENT_ID_BYTES)?;
                validate_positive("subject.step", u64::from(*step))
            }
            Self::Tool {
                call_id,
                ordinal,
                model_step,
            } => {
                validate_identifier("subject.call_id", call_id, MAX_AGENT_ID_BYTES)?;
                validate_positive("subject.ordinal", u64::from(*ordinal))?;
                validate_positive("subject.model_step", u64::from(*model_step))
            }
        }
    }
}

/// Provenance of a workflow fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactSource {
    Live,
    RestartRecovery,
}

/// Small typed payload for one append-only execution fact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutionFactData {
    AgentAdmitted {
        state: WorkflowState,
        manifest_digest: Sha256Digest,
        initial_job_id: String,
        initial_request_digest: Sha256Digest,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        knowledge_context_digest: Option<Sha256Digest>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        knowledge_corpus_digest: Option<Sha256Digest>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        knowledge_snapshot_digest: Option<Sha256Digest>,
    },
    /// Honest migration boundary for an Agent whose earlier execution facts
    /// predate this ledger. It is not a synthetic reconstruction of history.
    LegacySnapshot {
        state: WorkflowState,
        origin_revision: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        manifest_digest: Option<Sha256Digest>,
    },
    WorkflowTransition {
        from_revision: u64,
        to_revision: u64,
        command: Command,
        state: WorkflowState,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        external_call: Option<ExternalCall>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        emitted_result: Option<KnownToolResult>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        emitted_result_digest: Option<Sha256Digest>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        epoch_digest: Option<Sha256Digest>,
        source: FactSource,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        subject: Option<OperationRef>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        input_digest: Option<Sha256Digest>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        output_digest: Option<Sha256Digest>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        next_request_digest: Option<Sha256Digest>,
    },
}

impl ExecutionFactData {
    fn validate(&self) -> Result<(), ExecutionError> {
        match self {
            Self::AgentAdmitted {
                state,
                initial_job_id,
                knowledge_context_digest,
                knowledge_corpus_digest,
                knowledge_snapshot_digest,
                ..
            } => {
                validate_workflow_state(state)?;
                if state.status() != AgentStatus::ModelQueued {
                    return Err(invalid_field(
                        "fact.data.state",
                        "an admitted Agent must begin model_queued",
                    ));
                }
                validate_identifier(
                    "fact.data.initial_job_id",
                    initial_job_id,
                    MAX_AGENT_ID_BYTES,
                )?;
                validate_knowledge_digest_binding(
                    knowledge_context_digest,
                    knowledge_corpus_digest,
                    knowledge_snapshot_digest,
                )
            }
            Self::LegacySnapshot {
                state,
                origin_revision,
                ..
            } => {
                validate_workflow_state(state)?;
                validate_positive("fact.data.origin_revision", *origin_revision)
            }
            Self::WorkflowTransition {
                from_revision,
                to_revision,
                command,
                state,
                external_call,
                emitted_result,
                emitted_result_digest,
                epoch_digest,
                source,
                subject,
                input_digest,
                output_digest,
                next_request_digest,
            } => {
                validate_positive("fact.data.from_revision", *from_revision)?;
                if from_revision.checked_add(1) != Some(*to_revision) {
                    return Err(invalid_field(
                        "fact.data.to_revision",
                        "must advance exactly one workflow revision",
                    ));
                }
                validate_workflow_state(state)?;
                if let Some(subject) = subject {
                    subject.validate()?;
                }
                if (epoch_digest.is_some()
                    || input_digest.is_some()
                    || output_digest.is_some()
                    || next_request_digest.is_some()
                    || emitted_result.is_some()
                    || emitted_result_digest.is_some())
                    && subject.is_none()
                {
                    return Err(invalid_field(
                        "fact.data.subject",
                        "digest-bearing operation facts require a subject",
                    ));
                }
                if epoch_digest.is_some() && input_digest.is_none() {
                    return Err(invalid_field(
                        "fact.data.input_digest",
                        "an epoch-bound fact requires its durable operation input digest",
                    ));
                }
                if emitted_result.is_some() != emitted_result_digest.is_some() {
                    return Err(invalid_field(
                        "fact.data.emitted_result_digest",
                        "must be present exactly when a structured result is emitted",
                    ));
                }
                validate_external_call(
                    command,
                    state,
                    external_call,
                    epoch_digest,
                    subject,
                    input_digest,
                )?;
                validate_recovery_source(command, *source, external_call)?;
                validate_executed_terminal(command, *source, epoch_digest, subject)?;
                validate_non_release_material(
                    command,
                    state,
                    epoch_digest,
                    subject,
                    input_digest,
                    output_digest,
                    emitted_result,
                )?;
                validate_continuation_request_material(
                    command,
                    state,
                    emitted_result,
                    next_request_digest,
                )?;
                Ok(())
            }
        }
    }
}

/// One small append-only fact in an Agent-local digest chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionFact {
    pub schema_version: u16,
    pub agent_id: String,
    pub sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_fact_digest: Option<Sha256Digest>,
    pub recorded_at: RecordedAt,
    pub data: ExecutionFactData,
}

impl ExecutionFact {
    pub fn new(
        agent_id: impl Into<String>,
        sequence: u64,
        previous_fact_digest: Option<Sha256Digest>,
        recorded_at: RecordedAt,
        data: ExecutionFactData,
    ) -> Result<Self, ExecutionError> {
        let fact = Self {
            schema_version: EXECUTION_FACT_SCHEMA_VERSION,
            agent_id: agent_id.into(),
            sequence,
            previous_fact_digest,
            recorded_at,
            data,
        };
        fact.validate()?;
        Ok(fact)
    }

    pub fn validate(&self) -> Result<(), ExecutionError> {
        validate_schema_version(
            "execution_fact",
            self.schema_version,
            EXECUTION_FACT_SCHEMA_VERSION,
        )?;
        validate_identifier("fact.agent_id", &self.agent_id, MAX_AGENT_ID_BYTES)?;
        validate_positive("fact.sequence", self.sequence)?;
        if (self.sequence == 1) != self.previous_fact_digest.is_none() {
            return Err(invalid_field(
                "fact.previous_fact_digest",
                "must be absent only for sequence one",
            ));
        }
        match (&self.data, self.sequence) {
            (ExecutionFactData::AgentAdmitted { .. }, 1)
            | (ExecutionFactData::LegacySnapshot { .. }, 1) => {}
            (ExecutionFactData::WorkflowTransition { .. }, sequence) if sequence > 1 => {}
            (ExecutionFactData::AgentAdmitted { .. }, _) => {
                return Err(invalid_field(
                    "fact.data",
                    "agent_admitted must be the first fact",
                ));
            }
            (ExecutionFactData::LegacySnapshot { .. }, _) => {
                return Err(invalid_field(
                    "fact.data",
                    "legacy_snapshot must be the first fact",
                ));
            }
            (ExecutionFactData::WorkflowTransition { .. }, _) => {
                return Err(invalid_field(
                    "fact.data",
                    "workflow_transition requires a preceding fact",
                ));
            }
        }
        self.data.validate()?;
        ensure_bounded_canonical("execution fact", self, MAX_EXECUTION_FACT_BYTES)?;
        Ok(())
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, ExecutionError> {
        self.validate()?;
        canonical_json_bytes(self)
    }

    pub fn digest(&self) -> Result<Sha256Digest, ExecutionError> {
        self.validate()?;
        canonical_sha256(DigestDomain::ExecutionFact, self)
    }
}

/// Digest-bearing, self-validating persistence envelope for one fact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionFactEnvelope {
    pub schema_version: u16,
    pub digest: Sha256Digest,
    pub fact: ExecutionFact,
}

impl ExecutionFactEnvelope {
    pub fn new(fact: ExecutionFact) -> Result<Self, ExecutionError> {
        let digest = fact.digest()?;
        let envelope = Self {
            schema_version: EXECUTION_FACT_ENVELOPE_SCHEMA_VERSION,
            digest,
            fact,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, ExecutionError> {
        reject_oversize_input(
            "execution fact envelope",
            bytes,
            MAX_EXECUTION_FACT_BYTES + ENVELOPE_OVERHEAD_BYTES,
        )?;
        let envelope: Self = serde_json::from_slice(bytes)
            .map_err(|error| ExecutionError::InvalidJson(error.to_string()))?;
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn validate(&self) -> Result<(), ExecutionError> {
        validate_schema_version(
            "execution_fact_envelope",
            self.schema_version,
            EXECUTION_FACT_ENVELOPE_SCHEMA_VERSION,
        )?;
        self.fact.validate()?;
        if self.digest != self.fact.digest()? {
            return Err(ExecutionError::DigestMismatch {
                kind: "execution fact",
            });
        }
        Ok(())
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, ExecutionError> {
        self.validate()?;
        canonical_json_bytes(self)
    }
}

/// Durable point-in-time boundary shared by the aggregate and single-epoch
/// explain responses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionWatermark {
    pub agent_revision: u64,
    pub session_sequence: u64,
    pub fact_head_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fact_head_digest: Option<Sha256Digest>,
}

impl ExecutionWatermark {
    pub fn new(
        agent_revision: u64,
        session_sequence: u64,
        fact_head_sequence: u64,
        fact_head_digest: Option<Sha256Digest>,
    ) -> Result<Self, ExecutionError> {
        let watermark = Self {
            agent_revision,
            session_sequence,
            fact_head_sequence,
            fact_head_digest,
        };
        watermark.validate()?;
        Ok(watermark)
    }

    pub fn validate(&self) -> Result<(), ExecutionError> {
        validate_positive("watermark.agent_revision", self.agent_revision)?;
        validate_positive("watermark.session_sequence", self.session_sequence)?;
        if (self.fact_head_sequence == 0) != self.fact_head_digest.is_none() {
            return Err(invalid_field(
                "watermark.fact_head_digest",
                "must be absent exactly when the fact head sequence is zero",
            ));
        }
        Ok(())
    }
}

/// Whether the execution ledger began with the native admission fact or an
/// honest migration snapshot of older durable state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionHistoryOrigin {
    Native,
    LegacySnapshot,
}

/// Strength of one reconstruction dimension. This deliberately does not
/// imply that an external operation may be replayed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconstructionLevel {
    Complete,
    Partial,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentAuthority {
    Verified,
    LegacyUnbound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionHistoryReason {
    LegacyManifestUnbound,
    LegacyKnowledgeUnbound,
    LegacyExecutionSnapshot,
    ExactRequestUnavailable,
    DerivationInputsUnavailable,
    TerminalProposalMaterialUnavailable,
    OutcomePending,
    OutcomeUnknown,
}

/// Explicit reconstruction assessment for an execution history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionHistory {
    pub origin: ExecutionHistoryOrigin,
    pub overall: ReconstructionLevel,
    pub request_material: ReconstructionLevel,
    pub derivation: ReconstructionLevel,
    pub deployment_authority: DeploymentAuthority,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<ExecutionHistoryReason>,
}

impl ExecutionHistory {
    pub fn validate(&self) -> Result<(), ExecutionError> {
        if self.overall == ReconstructionLevel::Complete
            && (self.origin != ExecutionHistoryOrigin::Native
                || self.request_material != ReconstructionLevel::Complete
                || self.derivation != ReconstructionLevel::Complete
                || self.deployment_authority != DeploymentAuthority::Verified
                || !self.reasons.is_empty())
        {
            return Err(invalid_field(
                "history.overall",
                "complete history requires native, fully reconstructable, verified authority",
            ));
        }
        if self.overall != ReconstructionLevel::Complete && self.reasons.is_empty() {
            return Err(invalid_field(
                "history.reasons",
                "partial or unavailable history requires at least one stable reason",
            ));
        }
        Ok(())
    }
}

/// Current lifecycle projection for one immutable operation epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochExecutionStatus {
    WaitingApproval,
    Queued,
    Started,
    Succeeded,
    Failed,
    Cancelled,
    Rejected,
    NotDispatched,
    OutcomeUnknown,
}

impl EpochExecutionStatus {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Failed
                | Self::Cancelled
                | Self::Rejected
                | Self::NotDispatched
                | Self::OutcomeUnknown
        )
    }
}

/// Bounded summary for one immutable RunEpoch plus its current durable
/// projection. The envelope remains the historical authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunEpochSummary {
    pub envelope: RunEpochEnvelope,
    pub status: EpochExecutionStatus,
    pub queued_at: RecordedAt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<RecordedAt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<RecordedAt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome_digest: Option<Sha256Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<AssistantReplyProvenance>,
}

impl RunEpochSummary {
    pub fn validate(&self) -> Result<(), ExecutionError> {
        self.envelope.validate()?;
        match self.status {
            EpochExecutionStatus::WaitingApproval | EpochExecutionStatus::Queued => {
                if self.started_at.is_some()
                    || self.finished_at.is_some()
                    || self.outcome_digest.is_some()
                    || self.provenance.is_some()
                {
                    return Err(invalid_field(
                        "epoch.status",
                        "unstarted epochs cannot expose start, finish, outcome, or provenance",
                    ));
                }
            }
            EpochExecutionStatus::Started => {
                if self.started_at.is_none()
                    || self.finished_at.is_some()
                    || self.outcome_digest.is_some()
                    || self.provenance.is_some()
                {
                    return Err(invalid_field(
                        "epoch.status",
                        "started epochs require only a start timestamp",
                    ));
                }
            }
            EpochExecutionStatus::Succeeded => {
                if self.started_at.is_none()
                    || self.finished_at.is_none()
                    || self.outcome_digest.is_none()
                {
                    return Err(invalid_field(
                        "epoch.status",
                        "succeeded epochs require start, finish, and outcome evidence",
                    ));
                }
                if matches!(self.envelope.epoch.operation, RunOperation::Model { .. })
                    && self.provenance.is_none()
                {
                    return Err(invalid_field(
                        "epoch.provenance",
                        "a successful model epoch requires durable reply provenance",
                    ));
                }
            }
            EpochExecutionStatus::Failed
            | EpochExecutionStatus::Cancelled
            | EpochExecutionStatus::Rejected
            | EpochExecutionStatus::NotDispatched
            | EpochExecutionStatus::OutcomeUnknown => {
                if self.finished_at.is_none() || self.outcome_digest.is_none() {
                    return Err(invalid_field(
                        "epoch.status",
                        "terminal epochs require finish and outcome evidence",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionFactKind {
    AgentAdmitted,
    LegacySnapshot,
    WorkflowTransition,
}

/// Small public index over an already-validated execution fact envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionFactSummary {
    pub sequence: u64,
    pub digest: Sha256Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_fact_digest: Option<Sha256Digest>,
    pub recorded_at: RecordedAt,
    pub kind: ExecutionFactKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<OperationRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch_digest: Option<Sha256Digest>,
}

impl ExecutionFactSummary {
    pub fn from_envelope(envelope: &ExecutionFactEnvelope) -> Result<Self, ExecutionError> {
        envelope.validate()?;
        let (kind, subject, epoch_digest) = match &envelope.fact.data {
            ExecutionFactData::AgentAdmitted { .. } => {
                (ExecutionFactKind::AgentAdmitted, None, None)
            }
            ExecutionFactData::LegacySnapshot { .. } => {
                (ExecutionFactKind::LegacySnapshot, None, None)
            }
            ExecutionFactData::WorkflowTransition {
                subject,
                epoch_digest,
                ..
            } => (
                ExecutionFactKind::WorkflowTransition,
                subject.clone(),
                epoch_digest.clone(),
            ),
        };
        Ok(Self {
            sequence: envelope.fact.sequence,
            digest: envelope.digest.clone(),
            previous_fact_digest: envelope.fact.previous_fact_digest.clone(),
            recorded_at: envelope.fact.recorded_at.clone(),
            kind,
            subject,
            epoch_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ExecutionError> {
        validate_positive("fact_summary.sequence", self.sequence)?;
        if (self.sequence == 1) != self.previous_fact_digest.is_none() {
            return Err(invalid_field(
                "fact_summary.previous_fact_digest",
                "must be absent only for sequence one",
            ));
        }
        if let Some(subject) = &self.subject {
            subject.validate()?;
        }
        if self.kind != ExecutionFactKind::WorkflowTransition
            && (self.subject.is_some() || self.epoch_digest.is_some())
        {
            return Err(invalid_field(
                "fact_summary.kind",
                "only workflow transitions may reference an operation epoch",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExactMaterialKind {
    ModelRequest,
    ModelResponse,
    ExecutionError,
}

impl ExactMaterialKind {
    const fn domain(self) -> DigestDomain {
        match self {
            Self::ModelRequest => DigestDomain::ModelRequest,
            Self::ModelResponse => DigestDomain::ModelResponse,
            Self::ExecutionError => DigestDomain::ExecutionError,
        }
    }
}

/// Exact actor-scoped persisted JSON together with its canonical evidence.
/// This read model is intentionally sensitive and must never be cached.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactJsonMaterial {
    pub kind: ExactMaterialKind,
    pub digest: Sha256Digest,
    pub byte_len: u64,
    pub value: Value,
}

impl ExactJsonMaterial {
    pub fn new(kind: ExactMaterialKind, value: Value) -> Result<Self, ExecutionError> {
        let bytes = canonical_json_bytes(&value)?;
        let byte_len = u64::try_from(bytes.len()).map_err(|_| ExecutionError::PayloadTooLarge {
            kind: "exact JSON material",
            max_bytes: usize::MAX,
        })?;
        let material = Self {
            kind,
            digest: canonical_sha256(kind.domain(), &value)?,
            byte_len,
            value,
        };
        material.validate()?;
        Ok(material)
    }

    pub fn validate(&self) -> Result<(), ExecutionError> {
        let bytes = canonical_json_bytes(&self.value)?;
        let byte_len = u64::try_from(bytes.len()).map_err(|_| ExecutionError::PayloadTooLarge {
            kind: "exact JSON material",
            max_bytes: usize::MAX,
        })?;
        if self.byte_len != byte_len {
            return Err(invalid_field(
                "material.byte_len",
                "does not match canonical JSON length",
            ));
        }
        if self.digest != canonical_sha256(self.kind.domain(), &self.value)? {
            return Err(ExecutionError::DigestMismatch {
                kind: "exact JSON material",
            });
        }
        Ok(())
    }
}

/// Exact model outcome for one epoch. `Pending` covers both queued and started
/// work and never predicts an outcome.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum EpochOutcomeMaterial {
    Pending,
    Succeeded {
        response: ExactJsonMaterial,
        provenance: AssistantReplyProvenance,
    },
    Failed {
        error: ExactJsonMaterial,
    },
    OutcomeUnknown {
        error: ExactJsonMaterial,
    },
}

impl EpochOutcomeMaterial {
    pub fn validate(&self) -> Result<(), ExecutionError> {
        match self {
            Self::Pending => Ok(()),
            Self::Succeeded { response, .. } => {
                response.validate()?;
                if response.kind != ExactMaterialKind::ModelResponse {
                    return Err(invalid_field(
                        "outcome.response.kind",
                        "a successful model outcome requires model_response material",
                    ));
                }
                Ok(())
            }
            Self::Failed { error } | Self::OutcomeUnknown { error } => {
                error.validate()?;
                if error.kind != ExactMaterialKind::ExecutionError {
                    return Err(invalid_field(
                        "outcome.error.kind",
                        "a failed or unknown outcome requires execution_error material",
                    ));
                }
                Ok(())
            }
        }
    }
}

/// Aggregate actor-scoped execution explanation for one Session Agent turn.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentExecutionExplain {
    pub schema_version: u16,
    pub agent: AgentTurnDetail,
    pub watermark: ExecutionWatermark,
    pub history: ExecutionHistory,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<ManifestEnvelope>,
    pub epochs: Vec<RunEpochSummary>,
    pub facts: Vec<ExecutionFactSummary>,
}

impl AgentExecutionExplain {
    pub fn validate(&self) -> Result<(), ExecutionError> {
        validate_schema_version(
            "agent_execution_explain",
            self.schema_version,
            AGENT_EXECUTION_EXPLAIN_SCHEMA_VERSION,
        )?;
        self.watermark.validate()?;
        self.history.validate()?;
        if self.agent.revision != self.watermark.agent_revision {
            return Err(invalid_field(
                "watermark.agent_revision",
                "must match the returned Agent projection",
            ));
        }
        match (
            self.agent.deployment_manifest_digest.as_deref(),
            self.manifest.as_ref(),
        ) {
            (Some(digest), Some(manifest)) if digest == manifest.digest => {
                manifest.validate().map_err(|error| {
                    invalid_field("explain.manifest", format!("invalid manifest: {error}"))
                })?;
            }
            (None, None) => {}
            _ => {
                return Err(invalid_field(
                    "explain.manifest",
                    "must exactly match the Agent deployment binding",
                ));
            }
        }
        if self.manifest.is_some()
            != (self.history.deployment_authority == DeploymentAuthority::Verified)
        {
            return Err(invalid_field(
                "history.deployment_authority",
                "must reflect whether a verified historical manifest is present",
            ));
        }
        let mut previous_revision = None;
        for epoch in &self.epochs {
            epoch.validate()?;
            let authority = &epoch.envelope.epoch;
            if authority.agent_id != self.agent.id
                || authority.session_id != self.agent.session_id
                || authority.turn_id != self.agent.turn_id
            {
                return Err(invalid_field(
                    "explain.epochs",
                    "contains an epoch owned by another Agent turn",
                ));
            }
            if authority
                .bound_manifest_digest
                .as_ref()
                .map(Sha256Digest::as_str)
                != self.agent.deployment_manifest_digest.as_deref()
            {
                return Err(invalid_field(
                    "explain.epochs",
                    "contains an epoch with another historical deployment binding",
                ));
            }
            if previous_revision.is_some_and(|previous| previous >= authority.workflow_revision) {
                return Err(invalid_field(
                    "explain.epochs",
                    "must be ordered by strictly increasing workflow revision",
                ));
            }
            previous_revision = Some(authority.workflow_revision);
        }
        validate_fact_summaries(&self.facts, &self.watermark)?;
        if let Some(first) = self.facts.first() {
            let expected = match self.history.origin {
                ExecutionHistoryOrigin::Native => ExecutionFactKind::AgentAdmitted,
                ExecutionHistoryOrigin::LegacySnapshot => ExecutionFactKind::LegacySnapshot,
            };
            if first.kind != expected {
                return Err(invalid_field(
                    "history.origin",
                    "does not match the first execution fact",
                ));
            }
        }
        Ok(())
    }
}

/// Exact, actor-scoped material for one model RunEpoch.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRunEpochExplain {
    pub schema_version: u16,
    pub agent_id: String,
    pub session_id: String,
    pub turn_id: String,
    pub watermark: ExecutionWatermark,
    pub history: ExecutionHistory,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<ManifestEnvelope>,
    pub epoch: RunEpochSummary,
    pub request: ExactJsonMaterial,
    pub outcome: EpochOutcomeMaterial,
    pub linked_tools: Vec<AgentToolCallDetail>,
    pub facts: Vec<ExecutionFactSummary>,
}

impl AgentRunEpochExplain {
    pub fn validate(&self) -> Result<(), ExecutionError> {
        validate_schema_version(
            "agent_run_epoch_explain",
            self.schema_version,
            AGENT_RUN_EPOCH_EXPLAIN_SCHEMA_VERSION,
        )?;
        self.watermark.validate()?;
        self.history.validate()?;
        self.epoch.validate()?;
        self.request.validate()?;
        self.outcome.validate()?;
        if self.request.kind != ExactMaterialKind::ModelRequest {
            return Err(invalid_field(
                "epoch.request.kind",
                "a model epoch requires model_request material",
            ));
        }
        let RunOperation::Model {
            step,
            request_digest,
            ..
        } = &self.epoch.envelope.epoch.operation
        else {
            return Err(invalid_field(
                "epoch.operation",
                "the point explain endpoint accepts model epochs only",
            ));
        };
        let authority = &self.epoch.envelope.epoch;
        if authority.agent_id != self.agent_id
            || authority.session_id != self.session_id
            || authority.turn_id != self.turn_id
            || request_digest != &self.request.digest
            || self.watermark.agent_revision < authority.workflow_revision
        {
            return Err(invalid_field(
                "epoch",
                "does not match the requested Agent turn or exact request material",
            ));
        }
        let bound_manifest = authority
            .bound_manifest_digest
            .as_ref()
            .expect("validated RunEpochs always carry a bound manifest");
        match self.manifest.as_ref() {
            Some(manifest) if manifest.digest == bound_manifest.as_str() => {
                manifest.validate().map_err(|error| {
                    invalid_field("epoch.manifest", format!("invalid manifest: {error}"))
                })?;
            }
            _ => {
                return Err(invalid_field(
                    "epoch.manifest",
                    "must expose the exact manifest that authorized this RunEpoch",
                ));
            }
        }
        if self.history.deployment_authority != DeploymentAuthority::Verified {
            return Err(invalid_field(
                "epoch.history.deployment_authority",
                "a RunEpoch requires verified deployment authority",
            ));
        }
        match (
            authority.bound_manifest_digest.as_ref(),
            self.manifest.as_ref(),
        ) {
            (Some(digest), Some(manifest)) if digest.as_str() == manifest.digest => {
                manifest.validate().map_err(|error| {
                    invalid_field("epoch.manifest", format!("invalid manifest: {error}"))
                })?;
            }
            (None, None) => {}
            _ => {
                return Err(invalid_field(
                    "epoch.manifest",
                    "must exactly match the RunEpoch deployment binding",
                ));
            }
        }
        if self.manifest.is_some()
            != (self.history.deployment_authority == DeploymentAuthority::Verified)
        {
            return Err(invalid_field(
                "history.deployment_authority",
                "must reflect whether a verified historical manifest is present",
            ));
        }
        for call in &self.linked_tools {
            if call.model_step != *step {
                return Err(invalid_field(
                    "epoch.linked_tools",
                    "contains a tool call from another model step",
                ));
            }
        }
        validate_fact_summaries(&self.facts, &self.watermark)?;
        if !self
            .facts
            .iter()
            .any(|fact| fact.epoch_digest.as_ref() == Some(&self.epoch.envelope.digest))
        {
            return Err(invalid_field(
                "epoch.facts",
                "must contain the RunEpoch release fact in the complete fact chain",
            ));
        }
        match (&self.epoch.status, &self.outcome) {
            (
                EpochExecutionStatus::WaitingApproval
                | EpochExecutionStatus::Queued
                | EpochExecutionStatus::Started,
                EpochOutcomeMaterial::Pending,
            ) => {}
            (
                EpochExecutionStatus::Succeeded,
                EpochOutcomeMaterial::Succeeded {
                    response,
                    provenance,
                },
            ) if self.epoch.outcome_digest.as_ref() == Some(&response.digest)
                && self.epoch.provenance.as_ref() == Some(provenance) => {}
            (EpochExecutionStatus::Failed, EpochOutcomeMaterial::Failed { error })
                if self.epoch.outcome_digest.as_ref() == Some(&error.digest) => {}
            (
                EpochExecutionStatus::OutcomeUnknown,
                EpochOutcomeMaterial::OutcomeUnknown { error },
            ) if self.epoch.outcome_digest.as_ref() == Some(&error.digest) => {}
            _ => {
                return Err(invalid_field(
                    "epoch.outcome",
                    "does not match the durable epoch status",
                ));
            }
        }
        Ok(())
    }
}

fn validate_fact_summaries(
    facts: &[ExecutionFactSummary],
    watermark: &ExecutionWatermark,
) -> Result<(), ExecutionError> {
    if facts.is_empty() {
        if watermark.fact_head_sequence != 0 || watermark.fact_head_digest.is_some() {
            return Err(invalid_field(
                "explain.facts",
                "empty facts require an empty fact watermark",
            ));
        }
        return Ok(());
    }
    let mut previous = None;
    for (index, fact) in facts.iter().enumerate() {
        fact.validate()?;
        let expected = u64::try_from(index + 1).map_err(|_| ExecutionError::PayloadTooLarge {
            kind: "execution fact summaries",
            max_bytes: usize::MAX,
        })?;
        if fact.sequence != expected || fact.previous_fact_digest != previous {
            return Err(invalid_field(
                "explain.facts",
                "must contain the complete contiguous digest chain",
            ));
        }
        previous = Some(fact.digest.clone());
    }
    let last = facts.last().expect("non-empty facts have a last item");
    if watermark.fact_head_sequence != last.sequence
        || watermark.fact_head_digest.as_ref() != Some(&last.digest)
    {
        return Err(invalid_field(
            "explain.watermark",
            "does not match the returned execution fact tail",
        ));
    }
    Ok(())
}

/// Canonicalize JSON object keys recursively while preserving array order.
pub fn canonical_json_bytes(value: &impl Serialize) -> Result<Vec<u8>, ExecutionError> {
    let value = serde_json::to_value(value)
        .map_err(|error| ExecutionError::Serialization(error.to_string()))?;
    serde_json::to_vec(&canonicalize_json(value))
        .map_err(|error| ExecutionError::Serialization(error.to_string()))
}

/// Compute a length-delimited, domain-separated SHA-256 digest over canonical
/// JSON. The returned digest is lowercase hexadecimal without a prefix.
pub fn canonical_sha256(
    domain: DigestDomain,
    value: &impl Serialize,
) -> Result<Sha256Digest, ExecutionError> {
    let bytes = canonical_json_bytes(value)?;
    let domain = domain.bytes();
    let mut digest = Sha256::new();
    digest.update(
        u64::try_from(domain.len())
            .expect("a fixed execution digest domain fits in u64")
            .to_be_bytes(),
    );
    digest.update(domain);
    digest.update(
        u64::try_from(bytes.len())
            .map_err(|_| ExecutionError::PayloadTooLarge {
                kind: "canonical JSON",
                max_bytes: usize::MAX,
            })?
            .to_be_bytes(),
    );
    digest.update(bytes);
    Sha256Digest::from_hex(format!("{:x}", digest.finalize()))
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ExecutionError {
    #[error("unsupported {kind} schema version {actual}; expected {expected}")]
    UnsupportedSchemaVersion {
        kind: &'static str,
        expected: u16,
        actual: u16,
    },
    #[error("invalid execution field `{field}`: {reason}")]
    InvalidField { field: &'static str, reason: String },
    #[error("{kind} exceeds the {max_bytes}-byte canonical limit")]
    PayloadTooLarge {
        kind: &'static str,
        max_bytes: usize,
    },
    #[error("{kind} digest does not match its canonical payload")]
    DigestMismatch { kind: &'static str },
    #[error("invalid execution JSON: {0}")]
    InvalidJson(String),
    #[error("execution serialization failed: {0}")]
    Serialization(String),
}

fn validate_schema_version(
    kind: &'static str,
    actual: u16,
    expected: u16,
) -> Result<(), ExecutionError> {
    if actual != expected {
        return Err(ExecutionError::UnsupportedSchemaVersion {
            kind,
            expected,
            actual,
        });
    }
    Ok(())
}

fn validate_sha256_hex(field: &'static str, value: &str) -> Result<(), ExecutionError> {
    if value.len() != SHA256_HEX_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_field(
            field,
            "must be a 64-character lowercase SHA-256 hexadecimal value",
        ));
    }
    Ok(())
}

fn validate_knowledge_digest_binding(
    context: &Option<Sha256Digest>,
    corpus: &Option<Sha256Digest>,
    snapshot: &Option<Sha256Digest>,
) -> Result<(), ExecutionError> {
    let present = usize::from(context.is_some())
        + usize::from(corpus.is_some())
        + usize::from(snapshot.is_some());
    if present != 0 && present != 3 {
        return Err(invalid_field(
            "fact.data.knowledge_digest_binding",
            "context, corpus, and snapshot digests must be present together or all absent",
        ));
    }

    for (field, digest) in [
        ("fact.data.knowledge_context_digest", context),
        ("fact.data.knowledge_corpus_digest", corpus),
        ("fact.data.knowledge_snapshot_digest", snapshot),
    ] {
        if let Some(digest) = digest {
            validate_sha256_hex(field, digest.as_str())?;
        }
    }
    Ok(())
}

fn validate_identifier(
    field: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), ExecutionError> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > max_bytes
        || value.chars().any(char::is_control)
    {
        return Err(invalid_field(
            field,
            format!("must be canonical, control-free, and at most {max_bytes} UTF-8 bytes"),
        ));
    }
    Ok(())
}

fn validate_positive(field: &'static str, value: u64) -> Result<(), ExecutionError> {
    if value == 0 {
        return Err(invalid_field(field, "must be greater than zero"));
    }
    Ok(())
}

fn validate_workflow_state(state: &WorkflowState) -> Result<(), ExecutionError> {
    state
        .validate()
        .map_err(|error| invalid_field("fact.data.state", error))
}

fn validate_external_call(
    command: &Command,
    state: &WorkflowState,
    external_call: &Option<ExternalCall>,
    epoch_digest: &Option<Sha256Digest>,
    subject: &Option<OperationRef>,
    input_digest: &Option<Sha256Digest>,
) -> Result<(), ExecutionError> {
    let is_start = matches!(command, Command::StartModel | Command::StartTool);
    let refused_model_limit = matches!(command, Command::StartModel)
        && state.status() == AgentStatus::Failed
        && state.terminal_reason() == Some(TerminalReason::ModelStepLimitReached)
        && external_call.is_none()
        && epoch_digest.is_none()
        && subject.is_none()
        && input_digest.is_none();
    if is_start != external_call.is_some() && !refused_model_limit {
        return Err(invalid_field(
            "fact.data.external_call",
            "must be present for a released start command; only a model-limit refusal may omit it",
        ));
    }
    let Some(external_call) = external_call else {
        return Ok(());
    };
    if epoch_digest.is_none() || input_digest.is_none() {
        return Err(invalid_field(
            "fact.data.epoch_digest",
            "an execution release requires epoch and input digests",
        ));
    }
    let matches = matches!(
        (external_call, subject),
        (
            ExternalCall::Model { step: external_step },
            Some(OperationRef::Model {
                step: subject_step,
                ..
            })
        ) if external_step == subject_step
    ) || matches!(
        (external_call, subject),
        (
            ExternalCall::Tool { call: external_call },
            Some(OperationRef::Tool {
                ordinal: subject_call,
                ..
            })
        ) if external_call == subject_call
    );
    if !matches {
        return Err(invalid_field(
            "fact.data.subject",
            "must identify the external call released by this transition",
        ));
    }
    Ok(())
}

fn validate_recovery_source(
    command: &Command,
    source: FactSource,
    external_call: &Option<ExternalCall>,
) -> Result<(), ExecutionError> {
    if source != FactSource::RestartRecovery {
        return Ok(());
    }
    if !matches!(
        command,
        Command::ModelOutcomeUnknown | Command::ToolOutcomeUnknown
    ) || external_call.is_some()
    {
        return Err(invalid_field(
            "fact.data.source",
            "restart recovery must append an unknown outcome without releasing work",
        ));
    }
    Ok(())
}

fn validate_executed_terminal(
    command: &Command,
    source: FactSource,
    epoch_digest: &Option<Sha256Digest>,
    subject: &Option<OperationRef>,
) -> Result<(), ExecutionError> {
    if matches!(
        command,
        Command::ModelFinal { .. }
            | Command::ModelToolProposal { .. }
            | Command::ModelFailed
            | Command::ModelOutcomeUnknown
            | Command::ToolResultKnown { .. }
            | Command::ToolOutcomeUnknown
    ) && (subject.is_none() || (epoch_digest.is_none() && source != FactSource::RestartRecovery))
    {
        return Err(invalid_field(
            "fact.data.epoch_digest",
            "the terminal fact for an executed operation requires its epoch and subject",
        ));
    }
    Ok(())
}

fn validate_non_release_material(
    command: &Command,
    state: &WorkflowState,
    epoch_digest: &Option<Sha256Digest>,
    subject: &Option<OperationRef>,
    input_digest: &Option<Sha256Digest>,
    output_digest: &Option<Sha256Digest>,
    emitted_result: &Option<KnownToolResult>,
) -> Result<(), ExecutionError> {
    if epoch_digest.is_some() {
        return Ok(());
    }
    let valid = match command {
        Command::AuthorizationRevoked
        | Command::DeploymentUnavailable
        | Command::KnowledgeUnavailable => {
            subject.is_some()
                && input_digest.is_some()
                && output_digest.is_some()
                && emitted_result.is_none()
        }
        Command::ApprovalApproved => {
            matches!(subject, Some(OperationRef::Tool { .. }))
                && input_digest.is_some()
                && output_digest.is_none()
                && emitted_result.is_none()
        }
        Command::ApprovalRejected { .. } => {
            matches!(subject, Some(OperationRef::Tool { .. }))
                && input_digest.is_some()
                && output_digest.is_some()
                && (emitted_result.is_some()
                    || (state.status() == AgentStatus::Failed
                        && state.terminal_reason()
                            == Some(TerminalReason::ToolResultBytesLimitReached)))
        }
        _ => true,
    };
    if !valid {
        return Err(invalid_field(
            "fact.data",
            "a non-release authorization or approval fact requires its exact operation material",
        ));
    }
    Ok(())
}

fn validate_continuation_request_material(
    command: &Command,
    state: &WorkflowState,
    emitted_result: &Option<KnownToolResult>,
    next_request_digest: &Option<Sha256Digest>,
) -> Result<(), ExecutionError> {
    if next_request_digest.is_none() {
        return Ok(());
    }
    let known_result = matches!(
        command,
        Command::ModelToolProposal {
            disposition: workflows::ProposalDisposition::Deny { .. }
        } | Command::ApprovalRejected { .. }
            | Command::ToolResultKnown { .. }
    );
    if !known_result
        || state.status() != AgentStatus::ContinuationQueued
        || emitted_result.is_none()
    {
        return Err(invalid_field(
            "fact.data.next_request_digest",
            "may bind only a known-result transition that queued a continuation",
        ));
    }
    Ok(())
}

fn ensure_bounded_canonical(
    kind: &'static str,
    value: &impl Serialize,
    max_bytes: usize,
) -> Result<(), ExecutionError> {
    if canonical_json_bytes(value)?.len() > max_bytes {
        return Err(ExecutionError::PayloadTooLarge { kind, max_bytes });
    }
    Ok(())
}

fn reject_oversize_input(
    kind: &'static str,
    bytes: &[u8],
    max_bytes: usize,
) -> Result<(), ExecutionError> {
    if bytes.len() > max_bytes {
        return Err(ExecutionError::PayloadTooLarge { kind, max_bytes });
    }
    Ok(())
}

fn invalid_field(field: &'static str, reason: impl fmt::Display) -> ExecutionError {
    ExecutionError::InvalidField {
        field,
        reason: reason.to_string(),
    }
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

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const DIGEST_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const NEVER_PERSIST: &str = "sk-test-never-persist";

    fn digest(value: &str) -> Sha256Digest {
        Sha256Digest::from_hex(value).unwrap()
    }

    fn timestamp(second: u8) -> RecordedAt {
        RecordedAt::parse(format!("2026-08-27T12:00:{second:02}.000Z")).unwrap()
    }

    fn actor(user_id: &str, revision: u64) -> ActorRevision {
        ActorRevision::new(user_id, revision).unwrap()
    }

    fn manifest() -> ManifestEnvelope {
        let provider = deployment::ManifestProvider::new(
            "provider-one",
            Some("model-one".into()),
            protocol::AssistantReplyKind::Model,
        )
        .unwrap();
        let policy = deployment::ManifestPolicy::new("policy-one", "revision-one").unwrap();
        let spec = deployment::AgentSpec::new(
            "spec-one",
            "revision-one",
            "local",
            "test",
            provider,
            policy,
        )
        .unwrap();
        let deployment =
            deployment::AgentDeployment::new("deployment-one", "revision-one", spec).unwrap();
        ManifestEnvelope::from_deployment(deployment).unwrap()
    }

    fn model_epoch() -> RunEpoch {
        RunEpoch::new(
            "agent-001",
            "acc_local",
            "session-001",
            "turn-001",
            2,
            Some(digest(DIGEST_A)),
            digest(DIGEST_A),
            RunOperation::model("job-agent-001-1", 1, digest(DIGEST_B)).unwrap(),
            actor("user-owner", 7),
            None,
            timestamp(1),
        )
        .unwrap()
    }

    fn first_fact() -> ExecutionFactEnvelope {
        let fact = ExecutionFact::new(
            "agent-001",
            1,
            None,
            timestamp(0),
            ExecutionFactData::AgentAdmitted {
                state: WorkflowState::default(),
                manifest_digest: digest(DIGEST_A),
                initial_job_id: "job-agent-001-1".into(),
                initial_request_digest: digest(DIGEST_B),
                knowledge_context_digest: None,
                knowledge_corpus_digest: None,
                knowledge_snapshot_digest: None,
            },
        )
        .unwrap();
        ExecutionFactEnvelope::new(fact).unwrap()
    }

    fn start_fact(previous: Sha256Digest, epoch: Sha256Digest) -> ExecutionFactEnvelope {
        let started = workflows::reduce(&WorkflowState::default(), Command::StartModel)
            .unwrap()
            .into_state();
        let fact = ExecutionFact::new(
            "agent-001",
            2,
            Some(previous),
            timestamp(2),
            ExecutionFactData::WorkflowTransition {
                from_revision: 1,
                to_revision: 2,
                command: Command::StartModel,
                state: started,
                external_call: Some(ExternalCall::Model { step: 1 }),
                emitted_result: None,
                emitted_result_digest: None,
                epoch_digest: Some(epoch),
                source: FactSource::Live,
                subject: Some(OperationRef::Model {
                    job_id: "job-agent-001-1".into(),
                    step: 1,
                }),
                input_digest: Some(digest(DIGEST_B)),
                output_digest: None,
                next_request_digest: None,
            },
        )
        .unwrap();
        ExecutionFactEnvelope::new(fact).unwrap()
    }

    fn knowledge_bound_first_fact() -> ExecutionFactEnvelope {
        let mut fact = first_fact().fact;
        let ExecutionFactData::AgentAdmitted {
            knowledge_context_digest,
            knowledge_corpus_digest,
            knowledge_snapshot_digest,
            ..
        } = &mut fact.data
        else {
            unreachable!("first fact fixture must be an admission")
        };
        *knowledge_context_digest = Some(digest(DIGEST_A));
        *knowledge_corpus_digest = Some(digest(DIGEST_B));
        *knowledge_snapshot_digest = Some(digest(DIGEST_C));
        ExecutionFactEnvelope::new(fact).unwrap()
    }

    fn assert_no_secret_fields(value: &Value) {
        match value {
            Value::Object(object) => {
                for (key, value) in object {
                    assert!(
                        !matches!(
                            key.as_str(),
                            "endpoint"
                                | "api_key"
                                | "secret"
                                | "secret_value"
                                | "prompt"
                                | "request"
                                | "response"
                                | "result"
                                | "output"
                                | "error"
                                | "review_note"
                        ),
                        "raw or secret-bearing field `{key}` appeared in execution authority"
                    );
                    assert_no_secret_fields(value);
                }
            }
            Value::Array(values) => values.iter().for_each(assert_no_secret_fields),
            Value::String(value) => assert_ne!(value, NEVER_PERSIST),
            _ => {}
        }
    }

    #[test]
    fn canonical_digest_is_key_order_independent_and_domain_separated() {
        let left: Value = serde_json::from_str(r#"{"z":[{"b":2,"a":1}],"a":0}"#).unwrap();
        let right = json!({"a": 0, "z": [{"a": 1, "b": 2}]});
        assert_eq!(
            canonical_json_bytes(&left).unwrap(),
            canonical_json_bytes(&right).unwrap()
        );

        let epoch = canonical_sha256(DigestDomain::RunEpoch, &left).unwrap();
        let fact = canonical_sha256(DigestDomain::ExecutionFact, &right).unwrap();
        assert_ne!(epoch, fact);
        assert_eq!(
            epoch.as_str(),
            "27181e9e72a814583d27cd2a0e4170c028feaf6a48408d54db44fdda95382921"
        );
    }

    #[test]
    fn run_epoch_round_trip_is_strict_and_digest_bound() {
        let envelope = RunEpochEnvelope::new(model_epoch()).unwrap();
        let bytes = envelope.canonical_json_bytes().unwrap();
        assert_eq!(RunEpochEnvelope::from_json_slice(&bytes).unwrap(), envelope);

        let mut tampered = envelope.clone();
        tampered.epoch.workflow_revision += 1;
        assert!(matches!(
            tampered.validate(),
            Err(ExecutionError::DigestMismatch { kind: "run epoch" })
        ));

        let mut unknown = serde_json::to_value(&envelope).unwrap();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("api_key".into(), json!(NEVER_PERSIST));
        assert!(matches!(
            RunEpochEnvelope::from_json_slice(&serde_json::to_vec(&unknown).unwrap()),
            Err(ExecutionError::InvalidJson(_))
        ));
    }

    #[test]
    fn released_epoch_requires_the_same_bound_and_observed_manifest() {
        let mut epoch = model_epoch();
        epoch.observed_manifest_digest = digest(DIGEST_B);
        assert!(epoch.validate().is_err());

        epoch.observed_manifest_digest = digest(DIGEST_A);
        epoch.bound_manifest_digest = None;
        assert!(epoch.validate().is_err());
    }

    #[test]
    fn run_epoch_accepts_bounded_legacy_session_and_turn_references() {
        let mut epoch = model_epoch();
        epoch.session_id = "s".repeat(protocol::SESSION_ID_MAX_BYTES + 1);
        epoch.turn_id = "t".repeat(protocol::TURN_ID_MAX_BYTES + 1);
        epoch.validate().unwrap();

        epoch.session_id = "s".repeat(MAX_DURABLE_RESOURCE_ID_BYTES + 1);
        assert!(epoch.validate().is_err());

        epoch.session_id = "session-001".into();
        epoch.turn_id = "t".repeat(MAX_DURABLE_RESOURCE_ID_BYTES + 1);
        assert!(epoch.validate().is_err());
    }

    #[test]
    fn argument_digest_reference_normalizes_to_canonical_hex() {
        let prefixed = Sha256Digest::from_reference(format!("sha256:{DIGEST_A}")).unwrap();
        let plain = Sha256Digest::from_reference(DIGEST_A).unwrap();
        assert_eq!(prefixed, plain);
        assert_eq!(
            serde_json::to_string(&prefixed).unwrap(),
            format!("\"{DIGEST_A}\"")
        );
        assert!(Sha256Digest::from_hex(format!("sha256:{DIGEST_A}")).is_err());
    }

    #[test]
    fn execution_fact_chain_round_trips_and_tampering_is_detected() {
        let admitted = first_fact();
        let epoch = RunEpochEnvelope::new(model_epoch()).unwrap();
        let started = start_fact(admitted.digest.clone(), epoch.digest);
        let bytes = started.canonical_json_bytes().unwrap();
        assert_eq!(
            ExecutionFactEnvelope::from_json_slice(&bytes).unwrap(),
            started
        );

        let mut tampered = started;
        tampered.fact.sequence = 3;
        assert!(matches!(
            tampered.validate(),
            Err(ExecutionError::DigestMismatch {
                kind: "execution fact"
            })
        ));
    }

    #[test]
    fn admission_knowledge_binding_round_trips_without_changing_schema_v1() {
        let legacy = first_fact();
        let legacy_value = serde_json::to_value(&legacy).unwrap();
        let legacy_data = legacy_value["fact"]["data"].as_object().unwrap();
        assert!(!legacy_data.contains_key("knowledge_context_digest"));
        assert!(!legacy_data.contains_key("knowledge_corpus_digest"));
        assert!(!legacy_data.contains_key("knowledge_snapshot_digest"));
        assert_eq!(
            ExecutionFactEnvelope::from_json_slice(&legacy.canonical_json_bytes().unwrap())
                .unwrap(),
            legacy
        );

        let bound = knowledge_bound_first_fact();
        assert_eq!(bound.schema_version, EXECUTION_FACT_ENVELOPE_SCHEMA_VERSION);
        assert_eq!(bound.fact.schema_version, EXECUTION_FACT_SCHEMA_VERSION);
        let decoded =
            ExecutionFactEnvelope::from_json_slice(&bound.canonical_json_bytes().unwrap()).unwrap();
        assert_eq!(decoded, bound);
        let ExecutionFactData::AgentAdmitted {
            knowledge_context_digest,
            knowledge_corpus_digest,
            knowledge_snapshot_digest,
            ..
        } = decoded.fact.data
        else {
            unreachable!("decoded fact must remain an admission")
        };
        assert_eq!(knowledge_context_digest, Some(digest(DIGEST_A)));
        assert_eq!(knowledge_corpus_digest, Some(digest(DIGEST_B)));
        assert_eq!(knowledge_snapshot_digest, Some(digest(DIGEST_C)));
    }

    #[test]
    fn admission_rejects_partial_knowledge_digest_bindings() {
        for presence in [
            (true, false, false),
            (false, true, false),
            (false, false, true),
            (true, true, false),
            (true, false, true),
            (false, true, true),
        ] {
            let mut fact = first_fact().fact;
            let ExecutionFactData::AgentAdmitted {
                knowledge_context_digest,
                knowledge_corpus_digest,
                knowledge_snapshot_digest,
                ..
            } = &mut fact.data
            else {
                unreachable!("first fact fixture must be an admission")
            };
            *knowledge_context_digest = presence.0.then(|| digest(DIGEST_A));
            *knowledge_corpus_digest = presence.1.then(|| digest(DIGEST_B));
            *knowledge_snapshot_digest = presence.2.then(|| digest(DIGEST_C));

            assert!(matches!(
                fact.validate(),
                Err(ExecutionError::InvalidField {
                    field: "fact.data.knowledge_digest_binding",
                    ..
                })
            ));
        }
    }

    #[test]
    fn admission_knowledge_digest_tampering_is_rejected() {
        let mut envelope = knowledge_bound_first_fact();
        let ExecutionFactData::AgentAdmitted {
            knowledge_snapshot_digest,
            ..
        } = &mut envelope.fact.data
        else {
            unreachable!("knowledge-bound fact must be an admission")
        };
        *knowledge_snapshot_digest = Some(digest(DIGEST_A));
        assert!(matches!(
            envelope.validate(),
            Err(ExecutionError::DigestMismatch {
                kind: "execution fact"
            })
        ));

        let mut malformed = knowledge_bound_first_fact().fact;
        let ExecutionFactData::AgentAdmitted {
            knowledge_context_digest,
            ..
        } = &mut malformed.data
        else {
            unreachable!("knowledge-bound fact must be an admission")
        };
        *knowledge_context_digest = Some(Sha256Digest("A".repeat(SHA256_HEX_BYTES)));
        assert!(matches!(
            malformed.validate(),
            Err(ExecutionError::InvalidField {
                field: "fact.data.knowledge_context_digest",
                ..
            })
        ));
    }

    #[test]
    fn execution_release_requires_epoch_input_and_matching_subject() {
        let admitted = first_fact();
        let epoch = RunEpochEnvelope::new(model_epoch()).unwrap();
        let mut started = start_fact(admitted.digest, epoch.digest);
        if let ExecutionFactData::WorkflowTransition { epoch_digest, .. } = &mut started.fact.data {
            *epoch_digest = None;
        } else {
            panic!("fixture must be a workflow transition");
        }
        assert!(started.fact.validate().is_err());
        if let ExecutionFactData::WorkflowTransition {
            epoch_digest,
            subject,
            ..
        } = &mut started.fact.data
        {
            *epoch_digest = Some(digest(DIGEST_A));
            *subject = Some(OperationRef::Model {
                job_id: "job-agent-001-1".into(),
                step: 2,
            });
        } else {
            panic!("fixture must be a workflow transition");
        }
        assert!(started.fact.validate().is_err());
    }

    #[test]
    fn restart_recovery_is_unknown_epoch_bound_and_never_releases_work() {
        let started = workflows::reduce(&WorkflowState::default(), Command::StartModel)
            .unwrap()
            .into_state();
        let unknown = workflows::reduce(&started, Command::ModelOutcomeUnknown)
            .unwrap()
            .into_state();
        let data = ExecutionFactData::WorkflowTransition {
            from_revision: 2,
            to_revision: 3,
            command: Command::ModelOutcomeUnknown,
            state: unknown,
            external_call: None,
            emitted_result: None,
            emitted_result_digest: None,
            epoch_digest: Some(digest(DIGEST_A)),
            source: FactSource::RestartRecovery,
            subject: Some(OperationRef::Model {
                job_id: "job-agent-001-1".into(),
                step: 1,
            }),
            input_digest: Some(digest(DIGEST_B)),
            output_digest: Some(
                canonical_sha256(DigestDomain::ExecutionError, &json!({"code": "unknown"}))
                    .unwrap(),
            ),
            next_request_digest: None,
        };
        assert!(data.validate().is_ok());

        let mut invalid = data;
        let ExecutionFactData::WorkflowTransition { external_call, .. } = &mut invalid else {
            unreachable!();
        };
        *external_call = Some(ExternalCall::Model { step: 1 });
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn serialized_epoch_and_facts_have_no_raw_or_secret_bearing_fields() {
        let epoch = RunEpochEnvelope::new(model_epoch()).unwrap();
        let admitted = first_fact();
        let started = start_fact(admitted.digest.clone(), epoch.digest.clone());
        for value in [
            serde_json::to_value(epoch).unwrap(),
            serde_json::to_value(admitted).unwrap(),
            serde_json::to_value(started).unwrap(),
        ] {
            assert_no_secret_fields(&value);
            let serialized = serde_json::to_string(&value).unwrap();
            assert!(!serialized.contains(NEVER_PERSIST));
        }
    }

    #[test]
    fn versions_sequences_timestamps_and_unknown_nested_fields_are_rejected() {
        assert!(RecordedAt::parse("2026-08-27T12:00:00Z").is_err());
        assert!(ActorRevision::new("user-owner", 0).is_err());

        let admitted = first_fact();
        let mut wrong_version = admitted.clone();
        wrong_version.schema_version += 1;
        assert!(matches!(
            wrong_version.validate(),
            Err(ExecutionError::UnsupportedSchemaVersion {
                kind: "execution_fact_envelope",
                ..
            })
        ));

        let mut invalid_chain = admitted.clone();
        invalid_chain.fact.previous_fact_digest = Some(digest(DIGEST_A));
        assert!(invalid_chain.fact.validate().is_err());

        let mut value = serde_json::to_value(&admitted).unwrap();
        value["fact"]["data"]
            .as_object_mut()
            .unwrap()
            .insert("raw_response".into(), json!({"content": NEVER_PERSIST}));
        assert!(matches!(
            ExecutionFactEnvelope::from_json_slice(&serde_json::to_vec(&value).unwrap()),
            Err(ExecutionError::InvalidJson(_))
        ));
    }

    #[test]
    fn exact_json_material_is_canonical_digest_bound_and_explicitly_sensitive() {
        let left = ExactJsonMaterial::new(
            ExactMaterialKind::ModelRequest,
            serde_json::from_str(r#"{"messages":[{"content":"alpha","role":"user"}],"z":1}"#)
                .unwrap(),
        )
        .unwrap();
        let right = ExactJsonMaterial::new(
            ExactMaterialKind::ModelRequest,
            json!({"z": 1, "messages": [{"role": "user", "content": "alpha"}]}),
        )
        .unwrap();
        assert_eq!(left.digest, right.digest);
        assert_eq!(left.byte_len, right.byte_len);

        let mut tampered = left;
        tampered.value["messages"][0]["content"] = json!("omega");
        assert!(matches!(
            tampered.validate(),
            Err(ExecutionError::DigestMismatch {
                kind: "exact JSON material"
            })
        ));
    }

    #[test]
    fn fact_summary_preserves_the_verified_chain_index() {
        let admitted = first_fact();
        let summary = ExecutionFactSummary::from_envelope(&admitted).unwrap();
        assert_eq!(summary.sequence, 1);
        assert_eq!(summary.digest, admitted.digest);
        assert_eq!(summary.previous_fact_digest, None);
        assert_eq!(summary.kind, ExecutionFactKind::AgentAdmitted);
        assert_eq!(summary.subject, None);
        assert_eq!(summary.epoch_digest, None);
    }

    #[test]
    fn single_model_epoch_explain_binds_exact_request_and_outcome() {
        let manifest = manifest();
        let manifest_digest = Sha256Digest::from_hex(manifest.digest.clone()).unwrap();
        let request = ExactJsonMaterial::new(
            ExactMaterialKind::ModelRequest,
            json!({"messages": [{"role": "user", "content": "explain this"}]}),
        )
        .unwrap();
        let response = ExactJsonMaterial::new(
            ExactMaterialKind::ModelResponse,
            json!({"output": {"type": "final", "content": "done"}}),
        )
        .unwrap();
        let epoch = RunEpoch::new(
            "agent-001",
            "acc_local",
            "session-001",
            "turn-001",
            2,
            Some(manifest_digest.clone()),
            manifest_digest,
            RunOperation::model("job-agent-001-1", 1, request.digest.clone()).unwrap(),
            actor("user-owner", 7),
            None,
            timestamp(1),
        )
        .unwrap();
        let provenance = AssistantReplyProvenance {
            provider_id: "provider-one".into(),
            model: Some("model-one".into()),
            reply_kind: protocol::AssistantReplyKind::Model,
        };
        let summary = RunEpochSummary {
            envelope: RunEpochEnvelope::new(epoch).unwrap(),
            status: EpochExecutionStatus::Succeeded,
            queued_at: timestamp(1),
            started_at: Some(timestamp(2)),
            finished_at: Some(timestamp(3)),
            outcome_digest: Some(response.digest.clone()),
            provenance: Some(provenance.clone()),
        };
        let admitted = first_fact();
        let started = start_fact(admitted.digest.clone(), summary.envelope.digest.clone());
        let facts = vec![
            ExecutionFactSummary::from_envelope(&admitted).unwrap(),
            ExecutionFactSummary::from_envelope(&started).unwrap(),
        ];
        let explanation = AgentRunEpochExplain {
            schema_version: AGENT_RUN_EPOCH_EXPLAIN_SCHEMA_VERSION,
            agent_id: "agent-001".into(),
            session_id: "session-001".into(),
            turn_id: "turn-001".into(),
            watermark: ExecutionWatermark::new(2, 1, 2, Some(started.digest.clone())).unwrap(),
            history: ExecutionHistory {
                origin: ExecutionHistoryOrigin::LegacySnapshot,
                overall: ReconstructionLevel::Partial,
                request_material: ReconstructionLevel::Complete,
                derivation: ReconstructionLevel::Partial,
                deployment_authority: DeploymentAuthority::Verified,
                reasons: vec![ExecutionHistoryReason::LegacyExecutionSnapshot],
            },
            manifest: Some(manifest),
            epoch: summary,
            request,
            outcome: EpochOutcomeMaterial::Succeeded {
                response,
                provenance,
            },
            linked_tools: Vec::new(),
            facts,
        };
        explanation.validate().unwrap();

        let mut request_tampered = explanation.clone();
        request_tampered.request.value["messages"][0]["content"] = json!("other");
        assert!(request_tampered.validate().is_err());

        let mut chain_tampered = explanation;
        chain_tampered.facts.pop();
        assert!(chain_tampered.validate().is_err());
    }
}
