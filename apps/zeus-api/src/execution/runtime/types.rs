use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;
use sqlx::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::ModelError;

pub(super) const MAX_TOOL_RESULT_BYTES: usize = 1_048_576;
pub(super) const MAX_EXPERIENCE_ENTRIES: u16 = 20;
pub(super) const MAX_EXPERIENCE_CONTENT_CHARS: usize = 8_000;
pub(super) const MAX_EXPERIENCE_CONTEXT_CHARS: usize = 32_000;
pub(super) const MAX_CHILD_RUN_DEPTH: i16 = 8;
pub(super) const MAX_CHILD_TASK_CHARS: usize = 50_000;

#[derive(Debug)]
pub(super) enum RuntimeControl {
    WaitingApproval,
    WaitingChild,
    Canceled,
    Failed(RuntimeFailure),
}

impl From<RuntimeFailure> for RuntimeControl {
    fn from(value: RuntimeFailure) -> Self {
        Self::Failed(value)
    }
}

#[derive(Debug)]
pub(super) enum RuntimeFailure {
    Database,
    StaleFence,
    InvalidConfiguration(&'static str),
    InvalidSession,
    InvalidModelTool,
    InvalidToolInput,
    Limit(&'static str),
    Model(ModelError),
}

impl RuntimeFailure {
    pub(super) const fn code(&self) -> &'static str {
        match self {
            Self::Database => "runtime_database_error",
            Self::StaleFence => "stale_run_fence",
            Self::InvalidConfiguration(code) | Self::Limit(code) => code,
            Self::InvalidSession => "invalid_session_history",
            Self::InvalidModelTool => "invalid_model_tool_call",
            Self::InvalidToolInput => "capability_input_schema_violation",
            Self::Model(ModelError::Canceled) => "model_canceled",
            Self::Model(ModelError::Timeout) => "model_timeout",
            Self::Model(ModelError::RateLimited { .. }) => "model_rate_limited",
            Self::Model(ModelError::Server { .. }) => "model_server_error",
            Self::Model(ModelError::HttpStatus { .. }) => "model_request_rejected",
            Self::Model(ModelError::InvalidConfiguration) => "invalid_model_configuration",
            Self::Model(ModelError::InvalidResponse) => "invalid_model_response",
            Self::Model(ModelError::StreamInterrupted) => "model_stream_interrupted",
            Self::Model(ModelError::Transport) => "model_transport_error",
        }
    }

    pub(super) fn detail(&self) -> String {
        match self {
            Self::Model(error) => error.to_string(),
            _ => self.code().replace('_', " "),
        }
    }
}

impl From<sqlx::Error> for RuntimeFailure {
    fn from(error: sqlx::Error) -> Self {
        let database_code = error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .map(std::borrow::Cow::into_owned);
        let error_kind = if error.as_database_error().is_some() {
            "database"
        } else if matches!(error, sqlx::Error::RowNotFound) {
            "row_not_found"
        } else {
            "client"
        };
        tracing::error!(
            error_kind,
            database_code = database_code.as_deref().unwrap_or("none"),
            "runtime database operation failed"
        );
        Self::Database
    }
}

#[derive(Debug, FromRow)]
pub(super) struct RunPlan {
    pub(super) instructions: String,
    pub(super) model_profile_id: Uuid,
    pub(super) model_profile_revision: i64,
    pub(super) model_connection_id: Uuid,
    pub(super) model_connection_configuration: Value,
    pub(super) model_base_url: String,
    pub(super) model: String,
    pub(super) model_configuration: Value,
    pub(super) capability_policy: Value,
    pub(super) approval_policy: Value,
    pub(super) experience_policy: Value,
    pub(super) max_steps: i32,
    pub(super) max_runtime_seconds: i32,
    pub(super) token_budget: Option<i64>,
    pub(super) retry_policy: Value,
    pub(super) started_at: OffsetDateTime,
}

impl RunPlan {
    pub(super) fn model_network_attempts(&self) -> u8 {
        self.retry_policy
            .get("model_network_attempts")
            .and_then(Value::as_u64)
            .and_then(|value| u8::try_from(value.min(8)).ok())
            .unwrap_or(2)
    }

    pub(super) fn token_budget_u64(&self) -> Option<u64> {
        self.token_budget
            .and_then(|value| u64::try_from(value).ok())
    }

    pub(super) fn experience_limit(&self) -> u16 {
        self.experience_policy
            .get("max_entries")
            .and_then(Value::as_u64)
            .and_then(|value| u16::try_from(value).ok())
            .unwrap_or(8)
            .min(MAX_EXPERIENCE_ENTRIES)
    }

    pub(super) fn include_workspace_experience(&self) -> bool {
        self.experience_policy
            .get("include_workspace")
            .and_then(Value::as_bool)
            .unwrap_or(true)
    }

    pub(super) fn include_organization_experience(&self) -> bool {
        self.experience_policy
            .get("include_organization")
            .and_then(Value::as_bool)
            .unwrap_or(true)
    }

    pub(super) fn remaining_runtime(&self) -> Result<Duration, RuntimeFailure> {
        let elapsed = OffsetDateTime::now_utc() - self.started_at;
        let elapsed_seconds = elapsed.whole_seconds().max(0);
        let remaining = i64::from(self.max_runtime_seconds).saturating_sub(elapsed_seconds);
        if remaining <= 0 {
            return Err(RuntimeFailure::Limit("run_timeout"));
        }
        Ok(Duration::from_secs(
            u64::try_from(remaining).map_err(|_| RuntimeFailure::Limit("run_timeout"))?,
        ))
    }
}

#[derive(Debug, FromRow)]
pub(super) struct InjectedExperience {
    pub(super) id: Uuid,
    pub(super) scope: String,
    pub(super) version_number: i32,
    pub(super) title: String,
    pub(super) content: String,
    pub(super) rank: f32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ChildRunRequest {
    pub(super) workflow_version_id: Uuid,
    pub(super) task: String,
    pub(super) token_budget: i64,
    pub(super) max_runtime_seconds: i32,
}

#[derive(Debug, FromRow)]
pub(super) struct ParentRunContext {
    pub(super) root_run_id: Uuid,
    pub(super) depth: i16,
    pub(super) work_item_id: Option<Uuid>,
}

#[derive(Debug, FromRow)]
pub(super) struct TargetWorkflowContext {
    pub(super) capability_policy: Value,
    pub(super) approval_policy: Value,
    pub(super) max_runtime_seconds: i32,
    pub(super) token_budget: Option<i64>,
}

#[derive(Debug, FromRow)]
pub(super) struct PolicyCapability {
    pub(super) id: Uuid,
    pub(super) registry_key: String,
}

#[derive(Debug, FromRow)]
pub(super) struct ChildRunResult {
    pub(super) id: Uuid,
    pub(super) status: String,
    pub(super) output: Option<Value>,
    pub(super) error_code: Option<String>,
    pub(super) error_detail: Option<String>,
}

pub(super) enum ChildToolResume {
    Completed,
    Waiting,
}

pub(super) enum ChildRunCreateError {
    Runtime(RuntimeFailure),
    Rejected(&'static str),
}

#[derive(Debug, FromRow)]
pub(super) struct SecretRow {
    pub(super) secret_name: String,
    pub(super) ciphertext: Vec<u8>,
    pub(super) nonce: Vec<u8>,
    pub(super) key_id: String,
}

#[derive(Clone, Debug, FromRow)]
pub(super) struct RuntimeCapability {
    pub(super) id: Uuid,
    pub(super) registry_key: String,
    pub(super) display_name: String,
    pub(super) description: String,
    pub(super) input_schema: Value,
    pub(super) output_schema: Value,
    pub(super) idempotency_mode: String,
    pub(super) risk_level: String,
    pub(super) executor_key: String,
    pub(super) approval_required: bool,
    pub(super) timeout_seconds: i32,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum ToolExecutionError {
    InputSchemaViolation,
    OutputSchemaViolation,
    ExecutorUnavailable,
    OutcomeUnknown,
    Timeout,
    ChildRunRejected(&'static str),
}

#[derive(Debug, FromRow)]
pub(super) struct OpenToolCall {
    pub(super) id: Uuid,
    pub(super) call_key: String,
    pub(super) capability_id: Uuid,
    pub(super) idempotency_key: Option<String>,
    pub(super) status: String,
    pub(super) input: Value,
    pub(super) child_run_id: Option<Uuid>,
}

pub(super) enum ToolResume {
    Ready,
    WaitingApproval,
    WaitingChild,
}
