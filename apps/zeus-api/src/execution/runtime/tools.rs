use std::{collections::HashMap, time::Duration};

use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use super::{
    DurableRunExecutor,
    events::{append_run_event_in_transaction, append_session_event},
    policy::capability_is_allowed,
    types::{
        ChildToolResume, OpenToolCall, RunPlan, RuntimeCapability, RuntimeFailure,
        ToolExecutionError, ToolResume,
    },
};
use crate::{model::ToolDefinition, supervisor::ClaimedRun};

impl RuntimeCapability {
    pub(super) fn validate_schemas(&self) -> Result<(), RuntimeFailure> {
        jsonschema::validator_for(&self.input_schema)
            .and_then(|_| jsonschema::validator_for(&self.output_schema).map(|_| ()))
            .map_err(|_| RuntimeFailure::InvalidConfiguration("invalid_capability_schema"))
    }

    pub(super) fn validate_input(&self, input: &Value) -> Result<(), ToolExecutionError> {
        let validator = jsonschema::validator_for(&self.input_schema)
            .map_err(|_| ToolExecutionError::InputSchemaViolation)?;
        validator
            .validate(input)
            .map_err(|_| ToolExecutionError::InputSchemaViolation)
    }

    pub(super) fn validate_output(&self, output: &Value) -> Result<(), ToolExecutionError> {
        let validator = jsonschema::validator_for(&self.output_schema)
            .map_err(|_| ToolExecutionError::OutputSchemaViolation)?;
        validator
            .validate(output)
            .map_err(|_| ToolExecutionError::OutputSchemaViolation)
    }

    pub(super) fn model_name(&self) -> String {
        format!("cap_{}", self.id.simple())
    }

    pub(super) fn tool_definition(&self) -> ToolDefinition {
        ToolDefinition::new(
            self.model_name(),
            format!(
                "[{}] {} — {}",
                self.registry_key, self.display_name, self.description
            ),
            self.input_schema.clone(),
        )
    }

    pub(super) fn needs_approval(&self, approval_policy: &Value) -> bool {
        self.approval_required
            || (self.risk_level == "high"
                && approval_policy
                    .get("require_high_risk")
                    .and_then(Value::as_bool)
                    .unwrap_or(true))
    }

    pub(super) fn supports_idempotency(&self) -> bool {
        matches!(self.idempotency_mode.as_str(), "required" | "supported")
    }
}

impl DurableRunExecutor {
    pub(super) async fn load_capabilities(
        &self,
        run: &ClaimedRun,
        plan: &RunPlan,
    ) -> Result<Vec<RuntimeCapability>, RuntimeFailure> {
        let mut capabilities = sqlx::query_as::<_, RuntimeCapability>(
            "select d.id, d.registry_key, d.display_name, d.description,
                    d.input_schema, d.output_schema, d.idempotency_mode, d.risk_level,
                    d.executor_key, c.approval_required, c.timeout_seconds
             from workspace_capabilities c
             join capability_definitions d on d.id = c.capability_id
             where c.organization_id = $1 and c.workspace_id = $2
               and d.organization_id = $1
               and c.enabled and d.archived_at is null
             order by d.registry_key, d.id",
        )
        .bind(run.organization_id)
        .bind(run.workspace_id)
        .fetch_all(&self.pool)
        .await?;
        capabilities
            .retain(|capability| capability_is_allowed(&plan.capability_policy, capability));
        for capability in &capabilities {
            capability.validate_schemas()?;
        }
        Ok(capabilities)
    }

    pub(super) async fn resume_open_tools(
        &self,
        run: &ClaimedRun,
        plan: &RunPlan,
        capabilities: &[RuntimeCapability],
        cancellation: &CancellationToken,
    ) -> Result<ToolResume, super::types::RuntimeControl> {
        let calls = sqlx::query_as::<_, OpenToolCall>(
            "select id, call_key, capability_id, idempotency_key, status, input, child_run_id
             from tool_calls
             where organization_id = $1 and workspace_id = $2 and run_id = $3
               and status in ('pending_approval', 'ready', 'running', 'waiting_child')
             order by created_at, id",
        )
        .bind(run.organization_id)
        .bind(run.workspace_id)
        .bind(run.run_id)
        .fetch_all(&self.pool)
        .await
        .map_err(RuntimeFailure::from)?;
        if calls.iter().any(|call| call.status == "pending_approval") {
            return Ok(ToolResume::WaitingApproval);
        }

        let capability_by_id = capabilities
            .iter()
            .map(|capability| (capability.id, capability))
            .collect::<HashMap<_, _>>();
        for call in calls {
            if cancellation.is_cancelled() {
                return Err(super::types::RuntimeControl::Canceled);
            }
            let capability = capability_by_id
                .get(&call.capability_id)
                .copied()
                .ok_or(RuntimeFailure::InvalidModelTool)?;
            if capability.executor_key == "builtin.child_run" {
                match self.resume_child_tool(run, plan, &call, capability).await? {
                    ChildToolResume::Completed => continue,
                    ChildToolResume::Waiting => return Ok(ToolResume::WaitingChild),
                }
            }
            if call.status == "waiting_child" {
                return Err(
                    RuntimeFailure::InvalidConfiguration("invalid_child_tool_state").into(),
                );
            }
            self.start_tool_call(run, &call, capability).await?;
            let execution = if let Err(error) = capability.validate_input(&call.input) {
                Err(error)
            } else if call.status == "running" && call.idempotency_key.is_none() {
                Err(ToolExecutionError::OutcomeUnknown)
            } else {
                let timeout =
                    Duration::from_secs(u64::try_from(capability.timeout_seconds).unwrap_or(60));
                tokio::select! {
                    () = cancellation.cancelled() => return Err(super::types::RuntimeControl::Canceled),
                    result = tokio::time::timeout(
                        timeout,
                        execute_registered_capability(capability, &call.input),
                    ) => match result {
                        Ok(result) => result,
                        Err(_) => Err(ToolExecutionError::Timeout),
                    }
                }
            }
            .and_then(|result| {
                capability.validate_output(&result)?;
                Ok(result)
            });
            self.complete_tool_call(run, &call, capability, execution)
                .await?;
        }
        Ok(ToolResume::Ready)
    }

    pub(super) async fn start_tool_call(
        &self,
        run: &ClaimedRun,
        call: &OpenToolCall,
        capability: &RuntimeCapability,
    ) -> Result<(), RuntimeFailure> {
        let mut transaction = self.begin_fenced(run).await?;
        let affected = sqlx::query(
            "update tool_calls
             set status = 'running', fence_token = $1, started_at = coalesce(started_at, now())
             where id = $2 and organization_id = $3 and workspace_id = $4 and run_id = $5
               and status in ('ready', 'running')",
        )
        .bind(run.fence_token)
        .bind(call.id)
        .bind(run.organization_id)
        .bind(run.workspace_id)
        .bind(run.run_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if affected != 1 {
            return Err(RuntimeFailure::StaleFence);
        }
        append_run_event_in_transaction(
            &mut transaction,
            run,
            "tool.started",
            json!({
                "tool_call_id": call.id,
                "call_id": call.call_key,
                "capability_id": capability.id,
                "executor_key": capability.executor_key,
            }),
            None,
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub(super) async fn complete_tool_call(
        &self,
        run: &ClaimedRun,
        call: &OpenToolCall,
        capability: &RuntimeCapability,
        execution: Result<Value, ToolExecutionError>,
    ) -> Result<(), RuntimeFailure> {
        let (status, result, error_code) = match execution {
            Ok(result) => ("succeeded", normalize_tool_result(result), None),
            Err(error) => (
                "failed",
                json!({ "error": { "code": error.code() } }),
                Some(error.code()),
            ),
        };
        let mut transaction = self.begin_fenced(run).await?;
        let affected = sqlx::query(
            "update tool_calls
             set status = $1, result = $2, error_code = $3, finished_at = now()
             where id = $4 and organization_id = $5 and workspace_id = $6 and run_id = $7
               and status in ('running', 'waiting_child') and fence_token = $8",
        )
        .bind(status)
        .bind(&result)
        .bind(error_code)
        .bind(call.id)
        .bind(run.organization_id)
        .bind(run.workspace_id)
        .bind(run.run_id)
        .bind(run.fence_token)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if affected != 1 {
            return Err(RuntimeFailure::StaleFence);
        }
        let session_event_id = append_session_event(
            &mut transaction,
            run,
            "tool_result",
            json!({
                "call_id": call.call_key,
                "result": result,
                "synthetic": false,
                "tool_call_id": call.id,
            }),
        )
        .await?;
        append_run_event_in_transaction(
            &mut transaction,
            run,
            "tool.result",
            json!({
                "tool_call_id": call.id,
                "call_id": call.call_key,
                "capability_id": capability.id,
                "status": status,
                "error_code": error_code,
            }),
            Some(session_event_id),
        )
        .await?;
        sqlx::query(
            "insert into audit_events (
                organization_id, workspace_id, actor_kind, actor_id,
                action, target_type, target_id, metadata
             ) values ($1, $2, 'agent', null, $3, 'tool_call', $4, $5)",
        )
        .bind(run.organization_id)
        .bind(run.workspace_id)
        .bind(if status == "succeeded" {
            "capability.call_succeeded"
        } else {
            "capability.call_failed"
        })
        .bind(call.id)
        .bind(json!({ "run_id": run.run_id, "capability_id": capability.id }))
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }
}

async fn execute_registered_capability(
    capability: &RuntimeCapability,
    input: &Value,
) -> Result<Value, ToolExecutionError> {
    tokio::task::yield_now().await;
    match capability.executor_key.as_str() {
        "builtin.echo" => Ok(json!({ "echo": input })),
        _ => Err(ToolExecutionError::ExecutorUnavailable),
    }
}

pub(super) fn normalize_tool_result(mut value: Value) -> Value {
    redact_sensitive_fields(&mut value);
    if serde_json::to_vec(&value).map_or(true, |encoded| {
        encoded.len() > super::types::MAX_TOOL_RESULT_BYTES
    }) {
        json!({
            "error": { "code": "capability_result_too_large" },
            "truncated": true,
        })
    } else {
        value
    }
}

fn redact_sensitive_fields(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if is_sensitive_key(key) {
                    *value = Value::String("<REDACTED>".to_owned());
                } else {
                    redact_sensitive_fields(value);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                redact_sensitive_fields(value);
            }
        }
        _ => {}
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    [
        "authorization",
        "password",
        "secret",
        "token",
        "api_key",
        "cookie",
    ]
    .iter()
    .any(|candidate| normalized.contains(candidate))
}

impl ToolExecutionError {
    pub(super) const fn code(self) -> &'static str {
        match self {
            Self::InputSchemaViolation => "capability_input_schema_violation",
            Self::OutputSchemaViolation => "capability_output_schema_violation",
            Self::ExecutorUnavailable => "capability_executor_unavailable",
            Self::OutcomeUnknown => "capability_outcome_unknown",
            Self::Timeout => "capability_timeout",
            Self::ChildRunRejected(code) => code,
        }
    }
}
