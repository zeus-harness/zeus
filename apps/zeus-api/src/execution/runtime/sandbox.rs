use super::{
    DurableRunExecutor,
    tools::execute_registered_capability,
    types::{OpenToolCall, RunPlan, RuntimeCapability, ToolExecutionError},
};
use crate::{
    execution::{
        code_workspace::{CodeScope, RepositoryBinding},
        sandbox::{export_files, import_files},
    },
    supervisor::ClaimedRun,
};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScriptInput {
    script: String,
}
impl DurableRunExecutor {
    pub(super) async fn execute_tool(
        &self,
        run: &ClaimedRun,
        plan: &RunPlan,
        call: &OpenToolCall,
        capability: &RuntimeCapability,
    ) -> Result<Value, ToolExecutionError> {
        if capability.executor_key == "builtin.studio_resource_create" {
            return sqlx::query_scalar(
                "select zeus_private.create_studio_resource($1, $2, $3, $4)",
            )
            .bind(run.run_id)
            .bind(&self.node_id)
            .bind(run.fence_token)
            .bind(call.id)
            .fetch_one(&self.pool)
            .await
            .map_err(|_| ToolExecutionError::ChildRunRejected("studio_resource_creation_failed"));
        }
        if capability.executor_key != "builtin.sandbox_exec" {
            return execute_registered_capability(&self.pool, run, capability, &call.input).await;
        }
        let input: ScriptInput = serde_json::from_value(call.input.clone())
            .map_err(|_| ToolExecutionError::InputSchemaViolation)?;
        let environment = plan
            .execution_environment
            .as_deref()
            .ok_or(ToolExecutionError::ExecutorUnavailable)?;
        let storage = self
            .code_storage
            .as_ref()
            .ok_or(ToolExecutionError::ExecutorUnavailable)?;
        let client = self
            .sandbox
            .as_ref()
            .ok_or(ToolExecutionError::ExecutorUnavailable)?;
        let binding: RepositoryBinding = serde_json::from_value(
            plan.code_repository
                .clone()
                .ok_or(ToolExecutionError::ExecutorUnavailable)?,
        )
        .map_err(|_| ToolExecutionError::InputSchemaViolation)?;
        // Approval is mandatory independently of editable catalog risk/idempotency settings.
        self.authorize_sandbox(run, call).await?;
        let directory = storage.directory(CodeScope {
            organization_id: run.organization_id,
            workspace_id: run.workspace_id,
            run_id: run.run_id,
            fence: run.fence_token,
        });
        let files = export_files(&directory)
            .await
            .map_err(|_| ToolExecutionError::InputSchemaViolation)?;
        let execution = client.execute(
            call.id,
            environment,
            &input.script,
            u32::try_from(capability.timeout_seconds)
                .unwrap_or(30)
                .clamp(1, 300),
            files,
        );
        let permission_watch = async {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                self.authorize_sandbox(run, call).await?;
            }
            #[allow(unreachable_code)]
            Ok::<(), ToolExecutionError>(())
        };
        let result = tokio::select! {
            result = execution => result.map_err(|_| ToolExecutionError::OutcomeUnknown)?,
            result = permission_watch => { result?; return Err(ToolExecutionError::ExecutorUnavailable); }
        };
        self.authorize_sandbox(run, call).await?;
        import_files(&directory, &result.files)
            .await
            .map_err(|_| ToolExecutionError::OutputSchemaViolation)?;
        // Persist file changes before completing the tool event; never report unsaved success.
        self.save_code_checkpoint(run, &binding)
            .await
            .map_err(|_| ToolExecutionError::OutcomeUnknown)?;
        Ok(json!({"exit_code":result.exit_code, "output":result.output, "environment":environment}))
    }
    async fn authorize_sandbox(
        &self,
        run: &ClaimedRun,
        call: &OpenToolCall,
    ) -> Result<(), ToolExecutionError> {
        let allowed: bool = sqlx::query_scalar(
            "select zeus_private.sandbox_execution_authorized($1,$2,$3,$4,$5,$6)",
        )
        .bind(run.run_id)
        .bind(run.organization_id)
        .bind(run.workspace_id)
        .bind(run.fence_token)
        .bind(&self.node_id)
        .bind(call.id)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| ToolExecutionError::ExecutorUnavailable)?;
        if !allowed {
            return Err(ToolExecutionError::ExecutorUnavailable);
        }
        Ok(())
    }
}
