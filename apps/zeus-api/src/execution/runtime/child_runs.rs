use serde_json::json;
use uuid::Uuid;

use super::{
    DurableRunExecutor,
    events::append_run_event_in_transaction,
    policy::{approval_policy_is_weaker, capability_policy_is_subset, child_session_title},
    types::{
        ChildRunCreateError, ChildRunRequest, ChildRunResult, ChildToolResume, OpenToolCall,
        ParentRunContext, PolicyCapability, RunPlan, RuntimeCapability, RuntimeControl,
        RuntimeFailure, TargetWorkflowContext, ToolExecutionError,
    },
};
use crate::supervisor::ClaimedRun;

impl ChildRunRequest {
    pub(super) fn normalize_and_validate(&mut self) -> Result<(), ToolExecutionError> {
        self.task = self.task.trim().to_owned();
        if self.task.is_empty()
            || self.task.chars().count() > super::types::MAX_CHILD_TASK_CHARS
            || self.token_budget <= 0
            || self.max_runtime_seconds <= 0
        {
            return Err(ToolExecutionError::ChildRunRejected(
                "invalid_child_run_request",
            ));
        }
        Ok(())
    }
}

impl From<RuntimeFailure> for ChildRunCreateError {
    fn from(value: RuntimeFailure) -> Self {
        Self::Runtime(value)
    }
}

impl From<sqlx::Error> for ChildRunCreateError {
    fn from(error: sqlx::Error) -> Self {
        Self::Runtime(RuntimeFailure::from(error))
    }
}

impl DurableRunExecutor {
    pub(super) async fn resume_child_tool(
        &self,
        run: &ClaimedRun,
        plan: &RunPlan,
        call: &OpenToolCall,
        capability: &RuntimeCapability,
    ) -> Result<ChildToolResume, RuntimeControl> {
        if !capability.supports_idempotency() {
            return Err(RuntimeFailure::InvalidConfiguration(
                "child_run_capability_requires_idempotency",
            )
            .into());
        }

        if let Some(child_run_id) = call.child_run_id {
            let child = sqlx::query_as::<_, ChildRunResult>(
                "select id, status, output, error_code, error_detail
                 from runs
                 where id = $1 and organization_id = $2 and workspace_id = $3
                   and parent_run_id = $4",
            )
            .bind(child_run_id)
            .bind(run.organization_id)
            .bind(run.workspace_id)
            .bind(run.run_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(RuntimeFailure::from)?
            .ok_or(RuntimeFailure::InvalidConfiguration(
                "child_run_state_unavailable",
            ))?;
            if !matches!(child.status.as_str(), "succeeded" | "failed" | "canceled") {
                return Ok(ChildToolResume::Waiting);
            }

            self.adopt_waiting_child_tool(run, call).await?;
            let result = json!({
                "child_run_id": child.id,
                "status": child.status,
                "output": child.output,
                "error": child.error_code.map(|code| json!({
                    "code": code,
                    "detail": child.error_detail,
                })),
            });
            let execution = capability.validate_output(&result).map(|()| result);
            self.complete_tool_call(run, call, capability, execution)
                .await?;
            return Ok(ChildToolResume::Completed);
        }

        if call.status == "waiting_child" {
            return Err(RuntimeFailure::InvalidConfiguration("invalid_child_tool_state").into());
        }
        self.start_tool_call(run, call, capability).await?;
        let Ok(mut request) = serde_json::from_value::<ChildRunRequest>(call.input.clone()) else {
            self.complete_tool_call(
                run,
                call,
                capability,
                Err(ToolExecutionError::ChildRunRejected(
                    "invalid_child_run_request",
                )),
            )
            .await?;
            return Ok(ChildToolResume::Completed);
        };
        if let Err(error) = request.normalize_and_validate() {
            self.complete_tool_call(run, call, capability, Err(error))
                .await?;
            return Ok(ChildToolResume::Completed);
        }

        match self.create_child_run(run, plan, call, &request).await {
            Ok(_) => Ok(ChildToolResume::Waiting),
            Err(ChildRunCreateError::Rejected(code)) => {
                self.complete_tool_call(
                    run,
                    call,
                    capability,
                    Err(ToolExecutionError::ChildRunRejected(code)),
                )
                .await?;
                Ok(ChildToolResume::Completed)
            }
            Err(ChildRunCreateError::Runtime(error)) => Err(error.into()),
        }
    }

    async fn adopt_waiting_child_tool(
        &self,
        run: &ClaimedRun,
        call: &OpenToolCall,
    ) -> Result<(), RuntimeFailure> {
        let mut transaction = self.begin_fenced(run).await?;
        let affected = sqlx::query(
            "update tool_calls
             set fence_token = $1
             where id = $2 and organization_id = $3 and workspace_id = $4 and run_id = $5
               and status = 'waiting_child' and child_run_id = $6",
        )
        .bind(run.fence_token)
        .bind(call.id)
        .bind(run.organization_id)
        .bind(run.workspace_id)
        .bind(run.run_id)
        .bind(call.child_run_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if affected != 1 {
            return Err(RuntimeFailure::StaleFence);
        }
        transaction.commit().await?;
        Ok(())
    }

    #[allow(clippy::too_many_lines)] // Child creation validates policy and persists the complete hand-off atomically.
    async fn create_child_run(
        &self,
        run: &ClaimedRun,
        plan: &RunPlan,
        call: &OpenToolCall,
        request: &ChildRunRequest,
    ) -> Result<Uuid, ChildRunCreateError> {
        let mut transaction = self.begin_fenced(run).await?;
        let parent = sqlx::query_as::<_, ParentRunContext>(
            "select coalesce(root_run_id, id) as root_run_id, depth, work_item_id
             from runs
             where id = $1 and organization_id = $2 and workspace_id = $3",
        )
        .bind(run.run_id)
        .bind(run.organization_id)
        .bind(run.workspace_id)
        .fetch_one(&mut *transaction)
        .await?;
        if parent.depth >= super::types::MAX_CHILD_RUN_DEPTH {
            return Err(ChildRunCreateError::Rejected("child_run_depth_exceeded"));
        }

        let target = sqlx::query_as::<_, TargetWorkflowContext>(
            "select capability_policy, approval_policy, max_runtime_seconds, token_budget
             from workflow_versions
             where id = $1 and organization_id = $2 and workspace_id = $3",
        )
        .bind(request.workflow_version_id)
        .bind(run.organization_id)
        .bind(run.workspace_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ChildRunCreateError::Rejected("child_workflow_unavailable"))?;

        let policy_capabilities = sqlx::query_as::<_, PolicyCapability>(
            "select definition.id, definition.registry_key
             from workspace_capabilities workspace_capability
             join capability_definitions definition
               on definition.id = workspace_capability.capability_id
             where workspace_capability.organization_id = $1
               and workspace_capability.workspace_id = $2
               and definition.organization_id = $1
               and workspace_capability.enabled
               and definition.archived_at is null",
        )
        .bind(run.organization_id)
        .bind(run.workspace_id)
        .fetch_all(&mut *transaction)
        .await?;
        if !capability_policy_is_subset(
            &plan.capability_policy,
            &target.capability_policy,
            &policy_capabilities,
        ) {
            return Err(ChildRunCreateError::Rejected(
                "child_capability_budget_exceeded",
            ));
        }
        if approval_policy_is_weaker(&plan.approval_policy, &target.approval_policy) {
            return Err(ChildRunCreateError::Rejected(
                "child_approval_policy_is_weaker",
            ));
        }

        let parent_token_budget = plan.token_budget.ok_or(ChildRunCreateError::Rejected(
            "parent_token_budget_required",
        ))?;
        let parent_used: i64 = sqlx::query_scalar(
            "select coalesce(sum(prompt_tokens + completion_tokens), 0)::bigint
             from run_usage
             where organization_id = $1 and workspace_id = $2 and run_id = $3",
        )
        .bind(run.organization_id)
        .bind(run.workspace_id)
        .bind(run.run_id)
        .fetch_one(&mut *transaction)
        .await?;
        let child_allocated: i64 = sqlx::query_scalar(
            "select coalesce(sum(token_budget_override), 0)::bigint
             from runs
             where organization_id = $1 and workspace_id = $2 and parent_run_id = $3",
        )
        .bind(run.organization_id)
        .bind(run.workspace_id)
        .bind(run.run_id)
        .fetch_one(&mut *transaction)
        .await?;
        if parent_used
            .saturating_add(child_allocated)
            .saturating_add(request.token_budget)
            > parent_token_budget
            || target
                .token_budget
                .is_some_and(|budget| request.token_budget > budget)
        {
            return Err(ChildRunCreateError::Rejected("child_token_budget_exceeded"));
        }

        let parent_remaining =
            i32::try_from(plan.remaining_runtime()?.as_secs()).unwrap_or(i32::MAX);
        if request.max_runtime_seconds > parent_remaining
            || request.max_runtime_seconds > target.max_runtime_seconds
        {
            return Err(ChildRunCreateError::Rejected(
                "child_runtime_budget_exceeded",
            ));
        }

        let title = child_session_title(&request.task);
        let child_session_id: Uuid = sqlx::query_scalar(
            "insert into sessions (
                organization_id, workspace_id, work_item_id, title, status
             ) values ($1, $2, $3, $4, 'active') returning id",
        )
        .bind(run.organization_id)
        .bind(run.workspace_id)
        .bind(parent.work_item_id)
        .bind(title)
        .fetch_one(&mut *transaction)
        .await?;
        let idempotency_key = format!("child:{}:{}", run.run_id, call.id);
        let child_run_id: Uuid = sqlx::query_scalar(
            "insert into runs (
                organization_id, workspace_id, workflow_version_id, work_item_id,
                session_id, parent_run_id, root_run_id, depth,
                token_budget_override, max_runtime_seconds_override,
                input, idempotency_key
             ) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
             returning id",
        )
        .bind(run.organization_id)
        .bind(run.workspace_id)
        .bind(request.workflow_version_id)
        .bind(parent.work_item_id)
        .bind(child_session_id)
        .bind(run.run_id)
        .bind(parent.root_run_id)
        .bind(parent.depth + 1)
        .bind(request.token_budget)
        .bind(request.max_runtime_seconds)
        .bind(json!({
            "task": request.task,
            "parent_run_id": run.run_id,
            "parent_tool_call_id": call.id,
        }))
        .bind(idempotency_key)
        .fetch_one(&mut *transaction)
        .await?;

        sqlx::query(
            "select event_id from zeus_private.append_session_event(
               $1, 'user_message', 'agent', null, $2, $3, 1::smallint
             )",
        )
        .bind(child_session_id)
        .bind(json!({ "content": request.task }))
        .bind(child_run_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "select event_id from zeus_private.append_run_event(
               $1, 'run.queued', $2, null, 1::smallint
             )",
        )
        .bind(child_run_id)
        .bind(json!({
            "parent_run_id": run.run_id,
            "parent_tool_call_id": call.id,
            "token_budget": request.token_budget,
            "max_runtime_seconds": request.max_runtime_seconds,
        }))
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "insert into run_links (
                organization_id, workspace_id, parent_run_id, child_run_id, relation
             ) values ($1, $2, $3, $4, 'child')",
        )
        .bind(run.organization_id)
        .bind(run.workspace_id)
        .bind(run.run_id)
        .bind(child_run_id)
        .execute(&mut *transaction)
        .await?;
        let affected = sqlx::query(
            "update tool_calls
             set status = 'waiting_child', child_run_id = $1, fence_token = $2
             where id = $3 and organization_id = $4 and workspace_id = $5 and run_id = $6
               and status = 'running' and fence_token = $2 and child_run_id is null",
        )
        .bind(child_run_id)
        .bind(run.fence_token)
        .bind(call.id)
        .bind(run.organization_id)
        .bind(run.workspace_id)
        .bind(run.run_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if affected != 1 {
            return Err(ChildRunCreateError::Runtime(RuntimeFailure::StaleFence));
        }
        append_run_event_in_transaction(
            &mut transaction,
            run,
            "child.started",
            json!({
                "child_run_id": child_run_id,
                "tool_call_id": call.id,
                "workflow_version_id": request.workflow_version_id,
                "token_budget": request.token_budget,
                "max_runtime_seconds": request.max_runtime_seconds,
            }),
            None,
        )
        .await?;
        sqlx::query(
            "insert into audit_events (
                organization_id, workspace_id, actor_kind, actor_id,
                action, target_type, target_id, metadata
             ) values ($1, $2, 'agent', null, 'child_run.created', 'run', $3, $4)",
        )
        .bind(run.organization_id)
        .bind(run.workspace_id)
        .bind(child_run_id)
        .bind(json!({ "parent_run_id": run.run_id, "tool_call_id": call.id }))
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(child_run_id)
    }
}
