use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use async_trait::async_trait;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use zeus_core::{ModelMessage, SessionContextBuilder};

use super::{
    DurableRunExecutor,
    events::{append_run_event_in_transaction, append_session_event},
    policy::render_system_prompt,
    types::{RunPlan, RuntimeCapability, RuntimeControl, RuntimeFailure, ToolResume},
};
use crate::{
    model::{ModelCompletion, ModelError, OpenAiCompatibleAdapter, ToolDefinition},
    supervisor::{ClaimedRun, RunExecutor, RunOutcome},
};

impl DurableRunExecutor {
    async fn run(
        &self,
        run: &ClaimedRun,
        cancellation: CancellationToken,
    ) -> Result<Value, RuntimeControl> {
        let plan = self.load_plan(run).await?;
        let deadline = plan.remaining_runtime()?;
        match tokio::time::timeout(deadline, self.run_loop(run, &plan, cancellation)).await {
            Ok(result) => result,
            Err(_) => Err(RuntimeFailure::Limit("run_timeout").into()),
        }
    }

    async fn run_loop(
        &self,
        run: &ClaimedRun,
        plan: &RunPlan,
        cancellation: CancellationToken,
    ) -> Result<Value, RuntimeControl> {
        let api_key = self.load_model_api_key(run, plan).await?;
        let adapter = OpenAiCompatibleAdapter::new(
            &plan.model_base_url,
            &plan.model,
            api_key,
            plan.model_configuration.clone(),
        )
        .map_err(RuntimeFailure::Model)?;
        let capabilities = self.load_capabilities(run, plan).await?;
        let tool_definitions = capabilities
            .iter()
            .map(RuntimeCapability::tool_definition)
            .collect::<Vec<_>>();

        self.append_run_event(
            run,
            "runtime.started",
            json!({
                "attempt_number": run.attempt_number,
                "model_profile_id": plan.model_profile_id,
                "model_profile_revision": plan.model_profile_revision,
                "model": plan.model,
            }),
            None,
        )
        .await?;

        loop {
            if cancellation.is_cancelled() {
                return Err(RuntimeControl::Canceled);
            }

            if let Some(output) = self.load_final_output(run).await? {
                return Ok(output);
            }

            match self
                .resume_open_tools(run, plan, &capabilities, &cancellation)
                .await?
            {
                ToolResume::Ready => {}
                ToolResume::WaitingApproval => return Err(RuntimeControl::WaitingApproval),
                ToolResume::WaitingChild => return Err(RuntimeControl::WaitingChild),
            }

            let completed_steps = self.completed_model_steps(run).await?;
            if completed_steps >= i64::from(plan.max_steps) {
                return Err(RuntimeFailure::Limit("max_steps_exceeded").into());
            }

            let used_tokens = self.used_tokens(run).await?;
            if plan
                .token_budget_u64()
                .is_some_and(|budget| used_tokens >= budget)
            {
                return Err(RuntimeFailure::Limit("token_budget_exhausted").into());
            }

            let events = self.load_session_events(run).await?;
            let experience = self.load_experience_context(run, plan).await?;
            let system_prompt = render_system_prompt(&plan.instructions, &experience);
            let context = SessionContextBuilder::default()
                .with_system_prompt(&system_prompt)
                .build(&events)
                .map_err(|_| RuntimeFailure::InvalidSession)?;
            let completion = self
                .complete_with_retry(
                    run,
                    &adapter,
                    context.messages(),
                    &tool_definitions,
                    plan.model_network_attempts(),
                    &cancellation,
                )
                .await?;

            self.append_usage(run, &completion).await?;
            let next_used = used_tokens.saturating_add(completion.usage.accounted_tokens());
            if plan
                .token_budget_u64()
                .is_some_and(|budget| next_used > budget)
            {
                return Err(RuntimeFailure::Limit("token_budget_exceeded").into());
            }

            let has_tool_calls = !completion.tool_calls.is_empty();
            self.persist_model_completion(run, plan, &capabilities, &completion)
                .await?;
            if !has_tool_calls {
                return Ok(json!({ "content": completion.assistant_text }));
            }
        }
    }

    async fn completed_model_steps(&self, run: &ClaimedRun) -> Result<i64, RuntimeFailure> {
        sqlx::query_scalar(
            "select count(*)::bigint
             from run_events
             where organization_id = $1 and workspace_id = $2 and run_id = $3
               and event_type = 'model.completed'",
        )
        .bind(run.organization_id)
        .bind(run.workspace_id)
        .bind(run.run_id)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    async fn complete_with_retry(
        &self,
        run: &ClaimedRun,
        adapter: &OpenAiCompatibleAdapter,
        messages: &[ModelMessage],
        tools: &[ToolDefinition],
        max_retries: u8,
        cancellation: &CancellationToken,
    ) -> Result<ModelCompletion, RuntimeControl> {
        let mut retry_count = 0_u8;
        loop {
            self.append_run_event(
                run,
                "model.requested",
                json!({ "retry_count": retry_count }),
                None,
            )
            .await?;
            match adapter.chat(messages, tools, cancellation).await {
                Ok(completion) => return Ok(completion),
                Err(ModelError::Canceled) => return Err(RuntimeControl::Canceled),
                Err(error) if error.is_transient() && retry_count < max_retries => {
                    retry_count += 1;
                    self.append_run_event(
                        run,
                        "model.retry_scheduled",
                        json!({
                            "retry_count": retry_count,
                            "error_code": RuntimeFailure::Model(error).code(),
                        }),
                        None,
                    )
                    .await?;
                    let delay =
                        Duration::from_millis(250_u64.saturating_mul(1_u64 << retry_count.min(4)));
                    tokio::select! {
                        () = cancellation.cancelled() => return Err(RuntimeControl::Canceled),
                        () = tokio::time::sleep(delay) => {}
                    }
                }
                Err(error) => return Err(RuntimeFailure::Model(error).into()),
            }
        }
    }

    async fn load_final_output(&self, run: &ClaimedRun) -> Result<Option<Value>, RuntimeFailure> {
        sqlx::query_scalar(
            "select payload -> 'output'
             from run_events
             where organization_id = $1 and workspace_id = $2 and run_id = $3
               and event_type = 'model.final'
             order by sequence desc limit 1",
        )
        .bind(run.organization_id)
        .bind(run.workspace_id)
        .bind(run.run_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    #[allow(clippy::too_many_lines)] // The event pair is validated and persisted as one operation.
    async fn persist_model_completion(
        &self,
        run: &ClaimedRun,
        plan: &RunPlan,
        capabilities: &[RuntimeCapability],
        completion: &ModelCompletion,
    ) -> Result<(), RuntimeFailure> {
        if completion.assistant_text.is_empty() && completion.tool_calls.is_empty() {
            return Err(RuntimeFailure::InvalidModelTool);
        }
        let capability_by_name = capabilities
            .iter()
            .map(|capability| (capability.model_name(), capability))
            .collect::<HashMap<_, _>>();
        let mut seen_call_ids = HashSet::new();
        for call in &completion.tool_calls {
            let Some(capability) = capability_by_name.get(&call.capability).copied() else {
                return Err(RuntimeFailure::InvalidModelTool);
            };
            if call.call_id.trim().is_empty()
                || !seen_call_ids.insert(call.call_id.as_str())
                || !call.arguments.is_object()
            {
                return Err(RuntimeFailure::InvalidModelTool);
            }
            capability
                .validate_input(&call.arguments)
                .map_err(|_| RuntimeFailure::InvalidToolInput)?;
        }

        let mut transaction = self.begin_fenced(run).await?;
        let mut assistant_event_id = None;
        if !completion.assistant_text.is_empty() {
            assistant_event_id = Some(
                append_session_event(
                    &mut transaction,
                    run,
                    "assistant_message",
                    json!({ "content": completion.assistant_text }),
                )
                .await?,
            );
        }

        for call in &completion.tool_calls {
            let capability = capability_by_name
                .get(&call.capability)
                .copied()
                .ok_or(RuntimeFailure::InvalidModelTool)?;
            let requires_approval = capability.needs_approval(&plan.approval_policy);
            let status = if requires_approval {
                "pending_approval"
            } else {
                "ready"
            };
            let idempotency_key = capability
                .supports_idempotency()
                .then(|| format!("run:{}:tool:{}", run.run_id, call.call_id));
            let tool_call_id: uuid::Uuid = sqlx::query_scalar(
                "insert into tool_calls (
                    organization_id, workspace_id, run_id, session_id, capability_id,
                    call_key, idempotency_key, fence_token, status, input
                 ) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                 returning id",
            )
            .bind(run.organization_id)
            .bind(run.workspace_id)
            .bind(run.run_id)
            .bind(run.session_id)
            .bind(capability.id)
            .bind(&call.call_id)
            .bind(idempotency_key)
            .bind(run.fence_token)
            .bind(status)
            .bind(&call.arguments)
            .fetch_one(&mut *transaction)
            .await?;
            let session_event_id = append_session_event(
                &mut transaction,
                run,
                "tool_call",
                json!({
                    "call_id": call.call_id,
                    "capability": call.capability,
                    "registry_key": capability.registry_key,
                    "arguments": call.arguments,
                    "tool_call_id": tool_call_id,
                }),
            )
            .await?;
            append_run_event_in_transaction(
                &mut transaction,
                run,
                "tool.requested",
                json!({
                    "tool_call_id": tool_call_id,
                    "call_id": call.call_id,
                    "capability_id": capability.id,
                    "registry_key": capability.registry_key,
                    "status": status,
                }),
                Some(session_event_id),
            )
            .await?;
            if requires_approval {
                sqlx::query(
                    "insert into approvals (
                        organization_id, workspace_id, run_id, tool_call_id
                     ) values ($1, $2, $3, $4)",
                )
                .bind(run.organization_id)
                .bind(run.workspace_id)
                .bind(run.run_id)
                .bind(tool_call_id)
                .execute(&mut *transaction)
                .await?;
            }
        }

        append_run_event_in_transaction(
            &mut transaction,
            run,
            "model.completed",
            json!({
                "provider_request_id": completion.provider_request_id,
                "has_text": !completion.assistant_text.is_empty(),
                "tool_call_count": completion.tool_calls.len(),
            }),
            assistant_event_id,
        )
        .await?;
        if completion.tool_calls.is_empty() {
            append_run_event_in_transaction(
                &mut transaction,
                run,
                "model.final",
                json!({ "output": { "content": completion.assistant_text } }),
                assistant_event_id,
            )
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn append_usage(
        &self,
        run: &ClaimedRun,
        completion: &ModelCompletion,
    ) -> Result<(), RuntimeFailure> {
        let prompt_tokens = i64::try_from(completion.usage.prompt_tokens)
            .map_err(|_| RuntimeFailure::InvalidConfiguration("invalid_model_usage"))?;
        let completion_tokens = i64::try_from(completion.usage.completion_tokens)
            .map_err(|_| RuntimeFailure::InvalidConfiguration("invalid_model_usage"))?;
        let cache_tokens = completion
            .usage
            .cache_read_tokens
            .saturating_add(completion.usage.cache_write_tokens);
        let cache_tokens = i64::try_from(cache_tokens)
            .map_err(|_| RuntimeFailure::InvalidConfiguration("invalid_model_usage"))?;
        sqlx::query_scalar::<_, uuid::Uuid>(
            "select zeus_private.append_run_usage($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(run.run_id)
        .bind(&completion.provider_request_id)
        .bind(prompt_tokens)
        .bind(completion_tokens)
        .bind(cache_tokens)
        .bind(&self.node_id)
        .bind(run.fence_token)
        .fetch_one(&self.pool)
        .await?;
        Ok(())
    }
}

#[async_trait]
impl RunExecutor for DurableRunExecutor {
    async fn execute(&self, run: &ClaimedRun, cancellation: CancellationToken) -> RunOutcome {
        match self.run(run, cancellation).await {
            Ok(output) => RunOutcome::Succeeded(output),
            Err(RuntimeControl::WaitingApproval) => RunOutcome::WaitingApproval,
            Err(RuntimeControl::WaitingChild) => RunOutcome::WaitingChild,
            Err(RuntimeControl::Canceled) => RunOutcome::Canceled,
            Err(RuntimeControl::Failed(failure)) => RunOutcome::Failed {
                code: failure.code().to_owned(),
                detail: failure.detail(),
            },
        }
    }
}
