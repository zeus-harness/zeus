//! Session-native durable Agent Loop persistence.
//!
//! Every external operation crosses a committed `started` checkpoint. Known
//! results and their next model request commit together; indeterminate results
//! terminate the Session turn as `needs_attention` and are never re-queued.

use super::*;
use crate::{
    AgentFinalCompletion, AgentModelClaimOutcome, AgentModelCompletion, AgentModelFailureCommit,
    AgentModelJobStatus, AgentModelResolution, AgentModelSuccessCommit, AgentReviewCommit,
    AgentReviewContext, AgentReviewResult, AgentTerminalCompletion, AgentToolCall,
    AgentToolCallSpec, AgentToolClaimOutcome, AgentToolCompletion, AgentToolCompletionCommit,
    AgentToolOutcomeUnknownCommit, AgentToolWork,
};
use ::execution::{DigestDomain, FactSource, OperationRef, Sha256Digest};
use deployment::ManifestEnvelope;
use protocol::{
    AgentApprovalReview, AgentReviewResponse, AgentToolCallDetail, AgentToolCallStatus,
    AgentTurnDetail, AgentTurnStatus, AssistantReplyKind, PolicyDecision, ReviewDecision,
    ToolExecutorStatus,
};
use workflows::{
    AgentStatus as WorkflowStatus, Command as WorkflowCommand, ExternalCall, KnownToolResult,
    ProposalDisposition, State as WorkflowState, TerminalReason, ToolCompletionKind, reduce,
};

const AGENT_ID_MAX_BYTES: usize = 384;
const AGENT_ENVIRONMENT_MAX_BYTES: usize = 64;
const AGENT_REQUEST_JSON_MAX_BYTES: usize = 512 * 1024;
const AGENT_RESPONSE_JSON_MAX_BYTES: usize = 512 * 1024;
const AGENT_ERROR_JSON_MAX_BYTES: usize = 32 * 1024;
const AGENT_TOOL_ARGUMENTS_MAX_BYTES: usize = 16 * 1024;
const AGENT_TOOL_RESULT_JSON_MAX_BYTES: usize = 64 * 1024;
const AGENT_DEPLOYMENT_MANIFEST_MAX_BYTES: usize = 256 * 1024;

impl SqliteStore {
    /// Claims one queued model step. The returned job is externally callable
    /// only because its `started` state and workflow transition have committed.
    pub async fn claim_next_agent_model(
        &self,
        current_manifest: &ManifestEnvelope,
    ) -> Result<AgentModelClaimOutcome, StorageError> {
        validate_manifest_envelope(current_manifest, "current Agent deployment manifest")?;
        let current_manifest = current_manifest.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            claim_next_agent_model(connection, &current_manifest, &physical_limits)
        })
        .await
    }

    /// Commits one trusted provider response and the next durable loop state.
    /// A final reply, tool proposal, or policy-denied continuation is wholly
    /// atomic with the model-job terminal checkpoint.
    pub async fn complete_agent_model_success(
        &self,
        commit: AgentModelSuccessCommit,
    ) -> Result<AgentModelCompletion, StorageError> {
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            complete_agent_model_success(connection, commit, &physical_limits)
        })
        .await
    }

    /// Records a known provider failure or an indeterminate started outcome.
    /// Indeterminate operations become `needs_attention` and are never queued
    /// again automatically.
    pub async fn complete_agent_model_failure(
        &self,
        commit: AgentModelFailureCommit,
    ) -> Result<AgentTerminalCompletion, StorageError> {
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            complete_agent_model_failure(connection, commit, &physical_limits)
        })
        .await
    }

    /// Claims one already-admitted tool call after persisting its sole
    /// `started` checkpoint. The returned model job is the exact transcript
    /// authority from which the continuation must be built.
    pub async fn claim_next_agent_tool(
        &self,
        current_manifest: &ManifestEnvelope,
    ) -> Result<AgentToolClaimOutcome, StorageError> {
        validate_manifest_envelope(current_manifest, "current Agent deployment manifest")?;
        let current_manifest = current_manifest.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            claim_next_agent_tool(connection, &current_manifest, &physical_limits)
        })
        .await
    }

    /// Commits a known connector result together with the next immutable model
    /// request, or terminalizes the turn when a fixed loop limit is reached.
    pub async fn complete_agent_tool(
        &self,
        commit: AgentToolCompletionCommit,
    ) -> Result<AgentToolCompletion, StorageError> {
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            complete_agent_tool(connection, commit, &physical_limits)
        })
        .await
    }

    /// Records that a started connector may have taken effect. It is never
    /// retried; the owning Session is interrupted for explicit reconciliation.
    pub async fn complete_agent_tool_outcome_unknown(
        &self,
        commit: AgentToolOutcomeUnknownCommit,
    ) -> Result<AgentTerminalCompletion, StorageError> {
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            complete_agent_tool_outcome_unknown(connection, commit, &physical_limits)
        })
        .await
    }

    /// Returns one account-scoped Agent projection for an authenticated actor.
    pub async fn agent_turn_detail_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        turn_id: &str,
    ) -> Result<AgentTurnDetail, StorageError> {
        let context = validated_authz_context(context)?;
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let turn_id = validated_durable_reference(turn_id, "turn ID")?.to_owned();
        self.with_connection(move |connection| {
            query_agent_turn_detail_for_actor(connection, &context, &session_id, &turn_id)
        })
        .await
    }

    /// Returns the exact immutable deployment manifest bound to an Agent turn.
    /// Authorization and account isolation are checked before its binding is
    /// exposed. Pre-v19 legacy turns return `None`.
    pub async fn agent_deployment_manifest_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        turn_id: &str,
    ) -> Result<Option<ManifestEnvelope>, StorageError> {
        let context = validated_authz_context(context)?;
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let turn_id = validated_durable_reference(turn_id, "turn ID")?.to_owned();
        self.with_connection(move |connection| {
            query_agent_deployment_manifest_for_actor(connection, &context, &session_id, &turn_id)
        })
        .await
    }

    /// Returns one account-scoped, point-in-time view of the immutable
    /// RunEpoch authorities and append-only execution facts for an Agent turn.
    pub async fn agent_execution_explain_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        turn_id: &str,
    ) -> Result<::execution::AgentExecutionExplain, StorageError> {
        let context = validated_authz_context(context)?;
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let turn_id = validated_durable_reference(turn_id, "turn ID")?.to_owned();
        self.with_connection(move |connection| {
            super::execution::query_agent_execution_explain_for_actor(
                connection,
                &context,
                &session_id,
                &turn_id,
            )
        })
        .await
    }

    /// Returns the exact persisted request and outcome for one model RunEpoch.
    /// Reading this evidence never grants authority to replay the operation.
    pub async fn agent_run_epoch_explain_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        turn_id: &str,
        step: u32,
    ) -> Result<::execution::AgentRunEpochExplain, StorageError> {
        let context = validated_authz_context(context)?;
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let turn_id = validated_durable_reference(turn_id, "turn ID")?.to_owned();
        self.with_connection(move |connection| {
            super::execution::query_agent_run_epoch_explain_for_actor(
                connection,
                &context,
                &session_id,
                &turn_id,
                step,
            )
        })
        .await
    }

    /// Returns the exact server-owned transcript needed to construct an owner
    /// rejection result. Authorization is checked before the call is exposed.
    pub async fn agent_review_context_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        turn_id: &str,
        call_id: &str,
    ) -> Result<AgentReviewContext, StorageError> {
        let context = validated_authz_context(context)?;
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let turn_id = validated_durable_reference(turn_id, "turn ID")?.to_owned();
        let call_id = normalized_identifier(call_id, "agent call ID")?.to_owned();
        self.with_connection(move |connection| {
            query_agent_review_context_for_actor(
                connection,
                &context,
                &session_id,
                &turn_id,
                &call_id,
            )
        })
        .await
    }

    /// Atomically records one exact owner decision, its actor-scoped receipt,
    /// and either queues the tool or queues the rejection continuation.
    pub async fn review_agent_tool_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        turn_id: &str,
        commit: AgentReviewCommit,
    ) -> Result<AgentReviewResult, StorageError> {
        let context = validated_authz_context(context)?;
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let turn_id = validated_durable_reference(turn_id, "turn ID")?.to_owned();
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            review_agent_tool_for_actor(
                connection,
                &context,
                &session_id,
                &turn_id,
                commit,
                &physical_limits,
            )
        })
        .await
    }

    /// Settles one bounded batch of process-crash prefixes. Queued work stays
    /// claimable; only already-started model/tool operations become unknown.
    pub async fn recover_started_agent_work(
        &self,
    ) -> Result<Vec<AgentTerminalCompletion>, StorageError> {
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            recover_started_agent_work(connection, &physical_limits)
        })
        .await
    }
}

fn claim_next_agent_model(
    connection: &mut Connection,
    current_manifest: &ManifestEnvelope,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<AgentModelClaimOutcome, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let job_id = transaction
        .query_row(
            r#"SELECT id FROM agent_model_jobs
               WHERE status = 'queued' ORDER BY queued_at, id LIMIT 1"#,
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let Some(job_id) = job_id else {
        transaction.commit()?;
        return Ok(AgentModelClaimOutcome::NotAvailable);
    };
    let job = query_agent_model_job_by_id(&transaction, &job_id)?;
    let mut agent = query_agent_turn(&transaction, &job.agent_id)?;
    require_open_agent_turn(&transaction, &agent)?;
    require_agent_finalization_capacity(&transaction, &agent)?;
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::ReservedProgress,
    )?;
    let timestamp = now();

    if !agent_deployment_matches_current(&transaction, &agent, Some(&job), None, current_manifest)?
    {
        let error_json = deployment_unavailable_error(
            "the bound Agent deployment manifest is missing, invalid, or changed before model execution",
        );
        let command = WorkflowCommand::DeploymentUnavailable;
        let transition = reduce(&agent.workflow_state, command.clone())
            .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?;
        persist_agent_workflow_transition(
            &transaction,
            &mut agent,
            transition.state().clone(),
            None,
            Some(&error_json),
            Some(&timestamp),
            AgentTransitionFact {
                command,
                external_call: transition.external_call().cloned(),
                emitted_result: transition.emitted_result().cloned(),
                emitted_result_digest: None,
                epoch_digest: None,
                source: FactSource::Live,
                subject: Some(model_subject(&job)),
                input_digest: Some(model_request_digest(&job)?),
                output_digest: Some(super::execution::digest_json(
                    DigestDomain::ExecutionError,
                    &error_json,
                )?),
                next_request_digest: None,
            },
            &timestamp,
        )?;
        let changed = transaction.execute(
            r#"UPDATE agent_model_jobs
               SET status = 'failed', attempt = 1, error_json = ?1,
                   started_at = ?2, finished_at = ?2
               WHERE id = ?3 AND status = 'queued' AND attempt = 0"#,
            params![serde_json::to_string(&error_json)?, timestamp, job_id],
        )?;
        if changed != 1 {
            return Err(StorageError::ConcurrentModification);
        }
        let completion = interrupt_agent_turn(
            &transaction,
            &agent,
            "agent deployment became unavailable before model execution",
        )?;
        transaction.commit()?;
        return Ok(AgentModelClaimOutcome::Rejected(Box::new(completion)));
    }

    if !agent_actor_is_authorized(&transaction, &agent)? {
        let error_json = json!({
            "code": "authorization_revoked",
            "message": "the agent initiator is no longer authorized for this Session"
        });
        let command = WorkflowCommand::AuthorizationRevoked;
        let transition = reduce(&agent.workflow_state, command.clone())
            .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?;
        persist_agent_workflow_transition(
            &transaction,
            &mut agent,
            transition.state().clone(),
            None,
            Some(&error_json),
            Some(&timestamp),
            AgentTransitionFact {
                command,
                external_call: transition.external_call().cloned(),
                emitted_result: transition.emitted_result().cloned(),
                emitted_result_digest: None,
                epoch_digest: None,
                source: FactSource::Live,
                subject: Some(model_subject(&job)),
                input_digest: Some(model_request_digest(&job)?),
                output_digest: Some(super::execution::digest_json(
                    DigestDomain::ExecutionError,
                    &error_json,
                )?),
                next_request_digest: None,
            },
            &timestamp,
        )?;
        let changed = transaction.execute(
            r#"UPDATE agent_model_jobs
               SET status = 'failed', attempt = 1, error_json = ?1,
                   started_at = ?2, finished_at = ?2
               WHERE id = ?3 AND status = 'queued' AND attempt = 0"#,
            params![serde_json::to_string(&error_json)?, timestamp, job_id],
        )?;
        if changed != 1 {
            return Err(StorageError::ConcurrentModification);
        }
        let completion = interrupt_agent_turn(
            &transaction,
            &agent,
            "agent authorization was revoked before model execution",
        )?;
        transaction.commit()?;
        return Ok(AgentModelClaimOutcome::Rejected(Box::new(completion)));
    }

    let command = WorkflowCommand::StartModel;
    let transition = reduce(&agent.workflow_state, command.clone())
        .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?;
    let epoch_digest = super::execution::insert_model_run_epoch(
        &transaction,
        &agent,
        &job,
        &current_manifest.digest,
        &timestamp,
    )?;
    persist_agent_workflow_transition(
        &transaction,
        &mut agent,
        transition.state().clone(),
        None,
        None,
        None,
        AgentTransitionFact {
            command,
            external_call: transition.external_call().cloned(),
            emitted_result: transition.emitted_result().cloned(),
            emitted_result_digest: None,
            epoch_digest: Some(epoch_digest),
            source: FactSource::Live,
            subject: Some(model_subject(&job)),
            input_digest: Some(model_request_digest(&job)?),
            output_digest: None,
            next_request_digest: None,
        },
        &timestamp,
    )?;
    let changed = transaction.execute(
        r#"UPDATE agent_model_jobs
           SET status = 'started', attempt = 1, started_at = ?1
           WHERE id = ?2 AND status = 'queued' AND attempt = 0"#,
        params![timestamp, job_id],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    let claimed = query_agent_model_job_by_id(&transaction, &job_id)?;
    transaction.commit()?;
    Ok(AgentModelClaimOutcome::Claimed(Box::new(claimed)))
}

fn complete_agent_model_success(
    connection: &mut Connection,
    commit: AgentModelSuccessCommit,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<AgentModelCompletion, StorageError> {
    normalized_reply_value(&commit.job_id, "agent model job ID")?;
    validate_reply_json(
        &commit.response_json,
        "agent model response JSON",
        AGENT_RESPONSE_JSON_MAX_BYTES,
    )?;
    validate_agent_model_resolution(&commit.resolution)?;

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let job = query_agent_model_job_by_id(&transaction, &commit.job_id)?;
    let mut agent = query_agent_turn(&transaction, &job.agent_id)?;
    validate_agent_response_matches_job(&job, &commit.response_json, &commit.resolution)?;
    if job.status != AgentModelJobStatus::Started {
        let replay = replay_agent_model_success(&transaction, &job, &agent, &commit)?;
        transaction.commit()?;
        return Ok(replay);
    }
    if agent.status != AgentTurnStatus::ModelRunning || agent.model_steps != job.step {
        return Err(StorageError::InvalidAgentTransition(
            "agent model completion does not match the started workflow step".into(),
        ));
    }
    require_open_agent_turn(&transaction, &agent)?;
    require_agent_finalization_capacity(&transaction, &agent)?;
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Finalization,
    )?;

    let timestamp = now();
    let epoch_digest =
        super::execution::epoch_digest_for_operation(&transaction, "model", &job.id)?;
    let input_digest = model_request_digest(&job)?;
    let output_digest =
        super::execution::digest_json(DigestDomain::ModelResponse, &commit.response_json)?;
    let completion = match &commit.resolution {
        AgentModelResolution::Final {
            assistant_message,
            provenance,
        } => {
            let command = WorkflowCommand::ModelFinal {
                content_bytes: usize_to_u64(assistant_message.len(), "agent final message bytes")?,
            };
            let transition = reduce(&agent.workflow_state, command.clone())
                .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?;
            persist_agent_workflow_transition(
                &transaction,
                &mut agent,
                transition.state().clone(),
                None,
                None,
                Some(&timestamp),
                AgentTransitionFact {
                    command,
                    external_call: transition.external_call().cloned(),
                    emitted_result: transition.emitted_result().cloned(),
                    emitted_result_digest: None,
                    epoch_digest: Some(epoch_digest.clone()),
                    source: FactSource::Live,
                    subject: Some(model_subject(&job)),
                    input_digest: Some(input_digest.clone()),
                    output_digest: Some(output_digest.clone()),
                    next_request_digest: None,
                },
                &timestamp,
            )?;
            finish_agent_model_job_success(&transaction, &job, &commit.response_json, &timestamp)?;
            AgentModelCompletion::Final(Box::new(finalize_agent_success(
                &transaction,
                &agent,
                assistant_message,
                provenance,
                &timestamp,
            )?))
        }
        AgentModelResolution::ToolCall { call } => {
            let disposition = proposal_disposition(call.policy_decision.clone(), None)?;
            let command = WorkflowCommand::ModelToolProposal { disposition };
            let transition = reduce(&agent.workflow_state, command.clone())
                .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?;
            let proposed = transition.state().clone();
            if proposed.status() == WorkflowStatus::Failed {
                let error_json = workflow_terminal_error_for_resolution(
                    &proposed,
                    &commit.resolution,
                    &commit.response_json,
                )?;
                persist_agent_workflow_transition(
                    &transaction,
                    &mut agent,
                    proposed,
                    None,
                    Some(&error_json),
                    Some(&timestamp),
                    AgentTransitionFact {
                        command,
                        external_call: transition.external_call().cloned(),
                        emitted_result: transition.emitted_result().cloned(),
                        emitted_result_digest: None,
                        epoch_digest: Some(epoch_digest.clone()),
                        source: FactSource::Live,
                        subject: Some(model_subject(&job)),
                        input_digest: Some(input_digest.clone()),
                        output_digest: Some(output_digest.clone()),
                        next_request_digest: None,
                    },
                    &timestamp,
                )?;
                finish_agent_model_job_success(
                    &transaction,
                    &job,
                    &commit.response_json,
                    &timestamp,
                )?;
                AgentModelCompletion::Terminal(Box::new(interrupt_agent_turn(
                    &transaction,
                    &agent,
                    "agent loop rejected a model tool proposal at its fixed limit",
                )?))
            } else {
                let call_status = match call.policy_decision {
                    PolicyDecision::Allow => AgentToolCallStatus::Queued,
                    PolicyDecision::RequireApproval => AgentToolCallStatus::WaitingApproval,
                    PolicyDecision::Deny => {
                        return Err(StorageError::InvalidAgentTransition(
                            "a denied tool proposal requires a structured continuation result"
                                .into(),
                        ));
                    }
                };
                persist_agent_workflow_transition(
                    &transaction,
                    &mut agent,
                    proposed,
                    Some(&call.call_id),
                    None,
                    None,
                    AgentTransitionFact {
                        command,
                        external_call: transition.external_call().cloned(),
                        emitted_result: transition.emitted_result().cloned(),
                        emitted_result_digest: None,
                        epoch_digest: Some(epoch_digest.clone()),
                        source: FactSource::Live,
                        subject: Some(model_subject(&job)),
                        input_digest: Some(input_digest.clone()),
                        output_digest: Some(output_digest.clone()),
                        next_request_digest: None,
                    },
                    &timestamp,
                )?;
                let stored_call = insert_agent_tool_call(
                    &transaction,
                    &agent,
                    &job,
                    call,
                    call_status,
                    None,
                    &timestamp,
                )?;
                finish_agent_model_job_success(
                    &transaction,
                    &job,
                    &commit.response_json,
                    &timestamp,
                )?;
                AgentModelCompletion::ToolCall {
                    agent: Box::new(agent),
                    call: Box::new(stored_call),
                }
            }
        }
        AgentModelResolution::PolicyDenied {
            call,
            result_json,
            next_request_json,
        } => {
            let result_bytes = validate_agent_tool_result(result_json)?;
            let command = WorkflowCommand::ModelToolProposal {
                disposition: proposal_disposition(
                    call.policy_decision.clone(),
                    Some(result_bytes),
                )?,
            };
            let transition = reduce(&agent.workflow_state, command.clone())
                .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?;
            let proposed = transition.state().clone();
            if proposed.status() == WorkflowStatus::Failed {
                let result_limit =
                    proposed.terminal_reason() == Some(TerminalReason::ToolResultBytesLimitReached);
                let error_json = workflow_terminal_error_for_resolution(
                    &proposed,
                    &commit.resolution,
                    &commit.response_json,
                )?;
                persist_agent_workflow_transition(
                    &transaction,
                    &mut agent,
                    proposed,
                    None,
                    Some(&error_json),
                    Some(&timestamp),
                    AgentTransitionFact {
                        command,
                        external_call: transition.external_call().cloned(),
                        emitted_result: transition.emitted_result().cloned(),
                        emitted_result_digest: None,
                        epoch_digest: Some(epoch_digest.clone()),
                        source: FactSource::Live,
                        subject: Some(model_subject(&job)),
                        input_digest: Some(input_digest.clone()),
                        output_digest: Some(output_digest.clone()),
                        next_request_digest: None,
                    },
                    &timestamp,
                )?;
                if result_limit {
                    insert_agent_tool_call(
                        &transaction,
                        &agent,
                        &job,
                        call,
                        AgentToolCallStatus::NotDispatched,
                        Some(result_json),
                        &timestamp,
                    )?;
                }
                finish_agent_model_job_success(
                    &transaction,
                    &job,
                    &commit.response_json,
                    &timestamp,
                )?;
                AgentModelCompletion::Terminal(Box::new(interrupt_agent_turn(
                    &transaction,
                    &agent,
                    "agent loop rejected a policy-denied tool proposal at its fixed limit",
                )?))
            } else {
                let primary_state = proposed;
                let ContinuationSettlement {
                    state: settled,
                    next_request: continuation_request,
                    transition: settlement_transition,
                } = settle_known_result_continuation(
                    primary_state.clone(),
                    next_request_json.as_ref(),
                    "agent continuation request JSON",
                )?;
                let continuation_unavailable =
                    settled.terminal_reason() == Some(TerminalReason::ContinuationUnavailable);
                let terminal_error = if settled.status() == WorkflowStatus::Failed {
                    Some(workflow_terminal_error_for_resolution(
                        &settled,
                        &commit.resolution,
                        &commit.response_json,
                    )?)
                } else {
                    None
                };
                persist_agent_workflow_transition(
                    &transaction,
                    &mut agent,
                    primary_state,
                    None,
                    None,
                    None,
                    AgentTransitionFact {
                        command,
                        external_call: transition.external_call().cloned(),
                        emitted_result: transition.emitted_result().cloned(),
                        emitted_result_digest: Some(super::execution::digest_json(
                            DigestDomain::ToolResult,
                            result_json,
                        )?),
                        epoch_digest: Some(epoch_digest.clone()),
                        source: FactSource::Live,
                        subject: Some(model_subject(&job)),
                        input_digest: Some(input_digest.clone()),
                        output_digest: Some(output_digest.clone()),
                        next_request_digest: continuation_request
                            .map(|request| {
                                super::execution::digest_json(DigestDomain::ModelRequest, request)
                            })
                            .transpose()?,
                    },
                    &timestamp,
                )?;
                if let Some((settlement_command, settlement_transition)) = settlement_transition {
                    persist_agent_workflow_transition(
                        &transaction,
                        &mut agent,
                        settled,
                        None,
                        terminal_error.as_ref(),
                        terminal_error.as_ref().map(|_| timestamp.as_str()),
                        AgentTransitionFact {
                            command: settlement_command,
                            external_call: settlement_transition.external_call().cloned(),
                            emitted_result: settlement_transition.emitted_result().cloned(),
                            emitted_result_digest: None,
                            epoch_digest: None,
                            source: FactSource::Live,
                            subject: None,
                            input_digest: None,
                            output_digest: None,
                            next_request_digest: None,
                        },
                        &timestamp,
                    )?;
                }
                let stored_call = insert_agent_tool_call(
                    &transaction,
                    &agent,
                    &job,
                    call,
                    AgentToolCallStatus::NotDispatched,
                    Some(result_json),
                    &timestamp,
                )?;
                finish_agent_model_job_success(
                    &transaction,
                    &job,
                    &commit.response_json,
                    &timestamp,
                )?;
                if let Some(continuation_request) = continuation_request {
                    insert_continuation_model_job(
                        &transaction,
                        &agent,
                        continuation_request,
                        &timestamp,
                    )?;
                    AgentModelCompletion::ToolCall {
                        agent: Box::new(agent),
                        call: Box::new(stored_call),
                    }
                } else {
                    AgentModelCompletion::Terminal(Box::new(interrupt_agent_turn(
                        &transaction,
                        &agent,
                        if continuation_unavailable {
                            "agent policy denial is known but its model continuation is unavailable"
                        } else {
                            "agent loop reached its model or tool-result limit"
                        },
                    )?))
                }
            }
        }
    };
    transaction.commit()?;
    Ok(completion)
}

fn complete_agent_model_failure(
    connection: &mut Connection,
    commit: AgentModelFailureCommit,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<AgentTerminalCompletion, StorageError> {
    normalized_reply_value(&commit.job_id, "agent model job ID")?;
    validate_agent_error_json(&commit.error_json, "agent model error JSON")?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let job = query_agent_model_job_by_id(&transaction, &commit.job_id)?;
    let mut agent = query_agent_turn(&transaction, &job.agent_id)?;
    if job.status != AgentModelJobStatus::Started {
        let expected = if commit.outcome_unknown {
            AgentModelJobStatus::OutcomeUnknown
        } else {
            AgentModelJobStatus::Failed
        };
        if job.status != expected || job.error_json.as_ref() != Some(&commit.error_json) {
            return Err(StorageError::InvalidAgentTransition(
                "agent model completion conflicts with its durable terminal state".into(),
            ));
        }
        let replay = query_agent_terminal_completion(&transaction, &agent)?;
        transaction.commit()?;
        return Ok(replay);
    }
    if agent.status != AgentTurnStatus::ModelRunning || agent.model_steps != job.step {
        return Err(StorageError::InvalidAgentTransition(
            "agent model failure does not match the started workflow step".into(),
        ));
    }
    require_open_agent_turn(&transaction, &agent)?;
    require_agent_finalization_capacity(&transaction, &agent)?;
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Finalization,
    )?;
    let command = if commit.outcome_unknown {
        WorkflowCommand::ModelOutcomeUnknown
    } else {
        WorkflowCommand::ModelFailed
    };
    let transition = reduce(&agent.workflow_state, command.clone())
        .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?;
    let timestamp = now();
    let epoch_digest =
        super::execution::epoch_digest_for_operation(&transaction, "model", &job.id)?;
    persist_agent_workflow_transition(
        &transaction,
        &mut agent,
        transition.state().clone(),
        None,
        Some(&commit.error_json),
        Some(&timestamp),
        AgentTransitionFact {
            command,
            external_call: transition.external_call().cloned(),
            emitted_result: transition.emitted_result().cloned(),
            emitted_result_digest: None,
            epoch_digest: Some(epoch_digest),
            source: FactSource::Live,
            subject: Some(model_subject(&job)),
            input_digest: Some(model_request_digest(&job)?),
            output_digest: Some(super::execution::digest_json(
                DigestDomain::ExecutionError,
                &commit.error_json,
            )?),
            next_request_digest: None,
        },
        &timestamp,
    )?;
    let status = if commit.outcome_unknown {
        "outcome_unknown"
    } else {
        "failed"
    };
    let changed = transaction.execute(
        r#"UPDATE agent_model_jobs
           SET status = ?1, error_json = ?2, finished_at = ?3
           WHERE id = ?4 AND status = 'started' AND attempt = 1"#,
        params![
            status,
            serde_json::to_string(&commit.error_json)?,
            timestamp,
            job.id,
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    let reason = if commit.outcome_unknown {
        "agent model outcome is unknown"
    } else {
        "agent model provider failed"
    };
    let completion = interrupt_agent_turn(&transaction, &agent, reason)?;
    transaction.commit()?;
    Ok(completion)
}

fn claim_next_agent_tool(
    connection: &mut Connection,
    current_manifest: &ManifestEnvelope,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<AgentToolClaimOutcome, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let call_id = transaction
        .query_row(
            r#"SELECT call_id FROM agent_tool_calls
               WHERE status = 'queued' ORDER BY created_at, call_id LIMIT 1"#,
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let Some(call_id) = call_id else {
        transaction.commit()?;
        return Ok(AgentToolClaimOutcome::NotAvailable);
    };
    let call = query_agent_tool_call(&transaction, &call_id)?;
    let mut agent = query_agent_turn(&transaction, &call.agent_id)?;
    let model_job = query_agent_model_job(&transaction, &call.agent_id, call.model_step)?;
    validate_persisted_agent_model_tool_response(&model_job, &call)?;
    require_open_agent_turn(&transaction, &agent)?;
    require_agent_finalization_capacity(&transaction, &agent)?;
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::ReservedProgress,
    )?;
    if agent.status != AgentTurnStatus::ToolQueued
        || agent.pending_call_id.as_deref() != Some(call.call_id.as_str())
    {
        return Err(StorageError::InvalidAgentTransition(
            "queued agent tool does not match the current loop state".into(),
        ));
    }
    let timestamp = now();
    if !agent_deployment_matches_current(
        &transaction,
        &agent,
        Some(&model_job),
        Some(&call),
        current_manifest,
    )? {
        let error_json = deployment_unavailable_error(
            "the bound Agent deployment manifest is missing, invalid, or changed before tool execution",
        );
        let command = WorkflowCommand::DeploymentUnavailable;
        let transition = reduce(&agent.workflow_state, command.clone())
            .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?;
        persist_agent_workflow_transition(
            &transaction,
            &mut agent,
            transition.state().clone(),
            None,
            Some(&error_json),
            Some(&timestamp),
            AgentTransitionFact {
                command,
                external_call: transition.external_call().cloned(),
                emitted_result: transition.emitted_result().cloned(),
                emitted_result_digest: None,
                epoch_digest: None,
                source: FactSource::Live,
                subject: Some(tool_subject(&call)),
                input_digest: Some(tool_input_digest(&call)?),
                output_digest: Some(super::execution::digest_json(
                    DigestDomain::ExecutionError,
                    &error_json,
                )?),
                next_request_digest: None,
            },
            &timestamp,
        )?;
        let changed = transaction.execute(
            r#"UPDATE agent_tool_calls
               SET status = 'not_dispatched', result_json = ?1, finished_at = ?2
               WHERE call_id = ?3 AND status = 'queued'"#,
            params![serde_json::to_string(&error_json)?, timestamp, call.call_id],
        )?;
        if changed != 1 {
            return Err(StorageError::ConcurrentModification);
        }
        let completion = interrupt_agent_turn(
            &transaction,
            &agent,
            "agent deployment became unavailable before tool execution",
        )?;
        transaction.commit()?;
        return Ok(AgentToolClaimOutcome::Rejected(Box::new(completion)));
    }
    let initiator_authorized = agent_actor_is_authorized(&transaction, &agent)?;
    let approver_authorized = agent_tool_approver_is_authorized(&transaction, &call)?;
    if !initiator_authorized || !approver_authorized {
        let error_json = json!({
            "code": "authorization_revoked",
            "message": "the initiating or approving authority was revoked before tool execution"
        });
        let command = WorkflowCommand::AuthorizationRevoked;
        let transition = reduce(&agent.workflow_state, command.clone())
            .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?;
        persist_agent_workflow_transition(
            &transaction,
            &mut agent,
            transition.state().clone(),
            None,
            Some(&error_json),
            Some(&timestamp),
            AgentTransitionFact {
                command,
                external_call: transition.external_call().cloned(),
                emitted_result: transition.emitted_result().cloned(),
                emitted_result_digest: None,
                epoch_digest: None,
                source: FactSource::Live,
                subject: Some(tool_subject(&call)),
                input_digest: Some(tool_input_digest(&call)?),
                output_digest: Some(super::execution::digest_json(
                    DigestDomain::ExecutionError,
                    &error_json,
                )?),
                next_request_digest: None,
            },
            &timestamp,
        )?;
        let changed = transaction.execute(
            r#"UPDATE agent_tool_calls
               SET status = 'not_dispatched', result_json = ?1, finished_at = ?2
               WHERE call_id = ?3 AND status = 'queued'"#,
            params![serde_json::to_string(&error_json)?, timestamp, call.call_id],
        )?;
        if changed != 1 {
            return Err(StorageError::ConcurrentModification);
        }
        let completion = interrupt_agent_turn(
            &transaction,
            &agent,
            "agent tool authorization was revoked before execution",
        )?;
        transaction.commit()?;
        return Ok(AgentToolClaimOutcome::Rejected(Box::new(completion)));
    }
    let command = WorkflowCommand::StartTool;
    let transition = reduce(&agent.workflow_state, command.clone())
        .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?;
    let epoch_digest = super::execution::insert_tool_run_epoch(
        &transaction,
        &agent,
        &call,
        &current_manifest.digest,
        &timestamp,
    )?;
    persist_agent_workflow_transition(
        &transaction,
        &mut agent,
        transition.state().clone(),
        Some(&call.call_id),
        None,
        None,
        AgentTransitionFact {
            command,
            external_call: transition.external_call().cloned(),
            emitted_result: transition.emitted_result().cloned(),
            emitted_result_digest: None,
            epoch_digest: Some(epoch_digest),
            source: FactSource::Live,
            subject: Some(tool_subject(&call)),
            input_digest: Some(tool_input_digest(&call)?),
            output_digest: None,
            next_request_digest: None,
        },
        &timestamp,
    )?;
    let changed = transaction.execute(
        r#"UPDATE agent_tool_calls
           SET status = 'started', started_at = ?1
           WHERE call_id = ?2 AND status = 'queued'"#,
        params![timestamp, call.call_id],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    let work = AgentToolWork {
        call: query_agent_tool_call(&transaction, &call_id)?,
        model_job,
    };
    transaction.commit()?;
    Ok(AgentToolClaimOutcome::Claimed(Box::new(work)))
}

fn complete_agent_tool(
    connection: &mut Connection,
    commit: AgentToolCompletionCommit,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<AgentToolCompletion, StorageError> {
    normalized_identifier(&commit.call_id, "agent call ID")?;
    let result_bytes = validate_agent_tool_result(&commit.result_json)?;
    if let Some(next_request_json) = commit.next_request_json.as_ref() {
        validate_reply_json(
            next_request_json,
            "agent continuation request JSON",
            AGENT_REQUEST_JSON_MAX_BYTES,
        )?;
    }
    let completion_kind = tool_completion_kind(&commit.status)?;
    if let Some(request_id) = &commit.provider_request_id {
        normalized_account_value(
            request_id,
            "agent provider request ID",
            DISPATCH_IDENTIFIER_MAX_BYTES,
        )?;
    }
    let completion_next_request_json = commit
        .next_request_json
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?
        .unwrap_or_else(|| "null".into());
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let call = query_agent_tool_call(&transaction, &commit.call_id)?;
    let mut agent = query_agent_turn(&transaction, &call.agent_id)?;
    if call.status != AgentToolCallStatus::Running {
        let replay = replay_agent_tool_completion(&transaction, &call, &agent, &commit)?;
        transaction.commit()?;
        return Ok(replay);
    }
    if agent.status != AgentTurnStatus::ToolRunning
        || agent.pending_call_id.as_deref() != Some(call.call_id.as_str())
    {
        return Err(StorageError::InvalidAgentTransition(
            "agent tool completion does not match the started loop state".into(),
        ));
    }
    require_open_agent_turn(&transaction, &agent)?;
    require_agent_finalization_capacity(&transaction, &agent)?;
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Finalization,
    )?;
    let command = WorkflowCommand::ToolResultKnown {
        kind: completion_kind,
        result_bytes,
    };
    let transition = reduce(&agent.workflow_state, command.clone())
        .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?;
    let primary_state = transition.state().clone();
    let ContinuationSettlement {
        state: settled,
        next_request: continuation_request,
        transition: settlement_transition,
    } = settle_known_result_continuation(
        transition.state().clone(),
        commit.next_request_json.as_ref(),
        "agent continuation request JSON",
    )?;
    let continuation_unavailable =
        settled.terminal_reason() == Some(TerminalReason::ContinuationUnavailable);
    let timestamp = now();
    let terminal_error =
        (settled.status() == WorkflowStatus::Failed).then(|| workflow_terminal_error(&settled));
    let epoch_digest =
        super::execution::epoch_digest_for_operation(&transaction, "tool", &call.call_id)?;
    let primary_terminal_error = settlement_transition
        .is_none()
        .then_some(terminal_error.as_ref())
        .flatten();
    persist_agent_workflow_transition(
        &transaction,
        &mut agent,
        primary_state,
        None,
        primary_terminal_error,
        primary_terminal_error.map(|_| timestamp.as_str()),
        AgentTransitionFact {
            command,
            external_call: transition.external_call().cloned(),
            emitted_result: transition.emitted_result().cloned(),
            emitted_result_digest: None,
            epoch_digest: Some(epoch_digest),
            source: FactSource::Live,
            subject: Some(tool_subject(&call)),
            input_digest: Some(tool_input_digest(&call)?),
            output_digest: Some(super::execution::digest_json(
                DigestDomain::ToolResult,
                &commit.result_json,
            )?),
            next_request_digest: continuation_request
                .map(|request| super::execution::digest_json(DigestDomain::ModelRequest, request))
                .transpose()?,
        },
        &timestamp,
    )?;
    if let Some((settlement_command, settlement_transition)) = settlement_transition {
        persist_agent_workflow_transition(
            &transaction,
            &mut agent,
            settled,
            None,
            terminal_error.as_ref(),
            terminal_error.as_ref().map(|_| timestamp.as_str()),
            AgentTransitionFact {
                command: settlement_command,
                external_call: settlement_transition.external_call().cloned(),
                emitted_result: settlement_transition.emitted_result().cloned(),
                emitted_result_digest: None,
                epoch_digest: None,
                source: FactSource::Live,
                subject: None,
                input_digest: None,
                output_digest: None,
                next_request_digest: None,
            },
            &timestamp,
        )?;
    }
    let changed = transaction.execute(
        r#"UPDATE agent_tool_calls
           SET status = ?1, result_json = ?2, provider_request_id = ?3,
               completion_next_request_json = ?4, finished_at = ?5
           WHERE call_id = ?6 AND status = 'started'"#,
        params![
            agent_tool_status_to_db(&commit.status),
            serde_json::to_string(&commit.result_json)?,
            commit.provider_request_id,
            completion_next_request_json,
            timestamp,
            call.call_id,
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    let completion = if let Some(continuation_request) = continuation_request {
        let job =
            insert_continuation_model_job(&transaction, &agent, continuation_request, &timestamp)?;
        AgentToolCompletion::ModelQueued {
            agent: Box::new(agent),
            job: Box::new(job),
        }
    } else {
        AgentToolCompletion::Terminal(Box::new(interrupt_agent_turn(
            &transaction,
            &agent,
            if continuation_unavailable {
                "agent tool result is known but its model continuation is unavailable"
            } else {
                "agent loop reached its model or tool-result limit"
            },
        )?))
    };
    transaction.commit()?;
    Ok(completion)
}

fn complete_agent_tool_outcome_unknown(
    connection: &mut Connection,
    commit: AgentToolOutcomeUnknownCommit,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<AgentTerminalCompletion, StorageError> {
    normalized_identifier(&commit.call_id, "agent call ID")?;
    validate_agent_error_json(&commit.error_json, "agent tool unknown-outcome JSON")?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let call = query_agent_tool_call(&transaction, &commit.call_id)?;
    let mut agent = query_agent_turn(&transaction, &call.agent_id)?;
    if call.status != AgentToolCallStatus::Running {
        if call.status != AgentToolCallStatus::OutcomeUnknown
            || call.result_json.as_ref() != Some(&commit.error_json)
        {
            return Err(StorageError::InvalidAgentTransition(
                "agent tool unknown outcome conflicts with its durable state".into(),
            ));
        }
        let replay = query_agent_terminal_completion(&transaction, &agent)?;
        transaction.commit()?;
        return Ok(replay);
    }
    if agent.status != AgentTurnStatus::ToolRunning
        || agent.pending_call_id.as_deref() != Some(call.call_id.as_str())
    {
        return Err(StorageError::InvalidAgentTransition(
            "agent tool unknown outcome does not match the started loop state".into(),
        ));
    }
    require_open_agent_turn(&transaction, &agent)?;
    require_agent_finalization_capacity(&transaction, &agent)?;
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Finalization,
    )?;
    let command = WorkflowCommand::ToolOutcomeUnknown;
    let transition = reduce(&agent.workflow_state, command.clone())
        .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?;
    let timestamp = now();
    let epoch_digest =
        super::execution::epoch_digest_for_operation(&transaction, "tool", &call.call_id)?;
    persist_agent_workflow_transition(
        &transaction,
        &mut agent,
        transition.state().clone(),
        None,
        Some(&commit.error_json),
        Some(&timestamp),
        AgentTransitionFact {
            command,
            external_call: transition.external_call().cloned(),
            emitted_result: transition.emitted_result().cloned(),
            emitted_result_digest: None,
            epoch_digest: Some(epoch_digest),
            source: FactSource::Live,
            subject: Some(tool_subject(&call)),
            input_digest: Some(tool_input_digest(&call)?),
            output_digest: Some(super::execution::digest_json(
                DigestDomain::ExecutionError,
                &commit.error_json,
            )?),
            next_request_digest: None,
        },
        &timestamp,
    )?;
    let changed = transaction.execute(
        r#"UPDATE agent_tool_calls
           SET status = 'outcome_unknown', result_json = ?1, finished_at = ?2
           WHERE call_id = ?3 AND status = 'started'"#,
        params![
            serde_json::to_string(&commit.error_json)?,
            timestamp,
            call.call_id
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    let completion = interrupt_agent_turn(
        &transaction,
        &agent,
        "agent tool outcome is unknown and requires reconciliation",
    )?;
    transaction.commit()?;
    Ok(completion)
}

fn validate_agent_model_resolution(resolution: &AgentModelResolution) -> Result<(), StorageError> {
    match resolution {
        AgentModelResolution::Final {
            assistant_message,
            provenance,
        } => {
            validate_message(assistant_message, "agent assistant message")?;
            validate_reply_provenance(provenance)
        }
        AgentModelResolution::ToolCall { call } => {
            validate_agent_tool_call_spec(call)?;
            if call.policy_decision == PolicyDecision::Deny {
                return Err(StorageError::InvalidAgentTransition(
                    "a denied tool proposal must include its structured result".into(),
                ));
            }
            Ok(())
        }
        AgentModelResolution::PolicyDenied {
            call,
            result_json,
            next_request_json,
        } => {
            validate_agent_tool_call_spec(call)?;
            if call.policy_decision != PolicyDecision::Deny {
                return Err(StorageError::InvalidAgentTransition(
                    "a policy-denied result must bind a denied tool call".into(),
                ));
            }
            validate_agent_tool_result(result_json)?;
            match next_request_json {
                Some(next_request_json) => validate_reply_json(
                    next_request_json,
                    "agent continuation request JSON",
                    AGENT_REQUEST_JSON_MAX_BYTES,
                ),
                None => Ok(()),
            }
        }
    }
}

fn validate_agent_response_envelope<'a>(
    job: &AgentModelJob,
    response: &'a Value,
) -> Result<&'a serde_json::Map<String, Value>, StorageError> {
    let object = response.as_object().ok_or_else(|| {
        StorageError::InvalidAgentTransition("agent model response must be an object".into())
    })?;
    if object.len() != 3 || !object.contains_key("finish_reason") {
        return Err(StorageError::InvalidAgentTransition(
            "agent model response must use the typed provider response shape".into(),
        ));
    }
    match object.get("finish_reason") {
        Some(Value::Null) => {}
        Some(Value::String(reason)) => protocol::validate_reply_finish_reason(reason)
            .map_err(|error| invalid_resource_envelope("agent finish reason", error))?,
        _ => {
            return Err(StorageError::InvalidAgentTransition(
                "agent finish reason must be a string or null".into(),
            ));
        }
    }
    let provider = object
        .get("provider")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            StorageError::InvalidAgentTransition(
                "agent model response is missing provider metadata".into(),
            )
        })?;
    if provider.len() != 3
        || provider.get("provider_id").and_then(Value::as_str) != Some(job.provider_name.as_str())
        || !matches!(provider.get("reply_kind"), Some(Value::String(_)))
    {
        return Err(StorageError::InvalidAgentTransition(
            "agent model response provider does not match its durable job".into(),
        ));
    }
    let model_matches = match (&job.model_name, provider.get("model")) {
        (Some(expected), Some(Value::String(actual))) => expected == actual,
        (None, Some(Value::Null)) => true,
        _ => false,
    };
    if !model_matches {
        return Err(StorageError::InvalidAgentTransition(
            "agent model response model does not match its durable job".into(),
        ));
    }
    let expected_kind = if job.model_name.is_some() {
        "model"
    } else {
        "non_model_fallback"
    };
    if provider.get("reply_kind").and_then(Value::as_str) != Some(expected_kind) {
        return Err(StorageError::InvalidAgentTransition(
            "agent model response kind does not match its durable job".into(),
        ));
    }
    object
        .get("output")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            StorageError::InvalidAgentTransition("agent model output must be typed".into())
        })
}

fn validate_agent_tool_response_output(
    output: &serde_json::Map<String, Value>,
    provider_call_id: &str,
    tool_name: &str,
    arguments_json: &Value,
) -> Result<(), StorageError> {
    let provider_call = output.get("call").and_then(Value::as_object);
    if output.len() != 2
        || output.get("type").and_then(Value::as_str) != Some("tool_call")
        || provider_call.map(serde_json::Map::len) != Some(3)
        || provider_call
            .and_then(|call| call.get("id"))
            .and_then(Value::as_str)
            != Some(provider_call_id)
        || provider_call
            .and_then(|call| call.get("name"))
            .and_then(Value::as_str)
            != Some(tool_name)
        || provider_call.and_then(|call| call.get("arguments")) != Some(arguments_json)
    {
        return Err(StorageError::InvalidAgentTransition(
            "agent tool response disagrees with its server-resolved call".into(),
        ));
    }
    Ok(())
}

fn validate_agent_response_matches_job(
    job: &AgentModelJob,
    response: &Value,
    resolution: &AgentModelResolution,
) -> Result<(), StorageError> {
    let output = validate_agent_response_envelope(job, response)?;
    match resolution {
        AgentModelResolution::Final {
            assistant_message,
            provenance,
        } => {
            if output.len() != 2
                || output.get("type").and_then(Value::as_str) != Some("final")
                || output.get("content").and_then(Value::as_str) != Some(assistant_message.as_str())
                || provenance.provider_id != job.provider_name
                || provenance.model != job.model_name
            {
                return Err(StorageError::InvalidAgentTransition(
                    "agent final response disagrees with its durable resolution".into(),
                ));
            }
        }
        AgentModelResolution::ToolCall { call }
        | AgentModelResolution::PolicyDenied { call, .. } => {
            validate_agent_tool_response_output(
                output,
                &call.provider_call_id,
                &call.tool_name,
                &call.arguments_json,
            )?;
        }
    }
    Ok(())
}

pub(super) fn validate_persisted_agent_model_final_response(
    job: &AgentModelJob,
    content_bytes: u64,
) -> Result<(), StorageError> {
    let response = job.response_json.as_ref().ok_or_else(|| {
        StorageError::CorruptData(format!(
            "Agent model job `{}` is missing its successful response",
            job.id
        ))
    })?;
    let output = validate_agent_response_envelope(job, response)?;
    let actual_content_bytes = output
        .get("content")
        .and_then(Value::as_str)
        .map(str::len)
        .and_then(|length| u64::try_from(length).ok());
    if output.len() != 2
        || output.get("type").and_then(Value::as_str) != Some("final")
        || actual_content_bytes != Some(content_bytes)
    {
        return Err(StorageError::CorruptData(format!(
            "Agent model job `{}` final response shape is invalid",
            job.id
        )));
    }
    Ok(())
}

pub(super) fn validate_persisted_agent_model_tool_response(
    job: &AgentModelJob,
    call: &AgentToolCall,
) -> Result<(), StorageError> {
    let response = job.response_json.as_ref().ok_or_else(|| {
        StorageError::CorruptData(format!(
            "Agent model job `{}` is missing its successful response",
            job.id
        ))
    })?;
    let output = validate_agent_response_envelope(job, response).map_err(|error| {
        StorageError::CorruptData(format!(
            "Agent model job `{}` response envelope is invalid: {error}",
            job.id
        ))
    })?;
    validate_agent_tool_response_output(
        output,
        &call.provider_call_id,
        &call.tool_name,
        &call.arguments_json,
    )
    .map_err(|_| {
        StorageError::CorruptData(format!(
            "Agent model job `{}` response disagrees with tool call `{}`",
            job.id, call.call_id
        ))
    })
}

pub(super) fn validate_persisted_agent_model_tool_response_shape(
    job: &AgentModelJob,
) -> Result<(), StorageError> {
    let response = job.response_json.as_ref().ok_or_else(|| {
        StorageError::CorruptData(format!(
            "Agent model job `{}` is missing its successful response",
            job.id
        ))
    })?;
    let output = validate_agent_response_envelope(job, response).map_err(|error| {
        StorageError::CorruptData(format!(
            "Agent model job `{}` response envelope is invalid: {error}",
            job.id
        ))
    })?;
    let provider_call = output.get("call").and_then(Value::as_object);
    if output.len() != 2
        || output.get("type").and_then(Value::as_str) != Some("tool_call")
        || provider_call.map(serde_json::Map::len) != Some(3)
        || provider_call
            .and_then(|call| call.get("id"))
            .and_then(Value::as_str)
            .is_none()
        || provider_call
            .and_then(|call| call.get("name"))
            .and_then(Value::as_str)
            .is_none()
        || provider_call
            .and_then(|call| call.get("arguments"))
            .is_none()
    {
        return Err(StorageError::CorruptData(format!(
            "Agent model job `{}` tool response shape is invalid",
            job.id
        )));
    }
    let provider_call = provider_call.expect("validated tool response has a call object");
    let provider_call_id = provider_call
        .get("id")
        .and_then(Value::as_str)
        .expect("validated tool response has a call ID");
    let tool_name = provider_call
        .get("name")
        .and_then(Value::as_str)
        .expect("validated tool response has a tool name");
    let arguments = provider_call
        .get("arguments")
        .expect("validated tool response has arguments");
    let provider_call_id_valid = !provider_call_id.is_empty()
        && provider_call_id.trim() == provider_call_id
        && provider_call_id.len() <= DISPATCH_IDENTIFIER_MAX_BYTES
        && provider_call_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
    if !provider_call_id_valid
        || normalized_account_value(tool_name, "agent tool name", DISPATCH_TOOL_NAME_MAX_BYTES)
            .is_err()
        || validate_reply_json(
            arguments,
            "agent tool arguments JSON",
            AGENT_TOOL_ARGUMENTS_MAX_BYTES,
        )
        .is_err()
    {
        return Err(StorageError::CorruptData(format!(
            "Agent model job `{}` tool response material is invalid",
            job.id
        )));
    }
    Ok(())
}

fn validate_agent_tool_call_spec(spec: &AgentToolCallSpec) -> Result<(), StorageError> {
    if spec.call_id.is_empty()
        || spec.call_id.trim() != spec.call_id
        || spec.call_id.len() > DISPATCH_CALL_ID_MAX_BYTES
        || spec.call_id.chars().any(char::is_control)
    {
        return Err(StorageError::InvalidAgentTransition(format!(
            "agent call ID must be canonical, control-free, and at most {DISPATCH_CALL_ID_MAX_BYTES} UTF-8 bytes"
        )));
    }
    if spec.provider_call_id.is_empty()
        || spec.provider_call_id.trim() != spec.provider_call_id
        || spec.provider_call_id.len() > DISPATCH_IDENTIFIER_MAX_BYTES
        || !spec
            .provider_call_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(StorageError::InvalidAgentTransition(format!(
            "provider call ID must use the provider-safe alphabet and at most {DISPATCH_IDENTIFIER_MAX_BYTES} bytes"
        )));
    }
    normalized_account_value(
        &spec.tool_name,
        "agent tool name",
        DISPATCH_TOOL_NAME_MAX_BYTES,
    )?;
    normalized_account_value(
        &spec.tool_version,
        "agent tool version",
        DISPATCH_TOOL_VERSION_MAX_BYTES,
    )?;
    validate_reply_json(
        &spec.arguments_json,
        "agent tool arguments JSON",
        AGENT_TOOL_ARGUMENTS_MAX_BYTES,
    )?;
    if spec.arguments_digest != tools::arguments_digest(&spec.arguments_json) {
        return Err(StorageError::InvalidAgentTransition(
            "agent arguments digest does not match canonical arguments".into(),
        ));
    }
    normalized_account_value(
        &spec.policy_revision,
        "agent policy revision",
        DISPATCH_IDENTIFIER_MAX_BYTES,
    )?;
    Ok(())
}

fn validate_agent_tool_result(result: &Value) -> Result<u64, StorageError> {
    let bytes = bounded_json_serialized_len(result, AGENT_TOOL_RESULT_JSON_MAX_BYTES)?.ok_or_else(
        || {
            StorageError::InvalidAgentTransition(format!(
                "agent tool result JSON cannot exceed {AGENT_TOOL_RESULT_JSON_MAX_BYTES} serialized bytes"
            ))
        },
    )?;
    usize_to_u64(bytes, "agent tool result bytes")
}

fn validate_agent_error_json(value: &Value, field: &'static str) -> Result<(), StorageError> {
    validate_reply_json(value, field, AGENT_ERROR_JSON_MAX_BYTES)?;
    let object = value.as_object().expect("validated as an object");
    if object.get("code").and_then(Value::as_str).is_none()
        || object.get("message").and_then(Value::as_str).is_none()
    {
        return Err(StorageError::InvalidAgentTransition(format!(
            "{field} must contain string code and message fields"
        )));
    }
    Ok(())
}

fn proposal_disposition(
    decision: PolicyDecision,
    result_bytes: Option<u64>,
) -> Result<ProposalDisposition, StorageError> {
    match (decision, result_bytes) {
        (PolicyDecision::Allow, None) => Ok(ProposalDisposition::Allow),
        (PolicyDecision::RequireApproval, None) => Ok(ProposalDisposition::RequireApproval),
        (PolicyDecision::Deny, Some(result_bytes)) => {
            Ok(ProposalDisposition::Deny { result_bytes })
        }
        _ => Err(StorageError::InvalidAgentTransition(
            "agent policy disposition and result do not match".into(),
        )),
    }
}

fn workflow_terminal_error(state: &WorkflowState) -> Value {
    let reason = state
        .terminal_reason()
        .map(terminal_reason_code)
        .unwrap_or("agent_loop_failed");
    json!({
        "code": reason,
        "message": "the durable agent loop reached a terminal safety boundary"
    })
}

fn workflow_terminal_error_for_resolution(
    state: &WorkflowState,
    resolution: &AgentModelResolution,
    response_json: &Value,
) -> Result<Value, StorageError> {
    let mut error = workflow_terminal_error(state);
    let object = error
        .as_object_mut()
        .expect("workflow terminal errors are objects");
    object.insert(
        "resolution_fingerprint".into(),
        Value::String(agent_model_resolution_fingerprint(resolution)?),
    );
    let response_digest =
        super::execution::digest_json(DigestDomain::ModelResponse, response_json)?;
    let proposal_evidence = match resolution {
        AgentModelResolution::Final { .. } => None,
        AgentModelResolution::ToolCall { call } => Some(json!({
            "disposition": proposal_disposition(call.policy_decision.clone(), None)?,
            "model_response_digest": response_digest,
            "result_digest": Value::Null,
        })),
        AgentModelResolution::PolicyDenied {
            call, result_json, ..
        } => {
            let result_bytes = validate_agent_tool_result(result_json)?;
            Some(json!({
                "disposition": proposal_disposition(
                    call.policy_decision.clone(),
                    Some(result_bytes),
                )?,
                "model_response_digest": response_digest,
                "result_digest": super::execution::digest_json(
                    DigestDomain::ToolResult,
                    result_json,
                )?,
            }))
        }
    };
    if let Some(proposal_evidence) = proposal_evidence {
        object.insert("proposal_evidence".into(), proposal_evidence);
    }
    Ok(error)
}

fn agent_model_resolution_fingerprint(
    resolution: &AgentModelResolution,
) -> Result<String, StorageError> {
    let projection = match resolution {
        AgentModelResolution::Final {
            assistant_message,
            provenance,
        } => json!({
            "type": "final",
            "assistant_message": assistant_message,
            "provenance": provenance,
        }),
        AgentModelResolution::ToolCall { call } => json!({
            "type": "tool_call",
            "call": agent_tool_call_spec_projection(call),
        }),
        AgentModelResolution::PolicyDenied {
            call,
            result_json,
            next_request_json,
        } => json!({
            "type": "policy_denied",
            "call": agent_tool_call_spec_projection(call),
            "result": result_json,
            "next_request": next_request_json,
        }),
    };
    let mut digest = Sha256::new();
    digest.update(b"zeus-agent-model-resolution-v1\0");
    digest.update(serde_json::to_vec(&projection)?);
    Ok(format!("sha256:{:x}", digest.finalize()))
}

fn agent_tool_call_spec_projection(spec: &AgentToolCallSpec) -> Value {
    json!({
        "call_id": spec.call_id,
        "provider_call_id": spec.provider_call_id,
        "tool_name": spec.tool_name,
        "tool_version": spec.tool_version,
        "arguments": spec.arguments_json,
        "arguments_digest": spec.arguments_digest,
        "effect": spec.effect,
        "sandbox_profile": spec.sandbox_profile,
        "executor_status": spec.executor_status,
        "policy_decision": spec.policy_decision,
        "policy_revision": spec.policy_revision,
    })
}

fn require_terminal_resolution_replay(
    agent: &AgentTurn,
    resolution: &AgentModelResolution,
) -> Result<(), StorageError> {
    let expected = agent_model_resolution_fingerprint(resolution)?;
    let actual = agent
        .last_error_json
        .as_ref()
        .and_then(|error| error.get("resolution_fingerprint"))
        .and_then(Value::as_str);
    if actual != Some(expected.as_str()) {
        return Err(StorageError::InvalidAgentTransition(
            "agent model replay conflicts with its durable terminal resolution".into(),
        ));
    }
    Ok(())
}

fn terminal_reason_code(reason: TerminalReason) -> &'static str {
    match reason {
        TerminalReason::ModelFailed => "model_failed",
        TerminalReason::AuthorizationRevoked => "authorization_revoked",
        TerminalReason::ContinuationUnavailable => "continuation_unavailable",
        TerminalReason::ModelOutcomeUnknown => "model_outcome_unknown",
        TerminalReason::ToolOutcomeUnknown => "tool_outcome_unknown",
        TerminalReason::ModelStepLimitReached => "model_step_limit_reached",
        TerminalReason::ToolCallLimitReached => "tool_call_limit_reached",
        TerminalReason::PendingApprovalLimitReached => "pending_approval_limit_reached",
        TerminalReason::ToolResultBytesLimitReached => "tool_result_bytes_limit_reached",
    }
}

fn finish_agent_model_job_success(
    connection: &Connection,
    job: &AgentModelJob,
    response_json: &Value,
    timestamp: &str,
) -> Result<(), StorageError> {
    let changed = connection.execute(
        r#"UPDATE agent_model_jobs
           SET status = 'succeeded', response_json = ?1, finished_at = ?2
           WHERE id = ?3 AND status = 'started' AND attempt = 1"#,
        params![serde_json::to_string(response_json)?, timestamp, job.id],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    Ok(())
}

fn insert_continuation_model_job(
    connection: &Connection,
    agent: &AgentTurn,
    request_json: &Value,
    queued_at: &str,
) -> Result<AgentModelJob, StorageError> {
    validate_reply_json(
        request_json,
        "agent continuation request JSON",
        AGENT_REQUEST_JSON_MAX_BYTES,
    )?;
    let digest = agent.deployment_manifest_digest.as_deref().ok_or_else(|| {
        StorageError::CorruptData(
            "a legacy Agent cannot enqueue a post-v19 model continuation".into(),
        )
    })?;
    let manifest = query_agent_deployment_manifest(connection, digest)?;
    validate_request_tools_match_manifest(request_json, &manifest).map_err(|error| {
        StorageError::InvalidAgentTransition(format!(
            "agent continuation tools disagree with its deployment manifest: {error}"
        ))
    })?;
    if agent.status != AgentTurnStatus::WaitingModel {
        return Err(StorageError::InvalidAgentTransition(
            "only a waiting Agent can enqueue a model continuation".into(),
        ));
    }
    let step = agent
        .model_steps
        .checked_add(1)
        .ok_or(StorageError::IntegerOutOfRange("agent model step"))?;
    let job_id = model_job_id(&agent.id, step);
    connection.execute(
        r#"INSERT INTO agent_model_jobs(
               id, agent_id, account_id, actor_user_id, actor_membership_revision,
               session_id, turn_id, step, provider_name, model_name,
               status, attempt, request_json, response_json, error_json,
               queued_at, started_at, finished_at
           ) VALUES (
               ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
               'queued', 0, ?11, NULL, NULL, ?12, NULL, NULL
           )"#,
        params![
            job_id,
            agent.id,
            agent.account_id.as_str(),
            agent.actor_user_id,
            u64_to_i64(
                agent.actor_membership_revision.get(),
                "agent membership revision"
            )?,
            agent.session_id,
            agent.turn_id,
            i64::from(step),
            agent.provider_name,
            agent.model_name,
            serde_json::to_string(request_json)?,
            queued_at,
        ],
    )?;
    query_agent_model_job(connection, &agent.id, step)
}

fn finalize_agent_success(
    connection: &Connection,
    agent: &AgentTurn,
    assistant_message: &str,
    provenance: &AssistantReplyProvenance,
    timestamp: &str,
) -> Result<AgentFinalCompletion, StorageError> {
    let mut summary = require_open_agent_turn(connection, agent)?;
    let assistant_sequence = next_session_sequence(summary.sequence)?;
    let assistant_event = build_session_event(
        &agent.session_id,
        assistant_sequence,
        timestamp,
        SessionEventData::AssistantMessage {
            turn_id: agent.turn_id.clone(),
            content: assistant_message.to_owned(),
            provenance: Some(provenance.clone()),
        },
    );
    let assistant_payload = encode_event_payload(&assistant_event)?;
    let flush_sequence = assistant_sequence
        .checked_add(1)
        .ok_or(StorageError::IntegerOutOfRange("session sequence"))?;
    let flush_event = build_session_event(
        &agent.session_id,
        flush_sequence,
        timestamp,
        SessionEventData::TurnFlushed {
            turn_id: agent.turn_id.clone(),
        },
    );
    let flush_payload = encode_event_payload(&flush_event)?;
    let emitted_payload_bytes = checked_event_payload_total([&assistant_payload, &flush_payload])?;
    if require_session_finalization_capacity(
        connection,
        &agent.session_id,
        &agent.turn_id,
        2,
        emitted_payload_bytes,
    )?
    .0 != 2
    {
        return Err(StorageError::FinalizationReservationUnavailable);
    }
    insert_session_event(
        connection,
        &agent.session_id,
        &assistant_event,
        &assistant_payload,
    )?;
    update_session_projection(
        connection,
        &agent.session_id,
        summary.sequence,
        SessionStatus::Running,
        Some(&agent.turn_id),
        assistant_sequence,
        timestamp,
    )?;
    summary.sequence = assistant_sequence;
    let changed = connection.execute(
        r#"UPDATE session_turns
           SET status = 'flushed', assistant_message = ?1, completed_at = ?2
           WHERE session_id = ?3 AND id = ?4 AND status = 'open'"#,
        params![
            assistant_message,
            timestamp,
            agent.session_id,
            agent.turn_id
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    insert_session_event(connection, &agent.session_id, &flush_event, &flush_payload)?;
    update_session_projection(
        connection,
        &agent.session_id,
        summary.sequence,
        SessionStatus::Ready,
        None,
        flush_sequence,
        timestamp,
    )?;
    finish_session_finalization(
        connection,
        &agent.session_id,
        &agent.turn_id,
        2,
        emitted_payload_bytes,
    )?;
    Ok(AgentFinalCompletion {
        agent: query_agent_turn(connection, &agent.id)?,
        session: query_session_summary(connection, &agent.session_id)?,
        turn: query_session_turn(connection, &agent.session_id, &agent.turn_id)?,
        events: vec![assistant_event, flush_event],
        replayed: false,
    })
}

fn usize_to_u64(value: usize, field: &'static str) -> Result<u64, StorageError> {
    u64::try_from(value).map_err(|_| StorageError::IntegerOutOfRange(field))
}

fn insert_agent_tool_call(
    connection: &Connection,
    agent: &AgentTurn,
    job: &AgentModelJob,
    spec: &AgentToolCallSpec,
    status: AgentToolCallStatus,
    result_json: Option<&Value>,
    timestamp: &str,
) -> Result<AgentToolCall, StorageError> {
    validate_agent_tool_call_spec(spec)?;
    let digest = agent.deployment_manifest_digest.as_deref().ok_or_else(|| {
        StorageError::CorruptData(
            "a post-upgrade Agent tool call is missing its deployment manifest".into(),
        )
    })?;
    let manifest = query_agent_deployment_manifest(connection, digest)?;
    require_tool_spec_matches_manifest(spec, &manifest)?;
    if result_json.is_some() != status.is_terminal() {
        return Err(StorageError::InvalidAgentTransition(
            "agent tool terminal state and result must be committed together".into(),
        ));
    }
    if let Some(result) = result_json {
        validate_agent_tool_result(result)?;
    }
    let finished_at = status.is_terminal().then_some(timestamp);
    connection.execute(
        r#"INSERT INTO agent_tool_calls(
               call_id, agent_id, account_id, session_id, turn_id,
               provider_call_id, ordinal, model_step, tool_name, tool_version,
               arguments_json, arguments_digest, effect, sandbox_profile,
               executor_status, policy_decision, policy_revision, status,
               approving_actor_user_id, approving_membership_revision,
               review_note, reviewed_at, result_json, provider_request_id,
               created_at, started_at, finished_at
           ) VALUES (
               ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
               ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18,
               NULL, NULL, NULL, NULL, ?19, NULL, ?20, NULL, ?21
           )"#,
        params![
            spec.call_id,
            agent.id,
            agent.account_id.as_str(),
            agent.session_id,
            agent.turn_id,
            spec.provider_call_id,
            i64::from(agent.tool_calls),
            i64::from(job.step),
            spec.tool_name,
            spec.tool_version,
            serde_json::to_string(&spec.arguments_json)?,
            spec.arguments_digest,
            tool_effect_to_db(&spec.effect),
            sandbox_profile_to_db(&spec.sandbox_profile),
            executor_status_to_db(&spec.executor_status),
            policy_decision_to_db(&spec.policy_decision),
            spec.policy_revision,
            agent_tool_status_to_db(&status),
            result_json.map(serde_json::to_string).transpose()?,
            timestamp,
            finished_at,
        ],
    )?;
    query_agent_tool_call(connection, &spec.call_id)
}

fn replay_agent_model_success(
    connection: &Connection,
    job: &AgentModelJob,
    agent: &AgentTurn,
    commit: &AgentModelSuccessCommit,
) -> Result<AgentModelCompletion, StorageError> {
    if job.status != AgentModelJobStatus::Succeeded
        || job.response_json.as_ref() != Some(&commit.response_json)
    {
        return Err(StorageError::InvalidAgentTransition(
            "agent model success conflicts with its durable terminal state".into(),
        ));
    }
    match &commit.resolution {
        AgentModelResolution::Final { .. } => Ok(AgentModelCompletion::Final(Box::new(
            query_agent_final_completion(connection, agent)?,
        ))),
        AgentModelResolution::ToolCall { .. } => {
            let AgentModelResolution::ToolCall { call: expected } = &commit.resolution else {
                unreachable!("matched Agent tool-call resolution")
            };
            if let Some(call) = query_agent_tool_call_for_step(connection, &agent.id, job.step)? {
                require_persisted_agent_tool_call(&call, job, expected)?;
                Ok(AgentModelCompletion::ToolCall {
                    agent: Box::new(query_agent_turn(connection, &agent.id)?),
                    call: Box::new(call),
                })
            } else if agent.status.is_terminal() {
                require_terminal_resolution_replay(agent, &commit.resolution)?;
                Ok(AgentModelCompletion::Terminal(Box::new(
                    query_agent_terminal_completion(connection, agent)?,
                )))
            } else {
                Err(StorageError::CorruptData(
                    "successful agent tool proposal has no durable call".into(),
                ))
            }
        }
        AgentModelResolution::PolicyDenied {
            call: expected,
            result_json,
            next_request_json,
        } => {
            let call = query_agent_tool_call_for_step(connection, &agent.id, job.step)?;
            if call.is_none() {
                if agent.status.is_terminal() {
                    require_terminal_resolution_replay(agent, &commit.resolution)?;
                    return Ok(AgentModelCompletion::Terminal(Box::new(
                        query_agent_terminal_completion(connection, agent)?,
                    )));
                }
                return Err(StorageError::CorruptData(
                    "policy-denied model proposal has no durable call".into(),
                ));
            }
            let call = call.expect("checked as present");
            require_persisted_agent_tool_call(&call, job, expected)?;
            if call.status != AgentToolCallStatus::NotDispatched
                || call.result_json.as_ref() != Some(result_json)
            {
                return Err(StorageError::InvalidAgentTransition(
                    "policy-denied Agent replay conflicts with its durable tool result".into(),
                ));
            }
            let next_step = job
                .step
                .checked_add(1)
                .ok_or(StorageError::IntegerOutOfRange("agent model step"))?;
            if let Some(next_job) =
                query_agent_model_job_optional(connection, &agent.id, next_step)?
            {
                if next_request_json.as_ref() != Some(&next_job.request_json) {
                    return Err(StorageError::InvalidAgentTransition(
                        "policy-denied Agent replay conflicts with its durable continuation".into(),
                    ));
                }
                Ok(AgentModelCompletion::ToolCall {
                    agent: Box::new(query_agent_turn(connection, &agent.id)?),
                    call: Box::new(call),
                })
            } else if agent.status.is_terminal() {
                require_terminal_resolution_replay(agent, &commit.resolution)?;
                Ok(AgentModelCompletion::Terminal(Box::new(
                    query_agent_terminal_completion(connection, agent)?,
                )))
            } else {
                Err(StorageError::CorruptData(
                    "policy-denied model proposal has no continuation job".into(),
                ))
            }
        }
    }
}

fn require_persisted_agent_tool_call(
    call: &AgentToolCall,
    job: &AgentModelJob,
    expected: &AgentToolCallSpec,
) -> Result<(), StorageError> {
    if call.agent_id != job.agent_id
        || call.model_step != job.step
        || call.call_id != expected.call_id
        || call.provider_call_id != expected.provider_call_id
        || call.tool_name != expected.tool_name
        || call.tool_version != expected.tool_version
        || call.arguments_json != expected.arguments_json
        || call.arguments_digest != expected.arguments_digest
        || call.effect != expected.effect
        || call.sandbox_profile != expected.sandbox_profile
        || call.executor_status != expected.executor_status
        || call.policy_decision != expected.policy_decision
        || call.policy_revision != expected.policy_revision
    {
        return Err(StorageError::InvalidAgentTransition(
            "agent model replay conflicts with its durable tool resolution".into(),
        ));
    }
    Ok(())
}

fn query_agent_final_completion(
    connection: &Connection,
    agent: &AgentTurn,
) -> Result<AgentFinalCompletion, StorageError> {
    let current = query_agent_turn(connection, &agent.id)?;
    if current.status != AgentTurnStatus::Succeeded {
        return Err(StorageError::InvalidAgentTransition(
            "agent final completion is not durable".into(),
        ));
    }
    let session = query_session_summary(connection, &agent.session_id)?;
    let turn = query_session_turn(connection, &agent.session_id, &agent.turn_id)?;
    if turn.status != SessionTurnStatus::Flushed {
        return Err(StorageError::CorruptData(
            "successful agent disagrees with its immutable Session turn".into(),
        ));
    }
    let events = query_agent_final_events(connection, &agent.session_id, &agent.turn_id)?;
    let valid_events = matches!(
        events.as_slice(),
        [
            SessionEvent {
                data:
                    SessionEventData::AssistantMessage {
                        turn_id: assistant_turn_id,
                        content,
                        ..
                    },
                ..
            },
            SessionEvent {
                data: SessionEventData::TurnFlushed { turn_id: flush_turn_id },
                ..
            }
        ] if assistant_turn_id == &agent.turn_id
            && flush_turn_id == &agent.turn_id
            && turn.assistant_message.as_deref() == Some(content.as_str())
    );
    if !valid_events {
        return Err(StorageError::CorruptData(
            "successful agent must own one assistant and one flush event".into(),
        ));
    }
    Ok(AgentFinalCompletion {
        agent: current,
        session,
        turn,
        events,
        replayed: true,
    })
}

fn query_agent_terminal_completion(
    connection: &Connection,
    agent: &AgentTurn,
) -> Result<AgentTerminalCompletion, StorageError> {
    let current = query_agent_turn(connection, &agent.id)?;
    if !matches!(
        current.status,
        AgentTurnStatus::Failed | AgentTurnStatus::NeedsAttention
    ) {
        return Err(StorageError::InvalidAgentTransition(
            "agent terminal completion is not durable".into(),
        ));
    }
    let session = query_session_summary(connection, &agent.session_id)?;
    let turn = query_session_turn(connection, &agent.session_id, &agent.turn_id)?;
    if turn.status != SessionTurnStatus::Interrupted {
        return Err(StorageError::CorruptData(
            "terminal agent disagrees with its immutable Session turn".into(),
        ));
    }
    let mut events =
        query_agent_interruption_events(connection, &agent.session_id, &agent.turn_id)?;
    if events.len() != 1 {
        return Err(StorageError::CorruptData(
            "terminal agent must own exactly one interruption event".into(),
        ));
    }
    Ok(AgentTerminalCompletion {
        agent: current,
        session,
        turn,
        event: events.remove(0),
        replayed: true,
    })
}

fn query_agent_final_events(
    connection: &Connection,
    session_id: &str,
    turn_id: &str,
) -> Result<Vec<SessionEvent>, StorageError> {
    let mut events =
        query_bounded_agent_turn_events(connection, session_id, turn_id, "assistant_message", 2)?;
    events.extend(query_bounded_agent_turn_events(
        connection,
        session_id,
        turn_id,
        "turn_flushed",
        2,
    )?);
    events.sort_unstable_by_key(|event| event.sequence);
    Ok(events)
}

fn query_agent_interruption_events(
    connection: &Connection,
    session_id: &str,
    turn_id: &str,
) -> Result<Vec<SessionEvent>, StorageError> {
    query_bounded_agent_turn_events(connection, session_id, turn_id, "turn_interrupted", 2)
}

fn query_bounded_agent_turn_events(
    connection: &Connection,
    session_id: &str,
    turn_id: &str,
    event_kind: &str,
    row_limit: i64,
) -> Result<Vec<SessionEvent>, StorageError> {
    let mut statement = connection.prepare(
        r#"SELECT sequence, event_id, event_kind, payload_version, payload_json,
                  turn_id, created_at
           FROM session_events INDEXED BY session_events_turn_kind_idx
           WHERE session_id = ?1 AND turn_id = ?2 AND turn_id IS NOT NULL
             AND event_kind = ?3
           ORDER BY sequence LIMIT ?4"#,
    )?;
    statement
        .query_map(params![session_id, turn_id, event_kind, row_limit], |row| {
            Ok(StoredSessionEventRow {
                sequence: row.get(0)?,
                event_id: row.get(1)?,
                event_kind: row.get(2)?,
                payload_version: row.get(3)?,
                payload_json: row.get(4)?,
                turn_id: row.get(5)?,
                created_at: row.get(6)?,
            })
        })?
        .map(|row| row?.decode())
        .collect()
}

fn query_agent_turn_detail_for_actor(
    connection: &mut Connection,
    context: &AuthzContext,
    session_id: &str,
    turn_id: &str,
) -> Result<AgentTurnDetail, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_active_session_actor(&transaction, session_id, context)?;
    let agent = query_agent_turn_for_session_turn(&transaction, session_id, turn_id)?;
    if agent.account_id != context.account_id {
        return Err(StorageError::AgentTurnNotFound(turn_id.to_owned()));
    }
    let detail = agent_turn_detail(&transaction, &agent)?;
    transaction.commit()?;
    Ok(detail)
}

fn query_agent_deployment_manifest_for_actor(
    connection: &mut Connection,
    context: &AuthzContext,
    session_id: &str,
    turn_id: &str,
) -> Result<Option<ManifestEnvelope>, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_active_session_actor(&transaction, session_id, context)?;
    let agent = query_agent_turn_for_session_turn(&transaction, session_id, turn_id)?;
    if agent.account_id != context.account_id {
        return Err(StorageError::AgentTurnNotFound(turn_id.to_owned()));
    }
    let Some(digest) = agent.deployment_manifest_digest.as_deref() else {
        transaction.commit()?;
        return Ok(None);
    };
    let manifest = query_agent_deployment_manifest(&transaction, digest)?;
    require_manifest_matches_agent_identity(&transaction, &manifest, &agent).map_err(|error| {
        StorageError::CorruptData(format!(
            "Agent deployment manifest binding is invalid: {error}"
        ))
    })?;
    transaction.commit()?;
    Ok(Some(manifest))
}

fn query_agent_review_context_for_actor(
    connection: &mut Connection,
    context: &AuthzContext,
    session_id: &str,
    turn_id: &str,
    call_id: &str,
) -> Result<AgentReviewContext, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_agent_review_owner(&transaction, context, session_id)?;
    let agent = query_agent_turn_for_session_turn(&transaction, session_id, turn_id)?;
    let call = query_agent_tool_call(&transaction, call_id)?;
    if agent.account_id != context.account_id
        || call.account_id != context.account_id
        || call.agent_id != agent.id
        || call.session_id != session_id
        || call.turn_id != turn_id
    {
        return Err(StorageError::AgentToolCallNotFound(call_id.to_owned()));
    }
    let model_job = query_agent_model_job(&transaction, &agent.id, call.model_step)?;
    if model_job.status != AgentModelJobStatus::Succeeded {
        return Err(StorageError::CorruptData(
            "agent review call is not backed by a successful model step".into(),
        ));
    }
    let context = AgentReviewContext {
        agent,
        work: AgentToolWork { call, model_job },
    };
    transaction.commit()?;
    Ok(context)
}

fn require_agent_review_owner(
    connection: &Connection,
    context: &AuthzContext,
    session_id: &str,
) -> Result<(), StorageError> {
    require_active_session_actor(connection, session_id, context)?;
    let role = current_durable_role(connection, context)?;
    if !membership_allows(role, AccountCapability::ApproveDispatch) {
        return Err(StorageError::PermissionDenied);
    }
    Ok(())
}

pub(super) fn agent_turn_detail(
    connection: &Connection,
    agent: &AgentTurn,
) -> Result<AgentTurnDetail, StorageError> {
    let calls = query_agent_tool_calls(connection, &agent.id)?
        .iter()
        .map(agent_tool_call_detail)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(AgentTurnDetail {
        id: agent.id.clone(),
        session_id: agent.session_id.clone(),
        turn_id: agent.turn_id.clone(),
        deployment_manifest_digest: agent.deployment_manifest_digest.clone(),
        status: agent.status.clone(),
        model_steps: agent.model_steps,
        tool_calls: agent.tool_calls,
        tool_result_bytes: agent.tool_result_bytes,
        revision: agent.revision,
        pending_call_id: agent.pending_call_id.clone(),
        last_error: agent.last_error_json.clone(),
        calls,
        created_at: agent.created_at.clone(),
        updated_at: agent.updated_at.clone(),
        completed_at: agent.completed_at.clone(),
    })
}

pub(super) fn agent_tool_call_detail(
    call: &AgentToolCall,
) -> Result<AgentToolCallDetail, StorageError> {
    let review = match (
        call.approving_actor_user_id.as_ref(),
        call.approving_membership_revision.as_ref(),
        call.reviewed_at.as_ref(),
    ) {
        (Some(user_id), Some(revision), Some(reviewed_at)) => Some(AgentApprovalReview {
            decision: if call.status == AgentToolCallStatus::Rejected {
                ReviewDecision::Reject
            } else {
                ReviewDecision::Approve
            },
            reviewer_user_id: user_id.clone(),
            membership_revision: revision.get(),
            note: call.review_note.clone(),
            reviewed_at: reviewed_at.clone(),
        }),
        (None, None, None) => None,
        _ => {
            return Err(StorageError::CorruptData(
                "agent tool review evidence is incomplete".into(),
            ));
        }
    };
    let (output, error) = match call.status {
        AgentToolCallStatus::Succeeded => (call.result_json.clone(), None),
        AgentToolCallStatus::Failed
        | AgentToolCallStatus::Cancelled
        | AgentToolCallStatus::Rejected
        | AgentToolCallStatus::NotDispatched
        | AgentToolCallStatus::OutcomeUnknown => (None, call.result_json.clone()),
        AgentToolCallStatus::WaitingApproval
        | AgentToolCallStatus::Queued
        | AgentToolCallStatus::Running => (None, None),
    };
    Ok(AgentToolCallDetail {
        call_id: call.call_id.clone(),
        provider_call_id: call.provider_call_id.clone(),
        ordinal: call.ordinal,
        model_step: call.model_step,
        tool: call.tool_name.clone(),
        tool_version: call.tool_version.clone(),
        arguments: call.arguments_json.clone(),
        arguments_digest: call.arguments_digest.clone(),
        effect: call.effect.clone(),
        sandbox_profile: call.sandbox_profile.clone(),
        status: call.status.clone(),
        approval_required: call.policy_decision == PolicyDecision::RequireApproval,
        policy_revision: call.policy_revision.clone(),
        review,
        output,
        error,
        created_at: call.created_at.clone(),
        started_at: call.started_at.clone(),
        finished_at: call.finished_at.clone(),
    })
}

fn review_agent_tool_for_actor(
    connection: &mut Connection,
    context: &AuthzContext,
    session_id: &str,
    turn_id: &str,
    commit: AgentReviewCommit,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<AgentReviewResult, StorageError> {
    let key = normalized_key(&commit.idempotency_key)?.to_owned();
    normalized_identifier(&commit.call_id, "agent call ID")?;
    if let Some(note) = &commit.note {
        validate_review_note_value(note, "agent review note")?;
    }
    let request_fingerprint = agent_review_fingerprint(
        session_id,
        turn_id,
        &commit.call_id,
        &commit.decision,
        commit.note.as_deref(),
    )?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_agent_review_owner(&transaction, context, session_id)?;
    let mut agent = query_agent_turn_for_session_turn(&transaction, session_id, turn_id)?;
    let call = query_agent_tool_call(&transaction, &commit.call_id)?;
    if agent.account_id != context.account_id
        || call.account_id != context.account_id
        || call.agent_id != agent.id
        || call.session_id != session_id
        || call.turn_id != turn_id
    {
        return Err(StorageError::AgentToolCallNotFound(commit.call_id));
    }
    if let Some((stored_fingerprint, stored_call_id, stored_revision)) = transaction
        .query_row(
            r#"SELECT request_fingerprint, call_id, actor_membership_revision
               FROM agent_review_receipts
               WHERE account_id = ?1 AND actor_user_id = ?2 AND idempotency_key = ?3"#,
            params![context.account_id.as_str(), context.user_id, key],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?
    {
        if stored_fingerprint != request_fingerprint
            || stored_call_id != call.call_id
            || i64_to_u64(stored_revision, "agent review receipt revision")?
                != context.membership_revision.get()
        {
            return Err(StorageError::IdempotencyConflict);
        }
        let current_agent = query_agent_turn(&transaction, &agent.id)?;
        let current_call = query_agent_tool_call(&transaction, &call.call_id)?;
        let response = AgentReviewResponse {
            agent: agent_turn_detail(&transaction, &current_agent)?,
            call: agent_tool_call_detail(&current_call)?,
            replayed: true,
        };
        let queued_model_job = if commit.decision == ReviewDecision::Reject {
            let next_step = call
                .model_step
                .checked_add(1)
                .ok_or(StorageError::IntegerOutOfRange("agent model step"))?;
            match query_agent_model_job_optional(&transaction, &agent.id, next_step)? {
                Some(job) => Some(job),
                None if current_agent.status.is_terminal() => None,
                None => {
                    return Err(StorageError::CorruptData(
                        "replayed Agent rejection has no continuation model job".into(),
                    ));
                }
            }
        } else {
            None
        };
        let terminal_completion = if commit.decision == ReviewDecision::Reject
            && queued_model_job.is_none()
            && matches!(
                current_agent.status,
                AgentTurnStatus::Failed | AgentTurnStatus::NeedsAttention
            ) {
            Some(query_agent_terminal_completion(
                &transaction,
                &current_agent,
            )?)
        } else {
            None
        };
        transaction.commit()?;
        return Ok(AgentReviewResult {
            response,
            queued_model_job,
            terminal_completion,
        });
    }
    if call.status != AgentToolCallStatus::WaitingApproval
        || call.policy_decision != PolicyDecision::RequireApproval
        || agent.status != AgentTurnStatus::WaitingApproval
        || agent.pending_call_id.as_deref() != Some(call.call_id.as_str())
    {
        return Err(StorageError::InvalidAgentTransition(
            "agent tool call is no longer waiting for approval".into(),
        ));
    }
    require_open_agent_turn(&transaction, &agent)?;
    require_agent_finalization_capacity(&transaction, &agent)?;
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Finalization,
    )?;
    let timestamp = now();
    let mut queued_model_job = None;
    let mut terminal_completion = None;
    match commit.decision {
        ReviewDecision::Approve => {
            if commit.next_request_json.is_some() {
                return Err(StorageError::InvalidAgentTransition(
                    "approval accepts no continuation request".into(),
                ));
            }
            let command = WorkflowCommand::ApprovalApproved;
            let transition = reduce(&agent.workflow_state, command.clone())
                .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?;
            persist_agent_workflow_transition(
                &transaction,
                &mut agent,
                transition.state().clone(),
                Some(&call.call_id),
                None,
                None,
                AgentTransitionFact {
                    command,
                    external_call: transition.external_call().cloned(),
                    emitted_result: transition.emitted_result().cloned(),
                    emitted_result_digest: None,
                    epoch_digest: None,
                    source: FactSource::Live,
                    subject: Some(tool_subject(&call)),
                    input_digest: Some(tool_input_digest(&call)?),
                    output_digest: None,
                    next_request_digest: None,
                },
                &timestamp,
            )?;
            let changed = transaction.execute(
                r#"UPDATE agent_tool_calls
                   SET status = 'queued', approving_actor_user_id = ?1,
                       approving_membership_revision = ?2, review_note = ?3,
                       reviewed_at = ?4
                   WHERE call_id = ?5 AND status = 'waiting_approval'"#,
                params![
                    context.user_id,
                    u64_to_i64(
                        context.membership_revision.get(),
                        "agent approving membership revision"
                    )?,
                    commit.note,
                    timestamp,
                    call.call_id,
                ],
            )?;
            if changed != 1 {
                return Err(StorageError::ConcurrentModification);
            }
        }
        ReviewDecision::Reject => {
            let result_json =
                protocol::agent_approval_rejected_result(&call.call_id, commit.note.as_deref());
            let result_bytes = validate_agent_tool_result(&result_json)?;
            let command = WorkflowCommand::ApprovalRejected { result_bytes };
            let transition = reduce(&agent.workflow_state, command.clone())
                .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?;
            let primary_state = transition.state().clone();
            let deployment_unavailable = agent.deployment_manifest_digest.is_none()
                && primary_state.status() == WorkflowStatus::ContinuationQueued
                && commit.next_request_json.is_some();
            let requested_continuation = if deployment_unavailable {
                None
            } else {
                commit.next_request_json.as_ref()
            };
            let ContinuationSettlement {
                state: settled,
                next_request: continuation_request,
                transition: settlement_transition,
            } = settle_known_result_continuation(
                primary_state.clone(),
                requested_continuation,
                "agent rejection continuation request JSON",
            )?;
            let continuation_unavailable =
                settled.terminal_reason() == Some(TerminalReason::ContinuationUnavailable);
            let terminal_error = (settled.status() == WorkflowStatus::Failed).then(|| {
                if deployment_unavailable {
                    deployment_unavailable_error(
                        "the legacy Agent has no deployment manifest for a rejection continuation",
                    )
                } else {
                    workflow_terminal_error(&settled)
                }
            });
            let primary_terminal_error = if settlement_transition.is_none() {
                terminal_error.as_ref()
            } else {
                None
            };
            persist_agent_workflow_transition(
                &transaction,
                &mut agent,
                primary_state,
                None,
                primary_terminal_error,
                primary_terminal_error.map(|_| timestamp.as_str()),
                AgentTransitionFact {
                    command,
                    external_call: transition.external_call().cloned(),
                    emitted_result: transition.emitted_result().cloned(),
                    emitted_result_digest: None,
                    epoch_digest: None,
                    source: FactSource::Live,
                    subject: Some(tool_subject(&call)),
                    input_digest: Some(tool_input_digest(&call)?),
                    output_digest: Some(super::execution::digest_json(
                        DigestDomain::ToolResult,
                        &result_json,
                    )?),
                    next_request_digest: continuation_request
                        .map(|request| {
                            super::execution::digest_json(DigestDomain::ModelRequest, request)
                        })
                        .transpose()?,
                },
                &timestamp,
            )?;
            if let Some((settlement_command, settlement_transition)) = settlement_transition {
                persist_agent_workflow_transition(
                    &transaction,
                    &mut agent,
                    settled,
                    None,
                    terminal_error.as_ref(),
                    terminal_error.as_ref().map(|_| timestamp.as_str()),
                    AgentTransitionFact {
                        command: settlement_command,
                        external_call: settlement_transition.external_call().cloned(),
                        emitted_result: settlement_transition.emitted_result().cloned(),
                        emitted_result_digest: None,
                        epoch_digest: None,
                        source: FactSource::Live,
                        subject: None,
                        input_digest: None,
                        output_digest: None,
                        next_request_digest: None,
                    },
                    &timestamp,
                )?;
            }
            let changed = transaction.execute(
                r#"UPDATE agent_tool_calls
                   SET status = 'rejected', approving_actor_user_id = ?1,
                       approving_membership_revision = ?2, review_note = ?3,
                       reviewed_at = ?4, result_json = ?5, finished_at = ?4
                   WHERE call_id = ?6 AND status = 'waiting_approval'"#,
                params![
                    context.user_id,
                    u64_to_i64(
                        context.membership_revision.get(),
                        "agent approving membership revision"
                    )?,
                    commit.note,
                    timestamp,
                    serde_json::to_string(&result_json)?,
                    call.call_id,
                ],
            )?;
            if changed != 1 {
                return Err(StorageError::ConcurrentModification);
            }
            if let Some(next_request) = continuation_request {
                queued_model_job = Some(insert_continuation_model_job(
                    &transaction,
                    &agent,
                    next_request,
                    &timestamp,
                )?);
            } else {
                terminal_completion = Some(interrupt_agent_turn(
                    &transaction,
                    &agent,
                    if deployment_unavailable {
                        "agent deployment is unavailable for a rejection continuation"
                    } else if continuation_unavailable {
                        "agent rejection is known but its model continuation is unavailable"
                    } else {
                        "agent loop reached its model or tool-result limit after rejection"
                    },
                )?);
            }
        }
    }
    let compact_response = json!({
        "schema_version": 1,
        "call_id": call.call_id,
        "decision": commit.decision,
        "agent_revision": agent.revision,
    });
    transaction.execute(
        r#"INSERT INTO agent_review_receipts(
               account_id, actor_user_id, actor_membership_revision,
               idempotency_key, call_id, request_fingerprint, response_json, created_at
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
        params![
            context.account_id.as_str(),
            context.user_id,
            u64_to_i64(
                context.membership_revision.get(),
                "agent review membership revision"
            )?,
            key,
            call.call_id,
            request_fingerprint,
            serde_json::to_string(&compact_response)?,
            timestamp,
        ],
    )?;
    let current_agent = query_agent_turn(&transaction, &agent.id)?;
    let current_call = query_agent_tool_call(&transaction, &call.call_id)?;
    let response = AgentReviewResponse {
        agent: agent_turn_detail(&transaction, &current_agent)?,
        call: agent_tool_call_detail(&current_call)?,
        replayed: false,
    };
    transaction.commit()?;
    Ok(AgentReviewResult {
        response,
        queued_model_job,
        terminal_completion,
    })
}

fn agent_review_fingerprint(
    session_id: &str,
    turn_id: &str,
    call_id: &str,
    decision: &ReviewDecision,
    note: Option<&str>,
) -> Result<String, StorageError> {
    let bytes = serde_json::to_vec(&json!({
        "schema_version": 1,
        "session_id": session_id,
        "turn_id": turn_id,
        "call_id": call_id,
        "decision": decision,
        "note": note,
    }))?;
    let mut digest = Sha256::new();
    digest.update(b"zeus-agent-review-v1\0");
    digest.update(bytes);
    Ok(format!("sha256:{:x}", digest.finalize()))
}

fn recover_started_agent_work(
    connection: &mut Connection,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<Vec<AgentTerminalCompletion>, StorageError> {
    let mut recovered = Vec::new();
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut statement = transaction.prepare(
        r#"SELECT operation_kind, operation_id FROM (
               SELECT 'model' AS operation_kind, id AS operation_id,
                      started_at AS started_at
               FROM agent_model_jobs WHERE status = 'started'
               UNION ALL
               SELECT 'tool' AS operation_kind, call_id AS operation_id,
                      started_at AS started_at
               FROM agent_tool_calls WHERE status = 'started'
           ) ORDER BY started_at, operation_kind, operation_id LIMIT ?1"#,
    )?;
    let operations = statement
        .query_map([RECOVERY_BATCH_LIMIT], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    if operations.is_empty() {
        transaction.commit()?;
        return Ok(recovered);
    }
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Finalization,
    )?;
    for (kind, operation_id) in operations {
        match kind.as_str() {
            "model" => {
                let job = query_agent_model_job_by_id(&transaction, &operation_id)?;
                let mut agent = query_agent_turn(&transaction, &job.agent_id)?;
                require_open_agent_turn(&transaction, &agent)?;
                require_agent_finalization_capacity(&transaction, &agent)?;
                let error_json = json!({
                    "code": "model_outcome_unknown_after_restart",
                    "message": "the process restarted after the model checkpoint without a trustworthy result"
                });
                let command = WorkflowCommand::ModelOutcomeUnknown;
                let transition = reduce(&agent.workflow_state, command.clone())
                    .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?;
                let timestamp = now();
                let epoch_digest = super::execution::epoch_digest_for_recovery(
                    &transaction,
                    &agent,
                    "model",
                    &job.id,
                )?;
                persist_agent_workflow_transition(
                    &transaction,
                    &mut agent,
                    transition.state().clone(),
                    None,
                    Some(&error_json),
                    Some(&timestamp),
                    AgentTransitionFact {
                        command,
                        external_call: transition.external_call().cloned(),
                        emitted_result: transition.emitted_result().cloned(),
                        emitted_result_digest: None,
                        epoch_digest,
                        source: FactSource::RestartRecovery,
                        subject: Some(model_subject(&job)),
                        input_digest: Some(model_request_digest(&job)?),
                        output_digest: Some(super::execution::digest_json(
                            DigestDomain::ExecutionError,
                            &error_json,
                        )?),
                        next_request_digest: None,
                    },
                    &timestamp,
                )?;
                let changed = transaction.execute(
                    r#"UPDATE agent_model_jobs
                       SET status = 'outcome_unknown', error_json = ?1, finished_at = ?2
                       WHERE id = ?3 AND status = 'started' AND attempt = 1"#,
                    params![serde_json::to_string(&error_json)?, timestamp, job.id],
                )?;
                if changed != 1 {
                    return Err(StorageError::ConcurrentModification);
                }
                recovered.push(interrupt_agent_turn(
                    &transaction,
                    &agent,
                    "agent model outcome became unknown after process restart",
                )?);
            }
            "tool" => {
                let call = query_agent_tool_call(&transaction, &operation_id)?;
                let mut agent = query_agent_turn(&transaction, &call.agent_id)?;
                require_open_agent_turn(&transaction, &agent)?;
                require_agent_finalization_capacity(&transaction, &agent)?;
                let error_json = json!({
                    "code": "tool_outcome_unknown_after_restart",
                    "message": "the process restarted after the tool checkpoint without a trustworthy result"
                });
                let command = WorkflowCommand::ToolOutcomeUnknown;
                let transition = reduce(&agent.workflow_state, command.clone())
                    .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?;
                let timestamp = now();
                let epoch_digest = super::execution::epoch_digest_for_recovery(
                    &transaction,
                    &agent,
                    "tool",
                    &call.call_id,
                )?;
                persist_agent_workflow_transition(
                    &transaction,
                    &mut agent,
                    transition.state().clone(),
                    None,
                    Some(&error_json),
                    Some(&timestamp),
                    AgentTransitionFact {
                        command,
                        external_call: transition.external_call().cloned(),
                        emitted_result: transition.emitted_result().cloned(),
                        emitted_result_digest: None,
                        epoch_digest,
                        source: FactSource::RestartRecovery,
                        subject: Some(tool_subject(&call)),
                        input_digest: Some(tool_input_digest(&call)?),
                        output_digest: Some(super::execution::digest_json(
                            DigestDomain::ExecutionError,
                            &error_json,
                        )?),
                        next_request_digest: None,
                    },
                    &timestamp,
                )?;
                let changed = transaction.execute(
                    r#"UPDATE agent_tool_calls
                       SET status = 'outcome_unknown', result_json = ?1, finished_at = ?2
                       WHERE call_id = ?3 AND status = 'started'"#,
                    params![serde_json::to_string(&error_json)?, timestamp, call.call_id],
                )?;
                if changed != 1 {
                    return Err(StorageError::ConcurrentModification);
                }
                recovered.push(interrupt_agent_turn(
                    &transaction,
                    &agent,
                    "agent tool outcome became unknown after process restart",
                )?);
            }
            other => {
                return Err(StorageError::CorruptData(format!(
                    "unknown started Agent operation kind `{other}`"
                )));
            }
        }
    }
    transaction.commit()?;
    Ok(recovered)
}

fn validate_manifest_envelope(
    manifest: &ManifestEnvelope,
    field: &'static str,
) -> Result<(), StorageError> {
    manifest.validate().map_err(|error| {
        StorageError::InvalidAgentTransition(format!("{field} is invalid: {error}"))
    })?;
    let bytes = manifest.canonical_json_bytes().map_err(|error| {
        StorageError::InvalidAgentTransition(format!("{field} cannot be canonicalized: {error}"))
    })?;
    if bytes.len() > AGENT_DEPLOYMENT_MANIFEST_MAX_BYTES {
        return Err(StorageError::InvalidAgentTransition(format!(
            "{field} canonical envelope cannot exceed {AGENT_DEPLOYMENT_MANIFEST_MAX_BYTES} bytes"
        )));
    }
    Ok(())
}

fn require_manifest_matches_agent_spec(spec: &AgentTurnSpec) -> Result<(), StorageError> {
    let manifest_spec = &spec.manifest.manifest.deployment.spec;
    let expected_reply_kind = if spec.model_name.is_some() {
        AssistantReplyKind::Model
    } else {
        AssistantReplyKind::NonModelFallback
    };
    if manifest_spec.environment != spec.environment
        || manifest_spec.provider.provider_id != spec.provider_name
        || manifest_spec.provider.model != spec.model_name
        || manifest_spec.provider.reply_kind != expected_reply_kind
        || manifest_spec.workflow_schema_version != workflows::STATE_SCHEMA_VERSION
        || manifest_spec.loop_limits != workflows::Limits::default()
    {
        return Err(StorageError::InvalidAgentTransition(
            "Agent inputs disagree with the deployment manifest identity or fixed workflow limits"
                .into(),
        ));
    }
    if manifest_spec
        .tools
        .iter()
        .any(|tool| tool.executor_status != ToolExecutorStatus::Available)
    {
        return Err(StorageError::InvalidAgentTransition(
            "every provider-visible manifest tool must have an available executor".into(),
        ));
    }
    Ok(())
}

fn validate_request_tools_match_manifest(
    request_json: &Value,
    manifest: &ManifestEnvelope,
) -> Result<(), StorageError> {
    let request = request_json.as_object().ok_or_else(|| {
        StorageError::InvalidAgentTransition("agent model request must be an object".into())
    })?;
    let tools = match request.get("tools") {
        None => &[][..],
        Some(Value::Array(tools)) => tools.as_slice(),
        Some(_) => {
            return Err(StorageError::InvalidAgentTransition(
                "agent model request tools must be an array".into(),
            ));
        }
    };
    let manifest_tools = &manifest.manifest.deployment.spec.tools;
    if tools.len() != manifest_tools.len() {
        return Err(StorageError::InvalidAgentTransition(
            "agent model request tools do not match the deployment manifest".into(),
        ));
    }
    for (request_tool, manifest_tool) in tools.iter().zip(manifest_tools) {
        if manifest_tool.executor_status != ToolExecutorStatus::Available {
            return Err(StorageError::InvalidAgentTransition(
                "an unavailable manifest tool cannot be exposed to a provider".into(),
            ));
        }
        let expected = json!({
            "name": manifest_tool.name,
            "description": manifest_tool.description,
            "parameters": manifest_tool.input_schema,
        });
        if request_tool != &expected {
            return Err(StorageError::InvalidAgentTransition(format!(
                "provider-visible tool `{}` disagrees with the deployment manifest",
                manifest_tool.name
            )));
        }
    }
    Ok(())
}

fn canonical_manifest_json(manifest: &ManifestEnvelope) -> Result<String, StorageError> {
    validate_manifest_envelope(manifest, "Agent deployment manifest")?;
    String::from_utf8(manifest.canonical_json_bytes().map_err(|error| {
        StorageError::InvalidAgentTransition(format!(
            "Agent deployment manifest cannot be canonicalized: {error}"
        ))
    })?)
    .map_err(|error| {
        StorageError::InvalidAgentTransition(format!(
            "Agent deployment manifest canonical JSON is not UTF-8: {error}"
        ))
    })
}

fn persist_agent_deployment_manifest(
    connection: &Connection,
    manifest: &ManifestEnvelope,
    created_at: &str,
) -> Result<(), StorageError> {
    let canonical_json = canonical_manifest_json(manifest)?;
    connection.execute(
        r#"INSERT OR IGNORE INTO agent_deployment_manifests(
               digest, schema_version, envelope_json, created_at
           ) VALUES (?1, ?2, ?3, ?4)"#,
        params![
            manifest.digest,
            i64::from(manifest.schema_version),
            canonical_json,
            created_at,
        ],
    )?;
    let stored = connection
        .query_row(
            r#"SELECT schema_version, envelope_json
               FROM agent_deployment_manifests WHERE digest = ?1"#,
            [&manifest.digest],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((stored_schema_version, stored_json)) = stored else {
        return Err(StorageError::CorruptData(
            "Agent deployment manifest insert did not create a durable row".into(),
        ));
    };
    if stored_schema_version != i64::from(manifest.schema_version) || stored_json != canonical_json
    {
        return Err(StorageError::CorruptData(
            "Agent deployment manifest digest collides with different durable content".into(),
        ));
    }
    Ok(())
}

fn decode_agent_deployment_manifest(
    digest: &str,
    schema_version: i64,
    envelope_json: &str,
) -> Result<ManifestEnvelope, StorageError> {
    if envelope_json.len() > AGENT_DEPLOYMENT_MANIFEST_MAX_BYTES {
        return Err(StorageError::CorruptData(
            "stored Agent deployment manifest exceeds its canonical byte limit".into(),
        ));
    }
    let manifest =
        ManifestEnvelope::from_json_slice(envelope_json.as_bytes()).map_err(|error| {
            StorageError::CorruptData(format!("invalid stored Agent deployment manifest: {error}"))
        })?;
    let canonical = manifest.canonical_json_bytes().map_err(|error| {
        StorageError::CorruptData(format!(
            "stored Agent deployment manifest cannot be canonicalized: {error}"
        ))
    })?;
    if manifest.digest != digest
        || i64::from(manifest.schema_version) != schema_version
        || canonical.as_slice() != envelope_json.as_bytes()
    {
        return Err(StorageError::CorruptData(
            "stored Agent deployment manifest digest, schema, or canonical JSON disagrees".into(),
        ));
    }
    Ok(manifest)
}

pub(super) fn query_agent_deployment_manifest(
    connection: &Connection,
    digest: &str,
) -> Result<ManifestEnvelope, StorageError> {
    let stored = connection
        .query_row(
            r#"SELECT schema_version, envelope_json
               FROM agent_deployment_manifests WHERE digest = ?1"#,
            [digest],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((schema_version, envelope_json)) = stored else {
        return Err(StorageError::CorruptData(format!(
            "Agent deployment manifest `{digest}` is missing"
        )));
    };
    decode_agent_deployment_manifest(digest, schema_version, &envelope_json)
}

fn require_manifest_matches_runtime_identity(
    connection: &Connection,
    manifest: &ManifestEnvelope,
) -> Result<(), StorageError> {
    let runtime = connection
        .query_row(
            r#"SELECT profile, environment, policy_id, policy_revision
               FROM runtime_identity WHERE singleton = 1"#,
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((profile, environment, policy_id, policy_revision)) = runtime else {
        return Err(StorageError::InvalidAgentTransition(
            "runtime identity must be bound before an Agent deployment can be used".into(),
        ));
    };
    let spec = &manifest.manifest.deployment.spec;
    if spec.profile != profile
        || spec.environment != environment
        || spec.policy.policy_id != policy_id
        || spec.policy.revision != policy_revision
    {
        return Err(StorageError::InvalidAgentTransition(
            "Agent deployment manifest disagrees with the immutable runtime identity".into(),
        ));
    }
    Ok(())
}

pub(super) fn require_manifest_matches_agent_identity(
    connection: &Connection,
    manifest: &ManifestEnvelope,
    agent: &AgentTurn,
) -> Result<(), StorageError> {
    require_manifest_matches_runtime_identity(connection, manifest)?;
    let spec = &manifest.manifest.deployment.spec;
    let expected_reply_kind = if agent.model_name.is_some() {
        AssistantReplyKind::Model
    } else {
        AssistantReplyKind::NonModelFallback
    };
    if agent.deployment_manifest_digest.as_deref() != Some(manifest.digest.as_str())
        || agent.environment != spec.environment
        || agent.provider_name != spec.provider.provider_id
        || agent.model_name != spec.provider.model
        || spec.provider.reply_kind != expected_reply_kind
        || agent.workflow_state.schema_version() != spec.workflow_schema_version
        || agent.workflow_state.limits() != &spec.loop_limits
        || spec.loop_limits != workflows::Limits::default()
        || spec
            .tools
            .iter()
            .any(|tool| tool.executor_status != ToolExecutorStatus::Available)
    {
        return Err(StorageError::InvalidAgentTransition(
            "Agent projection disagrees with its deployment manifest".into(),
        ));
    }
    Ok(())
}

fn require_model_job_matches_manifest(
    job: &AgentModelJob,
    manifest: &ManifestEnvelope,
) -> Result<(), StorageError> {
    let spec = &manifest.manifest.deployment.spec;
    if job.provider_name != spec.provider.provider_id || job.model_name != spec.provider.model {
        return Err(StorageError::InvalidAgentTransition(
            "Agent model job provider disagrees with its deployment manifest".into(),
        ));
    }
    validate_request_tools_match_manifest(&job.request_json, manifest)
}

fn require_tool_call_matches_manifest(
    call: &AgentToolCall,
    manifest: &ManifestEnvelope,
) -> Result<(), StorageError> {
    let spec = &manifest.manifest.deployment.spec;
    let tool = spec
        .tools
        .iter()
        .find(|tool| tool.name == call.tool_name)
        .ok_or_else(|| {
            StorageError::InvalidAgentTransition(format!(
                "Agent tool `{}` is absent from its deployment manifest",
                call.tool_name
            ))
        })?;
    if call.tool_version != tool.version
        || call.effect != tool.effect
        || call.sandbox_profile != tool.sandbox_profile
        || call.executor_status != ToolExecutorStatus::Available
        || tool.executor_status != ToolExecutorStatus::Available
        || call.policy_revision != spec.policy.revision
    {
        return Err(StorageError::InvalidAgentTransition(format!(
            "Agent tool `{}` disagrees with its deployment manifest or policy revision",
            call.tool_name
        )));
    }
    Ok(())
}

fn require_tool_spec_matches_manifest(
    call: &AgentToolCallSpec,
    manifest: &ManifestEnvelope,
) -> Result<(), StorageError> {
    let spec = &manifest.manifest.deployment.spec;
    let tool = spec
        .tools
        .iter()
        .find(|tool| tool.name == call.tool_name)
        .ok_or_else(|| {
            StorageError::InvalidAgentTransition(format!(
                "Agent tool `{}` is absent from its deployment manifest",
                call.tool_name
            ))
        })?;
    if call.tool_version != tool.version
        || call.effect != tool.effect
        || call.sandbox_profile != tool.sandbox_profile
        || call.executor_status != ToolExecutorStatus::Available
        || tool.executor_status != ToolExecutorStatus::Available
        || call.policy_revision != spec.policy.revision
    {
        return Err(StorageError::InvalidAgentTransition(format!(
            "Agent tool `{}` disagrees with its deployment manifest or policy revision",
            call.tool_name
        )));
    }
    Ok(())
}

fn agent_deployment_matches_current(
    connection: &Connection,
    agent: &AgentTurn,
    job: Option<&AgentModelJob>,
    call: Option<&AgentToolCall>,
    current_manifest: &ManifestEnvelope,
) -> Result<bool, StorageError> {
    let Some(digest) = agent.deployment_manifest_digest.as_deref() else {
        return Ok(false);
    };
    if digest != current_manifest.digest {
        return Ok(false);
    }
    let persisted = match query_agent_deployment_manifest(connection, digest) {
        Ok(manifest) => manifest,
        Err(StorageError::Sqlite(error)) => return Err(StorageError::Sqlite(error)),
        Err(_) => return Ok(false),
    };
    if persisted != *current_manifest {
        return Ok(false);
    }
    if require_manifest_matches_agent_identity(connection, &persisted, agent).is_err() {
        return Ok(false);
    }
    if let Some(job) = job
        && require_model_job_matches_manifest(job, &persisted).is_err()
    {
        return Ok(false);
    }
    if let Some(call) = call
        && require_tool_call_matches_manifest(call, &persisted).is_err()
    {
        return Ok(false);
    }
    Ok(true)
}

fn deployment_unavailable_error(message: &str) -> Value {
    json!({
        "code": "deployment_unavailable",
        "message": message,
    })
}

pub(super) fn verify_agent_deployment_manifest_integrity(
    connection: &Connection,
) -> Result<(), StorageError> {
    {
        let mut statement = connection.prepare(
            r#"SELECT digest, schema_version, envelope_json
               FROM agent_deployment_manifests ORDER BY digest"#,
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (digest, schema_version, envelope_json) = row?;
            decode_agent_deployment_manifest(&digest, schema_version, &envelope_json)?;
        }
    }

    let agent_ids = {
        let mut statement = connection.prepare(
            r#"SELECT id FROM agent_turns
               WHERE deployment_manifest_digest IS NOT NULL ORDER BY id"#,
        )?;
        statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };
    for agent_id in agent_ids {
        let agent = query_agent_turn(connection, &agent_id)?;
        let digest = agent.deployment_manifest_digest.as_deref().ok_or_else(|| {
            StorageError::CorruptData(
                "bound Agent lost its deployment manifest digest during verification".into(),
            )
        })?;
        let manifest = query_agent_deployment_manifest(connection, digest)?;
        require_manifest_matches_agent_identity(connection, &manifest, &agent).map_err(
            |error| {
                StorageError::CorruptData(format!(
                    "Agent deployment identity binding is inconsistent: {error}"
                ))
            },
        )?;

        let jobs = {
            let mut statement = connection.prepare(&format!(
                "{} WHERE agent_id = ?1 ORDER BY step",
                model_job_select()
            ))?;
            statement
                .query_map([&agent.id], decode_agent_model_job_row)?
                .collect::<Result<Vec<_>, _>>()?
        };
        for job in jobs {
            let job = job.decode()?;
            require_model_job_matches_manifest(&job, &manifest).map_err(|error| {
                StorageError::CorruptData(format!(
                    "Agent model job deployment binding is inconsistent: {error}"
                ))
            })?;
        }
        for call in query_agent_tool_calls(connection, &agent.id)? {
            require_tool_call_matches_manifest(&call, &manifest).map_err(|error| {
                StorageError::CorruptData(format!(
                    "Agent tool deployment binding is inconsistent: {error}"
                ))
            })?;
        }
    }
    Ok(())
}

pub(super) fn validate_agent_turn_spec(spec: &AgentTurnSpec) -> Result<(), StorageError> {
    normalized_reply_value(&spec.id, "agent turn ID")?;
    if spec.id.len() > AGENT_ID_MAX_BYTES {
        return Err(StorageError::InvalidAgentTransition(format!(
            "agent turn ID cannot exceed {AGENT_ID_MAX_BYTES} UTF-8 bytes"
        )));
    }
    validated_authz_context(&spec.authz)?;
    normalized_account_value(
        &spec.environment,
        "agent environment",
        AGENT_ENVIRONMENT_MAX_BYTES,
    )?;
    protocol::validate_reply_provider_id(&spec.provider_name)
        .map_err(|error| invalid_resource_envelope("agent provider name", error))?;
    if let Some(model_name) = &spec.model_name {
        protocol::validate_reply_model_id(model_name)
            .map_err(|error| invalid_resource_envelope("agent model name", error))?;
    }
    validate_reply_json(
        &spec.request_json,
        "agent model request JSON",
        AGENT_REQUEST_JSON_MAX_BYTES,
    )?;
    validate_manifest_envelope(&spec.manifest, "Agent deployment manifest")?;
    require_manifest_matches_agent_spec(spec)?;
    validate_request_tools_match_manifest(&spec.request_json, &spec.manifest)?;
    WorkflowState::new(spec.manifest.manifest.deployment.spec.loop_limits.clone())
        .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?
        .validate()
        .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?;
    Ok(())
}

pub(super) fn agent_start_fingerprint(
    session_id: &str,
    request: &StartTurnRequest,
    spec: &AgentTurnSpec,
) -> Result<String, StorageError> {
    Ok(serde_json::to_string(&json!({
        "session_id": session_id,
        "request": request,
        "agent_turn": {
            "id": spec.id,
            "environment": spec.environment,
            "provider_name": spec.provider_name,
            "model_name": spec.model_name,
            "deployment_manifest_digest": spec.manifest.digest,
        },
    }))?)
}

pub(super) fn require_agent_matches_spec(
    agent: &AgentTurn,
    spec: &AgentTurnSpec,
) -> Result<(), StorageError> {
    // Like reply context, request_json is server-derived durable authority.
    if agent.id != spec.id
        || agent.account_id != spec.authz.account_id
        || agent.actor_user_id != spec.authz.user_id
        || agent.actor_membership_revision != spec.authz.membership_revision
        || agent.environment != spec.environment
        || agent.provider_name != spec.provider_name
        || agent.model_name != spec.model_name
        || agent.deployment_manifest_digest.as_deref() != Some(spec.manifest.digest.as_str())
    {
        return Err(StorageError::IdempotencyConflict);
    }
    Ok(())
}

pub(super) fn insert_agent_turn(
    connection: &Connection,
    session_id: &str,
    turn_id: &str,
    spec: &AgentTurnSpec,
    queued_at: &str,
) -> Result<(AgentTurn, AgentModelJob), StorageError> {
    validate_agent_turn_spec(spec)?;
    require_manifest_matches_runtime_identity(connection, &spec.manifest)?;
    persist_agent_deployment_manifest(connection, &spec.manifest, queued_at)?;
    let workflow_state =
        WorkflowState::new(spec.manifest.manifest.deployment.spec.loop_limits.clone())
            .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?;
    connection.execute(
        r#"INSERT INTO agent_turns(
               id, account_id, actor_user_id, actor_membership_revision,
               session_id, turn_id, deployment_manifest_digest,
               environment, provider_name, model_name,
               status, model_steps, tool_calls, tool_result_bytes, revision,
               pending_call_id, workflow_state_json, last_error_json,
               created_at, updated_at, completed_at
           ) VALUES (
               ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
               'waiting_model', 0, 0, 0, 1, NULL, ?11, NULL, ?12, ?12, NULL
           )"#,
        params![
            spec.id,
            spec.authz.account_id.as_str(),
            spec.authz.user_id,
            u64_to_i64(
                spec.authz.membership_revision.get(),
                "agent membership revision"
            )?,
            session_id,
            turn_id,
            spec.manifest.digest,
            spec.environment,
            spec.provider_name,
            spec.model_name,
            serde_json::to_string(&workflow_state)?,
            queued_at,
        ],
    )?;
    let job_id = model_job_id(&spec.id, 1);
    connection.execute(
        r#"INSERT INTO agent_model_jobs(
               id, agent_id, account_id, actor_user_id, actor_membership_revision,
               session_id, turn_id, step, provider_name, model_name,
               status, attempt, request_json, response_json, error_json,
               queued_at, started_at, finished_at
           ) VALUES (
               ?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9,
               'queued', 0, ?10, NULL, NULL, ?11, NULL, NULL
           )"#,
        params![
            job_id,
            spec.id,
            spec.authz.account_id.as_str(),
            spec.authz.user_id,
            u64_to_i64(
                spec.authz.membership_revision.get(),
                "agent membership revision"
            )?,
            session_id,
            turn_id,
            spec.provider_name,
            spec.model_name,
            serde_json::to_string(&spec.request_json)?,
            queued_at,
        ],
    )?;
    let agent = query_agent_turn(connection, &spec.id)?;
    let job = query_agent_model_job(connection, &spec.id, 1)?;
    super::execution::insert_native_head_and_admission(connection, &agent, &job, queued_at)?;
    Ok((agent, job))
}

fn model_job_id(agent_id: &str, step: u32) -> String {
    let mut digest = Sha256::new();
    digest.update(b"zeus-agent-model-job-v1\0");
    digest.update(agent_id.as_bytes());
    digest.update([0]);
    digest.update(step.to_be_bytes());
    format!("agent-model-{:x}", digest.finalize())
}

pub(super) fn query_agent_turn_for_session_turn(
    connection: &Connection,
    session_id: &str,
    turn_id: &str,
) -> Result<AgentTurn, StorageError> {
    connection
        .query_row(
            &format!(
                "{} WHERE session_id = ?1 AND turn_id = ?2",
                agent_turn_select()
            ),
            params![session_id, turn_id],
            decode_agent_turn_row,
        )
        .optional()?
        .ok_or_else(|| StorageError::AgentTurnNotFound(turn_id.to_owned()))?
        .decode()
}

pub(super) fn query_agent_turn(
    connection: &Connection,
    agent_id: &str,
) -> Result<AgentTurn, StorageError> {
    connection
        .query_row(
            &format!("{} WHERE id = ?1", agent_turn_select()),
            [agent_id],
            decode_agent_turn_row,
        )
        .optional()?
        .ok_or_else(|| StorageError::AgentTurnNotFound(agent_id.to_owned()))?
        .decode()
}

pub(super) fn query_agent_model_job(
    connection: &Connection,
    agent_id: &str,
    step: u32,
) -> Result<AgentModelJob, StorageError> {
    connection
        .query_row(
            &format!("{} WHERE agent_id = ?1 AND step = ?2", model_job_select()),
            params![agent_id, i64::from(step)],
            decode_agent_model_job_row,
        )
        .optional()?
        .ok_or_else(|| StorageError::AgentModelJobNotFound(format!("{agent_id}/step-{step}")))?
        .decode()
}

fn query_agent_model_job_optional(
    connection: &Connection,
    agent_id: &str,
    step: u32,
) -> Result<Option<AgentModelJob>, StorageError> {
    connection
        .query_row(
            &format!("{} WHERE agent_id = ?1 AND step = ?2", model_job_select()),
            params![agent_id, i64::from(step)],
            decode_agent_model_job_row,
        )
        .optional()?
        .map(StoredAgentModelJobRow::decode)
        .transpose()
}

pub(super) fn query_agent_model_job_by_id(
    connection: &Connection,
    job_id: &str,
) -> Result<AgentModelJob, StorageError> {
    connection
        .query_row(
            &format!("{} WHERE id = ?1", model_job_select()),
            [job_id],
            decode_agent_model_job_row,
        )
        .optional()?
        .ok_or_else(|| StorageError::AgentModelJobNotFound(job_id.to_owned()))?
        .decode()
}

fn require_open_agent_turn(
    connection: &Connection,
    agent: &AgentTurn,
) -> Result<SessionSummary, StorageError> {
    let summary = query_session_summary(connection, &agent.session_id)?;
    if summary.status != SessionStatus::Running
        || summary.active_turn_id.as_deref() != Some(agent.turn_id.as_str())
    {
        return Err(StorageError::CorruptData(format!(
            "agent turn `{}` disagrees with Session `{}` projection",
            agent.id, agent.session_id
        )));
    }
    let turn = query_session_turn(connection, &agent.session_id, &agent.turn_id)?;
    if turn.status != SessionTurnStatus::Open {
        return Err(StorageError::CorruptData(format!(
            "agent turn `{}` targets a non-open Session turn",
            agent.id
        )));
    }
    Ok(summary)
}

fn require_agent_finalization_capacity(
    connection: &Connection,
    agent: &AgentTurn,
) -> Result<(), StorageError> {
    let required = session_finalization_payload_reservation(
        &agent.turn_id,
        Some(&agent.provider_name),
        agent.model_name.as_deref(),
    )?;
    if require_session_finalization_capacity(
        connection,
        &agent.session_id,
        &agent.turn_id,
        2,
        required,
    )?
    .0 != 2
    {
        return Err(StorageError::FinalizationReservationUnavailable);
    }
    Ok(())
}

fn agent_actor_is_authorized(
    connection: &Connection,
    agent: &AgentTurn,
) -> Result<bool, StorageError> {
    let role = connection
        .query_row(
            r#"SELECT membership.role
               FROM sessions session
               JOIN accounts account ON account.id = session.account_id
               JOIN account_memberships membership
                 ON membership.account_id = session.account_id
               JOIN users user ON user.id = membership.user_id
               WHERE session.id = ?1 AND session.account_id = ?2
                 AND membership.user_id = ?3
                 AND membership.revision = ?4
                 AND membership.status = 'active'
                 AND account.status = 'active' AND user.status = 'active'"#,
            params![
                agent.session_id,
                agent.account_id.as_str(),
                agent.actor_user_id,
                u64_to_i64(
                    agent.actor_membership_revision.get(),
                    "agent membership revision"
                )?,
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    role.map(|role| decode_membership_role(&role))
        .transpose()
        .map(|role| role.is_some_and(|role| membership_allows(role, AccountCapability::Reply)))
}

fn agent_tool_approver_is_authorized(
    connection: &Connection,
    call: &AgentToolCall,
) -> Result<bool, StorageError> {
    if call.policy_decision != PolicyDecision::RequireApproval {
        return Ok(
            call.approving_actor_user_id.is_none() && call.approving_membership_revision.is_none()
        );
    }
    let (Some(user_id), Some(revision)) = (
        call.approving_actor_user_id.as_deref(),
        call.approving_membership_revision.as_ref(),
    ) else {
        return Err(StorageError::CorruptData(
            "approved agent tool is missing reviewer authority".into(),
        ));
    };
    let authorized: i64 = connection.query_row(
        r#"SELECT EXISTS(
               SELECT 1
               FROM accounts account
               JOIN account_memberships membership
                 ON membership.account_id = account.id
                AND membership.user_id = ?2
               JOIN users user ON user.id = membership.user_id
               WHERE account.id = ?1 AND account.status = 'active'
                 AND membership.role = 'owner' AND membership.status = 'active'
                 AND membership.revision = ?3 AND user.status = 'active'
           )"#,
        params![
            call.account_id.as_str(),
            user_id,
            u64_to_i64(revision.get(), "agent approving membership revision")?,
        ],
        |row| row.get(0),
    )?;
    Ok(authorized != 0)
}

fn tool_completion_kind(status: &AgentToolCallStatus) -> Result<ToolCompletionKind, StorageError> {
    match status {
        AgentToolCallStatus::Succeeded => Ok(ToolCompletionKind::Succeeded),
        AgentToolCallStatus::Failed => Ok(ToolCompletionKind::Failed),
        AgentToolCallStatus::Cancelled => Ok(ToolCompletionKind::Cancelled),
        AgentToolCallStatus::NotDispatched => Ok(ToolCompletionKind::NotDispatched),
        _ => Err(StorageError::InvalidAgentTransition(
            "a known started tool result must be succeeded, failed, cancelled, or not_dispatched"
                .into(),
        )),
    }
}

struct ContinuationSettlement<'a> {
    state: WorkflowState,
    next_request: Option<&'a Value>,
    transition: Option<(WorkflowCommand, workflows::Transition)>,
}

fn settle_known_result_continuation<'a>(
    continuation: WorkflowState,
    next_request_json: Option<&'a Value>,
    request_field: &'static str,
) -> Result<ContinuationSettlement<'a>, StorageError> {
    if continuation.status() != WorkflowStatus::ContinuationQueued {
        return Ok(ContinuationSettlement {
            state: continuation,
            next_request: None,
            transition: None,
        });
    }
    let start_command = WorkflowCommand::StartModel;
    let start = reduce(&continuation, start_command.clone())
        .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?;
    if start.state().status() == WorkflowStatus::Failed {
        return Ok(ContinuationSettlement {
            state: start.state().clone(),
            next_request: None,
            transition: Some((start_command, start)),
        });
    }
    if let Some(next_request_json) = next_request_json {
        validate_reply_json(
            next_request_json,
            request_field,
            AGENT_REQUEST_JSON_MAX_BYTES,
        )?;
        return Ok(ContinuationSettlement {
            state: continuation,
            next_request: Some(next_request_json),
            transition: None,
        });
    }
    let unavailable_command = WorkflowCommand::ContinuationUnavailable;
    let unavailable = reduce(&continuation, unavailable_command.clone())
        .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?;
    Ok(ContinuationSettlement {
        state: unavailable.state().clone(),
        next_request: None,
        transition: Some((unavailable_command, unavailable)),
    })
}

fn replay_agent_tool_completion(
    connection: &Connection,
    call: &AgentToolCall,
    agent: &AgentTurn,
    commit: &AgentToolCompletionCommit,
) -> Result<AgentToolCompletion, StorageError> {
    if call.status != commit.status
        || call.result_json.as_ref() != Some(&commit.result_json)
        || call.provider_request_id != commit.provider_request_id
    {
        return Err(StorageError::InvalidAgentTransition(
            "agent tool completion conflicts with its durable terminal state".into(),
        ));
    }
    let durable_next_request = query_agent_tool_completion_next_request(connection, &call.call_id)?;
    if durable_next_request.as_ref() != commit.next_request_json.as_ref() {
        return Err(StorageError::InvalidAgentTransition(
            "agent tool replay conflicts with its durable continuation request".into(),
        ));
    }
    let next_step = call
        .model_step
        .checked_add(1)
        .ok_or(StorageError::IntegerOutOfRange("agent model step"))?;
    if let Some(job) = query_agent_model_job_optional(connection, &agent.id, next_step)? {
        if durable_next_request.as_ref() != Some(&job.request_json) {
            return Err(StorageError::CorruptData(
                "agent tool completion request does not match its durable continuation job".into(),
            ));
        }
        Ok(AgentToolCompletion::ModelQueued {
            agent: Box::new(query_agent_turn(connection, &agent.id)?),
            job: Box::new(job),
        })
    } else if agent.status.is_terminal() {
        Ok(AgentToolCompletion::Terminal(Box::new(
            query_agent_terminal_completion(connection, agent)?,
        )))
    } else {
        Err(StorageError::CorruptData(
            "terminal agent tool result has no continuation model job".into(),
        ))
    }
}

fn query_agent_tool_completion_next_request(
    connection: &Connection,
    call_id: &str,
) -> Result<Option<Value>, StorageError> {
    let stored: Option<String> = connection.query_row(
        r#"SELECT completion_next_request_json
           FROM agent_tool_calls WHERE call_id = ?1"#,
        [call_id],
        |row| row.get(0),
    )?;
    let Some(stored) = stored else {
        return Err(StorageError::InvalidAgentTransition(
            "agent tool replay cannot verify its durable continuation request".into(),
        ));
    };
    let request: Value = serde_json::from_str(&stored)?;
    if request.is_null() {
        return Ok(None);
    }
    if !request.is_object() {
        return Err(StorageError::CorruptData(
            "stored agent tool completion request must be an object or null".into(),
        ));
    }
    Ok(Some(request))
}

struct AgentTransitionFact {
    command: WorkflowCommand,
    external_call: Option<ExternalCall>,
    emitted_result: Option<KnownToolResult>,
    emitted_result_digest: Option<Sha256Digest>,
    epoch_digest: Option<Sha256Digest>,
    source: FactSource,
    subject: Option<OperationRef>,
    input_digest: Option<Sha256Digest>,
    output_digest: Option<Sha256Digest>,
    next_request_digest: Option<Sha256Digest>,
}

fn model_subject(job: &AgentModelJob) -> OperationRef {
    OperationRef::Model {
        job_id: job.id.clone(),
        step: job.step,
    }
}

fn tool_subject(call: &AgentToolCall) -> OperationRef {
    OperationRef::Tool {
        call_id: call.call_id.clone(),
        ordinal: call.ordinal,
        model_step: call.model_step,
    }
}

fn model_request_digest(job: &AgentModelJob) -> Result<Sha256Digest, StorageError> {
    super::execution::digest_json(DigestDomain::ModelRequest, &job.request_json)
}

fn tool_input_digest(call: &AgentToolCall) -> Result<Sha256Digest, StorageError> {
    Sha256Digest::from_reference(&call.arguments_digest).map_err(|error| {
        StorageError::CorruptData(format!(
            "Agent tool `{}` has an invalid arguments digest: {error}",
            call.call_id
        ))
    })
}

#[allow(clippy::too_many_arguments)]
fn persist_agent_workflow_transition(
    connection: &Connection,
    agent: &mut AgentTurn,
    state: WorkflowState,
    pending_call_id: Option<&str>,
    last_error: Option<&Value>,
    completed_at: Option<&str>,
    fact: AgentTransitionFact,
    timestamp: &str,
) -> Result<(), StorageError> {
    let before = agent.clone();
    let emitted_result_digest = if fact.emitted_result.is_some() {
        match &fact.command {
            WorkflowCommand::ModelToolProposal {
                disposition: ProposalDisposition::Deny { .. },
            } => fact.emitted_result_digest.clone(),
            _ => fact
                .emitted_result_digest
                .clone()
                .or_else(|| fact.output_digest.clone()),
        }
    } else {
        None
    };
    update_agent_workflow(
        connection,
        agent,
        state.clone(),
        pending_call_id,
        last_error,
        completed_at,
        timestamp,
    )?;
    super::execution::append_transition(
        connection,
        &before,
        agent,
        super::execution::TransitionFact {
            command: fact.command,
            state,
            external_call: fact.external_call,
            emitted_result: fact.emitted_result,
            emitted_result_digest,
            epoch_digest: fact.epoch_digest.as_ref(),
            source: fact.source,
            subject: fact.subject,
            input_digest: fact.input_digest,
            output_digest: fact.output_digest,
            next_request_digest: fact.next_request_digest,
        },
        timestamp,
    )?;
    Ok(())
}

fn update_agent_workflow(
    connection: &Connection,
    agent: &mut AgentTurn,
    state: WorkflowState,
    pending_call_id: Option<&str>,
    last_error: Option<&Value>,
    completed_at: Option<&str>,
    timestamp: &str,
) -> Result<(), StorageError> {
    state
        .validate()
        .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?;
    let status = status_from_workflow(state.status());
    let terminal = status.is_terminal();
    if terminal != completed_at.is_some()
        || matches!(
            status,
            AgentTurnStatus::WaitingApproval
                | AgentTurnStatus::ToolQueued
                | AgentTurnStatus::ToolRunning
        ) != pending_call_id.is_some()
        || matches!(
            status,
            AgentTurnStatus::Failed | AgentTurnStatus::NeedsAttention
        ) != last_error.is_some()
    {
        return Err(StorageError::InvalidAgentTransition(
            "agent SQL projection does not match workflow state".into(),
        ));
    }
    let next_revision = agent
        .revision
        .checked_add(1)
        .ok_or(StorageError::IntegerOutOfRange("agent revision"))?;
    let changed = connection.execute(
        r#"UPDATE agent_turns
           SET status = ?1, model_steps = ?2, tool_calls = ?3,
               tool_result_bytes = ?4, revision = ?5, pending_call_id = ?6,
               workflow_state_json = ?7, last_error_json = ?8,
               updated_at = ?9, completed_at = ?10
           WHERE id = ?11 AND revision = ?12"#,
        params![
            agent_status_to_db(&status),
            i64::from(state.model_steps()),
            i64::from(state.tool_calls()),
            u64_to_i64(state.tool_result_bytes(), "agent tool result bytes")?,
            u64_to_i64(next_revision, "agent revision")?,
            pending_call_id,
            serde_json::to_string(&state)?,
            last_error.map(serde_json::to_string).transpose()?,
            timestamp,
            completed_at,
            agent.id,
            u64_to_i64(agent.revision, "agent revision")?,
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    *agent = query_agent_turn(connection, &agent.id)?;
    Ok(())
}

fn interrupt_agent_turn(
    connection: &Connection,
    agent: &AgentTurn,
    reason: &str,
) -> Result<AgentTerminalCompletion, StorageError> {
    if !matches!(
        agent.status,
        AgentTurnStatus::Failed | AgentTurnStatus::NeedsAttention
    ) {
        return Err(StorageError::InvalidAgentTransition(
            "only a failed or indeterminate agent may interrupt its Session turn".into(),
        ));
    }
    let summary = require_open_agent_turn(connection, agent)?;
    let timestamp = now();
    let sequence = next_session_sequence(summary.sequence)?;
    let event = build_session_event(
        &agent.session_id,
        sequence,
        &timestamp,
        SessionEventData::TurnInterrupted {
            turn_id: agent.turn_id.clone(),
            reason: reason.to_owned(),
        },
    );
    let payload = encode_event_payload(&event)?;
    require_session_finalization_capacity(
        connection,
        &agent.session_id,
        &agent.turn_id,
        1,
        payload.bytes,
    )?;
    let changed = connection.execute(
        r#"UPDATE session_turns SET status = 'interrupted', completed_at = ?1
           WHERE session_id = ?2 AND id = ?3 AND status = 'open'"#,
        params![timestamp, agent.session_id, agent.turn_id],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    insert_session_event(connection, &agent.session_id, &event, &payload)?;
    update_session_projection(
        connection,
        &agent.session_id,
        summary.sequence,
        SessionStatus::NeedsAttention,
        None,
        sequence,
        &timestamp,
    )?;
    finish_session_finalization(
        connection,
        &agent.session_id,
        &agent.turn_id,
        1,
        payload.bytes,
    )?;
    Ok(AgentTerminalCompletion {
        agent: query_agent_turn(connection, &agent.id)?,
        session: query_session_summary(connection, &agent.session_id)?,
        turn: query_session_turn(connection, &agent.session_id, &agent.turn_id)?,
        event,
        replayed: false,
    })
}

fn agent_turn_select() -> &'static str {
    r#"SELECT id, account_id, actor_user_id, actor_membership_revision,
              session_id, turn_id, deployment_manifest_digest,
              environment, provider_name, model_name,
              status, model_steps, tool_calls, tool_result_bytes, revision,
              pending_call_id, workflow_state_json, last_error_json,
              created_at, updated_at, completed_at
       FROM agent_turns"#
}

fn model_job_select() -> &'static str {
    r#"SELECT id, agent_id, account_id, actor_user_id, actor_membership_revision,
              session_id, turn_id, step, provider_name, model_name,
              status, attempt, request_json, response_json, error_json,
              queued_at, started_at, finished_at
       FROM agent_model_jobs"#
}

struct StoredAgentTurnRow {
    id: String,
    account_id: String,
    actor_user_id: String,
    actor_membership_revision: i64,
    session_id: String,
    turn_id: String,
    deployment_manifest_digest: Option<String>,
    environment: String,
    provider_name: String,
    model_name: Option<String>,
    status: String,
    model_steps: i64,
    tool_calls: i64,
    tool_result_bytes: i64,
    revision: i64,
    pending_call_id: Option<String>,
    workflow_state_json: String,
    last_error_json: Option<String>,
    created_at: String,
    updated_at: String,
    completed_at: Option<String>,
}

impl StoredAgentTurnRow {
    fn decode(self) -> Result<AgentTurn, StorageError> {
        let workflow_state: WorkflowState = serde_json::from_str(&self.workflow_state_json)?;
        workflow_state.validate().map_err(|error| {
            StorageError::CorruptData(format!("invalid agent workflow state: {error}"))
        })?;
        let status = agent_status_from_db(&self.status)?;
        if status != status_from_workflow(workflow_state.status())
            || i64_to_u64(self.model_steps, "agent model steps")?
                != u64::from(workflow_state.model_steps())
            || i64_to_u64(self.tool_calls, "agent tool calls")?
                != u64::from(workflow_state.tool_calls())
            || i64_to_u64(self.tool_result_bytes, "agent tool result bytes")?
                != workflow_state.tool_result_bytes()
        {
            return Err(StorageError::CorruptData(
                "agent workflow state disagrees with its SQL projection".into(),
            ));
        }
        Ok(AgentTurn {
            id: self.id,
            account_id: AccountId::from_persistence(self.account_id).map_err(|error| {
                StorageError::CorruptData(format!("invalid stored agent account ID: {error}"))
            })?,
            actor_user_id: self.actor_user_id,
            actor_membership_revision: MembershipRevision::new(i64_to_u64(
                self.actor_membership_revision,
                "agent membership revision",
            )?)
            .map_err(|error| {
                StorageError::CorruptData(format!(
                    "invalid stored agent membership revision: {error}"
                ))
            })?,
            session_id: self.session_id,
            turn_id: self.turn_id,
            deployment_manifest_digest: self.deployment_manifest_digest,
            environment: self.environment,
            provider_name: self.provider_name,
            model_name: self.model_name,
            status,
            model_steps: u32::try_from(self.model_steps)
                .map_err(|_| StorageError::IntegerOutOfRange("agent model steps"))?,
            tool_calls: u32::try_from(self.tool_calls)
                .map_err(|_| StorageError::IntegerOutOfRange("agent tool calls"))?,
            tool_result_bytes: i64_to_u64(self.tool_result_bytes, "agent tool result bytes")?,
            revision: i64_to_u64(self.revision, "agent revision")?,
            pending_call_id: self.pending_call_id,
            workflow_state,
            last_error_json: self
                .last_error_json
                .map(|value| serde_json::from_str(&value))
                .transpose()?,
            created_at: self.created_at,
            updated_at: self.updated_at,
            completed_at: self.completed_at,
        })
    }
}

fn decode_agent_turn_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredAgentTurnRow> {
    Ok(StoredAgentTurnRow {
        id: row.get(0)?,
        account_id: row.get(1)?,
        actor_user_id: row.get(2)?,
        actor_membership_revision: row.get(3)?,
        session_id: row.get(4)?,
        turn_id: row.get(5)?,
        deployment_manifest_digest: row.get(6)?,
        environment: row.get(7)?,
        provider_name: row.get(8)?,
        model_name: row.get(9)?,
        status: row.get(10)?,
        model_steps: row.get(11)?,
        tool_calls: row.get(12)?,
        tool_result_bytes: row.get(13)?,
        revision: row.get(14)?,
        pending_call_id: row.get(15)?,
        workflow_state_json: row.get(16)?,
        last_error_json: row.get(17)?,
        created_at: row.get(18)?,
        updated_at: row.get(19)?,
        completed_at: row.get(20)?,
    })
}

struct StoredAgentModelJobRow {
    id: String,
    agent_id: String,
    account_id: String,
    actor_user_id: String,
    actor_membership_revision: i64,
    session_id: String,
    turn_id: String,
    step: i64,
    provider_name: String,
    model_name: Option<String>,
    status: String,
    attempt: i64,
    request_json: String,
    response_json: Option<String>,
    error_json: Option<String>,
    queued_at: String,
    started_at: Option<String>,
    finished_at: Option<String>,
}

impl StoredAgentModelJobRow {
    fn decode(self) -> Result<AgentModelJob, StorageError> {
        Ok(AgentModelJob {
            id: self.id,
            agent_id: self.agent_id,
            account_id: AccountId::from_persistence(self.account_id).map_err(|error| {
                StorageError::CorruptData(format!("invalid stored agent account ID: {error}"))
            })?,
            actor_user_id: self.actor_user_id,
            actor_membership_revision: MembershipRevision::new(i64_to_u64(
                self.actor_membership_revision,
                "agent model membership revision",
            )?)
            .map_err(|error| {
                StorageError::CorruptData(format!(
                    "invalid stored agent model membership revision: {error}"
                ))
            })?,
            session_id: self.session_id,
            turn_id: self.turn_id,
            step: u32::try_from(self.step)
                .map_err(|_| StorageError::IntegerOutOfRange("agent model step"))?,
            provider_name: self.provider_name,
            model_name: self.model_name,
            status: model_job_status_from_db(&self.status)?,
            attempt: u32::try_from(self.attempt)
                .map_err(|_| StorageError::IntegerOutOfRange("agent model attempt"))?,
            request_json: serde_json::from_str(&self.request_json)?,
            response_json: self
                .response_json
                .map(|value| serde_json::from_str(&value))
                .transpose()?,
            error_json: self
                .error_json
                .map(|value| serde_json::from_str(&value))
                .transpose()?,
            queued_at: self.queued_at,
            started_at: self.started_at,
            finished_at: self.finished_at,
        })
    }
}

fn decode_agent_model_job_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredAgentModelJobRow> {
    Ok(StoredAgentModelJobRow {
        id: row.get(0)?,
        agent_id: row.get(1)?,
        account_id: row.get(2)?,
        actor_user_id: row.get(3)?,
        actor_membership_revision: row.get(4)?,
        session_id: row.get(5)?,
        turn_id: row.get(6)?,
        step: row.get(7)?,
        provider_name: row.get(8)?,
        model_name: row.get(9)?,
        status: row.get(10)?,
        attempt: row.get(11)?,
        request_json: row.get(12)?,
        response_json: row.get(13)?,
        error_json: row.get(14)?,
        queued_at: row.get(15)?,
        started_at: row.get(16)?,
        finished_at: row.get(17)?,
    })
}

pub(super) fn query_agent_tool_call(
    connection: &Connection,
    call_id: &str,
) -> Result<AgentToolCall, StorageError> {
    connection
        .query_row(
            &format!("{} WHERE call_id = ?1", agent_tool_call_select()),
            [call_id],
            decode_agent_tool_call_row,
        )
        .optional()?
        .ok_or_else(|| StorageError::AgentToolCallNotFound(call_id.to_owned()))?
        .decode()
}

fn query_agent_tool_call_for_step(
    connection: &Connection,
    agent_id: &str,
    model_step: u32,
) -> Result<Option<AgentToolCall>, StorageError> {
    connection
        .query_row(
            &format!(
                "{} WHERE agent_id = ?1 AND model_step = ?2",
                agent_tool_call_select()
            ),
            params![agent_id, i64::from(model_step)],
            decode_agent_tool_call_row,
        )
        .optional()?
        .map(StoredAgentToolCallRow::decode)
        .transpose()
}

fn query_agent_tool_calls(
    connection: &Connection,
    agent_id: &str,
) -> Result<Vec<AgentToolCall>, StorageError> {
    let mut statement = connection.prepare(&format!(
        "{} WHERE agent_id = ?1 ORDER BY ordinal",
        agent_tool_call_select()
    ))?;
    let rows = statement
        .query_map([agent_id], decode_agent_tool_call_row)?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(StoredAgentToolCallRow::decode)
        .collect()
}

fn agent_tool_call_select() -> &'static str {
    r#"SELECT call_id, agent_id, account_id, session_id, turn_id,
              provider_call_id, ordinal, model_step, tool_name, tool_version,
              arguments_json, arguments_digest, effect, sandbox_profile,
              executor_status, policy_decision, policy_revision, status,
              approving_actor_user_id, approving_membership_revision,
              review_note, reviewed_at, result_json, provider_request_id,
              created_at, started_at, finished_at
       FROM agent_tool_calls"#
}

struct StoredAgentToolCallRow {
    call_id: String,
    agent_id: String,
    account_id: String,
    session_id: String,
    turn_id: String,
    provider_call_id: String,
    ordinal: i64,
    model_step: i64,
    tool_name: String,
    tool_version: String,
    arguments_json: String,
    arguments_digest: String,
    effect: String,
    sandbox_profile: String,
    executor_status: String,
    policy_decision: String,
    policy_revision: String,
    status: String,
    approving_actor_user_id: Option<String>,
    approving_membership_revision: Option<i64>,
    review_note: Option<String>,
    reviewed_at: Option<String>,
    result_json: Option<String>,
    provider_request_id: Option<String>,
    created_at: String,
    started_at: Option<String>,
    finished_at: Option<String>,
}

impl StoredAgentToolCallRow {
    fn decode(self) -> Result<AgentToolCall, StorageError> {
        Ok(AgentToolCall {
            call_id: self.call_id,
            agent_id: self.agent_id,
            account_id: AccountId::from_persistence(self.account_id).map_err(|error| {
                StorageError::CorruptData(format!("invalid stored agent call account ID: {error}"))
            })?,
            session_id: self.session_id,
            turn_id: self.turn_id,
            provider_call_id: self.provider_call_id,
            ordinal: u32::try_from(self.ordinal)
                .map_err(|_| StorageError::IntegerOutOfRange("agent call ordinal"))?,
            model_step: u32::try_from(self.model_step)
                .map_err(|_| StorageError::IntegerOutOfRange("agent call model step"))?,
            tool_name: self.tool_name,
            tool_version: self.tool_version,
            arguments_json: serde_json::from_str(&self.arguments_json)?,
            arguments_digest: self.arguments_digest,
            effect: tool_effect_from_db(&self.effect)?,
            sandbox_profile: sandbox_profile_from_db(&self.sandbox_profile)?,
            executor_status: executor_status_from_db(&self.executor_status)?,
            policy_decision: policy_decision_from_db(&self.policy_decision)?,
            policy_revision: self.policy_revision,
            status: agent_tool_status_from_db(&self.status)?,
            approving_actor_user_id: self.approving_actor_user_id,
            approving_membership_revision: self
                .approving_membership_revision
                .map(|revision| {
                    MembershipRevision::new(i64_to_u64(
                        revision,
                        "agent approving membership revision",
                    )?)
                    .map_err(|error| {
                        StorageError::CorruptData(format!(
                            "invalid agent approving membership revision: {error}"
                        ))
                    })
                })
                .transpose()?,
            review_note: self.review_note,
            reviewed_at: self.reviewed_at,
            result_json: self
                .result_json
                .map(|value| serde_json::from_str(&value))
                .transpose()?,
            provider_request_id: self.provider_request_id,
            created_at: self.created_at,
            started_at: self.started_at,
            finished_at: self.finished_at,
        })
    }
}

fn decode_agent_tool_call_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredAgentToolCallRow> {
    Ok(StoredAgentToolCallRow {
        call_id: row.get(0)?,
        agent_id: row.get(1)?,
        account_id: row.get(2)?,
        session_id: row.get(3)?,
        turn_id: row.get(4)?,
        provider_call_id: row.get(5)?,
        ordinal: row.get(6)?,
        model_step: row.get(7)?,
        tool_name: row.get(8)?,
        tool_version: row.get(9)?,
        arguments_json: row.get(10)?,
        arguments_digest: row.get(11)?,
        effect: row.get(12)?,
        sandbox_profile: row.get(13)?,
        executor_status: row.get(14)?,
        policy_decision: row.get(15)?,
        policy_revision: row.get(16)?,
        status: row.get(17)?,
        approving_actor_user_id: row.get(18)?,
        approving_membership_revision: row.get(19)?,
        review_note: row.get(20)?,
        reviewed_at: row.get(21)?,
        result_json: row.get(22)?,
        provider_request_id: row.get(23)?,
        created_at: row.get(24)?,
        started_at: row.get(25)?,
        finished_at: row.get(26)?,
    })
}

fn agent_status_from_db(value: &str) -> Result<AgentTurnStatus, StorageError> {
    match value {
        "waiting_model" => Ok(AgentTurnStatus::WaitingModel),
        "model_running" => Ok(AgentTurnStatus::ModelRunning),
        "waiting_approval" => Ok(AgentTurnStatus::WaitingApproval),
        "tool_queued" => Ok(AgentTurnStatus::ToolQueued),
        "tool_running" => Ok(AgentTurnStatus::ToolRunning),
        "succeeded" => Ok(AgentTurnStatus::Succeeded),
        "failed" => Ok(AgentTurnStatus::Failed),
        "needs_attention" => Ok(AgentTurnStatus::NeedsAttention),
        other => Err(StorageError::CorruptData(format!(
            "unknown agent turn status `{other}`"
        ))),
    }
}

fn agent_status_to_db(status: &AgentTurnStatus) -> &'static str {
    match status {
        AgentTurnStatus::WaitingModel => "waiting_model",
        AgentTurnStatus::ModelRunning => "model_running",
        AgentTurnStatus::WaitingApproval => "waiting_approval",
        AgentTurnStatus::ToolQueued => "tool_queued",
        AgentTurnStatus::ToolRunning => "tool_running",
        AgentTurnStatus::Succeeded => "succeeded",
        AgentTurnStatus::Failed => "failed",
        AgentTurnStatus::NeedsAttention => "needs_attention",
    }
}

fn status_from_workflow(status: WorkflowStatus) -> AgentTurnStatus {
    match status {
        WorkflowStatus::ModelQueued | WorkflowStatus::ContinuationQueued => {
            AgentTurnStatus::WaitingModel
        }
        WorkflowStatus::ModelStarted => AgentTurnStatus::ModelRunning,
        WorkflowStatus::WaitingApproval => AgentTurnStatus::WaitingApproval,
        WorkflowStatus::ToolQueued => AgentTurnStatus::ToolQueued,
        WorkflowStatus::ToolStarted => AgentTurnStatus::ToolRunning,
        WorkflowStatus::Completed => AgentTurnStatus::Succeeded,
        WorkflowStatus::Failed => AgentTurnStatus::Failed,
        WorkflowStatus::NeedsAttention => AgentTurnStatus::NeedsAttention,
    }
}

fn model_job_status_from_db(value: &str) -> Result<AgentModelJobStatus, StorageError> {
    match value {
        "queued" => Ok(AgentModelJobStatus::Queued),
        "started" => Ok(AgentModelJobStatus::Started),
        "succeeded" => Ok(AgentModelJobStatus::Succeeded),
        "failed" => Ok(AgentModelJobStatus::Failed),
        "outcome_unknown" => Ok(AgentModelJobStatus::OutcomeUnknown),
        other => Err(StorageError::CorruptData(format!(
            "unknown agent model job status `{other}`"
        ))),
    }
}

fn executor_status_to_db(status: &ToolExecutorStatus) -> &'static str {
    match status {
        ToolExecutorStatus::Available => "available",
        ToolExecutorStatus::Unavailable => "unavailable",
    }
}

fn policy_decision_to_db(decision: &PolicyDecision) -> &'static str {
    match decision {
        PolicyDecision::Allow => "allow",
        PolicyDecision::RequireApproval => "require_approval",
        PolicyDecision::Deny => "deny",
    }
}

fn policy_decision_from_db(value: &str) -> Result<PolicyDecision, StorageError> {
    match value {
        "allow" => Ok(PolicyDecision::Allow),
        "require_approval" => Ok(PolicyDecision::RequireApproval),
        "deny" => Ok(PolicyDecision::Deny),
        other => Err(StorageError::CorruptData(format!(
            "unknown agent policy decision `{other}`"
        ))),
    }
}

fn executor_status_from_db(value: &str) -> Result<ToolExecutorStatus, StorageError> {
    match value {
        "available" => Ok(ToolExecutorStatus::Available),
        "unavailable" => Ok(ToolExecutorStatus::Unavailable),
        other => Err(StorageError::CorruptData(format!(
            "unknown agent executor status `{other}`"
        ))),
    }
}

fn agent_tool_status_to_db(status: &AgentToolCallStatus) -> &'static str {
    match status {
        AgentToolCallStatus::WaitingApproval => "waiting_approval",
        AgentToolCallStatus::Queued => "queued",
        AgentToolCallStatus::Running => "started",
        AgentToolCallStatus::Succeeded => "succeeded",
        AgentToolCallStatus::Failed => "failed",
        AgentToolCallStatus::Cancelled => "cancelled",
        AgentToolCallStatus::Rejected => "rejected",
        AgentToolCallStatus::NotDispatched => "not_dispatched",
        AgentToolCallStatus::OutcomeUnknown => "outcome_unknown",
    }
}

fn agent_tool_status_from_db(value: &str) -> Result<AgentToolCallStatus, StorageError> {
    match value {
        "waiting_approval" => Ok(AgentToolCallStatus::WaitingApproval),
        "queued" => Ok(AgentToolCallStatus::Queued),
        "started" => Ok(AgentToolCallStatus::Running),
        "succeeded" => Ok(AgentToolCallStatus::Succeeded),
        "failed" => Ok(AgentToolCallStatus::Failed),
        "cancelled" => Ok(AgentToolCallStatus::Cancelled),
        "rejected" => Ok(AgentToolCallStatus::Rejected),
        "not_dispatched" => Ok(AgentToolCallStatus::NotDispatched),
        "outcome_unknown" => Ok(AgentToolCallStatus::OutcomeUnknown),
        other => Err(StorageError::CorruptData(format!(
            "unknown agent tool status `{other}`"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_job_identity_is_stable_and_position_bound() {
        assert_eq!(model_job_id("agent-a", 2), model_job_id("agent-a", 2));
        assert_ne!(model_job_id("agent-a", 1), model_job_id("agent-a", 2));
        assert_ne!(model_job_id("agent-a", 1), model_job_id("agent-b", 1));
    }

    #[test]
    fn agent_tool_arguments_enforce_the_16_kib_serialized_boundary() {
        let empty_arguments = json!({"payload": ""});
        let envelope_bytes = serde_json::to_vec(&empty_arguments).unwrap().len();
        let spec_with_serialized_bytes = |serialized_bytes: usize| {
            let arguments_json = json!({
                "payload": "x".repeat(serialized_bytes - envelope_bytes),
            });
            assert_eq!(
                serde_json::to_vec(&arguments_json).unwrap().len(),
                serialized_bytes
            );
            AgentToolCallSpec {
                call_id: "agent-call-arguments-boundary".into(),
                provider_call_id: "provider-call-arguments-boundary".into(),
                tool_name: "workspace.list".into(),
                tool_version: "1.0.0".into(),
                arguments_digest: tools::arguments_digest(&arguments_json),
                arguments_json,
                effect: ToolEffect::ReadOnly,
                sandbox_profile: SandboxProfile::ReadOnly,
                executor_status: ToolExecutorStatus::Available,
                policy_decision: PolicyDecision::Allow,
                policy_revision: "local/v1".into(),
            }
        };

        assert!(
            validate_agent_tool_call_spec(&spec_with_serialized_bytes(
                AGENT_TOOL_ARGUMENTS_MAX_BYTES
            ))
            .is_ok()
        );
        assert!(matches!(
            validate_agent_tool_call_spec(&spec_with_serialized_bytes(
                AGENT_TOOL_ARGUMENTS_MAX_BYTES + 1
            )),
            Err(StorageError::InvalidReplyTransition(_))
        ));
    }
}
