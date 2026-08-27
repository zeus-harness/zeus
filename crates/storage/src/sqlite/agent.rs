//! Session-native durable Agent Loop persistence.
//!
//! Every external operation crosses a committed `started` checkpoint. Known
//! results and their next model request commit together; indeterminate results
//! terminate the Session turn as `needs_attention` and are never re-queued.

use super::*;
use crate::{
    AGENT_SYSTEM_PROMPT_MAX_BYTES, AgentFinalCompletion, AgentKnowledgeContextExplain,
    AgentModelClaimOutcome, AgentModelCompletion, AgentModelFailureCommit, AgentModelJobStatus,
    AgentModelResolution, AgentModelStartOutcome, AgentModelSuccessCommit, AgentOperationClaim,
    AgentOperationKind, AgentPreparedModel, AgentPreparedTool, AgentPromptCommit, AgentPromptState,
    AgentPromptUpdateResult, AgentReviewCommit, AgentReviewContext, AgentReviewResult,
    AgentTerminalCompletion, AgentToolCall, AgentToolCallSpec, AgentToolClaimOutcome,
    AgentToolCompletion, AgentToolCompletionCommit, AgentToolOutcomeUnknownCommit,
    AgentToolStartOutcome, AgentToolWork, AgentTurnReceiptProbe,
    DEFAULT_SESSION_AGENT_PROMPT_REVISION, DEFAULT_SESSION_AGENT_SYSTEM_PROMPT,
    KnowledgeCatalogCommit, KnowledgeCatalogRevisionPage, KnowledgeCatalogRevisionSummary,
    KnowledgeCatalogState, KnowledgeCatalogUpdateResult, SESSION_AGENT_PROMPT_ID,
};
use ::execution::{DigestDomain, FactSource, OperationRef, Sha256Digest};
use deployment::{ManifestEnvelope, prompt_content_digest};
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
const AGENT_KNOWLEDGE_BINDING_SCHEMA_VERSION: u16 = 1;
const AGENT_KNOWLEDGE_BINDING_MAX_BYTES: usize = 64 * 1024;
const AGENT_KNOWLEDGE_BINDING_DIGEST_DOMAIN: &[u8] =
    b"zeus.agent-knowledge-context-binding.sha256.v1";
const AGENT_KNOWLEDGE_LEGACY_SET_DIGEST_DOMAIN: &[u8] =
    b"zeus.agent-knowledge-legacy-set.sha256.v1\0";
const AGENT_OPERATION_HOLDER_MAX_BYTES: usize = 128;
const AGENT_OPERATION_CLAIM_TTL_SECONDS: i64 = 30;
const KNOWLEDGE_CATALOG_MAX_REVISIONS_PER_ACCOUNT: u64 = 256;
const KNOWLEDGE_CORPUS_MAX_REVISIONS_PER_ACCOUNT: i64 = 128;
const KNOWLEDGE_CORPUS_MAX_ENVELOPE_BYTES_PER_ACCOUNT: i64 = 64 * 1024 * 1024;
const AGENT_PROMPT_MAX_REVISIONS_PER_ACCOUNT: u64 = 256;
const AGENT_PROMPT_MAX_DISTINCT_REVISIONS_PER_ACCOUNT: i64 = 128;
const AGENT_PROMPT_MAX_CONTENT_BYTES_PER_ACCOUNT: i64 = 2 * 1024 * 1024;

#[derive(Serialize)]
struct AgentKnowledgeContextBinding<'a> {
    schema_version: u16,
    account_id: &'a str,
    actor_user_id: &'a str,
    actor_membership_revision: u64,
    session_id: &'a str,
    turn_id: &'a str,
    agent_id: &'a str,
    initial_model_job_id: &'a str,
    corpus_digest: &'a str,
    snapshot_digest: &'a str,
    query_digest: &'a str,
    context_digest: &'a str,
    context_bytes: u32,
    canonical_context: &'a str,
    created_at: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AgentKnowledgeDigests {
    pub context: Sha256Digest,
    pub corpus: Sha256Digest,
    pub snapshot: Sha256Digest,
}

struct StoredAgentKnowledgeContext {
    digest: String,
    schema_version: i64,
    account_id: String,
    actor_user_id: String,
    actor_membership_revision: i64,
    session_id: String,
    turn_id: String,
    agent_id: String,
    initial_model_job_id: String,
    corpus_digest: String,
    snapshot_digest: String,
    query_digest: String,
    context_digest: String,
    context_bytes: i64,
    canonical_context: String,
    snapshot_envelope_json: String,
    binding_json: String,
    created_at: String,
}

struct StoredLegacyAgentKnowledgeBoundary {
    agent_id: String,
    initial_model_job_id: String,
    execution_origin_fact_digest: String,
}

struct StoredLegacyAgentKnowledgeCommitment {
    agent_count: i64,
    set_digest: String,
}

impl SqliteStore {
    /// Durably prepares one queued model step without authorizing external I/O.
    /// A process crash in this phase is safe to reclaim because the job and
    /// Agent workflow both remain queued.
    pub async fn prepare_next_agent_model(
        &self,
        current_manifest: &ManifestEnvelope,
        holder_id: &str,
    ) -> Result<AgentModelClaimOutcome, StorageError> {
        validate_manifest_envelope(current_manifest, "current Agent deployment manifest")?;
        let holder_id = normalized_account_value(
            holder_id,
            "Agent operation holder ID",
            AGENT_OPERATION_HOLDER_MAX_BYTES,
        )?
        .to_owned();
        let current_manifest = current_manifest.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            prepare_next_agent_model(connection, &current_manifest, &holder_id, &physical_limits)
        })
        .await
    }

    /// Releases one exact prepared model claim into the durable `started`
    /// checkpoint. Only one retained execution context may use the returned
    /// job for provider I/O; exact response replay does not grant a second
    /// external invocation.
    pub async fn start_prepared_agent_model(
        &self,
        claim: &AgentOperationClaim,
        current_manifest: &ManifestEnvelope,
    ) -> Result<AgentModelStartOutcome, StorageError> {
        claim.validate()?;
        if claim.kind != AgentOperationKind::Model {
            return Err(StorageError::InvalidAgentTransition(
                "a model start requires a model operation claim".into(),
            ));
        }
        validate_manifest_envelope(current_manifest, "current Agent deployment manifest")?;
        let claim = claim.clone();
        let current_manifest = current_manifest.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            start_prepared_agent_model(connection, &claim, &current_manifest, &physical_limits)
        })
        .await
    }

    /// Compatibility façade that prepares and starts a model operation before
    /// returning it. Server workers use the explicit two-phase methods above;
    /// this keeps direct storage integrations on their original contract.
    pub async fn claim_next_agent_model(
        &self,
        current_manifest: &ManifestEnvelope,
    ) -> Result<AgentModelClaimOutcome, StorageError> {
        match self
            .prepare_next_agent_model(current_manifest, "storage-direct-model-v1")
            .await?
        {
            AgentModelClaimOutcome::Prepared(prepared) => {
                match self
                    .start_prepared_agent_model(&prepared.claim, current_manifest)
                    .await?
                {
                    AgentModelStartOutcome::Started(job) => {
                        Ok(AgentModelClaimOutcome::Claimed(job))
                    }
                    AgentModelStartOutcome::Rejected(completion) => {
                        Ok(AgentModelClaimOutcome::Rejected(completion))
                    }
                }
            }
            outcome => Ok(outcome),
        }
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

    /// Durably prepares one already-admitted tool call without authorizing
    /// connector I/O. Its exact model transcript remains attached to the
    /// returned preparation.
    pub async fn prepare_next_agent_tool(
        &self,
        current_manifest: &ManifestEnvelope,
        holder_id: &str,
    ) -> Result<AgentToolClaimOutcome, StorageError> {
        validate_manifest_envelope(current_manifest, "current Agent deployment manifest")?;
        let holder_id = normalized_account_value(
            holder_id,
            "Agent operation holder ID",
            AGENT_OPERATION_HOLDER_MAX_BYTES,
        )?
        .to_owned();
        let current_manifest = current_manifest.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            prepare_next_agent_tool(connection, &current_manifest, &holder_id, &physical_limits)
        })
        .await
    }

    /// Releases one exact prepared tool claim into the durable `started`
    /// checkpoint. Only one retained execution context may use the returned
    /// work for connector I/O; exact response replay does not grant a second
    /// external invocation.
    pub async fn start_prepared_agent_tool(
        &self,
        claim: &AgentOperationClaim,
        current_manifest: &ManifestEnvelope,
    ) -> Result<AgentToolStartOutcome, StorageError> {
        claim.validate()?;
        if claim.kind != AgentOperationKind::Tool {
            return Err(StorageError::InvalidAgentTransition(
                "a tool start requires a tool operation claim".into(),
            ));
        }
        validate_manifest_envelope(current_manifest, "current Agent deployment manifest")?;
        let claim = claim.clone();
        let current_manifest = current_manifest.clone();
        let physical_limits = self.physical_limits.clone();
        self.with_progress_connection(move |connection| {
            start_prepared_agent_tool(connection, &claim, &current_manifest, &physical_limits)
        })
        .await
    }

    /// Compatibility façade that prepares and starts a tool operation before
    /// returning it. Server workers use the explicit two-phase methods above.
    pub async fn claim_next_agent_tool(
        &self,
        current_manifest: &ManifestEnvelope,
    ) -> Result<AgentToolClaimOutcome, StorageError> {
        match self
            .prepare_next_agent_tool(current_manifest, "storage-direct-tool-v1")
            .await?
        {
            AgentToolClaimOutcome::Prepared(prepared) => {
                match self
                    .start_prepared_agent_tool(&prepared.claim, current_manifest)
                    .await?
                {
                    AgentToolStartOutcome::Started(work) => {
                        Ok(AgentToolClaimOutcome::Claimed(work))
                    }
                    AgentToolStartOutcome::Rejected(completion) => {
                        Ok(AgentToolClaimOutcome::Rejected(completion))
                    }
                }
            }
            outcome => Ok(outcome),
        }
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

    /// Returns the exact immutable knowledge selection bound to an Agent turn.
    /// Authorization and account isolation are checked before selected content
    /// is exposed. Frozen pre-v22 legacy turns return `None`.
    pub async fn agent_knowledge_context_for_actor(
        &self,
        context: &AuthzContext,
        session_id: &str,
        turn_id: &str,
    ) -> Result<Option<AgentKnowledgeContextExplain>, StorageError> {
        let context = validated_authz_context(context)?;
        let session_id = validated_durable_reference(session_id, "session ID")?.to_owned();
        let turn_id = validated_durable_reference(turn_id, "turn ID")?.to_owned();
        self.with_connection(move |connection| {
            query_agent_knowledge_context_for_actor(connection, &context, &session_id, &turn_id)
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

fn prepare_next_agent_model(
    connection: &mut Connection,
    current_manifest: &ManifestEnvelope,
    holder_id: &str,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<AgentModelClaimOutcome, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (timestamp, expires_at) = agent_operation_claim_window()?;
    expire_prepared_agent_operation_claims(&transaction, &timestamp)?;
    if let Some(claim) = query_prepared_agent_operation_claim_for_holder(
        &transaction,
        AgentOperationKind::Model,
        holder_id,
    )? {
        let job = query_agent_model_job_by_id(&transaction, &claim.operation_id)?;
        if job.agent_id != claim.agent_id
            || job.status != AgentModelJobStatus::Queued
            || job.attempt != 0
        {
            return Err(StorageError::CorruptData(
                "a prepared model claim disagrees with its durable job".into(),
            ));
        }
        let mut agent = query_agent_turn(&transaction, &job.agent_id)?;
        if !agent_knowledge_context_is_executable(&transaction, &agent, &job)? {
            require_open_agent_turn(&transaction, &agent)?;
            require_agent_finalization_capacity(&transaction, &agent)?;
            require_connection_physical_capacity(
                &transaction,
                physical_limits,
                PhysicalCapacityGate::ReservedProgress,
            )?;
            let completion = reject_model_for_unavailable_knowledge(
                &transaction,
                &mut agent,
                &job,
                Some(&claim),
                &timestamp,
            )?;
            transaction.commit()?;
            return Ok(AgentModelClaimOutcome::Rejected(Box::new(completion)));
        }
        transaction.commit()?;
        return Ok(AgentModelClaimOutcome::Prepared(Box::new(
            AgentPreparedModel { claim, job },
        )));
    }
    let job_id = transaction
        .query_row(
            r#"SELECT id FROM agent_model_jobs
               WHERE status = 'queued'
                 AND NOT EXISTS (
                     SELECT 1 FROM agent_operation_claims claim
                     WHERE claim.operation_kind = 'model'
                       AND claim.operation_id = agent_model_jobs.id
                       AND claim.phase IN ('prepared', 'started')
                 )
               ORDER BY queued_at, id LIMIT 1"#,
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
    if !agent_knowledge_context_is_executable(&transaction, &agent, &job)? {
        let completion = reject_model_for_unavailable_knowledge(
            &transaction,
            &mut agent,
            &job,
            None,
            &timestamp,
        )?;
        transaction.commit()?;
        return Ok(AgentModelClaimOutcome::Rejected(Box::new(completion)));
    }
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

    let claim = insert_prepared_agent_operation_claim(
        &transaction,
        AgentOperationKind::Model,
        &job.id,
        &job.agent_id,
        holder_id,
        &timestamp,
        &expires_at,
    )?;
    transaction.commit()?;
    Ok(AgentModelClaimOutcome::Prepared(Box::new(
        AgentPreparedModel { claim, job },
    )))
}

fn start_prepared_agent_model(
    connection: &mut Connection,
    claim: &AgentOperationClaim,
    current_manifest: &ManifestEnvelope,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<AgentModelStartOutcome, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let timestamp = now();
    let stored_claim = query_agent_operation_claim(&transaction, claim)?;
    let job = query_agent_model_job_by_id(&transaction, &claim.operation_id)?;
    if job.agent_id != claim.agent_id {
        return Err(StorageError::ConcurrentModification);
    }
    if stored_claim.phase == AgentOperationClaimPhase::Started {
        if job.status != AgentModelJobStatus::Started || job.attempt != 1 {
            return Err(StorageError::CorruptData(
                "started model claim disagrees with its durable job".into(),
            ));
        }
        let agent = query_agent_turn(&transaction, &job.agent_id)?;
        if !agent_knowledge_context_is_executable(&transaction, &agent, &job)? {
            return Err(StorageError::CorruptData(
                "a started model claim has no valid durable knowledge context".into(),
            ));
        }
        transaction.commit()?;
        return Ok(AgentModelStartOutcome::Started(Box::new(job)));
    }
    require_prepared_agent_operation_claim(&transaction, claim, &timestamp)?;
    if job.status != AgentModelJobStatus::Queued || job.attempt != 0 {
        return Err(StorageError::ConcurrentModification);
    }
    let mut agent = query_agent_turn(&transaction, &job.agent_id)?;
    require_open_agent_turn(&transaction, &agent)?;
    require_agent_finalization_capacity(&transaction, &agent)?;
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::ReservedProgress,
    )?;

    if !agent_knowledge_context_is_executable(&transaction, &agent, &job)? {
        let completion = reject_model_for_unavailable_knowledge(
            &transaction,
            &mut agent,
            &job,
            Some(claim),
            &timestamp,
        )?;
        transaction.commit()?;
        return Ok(AgentModelStartOutcome::Rejected(Box::new(completion)));
    }

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
            params![serde_json::to_string(&error_json)?, timestamp, job.id],
        )?;
        if changed != 1 {
            return Err(StorageError::ConcurrentModification);
        }
        release_agent_operation_claim(&transaction, claim, &timestamp)?;
        let completion = interrupt_agent_turn(
            &transaction,
            &agent,
            "agent deployment became unavailable before model execution",
        )?;
        transaction.commit()?;
        return Ok(AgentModelStartOutcome::Rejected(Box::new(completion)));
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
            params![serde_json::to_string(&error_json)?, timestamp, job.id],
        )?;
        if changed != 1 {
            return Err(StorageError::ConcurrentModification);
        }
        release_agent_operation_claim(&transaction, claim, &timestamp)?;
        let completion = interrupt_agent_turn(
            &transaction,
            &agent,
            "agent authorization was revoked before model execution",
        )?;
        transaction.commit()?;
        return Ok(AgentModelStartOutcome::Rejected(Box::new(completion)));
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
        params![timestamp, job.id],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    start_agent_operation_claim(&transaction, claim, &timestamp)?;
    let started = query_agent_model_job_by_id(&transaction, &job.id)?;
    transaction.commit()?;
    Ok(AgentModelStartOutcome::Started(Box::new(started)))
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
    release_started_agent_operation_claim(
        &transaction,
        AgentOperationKind::Model,
        &job.id,
        &timestamp,
    )?;
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
    release_started_agent_operation_claim(
        &transaction,
        AgentOperationKind::Model,
        &job.id,
        &timestamp,
    )?;
    let reason = if commit.outcome_unknown {
        "agent model outcome is unknown"
    } else {
        "agent model provider failed"
    };
    let completion = interrupt_agent_turn(&transaction, &agent, reason)?;
    transaction.commit()?;
    Ok(completion)
}

fn prepare_next_agent_tool(
    connection: &mut Connection,
    current_manifest: &ManifestEnvelope,
    holder_id: &str,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<AgentToolClaimOutcome, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (timestamp, expires_at) = agent_operation_claim_window()?;
    expire_prepared_agent_operation_claims(&transaction, &timestamp)?;
    if let Some(claim) = query_prepared_agent_operation_claim_for_holder(
        &transaction,
        AgentOperationKind::Tool,
        holder_id,
    )? {
        let call = query_agent_tool_call(&transaction, &claim.operation_id)?;
        if call.agent_id != claim.agent_id || call.status != AgentToolCallStatus::Queued {
            return Err(StorageError::CorruptData(
                "a prepared tool claim disagrees with its durable call".into(),
            ));
        }
        let model_job = query_agent_model_job(&transaction, &call.agent_id, call.model_step)?;
        validate_persisted_agent_model_tool_response(&model_job, &call)?;
        let mut agent = query_agent_turn(&transaction, &call.agent_id)?;
        if !agent_knowledge_context_is_executable(&transaction, &agent, &model_job)? {
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
                return Err(StorageError::CorruptData(
                    "a prepared tool claim disagrees with the current Agent state".into(),
                ));
            }
            let completion = reject_tool_for_unavailable_knowledge(
                &transaction,
                &mut agent,
                &call,
                Some(&claim),
                &timestamp,
            )?;
            transaction.commit()?;
            return Ok(AgentToolClaimOutcome::Rejected(Box::new(completion)));
        }
        let work = AgentToolWork { call, model_job };
        transaction.commit()?;
        return Ok(AgentToolClaimOutcome::Prepared(Box::new(
            AgentPreparedTool { claim, work },
        )));
    }
    let call_id = transaction
        .query_row(
            r#"SELECT call_id FROM agent_tool_calls
               WHERE status = 'queued'
                 AND NOT EXISTS (
                     SELECT 1 FROM agent_operation_claims claim
                     WHERE claim.operation_kind = 'tool'
                       AND claim.operation_id = agent_tool_calls.call_id
                       AND claim.phase IN ('prepared', 'started')
                 )
               ORDER BY created_at, call_id LIMIT 1"#,
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
    if !agent_knowledge_context_is_executable(&transaction, &agent, &model_job)? {
        let completion = reject_tool_for_unavailable_knowledge(
            &transaction,
            &mut agent,
            &call,
            None,
            &timestamp,
        )?;
        transaction.commit()?;
        return Ok(AgentToolClaimOutcome::Rejected(Box::new(completion)));
    }
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
    let claim = insert_prepared_agent_operation_claim(
        &transaction,
        AgentOperationKind::Tool,
        &call.call_id,
        &call.agent_id,
        holder_id,
        &timestamp,
        &expires_at,
    )?;
    let work = AgentToolWork { call, model_job };
    transaction.commit()?;
    Ok(AgentToolClaimOutcome::Prepared(Box::new(
        AgentPreparedTool { claim, work },
    )))
}

fn start_prepared_agent_tool(
    connection: &mut Connection,
    claim: &AgentOperationClaim,
    current_manifest: &ManifestEnvelope,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<AgentToolStartOutcome, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let timestamp = now();
    let stored_claim = query_agent_operation_claim(&transaction, claim)?;
    let call = query_agent_tool_call(&transaction, &claim.operation_id)?;
    if call.agent_id != claim.agent_id {
        return Err(StorageError::ConcurrentModification);
    }
    let model_job = query_agent_model_job(&transaction, &call.agent_id, call.model_step)?;
    if stored_claim.phase == AgentOperationClaimPhase::Started {
        if call.status != AgentToolCallStatus::Running {
            return Err(StorageError::CorruptData(
                "started tool claim disagrees with its durable call".into(),
            ));
        }
        let agent = query_agent_turn(&transaction, &call.agent_id)?;
        if !agent_knowledge_context_is_executable(&transaction, &agent, &model_job)? {
            return Err(StorageError::CorruptData(
                "a started tool claim has no valid durable knowledge context".into(),
            ));
        }
        let work = AgentToolWork { call, model_job };
        transaction.commit()?;
        return Ok(AgentToolStartOutcome::Started(Box::new(work)));
    }
    require_prepared_agent_operation_claim(&transaction, claim, &timestamp)?;
    if call.status != AgentToolCallStatus::Queued {
        return Err(StorageError::ConcurrentModification);
    }
    let mut agent = query_agent_turn(&transaction, &call.agent_id)?;
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
            "prepared agent tool does not match the current loop state".into(),
        ));
    }

    if !agent_knowledge_context_is_executable(&transaction, &agent, &model_job)? {
        let completion = reject_tool_for_unavailable_knowledge(
            &transaction,
            &mut agent,
            &call,
            Some(claim),
            &timestamp,
        )?;
        transaction.commit()?;
        return Ok(AgentToolStartOutcome::Rejected(Box::new(completion)));
    }

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
        release_agent_operation_claim(&transaction, claim, &timestamp)?;
        let completion = interrupt_agent_turn(
            &transaction,
            &agent,
            "agent deployment became unavailable before tool execution",
        )?;
        transaction.commit()?;
        return Ok(AgentToolStartOutcome::Rejected(Box::new(completion)));
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
        release_agent_operation_claim(&transaction, claim, &timestamp)?;
        let completion = interrupt_agent_turn(
            &transaction,
            &agent,
            "agent tool authorization was revoked before execution",
        )?;
        transaction.commit()?;
        return Ok(AgentToolStartOutcome::Rejected(Box::new(completion)));
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
    start_agent_operation_claim(&transaction, claim, &timestamp)?;
    let work = AgentToolWork {
        call: query_agent_tool_call(&transaction, &call.call_id)?,
        model_job,
    };
    transaction.commit()?;
    Ok(AgentToolStartOutcome::Started(Box::new(work)))
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
    release_started_agent_operation_claim(
        &transaction,
        AgentOperationKind::Tool,
        &call.call_id,
        &timestamp,
    )?;
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
    release_started_agent_operation_claim(
        &transaction,
        AgentOperationKind::Tool,
        &call.call_id,
        &timestamp,
    )?;
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
            require_canonical_policy_denied_agent_tool_result(&call.policy_revision, result_json)?;
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

fn canonical_policy_denied_agent_tool_result(policy_revision: &str) -> Value {
    json!({
        "code": "policy_denied",
        "message": "Zeus policy denied this tool call",
        "policy_revision": policy_revision,
        "status": "not_dispatched",
    })
}

fn require_canonical_policy_denied_agent_tool_result(
    policy_revision: &str,
    result: &Value,
) -> Result<(), StorageError> {
    if result != &canonical_policy_denied_agent_tool_result(policy_revision) {
        return Err(StorageError::InvalidAgentTransition(
            "policy-denied Agent tool result is not the canonical server-generated result".into(),
        ));
    }
    Ok(())
}

fn require_server_generated_agent_tool_result(call: &AgentToolCall) -> Result<(), StorageError> {
    let expected = match (&call.policy_decision, &call.status) {
        (PolicyDecision::Deny, AgentToolCallStatus::NotDispatched) => Some(
            canonical_policy_denied_agent_tool_result(&call.policy_revision),
        ),
        (PolicyDecision::RequireApproval, AgentToolCallStatus::Rejected) => Some(
            protocol::agent_approval_rejected_result(&call.call_id, call.review_note.as_deref()),
        ),
        _ => None,
    };
    if expected
        .as_ref()
        .is_some_and(|expected| call.result_json.as_ref() != Some(expected))
    {
        return Err(StorageError::InvalidAgentTransition(
            "durable server-generated Agent tool result cannot be recomputed exactly".into(),
        ));
    }
    Ok(())
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
    validate_request_matches_manifest(request_json, &manifest, AgentRequestPhase::Continuation)
        .map_err(|error| {
            StorageError::InvalidAgentTransition(format!(
                "agent continuation request disagrees with its deployment manifest: {error}"
            ))
        })?;
    require_agent_knowledge_request_integrity(connection, agent, request_json)?;
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
               status, attempt, request_json, knowledge_context_digest,
               response_json, error_json,
               queued_at, started_at, finished_at
           ) VALUES (
               ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
               'queued', 0, ?11, ?12, NULL, NULL, ?13, NULL, NULL
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
            agent.knowledge_context_digest,
            queued_at,
        ],
    )?;
    let job = query_agent_model_job(connection, &agent.id, step)?;
    require_agent_knowledge_context_integrity(connection, agent, &job)?;
    Ok(job)
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

fn query_agent_knowledge_context_for_actor(
    connection: &mut Connection,
    context: &AuthzContext,
    session_id: &str,
    turn_id: &str,
) -> Result<Option<AgentKnowledgeContextExplain>, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_active_session_actor(&transaction, session_id, context)?;
    let agent = query_agent_turn_for_session_turn(&transaction, session_id, turn_id)?;
    if agent.account_id != context.account_id {
        return Err(StorageError::AgentTurnNotFound(turn_id.to_owned()));
    }
    if agent.knowledge_context_digest.is_none() {
        let initial_job = query_agent_model_job(&transaction, &agent.id, 1)?;
        if agent_has_frozen_legacy_knowledge_boundary(&transaction, &agent, &initial_job)? {
            transaction.commit()?;
            return Ok(None);
        }
    }
    let (stored, _, _) = load_and_validate_agent_knowledge_context(&transaction, &agent)?;
    let snapshot =
        knowledge::SelectionSnapshotEnvelope::from_canonical_json(&stored.snapshot_envelope_json)
            .map_err(corrupt_knowledge_context)?;
    let explanation = AgentKnowledgeContextExplain {
        binding_schema_version: u16::try_from(stored.schema_version)
            .map_err(|_| StorageError::IntegerOutOfRange("Agent knowledge binding schema"))?,
        binding_digest: stored.digest,
        initial_model_job_id: stored.initial_model_job_id,
        corpus_digest: stored.corpus_digest,
        snapshot_digest: stored.snapshot_digest,
        query_digest: stored.query_digest,
        context_digest: stored.context_digest,
        context_bytes: u32::try_from(stored.context_bytes)
            .map_err(|_| StorageError::IntegerOutOfRange("Agent knowledge context bytes"))?,
        snapshot,
        created_at: stored.created_at,
    };
    transaction.commit()?;
    Ok(Some(explanation))
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

fn require_agent_review_receipt_replay_integrity(
    connection: &Connection,
    agent: &AgentTurn,
    call: &AgentToolCall,
    commit: &AgentReviewCommit,
    context: &AuthzContext,
    reviewed_at: &str,
) -> Result<(), StorageError> {
    let decision_matches = match commit.decision {
        ReviewDecision::Approve => matches!(
            call.status,
            AgentToolCallStatus::Queued
                | AgentToolCallStatus::Running
                | AgentToolCallStatus::Succeeded
                | AgentToolCallStatus::Failed
                | AgentToolCallStatus::Cancelled
                | AgentToolCallStatus::NotDispatched
                | AgentToolCallStatus::OutcomeUnknown
        ),
        ReviewDecision::Reject => call.status == AgentToolCallStatus::Rejected,
    };
    if call.policy_decision != PolicyDecision::RequireApproval
        || !decision_matches
        || call.approving_actor_user_id.as_deref() != Some(context.user_id.as_str())
        || call.approving_membership_revision.as_ref() != Some(&context.membership_revision)
        || call.review_note.as_deref() != commit.note.as_deref()
        || call.reviewed_at.as_deref() != Some(reviewed_at)
    {
        return Err(StorageError::InvalidAgentTransition(
            "durable Agent review receipt does not match the reviewed tool call".into(),
        ));
    }
    if commit.decision == ReviewDecision::Reject {
        require_server_generated_agent_tool_result(call)?;
    }
    let initial_job = query_agent_model_job(connection, &agent.id, 1)?;
    if agent_has_frozen_legacy_knowledge_boundary(connection, agent, &initial_job)? {
        return require_server_generated_agent_tool_result(call);
    }
    let causative_job = query_agent_model_job(connection, &agent.id, call.model_step)?;
    require_agent_knowledge_context_integrity(connection, agent, &causative_job)?;
    require_server_generated_agent_tool_result(call)
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
    if let Some((stored_fingerprint, stored_call_id, stored_revision, stored_created_at)) =
        transaction
            .query_row(
                r#"SELECT request_fingerprint, call_id, actor_membership_revision, created_at
               FROM agent_review_receipts
               WHERE account_id = ?1 AND actor_user_id = ?2 AND idempotency_key = ?3"#,
                params![context.account_id.as_str(), context.user_id, key],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
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
        require_agent_review_receipt_replay_integrity(
            &transaction,
            &current_agent,
            &current_call,
            &commit,
            context,
            &stored_created_at,
        )
        .map_err(corrupt_agent_integrity)?;
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
            let knowledge_unavailable = if !deployment_unavailable
                && primary_state.status() == WorkflowStatus::ContinuationQueued
                && commit.next_request_json.is_some()
            {
                let model_job = query_agent_model_job(&transaction, &agent.id, call.model_step)?;
                !agent_knowledge_context_is_executable(&transaction, &agent, &model_job)?
            } else {
                false
            };
            let requested_continuation = if deployment_unavailable || knowledge_unavailable {
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
                } else if knowledge_unavailable {
                    knowledge_unavailable_error(
                        "the legacy Agent has no valid knowledge context for a rejection continuation",
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
                    } else if knowledge_unavailable {
                        "agent knowledge is unavailable for a rejection continuation"
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AgentOperationClaimPhase {
    Prepared,
    Started,
    Released,
    Expired,
}

struct StoredAgentOperationClaim {
    claim: AgentOperationClaim,
    phase: AgentOperationClaimPhase,
}

fn agent_operation_kind_to_db(kind: AgentOperationKind) -> &'static str {
    match kind {
        AgentOperationKind::Model => "model",
        AgentOperationKind::Tool => "tool",
    }
}

fn agent_operation_claim_window() -> Result<(String, String), StorageError> {
    let acquired_at = Utc::now();
    let expires_at = acquired_at
        .checked_add_signed(chrono::Duration::seconds(AGENT_OPERATION_CLAIM_TTL_SECONDS))
        .ok_or(StorageError::IntegerOutOfRange(
            "Agent operation claim expiry",
        ))?;
    Ok((
        acquired_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        expires_at.to_rfc3339_opts(SecondsFormat::Millis, true),
    ))
}

fn expire_prepared_agent_operation_claims(
    connection: &Connection,
    timestamp: &str,
) -> Result<(), StorageError> {
    connection.execute(
        r#"UPDATE agent_operation_claims
           SET phase = 'expired', released_at = ?1
           WHERE phase = 'prepared' AND expires_at <= ?1"#,
        [timestamp],
    )?;
    Ok(())
}

fn expire_all_prepared_agent_operation_claims(
    connection: &Connection,
    timestamp: &str,
) -> Result<(), StorageError> {
    connection.execute(
        r#"UPDATE agent_operation_claims
           SET phase = 'expired', released_at = ?1
           WHERE phase = 'prepared'"#,
        [timestamp],
    )?;
    Ok(())
}

fn insert_prepared_agent_operation_claim(
    connection: &Connection,
    kind: AgentOperationKind,
    operation_id: &str,
    agent_id: &str,
    holder_id: &str,
    acquired_at: &str,
    expires_at: &str,
) -> Result<AgentOperationClaim, StorageError> {
    let kind_db = agent_operation_kind_to_db(kind);
    let generation = connection.query_row(
        r#"SELECT COALESCE(MAX(generation), 0) + 1
           FROM agent_operation_claims
           WHERE operation_kind = ?1 AND operation_id = ?2"#,
        params![kind_db, operation_id],
        |row| row.get::<_, i64>(0),
    )?;
    let (model_job_id, tool_call_id) = match kind {
        AgentOperationKind::Model => (Some(operation_id), None),
        AgentOperationKind::Tool => (None, Some(operation_id)),
    };
    connection.execute(
        r#"INSERT INTO agent_operation_claims(
               operation_kind, operation_id, model_job_id, tool_call_id,
               agent_id, generation, holder_id, phase, acquired_at,
               expires_at, started_at, released_at
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'prepared', ?8, ?9, NULL, NULL)"#,
        params![
            kind_db,
            operation_id,
            model_job_id,
            tool_call_id,
            agent_id,
            generation,
            holder_id,
            acquired_at,
            expires_at,
        ],
    )?;
    let claim = AgentOperationClaim {
        kind,
        operation_id: operation_id.to_owned(),
        agent_id: agent_id.to_owned(),
        generation: i64_to_u64(generation, "Agent operation claim generation")?,
        holder_id: holder_id.to_owned(),
        acquired_at: acquired_at.to_owned(),
        expires_at: expires_at.to_owned(),
    };
    claim.validate()?;
    Ok(claim)
}

fn query_prepared_agent_operation_claim_for_holder(
    connection: &Connection,
    kind: AgentOperationKind,
    holder_id: &str,
) -> Result<Option<AgentOperationClaim>, StorageError> {
    let stored = connection
        .query_row(
            r#"SELECT operation_id, agent_id, generation, acquired_at, expires_at
               FROM agent_operation_claims
               WHERE operation_kind = ?1 AND holder_id = ?2 AND phase = 'prepared'"#,
            params![agent_operation_kind_to_db(kind), holder_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;
    let claim = stored
        .map(
            |(operation_id, agent_id, generation, acquired_at, expires_at)|
             -> Result<AgentOperationClaim, StorageError> {
                Ok(AgentOperationClaim {
                    kind,
                    operation_id,
                    agent_id,
                    generation: i64_to_u64(generation, "Agent operation claim generation")?,
                    holder_id: holder_id.to_owned(),
                    acquired_at,
                    expires_at,
                })
            },
        )
        .transpose()?;
    if let Some(claim) = claim.as_ref() {
        claim.validate()?;
    }
    Ok(claim)
}

fn query_agent_operation_claim(
    connection: &Connection,
    claim: &AgentOperationClaim,
) -> Result<StoredAgentOperationClaim, StorageError> {
    let stored = connection
        .query_row(
            r#"SELECT agent_id, holder_id, phase, acquired_at, expires_at
               FROM agent_operation_claims
               WHERE operation_kind = ?1 AND operation_id = ?2 AND generation = ?3"#,
            params![
                agent_operation_kind_to_db(claim.kind),
                claim.operation_id,
                u64_to_i64(claim.generation, "Agent operation claim generation")?,
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or(StorageError::ConcurrentModification)?;
    let phase = match stored.2.as_str() {
        "prepared" => AgentOperationClaimPhase::Prepared,
        "started" => AgentOperationClaimPhase::Started,
        "released" => AgentOperationClaimPhase::Released,
        "expired" => AgentOperationClaimPhase::Expired,
        other => {
            return Err(StorageError::CorruptData(format!(
                "unknown Agent operation claim phase `{other}`"
            )));
        }
    };
    let persisted = AgentOperationClaim {
        kind: claim.kind,
        operation_id: claim.operation_id.clone(),
        agent_id: stored.0,
        generation: claim.generation,
        holder_id: stored.1,
        acquired_at: stored.3,
        expires_at: stored.4,
    };
    persisted.validate()?;
    if &persisted != claim {
        return Err(StorageError::ConcurrentModification);
    }
    Ok(StoredAgentOperationClaim {
        claim: persisted,
        phase,
    })
}

fn require_prepared_agent_operation_claim(
    connection: &Connection,
    claim: &AgentOperationClaim,
    timestamp: &str,
) -> Result<(), StorageError> {
    let stored = query_agent_operation_claim(connection, claim)?;
    if stored.phase != AgentOperationClaimPhase::Prepared
        || stored.claim.expires_at.as_str() <= timestamp
    {
        return Err(StorageError::ConcurrentModification);
    }
    Ok(())
}

fn start_agent_operation_claim(
    connection: &Connection,
    claim: &AgentOperationClaim,
    timestamp: &str,
) -> Result<(), StorageError> {
    let changed = connection.execute(
        r#"UPDATE agent_operation_claims
           SET phase = 'started', started_at = ?1
           WHERE operation_kind = ?2 AND operation_id = ?3 AND generation = ?4
             AND holder_id = ?5 AND phase = 'prepared' AND expires_at > ?1"#,
        params![
            timestamp,
            agent_operation_kind_to_db(claim.kind),
            claim.operation_id,
            u64_to_i64(claim.generation, "Agent operation claim generation")?,
            claim.holder_id,
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    Ok(())
}

fn release_agent_operation_claim(
    connection: &Connection,
    claim: &AgentOperationClaim,
    timestamp: &str,
) -> Result<(), StorageError> {
    let changed = connection.execute(
        r#"UPDATE agent_operation_claims
           SET phase = 'released', released_at = ?1
           WHERE operation_kind = ?2 AND operation_id = ?3 AND generation = ?4
             AND holder_id = ?5 AND phase = 'prepared'"#,
        params![
            timestamp,
            agent_operation_kind_to_db(claim.kind),
            claim.operation_id,
            u64_to_i64(claim.generation, "Agent operation claim generation")?,
            claim.holder_id,
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    Ok(())
}

fn release_started_agent_operation_claim(
    connection: &Connection,
    kind: AgentOperationKind,
    operation_id: &str,
    timestamp: &str,
) -> Result<(), StorageError> {
    let changed = connection.execute(
        r#"UPDATE agent_operation_claims
           SET phase = 'released', released_at = ?1
           WHERE operation_kind = ?2 AND operation_id = ?3 AND phase = 'started'"#,
        params![timestamp, agent_operation_kind_to_db(kind), operation_id],
    )?;
    if changed != 1 {
        return Err(StorageError::CorruptData(format!(
            "started {} operation `{operation_id}` has no active claim",
            agent_operation_kind_to_db(kind)
        )));
    }
    Ok(())
}

fn recover_started_agent_work(
    connection: &mut Connection,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<Vec<AgentTerminalCompletion>, StorageError> {
    let mut recovered = Vec::new();
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let recovery_timestamp = now();
    expire_all_prepared_agent_operation_claims(&transaction, &recovery_timestamp)?;
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
                release_started_agent_operation_claim(
                    &transaction,
                    AgentOperationKind::Model,
                    &job.id,
                    &timestamp,
                )?;
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
                release_started_agent_operation_claim(
                    &transaction,
                    AgentOperationKind::Tool,
                    &call.call_id,
                    &timestamp,
                )?;
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

#[derive(Clone, Copy)]
enum AgentRequestPhase {
    Initial,
    Continuation,
    LegacyPromptlessIntegrity,
}

fn validate_request_matches_manifest(
    request_json: &Value,
    manifest: &ManifestEnvelope,
    phase: AgentRequestPhase,
) -> Result<(), StorageError> {
    let request = request_json.as_object().ok_or_else(|| {
        StorageError::InvalidAgentTransition("agent model request must be an object".into())
    })?;
    if !matches!(phase, AgentRequestPhase::LegacyPromptlessIntegrity) {
        let typed_request = serde_json::from_value::<llm::ReplyRequest>(request_json.clone())
            .map_err(|error| {
                StorageError::InvalidAgentTransition(format!(
                    "agent model request does not match the typed provider contract: {error}"
                ))
            })?;
        let validation = match phase {
            AgentRequestPhase::Initial => llm::validate_initial_agent_reply_request(&typed_request),
            AgentRequestPhase::Continuation => llm::validate_agent_reply_request(&typed_request),
            AgentRequestPhase::LegacyPromptlessIntegrity => unreachable!(),
        };
        validation.map_err(|error| {
            StorageError::InvalidAgentTransition(format!(
                "agent model request violates the typed provider contract: {error}"
            ))
        })?;
        let messages = match request.get("messages") {
            Some(Value::Array(messages)) if !messages.is_empty() => messages,
            Some(Value::Array(_)) => {
                return Err(StorageError::InvalidAgentTransition(
                    "agent model request messages must not be empty".into(),
                ));
            }
            Some(_) => {
                return Err(StorageError::InvalidAgentTransition(
                    "agent model request messages must be an array".into(),
                ));
            }
            None => {
                return Err(StorageError::InvalidAgentTransition(
                    "agent model request must contain messages".into(),
                ));
            }
        };
        let prompt = manifest.manifest.deployment.spec.prompt.as_ref();
        let mut system_message: Option<&str> = None;
        for (index, message) in messages.iter().enumerate() {
            let message = message.as_object().ok_or_else(|| {
                StorageError::InvalidAgentTransition(format!(
                    "agent model request message {index} must be an object"
                ))
            })?;
            let role = message.get("role").and_then(Value::as_str).ok_or_else(|| {
                StorageError::InvalidAgentTransition(format!(
                    "agent model request message {index} role must be a string"
                ))
            })?;
            if !matches!(role, "system" | "user" | "context" | "assistant" | "tool") {
                return Err(StorageError::InvalidAgentTransition(format!(
                    "agent model request message {index} has an unsupported role"
                )));
            }
            let content = message
                .get("content")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    StorageError::InvalidAgentTransition(format!(
                        "agent model request message {index} content must be a string"
                    ))
                })?;
            if role == "system" {
                if index != 0 || system_message.is_some() {
                    return Err(StorageError::InvalidAgentTransition(
                        "agent model request may contain exactly one leading system message".into(),
                    ));
                }
                if message.contains_key("tool_call") || message.contains_key("tool_call_id") {
                    return Err(StorageError::InvalidAgentTransition(
                        "agent model request system message cannot contain tool metadata".into(),
                    ));
                }
                system_message = Some(content);
            }
        }
        match (prompt, system_message) {
            (Some(prompt), Some(content)) if prompt.matches_content(content) => {}
            (Some(_), Some(_)) => {
                return Err(StorageError::InvalidAgentTransition(
                    "agent model request system prompt content disagrees with the deployment manifest"
                        .into(),
                ));
            }
            (Some(_), None) => {
                return Err(StorageError::InvalidAgentTransition(
                    "agent model request is missing its manifest-bound system prompt".into(),
                ));
            }
            (None, Some(_)) => {
                return Err(StorageError::InvalidAgentTransition(
                    "agent model request cannot contain a system prompt without a manifest binding"
                        .into(),
                ));
            }
            (None, None) => {}
        }
        if prompt.is_some() && messages.len() == 1 {
            return Err(StorageError::InvalidAgentTransition(
                "agent model request must contain a conversation after its system prompt".into(),
            ));
        }
    }
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
    if let Some(candidate_prompt) = manifest.manifest.deployment.spec.prompt.as_ref() {
        let stored_manifests = {
            let mut statement = connection.prepare(
                r#"SELECT digest, schema_version, envelope_json
                   FROM agent_deployment_manifests ORDER BY digest"#,
            )?;
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        for (digest, schema_version, envelope_json) in stored_manifests {
            let stored = decode_agent_deployment_manifest(&digest, schema_version, &envelope_json)?;
            let Some(stored_prompt) = stored.manifest.deployment.spec.prompt.as_ref() else {
                continue;
            };
            if stored_prompt.prompt_id == candidate_prompt.prompt_id
                && stored_prompt.revision == candidate_prompt.revision
                && stored_prompt.content_digest != candidate_prompt.content_digest
            {
                return Err(StorageError::InvalidAgentTransition(format!(
                    "Agent prompt `{}` revision `{}` is already bound to different content",
                    candidate_prompt.prompt_id, candidate_prompt.revision
                )));
            }
        }
    }
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

fn manifest_matches_current_agent_prompt(
    connection: &Connection,
    account_id: &str,
    manifest: &ManifestEnvelope,
) -> Result<bool, StorageError> {
    let current = query_account_agent_prompt(connection, account_id)?;
    let Some(binding) = manifest.manifest.deployment.spec.prompt.as_ref() else {
        // Historical/direct-storage manifests predate the governed Zeus prompt
        // identity. Runtime admission still requires its exact resolved
        // manifest; this transaction-level fence applies once that identity is
        // present and preserves integrity reads for legacy Agents.
        return Ok(true);
    };
    if binding.prompt_id != SESSION_AGENT_PROMPT_ID {
        return Ok(true);
    }
    Ok(binding.prompt_id == current.prompt_id
        && binding.revision == current.binding_revision
        && binding.content_digest == current.content_digest)
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
    let phase = match job.step {
        1 => AgentRequestPhase::Initial,
        2.. => AgentRequestPhase::Continuation,
        0 => {
            return Err(StorageError::InvalidAgentTransition(
                "Agent model job step must be positive".into(),
            ));
        }
    };
    validate_request_matches_manifest(&job.request_json, manifest, phase)
}

fn require_model_job_matches_manifest_for_integrity(
    job: &AgentModelJob,
    manifest: &ManifestEnvelope,
) -> Result<(), StorageError> {
    let spec = &manifest.manifest.deployment.spec;
    if job.provider_name != spec.provider.provider_id || job.model_name != spec.provider.model {
        return Err(StorageError::InvalidAgentTransition(
            "Agent model job provider disagrees with its deployment manifest".into(),
        ));
    }
    if spec.prompt.is_none() {
        validate_request_matches_manifest(
            &job.request_json,
            manifest,
            AgentRequestPhase::LegacyPromptlessIntegrity,
        )
    } else {
        let phase = match job.step {
            1 => AgentRequestPhase::Initial,
            2.. => AgentRequestPhase::Continuation,
            0 => {
                return Err(StorageError::InvalidAgentTransition(
                    "Agent model job step must be positive".into(),
                ));
            }
        };
        validate_request_matches_manifest(&job.request_json, manifest, phase)
    }
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
    match manifest_matches_current_agent_prompt(
        connection,
        agent.account_id.as_str(),
        current_manifest,
    ) {
        Ok(true) => {}
        Ok(false) => return Ok(false),
        Err(StorageError::Sqlite(error)) => return Err(StorageError::Sqlite(error)),
        Err(_) => return Ok(false),
    }
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

fn knowledge_unavailable_error(message: &str) -> Value {
    json!({
        "code": "knowledge_unavailable",
        "message": message,
    })
}

fn reject_model_for_unavailable_knowledge(
    connection: &Connection,
    agent: &mut AgentTurn,
    job: &AgentModelJob,
    claim: Option<&AgentOperationClaim>,
    timestamp: &str,
) -> Result<AgentTerminalCompletion, StorageError> {
    let error_json = knowledge_unavailable_error(
        "the Agent knowledge context is missing, invalid, or changed before model execution",
    );
    let command = WorkflowCommand::KnowledgeUnavailable;
    let transition = reduce(&agent.workflow_state, command.clone())
        .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?;
    persist_agent_workflow_transition(
        connection,
        agent,
        transition.state().clone(),
        None,
        Some(&error_json),
        Some(timestamp),
        AgentTransitionFact {
            command,
            external_call: transition.external_call().cloned(),
            emitted_result: transition.emitted_result().cloned(),
            emitted_result_digest: None,
            epoch_digest: None,
            source: FactSource::Live,
            subject: Some(model_subject(job)),
            input_digest: Some(model_request_digest(job)?),
            output_digest: Some(super::execution::digest_json(
                DigestDomain::ExecutionError,
                &error_json,
            )?),
            next_request_digest: None,
        },
        timestamp,
    )?;
    let changed = connection.execute(
        r#"UPDATE agent_model_jobs
           SET status = 'failed', attempt = 1, error_json = ?1,
               started_at = ?2, finished_at = ?2
           WHERE id = ?3 AND status = 'queued' AND attempt = 0"#,
        params![serde_json::to_string(&error_json)?, timestamp, job.id],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    if let Some(claim) = claim {
        release_agent_operation_claim(connection, claim, timestamp)?;
    }
    interrupt_agent_turn(
        connection,
        agent,
        "agent knowledge became unavailable before model execution",
    )
}

fn reject_tool_for_unavailable_knowledge(
    connection: &Connection,
    agent: &mut AgentTurn,
    call: &AgentToolCall,
    claim: Option<&AgentOperationClaim>,
    timestamp: &str,
) -> Result<AgentTerminalCompletion, StorageError> {
    let error_json = knowledge_unavailable_error(
        "the Agent knowledge context is missing, invalid, or changed before tool execution",
    );
    let command = WorkflowCommand::KnowledgeUnavailable;
    let transition = reduce(&agent.workflow_state, command.clone())
        .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?;
    persist_agent_workflow_transition(
        connection,
        agent,
        transition.state().clone(),
        None,
        Some(&error_json),
        Some(timestamp),
        AgentTransitionFact {
            command,
            external_call: transition.external_call().cloned(),
            emitted_result: transition.emitted_result().cloned(),
            emitted_result_digest: None,
            epoch_digest: None,
            source: FactSource::Live,
            subject: Some(tool_subject(call)),
            input_digest: Some(tool_input_digest(call)?),
            output_digest: Some(super::execution::digest_json(
                DigestDomain::ExecutionError,
                &error_json,
            )?),
            next_request_digest: None,
        },
        timestamp,
    )?;
    let changed = connection.execute(
        r#"UPDATE agent_tool_calls
           SET status = 'not_dispatched', result_json = ?1, finished_at = ?2
           WHERE call_id = ?3 AND status = 'queued'"#,
        params![serde_json::to_string(&error_json)?, timestamp, call.call_id],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    if let Some(claim) = claim {
        release_agent_operation_claim(connection, claim, timestamp)?;
    }
    interrupt_agent_turn(
        connection,
        agent,
        "agent knowledge became unavailable before tool execution",
    )
}

pub(super) fn verify_agent_deployment_manifest_integrity(
    connection: &Connection,
) -> Result<(), StorageError> {
    {
        let mut prompt_identities = std::collections::BTreeMap::<(String, String), String>::new();
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
            let manifest =
                decode_agent_deployment_manifest(&digest, schema_version, &envelope_json)?;
            if let Some(prompt) = manifest.manifest.deployment.spec.prompt {
                let identity = (prompt.prompt_id.clone(), prompt.revision.clone());
                if let Some(existing_digest) =
                    prompt_identities.insert(identity, prompt.content_digest.clone())
                    && existing_digest != prompt.content_digest
                {
                    return Err(StorageError::CorruptData(format!(
                        "Agent prompt `{}` revision `{}` has conflicting durable content bindings",
                        prompt.prompt_id, prompt.revision
                    )));
                }
            }
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
            require_model_job_matches_manifest_for_integrity(&job, &manifest).map_err(|error| {
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

fn invalid_knowledge_context(error: impl std::fmt::Display) -> StorageError {
    StorageError::InvalidAgentTransition(format!("invalid Agent knowledge context: {error}"))
}

fn corrupt_knowledge_context(error: impl std::fmt::Display) -> StorageError {
    StorageError::CorruptData(format!("invalid stored Agent knowledge context: {error}"))
}

fn validate_request_knowledge_context(
    request_json: &Value,
    canonical_context: &str,
    query: Option<&str>,
) -> Result<(), StorageError> {
    let request =
        serde_json::from_value::<llm::ReplyRequest>(request_json.clone()).map_err(|error| {
            StorageError::InvalidAgentTransition(format!(
                "agent model request does not match the typed provider contract: {error}"
            ))
        })?;
    let contexts = request
        .messages
        .iter()
        .enumerate()
        .filter(|(_, message)| message.role == llm::ReplyRole::Context)
        .collect::<Vec<_>>();
    let [(index, context)] = contexts.as_slice() else {
        return Err(StorageError::InvalidAgentTransition(
            "agent model request must contain exactly one governed knowledge context".into(),
        ));
    };
    if context.content != canonical_context {
        return Err(StorageError::InvalidAgentTransition(
            "agent model request governed context disagrees with its selection snapshot".into(),
        ));
    }
    if let Some(query) = query {
        let user = index
            .checked_sub(1)
            .and_then(|previous| request.messages.get(previous))
            .filter(|message| message.role == llm::ReplyRole::User)
            .ok_or_else(|| {
                StorageError::InvalidAgentTransition(
                    "agent knowledge context must immediately follow its immutable user message"
                        .into(),
                )
            })?;
        if user.content != query {
            return Err(StorageError::InvalidAgentTransition(
                "agent knowledge query disagrees with the immutable Session user message".into(),
            ));
        }
    }
    Ok(())
}

fn agent_reply_tools_from_manifest(manifest: &ManifestEnvelope) -> Vec<llm::ReplyToolDefinition> {
    manifest
        .manifest
        .deployment
        .spec
        .tools
        .iter()
        .map(|tool| {
            llm::ReplyToolDefinition::new(tool.name.clone(), tool.input_schema.clone())
                .with_description(tool.description.clone())
        })
        .collect()
}

fn invalid_agent_transcript(error: impl std::fmt::Display) -> StorageError {
    StorageError::InvalidAgentTransition(format!(
        "Agent provider transcript disagrees with durable Session facts: {error}"
    ))
}

fn agent_transcript_storage_error(error: StorageError) -> StorageError {
    match error {
        error @ StorageError::Sqlite(_) => error,
        other => invalid_agent_transcript(other),
    }
}

fn require_initial_agent_request_transcript(
    connection: &Connection,
    agent: &AgentTurn,
    job: &AgentModelJob,
    manifest: &ManifestEnvelope,
    canonical_context: &str,
    query: &str,
) -> Result<(), StorageError> {
    let candidate = serde_json::from_value::<llm::ReplyRequest>(job.request_json.clone())
        .map_err(invalid_agent_transcript)?;
    let system_prompt = if manifest.manifest.deployment.spec.prompt.is_some() {
        Some(
            candidate
                .messages
                .first()
                .filter(|message| message.role == llm::ReplyRole::System)
                .map(|message| message.content.as_str())
                .ok_or_else(|| {
                    invalid_agent_transcript("manifest-bound system prompt is missing")
                })?,
        )
    } else {
        None
    };
    let (user_sequence, durable_user_message) =
        query_session_user_message_event(connection, &agent.session_id, &agent.turn_id)
            .map_err(agent_transcript_storage_error)?;
    let turn = query_session_turn(connection, &agent.session_id, &agent.turn_id)
        .map_err(agent_transcript_storage_error)?;
    if durable_user_message != query
        || turn.user_message != query
        || turn.id != agent.turn_id
        || turn.session_id != agent.session_id
    {
        return Err(invalid_agent_transcript(
            "the immutable user event, turn projection, and knowledge query differ",
        ));
    }
    let history_boundary = user_sequence
        .checked_sub(1)
        .ok_or_else(|| invalid_agent_transcript("the user event has no history boundary"))?;
    let history = query_session_reply_turns(
        connection,
        &agent.session_id,
        history_boundary,
        llm::AGENT_REQUEST_MAX_HISTORY_PAIRS_WITH_CONTEXT,
    )
    .map_err(agent_transcript_storage_error)?;
    let mut expected =
        llm::ReplyRequest::from_session_history_for_agent_with_optional_system_prompt_and_context(
            &history,
            query,
            system_prompt,
            canonical_context,
        )
        .map_err(invalid_agent_transcript)?;
    expected.tools = agent_reply_tools_from_manifest(manifest);
    let expected =
        llm::persisted_agent_reply_request(&expected).map_err(invalid_agent_transcript)?;
    if job.request_json != expected {
        return Err(invalid_agent_transcript(
            "the initial request is not the canonical reconstruction of durable history",
        ));
    }
    Ok(())
}

fn require_continuation_agent_request_transcript(
    connection: &Connection,
    agent: &AgentTurn,
    job: &AgentModelJob,
) -> Result<(), StorageError> {
    let previous_step = job
        .step
        .checked_sub(1)
        .ok_or_else(|| invalid_agent_transcript("continuation step underflow"))?;
    let previous_job = query_agent_model_job(connection, &agent.id, previous_step)
        .map_err(agent_transcript_storage_error)?;
    let call = query_agent_tool_call_for_step(connection, &agent.id, previous_step)
        .map_err(agent_transcript_storage_error)?
        .ok_or_else(|| {
            invalid_agent_transcript("the previous model step has no durable tool call")
        })?;
    validate_persisted_agent_model_tool_response(&previous_job, &call)
        .map_err(invalid_agent_transcript)?;
    let result = call.result_json.as_ref().ok_or_else(|| {
        invalid_agent_transcript("the previous tool call has no exact durable result")
    })?;
    require_server_generated_agent_tool_result(&call).map_err(invalid_agent_transcript)?;
    let previous_request =
        serde_json::from_value::<llm::ReplyRequest>(previous_job.request_json.clone())
            .map_err(invalid_agent_transcript)?;
    let provider_call = llm::ReplyToolCall::new(
        call.provider_call_id.clone(),
        call.tool_name.clone(),
        call.arguments_json.clone(),
    );
    let result_content = serde_json::to_string(result).map_err(invalid_agent_transcript)?;
    let expected =
        llm::agent_continuation_request(&previous_request, &provider_call, result_content)
            .and_then(|request| llm::persisted_agent_reply_request(&request))
            .map_err(invalid_agent_transcript)?;
    if job.request_json != expected {
        return Err(invalid_agent_transcript(
            "the continuation does not exactly extend the prior request, tool call, and result",
        ));
    }
    Ok(())
}

fn require_agent_request_transcript_chain(
    connection: &Connection,
    agent: &AgentTurn,
    through_step: u32,
    manifest: &ManifestEnvelope,
    context_digest: &str,
    canonical_context: &str,
    query: &str,
) -> Result<(), StorageError> {
    for step in 1..=through_step {
        let job = query_agent_model_job(connection, &agent.id, step)
            .map_err(agent_transcript_storage_error)?;
        if job.agent_id != agent.id
            || job.account_id != agent.account_id
            || job.actor_user_id != agent.actor_user_id
            || job.actor_membership_revision != agent.actor_membership_revision
            || job.session_id != agent.session_id
            || job.turn_id != agent.turn_id
            || job.knowledge_context_digest.as_deref() != Some(context_digest)
        {
            return Err(invalid_agent_transcript(format!(
                "model job step {step} differs from the Agent knowledge identity"
            )));
        }
        require_model_job_matches_manifest(&job, manifest).map_err(invalid_agent_transcript)?;
        if step == 1 {
            require_initial_agent_request_transcript(
                connection,
                agent,
                &job,
                manifest,
                canonical_context,
                query,
            )?;
        } else {
            require_continuation_agent_request_transcript(connection, agent, &job)?;
        }
        if let Some(call) = query_agent_tool_call_for_step(connection, &agent.id, step)
            .map_err(agent_transcript_storage_error)?
        {
            require_server_generated_agent_tool_result(&call).map_err(invalid_agent_transcript)?;
        }
    }
    Ok(())
}

fn validate_agent_knowledge_spec(spec: &AgentTurnSpec) -> Result<(), StorageError> {
    spec.knowledge
        .corpus
        .validate()
        .map_err(invalid_knowledge_context)?;
    spec.knowledge
        .snapshot
        .validate()
        .map_err(invalid_knowledge_context)?;
    if spec.knowledge.snapshot.snapshot().corpus_digest() != spec.knowledge.corpus.digest() {
        return Err(StorageError::InvalidAgentTransition(
            "Agent knowledge snapshot disagrees with its exact corpus revision".into(),
        ));
    }
    validate_request_knowledge_context(
        &spec.request_json,
        spec.knowledge.snapshot.snapshot().canonical_context(),
        None,
    )
}

fn aggregate_corpus_entry_bytes(
    corpus: &knowledge::CorpusRevisionEnvelope,
) -> Result<i64, StorageError> {
    let bytes = corpus.entries().iter().try_fold(0usize, |total, entry| {
        total
            .checked_add(entry.entry_id().len())
            .and_then(|total| total.checked_add(entry.revision().len()))
            .and_then(|total| total.checked_add(entry.title().len()))
            .and_then(|total| total.checked_add(entry.content().len()))
    });
    let bytes = bytes.ok_or(StorageError::IntegerOutOfRange(
        "knowledge corpus aggregate entry bytes",
    ))?;
    i64::try_from(bytes)
        .map_err(|_| StorageError::IntegerOutOfRange("knowledge corpus aggregate entry bytes"))
}

fn persist_agent_knowledge_corpus(
    connection: &Connection,
    account_id: &str,
    corpus: &knowledge::CorpusRevisionEnvelope,
    created_at: &str,
) -> Result<(), StorageError> {
    let digest = corpus.digest().to_hex();
    let envelope_json = corpus.canonical_json().map_err(invalid_knowledge_context)?;
    let entry_count = i64::try_from(corpus.entries().len())
        .map_err(|_| StorageError::IntegerOutOfRange("knowledge corpus entry count"))?;
    let aggregate_entry_bytes = aggregate_corpus_entry_bytes(corpus)?;
    connection.execute(
        r#"INSERT INTO knowledge_corpus_revisions(
               account_id, digest, schema_version, entry_count,
               aggregate_entry_bytes, envelope_json, created_at
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
           ON CONFLICT(account_id, digest) DO NOTHING"#,
        params![
            account_id,
            digest,
            i64::from(corpus.schema_version()),
            entry_count,
            aggregate_entry_bytes,
            envelope_json,
            created_at,
        ],
    )?;
    let stored = connection.query_row(
        r#"SELECT schema_version, entry_count, aggregate_entry_bytes, envelope_json
           FROM knowledge_corpus_revisions
           WHERE account_id = ?1 AND digest = ?2"#,
        params![account_id, digest],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
            ))
        },
    )?;
    if stored
        != (
            i64::from(corpus.schema_version()),
            entry_count,
            aggregate_entry_bytes,
            envelope_json,
        )
    {
        return Err(StorageError::InvalidAgentTransition(
            "Agent knowledge corpus digest collides with different durable bytes".into(),
        ));
    }
    Ok(())
}

fn agent_knowledge_binding_json(
    binding: &AgentKnowledgeContextBinding<'_>,
) -> Result<String, StorageError> {
    let encoded = serde_json::to_string(binding)?;
    if encoded.len() > AGENT_KNOWLEDGE_BINDING_MAX_BYTES {
        return Err(StorageError::InvalidAgentTransition(format!(
            "Agent knowledge binding cannot exceed {AGENT_KNOWLEDGE_BINDING_MAX_BYTES} bytes"
        )));
    }
    Ok(encoded)
}

fn agent_knowledge_binding_digest(binding_json: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(AGENT_KNOWLEDGE_BINDING_DIGEST_DOMAIN);
    digest.update((binding_json.len() as u64).to_be_bytes());
    digest.update(binding_json.as_bytes());
    format!("{:x}", digest.finalize())
}

fn persist_agent_knowledge_context(
    connection: &Connection,
    session_id: &str,
    turn_id: &str,
    initial_model_job_id: &str,
    spec: &AgentTurnSpec,
    created_at: &str,
) -> Result<String, StorageError> {
    let turn = query_session_turn(connection, session_id, turn_id)?;
    spec.knowledge
        .snapshot
        .validate_for_selection(&turn.user_message, spec.knowledge.corpus.entries())
        .map_err(invalid_knowledge_context)?;
    let snapshot = spec.knowledge.snapshot.snapshot();
    validate_request_knowledge_context(
        &spec.request_json,
        snapshot.canonical_context(),
        Some(&turn.user_message),
    )?;
    persist_agent_knowledge_corpus(
        connection,
        spec.authz.account_id.as_str(),
        &spec.knowledge.corpus,
        created_at,
    )?;

    let corpus_digest = spec.knowledge.corpus.digest().to_hex();
    let snapshot_digest = spec.knowledge.snapshot.digest().to_hex();
    let query_digest = snapshot.query_digest().to_hex();
    let context_digest = snapshot.context_digest().to_hex();
    let binding = AgentKnowledgeContextBinding {
        schema_version: AGENT_KNOWLEDGE_BINDING_SCHEMA_VERSION,
        account_id: spec.authz.account_id.as_str(),
        actor_user_id: &spec.authz.user_id,
        actor_membership_revision: spec.authz.membership_revision.get(),
        session_id,
        turn_id,
        agent_id: &spec.id,
        initial_model_job_id,
        corpus_digest: &corpus_digest,
        snapshot_digest: &snapshot_digest,
        query_digest: &query_digest,
        context_digest: &context_digest,
        context_bytes: snapshot.context_bytes(),
        canonical_context: snapshot.canonical_context(),
        created_at,
    };
    let binding_json = agent_knowledge_binding_json(&binding)?;
    let digest = agent_knowledge_binding_digest(&binding_json);
    let snapshot_envelope_json = spec
        .knowledge
        .snapshot
        .canonical_json()
        .map_err(invalid_knowledge_context)?;
    connection.execute(
        r#"INSERT INTO agent_knowledge_contexts(
               digest, schema_version, account_id, actor_user_id,
               actor_membership_revision, session_id, turn_id, agent_id,
               initial_model_job_id, corpus_digest, snapshot_digest,
               query_digest, context_digest, context_bytes, canonical_context,
               snapshot_envelope_json, binding_json, created_at
           ) VALUES (
               ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
               ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18
           )"#,
        params![
            digest,
            i64::from(AGENT_KNOWLEDGE_BINDING_SCHEMA_VERSION),
            spec.authz.account_id.as_str(),
            spec.authz.user_id,
            u64_to_i64(
                spec.authz.membership_revision.get(),
                "Agent knowledge membership revision"
            )?,
            session_id,
            turn_id,
            spec.id,
            initial_model_job_id,
            corpus_digest,
            snapshot_digest,
            query_digest,
            context_digest,
            i64::from(snapshot.context_bytes()),
            snapshot.canonical_context(),
            snapshot_envelope_json,
            binding_json,
            created_at,
        ],
    )?;
    Ok(digest)
}

fn query_stored_agent_knowledge_context(
    connection: &Connection,
    digest: &str,
) -> Result<StoredAgentKnowledgeContext, StorageError> {
    connection
        .query_row(
            r#"SELECT digest, schema_version, account_id, actor_user_id,
                      actor_membership_revision, session_id, turn_id, agent_id,
                      initial_model_job_id, corpus_digest, snapshot_digest,
                      query_digest, context_digest, context_bytes, canonical_context,
                      snapshot_envelope_json, binding_json, created_at
               FROM agent_knowledge_contexts WHERE digest = ?1"#,
            [digest],
            |row| {
                Ok(StoredAgentKnowledgeContext {
                    digest: row.get(0)?,
                    schema_version: row.get(1)?,
                    account_id: row.get(2)?,
                    actor_user_id: row.get(3)?,
                    actor_membership_revision: row.get(4)?,
                    session_id: row.get(5)?,
                    turn_id: row.get(6)?,
                    agent_id: row.get(7)?,
                    initial_model_job_id: row.get(8)?,
                    corpus_digest: row.get(9)?,
                    snapshot_digest: row.get(10)?,
                    query_digest: row.get(11)?,
                    context_digest: row.get(12)?,
                    context_bytes: row.get(13)?,
                    canonical_context: row.get(14)?,
                    snapshot_envelope_json: row.get(15)?,
                    binding_json: row.get(16)?,
                    created_at: row.get(17)?,
                })
            },
        )
        .optional()?
        .ok_or_else(|| {
            StorageError::CorruptData(format!("Agent knowledge context `{digest}` is missing"))
        })
}

fn query_stored_knowledge_corpus(
    connection: &Connection,
    account_id: &str,
    digest: &str,
) -> Result<knowledge::CorpusRevisionEnvelope, StorageError> {
    let stored = connection
        .query_row(
            r#"SELECT schema_version, entry_count, aggregate_entry_bytes, envelope_json
               FROM knowledge_corpus_revisions
               WHERE account_id = ?1 AND digest = ?2"#,
            params![account_id, digest],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| {
            StorageError::CorruptData(format!(
                "Agent knowledge corpus `{account_id}/{digest}` is missing"
            ))
        })?;
    let corpus = knowledge::CorpusRevisionEnvelope::from_canonical_json(&stored.3)
        .map_err(corrupt_knowledge_context)?;
    let expected_entry_count = i64::try_from(corpus.entries().len())
        .map_err(|_| StorageError::IntegerOutOfRange("stored knowledge corpus entry count"))?;
    let expected_entry_bytes = aggregate_corpus_entry_bytes(&corpus)?;
    if stored.0 != i64::from(corpus.schema_version())
        || stored.1 != expected_entry_count
        || stored.2 != expected_entry_bytes
        || corpus.digest().to_hex() != digest
    {
        return Err(StorageError::CorruptData(format!(
            "Agent knowledge corpus `{account_id}/{digest}` disagrees with its SQL projection"
        )));
    }
    Ok(corpus)
}

fn invalid_knowledge_catalog(error: impl std::fmt::Display) -> StorageError {
    StorageError::InvalidKnowledgeCatalog(error.to_string())
}

fn empty_knowledge_corpus() -> Result<knowledge::CorpusRevisionEnvelope, StorageError> {
    knowledge::CorpusRevisionEnvelope::new(Vec::new()).map_err(invalid_knowledge_catalog)
}

fn knowledge_catalog_fingerprint(
    expected_revision: u64,
    corpus_digest: &str,
) -> Result<String, StorageError> {
    Ok(serde_json::to_string(&json!({
        "expected_revision": expected_revision,
        "corpus_digest": corpus_digest,
    }))?)
}

fn query_account_knowledge_catalog(
    connection: &Connection,
    account_id: &str,
) -> Result<KnowledgeCatalogState, StorageError> {
    let stored = connection
        .query_row(
            r#"SELECT revision, active_corpus_digest, updated_by_user_id,
                      updated_by_membership_revision, updated_at
               FROM account_knowledge_catalogs WHERE account_id = ?1"#,
            [account_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;
    let account_id_value = decode_account_id(account_id.to_owned())?;
    let Some((revision, corpus_digest, actor_user_id, actor_revision, updated_at)) = stored else {
        return Ok(KnowledgeCatalogState {
            account_id: account_id_value,
            revision: 0,
            corpus: empty_knowledge_corpus()?,
            updated_by_user_id: None,
            updated_by_membership_revision: None,
            updated_at: None,
        });
    };
    Ok(KnowledgeCatalogState {
        account_id: account_id_value,
        revision: i64_to_u64(revision, "knowledge catalog revision")?,
        corpus: query_stored_knowledge_corpus(connection, account_id, &corpus_digest)?,
        updated_by_user_id: Some(actor_user_id),
        updated_by_membership_revision: Some(decode_membership_revision(actor_revision)?),
        updated_at: Some(updated_at),
    })
}

pub(super) fn query_account_knowledge_catalog_for_admin(
    connection: &Connection,
    context: &AuthzContext,
) -> Result<KnowledgeCatalogState, StorageError> {
    require_current_authority(connection, context, AccountCapability::AccountAdmin)?;
    query_account_knowledge_catalog(connection, context.account_id.as_str())
}

pub(super) fn query_active_knowledge_corpus_for_actor(
    connection: &Connection,
    context: &AuthzContext,
) -> Result<knowledge::CorpusRevisionEnvelope, StorageError> {
    require_current_authority(connection, context, AccountCapability::Reply)?;
    Ok(query_account_knowledge_catalog(connection, context.account_id.as_str())?.corpus)
}

pub(super) fn query_account_knowledge_catalog_revision_for_admin(
    connection: &mut Connection,
    context: &AuthzContext,
    revision: u64,
) -> Result<KnowledgeCatalogState, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_current_authority(&transaction, context, AccountCapability::AccountAdmin)?;
    let current = query_account_knowledge_catalog(&transaction, context.account_id.as_str())?;
    if revision == 0 {
        let catalog = KnowledgeCatalogState {
            account_id: context.account_id.clone(),
            revision: 0,
            corpus: empty_knowledge_corpus()?,
            updated_by_user_id: None,
            updated_by_membership_revision: None,
            updated_at: None,
        };
        transaction.commit()?;
        return Ok(catalog);
    }
    if revision > current.revision {
        return Err(StorageError::KnowledgeCatalogRevisionNotFound(revision));
    }
    let revision_sql = u64_to_i64(revision, "knowledge catalog revision")?;
    let stored = transaction
        .query_row(
            r#"SELECT actor_user_id, actor_membership_revision,
                      corpus_digest, created_at
               FROM knowledge_catalog_receipts
               WHERE account_id = ?1 AND catalog_revision = ?2"#,
            params![context.account_id.as_str(), revision_sql],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| {
            StorageError::CorruptData(format!(
                "knowledge catalog `{}` is missing committed revision {revision}",
                context.account_id
            ))
        })?;
    let catalog = KnowledgeCatalogState {
        account_id: context.account_id.clone(),
        revision,
        corpus: query_stored_knowledge_corpus(
            &transaction,
            context.account_id.as_str(),
            &stored.2,
        )?,
        updated_by_user_id: Some(stored.0),
        updated_by_membership_revision: Some(decode_membership_revision(stored.1)?),
        updated_at: Some(stored.3),
    };
    transaction.commit()?;
    Ok(catalog)
}

pub(super) fn query_account_knowledge_catalog_revisions_for_admin(
    connection: &mut Connection,
    context: &AuthzContext,
    before_revision: Option<u64>,
    limit: usize,
) -> Result<KnowledgeCatalogRevisionPage, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_current_authority(&transaction, context, AccountCapability::AccountAdmin)?;
    let fetch_limit = validated_read_page_limit(limit, COLLECTION_PAGE_MAX_LIMIT)?;
    let current = query_account_knowledge_catalog(&transaction, context.account_id.as_str())?;
    let initial_boundary =
        current
            .revision
            .checked_add(1)
            .ok_or(StorageError::IntegerOutOfRange(
                "knowledge catalog history boundary",
            ))?;
    let boundary = before_revision.unwrap_or(initial_boundary);
    if boundary == 0 {
        return Err(StorageError::InvalidPageCursor);
    }
    if boundary > initial_boundary {
        return Err(StorageError::PageCursorBeyondHead {
            head: current.revision,
        });
    }
    let boundary_sql = u64_to_i64(boundary, "knowledge catalog history boundary")?;
    let rows = {
        let mut statement = transaction.prepare(
            r#"SELECT receipt.catalog_revision, receipt.corpus_digest,
                      corpus.entry_count, corpus.aggregate_entry_bytes,
                      receipt.actor_user_id, receipt.actor_membership_revision,
                      receipt.created_at
               FROM knowledge_catalog_receipts receipt
               LEFT JOIN knowledge_corpus_revisions corpus
                 ON corpus.account_id = receipt.account_id
                AND corpus.digest = receipt.corpus_digest
               WHERE receipt.account_id = ?1
                 AND receipt.catalog_revision < ?2
               ORDER BY receipt.catalog_revision DESC
               LIMIT ?3"#,
        )?;
        statement
            .query_map(
                params![context.account_id.as_str(), boundary_sql, fetch_limit],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?
    };
    let mut expected_revision = boundary - 1;
    let mut items = Vec::with_capacity(rows.len());
    for (revision, digest, entry_count, entry_bytes, actor, actor_revision, created_at) in rows {
        let revision = i64_to_u64(revision, "knowledge catalog revision")?;
        if revision != expected_revision {
            return Err(StorageError::CorruptData(format!(
                "knowledge catalog `{}` history is not contiguous before revision {boundary}",
                context.account_id
            )));
        }
        let entry_count = entry_count.ok_or_else(|| {
            StorageError::CorruptData(format!(
                "knowledge catalog `{}` revision {revision} has no corpus projection",
                context.account_id
            ))
        })?;
        let entry_bytes = entry_bytes.ok_or_else(|| {
            StorageError::CorruptData(format!(
                "knowledge catalog `{}` revision {revision} has no corpus projection",
                context.account_id
            ))
        })?;
        items.push(KnowledgeCatalogRevisionSummary {
            revision,
            corpus_digest: digest,
            entry_count: i64_to_u64(entry_count, "knowledge corpus entry count")?,
            aggregate_entry_bytes: i64_to_u64(
                entry_bytes,
                "knowledge corpus aggregate entry bytes",
            )?,
            updated_by_user_id: actor,
            updated_by_membership_revision: decode_membership_revision(actor_revision)?,
            updated_at: created_at,
        });
        expected_revision =
            expected_revision
                .checked_sub(1)
                .ok_or(StorageError::IntegerOutOfRange(
                    "knowledge catalog history revision",
                ))?;
    }
    let fetch_limit = usize::try_from(fetch_limit)
        .map_err(|_| StorageError::IntegerOutOfRange("knowledge catalog history fetch limit"))?;
    if items.len() < fetch_limit && expected_revision != 0 {
        return Err(StorageError::CorruptData(format!(
            "knowledge catalog `{}` history is incomplete before revision {boundary}",
            context.account_id
        )));
    }
    let has_more = items.len() > limit;
    if has_more {
        items.truncate(limit);
    }
    let next_before_revision = has_more.then(|| {
        items
            .last()
            .expect("a page with another item must return at least one item")
            .revision
    });
    let page = KnowledgeCatalogRevisionPage {
        current_revision: current.revision,
        items,
        next_before_revision,
    };
    transaction.commit()?;
    Ok(page)
}

fn require_knowledge_corpus_capacity(
    connection: &Connection,
    account_id: &str,
    corpus_digest: &str,
    envelope_bytes: i64,
) -> Result<(), StorageError> {
    let exists: i64 = connection.query_row(
        r#"SELECT EXISTS(
               SELECT 1 FROM knowledge_corpus_revisions
               WHERE account_id = ?1 AND digest = ?2
           )"#,
        params![account_id, corpus_digest],
        |row| row.get(0),
    )?;
    if exists != 0 {
        return Ok(());
    }
    let (count, bytes): (i64, i64) = connection.query_row(
        r#"SELECT COUNT(*), COALESCE(SUM(length(CAST(envelope_json AS BLOB))), 0)
           FROM knowledge_corpus_revisions WHERE account_id = ?1"#,
        [account_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if count >= KNOWLEDGE_CORPUS_MAX_REVISIONS_PER_ACCOUNT
        || bytes
            .checked_add(envelope_bytes)
            .is_none_or(|total| total > KNOWLEDGE_CORPUS_MAX_ENVELOPE_BYTES_PER_ACCOUNT)
    {
        return Err(StorageError::StorageQuotaExceeded);
    }
    Ok(())
}

pub(super) fn replace_account_knowledge_catalog(
    connection: &mut Connection,
    context: &AuthzContext,
    commit: KnowledgeCatalogCommit,
    limits: &StorageLimits,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<KnowledgeCatalogUpdateResult, StorageError> {
    let key = normalized_key(&commit.idempotency_key)?.to_owned();
    commit
        .corpus
        .validate()
        .map_err(invalid_knowledge_catalog)?;
    let corpus_digest = commit.corpus.digest().to_hex();
    let corpus_json = commit
        .corpus
        .canonical_json()
        .map_err(invalid_knowledge_catalog)?;
    let corpus_bytes = i64::try_from(corpus_json.len())
        .map_err(|_| StorageError::IntegerOutOfRange("knowledge corpus envelope bytes"))?;
    let request_fingerprint =
        knowledge_catalog_fingerprint(commit.expected_revision, &corpus_digest)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_current_authority(&transaction, context, AccountCapability::AccountAdmin)?;

    let stored_receipt = transaction
        .query_row(
            r#"SELECT actor_membership_revision, request_fingerprint,
                      catalog_revision, corpus_digest, created_at
               FROM knowledge_catalog_receipts
               WHERE account_id = ?1 AND actor_user_id = ?2 AND idempotency_key = ?3"#,
            params![context.account_id.as_str(), context.user_id, key],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;
    if let Some((actor_revision, fingerprint, revision, stored_digest, created_at)) = stored_receipt
    {
        if decode_membership_revision(actor_revision)? != context.membership_revision
            || fingerprint != request_fingerprint
            || stored_digest != corpus_digest
        {
            return Err(StorageError::IdempotencyConflict);
        }
        let revision = i64_to_u64(revision, "knowledge catalog receipt revision")?;
        let current = query_account_knowledge_catalog(&transaction, context.account_id.as_str())?;
        if current.revision < revision {
            return Err(StorageError::CorruptData(
                "knowledge catalog receipt is ahead of the catalog head".into(),
            ));
        }
        let catalog = KnowledgeCatalogState {
            account_id: context.account_id.clone(),
            revision,
            corpus: query_stored_knowledge_corpus(
                &transaction,
                context.account_id.as_str(),
                &stored_digest,
            )?,
            updated_by_user_id: Some(context.user_id.clone()),
            updated_by_membership_revision: Some(context.membership_revision),
            updated_at: Some(created_at),
        };
        transaction.commit()?;
        return Ok(KnowledgeCatalogUpdateResult {
            catalog,
            replayed: true,
        });
    }

    let current = query_account_knowledge_catalog(&transaction, context.account_id.as_str())?;
    if current.revision != commit.expected_revision {
        return Err(StorageError::KnowledgeCatalogRevisionConflict);
    }
    if current.corpus.digest().to_hex() == corpus_digest {
        return Err(StorageError::InvalidKnowledgeCatalog(
            "the replacement corpus is already active".into(),
        ));
    }
    if current.revision >= KNOWLEDGE_CATALOG_MAX_REVISIONS_PER_ACCOUNT {
        return Err(StorageError::StorageQuotaExceeded);
    }
    let next_revision = current
        .revision
        .checked_add(1)
        .ok_or(StorageError::IntegerOutOfRange(
            "knowledge catalog revision",
        ))?;
    require_knowledge_corpus_capacity(
        &transaction,
        context.account_id.as_str(),
        &corpus_digest,
        corpus_bytes,
    )?;
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Admission,
    )?;
    let timestamp = now();
    prepare_account_audit_admission(
        &transaction,
        context.account_id.as_str(),
        AuditAdmission::General,
        limits,
        &timestamp,
    )?;
    persist_agent_knowledge_corpus(
        &transaction,
        context.account_id.as_str(),
        &commit.corpus,
        &timestamp,
    )
    .map_err(|error| match error {
        StorageError::InvalidAgentTransition(message) => {
            StorageError::InvalidKnowledgeCatalog(message)
        }
        other => other,
    })?;
    let next_revision_sql = u64_to_i64(next_revision, "knowledge catalog revision")?;
    let actor_revision_sql = u64_to_i64(
        context.membership_revision.get(),
        "knowledge catalog membership revision",
    )?;
    let changed = if current.revision == 0 {
        transaction.execute(
            r#"INSERT INTO account_knowledge_catalogs(
                   account_id, revision, active_corpus_digest, updated_by_user_id,
                   updated_by_membership_revision, updated_at
               ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)"#,
            params![
                context.account_id.as_str(),
                next_revision_sql,
                corpus_digest,
                context.user_id,
                actor_revision_sql,
                timestamp,
            ],
        )?
    } else {
        transaction.execute(
            r#"UPDATE account_knowledge_catalogs
               SET revision = ?1, active_corpus_digest = ?2,
                   updated_by_user_id = ?3, updated_by_membership_revision = ?4,
                   updated_at = ?5
               WHERE account_id = ?6 AND revision = ?7"#,
            params![
                next_revision_sql,
                corpus_digest,
                context.user_id,
                actor_revision_sql,
                timestamp,
                context.account_id.as_str(),
                u64_to_i64(current.revision, "knowledge catalog expected revision")?,
            ],
        )?
    };
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    transaction.execute(
        r#"INSERT INTO knowledge_catalog_receipts(
               account_id, actor_user_id, actor_membership_revision,
               idempotency_key, request_fingerprint, catalog_revision,
               corpus_digest, created_at
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
        params![
            context.account_id.as_str(),
            context.user_id,
            actor_revision_sql,
            key,
            request_fingerprint,
            next_revision_sql,
            corpus_digest,
            timestamp,
        ],
    )?;
    append_account_audit_event(
        &transaction,
        context.account_id.as_str(),
        AccountAuditEventInput {
            actor_user_id: Some(&context.user_id),
            action: "knowledge.catalog.updated",
            target_kind: "knowledge_catalog",
            target_id: &corpus_digest,
            metadata: json!({
                "previous_revision": current.revision,
                "revision": next_revision,
                "corpus_digest": corpus_digest,
                "entry_count": commit.corpus.entries().len(),
                "aggregate_entry_bytes": aggregate_corpus_entry_bytes(&commit.corpus)?,
            }),
        },
        &timestamp,
    )?;
    let catalog = KnowledgeCatalogState {
        account_id: context.account_id.clone(),
        revision: next_revision,
        corpus: commit.corpus,
        updated_by_user_id: Some(context.user_id.clone()),
        updated_by_membership_revision: Some(context.membership_revision),
        updated_at: Some(timestamp),
    };
    transaction.commit()?;
    Ok(KnowledgeCatalogUpdateResult {
        catalog,
        replayed: false,
    })
}

pub(super) fn verify_account_knowledge_catalog_integrity(
    connection: &Connection,
) -> Result<(), StorageError> {
    let account_capacity_violation: i64 = connection.query_row(
        r#"SELECT EXISTS(
               SELECT account_id
               FROM knowledge_corpus_revisions
               GROUP BY account_id
               HAVING COUNT(*) > ?1
                  OR SUM(length(CAST(envelope_json AS BLOB))) > ?2
           )"#,
        params![
            KNOWLEDGE_CORPUS_MAX_REVISIONS_PER_ACCOUNT,
            KNOWLEDGE_CORPUS_MAX_ENVELOPE_BYTES_PER_ACCOUNT,
        ],
        |row| row.get(0),
    )?;
    if account_capacity_violation != 0 {
        return Err(StorageError::CorruptData(
            "account knowledge corpus history exceeds its durable capacity".into(),
        ));
    }
    let orphan_receipt: i64 = connection.query_row(
        r#"SELECT EXISTS(
               SELECT 1 FROM knowledge_catalog_receipts receipt
               LEFT JOIN account_knowledge_catalogs catalog
                 ON catalog.account_id = receipt.account_id
               WHERE catalog.account_id IS NULL
           )"#,
        [],
        |row| row.get(0),
    )?;
    if orphan_receipt != 0 {
        return Err(StorageError::CorruptData(
            "knowledge catalog receipt has no catalog head".into(),
        ));
    }
    let account_ids = {
        let mut statement = connection
            .prepare("SELECT account_id FROM account_knowledge_catalogs ORDER BY account_id")?;
        statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };
    for account_id in account_ids {
        let catalog = query_account_knowledge_catalog(connection, &account_id)?;
        if catalog.revision == 0 || catalog.revision > KNOWLEDGE_CATALOG_MAX_REVISIONS_PER_ACCOUNT {
            return Err(StorageError::CorruptData(format!(
                "knowledge catalog `{account_id}` has an invalid revision"
            )));
        }
        let receipts = {
            let mut statement = connection.prepare(
                r#"SELECT actor_user_id, actor_membership_revision,
                          request_fingerprint, catalog_revision, corpus_digest, created_at
                   FROM knowledge_catalog_receipts
                   WHERE account_id = ?1 ORDER BY catalog_revision"#,
            )?;
            statement
                .query_map([&account_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        if u64::try_from(receipts.len()).ok() != Some(catalog.revision) {
            return Err(StorageError::CorruptData(format!(
                "knowledge catalog `{account_id}` receipt chain is incomplete"
            )));
        }
        for (index, (actor, actor_revision, fingerprint, revision, digest, created_at)) in
            receipts.iter().enumerate()
        {
            let expected_revision = u64::try_from(index)
                .map_err(|_| StorageError::IntegerOutOfRange("knowledge receipt index"))?
                .checked_add(1)
                .ok_or(StorageError::IntegerOutOfRange(
                    "knowledge receipt revision",
                ))?;
            if i64_to_u64(*revision, "knowledge receipt revision")? != expected_revision
                || *fingerprint != knowledge_catalog_fingerprint(expected_revision - 1, digest)?
            {
                return Err(StorageError::CorruptData(format!(
                    "knowledge catalog `{account_id}` receipt chain is inconsistent"
                )));
            }
            decode_membership_revision(*actor_revision)?;
            query_stored_knowledge_corpus(connection, &account_id, digest)?;
            if expected_revision == catalog.revision
                && (catalog.corpus.digest().to_hex() != *digest
                    || catalog.updated_by_user_id.as_deref() != Some(actor.as_str())
                    || catalog
                        .updated_by_membership_revision
                        .as_ref()
                        .map(|revision| revision.get())
                        != Some(i64_to_u64(
                            *actor_revision,
                            "knowledge catalog actor revision",
                        )?)
                    || catalog.updated_at.as_deref() != Some(created_at.as_str()))
            {
                return Err(StorageError::CorruptData(format!(
                    "knowledge catalog `{account_id}` head disagrees with its latest receipt"
                )));
            }
        }
    }
    Ok(())
}

fn invalid_agent_prompt(error: impl std::fmt::Display) -> StorageError {
    StorageError::InvalidAgentPrompt(error.to_string())
}

fn validate_agent_prompt_content(content: &str) -> Result<(), StorageError> {
    protocol::validate_user_message(content).map_err(invalid_agent_prompt)?;
    if content.len() > AGENT_SYSTEM_PROMPT_MAX_BYTES {
        return Err(StorageError::InvalidAgentPrompt(format!(
            "Agent prompt exceeds the {AGENT_SYSTEM_PROMPT_MAX_BYTES}-byte limit"
        )));
    }
    Ok(())
}

fn agent_prompt_binding_revision(revision: u64) -> Result<String, StorageError> {
    revision
        .checked_add(1)
        .map(|revision| revision.to_string())
        .ok_or(StorageError::IntegerOutOfRange(
            "Agent prompt binding revision",
        ))
}

fn default_agent_prompt_state(account_id: AccountId) -> Result<AgentPromptState, StorageError> {
    validate_agent_prompt_content(DEFAULT_SESSION_AGENT_SYSTEM_PROMPT)?;
    Ok(AgentPromptState {
        account_id,
        revision: 0,
        prompt_id: SESSION_AGENT_PROMPT_ID.to_owned(),
        binding_revision: DEFAULT_SESSION_AGENT_PROMPT_REVISION.to_owned(),
        content_digest: prompt_content_digest(DEFAULT_SESSION_AGENT_SYSTEM_PROMPT),
        content: DEFAULT_SESSION_AGENT_SYSTEM_PROMPT.to_owned(),
        updated_by_user_id: None,
        updated_by_membership_revision: None,
        updated_at: None,
    })
}

fn query_stored_agent_prompt(
    connection: &Connection,
    account_id: &str,
    digest: &str,
) -> Result<String, StorageError> {
    let stored = connection
        .query_row(
            r#"SELECT content_bytes, content
               FROM agent_prompt_revisions
               WHERE account_id = ?1 AND digest = ?2"#,
            params![account_id, digest],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .ok_or_else(|| {
            StorageError::CorruptData(format!("Agent prompt `{account_id}/{digest}` is missing"))
        })?;
    validate_agent_prompt_content(&stored.1).map_err(|error| {
        StorageError::CorruptData(format!(
            "Agent prompt `{account_id}/{digest}` is invalid: {error}"
        ))
    })?;
    let content_bytes = i64::try_from(stored.1.len())
        .map_err(|_| StorageError::IntegerOutOfRange("stored Agent prompt bytes"))?;
    if stored.0 != content_bytes || prompt_content_digest(&stored.1) != digest {
        return Err(StorageError::CorruptData(format!(
            "Agent prompt `{account_id}/{digest}` disagrees with its SQL projection"
        )));
    }
    Ok(stored.1)
}

pub(super) fn query_account_agent_prompt(
    connection: &Connection,
    account_id: &str,
) -> Result<AgentPromptState, StorageError> {
    let account_id_value = decode_account_id(account_id.to_owned())?;
    let stored = connection
        .query_row(
            r#"SELECT revision, active_prompt_digest, updated_by_user_id,
                      updated_by_membership_revision, updated_at
               FROM account_agent_prompt_configs WHERE account_id = ?1"#,
            [account_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((revision, digest, actor_user_id, actor_revision, updated_at)) = stored else {
        return default_agent_prompt_state(account_id_value);
    };
    let revision = i64_to_u64(revision, "Agent prompt revision")?;
    Ok(AgentPromptState {
        account_id: account_id_value,
        revision,
        prompt_id: SESSION_AGENT_PROMPT_ID.to_owned(),
        binding_revision: agent_prompt_binding_revision(revision)?,
        content: query_stored_agent_prompt(connection, account_id, &digest)?,
        content_digest: digest,
        updated_by_user_id: Some(actor_user_id),
        updated_by_membership_revision: Some(decode_membership_revision(actor_revision)?),
        updated_at: Some(updated_at),
    })
}

pub(super) fn query_account_agent_prompt_for_admin(
    connection: &Connection,
    context: &AuthzContext,
) -> Result<AgentPromptState, StorageError> {
    require_current_authority(connection, context, AccountCapability::AccountAdmin)?;
    query_account_agent_prompt(connection, context.account_id.as_str())
}

pub(super) fn query_active_agent_prompt_for_actor(
    connection: &Connection,
    context: &AuthzContext,
) -> Result<AgentPromptState, StorageError> {
    require_current_authority(connection, context, AccountCapability::Reply)?;
    query_account_agent_prompt(connection, context.account_id.as_str())
}

fn agent_prompt_fingerprint(
    expected_revision: u64,
    prompt_digest: &str,
) -> Result<String, StorageError> {
    Ok(serde_json::to_string(&json!({
        "expected_revision": expected_revision,
        "prompt_digest": prompt_digest,
    }))?)
}

fn require_agent_prompt_capacity(
    connection: &Connection,
    account_id: &str,
    digest: &str,
    content_bytes: i64,
) -> Result<(), StorageError> {
    let exists: i64 = connection.query_row(
        r#"SELECT EXISTS(
               SELECT 1 FROM agent_prompt_revisions
               WHERE account_id = ?1 AND digest = ?2
           )"#,
        params![account_id, digest],
        |row| row.get(0),
    )?;
    if exists != 0 {
        return Ok(());
    }
    let (count, bytes): (i64, i64) = connection.query_row(
        r#"SELECT COUNT(*), COALESCE(SUM(content_bytes), 0)
           FROM agent_prompt_revisions WHERE account_id = ?1"#,
        [account_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if count >= AGENT_PROMPT_MAX_DISTINCT_REVISIONS_PER_ACCOUNT
        || bytes
            .checked_add(content_bytes)
            .is_none_or(|total| total > AGENT_PROMPT_MAX_CONTENT_BYTES_PER_ACCOUNT)
    {
        return Err(StorageError::StorageQuotaExceeded);
    }
    Ok(())
}

pub(super) fn replace_account_agent_prompt(
    connection: &mut Connection,
    context: &AuthzContext,
    commit: AgentPromptCommit,
    limits: &StorageLimits,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<AgentPromptUpdateResult, StorageError> {
    let key = normalized_key(&commit.idempotency_key)?.to_owned();
    validate_agent_prompt_content(&commit.content)?;
    let prompt_digest = prompt_content_digest(&commit.content);
    let content_bytes = i64::try_from(commit.content.len())
        .map_err(|_| StorageError::IntegerOutOfRange("Agent prompt bytes"))?;
    let request_fingerprint = agent_prompt_fingerprint(commit.expected_revision, &prompt_digest)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_current_authority(&transaction, context, AccountCapability::AccountAdmin)?;

    let stored_receipt = transaction
        .query_row(
            r#"SELECT actor_membership_revision, request_fingerprint,
                      prompt_revision, prompt_digest, created_at
               FROM agent_prompt_config_receipts
               WHERE account_id = ?1 AND actor_user_id = ?2 AND idempotency_key = ?3"#,
            params![context.account_id.as_str(), context.user_id, key],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;
    if let Some((actor_revision, fingerprint, revision, stored_digest, created_at)) = stored_receipt
    {
        if decode_membership_revision(actor_revision)? != context.membership_revision
            || fingerprint != request_fingerprint
            || stored_digest != prompt_digest
        {
            return Err(StorageError::IdempotencyConflict);
        }
        let revision = i64_to_u64(revision, "Agent prompt receipt revision")?;
        let current = query_account_agent_prompt(&transaction, context.account_id.as_str())?;
        if current.revision < revision {
            return Err(StorageError::CorruptData(
                "Agent prompt receipt is ahead of the configuration head".into(),
            ));
        }
        let prompt = AgentPromptState {
            account_id: context.account_id.clone(),
            revision,
            prompt_id: SESSION_AGENT_PROMPT_ID.to_owned(),
            binding_revision: agent_prompt_binding_revision(revision)?,
            content: query_stored_agent_prompt(
                &transaction,
                context.account_id.as_str(),
                &stored_digest,
            )?,
            content_digest: stored_digest,
            updated_by_user_id: Some(context.user_id.clone()),
            updated_by_membership_revision: Some(context.membership_revision),
            updated_at: Some(created_at),
        };
        transaction.commit()?;
        return Ok(AgentPromptUpdateResult {
            prompt,
            replayed: true,
        });
    }

    let current = query_account_agent_prompt(&transaction, context.account_id.as_str())?;
    if current.revision != commit.expected_revision {
        return Err(StorageError::AgentPromptRevisionConflict);
    }
    if current.content_digest == prompt_digest {
        return Err(StorageError::InvalidAgentPrompt(
            "the replacement Agent prompt is already active".into(),
        ));
    }
    if current.revision >= AGENT_PROMPT_MAX_REVISIONS_PER_ACCOUNT {
        return Err(StorageError::StorageQuotaExceeded);
    }
    let next_revision = current
        .revision
        .checked_add(1)
        .ok_or(StorageError::IntegerOutOfRange("Agent prompt revision"))?;
    require_agent_prompt_capacity(
        &transaction,
        context.account_id.as_str(),
        &prompt_digest,
        content_bytes,
    )?;
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Admission,
    )?;
    let timestamp = now();
    prepare_account_audit_admission(
        &transaction,
        context.account_id.as_str(),
        AuditAdmission::General,
        limits,
        &timestamp,
    )?;
    transaction.execute(
        r#"INSERT OR IGNORE INTO agent_prompt_revisions(
               account_id, digest, content_bytes, content, created_at
           ) VALUES (?1, ?2, ?3, ?4, ?5)"#,
        params![
            context.account_id.as_str(),
            prompt_digest,
            content_bytes,
            commit.content,
            timestamp,
        ],
    )?;
    let persisted_content =
        query_stored_agent_prompt(&transaction, context.account_id.as_str(), &prompt_digest)?;
    if persisted_content != commit.content {
        return Err(StorageError::CorruptData(
            "content-addressed Agent prompt revision disagrees with the replacement".into(),
        ));
    }
    let next_revision_sql = u64_to_i64(next_revision, "Agent prompt revision")?;
    let actor_revision_sql = u64_to_i64(
        context.membership_revision.get(),
        "Agent prompt membership revision",
    )?;
    let changed = if current.revision == 0 {
        transaction.execute(
            r#"INSERT INTO account_agent_prompt_configs(
                   account_id, revision, active_prompt_digest, updated_by_user_id,
                   updated_by_membership_revision, updated_at
               ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)"#,
            params![
                context.account_id.as_str(),
                next_revision_sql,
                prompt_digest,
                context.user_id,
                actor_revision_sql,
                timestamp,
            ],
        )?
    } else {
        transaction.execute(
            r#"UPDATE account_agent_prompt_configs
               SET revision = ?1, active_prompt_digest = ?2,
                   updated_by_user_id = ?3, updated_by_membership_revision = ?4,
                   updated_at = ?5
               WHERE account_id = ?6 AND revision = ?7"#,
            params![
                next_revision_sql,
                prompt_digest,
                context.user_id,
                actor_revision_sql,
                timestamp,
                context.account_id.as_str(),
                u64_to_i64(current.revision, "Agent prompt expected revision")?,
            ],
        )?
    };
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    transaction.execute(
        r#"INSERT INTO agent_prompt_config_receipts(
               account_id, actor_user_id, actor_membership_revision,
               idempotency_key, request_fingerprint, prompt_revision,
               prompt_digest, created_at
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
        params![
            context.account_id.as_str(),
            context.user_id,
            actor_revision_sql,
            key,
            request_fingerprint,
            next_revision_sql,
            prompt_digest,
            timestamp,
        ],
    )?;
    let binding_revision = agent_prompt_binding_revision(next_revision)?;
    append_account_audit_event(
        &transaction,
        context.account_id.as_str(),
        AccountAuditEventInput {
            actor_user_id: Some(&context.user_id),
            action: "agent.prompt.updated",
            target_kind: "agent_prompt",
            target_id: SESSION_AGENT_PROMPT_ID,
            metadata: json!({
                "previous_revision": current.revision,
                "revision": next_revision,
                "binding_revision": binding_revision,
                "prompt_digest": prompt_digest,
                "content_bytes": content_bytes,
            }),
        },
        &timestamp,
    )?;
    let prompt = AgentPromptState {
        account_id: context.account_id.clone(),
        revision: next_revision,
        prompt_id: SESSION_AGENT_PROMPT_ID.to_owned(),
        binding_revision,
        content_digest: prompt_digest,
        content: commit.content,
        updated_by_user_id: Some(context.user_id.clone()),
        updated_by_membership_revision: Some(context.membership_revision),
        updated_at: Some(timestamp),
    };
    transaction.commit()?;
    Ok(AgentPromptUpdateResult {
        prompt,
        replayed: false,
    })
}

pub(super) fn verify_account_agent_prompt_integrity(
    connection: &Connection,
) -> Result<(), StorageError> {
    let capacity_violation: i64 = connection.query_row(
        r#"SELECT EXISTS(
               SELECT account_id
               FROM agent_prompt_revisions
               GROUP BY account_id
               HAVING COUNT(*) > ?1 OR SUM(content_bytes) > ?2
           )"#,
        params![
            AGENT_PROMPT_MAX_DISTINCT_REVISIONS_PER_ACCOUNT,
            AGENT_PROMPT_MAX_CONTENT_BYTES_PER_ACCOUNT,
        ],
        |row| row.get(0),
    )?;
    if capacity_violation != 0 {
        return Err(StorageError::CorruptData(
            "account Agent prompt history exceeds its durable capacity".into(),
        ));
    }
    let orphan: i64 = connection.query_row(
        r#"SELECT EXISTS(
               SELECT 1 FROM agent_prompt_config_receipts receipt
               LEFT JOIN account_agent_prompt_configs config
                 ON config.account_id = receipt.account_id
               WHERE config.account_id IS NULL
           )"#,
        [],
        |row| row.get(0),
    )?;
    if orphan != 0 {
        return Err(StorageError::CorruptData(
            "Agent prompt receipt has no configuration head".into(),
        ));
    }
    let unreferenced_revision: i64 = connection.query_row(
        r#"SELECT EXISTS(
               SELECT 1 FROM agent_prompt_revisions prompt
               LEFT JOIN agent_prompt_config_receipts receipt
                 ON receipt.account_id = prompt.account_id
                AND receipt.prompt_digest = prompt.digest
               WHERE receipt.account_id IS NULL
           )"#,
        [],
        |row| row.get(0),
    )?;
    if unreferenced_revision != 0 {
        return Err(StorageError::CorruptData(
            "Agent prompt revision has no committed receipt".into(),
        ));
    }
    let account_ids = {
        let mut statement = connection
            .prepare("SELECT account_id FROM account_agent_prompt_configs ORDER BY account_id")?;
        statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };
    for account_id in account_ids {
        let prompt = query_account_agent_prompt(connection, &account_id)?;
        if prompt.revision == 0 || prompt.revision > AGENT_PROMPT_MAX_REVISIONS_PER_ACCOUNT {
            return Err(StorageError::CorruptData(format!(
                "Agent prompt configuration `{account_id}` has an invalid revision"
            )));
        }
        let receipts = {
            let mut statement = connection.prepare(
                r#"SELECT actor_user_id, actor_membership_revision,
                          request_fingerprint, prompt_revision, prompt_digest, created_at
                   FROM agent_prompt_config_receipts
                   WHERE account_id = ?1 ORDER BY prompt_revision"#,
            )?;
            statement
                .query_map([&account_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        if u64::try_from(receipts.len()).ok() != Some(prompt.revision) {
            return Err(StorageError::CorruptData(format!(
                "Agent prompt configuration `{account_id}` receipt chain is incomplete"
            )));
        }
        for (index, (actor, actor_revision, fingerprint, revision, digest, created_at)) in
            receipts.iter().enumerate()
        {
            let expected_revision = u64::try_from(index)
                .map_err(|_| StorageError::IntegerOutOfRange("Agent prompt receipt index"))?
                .checked_add(1)
                .ok_or(StorageError::IntegerOutOfRange(
                    "Agent prompt receipt revision",
                ))?;
            if i64_to_u64(*revision, "Agent prompt receipt revision")? != expected_revision
                || *fingerprint != agent_prompt_fingerprint(expected_revision - 1, digest)?
            {
                return Err(StorageError::CorruptData(format!(
                    "Agent prompt configuration `{account_id}` receipt chain is inconsistent"
                )));
            }
            decode_membership_revision(*actor_revision)?;
            query_stored_agent_prompt(connection, &account_id, digest)?;
            if expected_revision == prompt.revision
                && (prompt.content_digest != *digest
                    || prompt.updated_by_user_id.as_deref() != Some(actor.as_str())
                    || prompt
                        .updated_by_membership_revision
                        .as_ref()
                        .map(|revision| revision.get())
                        != Some(i64_to_u64(*actor_revision, "Agent prompt actor revision")?)
                    || prompt.updated_at.as_deref() != Some(created_at.as_str()))
            {
                return Err(StorageError::CorruptData(format!(
                    "Agent prompt configuration `{account_id}` head disagrees with its latest receipt"
                )));
            }
        }
    }
    Ok(())
}

fn query_legacy_agent_knowledge_boundary(
    connection: &Connection,
    agent_id: &str,
) -> Result<Option<StoredLegacyAgentKnowledgeBoundary>, StorageError> {
    connection
        .query_row(
            r#"SELECT agent_id, initial_model_job_id, execution_origin_fact_digest
               FROM agent_knowledge_legacy_agents WHERE agent_id = ?1"#,
            [agent_id],
            |row| {
                Ok(StoredLegacyAgentKnowledgeBoundary {
                    agent_id: row.get(0)?,
                    initial_model_job_id: row.get(1)?,
                    execution_origin_fact_digest: row.get(2)?,
                })
            },
        )
        .optional()
        .map_err(StorageError::from)
}

fn query_legacy_agent_knowledge_boundaries(
    connection: &Connection,
) -> Result<Vec<StoredLegacyAgentKnowledgeBoundary>, StorageError> {
    let mut statement = connection.prepare(
        r#"SELECT agent_id, initial_model_job_id, execution_origin_fact_digest
           FROM agent_knowledge_legacy_agents ORDER BY agent_id"#,
    )?;
    statement
        .query_map([], |row| {
            Ok(StoredLegacyAgentKnowledgeBoundary {
                agent_id: row.get(0)?,
                initial_model_job_id: row.get(1)?,
                execution_origin_fact_digest: row.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(StorageError::from)
}

fn legacy_agent_knowledge_set_digest(
    boundaries: &[StoredLegacyAgentKnowledgeBoundary],
) -> Result<String, StorageError> {
    let mut digest = Sha256::new();
    digest.update(AGENT_KNOWLEDGE_LEGACY_SET_DIGEST_DOMAIN);
    digest.update(
        usize_to_u64(boundaries.len(), "legacy Agent knowledge boundary count")?.to_be_bytes(),
    );
    for boundary in boundaries {
        for value in [
            boundary.agent_id.as_bytes(),
            boundary.initial_model_job_id.as_bytes(),
            boundary.execution_origin_fact_digest.as_bytes(),
        ] {
            digest.update(
                usize_to_u64(value.len(), "legacy Agent knowledge boundary field bytes")?
                    .to_be_bytes(),
            );
            digest.update(value);
        }
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn query_legacy_agent_knowledge_commitment(
    connection: &Connection,
) -> Result<StoredLegacyAgentKnowledgeCommitment, StorageError> {
    connection
        .query_row(
            r#"SELECT agent_count, set_digest
               FROM agent_knowledge_legacy_boundary
               WHERE singleton = 1 AND schema_version = 1"#,
            [],
            |row| {
                Ok(StoredLegacyAgentKnowledgeCommitment {
                    agent_count: row.get(0)?,
                    set_digest: row.get(1)?,
                })
            },
        )
        .optional()?
        .ok_or_else(|| {
            StorageError::CorruptData(
                "the legacy Agent knowledge boundary commitment is missing".into(),
            )
        })
}

fn verify_legacy_agent_knowledge_boundary_commitment(
    connection: &Connection,
) -> Result<(), StorageError> {
    let commitment = query_legacy_agent_knowledge_commitment(connection)?;
    let boundaries = query_legacy_agent_knowledge_boundaries(connection)?;
    let agent_count = i64::try_from(boundaries.len())
        .map_err(|_| StorageError::IntegerOutOfRange("legacy Agent knowledge boundary count"))?;
    let set_digest = legacy_agent_knowledge_set_digest(&boundaries)?;
    if commitment.agent_count != agent_count || commitment.set_digest != set_digest {
        return Err(StorageError::CorruptData(
            "the frozen legacy Agent knowledge set disagrees with its migration commitment".into(),
        ));
    }
    Ok(())
}

pub(super) fn seal_legacy_agent_knowledge_boundary(
    connection: &Connection,
) -> Result<(), StorageError> {
    let boundaries = query_legacy_agent_knowledge_boundaries(connection)?;
    let agent_count = i64::try_from(boundaries.len())
        .map_err(|_| StorageError::IntegerOutOfRange("legacy Agent knowledge boundary count"))?;
    let set_digest = legacy_agent_knowledge_set_digest(&boundaries)?;
    let inserted = connection.execute(
        r#"INSERT INTO agent_knowledge_legacy_boundary(
               singleton, schema_version, agent_count, set_digest
           ) VALUES (1, 1, ?1, ?2)"#,
        params![agent_count, set_digest],
    )?;
    if inserted != 1 {
        return Err(StorageError::CorruptData(
            "the legacy Agent knowledge boundary commitment was not sealed exactly once".into(),
        ));
    }
    Ok(())
}

fn agent_matches_frozen_legacy_knowledge_boundary(
    connection: &Connection,
    agent: &AgentTurn,
    initial_job: &AgentModelJob,
) -> Result<bool, StorageError> {
    let Some(boundary) = query_legacy_agent_knowledge_boundary(connection, &agent.id)? else {
        return Ok(false);
    };
    let origin_fact_digest = connection
        .query_row(
            r#"SELECT fact_digest FROM agent_execution_events
               WHERE agent_id = ?1 AND sequence = 1"#,
            [&agent.id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| {
            StorageError::CorruptData(format!(
                "legacy Agent `{}` has no execution-origin fact",
                agent.id
            ))
        })?;
    if boundary.agent_id != agent.id
        || boundary.initial_model_job_id != initial_job.id
        || boundary.execution_origin_fact_digest != origin_fact_digest
        || initial_job.step != 1
        || initial_job.agent_id != agent.id
        || initial_job.account_id != agent.account_id
        || initial_job.actor_user_id != agent.actor_user_id
        || initial_job.actor_membership_revision != agent.actor_membership_revision
        || initial_job.session_id != agent.session_id
        || initial_job.turn_id != agent.turn_id
        || agent.knowledge_context_digest.is_some()
        || initial_job.knowledge_context_digest.is_some()
    {
        return Err(StorageError::CorruptData(format!(
            "legacy Agent `{}` disagrees with its frozen knowledge boundary",
            agent.id
        )));
    }
    Ok(true)
}

pub(super) fn agent_has_frozen_legacy_knowledge_boundary(
    connection: &Connection,
    agent: &AgentTurn,
    initial_job: &AgentModelJob,
) -> Result<bool, StorageError> {
    if query_legacy_agent_knowledge_boundary(connection, &agent.id)?.is_none() {
        return Ok(false);
    }
    verify_legacy_agent_knowledge_boundary_commitment(connection)?;
    agent_matches_frozen_legacy_knowledge_boundary(connection, agent, initial_job)
}

fn load_and_validate_agent_knowledge_context(
    connection: &Connection,
    agent: &AgentTurn,
) -> Result<(StoredAgentKnowledgeContext, String, AgentKnowledgeDigests), StorageError> {
    let initial_job = query_agent_model_job(connection, &agent.id, 1)?;
    let frozen_legacy =
        agent_has_frozen_legacy_knowledge_boundary(connection, agent, &initial_job)?;
    let digest = match (agent.knowledge_context_digest.as_deref(), frozen_legacy) {
        (None, true) => {
            return Err(StorageError::InvalidAgentTransition(
                "legacy Agent has no durable knowledge context and cannot execute".into(),
            ));
        }
        (None, false) => {
            return Err(StorageError::CorruptData(format!(
                "Agent `{}` lost its required durable knowledge context",
                agent.id
            )));
        }
        (Some(_), true) => {
            return Err(StorageError::CorruptData(format!(
                "legacy Agent `{}` was rebound after the frozen knowledge boundary",
                agent.id
            )));
        }
        (Some(digest), false) => digest,
    };
    let context = query_stored_agent_knowledge_context(connection, digest)?;
    let membership_revision = i64_to_u64(
        context.actor_membership_revision,
        "Agent knowledge membership revision",
    )?;
    if context.schema_version != i64::from(AGENT_KNOWLEDGE_BINDING_SCHEMA_VERSION)
        || context.digest != digest
        || context.account_id != agent.account_id.as_str()
        || context.actor_user_id != agent.actor_user_id
        || membership_revision != agent.actor_membership_revision.get()
        || context.session_id != agent.session_id
        || context.turn_id != agent.turn_id
        || context.agent_id != agent.id
        || context.created_at != agent.created_at
    {
        return Err(StorageError::CorruptData(format!(
            "Agent `{}` disagrees with its durable knowledge identity",
            agent.id
        )));
    }

    let corpus = query_stored_knowledge_corpus(
        connection,
        agent.account_id.as_str(),
        &context.corpus_digest,
    )?;
    let snapshot =
        knowledge::SelectionSnapshotEnvelope::from_canonical_json(&context.snapshot_envelope_json)
            .map_err(corrupt_knowledge_context)?;
    let turn = query_session_turn(connection, &agent.session_id, &agent.turn_id)?;
    snapshot
        .validate_for_selection(&turn.user_message, corpus.entries())
        .map_err(corrupt_knowledge_context)?;
    let selection = snapshot.snapshot();
    let context_bytes = u32::try_from(context.context_bytes)
        .map_err(|_| StorageError::IntegerOutOfRange("Agent knowledge context bytes"))?;
    if corpus.digest().to_hex() != context.corpus_digest
        || snapshot.digest().to_hex() != context.snapshot_digest
        || selection.query_digest().to_hex() != context.query_digest
        || selection.context_digest().to_hex() != context.context_digest
        || selection.context_bytes() != context_bytes
        || selection.canonical_context() != context.canonical_context
    {
        return Err(StorageError::CorruptData(format!(
            "Agent `{}` knowledge snapshot disagrees with its SQL projection",
            agent.id
        )));
    }

    let binding = AgentKnowledgeContextBinding {
        schema_version: AGENT_KNOWLEDGE_BINDING_SCHEMA_VERSION,
        account_id: &context.account_id,
        actor_user_id: &context.actor_user_id,
        actor_membership_revision: membership_revision,
        session_id: &context.session_id,
        turn_id: &context.turn_id,
        agent_id: &context.agent_id,
        initial_model_job_id: &context.initial_model_job_id,
        corpus_digest: &context.corpus_digest,
        snapshot_digest: &context.snapshot_digest,
        query_digest: &context.query_digest,
        context_digest: &context.context_digest,
        context_bytes,
        canonical_context: &context.canonical_context,
        created_at: &context.created_at,
    };
    let expected_binding_json =
        agent_knowledge_binding_json(&binding).map_err(corrupt_knowledge_context)?;
    if context.binding_json != expected_binding_json
        || context.digest != agent_knowledge_binding_digest(&expected_binding_json)
    {
        return Err(StorageError::CorruptData(format!(
            "Agent `{}` knowledge binding digest is inconsistent",
            agent.id
        )));
    }

    if initial_job.id != context.initial_model_job_id
        || initial_job.agent_id != agent.id
        || initial_job.account_id != agent.account_id
        || initial_job.actor_user_id != agent.actor_user_id
        || initial_job.actor_membership_revision != agent.actor_membership_revision
        || initial_job.session_id != agent.session_id
        || initial_job.turn_id != agent.turn_id
        || initial_job.step != 1
        || initial_job.knowledge_context_digest.as_deref() != Some(context.digest.as_str())
        || initial_job.queued_at != context.created_at
    {
        return Err(StorageError::CorruptData(format!(
            "Agent `{}` initial model job disagrees with its knowledge binding",
            agent.id
        )));
    }
    validate_request_knowledge_context(
        &initial_job.request_json,
        &context.canonical_context,
        Some(&turn.user_message),
    )
    .map_err(corrupt_knowledge_context)?;

    let digests = AgentKnowledgeDigests {
        context: Sha256Digest::from_hex(&context.digest).map_err(corrupt_knowledge_context)?,
        corpus: Sha256Digest::from_hex(&context.corpus_digest)
            .map_err(corrupt_knowledge_context)?,
        snapshot: Sha256Digest::from_hex(&context.snapshot_digest)
            .map_err(corrupt_knowledge_context)?,
    };
    Ok((context, turn.user_message, digests))
}

fn require_agent_knowledge_request_integrity(
    connection: &Connection,
    agent: &AgentTurn,
    request_json: &Value,
) -> Result<(), StorageError> {
    let (context, query, _) = load_and_validate_agent_knowledge_context(connection, agent)?;
    validate_request_knowledge_context(request_json, &context.canonical_context, Some(&query))
        .map_err(corrupt_knowledge_context)
}

pub(super) fn require_agent_knowledge_context_integrity(
    connection: &Connection,
    agent: &AgentTurn,
    job: &AgentModelJob,
) -> Result<AgentKnowledgeDigests, StorageError> {
    let (context, query, digests) = load_and_validate_agent_knowledge_context(connection, agent)?;
    if job.agent_id != agent.id
        || job.account_id != agent.account_id
        || job.actor_user_id != agent.actor_user_id
        || job.actor_membership_revision != agent.actor_membership_revision
        || job.session_id != agent.session_id
        || job.turn_id != agent.turn_id
        || job.knowledge_context_digest.as_deref() != Some(context.digest.as_str())
    {
        return Err(StorageError::CorruptData(format!(
            "Agent model job `{}` disagrees with its knowledge binding",
            job.id
        )));
    }
    validate_request_knowledge_context(&job.request_json, &context.canonical_context, Some(&query))
        .map_err(corrupt_knowledge_context)?;
    let manifest_digest = agent.deployment_manifest_digest.as_deref().ok_or_else(|| {
        StorageError::CorruptData(format!(
            "Agent `{}` has knowledge but no deployment manifest",
            agent.id
        ))
    })?;
    let manifest = query_agent_deployment_manifest(connection, manifest_digest)?;
    let latest_step = connection
        .query_row(
            "SELECT MAX(step) FROM agent_model_jobs WHERE agent_id = ?1",
            [&agent.id],
            |row| row.get::<_, Option<i64>>(0),
        )?
        .ok_or_else(|| {
            StorageError::CorruptData(format!("Agent `{}` has no durable model job", agent.id))
        })?;
    let latest_step = u32::try_from(latest_step)
        .map_err(|_| StorageError::IntegerOutOfRange("latest Agent model step"))?;
    if latest_step < job.step {
        return Err(StorageError::CorruptData(format!(
            "Agent model job `{}` is beyond the durable model-job head",
            job.id
        )));
    }
    require_agent_request_transcript_chain(
        connection,
        agent,
        latest_step,
        &manifest,
        &context.digest,
        &context.canonical_context,
        &query,
    )?;
    Ok(digests)
}

fn agent_knowledge_context_is_executable(
    connection: &Connection,
    agent: &AgentTurn,
    job: &AgentModelJob,
) -> Result<bool, StorageError> {
    match require_agent_knowledge_context_integrity(connection, agent, job) {
        Ok(_) => Ok(true),
        Err(StorageError::Sqlite(error)) => Err(StorageError::Sqlite(error)),
        Err(_) => Ok(false),
    }
}

pub(super) fn corrupt_agent_integrity(error: StorageError) -> StorageError {
    match error {
        error @ StorageError::Sqlite(_) => error,
        error @ StorageError::CorruptData(_) => error,
        other => StorageError::CorruptData(format!(
            "Agent durable integrity verification failed: {other}"
        )),
    }
}

pub(super) fn verify_agent_knowledge_context_integrity(
    connection: &Connection,
) -> Result<(), StorageError> {
    verify_legacy_agent_knowledge_boundary_commitment(connection)?;

    let corpora = {
        let mut statement = connection.prepare(
            r#"SELECT account_id, digest FROM knowledge_corpus_revisions
               ORDER BY account_id, digest"#,
        )?;
        statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    for (account_id, digest) in corpora {
        query_stored_knowledge_corpus(connection, &account_id, &digest)?;
    }

    let contexts = {
        let mut statement = connection.prepare(
            r#"SELECT digest, agent_id FROM agent_knowledge_contexts
               ORDER BY digest"#,
        )?;
        statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    for (digest, agent_id) in &contexts {
        let agent = query_agent_turn(connection, agent_id).map_err(|error| {
            StorageError::CorruptData(format!(
                "Agent knowledge context `{digest}` has no readable Agent: {error}"
            ))
        })?;
        if agent.knowledge_context_digest.as_deref() != Some(digest.as_str()) {
            return Err(StorageError::CorruptData(format!(
                "Agent knowledge context `{digest}` is not bound by its Agent"
            )));
        }
        let context = query_stored_agent_knowledge_context(connection, digest)?;
        let initial_job = query_agent_model_job_by_id(connection, &context.initial_model_job_id)?;
        require_agent_knowledge_context_integrity(connection, &agent, &initial_job)
            .map_err(corrupt_agent_integrity)?;
    }

    let agents = {
        let mut statement = connection
            .prepare(r#"SELECT id, knowledge_context_digest FROM agent_turns ORDER BY id"#)?;
        statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    let bound_agent_count = agents.iter().filter(|(_, digest)| digest.is_some()).count();
    if bound_agent_count != contexts.len() {
        return Err(StorageError::CorruptData(
            "Agent knowledge contexts do not form a one-to-one Agent binding".into(),
        ));
    }
    for (agent_id, context_digest) in agents {
        let agent = query_agent_turn(connection, &agent_id)?;
        let jobs = {
            let mut statement = connection.prepare(&format!(
                "{} WHERE agent_id = ?1 ORDER BY step",
                model_job_select()
            ))?;
            statement
                .query_map([&agent_id], decode_agent_model_job_row)?
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .map(StoredAgentModelJobRow::decode)
                .collect::<Result<Vec<_>, _>>()?
        };
        let initial_job = jobs.iter().find(|job| job.step == 1).ok_or_else(|| {
            StorageError::CorruptData(format!(
                "Agent `{agent_id}` has no initial model job for knowledge verification"
            ))
        })?;
        let frozen_legacy =
            agent_matches_frozen_legacy_knowledge_boundary(connection, &agent, initial_job)?;
        match (context_digest.as_deref(), frozen_legacy) {
            (Some(_), false) => {}
            (None, true) => {}
            (Some(_), true) => {
                return Err(StorageError::CorruptData(format!(
                    "legacy Agent `{agent_id}` was rebound after the frozen knowledge boundary"
                )));
            }
            (None, false) => {
                return Err(StorageError::CorruptData(format!(
                    "post-v22 Agent `{agent_id}` lost its required knowledge binding"
                )));
            }
        }
        for job in &jobs {
            if !frozen_legacy {
                require_agent_knowledge_context_integrity(connection, &agent, job)
                    .map_err(corrupt_agent_integrity)?;
            } else if job.knowledge_context_digest.is_some() {
                return Err(StorageError::CorruptData(format!(
                    "legacy Agent `{agent_id}` has a partially bound knowledge context"
                )));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_agent_turn_spec(spec: &AgentTurnSpec) -> Result<(), StorageError> {
    validate_agent_turn_receipt_probe(&spec.receipt_probe())?;
    validate_reply_json(
        &spec.request_json,
        "agent model request JSON",
        AGENT_REQUEST_JSON_MAX_BYTES,
    )?;
    validate_manifest_envelope(&spec.manifest, "Agent deployment manifest")?;
    require_manifest_matches_agent_spec(spec)?;
    validate_request_matches_manifest(
        &spec.request_json,
        &spec.manifest,
        AgentRequestPhase::Initial,
    )?;
    validate_agent_knowledge_spec(spec)?;
    WorkflowState::new(spec.manifest.manifest.deployment.spec.loop_limits.clone())
        .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?
        .validate()
        .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?;
    Ok(())
}

pub(super) fn validate_agent_turn_receipt_probe(
    probe: &AgentTurnReceiptProbe,
) -> Result<(), StorageError> {
    normalized_reply_value(&probe.id, "agent turn ID")?;
    if probe.id.len() > AGENT_ID_MAX_BYTES {
        return Err(StorageError::InvalidAgentTransition(format!(
            "agent turn ID cannot exceed {AGENT_ID_MAX_BYTES} UTF-8 bytes"
        )));
    }
    validated_authz_context(&probe.authz)?;
    normalized_account_value(
        &probe.environment,
        "agent environment",
        AGENT_ENVIRONMENT_MAX_BYTES,
    )?;
    protocol::validate_reply_provider_id(&probe.provider_name)
        .map_err(|error| invalid_resource_envelope("agent provider name", error))?;
    if let Some(model_name) = &probe.model_name {
        protocol::validate_reply_model_id(model_name)
            .map_err(|error| invalid_resource_envelope("agent model name", error))?;
    }
    Sha256Digest::from_hex(&probe.deployment_manifest_digest).map_err(|error| {
        StorageError::InvalidAgentTransition(format!(
            "invalid Agent deployment manifest digest: {error}"
        ))
    })?;
    Ok(())
}

pub(super) fn agent_start_fingerprint(
    session_id: &str,
    request: &StartTurnRequest,
    spec: &AgentTurnSpec,
) -> Result<String, StorageError> {
    agent_start_fingerprint_for_probe(session_id, request, &spec.receipt_probe())
}

pub(super) fn agent_start_fingerprint_for_probe(
    session_id: &str,
    request: &StartTurnRequest,
    probe: &AgentTurnReceiptProbe,
) -> Result<String, StorageError> {
    Ok(serde_json::to_string(&json!({
        "session_id": session_id,
        "request": request,
        "agent_turn": {
            "id": probe.id,
            "environment": probe.environment,
            "provider_name": probe.provider_name,
            "model_name": probe.model_name,
            "deployment_manifest_digest": probe.deployment_manifest_digest,
        },
    }))?)
}

pub(super) fn require_agent_matches_spec(
    agent: &AgentTurn,
    spec: &AgentTurnSpec,
) -> Result<(), StorageError> {
    require_agent_matches_probe(agent, &spec.receipt_probe())
}

pub(super) fn require_agent_matches_probe(
    agent: &AgentTurn,
    probe: &AgentTurnReceiptProbe,
) -> Result<(), StorageError> {
    // Like reply context, request_json is server-derived durable authority.
    if agent.id != probe.id
        || agent.account_id != probe.authz.account_id
        || agent.actor_user_id != probe.authz.user_id
        || agent.environment != probe.environment
        || agent.provider_name != probe.provider_name
        || agent.model_name != probe.model_name
        || agent.deployment_manifest_digest.as_deref()
            != Some(probe.deployment_manifest_digest.as_str())
    {
        return Err(StorageError::IdempotencyConflict);
    }
    // A receipt belongs to the stable account/user namespace, not to one
    // membership revision. Return the exact admitted work on replay; the
    // release gate still compares its stored revision with current authority
    // and rejects stale queued work before external I/O.
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
    if !manifest_matches_current_agent_prompt(
        connection,
        spec.authz.account_id.as_str(),
        &spec.manifest,
    )? {
        return Err(StorageError::InvalidAgentTransition(
            "Agent deployment manifest does not bind the active account Agent prompt".into(),
        ));
    }
    persist_agent_deployment_manifest(connection, &spec.manifest, queued_at)?;
    let job_id = model_job_id(&spec.id, 1);
    let knowledge_context_digest =
        persist_agent_knowledge_context(connection, session_id, turn_id, &job_id, spec, queued_at)?;
    let workflow_state =
        WorkflowState::new(spec.manifest.manifest.deployment.spec.loop_limits.clone())
            .map_err(|error| StorageError::InvalidAgentTransition(error.to_string()))?;
    connection.execute(
        r#"INSERT INTO agent_turns(
               id, account_id, actor_user_id, actor_membership_revision,
               session_id, turn_id, deployment_manifest_digest, knowledge_context_digest,
               environment, provider_name, model_name,
               status, model_steps, tool_calls, tool_result_bytes, revision,
               pending_call_id, workflow_state_json, last_error_json,
               created_at, updated_at, completed_at
           ) VALUES (
               ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
               'waiting_model', 0, 0, 0, 1, NULL, ?12, NULL, ?13, ?13, NULL
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
            knowledge_context_digest,
            spec.environment,
            spec.provider_name,
            spec.model_name,
            serde_json::to_string(&workflow_state)?,
            queued_at,
        ],
    )?;
    connection.execute(
        r#"INSERT INTO agent_model_jobs(
               id, agent_id, account_id, actor_user_id, actor_membership_revision,
               session_id, turn_id, step, provider_name, model_name,
               status, attempt, request_json, knowledge_context_digest,
               response_json, error_json,
               queued_at, started_at, finished_at
           ) VALUES (
               ?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9,
               'queued', 0, ?10, ?11, NULL, NULL, ?12, NULL, NULL
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
            knowledge_context_digest,
            queued_at,
        ],
    )?;
    let agent = query_agent_turn(connection, &spec.id)?;
    let job = query_agent_model_job(connection, &spec.id, 1)?;
    require_agent_knowledge_context_integrity(connection, &agent, &job)?;
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
              knowledge_context_digest,
              environment, provider_name, model_name,
              status, model_steps, tool_calls, tool_result_bytes, revision,
              pending_call_id, workflow_state_json, last_error_json,
              created_at, updated_at, completed_at
       FROM agent_turns"#
}

fn model_job_select() -> &'static str {
    r#"SELECT id, agent_id, account_id, actor_user_id, actor_membership_revision,
              session_id, turn_id, step, provider_name, model_name,
              status, attempt, request_json, knowledge_context_digest,
              response_json, error_json,
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
    knowledge_context_digest: Option<String>,
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
            knowledge_context_digest: self.knowledge_context_digest,
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
        knowledge_context_digest: row.get(7)?,
        environment: row.get(8)?,
        provider_name: row.get(9)?,
        model_name: row.get(10)?,
        status: row.get(11)?,
        model_steps: row.get(12)?,
        tool_calls: row.get(13)?,
        tool_result_bytes: row.get(14)?,
        revision: row.get(15)?,
        pending_call_id: row.get(16)?,
        workflow_state_json: row.get(17)?,
        last_error_json: row.get(18)?,
        created_at: row.get(19)?,
        updated_at: row.get(20)?,
        completed_at: row.get(21)?,
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
    knowledge_context_digest: Option<String>,
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
            knowledge_context_digest: self.knowledge_context_digest,
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
        knowledge_context_digest: row.get(13)?,
        response_json: row.get(14)?,
        error_json: row.get(15)?,
        queued_at: row.get(16)?,
        started_at: row.get(17)?,
        finished_at: row.get(18)?,
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
    let mut statement = connection.prepare(&format!(
        "{} WHERE agent_id = ?1 AND model_step = ?2 ORDER BY call_id LIMIT 2",
        agent_tool_call_select()
    ))?;
    let mut rows = statement
        .query_map(
            params![agent_id, i64::from(model_step)],
            decode_agent_tool_call_row,
        )?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    if rows.len() > 1 {
        return Err(StorageError::CorruptData(format!(
            "Agent `{agent_id}` has more than one tool call for model step {model_step}"
        )));
    }
    rows.pop().map(StoredAgentToolCallRow::decode).transpose()
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

    #[test]
    fn promptless_legacy_integrity_accepts_old_system_and_dotted_tools_but_claim_does_not() {
        let provider = deployment::ManifestProvider::new(
            "test-provider",
            Some("test-model".into()),
            protocol::AssistantReplyKind::Model,
        )
        .unwrap();
        let policy = deployment::ManifestPolicy::new("local", "local/v1").unwrap();
        let tool = deployment::ManifestTool::new(
            "workspace.list",
            "1.0.0",
            "List bounded workspace entries.",
            json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false,
            }),
            protocol::ToolEffect::ReadOnly,
            protocol::SandboxProfile::ReadOnly,
            protocol::ToolExecutorStatus::Available,
        )
        .unwrap();
        let spec = deployment::AgentSpec::new(
            "zeus-storage-legacy-agent",
            "1",
            "local-development",
            "local",
            provider,
            policy,
        )
        .unwrap()
        .with_tools(vec![tool])
        .unwrap();
        let manifest = ManifestEnvelope::from_deployment(
            deployment::AgentDeployment::new("zeus-storage-legacy-deployment", "1", spec).unwrap(),
        )
        .unwrap();
        let request = json!({
            "messages": [
                {"role": "system", "content": "Legacy provider prompt"},
                {"role": "user", "content": "Read legacy terminal history"}
            ],
            "tools": [{
                "name": "workspace.list",
                "description": "List bounded workspace entries.",
                "parameters": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": false,
                },
            }],
        });

        assert!(
            validate_request_matches_manifest(
                &request,
                &manifest,
                AgentRequestPhase::LegacyPromptlessIntegrity,
            )
            .is_ok()
        );
        assert!(matches!(
            validate_request_matches_manifest(&request, &manifest, AgentRequestPhase::Initial,),
            Err(StorageError::InvalidAgentTransition(_))
        ));
    }
}
