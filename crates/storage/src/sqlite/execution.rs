//! Agent-local RunEpoch persistence and append-only execution facts.

use execution::{
    AGENT_EXECUTION_EXPLAIN_SCHEMA_VERSION, AGENT_RUN_EPOCH_EXPLAIN_SCHEMA_VERSION, ActorRevision,
    AgentExecutionExplain, AgentRunEpochExplain, DeploymentAuthority, DeploymentCheck,
    DigestDomain, EpochExecutionStatus, EpochOutcomeMaterial, ExactJsonMaterial, ExactMaterialKind,
    ExecutionFact, ExecutionFactData, ExecutionFactEnvelope, ExecutionFactSummary,
    ExecutionHistory, ExecutionHistoryOrigin, ExecutionHistoryReason, ExecutionWatermark,
    FactSource, OperationRef, ReconstructionLevel, RecordedAt, RunEpoch, RunEpochEnvelope,
    RunEpochSummary, RunOperation, Sha256Digest, canonical_sha256,
};
use protocol::{AgentToolCallStatus, AssistantReplyProvenance};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::Serialize;
use serde_json::Value;
use workflows::{Command, ExternalCall, KnownToolResult, State as WorkflowState, reduce};

use super::{i64_to_u64, query_session_summary, require_active_session_actor, u64_to_i64};
use crate::{
    AgentModelJob, AgentModelJobStatus, AgentToolCall, AgentTurn, AuthzContext, StorageError,
};

const EXECUTION_LEDGER_SCHEMA_VERSION: i64 = 1;

pub(super) fn backfill_legacy_execution_ledgers(
    connection: &Connection,
    timestamp: &str,
) -> Result<(), StorageError> {
    let mut statement = connection.prepare(
        r#"SELECT agent.id, agent.revision, agent.workflow_state_json,
                  agent.deployment_manifest_digest
           FROM agent_turns agent
           LEFT JOIN agent_execution_heads head ON head.agent_id = agent.id
           WHERE head.agent_id IS NULL
           ORDER BY agent.id"#,
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);

    for (agent_id, revision, state_json, manifest_digest) in rows {
        let revision = i64_to_u64(revision, "legacy Agent revision")?;
        let state: WorkflowState = serde_json::from_str(&state_json)?;
        state.validate().map_err(|error| {
            StorageError::CorruptData(format!(
                "legacy Agent `{agent_id}` workflow state is invalid: {error}"
            ))
        })?;
        let manifest_digest = manifest_digest
            .map(Sha256Digest::from_hex)
            .transpose()
            .map_err(stored_execution_error)?;
        let envelope = fact_envelope(
            &agent_id,
            1,
            None,
            timestamp,
            ExecutionFactData::LegacySnapshot {
                state,
                origin_revision: revision,
                manifest_digest,
            },
        )?;
        insert_fact_row(connection, &envelope)?;
        insert_head(
            connection,
            NewExecutionHead {
                agent_id: &agent_id,
                projected_revision: revision,
                origin_revision: revision,
                history_origin: "legacy_snapshot",
                history_complete: false,
                envelope: &envelope,
                timestamp,
            },
        )?;
    }
    Ok(())
}

pub(super) fn insert_native_head_and_admission(
    connection: &Connection,
    agent: &AgentTurn,
    initial_job: &AgentModelJob,
    timestamp: &str,
) -> Result<(), StorageError> {
    let manifest_digest = agent.deployment_manifest_digest.as_deref().ok_or_else(|| {
        StorageError::CorruptData(format!(
            "new Agent `{}` is missing its deployment manifest",
            agent.id
        ))
    })?;
    let manifest_digest = Sha256Digest::from_hex(manifest_digest).map_err(live_execution_error)?;
    let knowledge =
        super::agent::require_agent_knowledge_context_integrity(connection, agent, initial_job)?;
    let initial_request_digest =
        digest_json(DigestDomain::ModelRequest, &initial_job.request_json)?;
    let envelope = fact_envelope(
        &agent.id,
        1,
        None,
        timestamp,
        ExecutionFactData::AgentAdmitted {
            state: agent.workflow_state.clone(),
            manifest_digest,
            initial_job_id: initial_job.id.clone(),
            initial_request_digest,
            knowledge_context_digest: Some(knowledge.context),
            knowledge_corpus_digest: Some(knowledge.corpus),
            knowledge_snapshot_digest: Some(knowledge.snapshot),
        },
    )?;
    insert_fact_row(connection, &envelope)?;
    insert_head(
        connection,
        NewExecutionHead {
            agent_id: &agent.id,
            projected_revision: agent.revision,
            origin_revision: agent.revision,
            history_origin: "native",
            history_complete: true,
            envelope: &envelope,
            timestamp,
        },
    )
}

pub(super) fn insert_model_run_epoch(
    connection: &Connection,
    agent: &AgentTurn,
    job: &AgentModelJob,
    observed_manifest_digest: &str,
    timestamp: &str,
) -> Result<Sha256Digest, StorageError> {
    let request_digest = digest_json(DigestDomain::ModelRequest, &job.request_json)?;
    let operation =
        RunOperation::model(&job.id, job.step, request_digest).map_err(live_execution_error)?;
    insert_matched_run_epoch(
        connection,
        agent,
        operation,
        None,
        observed_manifest_digest,
        timestamp,
    )
}

pub(super) fn insert_tool_run_epoch(
    connection: &Connection,
    agent: &AgentTurn,
    call: &AgentToolCall,
    observed_manifest_digest: &str,
    timestamp: &str,
) -> Result<Sha256Digest, StorageError> {
    let recomputed_arguments = tools::arguments_digest(&call.arguments_json);
    if recomputed_arguments != call.arguments_digest {
        return Err(StorageError::CorruptData(format!(
            "Agent tool `{}` arguments digest disagrees with its durable JSON",
            call.call_id
        )));
    }
    let arguments_digest =
        Sha256Digest::from_reference(&recomputed_arguments).map_err(live_execution_error)?;
    let operation = RunOperation::tool(
        &call.call_id,
        call.ordinal,
        call.model_step,
        &call.tool_name,
        &call.tool_version,
        arguments_digest,
        call.effect.clone(),
        call.sandbox_profile.clone(),
        &call.policy_revision,
    )
    .map_err(live_execution_error)?;
    let approver = match (
        call.approving_actor_user_id.as_deref(),
        call.approving_membership_revision.as_ref(),
    ) {
        (Some(user_id), Some(revision)) => {
            Some(ActorRevision::new(user_id, revision.get()).map_err(live_execution_error)?)
        }
        (None, None) => None,
        _ => {
            return Err(StorageError::CorruptData(format!(
                "Agent tool `{}` has a partial approving actor binding",
                call.call_id
            )));
        }
    };
    insert_matched_run_epoch(
        connection,
        agent,
        operation,
        approver,
        observed_manifest_digest,
        timestamp,
    )
}

fn insert_matched_run_epoch(
    connection: &Connection,
    agent: &AgentTurn,
    operation: RunOperation,
    approver: Option<ActorRevision>,
    observed_manifest_digest: &str,
    timestamp: &str,
) -> Result<Sha256Digest, StorageError> {
    let bound_manifest_digest = agent.deployment_manifest_digest.as_deref().ok_or_else(|| {
        StorageError::InvalidAgentTransition(
            "legacy Agent work cannot be released without a deployment manifest".into(),
        )
    })?;
    let bound_manifest_digest =
        Sha256Digest::from_hex(bound_manifest_digest).map_err(live_execution_error)?;
    let observed_manifest_digest =
        Sha256Digest::from_hex(observed_manifest_digest).map_err(live_execution_error)?;
    let initiator = ActorRevision::new(&agent.actor_user_id, agent.actor_membership_revision.get())
        .map_err(live_execution_error)?;
    let recorded_at = RecordedAt::parse(timestamp).map_err(live_execution_error)?;
    let epoch = RunEpoch::new(
        &agent.id,
        agent.account_id.as_str(),
        &agent.session_id,
        &agent.turn_id,
        agent
            .revision
            .checked_add(1)
            .ok_or(StorageError::IntegerOutOfRange("Agent workflow revision"))?,
        Some(bound_manifest_digest),
        observed_manifest_digest,
        operation,
        initiator,
        approver,
        recorded_at,
    )
    .map_err(live_execution_error)?;
    let envelope = RunEpochEnvelope::new(epoch).map_err(live_execution_error)?;
    insert_epoch_row(connection, &envelope)?;
    Ok(envelope.digest)
}

pub(super) struct TransitionFact<'a> {
    pub command: Command,
    pub state: WorkflowState,
    pub external_call: Option<ExternalCall>,
    pub emitted_result: Option<KnownToolResult>,
    pub emitted_result_digest: Option<Sha256Digest>,
    pub epoch_digest: Option<&'a Sha256Digest>,
    pub source: FactSource,
    pub subject: Option<OperationRef>,
    pub input_digest: Option<Sha256Digest>,
    pub output_digest: Option<Sha256Digest>,
    pub next_request_digest: Option<Sha256Digest>,
}

pub(super) fn append_transition(
    connection: &Connection,
    agent_before: &AgentTurn,
    agent_after: &AgentTurn,
    transition: TransitionFact<'_>,
    timestamp: &str,
) -> Result<Sha256Digest, StorageError> {
    let expected_revision = agent_before
        .revision
        .checked_add(1)
        .ok_or(StorageError::IntegerOutOfRange("Agent workflow revision"))?;
    if agent_after.id != agent_before.id || agent_after.revision != expected_revision {
        return Err(StorageError::ConcurrentModification);
    }
    let (sequence, previous_digest) = execution_head(connection, &agent_after.id)?;
    let sequence = sequence
        .checked_add(1)
        .ok_or(StorageError::IntegerOutOfRange("Agent execution sequence"))?;
    let envelope = fact_envelope(
        &agent_after.id,
        sequence,
        Some(previous_digest),
        timestamp,
        ExecutionFactData::WorkflowTransition {
            from_revision: agent_before.revision,
            to_revision: agent_after.revision,
            command: transition.command,
            state: transition.state,
            external_call: transition.external_call,
            emitted_result: transition.emitted_result,
            emitted_result_digest: transition.emitted_result_digest,
            epoch_digest: transition.epoch_digest.cloned(),
            source: transition.source,
            subject: transition.subject,
            input_digest: transition.input_digest,
            output_digest: transition.output_digest,
            next_request_digest: transition.next_request_digest,
        },
    )?;
    insert_fact_row(connection, &envelope)?;
    advance_head(connection, agent_after.revision, &envelope, timestamp)?;
    Ok(envelope.digest)
}

pub(super) fn epoch_digest_for_operation(
    connection: &Connection,
    operation_kind: &str,
    operation_id: &str,
) -> Result<Sha256Digest, StorageError> {
    epoch_digest_for_operation_optional(connection, operation_kind, operation_id)?.ok_or_else(
        || {
            StorageError::CorruptData(format!(
                "Agent {operation_kind} operation `{operation_id}` is missing its RunEpoch"
            ))
        },
    )
}

pub(super) fn epoch_digest_for_operation_optional(
    connection: &Connection,
    operation_kind: &str,
    operation_id: &str,
) -> Result<Option<Sha256Digest>, StorageError> {
    let column = match operation_kind {
        "model" => "model_job_id",
        "tool" => "tool_call_id",
        other => {
            return Err(StorageError::CorruptData(format!(
                "unknown Agent execution operation kind `{other}`"
            )));
        }
    };
    let digest = connection
        .query_row(
            &format!("SELECT digest FROM agent_run_epochs WHERE {column} = ?1"),
            [operation_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    digest
        .map(Sha256Digest::from_hex)
        .transpose()
        .map_err(stored_execution_error)
}

pub(super) fn epoch_digest_for_recovery(
    connection: &Connection,
    agent: &AgentTurn,
    operation_kind: &str,
    operation_id: &str,
) -> Result<Option<Sha256Digest>, StorageError> {
    if let Some(digest) =
        epoch_digest_for_operation_optional(connection, operation_kind, operation_id)?
    {
        return Ok(Some(digest));
    }

    let origin = connection
        .query_row(
            r#"SELECT head.head_sequence, head.projected_agent_revision,
                      head.history_origin, event.envelope_json
               FROM agent_execution_heads head
               JOIN agent_execution_events event
                 ON event.agent_id = head.agent_id AND event.sequence = 1
               WHERE head.agent_id = ?1"#,
            [&agent.id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| {
            StorageError::CorruptData(format!(
                "Agent `{}` is missing its recovery ledger origin",
                agent.id
            ))
        })?;
    let (head_sequence, projected_revision, history_origin, origin_json) = origin;
    let origin = ExecutionFactEnvelope::from_json_slice(origin_json.as_bytes())
        .map_err(stored_execution_error)?;
    let ExecutionFactData::LegacySnapshot {
        state,
        origin_revision,
        ..
    } = &origin.fact.data
    else {
        return Err(StorageError::CorruptData(format!(
            "Agent `{}` started operation is missing its native RunEpoch",
            agent.id
        )));
    };
    if head_sequence != 1
        || projected_revision != u64_to_i64(agent.revision, "Agent workflow revision")?
        || history_origin != "legacy_snapshot"
        || *origin_revision != agent.revision
        || state != &agent.workflow_state
    {
        return Err(StorageError::CorruptData(format!(
            "Agent `{}` missing RunEpoch is not an honest legacy started prefix",
            agent.id
        )));
    }

    let operation_matches = match operation_kind {
        "model" => {
            let job = super::agent::query_agent_model_job_by_id(connection, operation_id)?;
            job.agent_id == agent.id
                && job.status == AgentModelJobStatus::Started
                && job.attempt == 1
                && state.status() == workflows::AgentStatus::ModelStarted
                && state.model_steps() == job.step
        }
        "tool" => {
            let call = super::agent::query_agent_tool_call(connection, operation_id)?;
            call.agent_id == agent.id
                && call.status == AgentToolCallStatus::Running
                && state.status() == workflows::AgentStatus::ToolStarted
                && state.model_steps() == call.model_step
                && state.tool_calls() == call.ordinal
                && agent.pending_call_id.as_deref() == Some(call.call_id.as_str())
        }
        other => {
            return Err(StorageError::CorruptData(format!(
                "unknown Agent execution operation kind `{other}`"
            )));
        }
    };
    if !operation_matches {
        return Err(StorageError::CorruptData(format!(
            "Agent `{}` missing RunEpoch does not match its legacy started operation",
            agent.id
        )));
    }
    Ok(None)
}

pub(super) fn digest_json(
    domain: DigestDomain,
    value: &impl Serialize,
) -> Result<Sha256Digest, StorageError> {
    canonical_sha256(domain, value).map_err(live_execution_error)
}

pub(super) fn query_agent_execution_explain_for_actor(
    connection: &mut Connection,
    context: &AuthzContext,
    session_id: &str,
    turn_id: &str,
) -> Result<AgentExecutionExplain, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_active_session_actor(&transaction, session_id, context)?;
    let agent = super::agent::query_agent_turn_for_session_turn(&transaction, session_id, turn_id)?;
    if agent.account_id != context.account_id {
        return Err(StorageError::AgentTurnNotFound(turn_id.to_owned()));
    }

    let detail = super::agent::agent_turn_detail(&transaction, &agent)?;
    let manifest = query_bound_manifest(&transaction, &agent)?;
    let head = query_execution_read_head(&transaction, &agent)?;
    let facts = query_fact_summaries(&transaction, &agent, &head)?;
    let epochs = query_epoch_summaries(&transaction, &agent)?;
    let history = execution_history(
        &agent,
        &head,
        manifest.is_some(),
        agent.knowledge_context_digest.is_some(),
        &epochs,
        false,
    )?;
    let session_sequence = query_session_summary(&transaction, session_id)?.sequence;
    let explanation = AgentExecutionExplain {
        schema_version: AGENT_EXECUTION_EXPLAIN_SCHEMA_VERSION,
        agent: detail,
        watermark: execution_watermark(&head, session_sequence)?,
        history,
        manifest,
        epochs,
        facts,
    };
    explanation.validate().map_err(stored_execution_error)?;
    transaction.commit()?;
    Ok(explanation)
}

pub(super) fn query_agent_run_epoch_explain_for_actor(
    connection: &mut Connection,
    context: &AuthzContext,
    session_id: &str,
    turn_id: &str,
    step: u32,
) -> Result<AgentRunEpochExplain, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_active_session_actor(&transaction, session_id, context)?;
    let agent = super::agent::query_agent_turn_for_session_turn(&transaction, session_id, turn_id)?;
    if agent.account_id != context.account_id {
        return Err(StorageError::AgentTurnNotFound(turn_id.to_owned()));
    }
    if step == 0 {
        return Err(StorageError::InvalidAgentTransition(
            "Agent model step must be greater than zero".into(),
        ));
    }

    let manifest = query_bound_manifest(&transaction, &agent)?;
    let head = query_execution_read_head(&transaction, &agent)?;
    let facts = query_fact_summaries(&transaction, &agent, &head)?;
    let job = super::agent::query_agent_model_job(&transaction, &agent.id, step)?;
    let envelope = query_model_epoch(&transaction, &agent, &job)?;
    let epoch = model_epoch_summary(&envelope, &job)?;
    let request = ExactJsonMaterial::new(ExactMaterialKind::ModelRequest, job.request_json.clone())
        .map_err(stored_execution_error)?;
    let outcome = model_epoch_outcome(&job)?;
    let linked_tools = super::agent::agent_turn_detail(&transaction, &agent)?
        .calls
        .into_iter()
        .filter(|call| call.model_step == step)
        .collect();
    let history = execution_history(
        &agent,
        &head,
        manifest.is_some(),
        agent.knowledge_context_digest.is_some(),
        std::slice::from_ref(&epoch),
        true,
    )?;
    let session_sequence = query_session_summary(&transaction, session_id)?.sequence;
    let explanation = AgentRunEpochExplain {
        schema_version: AGENT_RUN_EPOCH_EXPLAIN_SCHEMA_VERSION,
        agent_id: agent.id,
        session_id: agent.session_id,
        turn_id: agent.turn_id,
        watermark: execution_watermark(&head, session_sequence)?,
        history,
        manifest,
        epoch,
        request,
        outcome,
        linked_tools,
        facts,
    };
    explanation.validate().map_err(stored_execution_error)?;
    transaction.commit()?;
    Ok(explanation)
}

#[derive(Clone)]
struct ExecutionReadHead {
    sequence: u64,
    projected_revision: u64,
    origin_revision: u64,
    origin: ExecutionHistoryOrigin,
    history_complete: bool,
    digest: Sha256Digest,
}

fn query_execution_read_head(
    connection: &Connection,
    agent: &AgentTurn,
) -> Result<ExecutionReadHead, StorageError> {
    let stored = connection
        .query_row(
            r#"SELECT head_sequence, projected_agent_revision, origin_revision,
                      history_origin, history_complete, head_hash
               FROM agent_execution_heads WHERE agent_id = ?1"#,
            [&agent.id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| {
            StorageError::CorruptData(format!(
                "Agent `{}` is missing its execution head",
                agent.id
            ))
        })?;
    let (sequence, projected_revision, origin_revision, origin, complete, digest) = stored;
    let projected_revision = i64_to_u64(projected_revision, "Agent execution revision")?;
    let origin_revision = i64_to_u64(origin_revision, "Agent execution origin revision")?;
    let origin = match origin.as_str() {
        "native" if complete == 1 && origin_revision == 1 => ExecutionHistoryOrigin::Native,
        "legacy_snapshot" if complete == 0 => ExecutionHistoryOrigin::LegacySnapshot,
        _ => {
            return Err(StorageError::CorruptData(format!(
                "Agent `{}` has an invalid execution history origin",
                agent.id
            )));
        }
    };
    if projected_revision != agent.revision {
        return Err(StorageError::CorruptData(format!(
            "Agent `{}` execution head revision disagrees with its projection",
            agent.id
        )));
    }
    Ok(ExecutionReadHead {
        sequence: i64_to_u64(sequence, "Agent execution sequence")?,
        projected_revision,
        origin_revision,
        origin,
        history_complete: complete == 1,
        digest: Sha256Digest::from_hex(digest).map_err(stored_execution_error)?,
    })
}

fn execution_watermark(
    head: &ExecutionReadHead,
    session_sequence: u64,
) -> Result<ExecutionWatermark, StorageError> {
    ExecutionWatermark::new(
        head.projected_revision,
        session_sequence,
        head.sequence,
        Some(head.digest.clone()),
    )
    .map_err(stored_execution_error)
}

fn query_bound_manifest(
    connection: &Connection,
    agent: &AgentTurn,
) -> Result<Option<deployment::ManifestEnvelope>, StorageError> {
    let Some(digest) = agent.deployment_manifest_digest.as_deref() else {
        return Ok(None);
    };
    let manifest = super::agent::query_agent_deployment_manifest(connection, digest)?;
    super::agent::require_manifest_matches_agent_identity(connection, &manifest, agent).map_err(
        |error| {
            StorageError::CorruptData(format!(
                "Agent deployment manifest binding is invalid: {error}"
            ))
        },
    )?;
    Ok(Some(manifest))
}

fn query_fact_summaries(
    connection: &Connection,
    agent: &AgentTurn,
    head: &ExecutionReadHead,
) -> Result<Vec<ExecutionFactSummary>, StorageError> {
    let agent_id = agent.id.as_str();
    let mut statement = connection.prepare(
        r#"SELECT sequence, fact_digest, previous_fact_digest, fact_kind,
                  agent_revision, epoch_digest, operation_kind, operation_id,
                  envelope_json, created_at
           FROM agent_execution_events WHERE agent_id = ?1 ORDER BY sequence"#,
    )?;
    let rows = statement
        .query_map([agent_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    if u64::try_from(rows.len()).ok() != Some(head.sequence) {
        return Err(StorageError::CorruptData(format!(
            "Agent `{agent_id}` execution sequence contains a gap"
        )));
    }

    let mut summaries = Vec::with_capacity(rows.len());
    let mut replay_state = None;
    let mut replay_revision = None;
    for (
        sequence,
        digest,
        previous,
        kind,
        revision,
        epoch,
        operation_kind,
        operation_id,
        envelope_json,
        created_at,
    ) in rows
    {
        let envelope = ExecutionFactEnvelope::from_json_slice(envelope_json.as_bytes())
            .map_err(stored_execution_error)?;
        if envelope
            .canonical_json_bytes()
            .map_err(stored_execution_error)?
            != envelope_json.as_bytes()
            || envelope.fact.agent_id != agent_id
            || u64_to_i64(envelope.fact.sequence, "Agent execution sequence")? != sequence
            || envelope.digest.as_str() != digest
            || envelope
                .fact
                .previous_fact_digest
                .as_ref()
                .map(Sha256Digest::as_str)
                != previous.as_deref()
            || envelope.fact.recorded_at.as_str() != created_at
        {
            return Err(StorageError::CorruptData(format!(
                "Agent `{agent_id}` execution envelope disagrees with its lookup columns"
            )));
        }
        if envelope.fact.sequence == 1 {
            validate_origin_binding(
                connection,
                agent,
                &envelope,
                head.origin,
                head.origin_revision,
            )?;
        }
        let lookup = fact_lookup_columns(&envelope.fact.data)?;
        if lookup.0 != kind
            || u64_to_i64(lookup.1, "Agent execution revision")? != revision
            || lookup.2.as_ref().map(Sha256Digest::as_str) != epoch.as_deref()
            || lookup.3 != operation_kind.as_deref()
            || lookup.4.as_deref() != operation_id.as_deref()
        {
            return Err(StorageError::CorruptData(format!(
                "Agent `{agent_id}` execution lookup columns are inconsistent"
            )));
        }
        validate_fact_replay(agent_id, &envelope, &mut replay_state, &mut replay_revision)?;
        validate_fact_epoch_binding(connection, &envelope)?;
        summaries
            .push(ExecutionFactSummary::from_envelope(&envelope).map_err(stored_execution_error)?);
    }
    if summaries.last().map(|summary| &summary.digest) != Some(&head.digest) {
        return Err(StorageError::CorruptData(format!(
            "Agent `{agent_id}` execution head does not match its fact tail"
        )));
    }
    if replay_revision != Some(head.projected_revision) {
        return Err(StorageError::CorruptData(format!(
            "Agent `{agent_id}` replayed revision disagrees with its execution head"
        )));
    }
    if replay_state.as_ref() != Some(&agent.workflow_state) {
        return Err(StorageError::CorruptData(format!(
            "Agent `{agent_id}` replayed state disagrees with its workflow projection"
        )));
    }
    Ok(summaries)
}

fn validate_origin_binding(
    connection: &Connection,
    agent: &AgentTurn,
    envelope: &ExecutionFactEnvelope,
    expected_origin: ExecutionHistoryOrigin,
    expected_origin_revision: u64,
) -> Result<(), StorageError> {
    let valid = match (&envelope.fact.data, expected_origin) {
        (
            ExecutionFactData::AgentAdmitted {
                state,
                manifest_digest,
                initial_job_id,
                initial_request_digest,
                knowledge_context_digest,
                knowledge_corpus_digest,
                knowledge_snapshot_digest,
            },
            ExecutionHistoryOrigin::Native,
        ) => {
            let job = super::agent::query_agent_model_job_by_id(connection, initial_job_id)?;
            let knowledge_binding_valid = match (
                knowledge_context_digest,
                knowledge_corpus_digest,
                knowledge_snapshot_digest,
            ) {
                (None, None, None) => {
                    super::agent::agent_has_frozen_legacy_knowledge_boundary(
                        connection, agent, &job,
                    )? && agent.knowledge_context_digest.is_none()
                        && job.knowledge_context_digest.is_none()
                }
                (Some(context), Some(corpus), Some(snapshot)) => {
                    let stored = super::agent::require_agent_knowledge_context_integrity(
                        connection, agent, &job,
                    )?;
                    context == &stored.context
                        && corpus == &stored.corpus
                        && snapshot == &stored.snapshot
                }
                _ => false,
            };
            state.status() == workflows::AgentStatus::ModelQueued
                && state.model_steps() == 0
                && state.tool_calls() == 0
                && manifest_digest.as_str()
                    == agent
                        .deployment_manifest_digest
                        .as_deref()
                        .unwrap_or_default()
                && job.id == *initial_job_id
                && job.agent_id == agent.id
                && job.account_id == agent.account_id
                && job.session_id == agent.session_id
                && job.turn_id == agent.turn_id
                && job.step == 1
                && digest_json(DigestDomain::ModelRequest, &job.request_json)?
                    == *initial_request_digest
                && knowledge_binding_valid
                && job.queued_at == agent.created_at
                && envelope.fact.recorded_at.as_str() == agent.created_at
                && expected_origin_revision == 1
        }
        (
            ExecutionFactData::LegacySnapshot {
                state,
                origin_revision,
                manifest_digest,
            },
            ExecutionHistoryOrigin::LegacySnapshot,
        ) => {
            let migration_applied_at = connection
                .query_row(
                    "SELECT applied_at FROM schema_migrations WHERE version = 20",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            state.validate().is_ok()
                && *origin_revision == expected_origin_revision
                && *origin_revision <= agent.revision
                && manifest_digest.as_ref().map(Sha256Digest::as_str)
                    == agent.deployment_manifest_digest.as_deref()
                && migration_applied_at.as_deref() == Some(envelope.fact.recorded_at.as_str())
        }
        _ => false,
    };
    if !valid {
        return Err(StorageError::CorruptData(format!(
            "Agent `{}` execution origin disagrees with its durable admission",
            agent.id
        )));
    }
    Ok(())
}

fn validate_fact_replay(
    agent_id: &str,
    envelope: &ExecutionFactEnvelope,
    previous_state: &mut Option<WorkflowState>,
    previous_revision: &mut Option<u64>,
) -> Result<(), StorageError> {
    match &envelope.fact.data {
        ExecutionFactData::AgentAdmitted { state, .. } => {
            if previous_state.is_some() || previous_revision.is_some() {
                return Err(StorageError::CorruptData(format!(
                    "Agent `{agent_id}` has more than one execution origin"
                )));
            }
            *previous_state = Some(state.clone());
            *previous_revision = Some(1);
        }
        ExecutionFactData::LegacySnapshot {
            state,
            origin_revision,
            ..
        } => {
            if previous_state.is_some() || previous_revision.is_some() {
                return Err(StorageError::CorruptData(format!(
                    "Agent `{agent_id}` has more than one execution origin"
                )));
            }
            *previous_state = Some(state.clone());
            *previous_revision = Some(*origin_revision);
        }
        ExecutionFactData::WorkflowTransition {
            from_revision,
            to_revision,
            command,
            state,
            external_call,
            emitted_result,
            ..
        } => {
            let prior_state = previous_state.as_ref().ok_or_else(|| {
                StorageError::CorruptData(format!(
                    "Agent `{agent_id}` transition has no execution origin"
                ))
            })?;
            if previous_revision.as_ref() != Some(from_revision) {
                return Err(StorageError::CorruptData(format!(
                    "Agent `{agent_id}` transition revision does not follow its predecessor"
                )));
            }
            let replay = reduce(prior_state, command.clone()).map_err(|error| {
                StorageError::CorruptData(format!(
                    "Agent `{agent_id}` execution command cannot be replayed: {error}"
                ))
            })?;
            if replay.state() != state
                || replay.external_call() != external_call.as_ref()
                || replay.emitted_result() != emitted_result.as_ref()
            {
                return Err(StorageError::CorruptData(format!(
                    "Agent `{agent_id}` execution transition disagrees with reducer replay"
                )));
            }
            *previous_state = Some(state.clone());
            *previous_revision = Some(*to_revision);
        }
    }
    Ok(())
}

fn validate_fact_epoch_binding(
    connection: &Connection,
    envelope: &ExecutionFactEnvelope,
) -> Result<(), StorageError> {
    let ExecutionFactData::WorkflowTransition {
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
        ..
    } = &envelope.fact.data
    else {
        return Ok(());
    };

    validate_continuation_request_binding(
        connection,
        envelope,
        command,
        state,
        subject.as_ref(),
        next_request_digest.as_ref(),
    )?;

    let Some(epoch_digest) = epoch_digest else {
        if *source == FactSource::RestartRecovery {
            return validate_legacy_epochless_recovery(connection, envelope);
        }
        return validate_epochless_operation_fact(connection, envelope);
    };
    let subject = subject.as_ref().ok_or_else(|| {
        StorageError::CorruptData(format!(
            "Agent `{}` epoch-bound fact is missing its operation subject",
            envelope.fact.agent_id
        ))
    })?;
    let input_digest = input_digest.as_ref().ok_or_else(|| {
        StorageError::CorruptData(format!(
            "Agent `{}` epoch-bound fact is missing its operation input digest",
            envelope.fact.agent_id
        ))
    })?;

    let stored_json = connection
        .query_row(
            r#"SELECT envelope_json FROM agent_run_epochs
               WHERE agent_id = ?1 AND digest = ?2"#,
            params![envelope.fact.agent_id, epoch_digest.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| {
            StorageError::CorruptData(format!(
                "Agent `{}` execution fact references a missing RunEpoch",
                envelope.fact.agent_id
            ))
        })?;
    let epoch = RunEpochEnvelope::from_json_slice(stored_json.as_bytes())
        .map_err(stored_execution_error)?;
    if epoch
        .canonical_json_bytes()
        .map_err(stored_execution_error)?
        != stored_json.as_bytes()
        || &epoch.digest != epoch_digest
        || epoch.epoch.agent_id != envelope.fact.agent_id
        || epoch.epoch.operation.reference() != *subject
        || epoch.epoch.operation.input_digest() != input_digest
    {
        return Err(StorageError::CorruptData(format!(
            "Agent `{}` execution fact disagrees with its RunEpoch binding",
            envelope.fact.agent_id
        )));
    }

    let command_matches_operation = matches!(
        (command, &epoch.epoch.operation),
        (
            Command::StartModel
                | Command::ModelFinal { .. }
                | Command::ModelToolProposal { .. }
                | Command::ModelFailed
                | Command::ModelOutcomeUnknown,
            RunOperation::Model { .. }
        )
    ) || matches!(
        (command, &epoch.epoch.operation),
        (
            Command::StartTool | Command::ToolResultKnown { .. } | Command::ToolOutcomeUnknown,
            RunOperation::Tool { .. }
        )
    );
    if !command_matches_operation {
        return Err(StorageError::CorruptData(format!(
            "Agent `{}` execution command references the wrong RunEpoch operation kind",
            envelope.fact.agent_id
        )));
    }

    if external_call.is_some() || matches!(command, Command::StartModel | Command::StartTool) {
        let release_matches = epoch.epoch.workflow_revision == *to_revision
            && (matches!(
                (command, external_call, &epoch.epoch.operation),
                (
                    Command::StartModel,
                    Some(ExternalCall::Model { step: external_step }),
                    RunOperation::Model { step: epoch_step, .. }
                ) if external_step == epoch_step
            ) || matches!(
                (command, external_call, &epoch.epoch.operation),
                (
                    Command::StartTool,
                    Some(ExternalCall::Tool { call: external_call }),
                    RunOperation::Tool { ordinal: epoch_call, .. }
                ) if external_call == epoch_call
            ));
        if !release_matches {
            return Err(StorageError::CorruptData(format!(
                "Agent `{}` execution release disagrees with its RunEpoch revision or operation",
                envelope.fact.agent_id
            )));
        }
    }
    validate_terminal_fact_material(
        connection,
        command,
        &epoch,
        &envelope.fact.recorded_at,
        TerminalFactMaterial {
            state,
            output_digest: output_digest.as_ref(),
            emitted_result: emitted_result.as_ref(),
            emitted_result_digest: emitted_result_digest.as_ref(),
        },
    )?;
    Ok(())
}

struct TerminalFactMaterial<'a> {
    state: &'a WorkflowState,
    output_digest: Option<&'a Sha256Digest>,
    emitted_result: Option<&'a KnownToolResult>,
    emitted_result_digest: Option<&'a Sha256Digest>,
}

fn validate_terminal_fact_material(
    connection: &Connection,
    command: &Command,
    epoch: &RunEpochEnvelope,
    recorded_at: &RecordedAt,
    material: TerminalFactMaterial<'_>,
) -> Result<(), StorageError> {
    let TerminalFactMaterial {
        state,
        output_digest,
        emitted_result,
        emitted_result_digest,
    } = material;
    let expected = match (command, &epoch.epoch.operation) {
        (Command::StartModel | Command::StartTool, _) => {
            if output_digest.is_some()
                || emitted_result.is_some()
                || emitted_result_digest.is_some()
            {
                return Err(StorageError::CorruptData(format!(
                    "RunEpoch `{}` release fact cannot have terminal output material",
                    epoch.digest
                )));
            }
            return Ok(());
        }
        (Command::ModelFinal { content_bytes }, RunOperation::Model { job_id, .. }) => {
            let job = super::agent::query_agent_model_job_by_id(connection, job_id)?;
            if job.status != AgentModelJobStatus::Succeeded
                || job.finished_at.as_deref() != Some(recorded_at.as_str())
            {
                return Err(StorageError::CorruptData(format!(
                    "RunEpoch `{}` success fact disagrees with its model job status",
                    epoch.digest
                )));
            }
            super::agent::validate_persisted_agent_model_final_response(&job, *content_bytes)
                .map_err(|error| {
                    StorageError::CorruptData(format!(
                        "RunEpoch `{}` final response is invalid: {error}",
                        epoch.digest
                    ))
                })?;
            let response = required_material(job.response_json.as_ref(), "model response")?;
            digest_json(DigestDomain::ModelResponse, response)?
        }
        (Command::ModelToolProposal { disposition }, RunOperation::Model { job_id, step, .. }) => {
            let job = super::agent::query_agent_model_job_by_id(connection, job_id)?;
            if job.status != AgentModelJobStatus::Succeeded
                || job.finished_at.as_deref() != Some(recorded_at.as_str())
            {
                return Err(StorageError::CorruptData(format!(
                    "RunEpoch `{}` proposal fact disagrees with its model job status",
                    epoch.digest
                )));
            }
            super::agent::validate_persisted_agent_model_tool_response_shape(&job).map_err(
                |error| {
                    StorageError::CorruptData(format!(
                        "RunEpoch `{}` tool proposal response is invalid: {error}",
                        epoch.digest
                    ))
                },
            )?;
            let response = required_material(job.response_json.as_ref(), "model response")?;
            let response_digest = digest_json(DigestDomain::ModelResponse, response)?;
            let mut statement = connection.prepare(
                r#"SELECT call_id FROM agent_tool_calls
                   WHERE agent_id = ?1 AND model_step = ?2 ORDER BY ordinal"#,
            )?;
            let call_ids = statement
                .query_map(params![epoch.epoch.agent_id, i64::from(*step)], |row| {
                    row.get::<_, String>(0)
                })?
                .collect::<Result<Vec<_>, _>>()?;
            drop(statement);
            if call_ids.len() > 1 {
                return Err(StorageError::CorruptData(format!(
                    "RunEpoch `{}` model step owns more than one durable tool proposal",
                    epoch.digest
                )));
            }
            if let Some(call_id) = call_ids.first() {
                let call = super::agent::query_agent_tool_call(connection, call_id)?;
                super::agent::validate_persisted_agent_model_tool_response(&job, &call)?;
                let decision_matches = matches!(
                    (disposition, &call.policy_decision),
                    (
                        workflows::ProposalDisposition::Allow,
                        protocol::PolicyDecision::Allow
                    ) | (
                        workflows::ProposalDisposition::RequireApproval,
                        protocol::PolicyDecision::RequireApproval
                    ) | (
                        workflows::ProposalDisposition::Deny { .. },
                        protocol::PolicyDecision::Deny
                    )
                );
                if !decision_matches {
                    return Err(StorageError::CorruptData(format!(
                        "RunEpoch `{}` proposal disposition disagrees with its durable tool call",
                        epoch.digest
                    )));
                }
                if call.model_step != *step || call.ordinal != state.tool_calls() {
                    return Err(StorageError::CorruptData(format!(
                        "RunEpoch `{}` proposal call disagrees with replayed workflow counters",
                        epoch.digest
                    )));
                }
                if call.created_at != recorded_at.as_str() {
                    return Err(StorageError::CorruptData(format!(
                        "RunEpoch `{}` proposal call timestamp disagrees with its model fact",
                        epoch.digest
                    )));
                }
                if let workflows::ProposalDisposition::Deny { result_bytes } = disposition {
                    let result =
                        required_material(call.result_json.as_ref(), "policy-denied tool result")?;
                    let result_digest = digest_json(DigestDomain::ToolResult, result)?;
                    if call.status != AgentToolCallStatus::NotDispatched
                        || call.started_at.is_some()
                        || call.finished_at.as_deref() != Some(recorded_at.as_str())
                        || json_serialized_bytes(result, "policy-denied tool result")?
                            != *result_bytes
                    {
                        return Err(StorageError::CorruptData(format!(
                            "RunEpoch `{}` policy denial disagrees with its durable result",
                            epoch.digest
                        )));
                    }
                    match (emitted_result, emitted_result_digest) {
                        (Some(result), Some(digest))
                            if result.kind == workflows::KnownToolResultKind::PolicyDenied
                                && result.serialized_bytes == *result_bytes
                                && digest == &result_digest => {}
                        (None, None)
                            if state.status() == workflows::AgentStatus::Failed
                                && state.terminal_reason()
                                    == Some(
                                        workflows::TerminalReason::ToolResultBytesLimitReached,
                                    ) => {}
                        _ => {
                            return Err(StorageError::CorruptData(format!(
                                "RunEpoch `{}` policy denial emission disagrees with its workflow state",
                                epoch.digest
                            )));
                        }
                    }
                    if state.status() == workflows::AgentStatus::Failed {
                        validate_terminal_proposal_evidence(
                            connection,
                            &epoch.epoch.agent_id,
                            disposition,
                            &response_digest,
                            Some(&result_digest),
                        )?;
                    }
                }
            } else {
                let no_call_limit = state.status() == workflows::AgentStatus::Failed
                    && matches!(
                        state.terminal_reason(),
                        Some(
                            workflows::TerminalReason::ToolCallLimitReached
                                | workflows::TerminalReason::PendingApprovalLimitReached
                        )
                    );
                if !no_call_limit || emitted_result.is_some() || emitted_result_digest.is_some() {
                    return Err(StorageError::CorruptData(format!(
                        "RunEpoch `{}` proposal is missing its required durable tool call",
                        epoch.digest
                    )));
                }
                validate_terminal_proposal_evidence(
                    connection,
                    &epoch.epoch.agent_id,
                    disposition,
                    &response_digest,
                    None,
                )?;
            }
            response_digest
        }
        (Command::ModelFailed, RunOperation::Model { job_id, .. }) => {
            let job = super::agent::query_agent_model_job_by_id(connection, job_id)?;
            if job.status != AgentModelJobStatus::Failed
                || job.finished_at.as_deref() != Some(recorded_at.as_str())
            {
                return Err(StorageError::CorruptData(format!(
                    "RunEpoch `{}` failure fact disagrees with its model job status",
                    epoch.digest
                )));
            }
            digest_json(
                DigestDomain::ExecutionError,
                required_material(job.error_json.as_ref(), "model error")?,
            )?
        }
        (Command::ModelOutcomeUnknown, RunOperation::Model { job_id, .. }) => {
            let job = super::agent::query_agent_model_job_by_id(connection, job_id)?;
            if job.status != AgentModelJobStatus::OutcomeUnknown
                || job.finished_at.as_deref() != Some(recorded_at.as_str())
            {
                return Err(StorageError::CorruptData(format!(
                    "RunEpoch `{}` unknown fact disagrees with its model job status",
                    epoch.digest
                )));
            }
            digest_json(
                DigestDomain::ExecutionError,
                required_material(job.error_json.as_ref(), "model error")?,
            )?
        }
        (Command::ToolResultKnown { kind, result_bytes }, RunOperation::Tool { call_id, .. }) => {
            let call = super::agent::query_agent_tool_call(connection, call_id)?;
            let status_matches = matches!(
                (kind, &call.status),
                (
                    workflows::ToolCompletionKind::Succeeded,
                    AgentToolCallStatus::Succeeded
                ) | (
                    workflows::ToolCompletionKind::Failed,
                    AgentToolCallStatus::Failed
                ) | (
                    workflows::ToolCompletionKind::Cancelled,
                    AgentToolCallStatus::Cancelled
                ) | (
                    workflows::ToolCompletionKind::NotDispatched,
                    AgentToolCallStatus::NotDispatched
                )
            );
            if !status_matches || call.finished_at.as_deref() != Some(recorded_at.as_str()) {
                return Err(StorageError::CorruptData(format!(
                    "RunEpoch `{}` result fact disagrees with its tool call status",
                    epoch.digest
                )));
            }
            let result = required_material(call.result_json.as_ref(), "tool result")?;
            if json_serialized_bytes(result, "tool result")? != *result_bytes {
                return Err(StorageError::CorruptData(format!(
                    "RunEpoch `{}` tool result byte count disagrees with durable material",
                    epoch.digest
                )));
            }
            digest_json(DigestDomain::ToolResult, result)?
        }
        (Command::ToolOutcomeUnknown, RunOperation::Tool { call_id, .. }) => {
            let call = super::agent::query_agent_tool_call(connection, call_id)?;
            if call.status != AgentToolCallStatus::OutcomeUnknown
                || call.finished_at.as_deref() != Some(recorded_at.as_str())
            {
                return Err(StorageError::CorruptData(format!(
                    "RunEpoch `{}` unknown fact disagrees with its tool call status",
                    epoch.digest
                )));
            }
            digest_json(
                DigestDomain::ExecutionError,
                required_material(call.result_json.as_ref(), "tool error")?,
            )?
        }
        _ => return Ok(()),
    };
    if output_digest != Some(&expected) {
        return Err(StorageError::CorruptData(format!(
            "RunEpoch `{}` terminal fact output digest disagrees with durable material",
            epoch.digest
        )));
    }
    if let Some(emitted_result_digest) = emitted_result_digest {
        let emitted_expected = match (command, &epoch.epoch.operation) {
            (
                Command::ModelToolProposal {
                    disposition: workflows::ProposalDisposition::Deny { result_bytes },
                },
                RunOperation::Model { step, .. },
            ) => {
                let mut statement = connection.prepare(
                    r#"SELECT result_json FROM agent_tool_calls
                       WHERE agent_id = ?1 AND model_step = ?2
                         AND policy_decision = 'deny' AND status = 'not_dispatched'"#,
                )?;
                let results = statement
                    .query_map(
                        params![
                            epoch.epoch.agent_id,
                            u64_to_i64(u64::from(*step), "model step")?
                        ],
                        |row| row.get::<_, String>(0),
                    )?
                    .collect::<Result<Vec<_>, _>>()?;
                drop(statement);
                if results.len() != 1
                    || emitted_result.map(|result| result.serialized_bytes) != Some(*result_bytes)
                {
                    return Err(StorageError::CorruptData(format!(
                        "RunEpoch `{}` policy-denied emission lacks one durable result",
                        epoch.digest
                    )));
                }
                let result: Value = serde_json::from_str(&results[0])?;
                if json_serialized_bytes(&result, "policy-denied result")? != *result_bytes {
                    return Err(StorageError::CorruptData(format!(
                        "RunEpoch `{}` policy-denied byte count disagrees with durable material",
                        epoch.digest
                    )));
                }
                digest_json(DigestDomain::ToolResult, &result)?
            }
            _ => expected.clone(),
        };
        if emitted_result_digest != &emitted_expected {
            return Err(StorageError::CorruptData(format!(
                "RunEpoch `{}` emitted result digest disagrees with durable material",
                epoch.digest
            )));
        }
    }
    Ok(())
}

fn validate_continuation_request_binding(
    connection: &Connection,
    envelope: &ExecutionFactEnvelope,
    command: &Command,
    state: &WorkflowState,
    subject: Option<&OperationRef>,
    next_request_digest: Option<&Sha256Digest>,
) -> Result<(), StorageError> {
    let binds_known_result = matches!(
        command,
        Command::ModelToolProposal {
            disposition: workflows::ProposalDisposition::Deny { .. }
        } | Command::ApprovalRejected { .. }
            | Command::ToolResultKnown { .. }
    );
    if !binds_known_result {
        if next_request_digest.is_some() {
            return Err(StorageError::CorruptData(format!(
                "Agent `{}` non-continuation fact carries a model request digest",
                envelope.fact.agent_id
            )));
        }
        return Ok(());
    }

    let Some(next_step) = state.model_steps().checked_add(1) else {
        if next_request_digest.is_some() {
            return Err(StorageError::CorruptData(format!(
                "Agent `{}` continuation request exceeds the model-step range",
                envelope.fact.agent_id
            )));
        }
        return Ok(());
    };
    let stored_job = connection
        .query_row(
            r#"SELECT request_json, queued_at FROM agent_model_jobs
               WHERE agent_id = ?1 AND step = ?2"#,
            params![envelope.fact.agent_id, i64::from(next_step)],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let job_request = stored_job
        .as_ref()
        .map(|(request, _)| serde_json::from_str::<Value>(request))
        .transpose()?;
    let expected_digest = job_request
        .as_ref()
        .map(|request| digest_json(DigestDomain::ModelRequest, request))
        .transpose()?;
    let job_matches = match (
        stored_job.as_ref(),
        expected_digest.as_ref(),
        next_request_digest,
    ) {
        (Some((_, queued_at)), Some(expected), Some(actual)) => {
            state.status() == workflows::AgentStatus::ContinuationQueued
                && queued_at == envelope.fact.recorded_at.as_str()
                && expected == actual
        }
        (None, None, None) => {
            validate_missing_continuation_settlement(connection, envelope, state)?
        }
        _ => false,
    };
    if !job_matches {
        return Err(StorageError::CorruptData(format!(
            "Agent `{}` continuation request fact disagrees with its durable model job",
            envelope.fact.agent_id
        )));
    }

    if matches!(command, Command::ToolResultKnown { .. }) {
        let OperationRef::Tool { call_id, .. } = subject.ok_or_else(|| {
            StorageError::CorruptData(format!(
                "Agent `{}` tool result is missing its operation subject",
                envelope.fact.agent_id
            ))
        })?
        else {
            return Err(StorageError::CorruptData(format!(
                "Agent `{}` tool result has a non-tool operation subject",
                envelope.fact.agent_id
            )));
        };
        let stored_copy: Option<String> = connection.query_row(
            "SELECT completion_next_request_json FROM agent_tool_calls WHERE call_id = ?1",
            [call_id],
            |row| row.get(0),
        )?;
        let stored_copy = stored_copy.ok_or_else(|| {
            StorageError::CorruptData(format!(
                "Agent tool `{call_id}` completion is missing its explicit continuation request copy"
            ))
        })?;
        let copied_request = serde_json::from_str::<Value>(&stored_copy)?;
        let copied_request = (!copied_request.is_null()).then_some(copied_request);
        if job_request.is_some() && copied_request.as_ref() != job_request.as_ref() {
            return Err(StorageError::CorruptData(format!(
                "Agent tool `{call_id}` continuation request copy disagrees with its execution fact"
            )));
        }
    }
    Ok(())
}

fn validate_missing_continuation_settlement(
    connection: &Connection,
    envelope: &ExecutionFactEnvelope,
    state: &WorkflowState,
) -> Result<bool, StorageError> {
    if state.status() != workflows::AgentStatus::ContinuationQueued {
        return Ok(true);
    }
    let next_sequence = envelope
        .fact
        .sequence
        .checked_add(1)
        .ok_or(StorageError::IntegerOutOfRange("Agent execution sequence"))?;
    let next_json = connection
        .query_row(
            r#"SELECT envelope_json FROM agent_execution_events
               WHERE agent_id = ?1 AND sequence = ?2"#,
            params![
                envelope.fact.agent_id,
                u64_to_i64(next_sequence, "Agent execution sequence")?
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let Some(next_json) = next_json else {
        return Ok(false);
    };
    let next = ExecutionFactEnvelope::from_json_slice(next_json.as_bytes())
        .map_err(stored_execution_error)?;
    let ExecutionFactData::WorkflowTransition {
        command,
        state: settled,
        ..
    } = &next.fact.data
    else {
        return Ok(false);
    };
    let explicit_unavailable = matches!(command, Command::ContinuationUnavailable)
        && settled.status() == workflows::AgentStatus::Failed
        && settled.terminal_reason() == Some(workflows::TerminalReason::ContinuationUnavailable);
    let model_limit_refusal = matches!(command, Command::StartModel)
        && settled.status() == workflows::AgentStatus::Failed
        && settled.terminal_reason() == Some(workflows::TerminalReason::ModelStepLimitReached);
    Ok(
        next.fact.previous_fact_digest.as_ref() == Some(&envelope.digest)
            && next.fact.recorded_at == envelope.fact.recorded_at
            && (explicit_unavailable || model_limit_refusal),
    )
}

fn validate_terminal_proposal_evidence(
    connection: &Connection,
    agent_id: &str,
    disposition: &workflows::ProposalDisposition,
    response_digest: &Sha256Digest,
    durable_result_digest: Option<&Sha256Digest>,
) -> Result<(), StorageError> {
    let agent = super::agent::query_agent_turn(connection, agent_id)?;
    let evidence = agent
        .last_error_json
        .as_ref()
        .and_then(|error| error.get("proposal_evidence"))
        .and_then(Value::as_object)
        .ok_or_else(|| {
            StorageError::CorruptData(format!(
                "Agent `{agent_id}` terminal proposal is missing resolution evidence"
            ))
        })?;
    let stored_disposition: workflows::ProposalDisposition =
        serde_json::from_value(evidence.get("disposition").cloned().ok_or_else(|| {
            StorageError::CorruptData(format!(
                "Agent `{agent_id}` terminal proposal is missing its disposition evidence"
            ))
        })?)?;
    let response_matches = evidence
        .get("model_response_digest")
        .and_then(Value::as_str)
        == Some(response_digest.as_str());
    let result_matches = match (disposition, durable_result_digest) {
        (workflows::ProposalDisposition::Deny { .. }, Some(expected)) => {
            evidence.get("result_digest").and_then(Value::as_str) == Some(expected.as_str())
        }
        (workflows::ProposalDisposition::Deny { .. }, None) => evidence
            .get("result_digest")
            .and_then(Value::as_str)
            .and_then(|digest| Sha256Digest::from_hex(digest.to_owned()).ok())
            .is_some(),
        (_, None) => evidence.get("result_digest") == Some(&Value::Null),
        (_, Some(_)) => false,
    };
    if stored_disposition != *disposition || !response_matches || !result_matches {
        return Err(StorageError::CorruptData(format!(
            "Agent `{agent_id}` terminal proposal disagrees with its durable resolution evidence"
        )));
    }
    Ok(())
}

fn validate_epochless_operation_fact(
    connection: &Connection,
    envelope: &ExecutionFactEnvelope,
) -> Result<(), StorageError> {
    let ExecutionFactData::WorkflowTransition {
        command,
        state,
        external_call,
        subject,
        input_digest,
        output_digest,
        emitted_result,
        emitted_result_digest,
        source,
        ..
    } = &envelope.fact.data
    else {
        return Ok(());
    };
    if matches!(command, Command::ContinuationUnavailable)
        || (matches!(command, Command::StartModel)
            && state.status() == workflows::AgentStatus::Failed
            && state.terminal_reason() == Some(workflows::TerminalReason::ModelStepLimitReached))
    {
        let expected_reason = match command {
            Command::ContinuationUnavailable => workflows::TerminalReason::ContinuationUnavailable,
            Command::StartModel => workflows::TerminalReason::ModelStepLimitReached,
            _ => unreachable!("matched epochless terminal settlement"),
        };
        let expected_code = match expected_reason {
            workflows::TerminalReason::ContinuationUnavailable => "continuation_unavailable",
            workflows::TerminalReason::ModelStepLimitReached => "model_step_limit_reached",
            _ => unreachable!("epochless settlement has one of two terminal reasons"),
        };
        let agent = super::agent::query_agent_turn(connection, &envelope.fact.agent_id)?;
        let stored_code = agent
            .last_error_json
            .as_ref()
            .and_then(|error| error.get("code"))
            .and_then(Value::as_str);
        let error_code_matches = stored_code == Some(expected_code)
            || (matches!(command, Command::ContinuationUnavailable)
                && stored_code == Some("deployment_unavailable")
                && is_legacy_rejection_deployment_settlement(connection, &agent, envelope)?)
            || (matches!(command, Command::ContinuationUnavailable)
                && stored_code == Some("knowledge_unavailable")
                && is_legacy_rejection_knowledge_settlement(connection, &agent, envelope)?);
        let exact_terminal_material = *source == FactSource::Live
            && external_call.is_none()
            && subject.is_none()
            && input_digest.is_none()
            && output_digest.is_none()
            && emitted_result.is_none()
            && emitted_result_digest.is_none()
            && state.status() == workflows::AgentStatus::Failed
            && state.terminal_reason() == Some(expected_reason)
            && agent.workflow_state == *state
            && agent.updated_at == envelope.fact.recorded_at.as_str()
            && agent.completed_at.as_deref() == Some(envelope.fact.recorded_at.as_str())
            && error_code_matches;
        if !exact_terminal_material {
            return Err(StorageError::CorruptData(format!(
                "Agent `{}` epochless terminal settlement disagrees with durable state",
                envelope.fact.agent_id
            )));
        }
        return Ok(());
    }
    if !matches!(
        command,
        Command::AuthorizationRevoked
            | Command::UserCancelled
            | Command::DeploymentUnavailable
            | Command::KnowledgeUnavailable
            | Command::ApprovalApproved
            | Command::ApprovalRejected { .. }
    ) {
        return Ok(());
    }
    let (Some(subject), Some(input_digest), FactSource::Live) = (subject, input_digest, source)
    else {
        return Err(StorageError::CorruptData(format!(
            "Agent `{}` non-release operation fact is incomplete",
            envelope.fact.agent_id
        )));
    };
    let rejection_error_code = match command {
        Command::AuthorizationRevoked => Some("authorization_revoked"),
        Command::UserCancelled => Some("user_cancelled"),
        Command::DeploymentUnavailable => Some("deployment_unavailable"),
        Command::KnowledgeUnavailable => Some("knowledge_unavailable"),
        _ => None,
    };
    let matches_durable = match (command, subject) {
        (
            Command::AuthorizationRevoked
            | Command::UserCancelled
            | Command::DeploymentUnavailable
            | Command::KnowledgeUnavailable,
            OperationRef::Model { job_id, step },
        ) => {
            let job = super::agent::query_agent_model_job_by_id(connection, job_id)?;
            let error = required_material(job.error_json.as_ref(), "model rejection error")?;
            let expected_output = digest_json(DigestDomain::ExecutionError, error)?;
            job.agent_id == envelope.fact.agent_id
                && job.step == *step
                && job.status == AgentModelJobStatus::Failed
                && job.attempt == 1
                && job.started_at.as_deref() == Some(envelope.fact.recorded_at.as_str())
                && job.finished_at.as_deref() == Some(envelope.fact.recorded_at.as_str())
                && digest_json(DigestDomain::ModelRequest, &job.request_json)? == *input_digest
                && output_digest.as_ref() == Some(&expected_output)
                && error.get("code").and_then(Value::as_str) == rejection_error_code
        }
        (
            Command::AuthorizationRevoked
            | Command::UserCancelled
            | Command::DeploymentUnavailable
            | Command::KnowledgeUnavailable,
            OperationRef::Tool {
                call_id,
                ordinal,
                model_step,
            },
        ) => {
            let call = super::agent::query_agent_tool_call(connection, call_id)?;
            let expected_input = recomputed_tool_input_digest(&call, "tool rejection")?;
            let error = required_material(call.result_json.as_ref(), "tool rejection error")?;
            let expected_output = digest_json(DigestDomain::ExecutionError, error)?;
            call.agent_id == envelope.fact.agent_id
                && call.ordinal == *ordinal
                && call.model_step == *model_step
                && call.status
                    == if matches!(command, Command::UserCancelled) {
                        AgentToolCallStatus::Cancelled
                    } else {
                        AgentToolCallStatus::NotDispatched
                    }
                && call.started_at.is_none()
                && call.finished_at.as_deref() == Some(envelope.fact.recorded_at.as_str())
                && expected_input == *input_digest
                && output_digest.as_ref() == Some(&expected_output)
                && error.get("code").and_then(Value::as_str) == rejection_error_code
        }
        (
            Command::ApprovalApproved,
            OperationRef::Tool {
                call_id,
                ordinal,
                model_step,
            },
        ) => {
            let call = super::agent::query_agent_tool_call(connection, call_id)?;
            call.agent_id == envelope.fact.agent_id
                && call.ordinal == *ordinal
                && call.model_step == *model_step
                && call.policy_decision == protocol::PolicyDecision::RequireApproval
                && call.status != AgentToolCallStatus::WaitingApproval
                && call.status != AgentToolCallStatus::Rejected
                && call.approving_actor_user_id.is_some()
                && call.approving_membership_revision.is_some()
                && call.reviewed_at.as_deref() == Some(envelope.fact.recorded_at.as_str())
                && recomputed_tool_input_digest(&call, "approved tool")? == *input_digest
                && output_digest.is_none()
                && emitted_result_digest.is_none()
        }
        (
            Command::ApprovalRejected { result_bytes },
            OperationRef::Tool {
                call_id,
                ordinal,
                model_step,
            },
        ) => {
            let call = super::agent::query_agent_tool_call(connection, call_id)?;
            let expected_output = digest_json(
                DigestDomain::ToolResult,
                required_material(call.result_json.as_ref(), "tool rejection result")?,
            )?;
            let actual_result_bytes = json_serialized_bytes(
                required_material(call.result_json.as_ref(), "tool rejection result")?,
                "tool rejection result",
            )?;
            let emitted_material_matches = match (emitted_result, emitted_result_digest) {
                (Some(result), Some(digest)) => {
                    digest == &expected_output && result.serialized_bytes == *result_bytes
                }
                (None, None) => {
                    state.status() == workflows::AgentStatus::Failed
                        && state.terminal_reason()
                            == Some(workflows::TerminalReason::ToolResultBytesLimitReached)
                }
                _ => false,
            };
            call.agent_id == envelope.fact.agent_id
                && call.ordinal == *ordinal
                && call.model_step == *model_step
                && call.policy_decision == protocol::PolicyDecision::RequireApproval
                && call.status == AgentToolCallStatus::Rejected
                && call.approving_actor_user_id.is_some()
                && call.approving_membership_revision.is_some()
                && call.reviewed_at.as_deref() == Some(envelope.fact.recorded_at.as_str())
                && call.finished_at.as_deref() == Some(envelope.fact.recorded_at.as_str())
                && recomputed_tool_input_digest(&call, "rejected tool")? == *input_digest
                && output_digest.as_ref() == Some(&expected_output)
                && emitted_material_matches
                && actual_result_bytes == *result_bytes
        }
        _ => false,
    };
    if !matches_durable {
        return Err(StorageError::CorruptData(format!(
            "Agent `{}` non-release operation fact disagrees with durable state",
            envelope.fact.agent_id
        )));
    }
    Ok(())
}

fn is_legacy_rejection_deployment_settlement(
    connection: &Connection,
    agent: &AgentTurn,
    envelope: &ExecutionFactEnvelope,
) -> Result<bool, StorageError> {
    if agent.deployment_manifest_digest.is_some() || envelope.fact.sequence <= 1 {
        return Ok(false);
    }
    let previous_sequence = envelope.fact.sequence - 1;
    let previous = connection
        .query_row(
            r#"SELECT event.envelope_json, head.history_origin
               FROM agent_execution_events event
               JOIN agent_execution_heads head ON head.agent_id = event.agent_id
               WHERE event.agent_id = ?1 AND event.sequence = ?2"#,
            params![
                envelope.fact.agent_id,
                u64_to_i64(previous_sequence, "Agent execution sequence")?
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((previous_json, history_origin)) = previous else {
        return Ok(false);
    };
    let previous = ExecutionFactEnvelope::from_json_slice(previous_json.as_bytes())
        .map_err(stored_execution_error)?;
    let ExecutionFactData::WorkflowTransition {
        command: Command::ApprovalRejected { .. },
        state,
        next_request_digest,
        ..
    } = &previous.fact.data
    else {
        return Ok(false);
    };
    Ok(history_origin == "legacy_snapshot"
        && envelope.fact.previous_fact_digest.as_ref() == Some(&previous.digest)
        && envelope.fact.recorded_at == previous.fact.recorded_at
        && state.status() == workflows::AgentStatus::ContinuationQueued
        && next_request_digest.is_none())
}

fn is_legacy_rejection_knowledge_settlement(
    connection: &Connection,
    agent: &AgentTurn,
    envelope: &ExecutionFactEnvelope,
) -> Result<bool, StorageError> {
    if agent.knowledge_context_digest.is_some() || envelope.fact.sequence <= 1 {
        return Ok(false);
    }
    let previous_sequence = envelope.fact.sequence - 1;
    let previous_json = connection
        .query_row(
            r#"SELECT envelope_json FROM agent_execution_events
               WHERE agent_id = ?1 AND sequence = ?2"#,
            params![
                envelope.fact.agent_id,
                u64_to_i64(previous_sequence, "Agent execution sequence")?
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let Some(previous_json) = previous_json else {
        return Ok(false);
    };
    let previous = ExecutionFactEnvelope::from_json_slice(previous_json.as_bytes())
        .map_err(stored_execution_error)?;
    let ExecutionFactData::WorkflowTransition {
        command: Command::ApprovalRejected { .. },
        state,
        next_request_digest,
        ..
    } = &previous.fact.data
    else {
        return Ok(false);
    };
    Ok(
        envelope.fact.previous_fact_digest.as_ref() == Some(&previous.digest)
            && envelope.fact.recorded_at == previous.fact.recorded_at
            && state.status() == workflows::AgentStatus::ContinuationQueued
            && next_request_digest.is_none(),
    )
}

fn recomputed_tool_input_digest(
    call: &AgentToolCall,
    description: &str,
) -> Result<Sha256Digest, StorageError> {
    let recomputed = tools::arguments_digest(&call.arguments_json);
    if recomputed != call.arguments_digest {
        return Err(StorageError::CorruptData(format!(
            "Agent tool `{}` {description} argument digest is inconsistent",
            call.call_id
        )));
    }
    Sha256Digest::from_reference(&recomputed).map_err(stored_execution_error)
}

fn validate_legacy_epochless_recovery(
    connection: &Connection,
    envelope: &ExecutionFactEnvelope,
) -> Result<(), StorageError> {
    let ExecutionFactData::WorkflowTransition {
        from_revision,
        command,
        subject: Some(subject),
        input_digest: Some(input_digest),
        output_digest: Some(output_digest),
        ..
    } = &envelope.fact.data
    else {
        return Err(StorageError::CorruptData(format!(
            "Agent `{}` epochless recovery fact is incomplete",
            envelope.fact.agent_id
        )));
    };
    if envelope.fact.sequence != 2 {
        return Err(StorageError::CorruptData(format!(
            "Agent `{}` epochless recovery is not the first post-migration fact",
            envelope.fact.agent_id
        )));
    }
    let (origin_json, history_origin): (String, String) = connection.query_row(
        r#"SELECT event.envelope_json, head.history_origin
           FROM agent_execution_events event
           JOIN agent_execution_heads head ON head.agent_id = event.agent_id
           WHERE event.agent_id = ?1 AND event.sequence = 1"#,
        [&envelope.fact.agent_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let origin = ExecutionFactEnvelope::from_json_slice(origin_json.as_bytes())
        .map_err(stored_execution_error)?;
    let ExecutionFactData::LegacySnapshot {
        state,
        origin_revision,
        ..
    } = &origin.fact.data
    else {
        return Err(StorageError::CorruptData(format!(
            "Agent `{}` epochless recovery lacks a legacy snapshot origin",
            envelope.fact.agent_id
        )));
    };
    if history_origin != "legacy_snapshot" || origin_revision != from_revision {
        return Err(StorageError::CorruptData(format!(
            "Agent `{}` epochless recovery revision is not its migration origin",
            envelope.fact.agent_id
        )));
    }

    let material_matches = match (command, subject) {
        (Command::ModelOutcomeUnknown, OperationRef::Model { job_id, step })
            if state.status() == workflows::AgentStatus::ModelStarted
                && state.model_steps() == *step =>
        {
            let job = super::agent::query_agent_model_job_by_id(connection, job_id)?;
            job.agent_id == envelope.fact.agent_id
                && job.step == *step
                && job.status == AgentModelJobStatus::OutcomeUnknown
                && job.attempt == 1
                && job.started_at.is_some()
                && job.finished_at.as_deref() == Some(envelope.fact.recorded_at.as_str())
                && digest_json(DigestDomain::ModelRequest, &job.request_json)? == *input_digest
                && digest_json(
                    DigestDomain::ExecutionError,
                    required_material(job.error_json.as_ref(), "model error")?,
                )? == *output_digest
        }
        (
            Command::ToolOutcomeUnknown,
            OperationRef::Tool {
                call_id,
                ordinal,
                model_step,
            },
        ) if state.status() == workflows::AgentStatus::ToolStarted
            && state.tool_calls() == *ordinal
            && state.model_steps() == *model_step =>
        {
            let call = super::agent::query_agent_tool_call(connection, call_id)?;
            let expected_input = recomputed_tool_input_digest(&call, "legacy recovery")?;
            call.agent_id == envelope.fact.agent_id
                && call.ordinal == *ordinal
                && call.model_step == *model_step
                && call.status == AgentToolCallStatus::OutcomeUnknown
                && call.started_at.is_some()
                && call.finished_at.as_deref() == Some(envelope.fact.recorded_at.as_str())
                && expected_input == *input_digest
                && digest_json(
                    DigestDomain::ExecutionError,
                    required_material(call.result_json.as_ref(), "tool error")?,
                )? == *output_digest
        }
        _ => false,
    };
    if !material_matches {
        return Err(StorageError::CorruptData(format!(
            "Agent `{}` epochless recovery disagrees with its legacy operation",
            envelope.fact.agent_id
        )));
    }
    Ok(())
}

fn query_epoch_summaries(
    connection: &Connection,
    agent: &AgentTurn,
) -> Result<Vec<RunEpochSummary>, StorageError> {
    let mut statement = connection.prepare(
        r#"SELECT digest, operation_kind, model_job_id, tool_call_id,
                  envelope_json, created_at
           FROM agent_run_epochs
           WHERE agent_id = ?1
           ORDER BY workflow_revision, digest"#,
    )?;
    let rows = statement
        .query_map([&agent.id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);

    rows.into_iter()
        .map(
            |(digest, kind, model_job_id, tool_call_id, json, created_at)| {
                let envelope = decode_epoch_envelope(agent, &digest, &json, &created_at)?;
                validate_epoch_durable_binding(connection, agent, &envelope)?;
                match (&envelope.epoch.operation, kind.as_str()) {
                    (RunOperation::Model { job_id, step, .. }, "model")
                        if model_job_id.as_deref() == Some(job_id.as_str())
                            && tool_call_id.is_none() =>
                    {
                        let job =
                            super::agent::query_agent_model_job(connection, &agent.id, *step)?;
                        model_epoch_summary(&envelope, &job)
                    }
                    (RunOperation::Tool { call_id, .. }, "tool")
                        if tool_call_id.as_deref() == Some(call_id.as_str())
                            && model_job_id.is_none() =>
                    {
                        let call = super::agent::query_agent_tool_call(connection, call_id)?;
                        tool_epoch_summary(&envelope, &call)
                    }
                    _ => Err(StorageError::CorruptData(format!(
                        "Agent `{}` RunEpoch operation lookup is inconsistent",
                        agent.id
                    ))),
                }
            },
        )
        .collect()
}

fn query_model_epoch(
    connection: &Connection,
    agent: &AgentTurn,
    job: &AgentModelJob,
) -> Result<RunEpochEnvelope, StorageError> {
    let row = connection
        .query_row(
            r#"SELECT digest, envelope_json, created_at
               FROM agent_run_epochs
               WHERE agent_id = ?1 AND operation_kind = 'model' AND model_job_id = ?2"#,
            params![agent.id, job.id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| {
            StorageError::AgentModelJobNotFound(format!("{}/step-{}", agent.id, job.step))
        })?;
    let envelope = decode_epoch_envelope(agent, &row.0, &row.1, &row.2)?;
    validate_epoch_durable_binding(connection, agent, &envelope)?;
    Ok(envelope)
}

fn decode_epoch_envelope(
    agent: &AgentTurn,
    digest: &str,
    json: &str,
    created_at: &str,
) -> Result<RunEpochEnvelope, StorageError> {
    let envelope =
        RunEpochEnvelope::from_json_slice(json.as_bytes()).map_err(stored_execution_error)?;
    if envelope
        .canonical_json_bytes()
        .map_err(stored_execution_error)?
        != json.as_bytes()
        || envelope.digest.as_str() != digest
        || envelope.epoch.agent_id != agent.id
        || envelope.epoch.account_id != agent.account_id.as_str()
        || envelope.epoch.session_id != agent.session_id
        || envelope.epoch.turn_id != agent.turn_id
        || envelope.epoch.created_at.as_str() != created_at
    {
        return Err(StorageError::CorruptData(format!(
            "Agent `{}` RunEpoch envelope disagrees with its durable binding",
            agent.id
        )));
    }
    Ok(envelope)
}

fn validate_epoch_durable_binding(
    connection: &Connection,
    agent: &AgentTurn,
    envelope: &RunEpochEnvelope,
) -> Result<(), StorageError> {
    let epoch = &envelope.epoch;
    let bound_manifest = epoch
        .bound_manifest_digest
        .as_ref()
        .map(Sha256Digest::as_str);
    if epoch.agent_id != agent.id
        || epoch.account_id != agent.account_id.as_str()
        || epoch.session_id != agent.session_id
        || epoch.turn_id != agent.turn_id
        || epoch.initiator.user_id != agent.actor_user_id
        || epoch.initiator.membership_revision != agent.actor_membership_revision.get()
        || bound_manifest != agent.deployment_manifest_digest.as_deref()
        || epoch.observed_manifest_digest.as_str()
            != agent
                .deployment_manifest_digest
                .as_deref()
                .unwrap_or_default()
    {
        return Err(StorageError::CorruptData(format!(
            "Agent `{}` RunEpoch authority disagrees with its durable Agent",
            agent.id
        )));
    }

    let operation_terminal = match &epoch.operation {
        RunOperation::Model {
            job_id,
            step,
            request_digest,
        } => {
            if epoch.approver.is_some() {
                return Err(StorageError::CorruptData(format!(
                    "model RunEpoch `{}` cannot carry tool approval authority",
                    envelope.digest
                )));
            }
            let job = super::agent::query_agent_model_job_by_id(connection, job_id)?;
            let expected_request = digest_json(DigestDomain::ModelRequest, &job.request_json)?;
            if job.agent_id != agent.id
                || job.account_id != agent.account_id
                || job.actor_user_id != agent.actor_user_id
                || job.actor_membership_revision != agent.actor_membership_revision
                || job.session_id != agent.session_id
                || job.turn_id != agent.turn_id
                || job.step != *step
                || &expected_request != request_digest
                || job.attempt != 1
                || job.started_at.as_deref() != Some(epoch.created_at.as_str())
                || job.status == AgentModelJobStatus::Queued
            {
                return Err(StorageError::CorruptData(format!(
                    "model RunEpoch `{}` disagrees with its durable job authority",
                    envelope.digest
                )));
            }
            job.status != AgentModelJobStatus::Started
        }
        RunOperation::Tool {
            call_id,
            ordinal,
            model_step,
            tool_name,
            tool_version,
            arguments_digest,
            effect,
            sandbox_profile,
            policy_revision,
        } => {
            let call = super::agent::query_agent_tool_call(connection, call_id)?;
            let recomputed_arguments = tools::arguments_digest(&call.arguments_json);
            if recomputed_arguments != call.arguments_digest {
                return Err(StorageError::CorruptData(format!(
                    "tool RunEpoch `{}` durable argument digest is inconsistent",
                    envelope.digest
                )));
            }
            let expected_arguments = Sha256Digest::from_reference(&recomputed_arguments)
                .map_err(stored_execution_error)?;
            let epoch_approver = epoch
                .approver
                .as_ref()
                .map(|actor| (actor.user_id.as_str(), actor.membership_revision));
            let call_approver = call.approving_actor_user_id.as_deref().zip(
                call.approving_membership_revision
                    .as_ref()
                    .map(|revision| revision.get()),
            );
            if call.agent_id != agent.id
                || call.account_id != agent.account_id
                || call.session_id != agent.session_id
                || call.turn_id != agent.turn_id
                || call.ordinal != *ordinal
                || call.model_step != *model_step
                || call.tool_name != *tool_name
                || call.tool_version != *tool_version
                || expected_arguments != *arguments_digest
                || call.effect != *effect
                || call.sandbox_profile != *sandbox_profile
                || call.policy_revision != *policy_revision
                || call_approver != epoch_approver
                || call.started_at.as_deref() != Some(epoch.created_at.as_str())
                || matches!(
                    call.status,
                    AgentToolCallStatus::WaitingApproval | AgentToolCallStatus::Queued
                )
            {
                return Err(StorageError::CorruptData(format!(
                    "tool RunEpoch `{}` disagrees with its durable call authority",
                    envelope.digest
                )));
            }
            call.status != AgentToolCallStatus::Running
        }
    };

    let mut statement = connection.prepare(
        r#"SELECT envelope_json FROM agent_execution_events
           WHERE agent_id = ?1 AND epoch_digest = ?2 ORDER BY sequence"#,
    )?;
    let event_json = statement
        .query_map(params![agent.id, envelope.digest.as_str()], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    let mut starts = Vec::new();
    let mut terminal_count = 0_usize;
    for json in event_json {
        let fact = ExecutionFactEnvelope::from_json_slice(json.as_bytes())
            .map_err(stored_execution_error)?;
        validate_fact_epoch_binding(connection, &fact)?;
        if matches!(
            fact.fact.data,
            ExecutionFactData::WorkflowTransition {
                command: Command::ModelFinal { .. }
                    | Command::ModelToolProposal { .. }
                    | Command::ModelFailed
                    | Command::ModelOutcomeUnknown
                    | Command::ToolResultKnown { .. }
                    | Command::ToolOutcomeUnknown,
                ..
            }
        ) {
            terminal_count += 1;
        }
        if matches!(
            fact.fact.data,
            ExecutionFactData::WorkflowTransition {
                command: Command::StartModel | Command::StartTool,
                ..
            }
        ) {
            starts.push(fact);
        }
    }
    if starts.len() != 1 {
        return Err(StorageError::CorruptData(format!(
            "RunEpoch `{}` must own exactly one release fact",
            envelope.digest
        )));
    }
    if terminal_count != usize::from(operation_terminal) {
        return Err(StorageError::CorruptData(format!(
            "RunEpoch `{}` terminal fact count disagrees with its durable operation",
            envelope.digest
        )));
    }
    let start = &starts[0];
    validate_fact_epoch_binding(connection, start)?;
    let ExecutionFactData::WorkflowTransition {
        to_revision,
        source,
        ..
    } = &start.fact.data
    else {
        unreachable!("the filtered fact is a workflow transition");
    };
    if *to_revision != epoch.workflow_revision
        || *source != FactSource::Live
        || start.fact.recorded_at != epoch.created_at
    {
        return Err(StorageError::CorruptData(format!(
            "RunEpoch `{}` release fact has inconsistent revision, source, or timestamp",
            envelope.digest
        )));
    }
    Ok(())
}

fn model_epoch_summary(
    envelope: &RunEpochEnvelope,
    job: &AgentModelJob,
) -> Result<RunEpochSummary, StorageError> {
    let RunOperation::Model { job_id, step, .. } = &envelope.epoch.operation else {
        return Err(StorageError::CorruptData(
            "model RunEpoch contains a non-model operation".into(),
        ));
    };
    if job_id != &job.id
        || *step != job.step
        || envelope.epoch.agent_id != job.agent_id
        || envelope.epoch.session_id != job.session_id
        || envelope.epoch.turn_id != job.turn_id
    {
        return Err(StorageError::CorruptData(format!(
            "model RunEpoch `{}` disagrees with its durable job",
            envelope.digest
        )));
    }
    let status = model_epoch_status(&job.status);
    let (outcome_digest, provenance) = match job.status {
        AgentModelJobStatus::Succeeded => {
            let response = required_material(job.response_json.as_ref(), "model response")?;
            (
                Some(digest_json(DigestDomain::ModelResponse, response)?),
                Some(model_response_provenance(job, response)?),
            )
        }
        AgentModelJobStatus::Failed | AgentModelJobStatus::OutcomeUnknown => {
            let error = required_material(job.error_json.as_ref(), "model error")?;
            (
                Some(digest_json(DigestDomain::ExecutionError, error)?),
                None,
            )
        }
        AgentModelJobStatus::Queued | AgentModelJobStatus::Started => (None, None),
    };
    let summary = RunEpochSummary {
        envelope: envelope.clone(),
        status,
        queued_at: recorded_at(&job.queued_at, "model queued timestamp")?,
        started_at: optional_recorded_at(job.started_at.as_deref(), "model start timestamp")?,
        finished_at: optional_recorded_at(job.finished_at.as_deref(), "model finish timestamp")?,
        outcome_digest,
        provenance,
    };
    summary.validate().map_err(stored_execution_error)?;
    Ok(summary)
}

fn model_epoch_outcome(job: &AgentModelJob) -> Result<EpochOutcomeMaterial, StorageError> {
    let outcome = match job.status {
        AgentModelJobStatus::Queued | AgentModelJobStatus::Started => EpochOutcomeMaterial::Pending,
        AgentModelJobStatus::Succeeded => {
            let response = required_material(job.response_json.as_ref(), "model response")?;
            EpochOutcomeMaterial::Succeeded {
                response: ExactJsonMaterial::new(
                    ExactMaterialKind::ModelResponse,
                    response.clone(),
                )
                .map_err(stored_execution_error)?,
                provenance: model_response_provenance(job, response)?,
            }
        }
        AgentModelJobStatus::Failed => EpochOutcomeMaterial::Failed {
            error: ExactJsonMaterial::new(
                ExactMaterialKind::ExecutionError,
                required_material(job.error_json.as_ref(), "model error")?.clone(),
            )
            .map_err(stored_execution_error)?,
        },
        AgentModelJobStatus::OutcomeUnknown => EpochOutcomeMaterial::OutcomeUnknown {
            error: ExactJsonMaterial::new(
                ExactMaterialKind::ExecutionError,
                required_material(job.error_json.as_ref(), "model error")?.clone(),
            )
            .map_err(stored_execution_error)?,
        },
    };
    outcome.validate().map_err(stored_execution_error)?;
    Ok(outcome)
}

fn tool_epoch_summary(
    envelope: &RunEpochEnvelope,
    call: &AgentToolCall,
) -> Result<RunEpochSummary, StorageError> {
    let RunOperation::Tool {
        call_id,
        ordinal,
        model_step,
        ..
    } = &envelope.epoch.operation
    else {
        return Err(StorageError::CorruptData(
            "tool RunEpoch contains a non-tool operation".into(),
        ));
    };
    if call_id != &call.call_id
        || *ordinal != call.ordinal
        || *model_step != call.model_step
        || envelope.epoch.agent_id != call.agent_id
        || envelope.epoch.session_id != call.session_id
        || envelope.epoch.turn_id != call.turn_id
    {
        return Err(StorageError::CorruptData(format!(
            "tool RunEpoch `{}` disagrees with its durable call",
            envelope.digest
        )));
    }
    let status = tool_epoch_status(&call.status);
    let outcome_digest = if call.status.is_terminal() {
        let result = required_material(call.result_json.as_ref(), "tool result")?;
        let domain = if call.status == AgentToolCallStatus::OutcomeUnknown {
            DigestDomain::ExecutionError
        } else {
            DigestDomain::ToolResult
        };
        Some(digest_json(domain, result)?)
    } else {
        None
    };
    let summary = RunEpochSummary {
        envelope: envelope.clone(),
        status,
        queued_at: recorded_at(&call.created_at, "tool queued timestamp")?,
        started_at: optional_recorded_at(call.started_at.as_deref(), "tool start timestamp")?,
        finished_at: optional_recorded_at(call.finished_at.as_deref(), "tool finish timestamp")?,
        outcome_digest,
        provenance: None,
    };
    summary.validate().map_err(stored_execution_error)?;
    Ok(summary)
}

fn model_epoch_status(status: &AgentModelJobStatus) -> EpochExecutionStatus {
    match status {
        AgentModelJobStatus::Queued => EpochExecutionStatus::Queued,
        AgentModelJobStatus::Started => EpochExecutionStatus::Started,
        AgentModelJobStatus::Succeeded => EpochExecutionStatus::Succeeded,
        AgentModelJobStatus::Failed => EpochExecutionStatus::Failed,
        AgentModelJobStatus::OutcomeUnknown => EpochExecutionStatus::OutcomeUnknown,
    }
}

fn tool_epoch_status(status: &AgentToolCallStatus) -> EpochExecutionStatus {
    match status {
        AgentToolCallStatus::WaitingApproval => EpochExecutionStatus::WaitingApproval,
        AgentToolCallStatus::Queued => EpochExecutionStatus::Queued,
        AgentToolCallStatus::Running => EpochExecutionStatus::Started,
        AgentToolCallStatus::Succeeded => EpochExecutionStatus::Succeeded,
        AgentToolCallStatus::Failed => EpochExecutionStatus::Failed,
        AgentToolCallStatus::Cancelled => EpochExecutionStatus::Cancelled,
        AgentToolCallStatus::Rejected => EpochExecutionStatus::Rejected,
        AgentToolCallStatus::NotDispatched => EpochExecutionStatus::NotDispatched,
        AgentToolCallStatus::OutcomeUnknown => EpochExecutionStatus::OutcomeUnknown,
    }
}

fn model_response_provenance(
    job: &AgentModelJob,
    response: &Value,
) -> Result<AssistantReplyProvenance, StorageError> {
    let provider = response.get("provider").cloned().ok_or_else(|| {
        StorageError::CorruptData(format!(
            "successful Agent model job `{}` is missing provider provenance",
            job.id
        ))
    })?;
    let provenance: AssistantReplyProvenance = serde_json::from_value(provider)?;
    if provenance.provider_id != job.provider_name || provenance.model != job.model_name {
        return Err(StorageError::CorruptData(format!(
            "successful Agent model job `{}` has mismatched provider provenance",
            job.id
        )));
    }
    Ok(provenance)
}

fn required_material<'a>(
    material: Option<&'a Value>,
    description: &str,
) -> Result<&'a Value, StorageError> {
    material.ok_or_else(|| {
        StorageError::CorruptData(format!(
            "terminal Agent execution is missing its {description}"
        ))
    })
}

fn json_serialized_bytes(value: &Value, description: &str) -> Result<u64, StorageError> {
    u64::try_from(serde_json::to_vec(value)?.len()).map_err(|_| {
        StorageError::CorruptData(format!("{description} serialized length is out of range"))
    })
}

fn recorded_at(value: &str, description: &str) -> Result<RecordedAt, StorageError> {
    RecordedAt::parse(value).map_err(|error| {
        StorageError::CorruptData(format!("invalid stored {description}: {error}"))
    })
}

fn optional_recorded_at(
    value: Option<&str>,
    description: &str,
) -> Result<Option<RecordedAt>, StorageError> {
    value
        .map(|value| recorded_at(value, description))
        .transpose()
}

fn execution_history(
    agent: &AgentTurn,
    head: &ExecutionReadHead,
    has_manifest: bool,
    has_knowledge: bool,
    epochs: &[RunEpochSummary],
    exact_request_returned: bool,
) -> Result<ExecutionHistory, StorageError> {
    let mut reasons = Vec::new();
    if head.origin == ExecutionHistoryOrigin::LegacySnapshot {
        reasons.push(ExecutionHistoryReason::LegacyExecutionSnapshot);
    }
    if !has_manifest {
        reasons.push(ExecutionHistoryReason::LegacyManifestUnbound);
    }
    if !has_knowledge {
        reasons.push(ExecutionHistoryReason::LegacyKnowledgeUnbound);
    }
    if epochs.iter().any(|epoch| {
        matches!(
            epoch.status,
            EpochExecutionStatus::WaitingApproval
                | EpochExecutionStatus::Queued
                | EpochExecutionStatus::Started
        )
    }) || matches!(
        agent.workflow_state.status(),
        workflows::AgentStatus::ModelStarted | workflows::AgentStatus::ToolStarted
    ) {
        reasons.push(ExecutionHistoryReason::OutcomePending);
    }
    if epochs
        .iter()
        .any(|epoch| epoch.status == EpochExecutionStatus::OutcomeUnknown)
        || matches!(
            agent.workflow_state.terminal_reason(),
            Some(
                workflows::TerminalReason::ModelOutcomeUnknown
                    | workflows::TerminalReason::ToolOutcomeUnknown
            )
        )
    {
        reasons.push(ExecutionHistoryReason::OutcomeUnknown);
    }

    let terminal_proposal_material_unavailable = matches!(
        agent.workflow_state.terminal_reason(),
        Some(
            workflows::TerminalReason::ToolCallLimitReached
                | workflows::TerminalReason::PendingApprovalLimitReached
        )
    );
    if terminal_proposal_material_unavailable {
        reasons.push(ExecutionHistoryReason::TerminalProposalMaterialUnavailable);
    }

    let derivation = if head.history_complete && !terminal_proposal_material_unavailable {
        ReconstructionLevel::Complete
    } else {
        if !reasons.contains(&ExecutionHistoryReason::DerivationInputsUnavailable) {
            reasons.push(ExecutionHistoryReason::DerivationInputsUnavailable);
        }
        ReconstructionLevel::Partial
    };
    let request_material = if exact_request_returned || head.history_complete {
        ReconstructionLevel::Complete
    } else {
        if !reasons.contains(&ExecutionHistoryReason::ExactRequestUnavailable) {
            reasons.push(ExecutionHistoryReason::ExactRequestUnavailable);
        }
        ReconstructionLevel::Partial
    };
    let deployment_authority = if has_manifest {
        DeploymentAuthority::Verified
    } else {
        DeploymentAuthority::LegacyUnbound
    };
    let overall = if head.origin == ExecutionHistoryOrigin::Native
        && head.history_complete
        && has_manifest
        && has_knowledge
        && reasons.is_empty()
    {
        ReconstructionLevel::Complete
    } else {
        ReconstructionLevel::Partial
    };
    let history = ExecutionHistory {
        origin: head.origin,
        overall,
        request_material,
        derivation,
        deployment_authority,
        reasons,
    };
    history.validate().map_err(stored_execution_error)?;
    Ok(history)
}

pub(super) fn verify_agent_execution_integrity(
    connection: &Connection,
) -> Result<(), StorageError> {
    let mut tool_statement = connection.prepare(
        "SELECT call_id, arguments_json, arguments_digest FROM agent_tool_calls ORDER BY call_id",
    )?;
    let tool_inputs = tool_statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(tool_statement);
    for (call_id, arguments_json, stored_digest) in tool_inputs {
        let arguments: Value = serde_json::from_str(&arguments_json)?;
        if tools::arguments_digest(&arguments) != stored_digest {
            return Err(StorageError::CorruptData(format!(
                "Agent tool `{call_id}` arguments digest disagrees with its durable JSON"
            )));
        }
    }

    let agent_count: i64 =
        connection.query_row("SELECT COUNT(*) FROM agent_turns", [], |row| row.get(0))?;
    let head_count: i64 =
        connection.query_row("SELECT COUNT(*) FROM agent_execution_heads", [], |row| {
            row.get(0)
        })?;
    if agent_count != head_count {
        return Err(StorageError::CorruptData(
            "every Agent must own exactly one execution head".into(),
        ));
    }

    let mut head_statement = connection.prepare(
        r#"SELECT head.agent_id, head.head_sequence, head.projected_agent_revision,
                  head.origin_revision, head.history_origin, head.history_complete,
                  head.head_hash, head.committed_payload_bytes, agent.revision,
                  agent.workflow_state_json
           FROM agent_execution_heads head
           JOIN agent_turns agent ON agent.id = head.agent_id
           ORDER BY head.agent_id"#,
    )?;
    let heads = head_statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, String>(9)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(head_statement);

    for (
        agent_id,
        head_sequence,
        projected_revision,
        origin_revision,
        history_origin,
        history_complete,
        head_hash,
        committed_bytes,
        agent_revision,
        agent_state_json,
    ) in heads
    {
        if projected_revision != agent_revision {
            return Err(StorageError::CorruptData(format!(
                "Agent `{agent_id}` execution head revision disagrees with its projection"
            )));
        }
        let expected_origin = match (history_origin.as_str(), history_complete, origin_revision) {
            ("native", 1, 1) => ExecutionHistoryOrigin::Native,
            ("legacy_snapshot", 0, revision) if revision > 0 => {
                ExecutionHistoryOrigin::LegacySnapshot
            }
            _ => {
                return Err(StorageError::CorruptData(format!(
                    "Agent `{agent_id}` execution history origin is invalid"
                )));
            }
        };
        let durable_agent = super::agent::query_agent_turn(connection, &agent_id)?;
        let mut statement = connection.prepare(
            r#"SELECT sequence, fact_digest, previous_fact_digest, fact_kind,
                      agent_revision, epoch_digest, operation_kind, operation_id,
                      envelope_json, created_at
               FROM agent_execution_events WHERE agent_id = ?1 ORDER BY sequence"#,
        )?;
        let rows = statement
            .query_map([&agent_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        if i64::try_from(rows.len()).ok() != Some(head_sequence) {
            return Err(StorageError::CorruptData(format!(
                "Agent `{agent_id}` execution sequence contains a gap"
            )));
        }
        let mut previous = None;
        let mut payload_bytes = 0_i64;
        let mut last_state = None;
        let mut replay_state = None;
        let mut replay_revision = None;
        for (
            index,
            (
                sequence,
                digest,
                stored_previous,
                stored_kind,
                stored_revision,
                stored_epoch,
                stored_operation_kind,
                stored_operation_id,
                envelope_json,
                stored_created_at,
            ),
        ) in rows.into_iter().enumerate()
        {
            let expected_sequence = i64::try_from(index + 1)
                .map_err(|_| StorageError::IntegerOutOfRange("Agent execution sequence"))?;
            if sequence != expected_sequence || stored_previous != previous {
                return Err(StorageError::CorruptData(format!(
                    "Agent `{agent_id}` execution digest chain is discontinuous"
                )));
            }
            let envelope = ExecutionFactEnvelope::from_json_slice(envelope_json.as_bytes())
                .map_err(stored_execution_error)?;
            if envelope
                .canonical_json_bytes()
                .map_err(stored_execution_error)?
                != envelope_json.as_bytes()
            {
                return Err(StorageError::CorruptData(format!(
                    "Agent `{agent_id}` execution envelope is not canonical JSON"
                )));
            }
            if envelope.fact.agent_id != agent_id
                || u64_to_i64(envelope.fact.sequence, "Agent execution sequence")? != sequence
                || envelope.digest.as_str() != digest
                || envelope
                    .fact
                    .previous_fact_digest
                    .as_ref()
                    .map(Sha256Digest::as_str)
                    != stored_previous.as_deref()
                || envelope.fact.recorded_at.as_str() != stored_created_at
            {
                return Err(StorageError::CorruptData(format!(
                    "Agent `{agent_id}` execution envelope disagrees with its lookup columns"
                )));
            }
            if envelope.fact.sequence == 1 {
                validate_origin_binding(
                    connection,
                    &durable_agent,
                    &envelope,
                    expected_origin,
                    i64_to_u64(origin_revision, "Agent execution origin revision")?,
                )?;
            }
            let (kind, revision, epoch, operation_kind, operation_id) =
                fact_lookup_columns(&envelope.fact.data)?;
            if kind != stored_kind
                || u64_to_i64(revision, "Agent execution revision")? != stored_revision
                || epoch.as_ref().map(Sha256Digest::as_str) != stored_epoch.as_deref()
                || operation_kind != stored_operation_kind.as_deref()
                || operation_id.as_deref() != stored_operation_id.as_deref()
            {
                return Err(StorageError::CorruptData(format!(
                    "Agent `{agent_id}` execution lookup columns are inconsistent"
                )));
            }
            validate_fact_replay(
                &agent_id,
                &envelope,
                &mut replay_state,
                &mut replay_revision,
            )?;
            validate_fact_epoch_binding(connection, &envelope)?;
            last_state = Some(match &envelope.fact.data {
                ExecutionFactData::AgentAdmitted { state, .. }
                | ExecutionFactData::LegacySnapshot { state, .. }
                | ExecutionFactData::WorkflowTransition { state, .. } => state.clone(),
            });
            payload_bytes = payload_bytes
                .checked_add(i64::try_from(envelope_json.len()).map_err(|_| {
                    StorageError::IntegerOutOfRange("Agent execution payload bytes")
                })?)
                .ok_or(StorageError::IntegerOutOfRange(
                    "Agent execution payload bytes",
                ))?;
            previous = Some(digest);
        }
        if previous.as_deref() != Some(head_hash.as_str()) || payload_bytes != committed_bytes {
            return Err(StorageError::CorruptData(format!(
                "Agent `{agent_id}` execution head does not match its fact tail"
            )));
        }
        if replay_revision != Some(i64_to_u64(projected_revision, "Agent execution revision")?) {
            return Err(StorageError::CorruptData(format!(
                "Agent `{agent_id}` replayed revision disagrees with its execution head"
            )));
        }
        let projected_state: WorkflowState = serde_json::from_str(&agent_state_json)?;
        if last_state.as_ref() != Some(&projected_state)
            || replay_state.as_ref() != Some(&projected_state)
        {
            return Err(StorageError::CorruptData(format!(
                "Agent `{agent_id}` execution fact tail disagrees with its workflow projection"
            )));
        }
    }

    validate_model_job_fact_reverse_bindings(connection)?;

    let mut epoch_statement = connection
        .prepare(r#"SELECT digest, envelope_json FROM agent_run_epochs ORDER BY digest"#)?;
    let epochs = epoch_statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(epoch_statement);
    for (digest, envelope_json) in epochs {
        let envelope = RunEpochEnvelope::from_json_slice(envelope_json.as_bytes())
            .map_err(stored_execution_error)?;
        if envelope.digest.as_str() != digest
            || envelope
                .canonical_json_bytes()
                .map_err(stored_execution_error)?
                != envelope_json.as_bytes()
        {
            return Err(StorageError::CorruptData(
                "Agent RunEpoch envelope disagrees with its digest column".into(),
            ));
        }
        let agent = super::agent::query_agent_turn(connection, &envelope.epoch.agent_id)?;
        validate_epoch_durable_binding(connection, &agent, &envelope)?;
    }
    let broken_epoch_binding: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM agent_run_epochs epoch
           JOIN agent_turns agent ON agent.id = epoch.agent_id
           LEFT JOIN agent_model_jobs model ON model.id = epoch.model_job_id
           LEFT JOIN agent_tool_calls tool ON tool.call_id = epoch.tool_call_id
           WHERE epoch.account_id <> agent.account_id
              OR epoch.session_id <> agent.session_id
              OR epoch.turn_id <> agent.turn_id
              OR epoch.actor_user_id <> agent.actor_user_id
              OR epoch.actor_membership_revision <> agent.actor_membership_revision
              OR epoch.bound_manifest_digest IS NOT agent.deployment_manifest_digest
              OR (epoch.operation_kind = 'model' AND (
                    model.id IS NULL OR model.agent_id <> epoch.agent_id
                    OR model.account_id <> epoch.account_id
                    OR model.session_id <> epoch.session_id
                    OR model.turn_id <> epoch.turn_id
                 ))
              OR (epoch.operation_kind = 'tool' AND (
                    tool.call_id IS NULL OR tool.agent_id <> epoch.agent_id
                    OR tool.account_id <> epoch.account_id
                    OR tool.session_id <> epoch.session_id
                    OR tool.turn_id <> epoch.turn_id
                 ))"#,
        [],
        |row| row.get(0),
    )?;
    if broken_epoch_binding != 0 {
        return Err(StorageError::CorruptData(
            "Agent RunEpoch binding disagrees with its durable operation".into(),
        ));
    }
    Ok(())
}

fn validate_model_job_fact_reverse_bindings(connection: &Connection) -> Result<(), StorageError> {
    let mut statement = connection.prepare(
        r#"SELECT job.id, job.agent_id, job.step, job.request_json, job.queued_at,
                  head.history_origin, origin.envelope_json
           FROM agent_model_jobs job
           JOIN agent_execution_heads head ON head.agent_id = job.agent_id
           JOIN agent_execution_events origin
             ON origin.agent_id = head.agent_id AND origin.sequence = 1
           WHERE job.step > 1
           ORDER BY job.agent_id, job.step"#,
    )?;
    let jobs = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);

    for (job_id, agent_id, step, request_json, queued_at, history_origin, origin_json) in jobs {
        let step = u32::try_from(i64_to_u64(step, "Agent model step")?)
            .map_err(|_| StorageError::IntegerOutOfRange("Agent model step"))?;
        if history_origin == "legacy_snapshot" {
            let origin = ExecutionFactEnvelope::from_json_slice(origin_json.as_bytes())
                .map_err(stored_execution_error)?;
            let ExecutionFactData::LegacySnapshot { state, .. } = &origin.fact.data else {
                return Err(StorageError::CorruptData(format!(
                    "Agent `{agent_id}` legacy execution head has a non-legacy origin fact"
                )));
            };
            let historical_started_or_settled = step <= state.model_steps();
            let historical_queued_continuation = state.status()
                == workflows::AgentStatus::ContinuationQueued
                && state.model_steps().checked_add(1) == Some(step);
            if historical_started_or_settled || historical_queued_continuation {
                continue;
            }
        }
        let request: Value = serde_json::from_str(&request_json)?;
        let request_digest = digest_json(DigestDomain::ModelRequest, &request)?;
        let mut statement = connection.prepare(
            r#"SELECT envelope_json FROM agent_execution_events
               WHERE agent_id = ?1 AND created_at = ?2
                 AND json_extract(
                     envelope_json, '$.fact.data.next_request_digest'
                 ) = ?3
               ORDER BY sequence"#,
        )?;
        let candidates = statement
            .query_map(
                params![agent_id, queued_at, request_digest.as_str()],
                |row| row.get::<_, String>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let mut bindings = 0_u32;
        for candidate in candidates {
            let envelope = ExecutionFactEnvelope::from_json_slice(candidate.as_bytes())
                .map_err(stored_execution_error)?;
            let ExecutionFactData::WorkflowTransition {
                command,
                state,
                next_request_digest: Some(digest),
                ..
            } = &envelope.fact.data
            else {
                continue;
            };
            let known_result = matches!(
                command,
                Command::ModelToolProposal {
                    disposition: workflows::ProposalDisposition::Deny { .. }
                } | Command::ApprovalRejected { .. }
                    | Command::ToolResultKnown { .. }
            );
            if known_result
                && state.status() == workflows::AgentStatus::ContinuationQueued
                && state.model_steps().checked_add(1) == Some(step)
                && digest == &request_digest
            {
                bindings = bindings
                    .checked_add(1)
                    .ok_or(StorageError::IntegerOutOfRange(
                        "Agent continuation fact bindings",
                    ))?;
            }
        }
        if bindings != 1 {
            return Err(StorageError::CorruptData(format!(
                "Agent model job `{job_id}` does not have exactly one continuation request fact"
            )));
        }
    }
    Ok(())
}

fn fact_envelope(
    agent_id: &str,
    sequence: u64,
    previous_fact_digest: Option<Sha256Digest>,
    timestamp: &str,
    data: ExecutionFactData,
) -> Result<ExecutionFactEnvelope, StorageError> {
    let recorded_at = RecordedAt::parse(timestamp).map_err(live_execution_error)?;
    let fact = ExecutionFact::new(agent_id, sequence, previous_fact_digest, recorded_at, data)
        .map_err(live_execution_error)?;
    ExecutionFactEnvelope::new(fact).map_err(live_execution_error)
}

fn insert_fact_row(
    connection: &Connection,
    envelope: &ExecutionFactEnvelope,
) -> Result<(), StorageError> {
    let (kind, agent_revision, epoch_digest, operation_kind, operation_id) =
        fact_lookup_columns(&envelope.fact.data)?;
    let json = envelope
        .canonical_json_bytes()
        .map_err(live_execution_error)?;
    let json = String::from_utf8(json).map_err(|error| {
        StorageError::CorruptData(format!("execution fact JSON is not UTF-8: {error}"))
    })?;
    connection.execute(
        r#"INSERT INTO agent_execution_events(
               agent_id, sequence, fact_digest, previous_fact_digest,
               fact_kind, payload_version, agent_revision, epoch_digest,
               operation_kind, operation_id, envelope_json, created_at
           ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, ?8, ?9, ?10, ?11)"#,
        params![
            envelope.fact.agent_id,
            u64_to_i64(envelope.fact.sequence, "Agent execution sequence")?,
            envelope.digest.as_str(),
            envelope
                .fact
                .previous_fact_digest
                .as_ref()
                .map(Sha256Digest::as_str),
            kind,
            u64_to_i64(agent_revision, "Agent execution revision")?,
            epoch_digest.as_ref().map(Sha256Digest::as_str),
            operation_kind,
            operation_id,
            json,
            envelope.fact.recorded_at.as_str(),
        ],
    )?;
    Ok(())
}

fn insert_epoch_row(
    connection: &Connection,
    envelope: &RunEpochEnvelope,
) -> Result<(), StorageError> {
    let epoch = &envelope.epoch;
    let (operation_kind, model_job_id, tool_call_id, input_digest) = match &epoch.operation {
        RunOperation::Model {
            job_id,
            request_digest,
            ..
        } => (
            "model",
            Some(job_id.as_str()),
            None,
            request_digest.as_str(),
        ),
        RunOperation::Tool {
            call_id,
            arguments_digest,
            ..
        } => (
            "tool",
            None,
            Some(call_id.as_str()),
            arguments_digest.as_str(),
        ),
    };
    let json = envelope
        .canonical_json_bytes()
        .map_err(live_execution_error)?;
    let json = String::from_utf8(json).map_err(|error| {
        StorageError::CorruptData(format!("RunEpoch JSON is not UTF-8: {error}"))
    })?;
    connection.execute(
        r#"INSERT INTO agent_run_epochs(
               digest, schema_version, agent_id, account_id, session_id, turn_id,
               workflow_revision, operation_kind, model_job_id, tool_call_id,
               bound_manifest_digest, observed_manifest_digest, deployment_check,
               actor_user_id, actor_membership_revision,
               approving_actor_user_id, approving_membership_revision,
               input_digest, envelope_json, created_at
           ) VALUES (
               ?1, 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
               ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19
           )"#,
        params![
            envelope.digest.as_str(),
            epoch.agent_id,
            epoch.account_id,
            epoch.session_id,
            epoch.turn_id,
            u64_to_i64(epoch.workflow_revision, "RunEpoch workflow revision")?,
            operation_kind,
            model_job_id,
            tool_call_id,
            epoch
                .bound_manifest_digest
                .as_ref()
                .map(Sha256Digest::as_str),
            epoch.observed_manifest_digest.as_str(),
            deployment_check_to_db(epoch.deployment_check),
            epoch.initiator.user_id,
            u64_to_i64(
                epoch.initiator.membership_revision,
                "RunEpoch actor revision"
            )?,
            epoch.approver.as_ref().map(|actor| actor.user_id.as_str()),
            epoch
                .approver
                .as_ref()
                .map(|actor| u64_to_i64(actor.membership_revision, "RunEpoch approver revision"))
                .transpose()?,
            input_digest,
            json,
            epoch.created_at.as_str(),
        ],
    )?;
    Ok(())
}

struct NewExecutionHead<'a> {
    agent_id: &'a str,
    projected_revision: u64,
    origin_revision: u64,
    history_origin: &'a str,
    history_complete: bool,
    envelope: &'a ExecutionFactEnvelope,
    timestamp: &'a str,
}

fn insert_head(connection: &Connection, head: NewExecutionHead<'_>) -> Result<(), StorageError> {
    let NewExecutionHead {
        agent_id,
        projected_revision,
        origin_revision,
        history_origin,
        history_complete,
        envelope,
        timestamp,
    } = head;
    let payload_bytes = i64::try_from(
        envelope
            .canonical_json_bytes()
            .map_err(live_execution_error)?
            .len(),
    )
    .map_err(|_| StorageError::IntegerOutOfRange("Agent execution payload bytes"))?;
    connection.execute(
        r#"INSERT INTO agent_execution_heads(
               agent_id, schema_version, head_sequence, projected_agent_revision,
               origin_revision, history_origin, history_complete, head_hash,
               committed_payload_bytes, created_at, updated_at
           ) VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)"#,
        params![
            agent_id,
            EXECUTION_LEDGER_SCHEMA_VERSION,
            u64_to_i64(projected_revision, "Agent execution revision")?,
            u64_to_i64(origin_revision, "Agent execution origin revision")?,
            history_origin,
            if history_complete { 1 } else { 0 },
            envelope.digest.as_str(),
            payload_bytes,
            timestamp,
        ],
    )?;
    Ok(())
}

fn advance_head(
    connection: &Connection,
    projected_revision: u64,
    envelope: &ExecutionFactEnvelope,
    timestamp: &str,
) -> Result<(), StorageError> {
    let payload_bytes = i64::try_from(
        envelope
            .canonical_json_bytes()
            .map_err(live_execution_error)?
            .len(),
    )
    .map_err(|_| StorageError::IntegerOutOfRange("Agent execution payload bytes"))?;
    let changed = connection.execute(
        r#"UPDATE agent_execution_heads
           SET head_sequence = head_sequence + 1,
               projected_agent_revision = ?1,
               head_hash = ?2,
               committed_payload_bytes = committed_payload_bytes + ?3,
               updated_at = ?4
           WHERE agent_id = ?5
             AND head_sequence = ?6
             AND head_hash = ?7
             AND projected_agent_revision + 1 = ?1"#,
        params![
            u64_to_i64(projected_revision, "Agent execution revision")?,
            envelope.digest.as_str(),
            payload_bytes,
            timestamp,
            envelope.fact.agent_id,
            u64_to_i64(
                envelope.fact.sequence - 1,
                "previous Agent execution sequence"
            )?,
            envelope
                .fact
                .previous_fact_digest
                .as_ref()
                .expect("a transition fact always has a predecessor")
                .as_str(),
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    Ok(())
}

fn execution_head(
    connection: &Connection,
    agent_id: &str,
) -> Result<(u64, Sha256Digest), StorageError> {
    let (sequence, digest): (i64, String) = connection
        .query_row(
            r#"SELECT head_sequence, head_hash FROM agent_execution_heads
               WHERE agent_id = ?1"#,
            [agent_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or_else(|| {
            StorageError::CorruptData(format!("Agent `{agent_id}` is missing its execution head"))
        })?;
    Ok((
        i64_to_u64(sequence, "Agent execution sequence")?,
        Sha256Digest::from_hex(digest).map_err(stored_execution_error)?,
    ))
}

type FactLookupColumns = (
    &'static str,
    u64,
    Option<Sha256Digest>,
    Option<&'static str>,
    Option<String>,
);

fn fact_lookup_columns(data: &ExecutionFactData) -> Result<FactLookupColumns, StorageError> {
    match data {
        ExecutionFactData::AgentAdmitted { .. } => Ok(("agent_admitted", 1, None, None, None)),
        ExecutionFactData::LegacySnapshot {
            origin_revision, ..
        } => Ok(("legacy_snapshot", *origin_revision, None, None, None)),
        ExecutionFactData::WorkflowTransition {
            to_revision,
            epoch_digest,
            subject,
            ..
        } => {
            let (kind, id) = match subject {
                Some(OperationRef::Model { job_id, .. }) => (Some("model"), Some(job_id.clone())),
                Some(OperationRef::Tool { call_id, .. }) => (Some("tool"), Some(call_id.clone())),
                None => (None, None),
            };
            Ok((
                "workflow_transition",
                *to_revision,
                epoch_digest.clone(),
                kind,
                id,
            ))
        }
    }
}

fn deployment_check_to_db(check: DeploymentCheck) -> &'static str {
    match check {
        DeploymentCheck::Matched => "matched",
    }
}

fn live_execution_error(error: execution::ExecutionError) -> StorageError {
    StorageError::InvalidAgentTransition(format!("invalid Agent execution fact: {error}"))
}

fn stored_execution_error(error: execution::ExecutionError) -> StorageError {
    StorageError::CorruptData(format!("invalid stored Agent execution fact: {error}"))
}
