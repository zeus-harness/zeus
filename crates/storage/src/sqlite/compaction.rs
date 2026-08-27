//! Durable, non-destructive Session context compaction.

use super::*;
use crate::{
    SessionCompactionClaimOutcome, SessionCompactionFailureCommit, SessionCompactionJob,
    SessionCompactionJobStatus, SessionCompactionSuccessCommit, SessionContextCheckpoint,
};
use llm::{
    COMPACTION_SOURCE_TURN_PAIRS, ReplyRequest, ReplyResponse, validate_compaction_response,
};

const COMPACTION_SOURCE_LOOKAHEAD_PAIRS: usize =
    llm::AGENT_REQUEST_MAX_HISTORY_PAIRS_WITH_CONTEXT + 1;
const COMPACTION_REQUEST_JSON_MAX_BYTES: usize = 512 * 1024;
const COMPACTION_RESPONSE_JSON_MAX_BYTES: usize = 512 * 1024;
const COMPACTION_ERROR_JSON_MAX_BYTES: usize = 32 * 1024;
const COMPACTION_SOURCE_DIGEST_DOMAIN: &[u8] = b"zeus.session-compaction-source.sha256.v1\0";
const COMPACTION_SUMMARY_DIGEST_DOMAIN: &[u8] = b"zeus.session-compaction-summary.sha256.v1\0";

struct SourceTurn {
    turn: SessionTurn,
    user_sequence: u64,
    flush_sequence: u64,
}

struct EnqueueSpec<'a> {
    account_id: &'a AccountId,
    actor_user_id: &'a str,
    actor_membership_revision: MembershipRevision,
    session_id: &'a str,
    provider_name: &'a str,
    model_name: &'a str,
    queued_at: &'a str,
}

pub(super) fn maybe_enqueue_after_agent_final(
    connection: &Connection,
    agent: &AgentTurn,
    job: &AgentModelJob,
    provenance: &AssistantReplyProvenance,
) -> Result<Option<SessionCompactionJob>, StorageError> {
    if provenance.reply_kind != protocol::AssistantReplyKind::Model {
        return Ok(None);
    }
    let Some(model_name) = job.model_name.as_deref() else {
        return Ok(None);
    };
    maybe_enqueue(
        connection,
        EnqueueSpec {
            account_id: &agent.account_id,
            actor_user_id: &agent.actor_user_id,
            actor_membership_revision: agent.actor_membership_revision,
            session_id: &agent.session_id,
            provider_name: &job.provider_name,
            model_name,
            queued_at: &now(),
        },
    )
}

fn maybe_enqueue(
    connection: &Connection,
    spec: EnqueueSpec<'_>,
) -> Result<Option<SessionCompactionJob>, StorageError> {
    let active: i64 = connection.query_row(
        r#"SELECT COUNT(*) FROM session_compaction_jobs
           WHERE session_id = ?1 AND status IN ('queued', 'started')"#,
        [spec.session_id],
        |row| row.get(0),
    )?;
    if active != 0 {
        return Ok(None);
    }
    let latest_status = connection
        .query_row(
            r#"SELECT status FROM session_compaction_jobs
               WHERE session_id = ?1 ORDER BY generation DESC LIMIT 1"#,
            [spec.session_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|status| status_from_db(&status))
        .transpose()?;
    // There is no implicit retry authority for background model work. A known
    // failure needs an explicit future repair path; an indeterminate call must
    // never be replayed under a fresh job ID because it may already be billed.
    if matches!(
        latest_status,
        Some(SessionCompactionJobStatus::Failed | SessionCompactionJobStatus::OutcomeUnknown)
    ) {
        return Ok(None);
    }
    let previous = latest_checkpoint(connection, spec.session_id, i64::MAX as u64)?;
    let after_sequence = previous
        .as_ref()
        .map_or(0, |checkpoint| checkpoint.source_end_sequence);
    let available = query_oldest_source_turns(
        connection,
        spec.session_id,
        after_sequence,
        COMPACTION_SOURCE_LOOKAHEAD_PAIRS,
    )?;
    if available.len() < COMPACTION_SOURCE_LOOKAHEAD_PAIRS {
        return Ok(None);
    }
    let previous_summary = previous
        .as_ref()
        .map(|checkpoint| checkpoint.summary_text.as_str());
    let candidates = &available[..COMPACTION_SOURCE_TURN_PAIRS];
    let (selected_len, request) = largest_fitting_source_request(previous_summary, candidates)?;
    let selected = &candidates[..selected_len];
    let request_json = serde_json::to_value(&request)?;
    require_bounded_json(
        &request_json,
        COMPACTION_REQUEST_JSON_MAX_BYTES,
        "Session compaction request",
    )?;
    let source_content_bytes = source_content_bytes(previous_summary, selected)?;
    let source_digest = source_digest(previous.as_ref(), selected)?;
    let generation: i64 = connection.query_row(
        r#"SELECT COALESCE(MAX(generation), 0) + 1
           FROM session_compaction_jobs WHERE session_id = ?1"#,
        [spec.session_id],
        |row| row.get(0),
    )?;
    let id = deterministic_job_id(spec.session_id, generation, &source_digest);
    connection.execute(
        r#"INSERT INTO session_compaction_jobs(
               id, account_id, actor_user_id, actor_membership_revision,
               session_id, generation, previous_job_id, provider_name, model_name,
               status, attempt, source_start_sequence, source_end_sequence,
               source_digest, source_content_bytes, request_json, response_json,
               summary_text, summary_digest, summary_bytes, error_json,
               queued_at, started_at, finished_at
           ) VALUES (
               ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
               'queued', 0, ?10, ?11, ?12, ?13, ?14,
               NULL, NULL, NULL, NULL, NULL, ?15, NULL, NULL
           )"#,
        params![
            id,
            spec.account_id.as_str(),
            spec.actor_user_id,
            u64_to_i64(
                spec.actor_membership_revision.get(),
                "compaction actor membership revision"
            )?,
            spec.session_id,
            generation,
            previous
                .as_ref()
                .map(|checkpoint| checkpoint.job_id.as_str()),
            spec.provider_name,
            spec.model_name,
            u64_to_i64(selected[0].user_sequence, "compaction source start")?,
            u64_to_i64(
                selected
                    .last()
                    .expect("fixed non-empty batch")
                    .flush_sequence,
                "compaction source end"
            )?,
            source_digest,
            i64::try_from(source_content_bytes)
                .map_err(|_| StorageError::IntegerOutOfRange("compaction source bytes"))?,
            serde_json::to_string(&request_json)?,
            spec.queued_at,
        ],
    )?;
    query_job(connection, &id).map(Some)
}

pub(super) fn peek_next(
    connection: &Connection,
) -> Result<Option<SessionCompactionJob>, StorageError> {
    let id = connection
        .query_row(
            r#"SELECT id FROM session_compaction_jobs
               WHERE status = 'queued' ORDER BY queued_at, id LIMIT 1"#,
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    id.map(|id| query_job(connection, &id)).transpose()
}

pub(super) fn start_observed(
    connection: &mut Connection,
    job_id: &str,
) -> Result<SessionCompactionClaimOutcome, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let job = query_job(&transaction, job_id)?;
    if job.status == SessionCompactionJobStatus::Started {
        transaction.commit()?;
        return Ok(SessionCompactionClaimOutcome::Claimed(Box::new(job)));
    }
    if job.status != SessionCompactionJobStatus::Queued {
        transaction.commit()?;
        return Ok(SessionCompactionClaimOutcome::NotAvailable);
    }
    let Some(head) = peek_next(&transaction)? else {
        transaction.commit()?;
        return Ok(SessionCompactionClaimOutcome::NotAvailable);
    };
    if head.id != job.id {
        transaction.commit()?;
        return Ok(SessionCompactionClaimOutcome::NotAvailable);
    }
    if !compaction_actor_is_authorized(&transaction, &job)? {
        let timestamp = now();
        let changed = transaction.execute(
            r#"UPDATE session_compaction_jobs
               SET status = 'started', attempt = 1, started_at = ?1
               WHERE id = ?2 AND status = 'queued' AND attempt = 0"#,
            params![timestamp, job.id],
        )?;
        if changed != 1 {
            return Err(StorageError::ConcurrentModification);
        }
        let error_json = json!({
            "code": "authorization_revoked",
            "message": "the compaction initiator is no longer authorized for this Session"
        });
        transaction.execute(
            r#"UPDATE session_compaction_jobs
               SET status = 'failed', error_json = ?1, finished_at = ?2
               WHERE id = ?3 AND status = 'started' AND attempt = 1"#,
            params![serde_json::to_string(&error_json)?, timestamp, job.id],
        )?;
        transaction.commit()?;
        return Ok(SessionCompactionClaimOutcome::NotAvailable);
    }
    require_exact_source(&transaction, &job)?;
    let changed = transaction.execute(
        r#"UPDATE session_compaction_jobs
           SET status = 'started', attempt = 1, started_at = ?1
           WHERE id = ?2 AND status = 'queued' AND attempt = 0"#,
        params![now(), job.id],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    let started = query_job(&transaction, &job.id)?;
    transaction.commit()?;
    Ok(SessionCompactionClaimOutcome::Claimed(Box::new(started)))
}

pub(super) fn complete_success(
    connection: &mut Connection,
    commit: SessionCompactionSuccessCommit,
) -> Result<SessionCompactionJob, StorageError> {
    require_bounded_json(
        &commit.response_json,
        COMPACTION_RESPONSE_JSON_MAX_BYTES,
        "Session compaction response",
    )?;
    let response = serde_json::from_value::<ReplyResponse>(commit.response_json.clone())
        .map_err(|_| StorageError::InvalidAgentTransition("invalid compaction response".into()))?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let job = query_job(&transaction, &commit.job_id)?;
    if job.status == SessionCompactionJobStatus::Succeeded {
        if job.response_json.as_ref() == Some(&commit.response_json)
            && job.summary_text.as_deref() == Some(commit.summary_text.as_str())
        {
            transaction.commit()?;
            return Ok(job);
        }
        return Err(StorageError::InvalidAgentTransition(
            "conflicting Session compaction success replay".into(),
        ));
    }
    if job.status != SessionCompactionJobStatus::Started
        || response.provider.provider_id != job.provider_name
        || response.provider.model.as_deref() != Some(job.model_name.as_str())
    {
        return Err(StorageError::InvalidAgentTransition(
            "Session compaction completion does not match its started provider work".into(),
        ));
    }
    let source_bytes = usize::try_from(job.source_content_bytes)
        .map_err(|_| StorageError::IntegerOutOfRange("compaction source bytes"))?;
    let summary = validate_compaction_response(&response, source_bytes)
        .map_err(|_| StorageError::InvalidAgentTransition("invalid compaction summary".into()))?;
    if summary != commit.summary_text {
        return Err(StorageError::InvalidAgentTransition(
            "compaction summary differs from the persisted provider response".into(),
        ));
    }
    require_exact_source(&transaction, &job)?;
    let summary_digest = digest_text(COMPACTION_SUMMARY_DIGEST_DOMAIN, summary);
    let changed = transaction.execute(
        r#"UPDATE session_compaction_jobs
           SET status = 'succeeded', response_json = ?1, summary_text = ?2,
               summary_digest = ?3, summary_bytes = ?4, finished_at = ?5
           WHERE id = ?6 AND status = 'started' AND attempt = 1"#,
        params![
            serde_json::to_string(&commit.response_json)?,
            summary,
            summary_digest,
            i64::try_from(summary.len())
                .map_err(|_| StorageError::IntegerOutOfRange("compaction summary bytes"))?,
            now(),
            job.id,
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    let completed = query_job(&transaction, &job.id)?;
    let _ = maybe_enqueue(
        &transaction,
        EnqueueSpec {
            account_id: &completed.account_id,
            actor_user_id: &completed.actor_user_id,
            actor_membership_revision: completed.actor_membership_revision,
            session_id: &completed.session_id,
            provider_name: &completed.provider_name,
            model_name: &completed.model_name,
            queued_at: &now(),
        },
    )?;
    transaction.commit()?;
    Ok(completed)
}

pub(super) fn complete_failure(
    connection: &mut Connection,
    commit: SessionCompactionFailureCommit,
) -> Result<SessionCompactionJob, StorageError> {
    require_bounded_json(
        &commit.error_json,
        COMPACTION_ERROR_JSON_MAX_BYTES,
        "Session compaction error",
    )?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let job = query_job(&transaction, &commit.job_id)?;
    let wanted = if commit.outcome_unknown {
        SessionCompactionJobStatus::OutcomeUnknown
    } else {
        SessionCompactionJobStatus::Failed
    };
    if job.status == wanted && job.error_json.as_ref() == Some(&commit.error_json) {
        transaction.commit()?;
        return Ok(job);
    }
    if job.status != SessionCompactionJobStatus::Started {
        return Err(StorageError::InvalidAgentTransition(
            "Session compaction failure does not match a started job".into(),
        ));
    }
    let status = if commit.outcome_unknown {
        "outcome_unknown"
    } else {
        "failed"
    };
    let changed = transaction.execute(
        r#"UPDATE session_compaction_jobs
           SET status = ?1, error_json = ?2, finished_at = ?3
           WHERE id = ?4 AND status = 'started' AND attempt = 1"#,
        params![
            status,
            serde_json::to_string(&commit.error_json)?,
            now(),
            job.id,
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    let terminal = query_job(&transaction, &job.id)?;
    transaction.commit()?;
    Ok(terminal)
}

pub(super) fn recover_started(
    connection: &mut Connection,
) -> Result<Vec<SessionCompactionJob>, StorageError> {
    let ids = {
        let mut statement = connection.prepare(
            r#"SELECT id FROM session_compaction_jobs
               WHERE status = 'started' ORDER BY started_at, id LIMIT ?1"#,
        )?;
        statement
            .query_map([RECOVERY_BATCH_LIMIT], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };
    let mut recovered = Vec::with_capacity(ids.len());
    for id in ids {
        recovered.push(complete_failure(
            connection,
            SessionCompactionFailureCommit {
                job_id: id,
                error_json: json!({
                    "code": "process_restarted",
                    "message": "process restarted after Session compaction was durably started"
                }),
                outcome_unknown: true,
            },
        )?);
    }
    Ok(recovered)
}

pub(super) fn checkpoint_for_actor(
    connection: &mut Connection,
    context: &AuthzContext,
    session_id: &str,
    through_sequence: u64,
) -> Result<Option<SessionContextCheckpoint>, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    require_active_session_actor(&transaction, session_id, context)?;
    let session = query_session_summary(&transaction, session_id)?;
    if through_sequence > session.sequence {
        return Err(StorageError::ConcurrentModification);
    }
    let checkpoint = latest_checkpoint(&transaction, session_id, through_sequence)?;
    transaction.commit()?;
    Ok(checkpoint)
}

pub(super) fn latest_checkpoint(
    connection: &Connection,
    session_id: &str,
    through_sequence: u64,
) -> Result<Option<SessionContextCheckpoint>, StorageError> {
    let through_sequence = u64_to_i64(through_sequence, "compaction checkpoint boundary")?;
    let row = connection
        .query_row(
            r#"SELECT id, generation, source_end_sequence, source_digest,
                      summary_text, summary_digest
               FROM session_compaction_jobs
               WHERE session_id = ?1 AND status = 'succeeded'
                 AND source_end_sequence <= ?2
               ORDER BY generation DESC LIMIT 1"#,
            params![session_id, through_sequence],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(job_id, generation, source_end_sequence, source_digest, summary_text, summary_digest)| {
            if digest_text(COMPACTION_SUMMARY_DIGEST_DOMAIN, &summary_text) != summary_digest {
                return Err(StorageError::CorruptData(format!(
                    "Session compaction `{job_id}` summary digest is invalid"
                )));
            }
            Ok(SessionContextCheckpoint {
                job_id,
                generation: i64_to_u64(generation, "compaction generation")?,
                source_end_sequence: i64_to_u64(source_end_sequence, "compaction source end")?,
                source_digest,
                summary_text,
                summary_digest,
            })
        },
    )
    .transpose()
}

pub(super) fn checkpoints_matching_message(
    connection: &Connection,
    session_id: &str,
    through_sequence: u64,
    framed_content: &str,
) -> Result<Vec<SessionContextCheckpoint>, StorageError> {
    let through_sequence = u64_to_i64(through_sequence, "compaction checkpoint boundary")?;
    let mut statement = connection.prepare(
        r#"SELECT id FROM session_compaction_jobs
           WHERE session_id = ?1 AND status = 'succeeded'
             AND source_end_sequence <= ?2
           ORDER BY generation DESC"#,
    )?;
    let ids = statement
        .query_map(params![session_id, through_sequence], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut matches = Vec::new();
    for id in ids {
        let checkpoint = query_checkpoint_by_id(connection, &id)?;
        if llm::ReplyMessage::compacted_summary(&checkpoint.summary_text).content == framed_content
        {
            matches.push(checkpoint);
        }
    }
    Ok(matches)
}

pub(super) fn verify_integrity(connection: &Connection) -> Result<(), StorageError> {
    let ids = {
        let mut statement = connection
            .prepare("SELECT id FROM session_compaction_jobs ORDER BY session_id, generation")?;
        statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };
    for id in ids {
        let job = query_job(connection, &id)?;
        require_exact_source(connection, &job)?;
        if job.status == SessionCompactionJobStatus::Succeeded {
            let summary = job.summary_text.as_deref().ok_or_else(|| {
                StorageError::CorruptData(format!("Session compaction `{id}` has no summary"))
            })?;
            let expected_summary_digest = digest_text(COMPACTION_SUMMARY_DIGEST_DOMAIN, summary);
            if job.summary_digest.as_deref() != Some(expected_summary_digest.as_str()) {
                return Err(StorageError::CorruptData(format!(
                    "Session compaction `{id}` summary digest is invalid"
                )));
            }
            let response = serde_json::from_value::<ReplyResponse>(
                job.response_json.clone().ok_or_else(|| {
                    StorageError::CorruptData(format!(
                        "Session compaction `{id}` has no provider response"
                    ))
                })?,
            )
            .map_err(|_| {
                StorageError::CorruptData(format!(
                    "Session compaction `{id}` provider response is invalid"
                ))
            })?;
            if response.provider.provider_id != job.provider_name
                || response.provider.model.as_deref() != Some(job.model_name.as_str())
                || validate_compaction_response(
                    &response,
                    usize::try_from(job.source_content_bytes)
                        .map_err(|_| StorageError::IntegerOutOfRange("compaction source bytes"))?,
                )
                .ok()
                    != Some(summary)
            {
                return Err(StorageError::CorruptData(format!(
                    "Session compaction `{id}` completion binding is invalid"
                )));
            }
        }
    }
    Ok(())
}

fn require_exact_source(
    connection: &Connection,
    job: &SessionCompactionJob,
) -> Result<(), StorageError> {
    let previous = job
        .previous_job_id
        .as_deref()
        .map(|id| query_checkpoint_by_id(connection, id))
        .transpose()?;
    let mut sources = query_oldest_source_turns(
        connection,
        &job.session_id,
        previous
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.source_end_sequence),
        COMPACTION_SOURCE_TURN_PAIRS,
    )?;
    let Some(source_end_index) = sources
        .iter()
        .position(|source| source.flush_sequence == job.source_end_sequence)
    else {
        return Err(StorageError::CorruptData(format!(
            "Session compaction `{}` source boundary changed",
            job.id
        )));
    };
    sources.truncate(source_end_index + 1);
    if sources.is_empty()
        || sources[0].user_sequence != job.source_start_sequence
        || source_digest(previous.as_ref(), &sources)? != job.source_digest
    {
        return Err(StorageError::CorruptData(format!(
            "Session compaction `{}` source boundary changed",
            job.id
        )));
    }
    let turns = sources
        .iter()
        .map(|source| source.turn.clone())
        .collect::<Vec<_>>();
    let expected = ReplyRequest::for_compaction(
        previous
            .as_ref()
            .map(|checkpoint| checkpoint.summary_text.as_str()),
        &turns,
    )
    .map_err(|error| StorageError::CorruptData(format!("invalid compaction source: {error}")))?;
    if serde_json::to_value(expected)? != job.request_json {
        return Err(StorageError::CorruptData(format!(
            "Session compaction `{}` request differs from its source",
            job.id
        )));
    }
    let expected_source_bytes = source_content_bytes(
        previous
            .as_ref()
            .map(|checkpoint| checkpoint.summary_text.as_str()),
        &sources,
    )?;
    if u64::try_from(expected_source_bytes)
        .map_err(|_| StorageError::IntegerOutOfRange("compaction source bytes"))?
        != job.source_content_bytes
    {
        return Err(StorageError::CorruptData(format!(
            "Session compaction `{}` source byte count changed",
            job.id
        )));
    }
    Ok(())
}

fn largest_fitting_source_request(
    previous_summary: Option<&str>,
    candidates: &[SourceTurn],
) -> Result<(usize, ReplyRequest), StorageError> {
    for source in candidates {
        if source.turn.status != SessionTurnStatus::Flushed
            || protocol::validate_user_message(&source.turn.user_message).is_err()
            || source
                .turn
                .assistant_message
                .as_deref()
                .is_none_or(|message| protocol::validate_assistant_message(message).is_err())
        {
            return Err(StorageError::CorruptData(
                "invalid complete turn in Session compaction source".into(),
            ));
        }
    }
    for selected_len in (1..=candidates.len().min(COMPACTION_SOURCE_TURN_PAIRS)).rev() {
        let turns = candidates[..selected_len]
            .iter()
            .map(|source| source.turn.clone())
            .collect::<Vec<_>>();
        if let Ok(request) = ReplyRequest::for_compaction(previous_summary, &turns) {
            return Ok((selected_len, request));
        }
    }
    Err(StorageError::CorruptData(
        "no complete Session turn fits the compaction request envelope".into(),
    ))
}

fn source_content_bytes(
    previous_summary: Option<&str>,
    sources: &[SourceTurn],
) -> Result<usize, StorageError> {
    sources
        .iter()
        .try_fold(previous_summary.map_or(0, str::len), |total, source| {
            total
                .checked_add(source.turn.user_message.len())
                .and_then(|total| {
                    total.checked_add(
                        source
                            .turn
                            .assistant_message
                            .as_ref()
                            .map_or(0, String::len),
                    )
                })
                .ok_or(StorageError::IntegerOutOfRange(
                    "compaction source content bytes",
                ))
        })
}

fn compaction_actor_is_authorized(
    connection: &Connection,
    job: &SessionCompactionJob,
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
                 AND membership.user_id = ?3 AND membership.revision = ?4
                 AND membership.status = 'active'
                 AND account.status = 'active' AND user.status = 'active'"#,
            params![
                job.session_id,
                job.account_id.as_str(),
                job.actor_user_id,
                u64_to_i64(
                    job.actor_membership_revision.get(),
                    "compaction actor membership revision"
                )?,
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    role.map(|role| decode_membership_role(&role))
        .transpose()
        .map(|role| role.is_some_and(|role| membership_allows(role, AccountCapability::Reply)))
}

fn query_oldest_source_turns(
    connection: &Connection,
    session_id: &str,
    after_sequence: u64,
    limit: usize,
) -> Result<Vec<SourceTurn>, StorageError> {
    let mut statement = connection.prepare(
        r#"SELECT turn.id, turn.session_id, turn.ordinal, turn.status,
                  turn.user_message, turn.assistant_message,
                  turn.started_at, turn.completed_at,
                  user.sequence, flushed.sequence
           FROM session_events user
           JOIN session_events assistant
             ON assistant.session_id = user.session_id
            AND assistant.turn_id = user.turn_id
            AND assistant.event_kind = 'assistant_message'
           JOIN session_events flushed
             ON flushed.session_id = assistant.session_id
            AND flushed.turn_id = assistant.turn_id
            AND flushed.sequence = assistant.sequence + 1
            AND flushed.event_kind = 'turn_flushed'
           JOIN session_turns turn
             ON turn.session_id = user.session_id AND turn.id = user.turn_id
           WHERE user.session_id = ?1
             AND user.event_kind = 'user_message'
             AND user.sequence > ?2
             AND turn.status = 'flushed'
             AND turn.assistant_message IS NOT NULL
           ORDER BY user.sequence
           LIMIT ?3"#,
    )?;
    let rows = statement
        .query_map(
            params![
                session_id,
                u64_to_i64(after_sequence, "compaction prior boundary")?,
                capacity_limit(limit)?
            ],
            |row| {
                Ok((
                    StoredSessionTurnRow {
                        id: row.get(0)?,
                        session_id: row.get(1)?,
                        ordinal: row.get(2)?,
                        status: row.get(3)?,
                        user_message: row.get(4)?,
                        assistant_message: row.get(5)?,
                        started_at: row.get(6)?,
                        completed_at: row.get(7)?,
                    },
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(stored, user_sequence, flush_sequence)| {
            Ok(SourceTurn {
                turn: stored.decode()?,
                user_sequence: i64_to_u64(user_sequence, "compaction source user sequence")?,
                flush_sequence: i64_to_u64(flush_sequence, "compaction source flush sequence")?,
            })
        })
        .collect()
}

fn source_digest(
    previous: Option<&SessionContextCheckpoint>,
    sources: &[SourceTurn],
) -> Result<String, StorageError> {
    let mut digest = Sha256::new();
    digest.update(COMPACTION_SOURCE_DIGEST_DOMAIN);
    if let Some(previous) = previous {
        update_digest(&mut digest, previous.job_id.as_bytes());
        update_digest(&mut digest, previous.summary_digest.as_bytes());
        update_digest(&mut digest, previous.summary_text.as_bytes());
    } else {
        update_digest(&mut digest, &[]);
    }
    for source in sources {
        update_digest(&mut digest, &source.user_sequence.to_le_bytes());
        update_digest(&mut digest, &source.flush_sequence.to_le_bytes());
        update_digest(&mut digest, source.turn.id.as_bytes());
        update_digest(&mut digest, source.turn.user_message.as_bytes());
        update_digest(
            &mut digest,
            source
                .turn
                .assistant_message
                .as_deref()
                .ok_or_else(|| StorageError::CorruptData("compaction source is incomplete".into()))?
                .as_bytes(),
        );
    }
    Ok(hex_digest(digest.finalize()))
}

fn deterministic_job_id(session_id: &str, generation: i64, source_digest: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"zeus.session-compaction-job-id.v1\0");
    update_digest(&mut digest, session_id.as_bytes());
    update_digest(&mut digest, &generation.to_le_bytes());
    update_digest(&mut digest, source_digest.as_bytes());
    format!("cmp-{}", hex_digest(digest.finalize()))
}

fn query_checkpoint_by_id(
    connection: &Connection,
    id: &str,
) -> Result<SessionContextCheckpoint, StorageError> {
    let job = query_job(connection, id)?;
    if job.status != SessionCompactionJobStatus::Succeeded {
        return Err(StorageError::CorruptData(format!(
            "Session compaction `{id}` references a non-succeeded checkpoint"
        )));
    }
    let summary_text = job.summary_text.ok_or_else(|| {
        StorageError::CorruptData(format!("Session compaction `{id}` has no summary"))
    })?;
    let summary_digest = job.summary_digest.ok_or_else(|| {
        StorageError::CorruptData(format!("Session compaction `{id}` has no summary digest"))
    })?;
    Ok(SessionContextCheckpoint {
        job_id: job.id,
        generation: job.generation,
        source_end_sequence: job.source_end_sequence,
        source_digest: job.source_digest,
        summary_text,
        summary_digest,
    })
}

fn query_job(connection: &Connection, id: &str) -> Result<SessionCompactionJob, StorageError> {
    connection
        .query_row(
            r#"SELECT id, account_id, actor_user_id, actor_membership_revision,
                      session_id, generation, previous_job_id, provider_name, model_name,
                      status, attempt, source_start_sequence, source_end_sequence,
                      source_digest, source_content_bytes, request_json, response_json,
                      summary_text, summary_digest, error_json,
                      queued_at, started_at, finished_at
               FROM session_compaction_jobs WHERE id = ?1"#,
            [id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, i64>(14)?,
                    row.get::<_, String>(15)?,
                    row.get::<_, Option<String>>(16)?,
                    row.get::<_, Option<String>>(17)?,
                    row.get::<_, Option<String>>(18)?,
                    row.get::<_, Option<String>>(19)?,
                    row.get::<_, String>(20)?,
                    row.get::<_, Option<String>>(21)?,
                    row.get::<_, Option<String>>(22)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| StorageError::CorruptData(format!("Session compaction `{id}` not found")))
        .and_then(
            |(
                id,
                account_id,
                actor_user_id,
                actor_membership_revision,
                session_id,
                generation,
                previous_job_id,
                provider_name,
                model_name,
                status,
                attempt,
                source_start_sequence,
                source_end_sequence,
                source_digest,
                source_content_bytes,
                request_json,
                response_json,
                summary_text,
                summary_digest,
                error_json,
                queued_at,
                started_at,
                finished_at,
            )| {
                Ok(SessionCompactionJob {
                    id,
                    account_id: AccountId::from_persistence(account_id)
                        .map_err(|error| StorageError::InvalidAccountData(error.to_string()))?,
                    actor_user_id,
                    actor_membership_revision: MembershipRevision::new(i64_to_u64(
                        actor_membership_revision,
                        "compaction actor membership revision",
                    )?)
                    .map_err(|error| StorageError::InvalidAccountData(error.to_string()))?,
                    session_id,
                    generation: i64_to_u64(generation, "compaction generation")?,
                    previous_job_id,
                    provider_name,
                    model_name,
                    status: status_from_db(&status)?,
                    attempt: u32::try_from(attempt)
                        .map_err(|_| StorageError::IntegerOutOfRange("compaction attempt"))?,
                    source_start_sequence: i64_to_u64(
                        source_start_sequence,
                        "compaction source start",
                    )?,
                    source_end_sequence: i64_to_u64(source_end_sequence, "compaction source end")?,
                    source_digest,
                    source_content_bytes: i64_to_u64(
                        source_content_bytes,
                        "compaction source bytes",
                    )?,
                    request_json: serde_json::from_str(&request_json)?,
                    response_json: response_json
                        .map(|value| serde_json::from_str(&value))
                        .transpose()?,
                    summary_text,
                    summary_digest,
                    error_json: error_json
                        .map(|value| serde_json::from_str(&value))
                        .transpose()?,
                    queued_at,
                    started_at,
                    finished_at,
                })
            },
        )
}

fn status_from_db(value: &str) -> Result<SessionCompactionJobStatus, StorageError> {
    match value {
        "queued" => Ok(SessionCompactionJobStatus::Queued),
        "started" => Ok(SessionCompactionJobStatus::Started),
        "succeeded" => Ok(SessionCompactionJobStatus::Succeeded),
        "failed" => Ok(SessionCompactionJobStatus::Failed),
        "outcome_unknown" => Ok(SessionCompactionJobStatus::OutcomeUnknown),
        other => Err(StorageError::CorruptData(format!(
            "unsupported Session compaction status `{other}`"
        ))),
    }
}

fn require_bounded_json(value: &Value, max_bytes: usize, field: &str) -> Result<(), StorageError> {
    if !value.is_object() || serde_json::to_vec(value)?.len() > max_bytes {
        return Err(StorageError::InvalidResourceEnvelope(format!(
            "{field} must be an object of at most {max_bytes} serialized bytes"
        )));
    }
    Ok(())
}

fn digest_text(domain: &[u8], text: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    update_digest(&mut digest, text.as_bytes());
    hex_digest(digest.finalize())
}

fn update_digest(digest: &mut Sha256, value: &[u8]) {
    digest.update(
        u64::try_from(value.len())
            .expect("bounded compaction digest input fits in u64")
            .to_le_bytes(),
    );
    digest.update(value);
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(64);
    for byte in bytes.as_ref() {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_turn(ordinal: u64, bytes_per_message: usize) -> SourceTurn {
        SourceTurn {
            turn: SessionTurn {
                id: format!("turn-{ordinal}"),
                session_id: "session-compaction-envelope".into(),
                ordinal,
                status: SessionTurnStatus::Flushed,
                user_message: "u".repeat(bytes_per_message),
                assistant_message: Some("a".repeat(bytes_per_message)),
                started_at: "2026-08-28T00:00:00.000Z".into(),
                completed_at: Some("2026-08-28T00:00:01.000Z".into()),
            },
            user_sequence: ordinal * 3 + 2,
            flush_sequence: ordinal * 3 + 4,
        }
    }

    #[test]
    fn largest_fitting_source_prefix_never_splits_a_legal_turn() {
        let mut sources = (0..3)
            .map(|ordinal| source_turn(ordinal, 60 * 1024))
            .collect::<Vec<_>>();
        sources.extend(
            (3..COMPACTION_SOURCE_TURN_PAIRS as u64).map(|ordinal| source_turn(ordinal, 16)),
        );

        let (selected_len, request) = largest_fitting_source_request(None, &sources).unwrap();

        assert_eq!(selected_len, 2);
        assert_eq!(request.messages.len(), 6);
        assert_eq!(request.messages[1].content.len(), 60 * 1024);
        assert_eq!(request.messages[4].content.len(), 60 * 1024);
    }
}
