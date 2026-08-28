-- A running model is side-effect free from Zeus' perspective and may be
-- terminalized by an authenticated user cancellation. The exact RunEpoch and
-- execution fact remain mandatory. Started tools keep their stricter outcome
-- boundary in the separate tool transition trigger.

DROP TRIGGER agent_model_jobs_enforce_forward_transition;

CREATE TRIGGER agent_model_jobs_enforce_forward_transition
BEFORE UPDATE ON agent_model_jobs
WHEN NOT (
        (OLD.status = 'queued' AND NEW.status = 'started'
         AND NEW.attempt = 1
         AND EXISTS (
             SELECT 1 FROM agent_turns agent
             WHERE agent.id = OLD.agent_id
               AND agent.status = 'model_running'
               AND agent.model_steps = OLD.step
         )
         AND EXISTS (
             SELECT 1
             FROM agent_run_epochs epoch
             JOIN agent_execution_events event
               ON event.agent_id = epoch.agent_id
              AND event.epoch_digest = epoch.digest
             JOIN agent_execution_heads head
               ON head.agent_id = event.agent_id
              AND head.head_sequence = event.sequence
              AND head.head_hash = event.fact_digest
             WHERE epoch.model_job_id = OLD.id
               AND epoch.operation_kind = 'model'
               AND epoch.workflow_revision = event.agent_revision
               AND json_extract(
                   event.envelope_json, '$.fact.data.command.command'
               ) = 'start_model'
         ))
        OR
        (OLD.status = 'queued' AND NEW.status = 'failed'
         AND NEW.attempt = 1
         AND NOT EXISTS (
             SELECT 1 FROM agent_run_epochs epoch
             WHERE epoch.model_job_id = OLD.id
         )
         AND EXISTS (
             SELECT 1 FROM agent_turns agent
             WHERE agent.id = OLD.agent_id
               AND agent.status = 'failed'
               AND agent.model_steps + 1 = OLD.step
               AND json_extract(
                   agent.workflow_state_json, '$.terminal_reason'
               ) = 'authorization_revoked'
         ))
        OR
        (OLD.status = 'started'
         AND NEW.status IN ('succeeded', 'failed', 'outcome_unknown')
         AND NEW.attempt = 1
         AND EXISTS (
             SELECT 1 FROM agent_turns agent
             WHERE agent.id = OLD.agent_id
               AND agent.model_steps = OLD.step
               AND (
                   (NEW.status = 'succeeded' AND (
                       agent.status IN (
                           'waiting_approval', 'tool_queued', 'waiting_model', 'succeeded'
                       )
                       OR (
                           agent.status = 'failed'
                           AND json_extract(
                               agent.workflow_state_json, '$.terminal_reason'
                           ) IN (
                               'tool_call_limit_reached',
                               'pending_approval_limit_reached',
                               'tool_result_bytes_limit_reached',
                               'model_step_limit_reached',
                               'continuation_unavailable'
                           )
                       )
                   ))
                   OR (NEW.status = 'failed' AND agent.status = 'failed')
                   OR (NEW.status = 'outcome_unknown' AND agent.status = 'needs_attention')
               )
         )
         AND (
             EXISTS (
                 SELECT 1
                 FROM agent_run_epochs epoch
                 JOIN agent_execution_events event
                   ON event.agent_id = epoch.agent_id
                  AND event.epoch_digest = epoch.digest
                 JOIN agent_execution_heads head
                   ON head.agent_id = event.agent_id
                  AND head.head_sequence >= event.sequence
                 WHERE epoch.model_job_id = OLD.id
                   AND epoch.operation_kind = 'model'
                   AND (
                       (NEW.status = 'succeeded' AND json_extract(
                           event.envelope_json, '$.fact.data.command.command'
                       ) IN ('model_final', 'model_tool_proposal'))
                       OR
                       (NEW.status = 'failed' AND json_extract(
                           event.envelope_json, '$.fact.data.command.command'
                       ) IN ('model_failed', 'user_cancelled'))
                       OR
                       (NEW.status = 'outcome_unknown' AND json_extract(
                           event.envelope_json, '$.fact.data.command.command'
                       ) = 'model_outcome_unknown')
                   )
             )
             OR (
                 NEW.status = 'outcome_unknown'
                 AND NOT EXISTS (
                     SELECT 1 FROM agent_run_epochs epoch
                     WHERE epoch.model_job_id = OLD.id
                 )
                 AND EXISTS (
                     SELECT 1
                     FROM agent_execution_heads head
                     JOIN agent_execution_events event
                       ON event.agent_id = head.agent_id
                      AND event.sequence = head.head_sequence
                      AND event.fact_digest = head.head_hash
                     WHERE head.agent_id = OLD.agent_id
                       AND head.history_origin = 'legacy_snapshot'
                       AND head.head_sequence = 2
                       AND event.epoch_digest IS NULL
                       AND event.operation_kind = 'model'
                       AND event.operation_id = OLD.id
                       AND json_extract(
                           event.envelope_json, '$.fact.data.command.command'
                       ) = 'model_outcome_unknown'
                 )
             )
         ))
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid agent model job transition');
END;
