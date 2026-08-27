-- Bind an Agent tool completion to the exact continuation input supplied by
-- its first durable commit. A JSON null records an explicit absent request;
-- SQL NULL is reserved for calls that have not used this completion path or
-- for legacy terminal rows whose original input cannot be reconstructed.

ALTER TABLE agent_tool_calls
    ADD COLUMN completion_next_request_json TEXT CHECK (
        completion_next_request_json IS NULL
        OR (
            status IN ('succeeded', 'failed', 'cancelled', 'not_dispatched')
            AND policy_decision IN ('allow', 'require_approval')
            AND started_at IS NOT NULL
            AND finished_at IS NOT NULL
            AND result_json IS NOT NULL
            AND json_valid(completion_next_request_json)
            AND json_type(completion_next_request_json) IN ('object', 'null')
            AND length(CAST(completion_next_request_json AS BLOB)) <= 524288
        )
    );

-- A queued continuation is authoritative enough to recover the original
-- completion input during an in-place v17 upgrade. Terminal v17 rows without
-- a next job remain SQL NULL and therefore fail closed on a later replay.
-- `started_at`, the terminal output columns, and the next job together prove
-- this was a started tool completion rather than PolicyDenied or review
-- rejection. `provider_request_id` is intentionally not required because a
-- known failed, cancelled, or not-dispatched connector result may omit it.
-- The v17 transition trigger rejects every status-preserving update, so it is
-- removed and restored inside this migration's enclosing transaction.
DROP TRIGGER agent_tool_calls_enforce_forward_transition;

UPDATE agent_tool_calls AS call
SET completion_next_request_json = (
    SELECT job.request_json
    FROM agent_model_jobs AS job
    WHERE job.agent_id = call.agent_id
      AND job.step = call.model_step + 1
)
WHERE call.status IN ('succeeded', 'failed', 'cancelled', 'not_dispatched')
  AND call.policy_decision IN ('allow', 'require_approval')
  AND call.started_at IS NOT NULL
  AND call.finished_at IS NOT NULL
  AND call.result_json IS NOT NULL
  AND EXISTS (
      SELECT 1
      FROM agent_model_jobs AS job
      WHERE job.agent_id = call.agent_id
        AND job.step = call.model_step + 1
  );

CREATE TRIGGER agent_tool_calls_enforce_forward_transition
BEFORE UPDATE ON agent_tool_calls
WHEN NOT (
        (OLD.status = 'waiting_approval'
         AND NEW.status IN ('queued', 'rejected')
         AND EXISTS (
             SELECT 1
             FROM accounts account
             JOIN account_memberships membership
               ON membership.account_id = account.id
              AND membership.user_id = NEW.approving_actor_user_id
             JOIN users user ON user.id = membership.user_id
             WHERE account.id = OLD.account_id
               AND account.status = 'active'
               AND membership.role = 'owner'
               AND membership.status = 'active'
               AND membership.revision = NEW.approving_membership_revision
               AND user.status = 'active'
         )
         AND EXISTS (
             SELECT 1 FROM agent_turns agent
             WHERE agent.id = OLD.agent_id
               AND (
                   (NEW.status = 'queued' AND agent.status = 'tool_queued'
                    AND agent.pending_call_id = OLD.call_id)
                   OR
                   (NEW.status = 'rejected'
                    AND agent.pending_call_id IS NULL
                    AND (
                        agent.status = 'waiting_model'
                        OR (
                            agent.status = 'failed'
                            AND json_extract(
                                agent.workflow_state_json, '$.terminal_reason'
                            ) IN (
                                'tool_result_bytes_limit_reached',
                                'model_step_limit_reached',
                                'continuation_unavailable'
                            )
                        )
                    ))
               )
         ))
        OR
        (OLD.status = 'queued' AND NEW.status = 'started'
         AND EXISTS (
             SELECT 1 FROM agent_turns agent
             WHERE agent.id = OLD.agent_id
               AND agent.status = 'tool_running'
               AND agent.pending_call_id = OLD.call_id
         ))
        OR
        (OLD.status = 'started'
         AND NEW.status IN ('succeeded', 'failed', 'cancelled', 'not_dispatched', 'outcome_unknown')
         AND EXISTS (
             SELECT 1 FROM agent_turns agent
             WHERE agent.id = OLD.agent_id
               AND (
                   (NEW.status IN ('succeeded', 'failed', 'cancelled', 'not_dispatched')
                    AND agent.pending_call_id IS NULL
                    AND (
                        agent.status = 'waiting_model'
                        OR (
                            agent.status = 'failed'
                            AND json_extract(
                                agent.workflow_state_json, '$.terminal_reason'
                            ) IN (
                                'tool_result_bytes_limit_reached',
                                'model_step_limit_reached',
                                'continuation_unavailable',
                                'authorization_revoked'
                            )
                        )
                    ))
                   OR
                   (NEW.status = 'outcome_unknown'
                    AND agent.status = 'needs_attention'
                    AND agent.pending_call_id IS NULL)
               )
         ))
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid agent tool call transition');
END;

CREATE TRIGGER agent_tool_calls_require_completion_next_request
BEFORE UPDATE OF status ON agent_tool_calls
WHEN OLD.status = 'started'
 AND NEW.status IN ('succeeded', 'failed', 'cancelled', 'not_dispatched')
 AND NEW.completion_next_request_json IS NULL
BEGIN
    SELECT RAISE(ABORT, 'agent tool completion continuation is required');
END;

CREATE TRIGGER agent_tool_calls_freeze_completion_next_request
BEFORE UPDATE OF completion_next_request_json
ON agent_tool_calls
WHEN NOT (
    OLD.status = 'started'
    AND NEW.status IN ('succeeded', 'failed', 'cancelled', 'not_dispatched')
    AND OLD.completion_next_request_json IS NULL
    AND NEW.completion_next_request_json IS NOT NULL
    AND (
        NOT EXISTS (
            SELECT 1 FROM agent_model_jobs job
            WHERE job.agent_id = NEW.agent_id
              AND job.step = NEW.model_step + 1
        )
        OR (
            json_type(NEW.completion_next_request_json) = 'object'
            AND NEW.completion_next_request_json IS (
                SELECT job.request_json
                FROM agent_model_jobs job
                WHERE job.agent_id = NEW.agent_id
                  AND job.step = NEW.model_step + 1
            )
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'agent tool completion continuation is immutable');
END;

CREATE TRIGGER agent_model_jobs_bind_tool_completion_request
BEFORE INSERT ON agent_model_jobs
WHEN EXISTS (
    SELECT 1
    FROM agent_tool_calls call
    WHERE call.agent_id = NEW.agent_id
      AND call.model_step + 1 = NEW.step
      AND call.status IN ('succeeded', 'failed', 'cancelled', 'not_dispatched')
      AND call.policy_decision IN ('allow', 'require_approval')
      AND call.started_at IS NOT NULL
      AND (
          call.completion_next_request_json IS NULL
          OR json_type(call.completion_next_request_json) <> 'object'
          OR call.completion_next_request_json IS NOT NEW.request_json
      )
)
BEGIN
    SELECT RAISE(ABORT, 'agent continuation job conflicts with its tool completion');
END;
