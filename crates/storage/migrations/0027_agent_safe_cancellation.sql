DROP TRIGGER agent_tool_calls_enforce_forward_transition;

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
             WHERE epoch.tool_call_id = OLD.call_id
               AND epoch.operation_kind = 'tool'
               AND epoch.workflow_revision = event.agent_revision
               AND json_extract(
                   event.envelope_json, '$.fact.data.command.command'
               ) = 'start_tool'
         ))
        OR
        (OLD.status = 'queued' AND NEW.status = 'not_dispatched'
         AND NEW.started_at IS NULL
         AND NOT EXISTS (
             SELECT 1 FROM agent_run_epochs epoch
             WHERE epoch.tool_call_id = OLD.call_id
         )
         AND EXISTS (
             SELECT 1 FROM agent_turns agent
             WHERE agent.id = OLD.agent_id
               AND agent.status = 'failed'
               AND agent.pending_call_id IS NULL
               AND json_extract(
                   agent.workflow_state_json, '$.terminal_reason'
               ) = 'authorization_revoked'
         ))
        OR
        (OLD.status IN ('waiting_approval', 'queued')
         AND NEW.status = 'cancelled'
         AND NEW.started_at IS NULL
         AND json_extract(NEW.result_json, '$.code') = 'user_cancelled'
         AND NOT EXISTS (
             SELECT 1 FROM agent_run_epochs epoch
             WHERE epoch.tool_call_id = OLD.call_id
         )
         AND EXISTS (
             SELECT 1
             FROM agent_turns agent
             JOIN agent_execution_heads head ON head.agent_id = agent.id
             JOIN agent_execution_events event
               ON event.agent_id = head.agent_id
              AND event.sequence = head.head_sequence
              AND event.fact_digest = head.head_hash
             WHERE agent.id = OLD.agent_id
               AND agent.status = 'failed'
               AND agent.pending_call_id IS NULL
               AND json_extract(
                   agent.workflow_state_json, '$.terminal_reason'
               ) = 'authorization_revoked'
               AND event.epoch_digest IS NULL
               AND event.operation_kind = 'tool'
               AND event.operation_id = OLD.call_id
               AND json_extract(
                   event.envelope_json, '$.fact.data.command.command'
               ) = 'user_cancelled'
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
                 WHERE epoch.tool_call_id = OLD.call_id
                   AND epoch.operation_kind = 'tool'
                   AND (
                       (NEW.status IN ('succeeded', 'failed', 'cancelled', 'not_dispatched')
                        AND json_extract(
                            event.envelope_json, '$.fact.data.command.command'
                        ) = 'tool_result_known')
                       OR
                       (NEW.status = 'outcome_unknown' AND json_extract(
                           event.envelope_json, '$.fact.data.command.command'
                       ) = 'tool_outcome_unknown')
                   )
             )
             OR (
                 NEW.status = 'outcome_unknown'
                 AND NOT EXISTS (
                     SELECT 1 FROM agent_run_epochs epoch
                     WHERE epoch.tool_call_id = OLD.call_id
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
                       AND event.operation_kind = 'tool'
                       AND event.operation_id = OLD.call_id
                       AND json_extract(
                           event.envelope_json, '$.fact.data.command.command'
                       ) = 'tool_outcome_unknown'
                 )
             )
         ))
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid agent tool call transition');
END;
