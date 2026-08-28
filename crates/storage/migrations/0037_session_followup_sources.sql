-- Immutable provenance for Agent-to-Agent follow-ups. Public user follow-ups
-- have no row in this table; Agent sources are admitted only from one exact
-- started tool call and remain queryable after the follow-up is claimed.

CREATE TABLE session_followup_sources (
    session_id         TEXT NOT NULL,
    turn_id            TEXT NOT NULL,
    source_kind        TEXT NOT NULL CHECK (
        source_kind IN ('subagent_message', 'subagent_report')
    ),
    source_session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE RESTRICT,
    source_agent_id    TEXT NOT NULL REFERENCES agent_turns(id) ON DELETE RESTRICT,
    source_call_id     TEXT NOT NULL UNIQUE REFERENCES agent_tool_calls(call_id) ON DELETE RESTRICT,
    created_at         TEXT NOT NULL,
    PRIMARY KEY (session_id, turn_id),
    FOREIGN KEY (session_id, turn_id)
        REFERENCES session_followups(session_id, turn_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

-- Backfill already-successful Agent messages created before this migration.
-- Deep readiness verifies the complete tool/lineage/content relationship.
INSERT INTO session_followup_sources(
    session_id, turn_id, source_kind, source_session_id,
    source_agent_id, source_call_id, created_at
)
SELECT followup.session_id, followup.turn_id,
       CASE call.tool_name
           WHEN 'send_message' THEN 'subagent_message'
           WHEN 'report' THEN 'subagent_report'
       END,
       call.session_id, call.agent_id, call.call_id, followup.enqueued_at
FROM agent_tool_calls call
JOIN session_followups followup
  ON followup.turn_id = json_extract(call.result_json, '$.message_id')
WHERE call.status = 'succeeded'
  AND (
      (call.tool_name = 'send_message' AND call.tool_version = '1-direct-child-followup')
      OR
      (call.tool_name = 'report' AND call.tool_version = '1-durable-parent-followup')
  );

CREATE TRIGGER session_followup_sources_validate_insert
BEFORE INSERT ON session_followup_sources
WHEN NOT EXISTS (
    SELECT 1
    FROM session_followups followup
    JOIN agent_tool_calls call
      ON call.call_id = NEW.source_call_id
    JOIN agent_turns agent
      ON agent.id = call.agent_id
     AND agent.account_id = call.account_id
     AND agent.session_id = call.session_id
     AND agent.turn_id = call.turn_id
    WHERE followup.session_id = NEW.session_id
      AND followup.turn_id = NEW.turn_id
      AND followup.status = 'queued'
      AND followup.account_id = call.account_id
      AND followup.actor_user_id = agent.actor_user_id
      AND followup.actor_membership_revision = agent.actor_membership_revision
      AND call.status = 'started'
      AND call.session_id = NEW.source_session_id
      AND call.agent_id = NEW.source_agent_id
      AND followup.enqueued_at = NEW.created_at
      AND (
          (
              NEW.source_kind = 'subagent_message'
              AND call.tool_name = 'send_message'
              AND call.tool_version = '1-direct-child-followup'
              AND json_extract(call.arguments_json, '$.subagent_id') = followup.session_id
              AND EXISTS (
                  SELECT 1 FROM agent_subagent_spawns spawn
                  WHERE spawn.account_id = call.account_id
                    AND spawn.actor_user_id = agent.actor_user_id
                    AND spawn.parent_session_id = call.session_id
                    AND spawn.child_session_id = followup.session_id
              )
          )
          OR
          (
              NEW.source_kind = 'subagent_report'
              AND call.tool_name = 'report'
              AND call.tool_version = '1-durable-parent-followup'
              AND EXISTS (
                  SELECT 1 FROM agent_subagent_spawns spawn
                  WHERE spawn.account_id = call.account_id
                    AND spawn.actor_user_id = agent.actor_user_id
                    AND spawn.child_session_id = call.session_id
                    AND spawn.parent_session_id = followup.session_id
              )
          )
      )
)
BEGIN
    SELECT RAISE(ABORT, 'invalid Session follow-up source');
END;

CREATE TRIGGER session_followup_sources_reject_update
BEFORE UPDATE ON session_followup_sources
BEGIN
    SELECT RAISE(ABORT, 'Session follow-up sources are immutable');
END;

CREATE TRIGGER session_followup_sources_reject_delete
BEFORE DELETE ON session_followup_sources
BEGIN
    SELECT RAISE(ABORT, 'Session follow-up sources are durable');
END;

CREATE TRIGGER agent_tool_calls_bind_followup_source
BEFORE UPDATE OF status, result_json ON agent_tool_calls
WHEN OLD.status = 'started'
 AND NEW.status = 'succeeded'
 AND (
     (OLD.tool_name = 'send_message' AND OLD.tool_version = '1-direct-child-followup')
     OR
     (OLD.tool_name = 'report' AND OLD.tool_version = '1-durable-parent-followup')
 )
 AND NOT EXISTS (
     SELECT 1
     FROM session_followup_sources source
     WHERE source.source_call_id = OLD.call_id
       AND source.turn_id = json_extract(NEW.result_json, '$.message_id')
       AND (
           (OLD.tool_name = 'send_message'
            AND source.source_kind = 'subagent_message'
            AND source.session_id = json_extract(NEW.result_json, '$.subagent_id'))
           OR
           (OLD.tool_name = 'report'
            AND source.source_kind = 'subagent_report')
       )
 )
BEGIN
    SELECT RAISE(ABORT, 'Agent message completion is not bound to its follow-up source');
END;
