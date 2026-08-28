CREATE TABLE agent_subagent_spawns (
    call_id TEXT PRIMARY KEY
        REFERENCES agent_tool_calls(call_id),
    account_id TEXT NOT NULL
        REFERENCES accounts(id),
    actor_user_id TEXT NOT NULL
        REFERENCES users(id),
    parent_session_id TEXT NOT NULL
        REFERENCES sessions(id),
    parent_turn_id TEXT NOT NULL
        REFERENCES session_turns(id),
    parent_agent_id TEXT NOT NULL
        REFERENCES agent_turns(id),
    parent_sequence INTEGER NOT NULL CHECK(parent_sequence > 0),
    child_session_id TEXT NOT NULL UNIQUE
        REFERENCES sessions(id),
    child_turn_id TEXT NOT NULL UNIQUE
        REFERENCES session_turns(id),
    child_agent_id TEXT NOT NULL UNIQUE
        REFERENCES agent_turns(id),
    description TEXT NOT NULL
        CHECK(length(CAST(description AS BLOB)) BETWEEN 1 AND 256),
    prompt_digest TEXT NOT NULL
        CHECK(length(prompt_digest) = 64 AND prompt_digest NOT GLOB '*[^0-9a-f]*'),
    created_at TEXT NOT NULL
) STRICT;

CREATE INDEX agent_subagent_spawns_parent_idx
    ON agent_subagent_spawns(
        account_id, parent_session_id, created_at DESC, child_session_id ASC
    );

CREATE TRIGGER agent_subagent_spawns_validate_insert
BEFORE INSERT ON agent_subagent_spawns
WHEN NOT EXISTS (
    SELECT 1
    FROM agent_tool_calls call
    JOIN agent_turns parent
      ON parent.id = call.agent_id
     AND parent.account_id = call.account_id
     AND parent.session_id = call.session_id
     AND parent.turn_id = call.turn_id
    JOIN session_forks fork
      ON fork.child_session_id = NEW.child_session_id
     AND fork.account_id = NEW.account_id
     AND fork.parent_session_id = NEW.parent_session_id
     AND fork.parent_sequence = NEW.parent_sequence
     AND fork.created_by_user_id = NEW.actor_user_id
     AND fork.created_by_membership_revision = parent.actor_membership_revision
    JOIN sessions child
      ON child.id = NEW.child_session_id
     AND child.account_id = NEW.account_id
     AND child.owner_user_id = NEW.actor_user_id
     AND child.title = NEW.description
    JOIN session_turns child_turn
      ON child_turn.id = NEW.child_turn_id
     AND child_turn.session_id = NEW.child_session_id
     AND child_turn.status = 'open'
    JOIN agent_turns child_agent
      ON child_agent.id = NEW.child_agent_id
     AND child_agent.account_id = NEW.account_id
     AND child_agent.actor_user_id = NEW.actor_user_id
     AND child_agent.actor_membership_revision = parent.actor_membership_revision
     AND child_agent.session_id = NEW.child_session_id
     AND child_agent.turn_id = NEW.child_turn_id
     AND child_agent.status = 'waiting_model'
    WHERE call.call_id = NEW.call_id
      AND call.tool_name = 'spawn_agent'
      AND call.tool_version = '1-durable-session-fork'
      AND call.status = 'started'
      AND call.account_id = NEW.account_id
      AND call.session_id = NEW.parent_session_id
      AND call.turn_id = NEW.parent_turn_id
      AND call.agent_id = NEW.parent_agent_id
      AND parent.actor_user_id = NEW.actor_user_id
      AND fork.created_at = NEW.created_at
      AND child_agent.created_at = NEW.created_at
)
BEGIN
    SELECT RAISE(ABORT, 'invalid Agent subagent spawn');
END;

CREATE TRIGGER agent_subagent_spawns_reject_update
BEFORE UPDATE ON agent_subagent_spawns
BEGIN
    SELECT RAISE(ABORT, 'Agent subagent spawns are immutable');
END;

CREATE TRIGGER agent_subagent_spawns_reject_delete
BEFORE DELETE ON agent_subagent_spawns
BEGIN
    SELECT RAISE(ABORT, 'Agent subagent spawns are append-only');
END;

CREATE TRIGGER agent_tool_calls_bind_subagent_spawn
BEFORE UPDATE OF status, result_json ON agent_tool_calls
WHEN OLD.status = 'started'
 AND OLD.tool_name = 'spawn_agent'
 AND OLD.tool_version = '1-durable-session-fork'
 AND (
     (NEW.status = 'succeeded' AND NOT EXISTS (
         SELECT 1
         FROM agent_subagent_spawns spawn
         WHERE spawn.call_id = OLD.call_id
           AND json_type(NEW.result_json) = 'object'
           AND json_extract(NEW.result_json, '$.subagent_id') = spawn.child_session_id
     ))
     OR (NEW.status <> 'succeeded' AND EXISTS (
         SELECT 1 FROM agent_subagent_spawns spawn
         WHERE spawn.call_id = OLD.call_id
     ))
 )
BEGIN
    SELECT RAISE(ABORT, 'Agent subagent completion is not bound to its spawn');
END;
