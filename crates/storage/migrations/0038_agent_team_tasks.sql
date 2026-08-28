-- Append-only shared task DAG for one root Session and every Agent child
-- admitted beneath it. Each mutation is bound to one exact started tool call;
-- the successful call cannot commit unless its result names this snapshot.

CREATE TABLE agent_team_task_snapshots (
    account_id          TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    root_session_id     TEXT NOT NULL REFERENCES sessions(id) ON DELETE RESTRICT,
    board_sequence      INTEGER NOT NULL CHECK (board_sequence BETWEEN 1 AND 4096),
    task_id             TEXT NOT NULL,
    task_number         INTEGER NOT NULL CHECK (task_number BETWEEN 1 AND 256),
    revision            INTEGER NOT NULL CHECK (revision > 0),
    source_session_id   TEXT NOT NULL REFERENCES sessions(id) ON DELETE RESTRICT,
    source_turn_id      TEXT NOT NULL,
    source_agent_id     TEXT NOT NULL REFERENCES agent_turns(id) ON DELETE RESTRICT,
    call_id             TEXT NOT NULL UNIQUE REFERENCES agent_tool_calls(call_id) ON DELETE RESTRICT,
    subject             TEXT NOT NULL,
    description         TEXT NOT NULL,
    status              TEXT NOT NULL CHECK (
        status IN ('pending', 'in_progress', 'completed', 'deleted')
    ),
    owner_session_id    TEXT REFERENCES sessions(id) ON DELETE RESTRICT,
    blocked_by_json     TEXT NOT NULL CHECK (
        json_valid(blocked_by_json) AND json_type(blocked_by_json) = 'array'
    ),
    write_scopes_json   TEXT NOT NULL CHECK (
        json_valid(write_scopes_json) AND json_type(write_scopes_json) = 'array'
    ),
    created_at          TEXT NOT NULL,
    PRIMARY KEY (root_session_id, task_number, revision),
    UNIQUE (root_session_id, board_sequence),
    UNIQUE (root_session_id, task_id, revision),
    FOREIGN KEY (source_session_id, source_turn_id)
        REFERENCES session_turns(session_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (source_agent_id, call_id)
        REFERENCES agent_tool_calls(agent_id, call_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE INDEX agent_team_task_snapshots_current_idx
    ON agent_team_task_snapshots(root_session_id, task_number, revision DESC);

CREATE TRIGGER agent_team_task_snapshots_validate_insert
BEFORE INSERT ON agent_team_task_snapshots
WHEN NEW.task_id <> 'task-' || NEW.task_number
 OR NEW.board_sequence <> COALESCE((
     SELECT MAX(existing.board_sequence) + 1
     FROM agent_team_task_snapshots existing
     WHERE existing.root_session_id = NEW.root_session_id
 ), 1)
 OR length(NEW.subject) = 0
 OR length(CAST(NEW.subject AS BLOB)) > 200
 OR length(NEW.description) = 0
 OR length(CAST(NEW.description AS BLOB)) > 16384
 OR (NEW.status IN ('pending', 'deleted') AND NEW.owner_session_id IS NOT NULL)
 OR (NEW.status = 'in_progress' AND NEW.owner_session_id IS NULL)
 OR NOT EXISTS (
     SELECT 1
     FROM agent_tool_calls call
     JOIN agent_turns agent
       ON agent.id = call.agent_id
      AND agent.account_id = call.account_id
      AND agent.session_id = call.session_id
      AND agent.turn_id = call.turn_id
     JOIN sessions source_session
       ON source_session.id = call.session_id
      AND source_session.account_id = call.account_id
     JOIN sessions root_session
       ON root_session.id = NEW.root_session_id
      AND root_session.account_id = call.account_id
     WHERE call.call_id = NEW.call_id
       AND call.status = 'started'
       AND call.account_id = NEW.account_id
       AND call.session_id = NEW.source_session_id
       AND call.turn_id = NEW.source_turn_id
       AND call.agent_id = NEW.source_agent_id
       AND call.tool_version = '1-session-dag'
       AND call.tool_name IN ('team_task_create', 'team_task_update')
       AND NOT EXISTS (
           SELECT 1 FROM agent_subagent_spawns parent_edge
           WHERE parent_edge.account_id = call.account_id
             AND parent_edge.child_session_id = NEW.root_session_id
       )
       AND EXISTS (
           WITH RECURSIVE ancestors(session_id) AS (
               SELECT call.session_id
               UNION ALL
               SELECT edge.parent_session_id
               FROM agent_subagent_spawns edge
               JOIN ancestors current
                 ON current.session_id = edge.child_session_id
               WHERE edge.account_id = call.account_id
           )
           SELECT 1 FROM ancestors WHERE session_id = NEW.root_session_id
       )
       AND (
           NEW.owner_session_id IS NULL
           OR EXISTS (
               WITH RECURSIVE owner_ancestors(session_id) AS (
                   SELECT NEW.owner_session_id
                   UNION ALL
                   SELECT edge.parent_session_id
                   FROM agent_subagent_spawns edge
                   JOIN owner_ancestors current
                     ON current.session_id = edge.child_session_id
                   WHERE edge.account_id = call.account_id
               )
               SELECT 1 FROM owner_ancestors WHERE session_id = NEW.root_session_id
           )
       )
       AND (
           (
               call.tool_name = 'team_task_create'
               AND NEW.revision = 1
               AND NEW.task_number = COALESCE((
                   SELECT MAX(existing.task_number) + 1
                   FROM agent_team_task_snapshots existing
                   WHERE existing.root_session_id = NEW.root_session_id
               ), 1)
               AND NOT EXISTS (
                   SELECT 1 FROM agent_team_task_snapshots existing
                   WHERE existing.root_session_id = NEW.root_session_id
                     AND existing.task_id = NEW.task_id
               )
           )
           OR
           (
               call.tool_name = 'team_task_update'
               AND json_extract(call.arguments_json, '$.task_id') = NEW.task_id
               AND json_extract(call.arguments_json, '$.expected_revision') = NEW.revision - 1
               AND NEW.revision = (
                   SELECT MAX(existing.revision) + 1
                   FROM agent_team_task_snapshots existing
                   WHERE existing.root_session_id = NEW.root_session_id
                     AND existing.task_id = NEW.task_id
               )
           )
       )
 )
BEGIN
    SELECT RAISE(ABORT, 'invalid Agent Team task snapshot');
END;

CREATE TRIGGER agent_team_task_snapshots_reject_update
BEFORE UPDATE ON agent_team_task_snapshots
BEGIN
    SELECT RAISE(ABORT, 'Agent Team task snapshots are append-only');
END;

CREATE TRIGGER agent_team_task_snapshots_reject_delete
BEFORE DELETE ON agent_team_task_snapshots
BEGIN
    SELECT RAISE(ABORT, 'Agent Team task snapshots are durable');
END;

CREATE TRIGGER agent_tool_calls_bind_team_task_snapshot
BEFORE UPDATE OF status, result_json ON agent_tool_calls
WHEN OLD.status = 'started'
 AND NEW.status = 'succeeded'
 AND OLD.tool_version = '1-session-dag'
 AND OLD.tool_name IN ('team_task_create', 'team_task_update')
 AND NOT EXISTS (
     SELECT 1 FROM agent_team_task_snapshots snapshot
     WHERE snapshot.call_id = OLD.call_id
       AND snapshot.task_id = json_extract(NEW.result_json, '$.task.id')
       AND snapshot.revision = json_extract(NEW.result_json, '$.task.revision')
       AND snapshot.status = json_extract(NEW.result_json, '$.task.status')
 )
BEGIN
    SELECT RAISE(ABORT, 'Agent Team task completion is not bound to its snapshot');
END;
