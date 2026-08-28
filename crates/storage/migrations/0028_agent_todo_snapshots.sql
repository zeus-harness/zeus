-- Agent-owned whole-list planning snapshots. A snapshot is append-only and
-- can only be inserted for the exact started `todo_write` call that advances
-- the preceding revision. The tool result and the snapshot are then bound by
-- a separate completion trigger in the same transaction.

CREATE TABLE agent_todo_snapshots (
    account_id          TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    session_id          TEXT NOT NULL,
    turn_id             TEXT NOT NULL,
    agent_id            TEXT NOT NULL REFERENCES agent_turns(id) ON DELETE RESTRICT,
    revision            INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 4),
    call_id             TEXT NOT NULL UNIQUE REFERENCES agent_tool_calls(call_id) ON DELETE RESTRICT,
    todos_json          TEXT NOT NULL CHECK (
        json_valid(todos_json)
        AND json_type(todos_json) = 'array'
        AND json_array_length(todos_json) BETWEEN 0 AND 24
        AND length(CAST(todos_json AS BLOB)) <= 12288
    ),
    digest              TEXT NOT NULL CHECK (
        length(digest) = 71
        AND substr(digest, 1, 7) = 'sha256:'
        AND substr(digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    item_count          INTEGER NOT NULL CHECK (item_count BETWEEN 0 AND 24),
    pending_count       INTEGER NOT NULL CHECK (pending_count BETWEEN 0 AND 24),
    in_progress_count   INTEGER NOT NULL CHECK (in_progress_count BETWEEN 0 AND 1),
    completed_count     INTEGER NOT NULL CHECK (completed_count BETWEEN 0 AND 24),
    created_at          TEXT NOT NULL,
    PRIMARY KEY (agent_id, revision),
    FOREIGN KEY (account_id, session_id)
        REFERENCES sessions(account_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (session_id, turn_id)
        REFERENCES session_turns(session_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (agent_id, call_id)
        REFERENCES agent_tool_calls(agent_id, call_id) ON DELETE RESTRICT,
    CHECK (json_array_length(todos_json) = item_count),
    CHECK (pending_count + in_progress_count + completed_count = item_count)
) STRICT;

CREATE INDEX agent_todo_snapshots_latest_idx
    ON agent_todo_snapshots(agent_id, revision DESC);

CREATE TRIGGER agent_todo_snapshots_validate_insert
BEFORE INSERT ON agent_todo_snapshots
WHEN NOT EXISTS (
        SELECT 1
        FROM agent_turns agent
        JOIN agent_tool_calls call
          ON call.agent_id = agent.id AND call.call_id = NEW.call_id
        WHERE agent.id = NEW.agent_id
          AND agent.account_id = NEW.account_id
          AND agent.session_id = NEW.session_id
          AND agent.turn_id = NEW.turn_id
          AND call.account_id = NEW.account_id
          AND call.session_id = NEW.session_id
          AND call.turn_id = NEW.turn_id
          AND call.tool_name = 'todo_write'
          AND call.tool_version = '1-single-active'
          AND call.status = 'started'
          AND call.result_json IS NULL
          AND json_type(call.arguments_json, '$.expected_revision') = 'integer'
          AND json_extract(call.arguments_json, '$.expected_revision') = NEW.revision - 1
    )
    OR COALESCE((
        SELECT MAX(snapshot.revision)
        FROM agent_todo_snapshots snapshot
        WHERE snapshot.agent_id = NEW.agent_id
    ), 0) <> NEW.revision - 1
    OR EXISTS (
        SELECT 1
        FROM json_each(NEW.todos_json) item
        WHERE json_type(item.value) <> 'object'
           OR (SELECT COUNT(*) FROM json_each(item.value)) <> 2
           OR json_type(item.value, '$.content') <> 'text'
           OR length(CAST(json_extract(item.value, '$.content') AS BLOB)) NOT BETWEEN 1 AND 256
           OR trim(json_extract(item.value, '$.content')) <> json_extract(item.value, '$.content')
           OR json_type(item.value, '$.status') <> 'text'
           OR json_extract(item.value, '$.status') NOT IN (
               'pending', 'in_progress', 'completed'
           )
    )
    OR NEW.pending_count <> (
        SELECT COUNT(*) FROM json_each(NEW.todos_json) item
        WHERE json_extract(item.value, '$.status') = 'pending'
    )
    OR NEW.in_progress_count <> (
        SELECT COUNT(*) FROM json_each(NEW.todos_json) item
        WHERE json_extract(item.value, '$.status') = 'in_progress'
    )
    OR NEW.completed_count <> (
        SELECT COUNT(*) FROM json_each(NEW.todos_json) item
        WHERE json_extract(item.value, '$.status') = 'completed'
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid Agent todo snapshot');
END;

CREATE TRIGGER agent_todo_snapshots_reject_update
BEFORE UPDATE ON agent_todo_snapshots
BEGIN
    SELECT RAISE(ABORT, 'Agent todo snapshots are immutable');
END;

CREATE TRIGGER agent_todo_snapshots_reject_delete
BEFORE DELETE ON agent_todo_snapshots
BEGIN
    SELECT RAISE(ABORT, 'Agent todo snapshots are append-only');
END;

CREATE TRIGGER agent_tool_calls_bind_todo_snapshot
BEFORE UPDATE OF status, result_json ON agent_tool_calls
WHEN OLD.status = 'started'
 AND OLD.tool_name = 'todo_write'
 AND OLD.tool_version = '1-single-active'
 AND (
     (NEW.status = 'succeeded' AND NOT EXISTS (
         SELECT 1
         FROM agent_todo_snapshots snapshot
         WHERE snapshot.call_id = OLD.call_id
           AND json_type(NEW.result_json) = 'object'
           AND json_extract(NEW.result_json, '$.revision') = snapshot.revision
           AND json_extract(NEW.result_json, '$.digest') = snapshot.digest
           AND json(json_extract(NEW.result_json, '$.todos')) = json(snapshot.todos_json)
           AND json_extract(NEW.result_json, '$.counts.pending') = snapshot.pending_count
           AND json_extract(NEW.result_json, '$.counts.in_progress') = snapshot.in_progress_count
           AND json_extract(NEW.result_json, '$.counts.completed') = snapshot.completed_count
     ))
     OR (NEW.status <> 'succeeded' AND EXISTS (
         SELECT 1 FROM agent_todo_snapshots snapshot
         WHERE snapshot.call_id = OLD.call_id
     ))
 )
BEGIN
    SELECT RAISE(ABORT, 'Agent todo completion is not bound to its snapshot');
END;
