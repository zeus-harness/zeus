-- One append-only completion Goal timeline per Session. Mutations are bound to
-- the exact started Agent tool call and its successful result. The global
-- sequence allows a completed Goal to be replaced while each Goal's revision
-- restarts at one.

CREATE TABLE agent_goal_snapshots (
    account_id       TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    session_id       TEXT NOT NULL,
    sequence         INTEGER NOT NULL CHECK (sequence > 0),
    turn_id          TEXT NOT NULL,
    agent_id         TEXT NOT NULL REFERENCES agent_turns(id) ON DELETE RESTRICT,
    goal_id          TEXT NOT NULL CHECK (
        length(CAST(goal_id AS BLOB)) BETWEEN 1 AND 80
        AND trim(goal_id) = goal_id
    ),
    goal_revision    INTEGER NOT NULL CHECK (goal_revision > 0),
    call_id          TEXT NOT NULL UNIQUE REFERENCES agent_tool_calls(call_id) ON DELETE RESTRICT,
    objective        TEXT NOT NULL CHECK (
        length(CAST(objective AS BLOB)) BETWEEN 1 AND 1024
        AND trim(objective) = objective
    ),
    phase            TEXT NOT NULL CHECK (phase IN ('active', 'paused', 'blocked', 'completed')),
    rounds_started   INTEGER NOT NULL CHECK (rounds_started >= 0),
    max_rounds       INTEGER NOT NULL CHECK (max_rounds BETWEEN 1 AND 4096),
    blocker_code     TEXT,
    blocker_message  TEXT,
    created_at       TEXT NOT NULL,
    PRIMARY KEY (session_id, sequence),
    UNIQUE (session_id, goal_id, goal_revision),
    FOREIGN KEY (account_id, session_id)
        REFERENCES sessions(account_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (session_id, turn_id)
        REFERENCES session_turns(session_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (agent_id, call_id)
        REFERENCES agent_tool_calls(agent_id, call_id) ON DELETE RESTRICT,
    CHECK (rounds_started <= max_rounds),
    CHECK (
        (phase = 'blocked'
         AND blocker_code = 'model_reported'
         AND length(CAST(blocker_message AS BLOB)) BETWEEN 1 AND 1024
         AND trim(blocker_message) = blocker_message)
        OR
        (phase <> 'blocked' AND blocker_code IS NULL AND blocker_message IS NULL)
    )
) STRICT;

CREATE INDEX agent_goal_snapshots_latest_idx
    ON agent_goal_snapshots(session_id, sequence DESC);

CREATE TRIGGER agent_goal_snapshots_validate_insert
BEFORE INSERT ON agent_goal_snapshots
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
          AND call.status = 'started'
          AND call.result_json IS NULL
          AND call.tool_version = '1-session-cas'
          AND call.tool_name IN ('create_goal', 'update_goal')
    )
    OR NEW.sequence <> COALESCE((
        SELECT MAX(snapshot.sequence)
        FROM agent_goal_snapshots snapshot
        WHERE snapshot.session_id = NEW.session_id
    ), 0) + 1
    OR (
        (SELECT tool_name FROM agent_tool_calls WHERE call_id = NEW.call_id) = 'create_goal'
        AND (
            NEW.goal_revision <> 1
            OR EXISTS (
                SELECT 1 FROM agent_goal_snapshots current
                WHERE current.session_id = NEW.session_id
                  AND current.sequence = NEW.sequence - 1
                  AND current.phase <> 'completed'
            )
        )
    )
    OR (
        (SELECT tool_name FROM agent_tool_calls WHERE call_id = NEW.call_id) = 'update_goal'
        AND NOT EXISTS (
            SELECT 1
            FROM agent_goal_snapshots current
            JOIN agent_tool_calls call ON call.call_id = NEW.call_id
            WHERE current.session_id = NEW.session_id
              AND current.sequence = NEW.sequence - 1
              AND current.goal_id = NEW.goal_id
              AND current.goal_revision + 1 = NEW.goal_revision
              AND json_type(call.arguments_json, '$.goal_id') = 'text'
              AND json_extract(call.arguments_json, '$.goal_id') = current.goal_id
              AND json_type(call.arguments_json, '$.expected_revision') = 'integer'
              AND json_extract(call.arguments_json, '$.expected_revision') = current.goal_revision
        )
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid Agent goal snapshot');
END;

CREATE TRIGGER agent_goal_snapshots_reject_update
BEFORE UPDATE ON agent_goal_snapshots
BEGIN
    SELECT RAISE(ABORT, 'Agent goal snapshots are immutable');
END;

CREATE TRIGGER agent_goal_snapshots_reject_delete
BEFORE DELETE ON agent_goal_snapshots
BEGIN
    SELECT RAISE(ABORT, 'Agent goal snapshots are append-only');
END;

CREATE TRIGGER agent_tool_calls_bind_goal_snapshot
BEFORE UPDATE OF status, result_json ON agent_tool_calls
WHEN OLD.status = 'started'
 AND OLD.tool_version = '1-session-cas'
 AND OLD.tool_name IN ('create_goal', 'update_goal')
 AND (
     (NEW.status = 'succeeded' AND NOT EXISTS (
         SELECT 1
         FROM agent_goal_snapshots snapshot
         WHERE snapshot.call_id = OLD.call_id
           AND json_type(NEW.result_json, '$.goal') = 'object'
           AND json_extract(NEW.result_json, '$.goal.id') = snapshot.goal_id
           AND json_extract(NEW.result_json, '$.goal.revision') = snapshot.goal_revision
           AND json_extract(NEW.result_json, '$.goal.objective') = snapshot.objective
           AND json_extract(NEW.result_json, '$.goal.phase') = snapshot.phase
           AND json_extract(NEW.result_json, '$.goal.rounds_started') = snapshot.rounds_started
           AND json_extract(NEW.result_json, '$.goal.max_rounds') = snapshot.max_rounds
           AND (
               (snapshot.blocker_code IS NULL
                AND json_type(NEW.result_json, '$.goal.blocker') IS NULL)
               OR
               (json_extract(NEW.result_json, '$.goal.blocker.code') = snapshot.blocker_code
                AND json_extract(NEW.result_json, '$.goal.blocker.message') = snapshot.blocker_message)
           )
     ))
     OR (NEW.status <> 'succeeded' AND EXISTS (
         SELECT 1 FROM agent_goal_snapshots snapshot
         WHERE snapshot.call_id = OLD.call_id
     ))
 )
BEGIN
    SELECT RAISE(ABORT, 'Agent goal completion is not bound to its snapshot');
END;
