-- Durable admission evidence for same-Session automatic Goal rounds. Armed
-- continuation authority remains process-local; only a round that atomically
-- owns a real Session turn and Agent enqueue consumes the durable budget.

CREATE TABLE agent_goal_rounds (
    account_id                  TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    actor_user_id               TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    actor_membership_revision   INTEGER NOT NULL CHECK (actor_membership_revision > 0),
    session_id                  TEXT NOT NULL,
    goal_id                     TEXT NOT NULL CHECK (
        length(CAST(goal_id AS BLOB)) BETWEEN 1 AND 80
        AND trim(goal_id) = goal_id
    ),
    goal_revision               INTEGER NOT NULL CHECK (goal_revision > 0),
    round                       INTEGER NOT NULL CHECK (round > 0),
    turn_id                     TEXT NOT NULL UNIQUE,
    agent_id                    TEXT NOT NULL UNIQUE REFERENCES agent_turns(id) ON DELETE RESTRICT,
    prompt_digest               TEXT NOT NULL CHECK (
        length(prompt_digest) = 64
        AND prompt_digest NOT GLOB '*[^0-9a-f]*'
    ),
    admitted_at                 TEXT NOT NULL,
    PRIMARY KEY (session_id, goal_id, round),
    FOREIGN KEY (account_id, actor_user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (account_id, session_id)
        REFERENCES sessions(account_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (session_id, turn_id)
        REFERENCES session_turns(session_id, id) ON DELETE RESTRICT
) STRICT;

CREATE INDEX agent_goal_rounds_latest_idx
    ON agent_goal_rounds(session_id, goal_id, round DESC);

CREATE TRIGGER agent_goal_rounds_validate_insert
BEFORE INSERT ON agent_goal_rounds
WHEN NOT EXISTS (
        SELECT 1
        FROM agent_turns agent
        JOIN session_turns turn
          ON turn.session_id = agent.session_id AND turn.id = agent.turn_id
        JOIN agent_model_jobs job
          ON job.agent_id = agent.id AND job.step = 1
        WHERE agent.id = NEW.agent_id
          AND agent.account_id = NEW.account_id
          AND agent.actor_user_id = NEW.actor_user_id
          AND agent.actor_membership_revision = NEW.actor_membership_revision
          AND agent.session_id = NEW.session_id
          AND agent.turn_id = NEW.turn_id
          AND agent.status = 'waiting_model'
          AND turn.status = 'open'
          AND job.status = 'queued'
          AND agent.created_at = NEW.admitted_at
          AND turn.started_at = NEW.admitted_at
          AND job.queued_at = NEW.admitted_at
    )
    OR NEW.round <> COALESCE((
        SELECT MAX(prior.round)
        FROM agent_goal_rounds prior
        WHERE prior.session_id = NEW.session_id
          AND prior.goal_id = NEW.goal_id
    ), 0) + 1
    OR NOT EXISTS (
        SELECT 1
        FROM agent_goal_snapshots goal
        WHERE goal.session_id = NEW.session_id
          AND goal.sequence = (
              SELECT MAX(current.sequence)
              FROM agent_goal_snapshots current
              WHERE current.session_id = NEW.session_id
          )
          AND goal.goal_id = NEW.goal_id
          AND goal.goal_revision = NEW.goal_revision
          AND goal.phase = 'active'
          AND NEW.round <= goal.max_rounds
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid Agent goal round admission');
END;

CREATE TRIGGER agent_goal_rounds_reject_update
BEFORE UPDATE ON agent_goal_rounds
BEGIN
    SELECT RAISE(ABORT, 'Agent goal round admissions are immutable');
END;

CREATE TRIGGER agent_goal_rounds_reject_delete
BEFORE DELETE ON agent_goal_rounds
BEGIN
    SELECT RAISE(ABORT, 'Agent goal round admissions are append-only');
END;

-- v30 adds origin authority to the v29 lifecycle trigger. Model-created or
-- model-rearmed loops are forbidden: create/edit/pause/resume require a direct
-- human turn. Direct-human turns may conclude a Goal; an admitted Goal round
-- may conclude only its own revision, and its model-reported blocking requires
-- three admitted rounds.
DROP TRIGGER agent_goal_snapshots_validate_insert;

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
            OR EXISTS (
                SELECT 1 FROM agent_goal_rounds round
                WHERE round.agent_id = NEW.agent_id
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
    OR (
        (SELECT tool_name FROM agent_tool_calls WHERE call_id = NEW.call_id) = 'update_goal'
        AND json_extract(
            (SELECT arguments_json FROM agent_tool_calls WHERE call_id = NEW.call_id),
            '$.action'
        ) IN ('edit', 'pause', 'resume')
        AND EXISTS (
            SELECT 1 FROM agent_goal_rounds round
            WHERE round.agent_id = NEW.agent_id
        )
    )
    OR (
        (SELECT tool_name FROM agent_tool_calls WHERE call_id = NEW.call_id) = 'update_goal'
        AND json_extract(
            (SELECT arguments_json FROM agent_tool_calls WHERE call_id = NEW.call_id),
            '$.action'
        ) IN ('complete', 'blocked')
        AND EXISTS (
            SELECT 1 FROM agent_goal_rounds origin
            WHERE origin.agent_id = NEW.agent_id
        )
        AND NOT EXISTS (
            SELECT 1 FROM agent_goal_rounds round
            WHERE round.agent_id = NEW.agent_id
              AND round.goal_id = NEW.goal_id
              AND round.goal_revision + 1 = NEW.goal_revision
              AND round.round = NEW.rounds_started
              AND (
                  json_extract(
                      (SELECT arguments_json FROM agent_tool_calls WHERE call_id = NEW.call_id),
                      '$.action'
                  ) <> 'blocked'
                  OR round.round >= 3
              )
        )
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid Agent goal snapshot');
END;
