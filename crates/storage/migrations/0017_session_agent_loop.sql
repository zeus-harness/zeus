-- Session-native durable Agent Loop. These tables deliberately do not reuse
-- the legacy demo Run/reply queues: one Session turn can own up to eight model
-- steps and four sequential tool calls without weakening their old contracts.

CREATE TABLE agent_turns (
    id                           TEXT PRIMARY KEY CHECK (length(trim(id)) BETWEEN 1 AND 384),
    account_id                   TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    actor_user_id                TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    actor_membership_revision    INTEGER NOT NULL CHECK (actor_membership_revision > 0),
    session_id                   TEXT NOT NULL,
    turn_id                      TEXT NOT NULL,
    environment                  TEXT NOT NULL CHECK (length(trim(environment)) BETWEEN 1 AND 64),
    provider_name                TEXT NOT NULL CHECK (length(trim(provider_name)) BETWEEN 1 AND 128),
    model_name                   TEXT CHECK (
        model_name IS NULL OR length(trim(model_name)) BETWEEN 1 AND 128
    ),
    status                       TEXT NOT NULL CHECK (status IN (
        'waiting_model', 'model_running', 'waiting_approval',
        'tool_queued', 'tool_running', 'succeeded', 'failed', 'needs_attention'
    )),
    model_steps                  INTEGER NOT NULL CHECK (model_steps BETWEEN 0 AND 8),
    tool_calls                   INTEGER NOT NULL CHECK (tool_calls BETWEEN 0 AND 4),
    tool_result_bytes            INTEGER NOT NULL CHECK (tool_result_bytes BETWEEN 0 AND 131072),
    revision                     INTEGER NOT NULL CHECK (revision > 0),
    pending_call_id              TEXT,
    workflow_state_json          TEXT NOT NULL CHECK (
        json_valid(workflow_state_json)
        AND length(CAST(workflow_state_json AS BLOB)) <= 4096
        AND COALESCE(json_type(workflow_state_json, '$.schema_version') = 'integer', 0)
        AND COALESCE(json_extract(workflow_state_json, '$.schema_version') = 1, 0)
        AND COALESCE(json_type(workflow_state_json, '$.limits') = 'object', 0)
        AND COALESCE(json_extract(workflow_state_json, '$.limits.max_model_steps') = 8, 0)
        AND COALESCE(json_extract(workflow_state_json, '$.limits.max_tool_calls') = 4, 0)
        AND COALESCE(json_extract(workflow_state_json, '$.limits.max_pending_approvals') = 1, 0)
        AND COALESCE(json_extract(workflow_state_json, '$.limits.max_tool_result_bytes') = 65536, 0)
        AND COALESCE(json_extract(workflow_state_json, '$.limits.max_turn_tool_result_bytes') = 131072, 0)
        AND COALESCE(json_type(workflow_state_json, '$.model_steps') = 'integer', 0)
        AND COALESCE(json_extract(workflow_state_json, '$.model_steps') = model_steps, 0)
        AND COALESCE(json_type(workflow_state_json, '$.tool_calls') = 'integer', 0)
        AND COALESCE(json_extract(workflow_state_json, '$.tool_calls') = tool_calls, 0)
        AND COALESCE(json_type(workflow_state_json, '$.pending_approvals') = 'integer', 0)
        AND COALESCE(
            json_extract(workflow_state_json, '$.pending_approvals') =
                CASE status WHEN 'waiting_approval' THEN 1 ELSE 0 END,
            0
        )
        AND COALESCE(json_type(workflow_state_json, '$.tool_result_bytes') = 'integer', 0)
        AND COALESCE(json_extract(workflow_state_json, '$.tool_result_bytes') = tool_result_bytes, 0)
        AND COALESCE((
            (status = 'waiting_model'
             AND json_extract(workflow_state_json, '$.status') IN ('model_queued', 'continuation_queued'))
            OR (status = 'model_running'
                AND json_extract(workflow_state_json, '$.status') = 'model_started')
            OR (status = 'waiting_approval'
                AND json_extract(workflow_state_json, '$.status') = 'waiting_approval')
            OR (status = 'tool_queued'
                AND json_extract(workflow_state_json, '$.status') = 'tool_queued')
            OR (status = 'tool_running'
                AND json_extract(workflow_state_json, '$.status') = 'tool_started')
            OR (status = 'succeeded'
                AND json_extract(workflow_state_json, '$.status') = 'completed')
            OR (status = 'failed'
                AND json_extract(workflow_state_json, '$.status') = 'failed')
            OR (status = 'needs_attention'
                AND json_extract(workflow_state_json, '$.status') = 'needs_attention')
        ), 0)
        AND COALESCE(
            (status = 'failed'
             AND json_extract(workflow_state_json, '$.terminal_reason') IN (
                 'model_failed', 'authorization_revoked', 'model_step_limit_reached',
                 'tool_call_limit_reached', 'pending_approval_limit_reached',
                 'tool_result_bytes_limit_reached', 'continuation_unavailable'
             ))
            OR
            (status = 'needs_attention'
             AND json_extract(workflow_state_json, '$.terminal_reason') IN (
                 'model_outcome_unknown', 'tool_outcome_unknown'
             ))
            OR
            (status NOT IN ('failed', 'needs_attention')
             AND json_type(workflow_state_json, '$.terminal_reason') = 'null'),
            0
        )
    ),
    last_error_json              TEXT CHECK (
        last_error_json IS NULL
        OR (json_valid(last_error_json) AND length(CAST(last_error_json AS BLOB)) <= 32768)
    ),
    created_at                   TEXT NOT NULL,
    updated_at                   TEXT NOT NULL,
    completed_at                 TEXT,
    UNIQUE (session_id, turn_id),
    FOREIGN KEY (account_id, actor_user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (account_id, session_id)
        REFERENCES sessions(account_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (session_id, turn_id)
        REFERENCES session_turns(session_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (id, pending_call_id)
        REFERENCES agent_tool_calls(agent_id, call_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        (status IN ('waiting_approval', 'tool_queued', 'tool_running')
         AND pending_call_id IS NOT NULL)
        OR
        (status NOT IN ('waiting_approval', 'tool_queued', 'tool_running')
         AND pending_call_id IS NULL)
    ),
    CHECK (
        (status IN ('succeeded', 'failed', 'needs_attention') AND completed_at IS NOT NULL)
        OR
        (status NOT IN ('succeeded', 'failed', 'needs_attention') AND completed_at IS NULL)
    ),
    CHECK (
        (status IN ('failed', 'needs_attention') AND last_error_json IS NOT NULL)
        OR status NOT IN ('failed', 'needs_attention')
    )
) STRICT;

CREATE TABLE agent_model_jobs (
    id                           TEXT PRIMARY KEY CHECK (length(trim(id)) BETWEEN 1 AND 384),
    agent_id                     TEXT NOT NULL REFERENCES agent_turns(id) ON DELETE RESTRICT,
    account_id                   TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    actor_user_id                TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    actor_membership_revision    INTEGER NOT NULL CHECK (actor_membership_revision > 0),
    session_id                   TEXT NOT NULL,
    turn_id                      TEXT NOT NULL,
    step                         INTEGER NOT NULL CHECK (step BETWEEN 1 AND 8),
    provider_name                TEXT NOT NULL CHECK (length(trim(provider_name)) BETWEEN 1 AND 128),
    model_name                   TEXT CHECK (
        model_name IS NULL OR length(trim(model_name)) BETWEEN 1 AND 128
    ),
    status                       TEXT NOT NULL CHECK (
        status IN ('queued', 'started', 'succeeded', 'failed', 'outcome_unknown')
    ),
    attempt                      INTEGER NOT NULL CHECK (attempt IN (0, 1)),
    request_json                 TEXT NOT NULL CHECK (
        json_valid(request_json) AND length(CAST(request_json AS BLOB)) <= 524288
    ),
    response_json                TEXT CHECK (
        response_json IS NULL
        OR (json_valid(response_json) AND length(CAST(response_json AS BLOB)) <= 524288)
    ),
    error_json                   TEXT CHECK (
        error_json IS NULL
        OR (json_valid(error_json) AND length(CAST(error_json AS BLOB)) <= 32768)
    ),
    queued_at                    TEXT NOT NULL,
    started_at                   TEXT,
    finished_at                  TEXT,
    UNIQUE (agent_id, step),
    FOREIGN KEY (account_id, actor_user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (session_id, turn_id)
        REFERENCES session_turns(session_id, id) ON DELETE RESTRICT,
    CHECK (
        (status = 'queued' AND attempt = 0 AND response_json IS NULL
         AND error_json IS NULL AND started_at IS NULL AND finished_at IS NULL)
        OR
        (status = 'started' AND attempt = 1 AND response_json IS NULL
         AND error_json IS NULL AND started_at IS NOT NULL AND finished_at IS NULL)
        OR
        (status = 'succeeded' AND attempt = 1 AND response_json IS NOT NULL
         AND error_json IS NULL AND started_at IS NOT NULL AND finished_at IS NOT NULL)
        OR
        (status IN ('failed', 'outcome_unknown') AND attempt = 1
         AND response_json IS NULL AND error_json IS NOT NULL
         AND started_at IS NOT NULL AND finished_at IS NOT NULL)
    )
) STRICT;

CREATE TABLE agent_tool_calls (
    call_id                       TEXT PRIMARY KEY CHECK (length(trim(call_id)) BETWEEN 1 AND 160),
    agent_id                      TEXT NOT NULL REFERENCES agent_turns(id) ON DELETE RESTRICT,
    account_id                    TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    session_id                    TEXT NOT NULL,
    turn_id                       TEXT NOT NULL,
    provider_call_id              TEXT NOT NULL CHECK (length(trim(provider_call_id)) BETWEEN 1 AND 128),
    ordinal                       INTEGER NOT NULL CHECK (ordinal BETWEEN 1 AND 4),
    model_step                    INTEGER NOT NULL CHECK (model_step BETWEEN 1 AND 8),
    tool_name                     TEXT NOT NULL CHECK (length(trim(tool_name)) BETWEEN 1 AND 96),
    tool_version                  TEXT NOT NULL CHECK (length(trim(tool_version)) BETWEEN 1 AND 64),
    arguments_json                TEXT NOT NULL CHECK (
        json_valid(arguments_json) AND length(CAST(arguments_json AS BLOB)) <= 65536
    ),
    arguments_digest              TEXT NOT NULL CHECK (length(trim(arguments_digest)) BETWEEN 1 AND 128),
    effect                        TEXT NOT NULL CHECK (
        effect IN ('read_only', 'local_write', 'production_write', 'destructive')
    ),
    sandbox_profile               TEXT NOT NULL CHECK (
        sandbox_profile IN ('read_only', 'workspace_write', 'isolated_container', 'production_guarded')
    ),
    executor_status               TEXT NOT NULL CHECK (executor_status IN ('available', 'unavailable')),
    policy_decision               TEXT NOT NULL CHECK (
        policy_decision IN ('allow', 'require_approval', 'deny')
    ),
    policy_revision               TEXT NOT NULL CHECK (length(trim(policy_revision)) BETWEEN 1 AND 128),
    status                        TEXT NOT NULL CHECK (status IN (
        'waiting_approval', 'queued', 'started', 'succeeded', 'failed', 'cancelled',
        'rejected', 'not_dispatched', 'outcome_unknown'
    )),
    approving_actor_user_id       TEXT REFERENCES users(id) ON DELETE RESTRICT,
    approving_membership_revision INTEGER CHECK (approving_membership_revision > 0),
    review_note                   TEXT CHECK (
        review_note IS NULL OR length(CAST(review_note AS BLOB)) <= 8192
    ),
    reviewed_at                   TEXT,
    result_json                   TEXT CHECK (
        result_json IS NULL
        OR (json_valid(result_json) AND length(CAST(result_json AS BLOB)) <= 65536)
    ),
    provider_request_id           TEXT CHECK (
        provider_request_id IS NULL OR length(trim(provider_request_id)) BETWEEN 1 AND 128
    ),
    created_at                    TEXT NOT NULL,
    started_at                    TEXT,
    finished_at                   TEXT,
    UNIQUE (agent_id, ordinal),
    UNIQUE (agent_id, call_id),
    UNIQUE (agent_id, model_step, provider_call_id),
    FOREIGN KEY (account_id, approving_actor_user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (session_id, turn_id)
        REFERENCES session_turns(session_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (agent_id, model_step)
        REFERENCES agent_model_jobs(agent_id, step) ON DELETE RESTRICT,
    CHECK (
        (approving_actor_user_id IS NULL AND approving_membership_revision IS NULL
         AND review_note IS NULL AND reviewed_at IS NULL)
        OR
        (approving_actor_user_id IS NOT NULL AND approving_membership_revision IS NOT NULL
         AND reviewed_at IS NOT NULL)
    ),
    CHECK (
        (status IN ('waiting_approval', 'queued') AND started_at IS NULL
         AND finished_at IS NULL AND result_json IS NULL)
        OR
        (status = 'started' AND started_at IS NOT NULL
         AND finished_at IS NULL AND result_json IS NULL)
        OR
        (status IN ('succeeded', 'failed', 'cancelled', 'rejected', 'not_dispatched', 'outcome_unknown')
         AND finished_at IS NOT NULL AND result_json IS NOT NULL)
    ),
    CHECK (
        (status = 'waiting_approval' AND policy_decision = 'require_approval'
         AND approving_actor_user_id IS NULL)
        OR status <> 'waiting_approval'
    ),
    CHECK (
        (status IN ('queued', 'started') AND (
            (policy_decision = 'allow' AND approving_actor_user_id IS NULL)
            OR
            (policy_decision = 'require_approval' AND approving_actor_user_id IS NOT NULL)
        ))
        OR status NOT IN ('queued', 'started')
    )
) STRICT;

CREATE TABLE agent_review_receipts (
    account_id                    TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    actor_user_id                 TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    actor_membership_revision     INTEGER NOT NULL CHECK (actor_membership_revision > 0),
    idempotency_key               TEXT NOT NULL CHECK (length(trim(idempotency_key)) BETWEEN 1 AND 128),
    call_id                       TEXT NOT NULL REFERENCES agent_tool_calls(call_id) ON DELETE RESTRICT,
    request_fingerprint           TEXT NOT NULL CHECK (length(trim(request_fingerprint)) BETWEEN 1 AND 128),
    response_json                 TEXT NOT NULL CHECK (
        json_valid(response_json) AND length(CAST(response_json AS BLOB)) <= 524288
    ),
    created_at                    TEXT NOT NULL,
    PRIMARY KEY (account_id, actor_user_id, idempotency_key),
    FOREIGN KEY (account_id, actor_user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT
) STRICT;

CREATE INDEX agent_turns_account_status_idx
    ON agent_turns(account_id, status, updated_at, id);
CREATE INDEX session_events_turn_kind_idx
    ON session_events(session_id, turn_id, event_kind, sequence)
    WHERE turn_id IS NOT NULL;
CREATE INDEX agent_turns_recovery_idx
    ON agent_turns(status, updated_at, id)
    WHERE status IN ('model_running', 'tool_running');
CREATE INDEX agent_model_jobs_ready_idx
    ON agent_model_jobs(status, queued_at, id)
    WHERE status = 'queued';
CREATE INDEX agent_model_jobs_started_idx
    ON agent_model_jobs(status, started_at, id)
    WHERE status = 'started';
CREATE UNIQUE INDEX agent_model_jobs_one_live_idx
    ON agent_model_jobs(agent_id)
    WHERE status IN ('queued', 'started');
CREATE INDEX agent_tool_calls_ready_idx
    ON agent_tool_calls(status, created_at, call_id)
    WHERE status = 'queued';
CREATE INDEX agent_tool_calls_started_idx
    ON agent_tool_calls(status, started_at, call_id)
    WHERE status = 'started';
CREATE UNIQUE INDEX agent_tool_calls_one_live_idx
    ON agent_tool_calls(agent_id)
    WHERE status IN ('waiting_approval', 'queued', 'started');

CREATE TRIGGER agent_turns_reject_identity_update
BEFORE UPDATE OF id, account_id, actor_user_id, actor_membership_revision,
                 session_id, turn_id, environment, provider_name, model_name, created_at
ON agent_turns
BEGIN
    SELECT RAISE(ABORT, 'agent turn identity is immutable');
END;

CREATE TRIGGER agent_turns_require_current_authority
BEFORE INSERT ON agent_turns
WHEN NOT EXISTS (
        SELECT 1
        FROM sessions session
        JOIN accounts account ON account.id = session.account_id
        JOIN session_turns turn
          ON turn.session_id = session.id AND turn.id = NEW.turn_id
        JOIN account_memberships membership
          ON membership.account_id = session.account_id
         AND membership.user_id = NEW.actor_user_id
        JOIN users user ON user.id = membership.user_id
        WHERE session.id = NEW.session_id
          AND session.account_id = NEW.account_id
          AND session.status = 'running'
          AND session.active_turn_id = NEW.turn_id
          AND turn.status = 'open'
          AND account.status = 'active'
          AND membership.status = 'active'
          AND membership.revision = NEW.actor_membership_revision
          AND user.status = 'active'
    )
BEGIN
    SELECT RAISE(ABORT, 'agent turn requires current Session authority');
END;

CREATE TRIGGER agent_turns_enforce_forward_revision
BEFORE UPDATE ON agent_turns
WHEN NEW.revision <> OLD.revision + 1
  OR NEW.model_steps < OLD.model_steps
  OR NEW.model_steps > OLD.model_steps + 1
  OR NEW.tool_calls < OLD.tool_calls
  OR NEW.tool_calls > OLD.tool_calls + 1
  OR NEW.tool_result_bytes < OLD.tool_result_bytes
  OR NEW.tool_result_bytes > OLD.tool_result_bytes + 65536
  OR OLD.status IN ('succeeded', 'failed', 'needs_attention')
  OR NOT (
      (OLD.status = 'waiting_model' AND NEW.status IN ('model_running', 'failed', 'needs_attention'))
      OR
      (OLD.status = 'model_running' AND NEW.status IN (
          'waiting_approval', 'tool_queued', 'waiting_model',
          'succeeded', 'failed', 'needs_attention'
      ))
      OR
      (OLD.status = 'waiting_approval' AND NEW.status IN (
          'tool_queued', 'waiting_model', 'failed', 'needs_attention'
      ))
      OR
      (OLD.status = 'tool_queued' AND NEW.status IN (
          'tool_running', 'failed', 'needs_attention'
      ))
      OR
      (OLD.status = 'tool_running' AND NEW.status IN (
          'waiting_model', 'failed', 'needs_attention'
      ))
  )
  OR (NEW.model_steps <> OLD.model_steps
      AND NOT (OLD.status = 'waiting_model' AND NEW.status = 'model_running'))
  OR (NEW.tool_calls <> OLD.tool_calls
      AND OLD.status <> 'model_running')
  OR (NEW.tool_result_bytes <> OLD.tool_result_bytes
      AND NOT (
          NEW.status = 'waiting_model'
          OR (
              NEW.status = 'failed'
              AND json_extract(
                  NEW.workflow_state_json, '$.terminal_reason'
              ) IN ('model_step_limit_reached', 'continuation_unavailable')
          )
      ))
BEGIN
    SELECT RAISE(ABORT, 'invalid agent turn transition');
END;

CREATE TRIGGER agent_model_jobs_require_current_step
BEFORE INSERT ON agent_model_jobs
WHEN NOT EXISTS (
        SELECT 1 FROM agent_turns agent
        WHERE agent.id = NEW.agent_id
          AND agent.account_id = NEW.account_id
          AND agent.session_id = NEW.session_id
          AND agent.turn_id = NEW.turn_id
          AND agent.actor_user_id = NEW.actor_user_id
          AND agent.actor_membership_revision = NEW.actor_membership_revision
          AND agent.provider_name = NEW.provider_name
          AND agent.model_name IS NEW.model_name
          AND agent.status = 'waiting_model'
          AND agent.model_steps + 1 = NEW.step
    )
BEGIN
    SELECT RAISE(ABORT, 'agent model job does not match the current step');
END;

CREATE TRIGGER agent_model_jobs_reject_input_update
BEFORE UPDATE OF id, agent_id, account_id, actor_user_id, actor_membership_revision,
                 session_id, turn_id, step, provider_name, model_name, request_json, queued_at
ON agent_model_jobs
BEGIN
    SELECT RAISE(ABORT, 'agent model job input is immutable');
END;

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
         ))
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid agent model job transition');
END;

CREATE TRIGGER agent_model_jobs_reject_delete
BEFORE DELETE ON agent_model_jobs
BEGIN
    SELECT RAISE(ABORT, 'agent model jobs are durable records');
END;

CREATE TRIGGER agent_tool_calls_require_current_call
BEFORE INSERT ON agent_tool_calls
WHEN NOT EXISTS (
        SELECT 1 FROM agent_turns agent
        WHERE agent.id = NEW.agent_id
          AND agent.account_id = NEW.account_id
          AND agent.session_id = NEW.session_id
          AND agent.turn_id = NEW.turn_id
          AND agent.tool_calls = NEW.ordinal
          AND agent.model_steps = NEW.model_step
          AND (
              (NEW.status IN ('waiting_approval', 'queued')
               AND agent.status IN ('waiting_approval', 'tool_queued')
               AND agent.pending_call_id = NEW.call_id)
              OR
              (NEW.status = 'not_dispatched'
               AND NEW.policy_decision = 'deny'
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
    )
BEGIN
    SELECT RAISE(ABORT, 'agent tool call does not match the current loop state');
END;

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

CREATE TRIGGER agent_tool_calls_reject_input_update
BEFORE UPDATE OF call_id, agent_id, account_id, session_id, turn_id,
                 provider_call_id, ordinal, model_step, tool_name, tool_version,
                 arguments_json, arguments_digest, effect, sandbox_profile,
                 executor_status, policy_decision, policy_revision, created_at
ON agent_tool_calls
BEGIN
    SELECT RAISE(ABORT, 'agent tool call input is immutable');
END;

CREATE TRIGGER agent_tool_calls_freeze_review_binding
BEFORE UPDATE OF approving_actor_user_id, approving_membership_revision,
                 review_note, reviewed_at
ON agent_tool_calls
WHEN OLD.status <> 'waiting_approval'
BEGIN
    SELECT RAISE(ABORT, 'agent tool call review binding is immutable');
END;

CREATE TRIGGER agent_tool_calls_reject_delete
BEFORE DELETE ON agent_tool_calls
BEGIN
    SELECT RAISE(ABORT, 'agent tool calls are durable records');
END;

CREATE TRIGGER agent_turns_reject_delete
BEFORE DELETE ON agent_turns
BEGIN
    SELECT RAISE(ABORT, 'agent turns are durable records');
END;

CREATE TRIGGER agent_review_receipts_require_current_owner
BEFORE INSERT ON agent_review_receipts
WHEN NOT EXISTS (
        SELECT 1
        FROM agent_tool_calls call
        JOIN accounts account ON account.id = call.account_id
        JOIN account_memberships membership
          ON membership.account_id = call.account_id
         AND membership.user_id = NEW.actor_user_id
        JOIN users user ON user.id = membership.user_id
        WHERE call.call_id = NEW.call_id
          AND call.account_id = NEW.account_id
          AND call.approving_actor_user_id = NEW.actor_user_id
          AND call.approving_membership_revision = NEW.actor_membership_revision
          AND account.status = 'active'
          AND membership.role = 'owner'
          AND membership.status = 'active'
          AND membership.revision = NEW.actor_membership_revision
          AND user.status = 'active'
    )
BEGIN
    SELECT RAISE(ABORT, 'agent review receipt requires current owner authority');
END;

CREATE TRIGGER agent_review_receipts_reject_update
BEFORE UPDATE ON agent_review_receipts
BEGIN
    SELECT RAISE(ABORT, 'agent review receipts are immutable');
END;

CREATE TRIGGER agent_review_receipts_reject_delete
BEFORE DELETE ON agent_review_receipts
BEGIN
    SELECT RAISE(ABORT, 'agent review receipts are durable records');
END;
