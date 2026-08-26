-- Dispatch authorization must survive the gap between approval and connector
-- execution. Rebuild the table so the approving actor is immutable and a
-- failed claim has a terminal, durable state that never reaches a connector.
DROP TRIGGER dispatch_jobs_reject_input_update;
DROP TRIGGER dispatch_jobs_enforce_forward_transition;
DROP TRIGGER dispatch_jobs_reject_delete;

ALTER TABLE dispatch_jobs RENAME TO dispatch_jobs_v7;

CREATE TABLE dispatch_jobs (
    call_id                    TEXT PRIMARY KEY
        CHECK (length(trim(call_id)) > 0),
    run_id                     TEXT NOT NULL,
    approval_id                TEXT NOT NULL UNIQUE
        CHECK (length(trim(approval_id)) > 0),
    approval_event_sequence    INTEGER NOT NULL CHECK (approval_event_sequence > 0),
    approving_actor_user_id    TEXT REFERENCES users(id) ON DELETE RESTRICT,
    tool_name                  TEXT NOT NULL CHECK (length(trim(tool_name)) > 0),
    tool_version               TEXT NOT NULL CHECK (length(trim(tool_version)) > 0),
    effect                     TEXT NOT NULL CHECK (
        effect IN ('read_only', 'local_write', 'production_write', 'destructive')
    ),
    args_json                  TEXT NOT NULL CHECK (json_valid(args_json)),
    args_digest                TEXT NOT NULL CHECK (length(trim(args_digest)) > 0),
    policy_id                  TEXT NOT NULL CHECK (length(trim(policy_id)) > 0),
    policy_revision            TEXT NOT NULL CHECK (length(trim(policy_revision)) > 0),
    sandbox_profile            TEXT NOT NULL CHECK (
        sandbox_profile IN (
            'read_only', 'workspace_write', 'isolated_container', 'production_guarded'
        )
    ),
    status                     TEXT NOT NULL CHECK (
        status IN ('queued', 'started', 'finished', 'rejected')
    ),
    attempt                    INTEGER NOT NULL DEFAULT 0 CHECK (attempt IN (0, 1)),
    result_json                TEXT CHECK (result_json IS NULL OR json_valid(result_json)),
    authorization_error_json  TEXT CHECK (
        authorization_error_json IS NULL OR json_valid(authorization_error_json)
    ),
    queued_at                  TEXT NOT NULL,
    started_at                 TEXT,
    finished_at                TEXT,
    start_event_sequence       INTEGER CHECK (start_event_sequence > 0),
    result_event_sequence      INTEGER CHECK (result_event_sequence > 0),
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, approval_event_sequence)
        REFERENCES run_events(run_id, sequence) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, start_event_sequence)
        REFERENCES run_events(run_id, sequence) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, result_event_sequence)
        REFERENCES run_events(run_id, sequence) ON DELETE RESTRICT,
    CHECK (
        (status = 'queued'
            AND attempt = 0
            AND result_json IS NULL
            AND authorization_error_json IS NULL
            AND started_at IS NULL
            AND finished_at IS NULL
            AND start_event_sequence IS NULL
            AND result_event_sequence IS NULL)
        OR
        (status = 'started'
            AND attempt = 1
            AND result_json IS NULL
            AND authorization_error_json IS NULL
            AND started_at IS NOT NULL
            AND finished_at IS NULL
            AND start_event_sequence IS NOT NULL
            AND result_event_sequence IS NULL)
        OR
        (status = 'finished'
            AND attempt = 1
            AND result_json IS NOT NULL
            AND authorization_error_json IS NULL
            AND started_at IS NOT NULL
            AND finished_at IS NOT NULL
            AND start_event_sequence IS NOT NULL
            AND result_event_sequence IS NOT NULL)
        OR
        (status = 'rejected'
            AND attempt = 0
            AND result_json IS NOT NULL
            AND authorization_error_json IS NOT NULL
            AND started_at IS NULL
            AND finished_at IS NOT NULL
            AND start_event_sequence IS NULL
            AND result_event_sequence IS NOT NULL)
    )
) STRICT;

INSERT INTO dispatch_jobs(
    call_id, run_id, approval_id, approval_event_sequence,
    approving_actor_user_id, tool_name, tool_version, effect, args_json,
    args_digest, policy_id, policy_revision, sandbox_profile, status, attempt,
    result_json, authorization_error_json, queued_at, started_at, finished_at,
    start_event_sequence, result_event_sequence
)
SELECT
    j.call_id, j.run_id, j.approval_id, j.approval_event_sequence,
    CASE
        WHEN (SELECT COUNT(*) FROM users WHERE role = 'owner') = 1
         AND r.owner_user_id = (SELECT id FROM users WHERE role = 'owner')
        THEN r.owner_user_id
        ELSE NULL
    END,
    j.tool_name, j.tool_version, j.effect, j.args_json, j.args_digest,
    j.policy_id, j.policy_revision, j.sandbox_profile, j.status, j.attempt,
    j.result_json, NULL, j.queued_at, j.started_at, j.finished_at,
    j.start_event_sequence, j.result_event_sequence
FROM dispatch_jobs_v7 j
JOIN runs r ON r.id = j.run_id;

DROP TABLE dispatch_jobs_v7;

CREATE INDEX dispatch_jobs_ready_idx
    ON dispatch_jobs(status, queued_at, call_id);
CREATE INDEX dispatch_jobs_run_idx
    ON dispatch_jobs(run_id, status, call_id);
CREATE INDEX dispatch_jobs_actor_idx
    ON dispatch_jobs(approving_actor_user_id, status, queued_at, call_id);

CREATE TRIGGER dispatch_jobs_require_actor_on_insert
BEFORE INSERT ON dispatch_jobs
WHEN NEW.approving_actor_user_id IS NULL
  OR NOT EXISTS (
      SELECT 1
      FROM runs r
      JOIN users u ON u.id = NEW.approving_actor_user_id
      WHERE r.id = NEW.run_id
        AND r.owner_user_id = NEW.approving_actor_user_id
        AND u.role = 'owner'
        AND u.status = 'active'
  )
BEGIN
    SELECT RAISE(ABORT, 'new dispatch jobs require an active owner actor');
END;

CREATE TRIGGER dispatch_jobs_reject_input_update
BEFORE UPDATE OF
    call_id,
    run_id,
    approval_id,
    approval_event_sequence,
    approving_actor_user_id,
    tool_name,
    tool_version,
    effect,
    args_json,
    args_digest,
    policy_id,
    policy_revision,
    sandbox_profile,
    queued_at
ON dispatch_jobs
WHEN NOT (
    OLD.approving_actor_user_id IS NULL
    AND NEW.approving_actor_user_id IS NOT NULL
    AND NEW.call_id IS OLD.call_id
    AND NEW.run_id IS OLD.run_id
    AND NEW.approval_id IS OLD.approval_id
    AND NEW.approval_event_sequence IS OLD.approval_event_sequence
    AND NEW.tool_name IS OLD.tool_name
    AND NEW.tool_version IS OLD.tool_version
    AND NEW.effect IS OLD.effect
    AND NEW.args_json IS OLD.args_json
    AND NEW.args_digest IS OLD.args_digest
    AND NEW.policy_id IS OLD.policy_id
    AND NEW.policy_revision IS OLD.policy_revision
    AND NEW.sandbox_profile IS OLD.sandbox_profile
    AND NEW.status IS OLD.status
    AND NEW.attempt IS OLD.attempt
    AND NEW.result_json IS OLD.result_json
    AND NEW.authorization_error_json IS OLD.authorization_error_json
    AND NEW.queued_at IS OLD.queued_at
    AND NEW.started_at IS OLD.started_at
    AND NEW.finished_at IS OLD.finished_at
    AND NEW.start_event_sequence IS OLD.start_event_sequence
    AND NEW.result_event_sequence IS OLD.result_event_sequence
)
BEGIN
    SELECT RAISE(ABORT, 'dispatch job authorization is immutable');
END;

CREATE TRIGGER dispatch_jobs_require_owner_on_legacy_claim
BEFORE UPDATE OF approving_actor_user_id ON dispatch_jobs
WHEN OLD.approving_actor_user_id IS NULL
 AND NOT EXISTS (
     SELECT 1
     FROM runs r
     JOIN users u ON u.id = NEW.approving_actor_user_id
     WHERE r.id = NEW.run_id
       AND r.owner_user_id = NEW.approving_actor_user_id
       AND u.role = 'owner'
       AND u.status = 'active'
 )
BEGIN
    SELECT RAISE(ABORT, 'legacy dispatch must be claimed by its run owner');
END;

CREATE TRIGGER dispatch_jobs_enforce_forward_transition
BEFORE UPDATE ON dispatch_jobs
WHEN NOT (
    (OLD.status = 'queued' AND NEW.status IN ('started', 'rejected'))
    OR (OLD.status = 'started' AND NEW.status = 'finished')
    OR (
        OLD.approving_actor_user_id IS NULL
        AND NEW.approving_actor_user_id IS NOT NULL
        AND OLD.status = NEW.status
    )
)
BEGIN
    SELECT RAISE(ABORT, 'invalid dispatch job state transition');
END;

CREATE TRIGGER dispatch_jobs_reject_delete
BEFORE DELETE ON dispatch_jobs
BEGIN
    SELECT RAISE(ABORT, 'dispatch jobs are durable records');
END;

-- These relations are also checked in transactional code. Database triggers
-- prevent a future caller from creating cross-owner bindings by bypassing it.
CREATE TRIGGER session_runs_require_same_owner
BEFORE INSERT ON session_runs
WHEN (SELECT owner_user_id FROM sessions WHERE id = NEW.session_id)
     IS NOT (SELECT owner_user_id FROM runs WHERE id = NEW.run_id)
BEGIN
    SELECT RAISE(ABORT, 'session and run owners must match');
END;

CREATE TRIGGER reply_jobs_require_session_owner
BEFORE INSERT ON reply_jobs
WHEN NEW.actor_user_id
     IS NOT (SELECT owner_user_id FROM sessions WHERE id = NEW.session_id)
BEGIN
    SELECT RAISE(ABORT, 'reply actor must own the session');
END;

CREATE TRIGGER session_receipts_require_session_owner_on_insert
BEFORE INSERT ON session_command_receipts
WHEN NEW.actor_scope <> '__legacy__'
 AND NEW.actor_scope
     IS NOT (SELECT owner_user_id FROM sessions WHERE id = NEW.session_id)
BEGIN
    SELECT RAISE(ABORT, 'session receipt actor must own the session');
END;

CREATE TRIGGER session_receipts_require_session_owner_on_claim
BEFORE UPDATE OF actor_scope ON session_command_receipts
WHEN NEW.actor_scope <> '__legacy__'
 AND NEW.actor_scope
     IS NOT (SELECT owner_user_id FROM sessions WHERE id = NEW.session_id)
BEGIN
    SELECT RAISE(ABORT, 'legacy session receipt must be claimed by its session owner');
END;

CREATE TRIGGER run_receipts_require_run_owner_on_insert
BEFORE INSERT ON idempotency_receipts
WHEN NEW.actor_scope <> '__legacy__'
 AND NEW.actor_scope
     IS NOT (SELECT owner_user_id FROM runs WHERE id = NEW.run_id)
BEGIN
    SELECT RAISE(ABORT, 'run receipt actor must own the run');
END;

CREATE TRIGGER run_receipts_require_run_owner_on_claim
BEFORE UPDATE OF actor_scope ON idempotency_receipts
WHEN NEW.actor_scope <> '__legacy__'
 AND NEW.actor_scope
     IS NOT (SELECT owner_user_id FROM runs WHERE id = NEW.run_id)
BEGIN
    SELECT RAISE(ABORT, 'legacy run receipt must be claimed by its run owner');
END;

-- Claim every post-bootstrap legacy receipt only after owner-consistency
-- triggers are active. Unconfigured databases retain the sentinel until the
-- bootstrap transaction creates and claims their unique owner.
UPDATE session_command_receipts
SET actor_scope = (SELECT id FROM users WHERE role = 'owner')
WHERE actor_scope = '__legacy__'
  AND (SELECT COUNT(*) FROM users WHERE role = 'owner') = 1;

UPDATE idempotency_receipts
SET actor_scope = (SELECT id FROM users WHERE role = 'owner')
WHERE actor_scope = '__legacy__'
  AND (SELECT COUNT(*) FROM users WHERE role = 'owner') = 1;
