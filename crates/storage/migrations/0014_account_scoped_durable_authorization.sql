-- v14 makes the v13 account membership the sole durable authorization
-- authority.  The legacy users.role and resource owner_user_id columns remain
-- as creator metadata only; no v14 authorization trigger reads either field.

CREATE TABLE durable_authorization_preflight_gate (
    ok INTEGER NOT NULL CHECK (ok = 1)
) STRICT;

INSERT INTO durable_authorization_preflight_gate(ok)
SELECT CASE
    WHEN NOT EXISTS (SELECT 1 FROM pragma_foreign_key_check)
     AND (SELECT COUNT(*) FROM accounts) = 1
     AND EXISTS (
         SELECT 1 FROM accounts
         WHERE id = 'acc_local' AND status = 'active'
     )
     AND (
         (NOT EXISTS (SELECT 1 FROM users)
          AND NOT EXISTS (SELECT 1 FROM account_memberships)
          AND NOT EXISTS (SELECT 1 FROM auth_sessions))
         OR
         (SELECT COUNT(*)
          FROM account_memberships membership
          JOIN users user ON user.id = membership.user_id
          WHERE membership.account_id = 'acc_local'
            AND membership.role = 'owner'
            AND membership.status = 'active'
            AND user.status = 'active') = 1
     )
    THEN 1 ELSE 0 END;

DROP TABLE durable_authorization_preflight_gate;

-- A login session has a stable, non-secret identity and is bound to exactly
-- one account membership revision.  Legacy member sessions are deliberately
-- not copied: v13 did not authorize those users for acc_local.
DROP TRIGGER auth_sessions_reject_update;
DROP INDEX auth_sessions_user_idx;
DROP INDEX auth_sessions_expiry_idx;
ALTER TABLE auth_sessions RENAME TO auth_sessions_v13;

CREATE TABLE auth_sessions (
    id                  TEXT PRIMARY KEY
        CHECK (length(id) BETWEEN 1 AND 128 AND id = trim(id)),
    token_hash          TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64),
    account_id          TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    membership_revision INTEGER NOT NULL CHECK (membership_revision > 0),
    csrf_hash           TEXT NOT NULL CHECK (length(csrf_hash) = 64),
    created_at          TEXT NOT NULL,
    expires_at          TEXT NOT NULL,
    last_seen_at        TEXT NOT NULL,
    FOREIGN KEY (account_id, user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT
) STRICT;

INSERT INTO auth_sessions(
    id, token_hash, account_id, user_id, membership_revision, csrf_hash,
    created_at, expires_at, last_seen_at
)
SELECT
    'asi_legacy_' || lower(hex(randomblob(16))),
    session.token_hash,
    membership.account_id,
    session.user_id,
    membership.revision,
    session.csrf_hash,
    session.created_at,
    session.expires_at,
    session.last_seen_at
FROM auth_sessions_v13 session
JOIN users user
  ON user.id = session.user_id AND user.status = 'active'
JOIN account_memberships membership
  ON membership.user_id = session.user_id
 AND membership.account_id = 'acc_local'
 AND membership.status = 'active'
 AND membership.role = 'owner'
JOIN accounts account
  ON account.id = membership.account_id AND account.status = 'active';

DROP TABLE auth_sessions_v13;

CREATE INDEX auth_sessions_user_idx
    ON auth_sessions(account_id, user_id, expires_at, id);
CREATE INDEX auth_sessions_expiry_idx
    ON auth_sessions(expires_at, id);

CREATE TRIGGER auth_sessions_reject_duplicate_insert
BEFORE INSERT ON auth_sessions
WHEN EXISTS (
    SELECT 1 FROM auth_sessions
    WHERE id = NEW.id OR token_hash = NEW.token_hash
)
BEGIN
    SELECT RAISE(ABORT, 'authentication session identity already exists');
END;

CREATE TRIGGER auth_sessions_require_current_membership
BEFORE INSERT ON auth_sessions
WHEN NOT EXISTS (
    SELECT 1
    FROM accounts account
    JOIN account_memberships membership
      ON membership.account_id = account.id
    JOIN users user ON user.id = membership.user_id
    WHERE account.id = NEW.account_id
      AND account.status = 'active'
      AND membership.user_id = NEW.user_id
      AND membership.status = 'active'
      AND membership.revision = NEW.membership_revision
      AND user.status = 'active'
)
BEGIN
    SELECT RAISE(ABORT, 'authentication session requires a current active membership');
END;

CREATE TRIGGER auth_sessions_reject_update
BEFORE UPDATE ON auth_sessions
BEGIN
    SELECT RAISE(ABORT, 'auth sessions are immutable; rotate or revoke instead');
END;

-- Receipts are isolated by account and actor.  NULL actor is retained only for
-- the narrow pre-bootstrap internal-seed path; configured writes require an
-- active membership and every duplicate (including NULL) is rejected before
-- INSERT OR REPLACE conflict handling.
DROP TRIGGER session_command_receipts_reject_update;
DROP TRIGGER session_command_receipts_reject_delete;
DROP TRIGGER session_receipts_require_session_owner_on_insert;
DROP TRIGGER session_receipts_require_session_owner_on_claim;
ALTER TABLE session_command_receipts RENAME TO session_command_receipts_v13;

CREATE TABLE session_command_receipts (
    account_id          TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    actor_user_id       TEXT REFERENCES users(id) ON DELETE RESTRICT,
    idempotency_key     TEXT NOT NULL CHECK (length(trim(idempotency_key)) > 0),
    operation           TEXT NOT NULL CHECK (operation IN (
        'create_session', 'attach_run', 'start_turn', 'flush_turn', 'resume_session'
    )),
    request_fingerprint TEXT NOT NULL CHECK (json_valid(request_fingerprint)),
    response_json       TEXT NOT NULL CHECK (json_valid(response_json)),
    session_id          TEXT NOT NULL,
    event_sequence      INTEGER NOT NULL CHECK (event_sequence > 0),
    created_at          TEXT NOT NULL,
    FOREIGN KEY (account_id, actor_user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (session_id, event_sequence)
        REFERENCES session_events(session_id, sequence) ON DELETE RESTRICT
) STRICT;

INSERT INTO session_command_receipts(
    account_id, actor_user_id, idempotency_key, operation,
    request_fingerprint, response_json, session_id, event_sequence, created_at
)
SELECT
    session.account_id,
    CASE WHEN receipt.actor_scope = '__legacy__' THEN NULL ELSE receipt.actor_scope END,
    receipt.idempotency_key, receipt.operation, receipt.request_fingerprint,
    receipt.response_json, receipt.session_id, receipt.event_sequence, receipt.created_at
FROM session_command_receipts_v13 receipt
JOIN sessions session ON session.id = receipt.session_id;

DROP TABLE session_command_receipts_v13;

CREATE UNIQUE INDEX session_command_receipts_actor_key_idx
    ON session_command_receipts(account_id, actor_user_id, operation, idempotency_key)
    WHERE actor_user_id IS NOT NULL;
CREATE UNIQUE INDEX session_command_receipts_prebootstrap_key_idx
    ON session_command_receipts(account_id, operation, idempotency_key)
    WHERE actor_user_id IS NULL;

CREATE TRIGGER session_command_receipts_require_authority
BEFORE INSERT ON session_command_receipts
WHEN EXISTS (
        SELECT 1 FROM session_command_receipts receipt
        WHERE receipt.account_id = NEW.account_id
          AND receipt.actor_user_id IS NEW.actor_user_id
          AND receipt.operation = NEW.operation
          AND receipt.idempotency_key = NEW.idempotency_key
     )
  OR NOT EXISTS (
        SELECT 1 FROM sessions session
        WHERE session.id = NEW.session_id
          AND session.account_id = NEW.account_id
     )
  OR (
        NEW.actor_user_id IS NULL
        AND (NEW.account_id <> 'acc_local'
             OR EXISTS (SELECT 1 FROM users)
             OR EXISTS (SELECT 1 FROM account_memberships))
     )
  OR (
        NEW.actor_user_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1 FROM account_memberships membership
            JOIN users user ON user.id = membership.user_id
            JOIN accounts account ON account.id = membership.account_id
            WHERE membership.account_id = NEW.account_id
              AND membership.user_id = NEW.actor_user_id
              AND membership.status = 'active'
              AND user.status = 'active'
              AND account.status = 'active'
        )
     )
BEGIN
    SELECT RAISE(ABORT, 'session receipt requires its account actor and resource');
END;

CREATE TRIGGER session_command_receipts_reject_update
BEFORE UPDATE ON session_command_receipts
WHEN NOT (
    OLD.actor_user_id IS NULL
    AND NEW.actor_user_id IS NOT NULL
    AND NEW.account_id IS OLD.account_id
    AND NEW.idempotency_key IS OLD.idempotency_key
    AND NEW.operation IS OLD.operation
    AND NEW.request_fingerprint IS OLD.request_fingerprint
    AND NEW.response_json IS OLD.response_json
    AND NEW.session_id IS OLD.session_id
    AND NEW.event_sequence IS OLD.event_sequence
    AND NEW.created_at IS OLD.created_at
    AND EXISTS (
        SELECT 1
        FROM accounts account
        JOIN account_memberships membership
          ON membership.account_id = account.id
        JOIN users user ON user.id = membership.user_id
        JOIN sessions session
          ON session.id = NEW.session_id
         AND session.account_id = account.id
        WHERE account.id = NEW.account_id
          AND account.status = 'active'
          AND membership.user_id = NEW.actor_user_id
          AND membership.role = 'owner'
          AND membership.status = 'active'
          AND membership.revision = 1
          AND user.status = 'active'
    )
)
BEGIN
    SELECT RAISE(ABORT, 'session command receipts are immutable');
END;

CREATE TRIGGER session_command_receipts_reject_delete
BEFORE DELETE ON session_command_receipts
BEGIN
    SELECT RAISE(ABORT, 'session command receipts are durable');
END;

DROP TRIGGER idempotency_receipts_reject_update;
DROP TRIGGER idempotency_receipts_reject_delete;
DROP TRIGGER run_receipts_require_run_owner_on_insert;
DROP TRIGGER run_receipts_require_run_owner_on_claim;
ALTER TABLE idempotency_receipts RENAME TO idempotency_receipts_v13;

CREATE TABLE idempotency_receipts (
    account_id          TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    actor_user_id       TEXT REFERENCES users(id) ON DELETE RESTRICT,
    idempotency_key     TEXT NOT NULL CHECK (length(trim(idempotency_key)) > 0),
    operation           TEXT NOT NULL CHECK (operation = 'review'),
    request_fingerprint TEXT NOT NULL CHECK (json_valid(request_fingerprint)),
    response_json       TEXT NOT NULL CHECK (json_valid(response_json)),
    run_id              TEXT NOT NULL,
    event_sequence      INTEGER NOT NULL CHECK (event_sequence > 0),
    created_at          TEXT NOT NULL,
    FOREIGN KEY (account_id, actor_user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, event_sequence)
        REFERENCES run_events(run_id, sequence) ON DELETE RESTRICT
) STRICT;

INSERT INTO idempotency_receipts(
    account_id, actor_user_id, idempotency_key, operation,
    request_fingerprint, response_json, run_id, event_sequence, created_at
)
SELECT
    run.account_id,
    CASE WHEN receipt.actor_scope = '__legacy__' THEN NULL ELSE receipt.actor_scope END,
    receipt.idempotency_key, receipt.operation, receipt.request_fingerprint,
    receipt.response_json, receipt.run_id, receipt.event_sequence, receipt.created_at
FROM idempotency_receipts_v13 receipt
JOIN runs run ON run.id = receipt.run_id;

DROP TABLE idempotency_receipts_v13;

CREATE UNIQUE INDEX idempotency_receipts_actor_key_idx
    ON idempotency_receipts(account_id, actor_user_id, operation, idempotency_key)
    WHERE actor_user_id IS NOT NULL;
CREATE UNIQUE INDEX idempotency_receipts_prebootstrap_key_idx
    ON idempotency_receipts(account_id, operation, idempotency_key)
    WHERE actor_user_id IS NULL;

CREATE TRIGGER idempotency_receipts_require_authority
BEFORE INSERT ON idempotency_receipts
WHEN EXISTS (
        SELECT 1 FROM idempotency_receipts receipt
        WHERE receipt.account_id = NEW.account_id
          AND receipt.actor_user_id IS NEW.actor_user_id
          AND receipt.operation = NEW.operation
          AND receipt.idempotency_key = NEW.idempotency_key
     )
  OR NOT EXISTS (
        SELECT 1 FROM runs run
        WHERE run.id = NEW.run_id AND run.account_id = NEW.account_id
     )
  OR (
        NEW.actor_user_id IS NULL
        AND (NEW.account_id <> 'acc_local'
             OR EXISTS (SELECT 1 FROM users)
             OR EXISTS (SELECT 1 FROM account_memberships))
     )
  OR (
        NEW.actor_user_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1 FROM account_memberships membership
            JOIN users user ON user.id = membership.user_id
            JOIN accounts account ON account.id = membership.account_id
            WHERE membership.account_id = NEW.account_id
              AND membership.user_id = NEW.actor_user_id
              AND membership.status = 'active'
              AND membership.role = 'owner'
              AND user.status = 'active'
              AND account.status = 'active'
        )
     )
BEGIN
    SELECT RAISE(ABORT, 'run receipt requires its account actor and resource');
END;

CREATE TRIGGER idempotency_receipts_reject_update
BEFORE UPDATE ON idempotency_receipts
WHEN NOT (
    OLD.actor_user_id IS NULL
    AND NEW.actor_user_id IS NOT NULL
    AND NEW.account_id IS OLD.account_id
    AND NEW.idempotency_key IS OLD.idempotency_key
    AND NEW.operation IS OLD.operation
    AND NEW.request_fingerprint IS OLD.request_fingerprint
    AND NEW.response_json IS OLD.response_json
    AND NEW.run_id IS OLD.run_id
    AND NEW.event_sequence IS OLD.event_sequence
    AND NEW.created_at IS OLD.created_at
    AND EXISTS (
        SELECT 1
        FROM accounts account
        JOIN account_memberships membership
          ON membership.account_id = account.id
        JOIN users user ON user.id = membership.user_id
        JOIN runs run ON run.id = NEW.run_id AND run.account_id = account.id
        WHERE account.id = NEW.account_id
          AND account.status = 'active'
          AND membership.user_id = NEW.actor_user_id
          AND membership.role = 'owner'
          AND membership.status = 'active'
          AND membership.revision = 1
          AND user.status = 'active'
    )
)
BEGIN
    SELECT RAISE(ABORT, 'idempotency receipts are immutable');
END;

CREATE TRIGGER idempotency_receipts_reject_delete
BEFORE DELETE ON idempotency_receipts
BEGIN
    SELECT RAISE(ABORT, 'idempotency receipts are durable');
END;

-- Rebuild jobs and their child reservations as one graph.  Historical v13
-- configured work receives revision 1 from the durable owner membership.
DROP TRIGGER session_runs_require_same_owner;
DROP TRIGGER reply_jobs_require_session_owner;
DROP TRIGGER reply_jobs_reject_input_update;
DROP TRIGGER reply_jobs_enforce_forward_transition;
DROP TRIGGER reply_jobs_reject_delete;
DROP TRIGGER dispatch_jobs_require_actor_on_insert;
DROP TRIGGER dispatch_jobs_reject_input_update;
DROP TRIGGER dispatch_jobs_require_owner_on_legacy_claim;
DROP TRIGGER dispatch_jobs_enforce_forward_transition;
DROP TRIGGER dispatch_jobs_reject_delete;
DROP TRIGGER finalization_reservations_require_dispatch_binding;
DROP TRIGGER finalization_reservations_require_resource_scope_on_insert;
DROP TRIGGER finalization_reservations_require_resource_scope_on_claim;
DROP TRIGGER finalization_reservations_require_event_payload_capacity_on_insert;
DROP TRIGGER finalization_reservations_enforce_update;
DROP TRIGGER finalization_reservations_reject_live_delete;

DROP INDEX reply_jobs_ready_idx;
DROP INDEX reply_jobs_actor_idx;
DROP INDEX reply_jobs_started_idx;
DROP INDEX dispatch_jobs_ready_idx;
DROP INDEX dispatch_jobs_run_idx;
DROP INDEX dispatch_jobs_actor_idx;
DROP INDEX dispatch_jobs_started_idx;
DROP INDEX finalization_reservations_turn_idx;
DROP INDEX finalization_reservations_dispatch_idx;
DROP INDEX finalization_reservations_scope_active_idx;
DROP INDEX finalization_reservations_kind_active_idx;

ALTER TABLE finalization_reservations RENAME TO finalization_reservations_v13;
ALTER TABLE reply_jobs RENAME TO reply_jobs_v13;
ALTER TABLE dispatch_jobs RENAME TO dispatch_jobs_v13;

CREATE TABLE reply_jobs (
    id                          TEXT PRIMARY KEY CHECK (length(trim(id)) > 0),
    account_id                  TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    actor_user_id               TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    actor_membership_revision   INTEGER NOT NULL CHECK (actor_membership_revision > 0),
    session_id                  TEXT NOT NULL,
    turn_id                     TEXT NOT NULL,
    provider_name               TEXT NOT NULL CHECK (length(trim(provider_name)) > 0),
    model_name                  TEXT,
    status                      TEXT NOT NULL CHECK (
        status IN ('queued', 'started', 'succeeded', 'failed', 'outcome_unknown')
    ),
    attempt                     INTEGER NOT NULL CHECK (attempt IN (0, 1)),
    request_json                TEXT NOT NULL CHECK (json_valid(request_json)),
    response_json               TEXT CHECK (response_json IS NULL OR json_valid(response_json)),
    error_json                  TEXT CHECK (error_json IS NULL OR json_valid(error_json)),
    completion_fingerprint      TEXT CHECK (
        completion_fingerprint IS NULL OR json_valid(completion_fingerprint)
    ),
    assistant_event_sequence    INTEGER,
    terminal_event_sequence     INTEGER,
    queued_at                   TEXT NOT NULL,
    started_at                  TEXT,
    finished_at                 TEXT,
    UNIQUE (session_id, turn_id),
    FOREIGN KEY (account_id, actor_user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (session_id, turn_id)
        REFERENCES session_turns(session_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (session_id, assistant_event_sequence)
        REFERENCES session_events(session_id, sequence) ON DELETE RESTRICT,
    FOREIGN KEY (session_id, terminal_event_sequence)
        REFERENCES session_events(session_id, sequence) ON DELETE RESTRICT,
    CHECK (model_name IS NULL OR length(trim(model_name)) > 0),
    CHECK (
        (status = 'queued' AND attempt = 0 AND response_json IS NULL
         AND error_json IS NULL AND completion_fingerprint IS NULL
         AND assistant_event_sequence IS NULL AND terminal_event_sequence IS NULL
         AND started_at IS NULL AND finished_at IS NULL)
        OR
        (status = 'started' AND attempt = 1 AND response_json IS NULL
         AND error_json IS NULL AND completion_fingerprint IS NULL
         AND assistant_event_sequence IS NULL AND terminal_event_sequence IS NULL
         AND started_at IS NOT NULL AND finished_at IS NULL)
        OR
        (status = 'succeeded' AND attempt = 1 AND response_json IS NOT NULL
         AND error_json IS NULL AND completion_fingerprint IS NOT NULL
         AND assistant_event_sequence IS NOT NULL
         AND terminal_event_sequence = assistant_event_sequence + 1
         AND started_at IS NOT NULL AND finished_at IS NOT NULL)
        OR
        (status IN ('failed', 'outcome_unknown') AND attempt = 1
         AND response_json IS NULL AND error_json IS NOT NULL
         AND completion_fingerprint IS NOT NULL
         AND assistant_event_sequence IS NULL AND terminal_event_sequence IS NOT NULL
         AND started_at IS NOT NULL AND finished_at IS NOT NULL)
    )
) STRICT;

INSERT INTO reply_jobs(
    id, account_id, actor_user_id, actor_membership_revision,
    session_id, turn_id, provider_name, model_name, status, attempt,
    request_json, response_json, error_json, completion_fingerprint,
    assistant_event_sequence, terminal_event_sequence,
    queued_at, started_at, finished_at
)
SELECT
    job.id, session.account_id, job.actor_user_id, membership.revision,
    job.session_id, job.turn_id, job.provider_name, job.model_name,
    job.status, job.attempt, job.request_json, job.response_json, job.error_json,
    job.completion_fingerprint, job.assistant_event_sequence,
    job.terminal_event_sequence, job.queued_at, job.started_at, job.finished_at
FROM reply_jobs_v13 job
JOIN sessions session ON session.id = job.session_id
JOIN account_memberships membership
  ON membership.account_id = session.account_id
 AND membership.user_id = job.actor_user_id;

CREATE INDEX reply_jobs_ready_idx ON reply_jobs(status, queued_at, id);
CREATE INDEX reply_jobs_actor_idx
    ON reply_jobs(account_id, actor_user_id, status, queued_at, id);
CREATE INDEX reply_jobs_account_idx
    ON reply_jobs(account_id, status, queued_at, id);
CREATE INDEX reply_jobs_started_idx
    ON reply_jobs(status, started_at, id);

CREATE TABLE dispatch_jobs (
    call_id                        TEXT PRIMARY KEY CHECK (length(trim(call_id)) > 0),
    account_id                     TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    run_id                         TEXT NOT NULL,
    approval_id                    TEXT NOT NULL UNIQUE CHECK (length(trim(approval_id)) > 0),
    approval_event_sequence        INTEGER NOT NULL CHECK (approval_event_sequence > 0),
    initiating_actor_user_id       TEXT REFERENCES users(id) ON DELETE RESTRICT,
    initiating_membership_revision INTEGER CHECK (initiating_membership_revision > 0),
    approving_actor_user_id        TEXT REFERENCES users(id) ON DELETE RESTRICT,
    approving_membership_revision  INTEGER CHECK (approving_membership_revision > 0),
    tool_name                      TEXT NOT NULL CHECK (length(trim(tool_name)) > 0),
    tool_version                   TEXT NOT NULL CHECK (length(trim(tool_version)) > 0),
    effect                         TEXT NOT NULL CHECK (
        effect IN ('read_only', 'local_write', 'production_write', 'destructive')
    ),
    args_json                      TEXT NOT NULL CHECK (json_valid(args_json)),
    args_digest                    TEXT NOT NULL CHECK (length(trim(args_digest)) > 0),
    policy_id                      TEXT NOT NULL CHECK (length(trim(policy_id)) > 0),
    policy_revision                TEXT NOT NULL CHECK (length(trim(policy_revision)) > 0),
    sandbox_profile                TEXT NOT NULL CHECK (
        sandbox_profile IN ('read_only', 'workspace_write', 'isolated_container', 'production_guarded')
    ),
    status                         TEXT NOT NULL CHECK (
        status IN ('queued', 'started', 'finished', 'rejected')
    ),
    attempt                        INTEGER NOT NULL CHECK (attempt IN (0, 1)),
    result_json                    TEXT CHECK (result_json IS NULL OR json_valid(result_json)),
    authorization_error_json       TEXT CHECK (
        authorization_error_json IS NULL OR json_valid(authorization_error_json)
    ),
    queued_at                      TEXT NOT NULL,
    started_at                     TEXT,
    finished_at                    TEXT,
    start_event_sequence           INTEGER CHECK (start_event_sequence > 0),
    result_event_sequence          INTEGER CHECK (result_event_sequence > 0),
    FOREIGN KEY (account_id, initiating_actor_user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (account_id, approving_actor_user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, approval_event_sequence)
        REFERENCES run_events(run_id, sequence) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, start_event_sequence)
        REFERENCES run_events(run_id, sequence) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, result_event_sequence)
        REFERENCES run_events(run_id, sequence) ON DELETE RESTRICT,
    CHECK (
        (initiating_actor_user_id IS NULL
         AND initiating_membership_revision IS NULL
         AND approving_actor_user_id IS NULL
         AND approving_membership_revision IS NULL)
        OR
        (initiating_actor_user_id IS NOT NULL
         AND initiating_membership_revision IS NOT NULL
         AND approving_actor_user_id IS NOT NULL
         AND approving_membership_revision IS NOT NULL)
    ),
    CHECK (
        (status = 'queued' AND attempt = 0 AND result_json IS NULL
         AND authorization_error_json IS NULL AND started_at IS NULL
         AND finished_at IS NULL AND start_event_sequence IS NULL
         AND result_event_sequence IS NULL)
        OR
        (status = 'started' AND attempt = 1 AND result_json IS NULL
         AND authorization_error_json IS NULL AND started_at IS NOT NULL
         AND finished_at IS NULL AND start_event_sequence IS NOT NULL
         AND result_event_sequence IS NULL)
        OR
        (status = 'finished' AND attempt = 1 AND result_json IS NOT NULL
         AND authorization_error_json IS NULL AND started_at IS NOT NULL
         AND finished_at IS NOT NULL AND start_event_sequence IS NOT NULL
         AND result_event_sequence IS NOT NULL)
        OR
        (status = 'rejected' AND attempt = 0 AND result_json IS NOT NULL
         AND authorization_error_json IS NOT NULL AND started_at IS NULL
         AND finished_at IS NOT NULL AND start_event_sequence IS NULL
         AND result_event_sequence IS NOT NULL)
    )
) STRICT;

INSERT INTO dispatch_jobs(
    call_id, account_id, run_id, approval_id, approval_event_sequence,
    initiating_actor_user_id, initiating_membership_revision,
    approving_actor_user_id, approving_membership_revision,
    tool_name, tool_version, effect, args_json, args_digest, policy_id,
    policy_revision, sandbox_profile, status, attempt, result_json,
    authorization_error_json, queued_at, started_at, finished_at,
    start_event_sequence, result_event_sequence
)
SELECT
    job.call_id, run.account_id, job.run_id, job.approval_id,
    job.approval_event_sequence,
    job.approving_actor_user_id, membership.revision,
    job.approving_actor_user_id, membership.revision,
    job.tool_name, job.tool_version, job.effect, job.args_json, job.args_digest,
    job.policy_id, job.policy_revision, job.sandbox_profile, job.status,
    job.attempt, job.result_json, job.authorization_error_json, job.queued_at,
    job.started_at, job.finished_at, job.start_event_sequence,
    job.result_event_sequence
FROM dispatch_jobs_v13 job
JOIN runs run ON run.id = job.run_id
LEFT JOIN account_memberships membership
  ON membership.account_id = run.account_id
 AND membership.user_id = job.approving_actor_user_id;

CREATE INDEX dispatch_jobs_ready_idx
    ON dispatch_jobs(status, queued_at, call_id);
CREATE INDEX dispatch_jobs_run_idx
    ON dispatch_jobs(account_id, run_id, status, call_id);
CREATE INDEX dispatch_jobs_actor_idx
    ON dispatch_jobs(account_id, approving_actor_user_id, status, queued_at, call_id);
CREATE INDEX dispatch_jobs_initiator_idx
    ON dispatch_jobs(account_id, initiating_actor_user_id, status, queued_at, call_id);
CREATE INDEX dispatch_jobs_account_idx
    ON dispatch_jobs(account_id, status, queued_at, call_id);
CREATE INDEX dispatch_jobs_started_idx
    ON dispatch_jobs(status, started_at, call_id);

CREATE TABLE finalization_reservations (
    kind                          TEXT NOT NULL CHECK (kind IN ('session_turn', 'dispatch')),
    account_id                    TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    actor_user_id                 TEXT REFERENCES users(id) ON DELETE RESTRICT,
    session_id                    TEXT,
    turn_id                       TEXT,
    run_id                        TEXT,
    call_id                       TEXT,
    remaining_event_slots         INTEGER NOT NULL CHECK (remaining_event_slots BETWEEN 0 AND 2),
    reserved_bytes                INTEGER CHECK (reserved_bytes IS NULL),
    created_at                    TEXT NOT NULL,
    remaining_event_payload_bytes INTEGER NOT NULL CHECK (remaining_event_payload_bytes >= 0),
    FOREIGN KEY (account_id, actor_user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (session_id, turn_id)
        REFERENCES session_turns(session_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE RESTRICT,
    FOREIGN KEY (call_id) REFERENCES dispatch_jobs(call_id) ON DELETE RESTRICT,
    CHECK (
        (kind = 'session_turn' AND session_id IS NOT NULL AND turn_id IS NOT NULL
         AND run_id IS NULL AND call_id IS NULL)
        OR
        (kind = 'dispatch' AND session_id IS NULL AND turn_id IS NULL
         AND run_id IS NOT NULL AND call_id IS NOT NULL)
    )
) STRICT;

INSERT INTO finalization_reservations(
    kind, account_id, actor_user_id, session_id, turn_id, run_id, call_id,
    remaining_event_slots, reserved_bytes, created_at,
    remaining_event_payload_bytes
)
SELECT
    reservation.kind,
    CASE reservation.kind WHEN 'session_turn' THEN session.account_id ELSE run.account_id END,
    CASE WHEN reservation.scope_id = '__legacy__' THEN NULL ELSE reservation.scope_id END,
    reservation.session_id, reservation.turn_id, reservation.run_id,
    reservation.call_id, reservation.remaining_event_slots,
    reservation.reserved_bytes, reservation.created_at,
    reservation.remaining_event_payload_bytes
FROM finalization_reservations_v13 reservation
LEFT JOIN sessions session
  ON reservation.kind = 'session_turn' AND session.id = reservation.session_id
LEFT JOIN runs run
  ON reservation.kind = 'dispatch' AND run.id = reservation.run_id;

DROP TABLE finalization_reservations_v13;
DROP TABLE reply_jobs_v13;
DROP TABLE dispatch_jobs_v13;

CREATE UNIQUE INDEX finalization_reservations_turn_idx
    ON finalization_reservations(session_id, turn_id) WHERE kind = 'session_turn';
CREATE UNIQUE INDEX finalization_reservations_dispatch_idx
    ON finalization_reservations(run_id, call_id) WHERE kind = 'dispatch';
CREATE INDEX finalization_reservations_actor_active_idx
    ON finalization_reservations(account_id, actor_user_id, kind, remaining_event_slots)
    WHERE remaining_event_slots > 0;
CREATE INDEX finalization_reservations_account_active_idx
    ON finalization_reservations(account_id, kind, remaining_event_slots)
    WHERE remaining_event_slots > 0;
CREATE INDEX finalization_reservations_kind_active_idx
    ON finalization_reservations(kind, remaining_event_slots)
    WHERE remaining_event_slots > 0;

CREATE TRIGGER reply_jobs_require_authority
BEFORE INSERT ON reply_jobs
WHEN EXISTS (
        SELECT 1 FROM reply_jobs job
        WHERE job.id = NEW.id
           OR (job.session_id = NEW.session_id AND job.turn_id = NEW.turn_id)
     )
  OR NOT EXISTS (
        SELECT 1
        FROM sessions session
        JOIN accounts account ON account.id = session.account_id
        JOIN account_memberships membership
          ON membership.account_id = session.account_id
        JOIN users user ON user.id = membership.user_id
        WHERE session.id = NEW.session_id
          AND session.account_id = NEW.account_id
          AND account.status = 'active'
          AND membership.user_id = NEW.actor_user_id
          AND membership.revision = NEW.actor_membership_revision
          AND membership.status = 'active'
          AND user.status = 'active'
     )
  OR NOT EXISTS (
        SELECT 1 FROM finalization_reservations reservation
        WHERE reservation.kind = 'session_turn'
          AND reservation.account_id = NEW.account_id
          AND reservation.actor_user_id = NEW.actor_user_id
          AND reservation.session_id = NEW.session_id
          AND reservation.turn_id = NEW.turn_id
          AND reservation.remaining_event_slots = 2
          AND reservation.remaining_event_payload_bytes = CASE
              WHEN length(CAST(NEW.turn_id AS BLOB))
                   > ((9223372036854775807 - 524288) / 6) / 2
              THEN 9223372036854775807
              ELSE CASE
                  WHEN length(CAST(NEW.provider_name AS BLOB))
                       > (9223372036854775807 - 524288) / 6
                          - 2 * length(CAST(NEW.turn_id AS BLOB))
                  THEN 9223372036854775807
                  ELSE CASE
                      WHEN length(CAST(COALESCE(NEW.model_name, '') AS BLOB))
                           > (9223372036854775807 - 524288) / 6
                              - 2 * length(CAST(NEW.turn_id AS BLOB))
                              - length(CAST(NEW.provider_name AS BLOB))
                      THEN 9223372036854775807
                      ELSE 524288 + 6 * (
                          2 * length(CAST(NEW.turn_id AS BLOB))
                          + length(CAST(NEW.provider_name AS BLOB))
                          + length(CAST(COALESCE(NEW.model_name, '') AS BLOB))
                      )
                  END
              END
          END
     )
BEGIN
    SELECT RAISE(ABORT, 'reply job requires current account authority and reservation');
END;

CREATE TRIGGER reply_jobs_reject_input_update
BEFORE UPDATE OF id, account_id, actor_user_id, actor_membership_revision,
    session_id, turn_id, provider_name, model_name, request_json, queued_at
ON reply_jobs
BEGIN
    SELECT RAISE(ABORT, 'reply job authorization and input are immutable');
END;

CREATE TRIGGER reply_jobs_enforce_forward_transition
BEFORE UPDATE ON reply_jobs
WHEN NOT ((OLD.status = 'queued' AND NEW.status = 'started')
       OR (OLD.status = 'started' AND NEW.status IN ('succeeded', 'failed', 'outcome_unknown')))
BEGIN
    SELECT RAISE(ABORT, 'invalid reply job state transition');
END;

CREATE TRIGGER reply_jobs_reject_delete
BEFORE DELETE ON reply_jobs
BEGIN
    SELECT RAISE(ABORT, 'reply jobs are durable records');
END;

CREATE TRIGGER dispatch_jobs_require_authority
BEFORE INSERT ON dispatch_jobs
WHEN EXISTS (
        SELECT 1 FROM dispatch_jobs job
        WHERE job.call_id = NEW.call_id OR job.approval_id = NEW.approval_id
     )
  OR NOT EXISTS (
        SELECT 1 FROM runs run
        JOIN accounts account ON account.id = run.account_id
        WHERE run.id = NEW.run_id AND run.account_id = NEW.account_id
          AND account.status = 'active'
     )
  OR (
        NEW.initiating_actor_user_id IS NULL
        AND (
            NEW.account_id <> 'acc_local'
            OR NEW.approving_actor_user_id IS NOT NULL
            OR NEW.initiating_membership_revision IS NOT NULL
            OR NEW.approving_membership_revision IS NOT NULL
            OR EXISTS (SELECT 1 FROM users)
            OR EXISTS (SELECT 1 FROM account_memberships)
        )
     )
  OR (
        NEW.initiating_actor_user_id IS NOT NULL
        AND (
          NEW.approving_actor_user_id IS NULL
          OR NOT EXISTS (
        SELECT 1
        FROM account_memberships membership
        JOIN users user ON user.id = membership.user_id
        WHERE membership.account_id = NEW.account_id
          AND membership.user_id = NEW.initiating_actor_user_id
          AND membership.revision = NEW.initiating_membership_revision
          AND membership.status = 'active'
          AND user.status = 'active'
          )
          OR NOT EXISTS (
        SELECT 1
        FROM account_memberships membership
        JOIN users user ON user.id = membership.user_id
        WHERE membership.account_id = NEW.account_id
          AND membership.user_id = NEW.approving_actor_user_id
          AND membership.revision = NEW.approving_membership_revision
          AND membership.role = 'owner'
          AND membership.status = 'active'
          AND user.status = 'active'
          )
        )
     )
BEGIN
    SELECT RAISE(ABORT, 'dispatch requires current initiating and approving authority');
END;

CREATE TRIGGER dispatch_jobs_reject_input_update
BEFORE UPDATE OF call_id, account_id, run_id, approval_id,
    approval_event_sequence, initiating_actor_user_id,
    initiating_membership_revision, approving_actor_user_id,
    approving_membership_revision, tool_name, tool_version, effect,
    args_json, args_digest, policy_id, policy_revision, sandbox_profile, queued_at
ON dispatch_jobs
WHEN NOT (
    OLD.initiating_actor_user_id IS NULL
    AND OLD.initiating_membership_revision IS NULL
    AND OLD.approving_actor_user_id IS NULL
    AND OLD.approving_membership_revision IS NULL
    AND NEW.initiating_actor_user_id IS NOT NULL
    AND NEW.initiating_actor_user_id IS NEW.approving_actor_user_id
    AND NEW.initiating_membership_revision = 1
    AND NEW.approving_membership_revision = 1
    AND NEW.call_id IS OLD.call_id
    AND NEW.account_id IS OLD.account_id
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
    AND NEW.queued_at IS OLD.queued_at
    AND EXISTS (
        SELECT 1
        FROM runs run
        JOIN accounts account ON account.id = run.account_id
        JOIN account_memberships membership
          ON membership.account_id = account.id
        JOIN users user ON user.id = membership.user_id
        WHERE run.id = NEW.run_id
          AND run.account_id = NEW.account_id
          AND account.status = 'active'
          AND membership.user_id = NEW.approving_actor_user_id
          AND membership.role = 'owner'
          AND membership.status = 'active'
          AND membership.revision = 1
          AND user.status = 'active'
    )
)
BEGIN
    SELECT RAISE(ABORT, 'dispatch job authorization and input are immutable');
END;

CREATE TRIGGER dispatch_jobs_enforce_forward_transition
BEFORE UPDATE ON dispatch_jobs
WHEN NOT ((OLD.status = 'queued' AND NEW.status IN ('started', 'rejected'))
       OR (OLD.status = 'started' AND NEW.status = 'finished')
       OR (
           OLD.initiating_actor_user_id IS NULL
           AND OLD.approving_actor_user_id IS NULL
           AND NEW.initiating_actor_user_id IS NOT NULL
           AND NEW.initiating_actor_user_id IS NEW.approving_actor_user_id
           AND NEW.initiating_membership_revision = 1
           AND NEW.approving_membership_revision = 1
           AND NEW.status IS OLD.status
           AND NEW.attempt IS OLD.attempt
           AND NEW.result_json IS OLD.result_json
           AND NEW.authorization_error_json IS OLD.authorization_error_json
           AND NEW.started_at IS OLD.started_at
           AND NEW.finished_at IS OLD.finished_at
           AND NEW.start_event_sequence IS OLD.start_event_sequence
           AND NEW.result_event_sequence IS OLD.result_event_sequence
       ))
BEGIN
    SELECT RAISE(ABORT, 'invalid dispatch job state transition');
END;

CREATE TRIGGER dispatch_jobs_reject_delete
BEFORE DELETE ON dispatch_jobs
BEGIN
    SELECT RAISE(ABORT, 'dispatch jobs are durable records');
END;

CREATE TRIGGER finalization_reservations_require_authority
BEFORE INSERT ON finalization_reservations
WHEN EXISTS (
        SELECT 1 FROM finalization_reservations reservation
        WHERE (NEW.kind = 'session_turn'
               AND reservation.kind = 'session_turn'
               AND reservation.session_id = NEW.session_id
               AND reservation.turn_id = NEW.turn_id)
           OR (NEW.kind = 'dispatch'
               AND reservation.kind = 'dispatch'
               AND reservation.run_id = NEW.run_id
               AND reservation.call_id = NEW.call_id)
     )
  OR NOT (
        (NEW.kind = 'session_turn' AND EXISTS (
            SELECT 1 FROM sessions session
            WHERE session.id = NEW.session_id
              AND session.account_id = NEW.account_id
        ))
        OR
        (NEW.kind = 'dispatch' AND EXISTS (
            SELECT 1 FROM dispatch_jobs job
            WHERE job.call_id = NEW.call_id
              AND job.run_id = NEW.run_id
              AND job.account_id = NEW.account_id
              AND job.initiating_actor_user_id IS NEW.actor_user_id
        ))
     )
  OR (
        NEW.actor_user_id IS NULL
        AND (NEW.account_id <> 'acc_local'
             OR EXISTS (SELECT 1 FROM users)
             OR EXISTS (SELECT 1 FROM account_memberships))
     )
  OR (
        NEW.actor_user_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1
            FROM account_memberships membership
            JOIN users user ON user.id = membership.user_id
            JOIN accounts account ON account.id = membership.account_id
            WHERE membership.account_id = NEW.account_id
              AND membership.user_id = NEW.actor_user_id
              AND membership.status = 'active'
              AND user.status = 'active'
              AND account.status = 'active'
        )
     )
BEGIN
    SELECT RAISE(ABORT, 'reservation requires its account actor and durable work');
END;

CREATE TRIGGER finalization_reservations_require_event_payload_capacity_on_insert
BEFORE INSERT ON finalization_reservations
WHEN NOT (
    (NEW.kind = 'session_turn'
        AND NEW.remaining_event_slots = 2
        AND (
            (NOT EXISTS (
                SELECT 1
                FROM reply_jobs job
                WHERE job.session_id = NEW.session_id
                  AND job.turn_id = NEW.turn_id
            )
                AND NEW.remaining_event_payload_bytes >= CASE
                    WHEN length(CAST(NEW.turn_id AS BLOB))
                         > (9223372036854775807 - 524288) / 12
                    THEN 9223372036854775807
                    ELSE 524288 + 12 * length(CAST(NEW.turn_id AS BLOB))
                END)
            OR
            EXISTS (
                SELECT 1
                FROM reply_jobs job
                WHERE job.session_id = NEW.session_id
                  AND job.turn_id = NEW.turn_id
                  AND NEW.remaining_event_payload_bytes = CASE
                      WHEN length(CAST(NEW.turn_id AS BLOB))
                           > ((9223372036854775807 - 524288) / 6) / 2
                      THEN 9223372036854775807
                      ELSE CASE
                          WHEN length(CAST(job.provider_name AS BLOB))
                               > (9223372036854775807 - 524288) / 6
                                  - 2 * length(CAST(NEW.turn_id AS BLOB))
                          THEN 9223372036854775807
                          ELSE CASE
                              WHEN length(CAST(COALESCE(job.model_name, '') AS BLOB))
                                   > (9223372036854775807 - 524288) / 6
                                      - 2 * length(CAST(NEW.turn_id AS BLOB))
                                      - length(CAST(job.provider_name AS BLOB))
                              THEN 9223372036854775807
                              ELSE 524288 + 6 * (
                                  2 * length(CAST(NEW.turn_id AS BLOB))
                                  + length(CAST(job.provider_name AS BLOB))
                                  + length(CAST(COALESCE(job.model_name, '') AS BLOB))
                              )
                          END
                      END
                  END
            )
        )
        AND EXISTS (
            SELECT 1
            FROM session_turns turn
            WHERE turn.session_id = NEW.session_id
              AND turn.id = NEW.turn_id
              AND turn.status = 'open'
        ))
    OR
    (NEW.kind = 'dispatch'
        AND NEW.remaining_event_slots = 2
        AND NEW.remaining_event_payload_bytes = CASE
            WHEN length(CAST(NEW.call_id AS BLOB))
                 > (9223372036854775807 - 98304) / 12
            THEN 9223372036854775807
            ELSE 98304 + 12 * length(CAST(NEW.call_id AS BLOB))
        END
        AND EXISTS (
            SELECT 1
            FROM dispatch_jobs job
            WHERE job.run_id = NEW.run_id
              AND job.call_id = NEW.call_id
              AND job.status = 'queued'
        ))
)
BEGIN
    SELECT RAISE(ABORT, 'new reservation capacity does not match its durable work');
END;

CREATE TRIGGER finalization_reservations_enforce_update
BEFORE UPDATE ON finalization_reservations
WHEN NOT (
    NEW.kind IS OLD.kind
    AND NEW.account_id IS OLD.account_id
    AND NEW.session_id IS OLD.session_id
    AND NEW.turn_id IS OLD.turn_id
    AND NEW.run_id IS OLD.run_id
    AND NEW.call_id IS OLD.call_id
    AND NEW.reserved_bytes IS OLD.reserved_bytes
    AND NEW.created_at IS OLD.created_at
    AND (
        (OLD.actor_user_id IS NULL
            AND NEW.actor_user_id IS NOT NULL
            AND NEW.remaining_event_slots = OLD.remaining_event_slots
            AND NEW.remaining_event_payload_bytes = OLD.remaining_event_payload_bytes
            AND EXISTS (
                SELECT 1
                FROM accounts account
                JOIN account_memberships membership
                  ON membership.account_id = account.id
                JOIN users user ON user.id = membership.user_id
                WHERE account.id = NEW.account_id
                  AND account.status = 'active'
                  AND membership.user_id = NEW.actor_user_id
                  AND membership.role = 'owner'
                  AND membership.status = 'active'
                  AND membership.revision = 1
                  AND user.status = 'active'
            )
            AND (
                (NEW.kind = 'session_turn' AND EXISTS (
                    SELECT 1 FROM sessions session
                    WHERE session.id = NEW.session_id
                      AND session.account_id = NEW.account_id
                ))
                OR
                (NEW.kind = 'dispatch' AND EXISTS (
                    SELECT 1 FROM dispatch_jobs job
                    WHERE job.call_id = NEW.call_id
                      AND job.run_id = NEW.run_id
                      AND job.account_id = NEW.account_id
                      AND job.initiating_actor_user_id = NEW.actor_user_id
                      AND job.initiating_membership_revision = 1
                      AND job.approving_actor_user_id = NEW.actor_user_id
                      AND job.approving_membership_revision = 1
                ))
            ))
        OR
        (NEW.actor_user_id IS OLD.actor_user_id
            AND NEW.remaining_event_payload_bytes < OLD.remaining_event_payload_bytes
            AND (
                (NEW.kind = 'session_turn'
                    AND OLD.remaining_event_slots = 2
                    AND NEW.remaining_event_slots = 0
                    AND NEW.remaining_event_payload_bytes = 0
                    AND EXISTS (
                        SELECT 1
                        FROM session_turns turn
                        WHERE turn.session_id = NEW.session_id
                          AND turn.id = NEW.turn_id
                          AND turn.status IN ('flushed', 'interrupted')
                    ))
                OR
                (NEW.kind = 'dispatch'
                    AND OLD.remaining_event_slots = 2
                    AND NEW.remaining_event_slots = 1
                    AND NEW.remaining_event_payload_bytes = CASE
                        WHEN length(CAST(NEW.call_id AS BLOB))
                             > (9223372036854775807 - 65536) / 6
                        THEN 9223372036854775807
                        ELSE 65536 + 6 * length(CAST(NEW.call_id AS BLOB))
                    END
                    AND EXISTS (
                        SELECT 1 FROM dispatch_jobs job
                        WHERE job.run_id = NEW.run_id
                          AND job.call_id = NEW.call_id
                          AND job.status = 'started'
                    ))
                OR
                (NEW.kind = 'dispatch'
                    AND OLD.remaining_event_slots = 2
                    AND NEW.remaining_event_slots = 0
                    AND NEW.remaining_event_payload_bytes = 0
                    AND EXISTS (
                        SELECT 1 FROM dispatch_jobs job
                        WHERE job.run_id = NEW.run_id
                          AND job.call_id = NEW.call_id
                          AND job.status = 'rejected'
                    ))
                OR
                (NEW.kind = 'dispatch'
                    AND OLD.remaining_event_slots = 1
                    AND NEW.remaining_event_slots = 0
                    AND NEW.remaining_event_payload_bytes = 0
                    AND EXISTS (
                        SELECT 1 FROM dispatch_jobs job
                        WHERE job.run_id = NEW.run_id
                          AND job.call_id = NEW.call_id
                          AND job.status = 'finished'
                    ))
            ))
    )
)
BEGIN
    SELECT RAISE(ABORT, 'reservation updates must claim bootstrap authority or consume exact capacity');
END;

CREATE TRIGGER finalization_reservations_reject_live_delete
BEFORE DELETE ON finalization_reservations
WHEN OLD.remaining_event_slots <> 0 OR OLD.remaining_event_payload_bytes <> 0
BEGIN
    SELECT RAISE(ABORT, 'reservation must be empty before deletion');
END;

-- creator metadata is no longer a global authorization role.
DROP INDEX users_single_owner_idx;
