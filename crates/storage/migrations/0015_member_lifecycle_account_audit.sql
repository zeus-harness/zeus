-- v15 stops inferring a tool-call initiator from the approving owner.  Rebuild
-- the dispatch table so an unknown initiator is represented by a NULL pair,
-- independently of the mandatory approving authority pair. Existing proven
-- v14 rows retain both subjects exactly as stored.
DROP TRIGGER dispatch_jobs_require_authority;
DROP TRIGGER dispatch_jobs_reject_input_update;
DROP TRIGGER dispatch_jobs_enforce_forward_transition;
DROP TRIGGER dispatch_jobs_reject_delete;
DROP INDEX dispatch_jobs_ready_idx;
DROP INDEX dispatch_jobs_run_idx;
DROP INDEX dispatch_jobs_actor_idx;
DROP INDEX dispatch_jobs_initiator_idx;
DROP INDEX dispatch_jobs_account_idx;
DROP INDEX dispatch_jobs_started_idx;

PRAGMA legacy_alter_table = ON;
ALTER TABLE dispatch_jobs RENAME TO dispatch_jobs_v14_provenance;

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
         AND initiating_membership_revision IS NULL)
        OR
        (initiating_actor_user_id IS NOT NULL
         AND initiating_membership_revision IS NOT NULL)
    ),
    CHECK (
        (approving_actor_user_id IS NULL
         AND approving_membership_revision IS NULL
         AND initiating_actor_user_id IS NULL)
        OR
        (approving_actor_user_id IS NOT NULL
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
    call_id, account_id, run_id, approval_id, approval_event_sequence,
    initiating_actor_user_id, initiating_membership_revision,
    approving_actor_user_id, approving_membership_revision,
    tool_name, tool_version, effect, args_json, args_digest, policy_id,
    policy_revision, sandbox_profile, status, attempt, result_json,
    authorization_error_json, queued_at, started_at, finished_at,
    start_event_sequence, result_event_sequence
FROM dispatch_jobs_v14_provenance;

-- SQLite correctly retargets child foreign keys when the parent is renamed.
-- Rebuild the sole child as part of the same transaction so it binds to the
-- new dispatch table rather than the temporary v14 table.
DROP TRIGGER finalization_reservations_require_authority;
DROP TRIGGER finalization_reservations_require_event_payload_capacity_on_insert;
DROP TRIGGER finalization_reservations_enforce_update;
DROP TRIGGER finalization_reservations_reject_live_delete;
DROP INDEX finalization_reservations_turn_idx;
DROP INDEX finalization_reservations_dispatch_idx;
DROP INDEX finalization_reservations_actor_active_idx;
DROP INDEX finalization_reservations_account_active_idx;
DROP INDEX finalization_reservations_kind_active_idx;

ALTER TABLE finalization_reservations
    RENAME TO finalization_reservations_v14_provenance;

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
    kind, account_id, actor_user_id, session_id, turn_id, run_id, call_id,
    remaining_event_slots, reserved_bytes, created_at,
    remaining_event_payload_bytes
FROM finalization_reservations_v14_provenance;

DROP TABLE finalization_reservations_v14_provenance;
DROP TABLE dispatch_jobs_v14_provenance;
PRAGMA legacy_alter_table = OFF;

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
        NEW.approving_actor_user_id IS NULL
        AND (
            NEW.account_id <> 'acc_local'
            OR NEW.initiating_actor_user_id IS NOT NULL
            OR NEW.initiating_membership_revision IS NOT NULL
            OR NEW.approving_membership_revision IS NOT NULL
            OR EXISTS (SELECT 1 FROM users)
            OR EXISTS (SELECT 1 FROM account_memberships)
        )
     )
  OR (
        NEW.approving_actor_user_id IS NOT NULL
        AND (
          NOT EXISTS (
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
          OR (
            NEW.initiating_actor_user_id IS NOT NULL
            AND NOT EXISTS (
              SELECT 1
              FROM account_memberships membership
              JOIN users user ON user.id = membership.user_id
              WHERE membership.account_id = NEW.account_id
                AND membership.user_id = NEW.initiating_actor_user_id
                AND membership.revision = NEW.initiating_membership_revision
                AND membership.status = 'active'
                AND user.status = 'active'
            )
          )
        )
     )
BEGIN
    SELECT RAISE(ABORT, 'dispatch requires current approving and recorded initiating authority');
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
    AND NEW.initiating_actor_user_id IS NULL
    AND NEW.initiating_membership_revision IS NULL
    AND NEW.approving_actor_user_id IS NOT NULL
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
        JOIN account_memberships membership ON membership.account_id = account.id
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
           AND NEW.initiating_actor_user_id IS NULL
           AND NEW.approving_actor_user_id IS NOT NULL
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

-- A finalization reservation owns capacity; when initiator provenance is
-- absent its accounting owner is the approving owner, without populating the
-- dispatch initiator columns.
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
              AND COALESCE(job.initiating_actor_user_id,
                           job.approving_actor_user_id) IS NEW.actor_user_id
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
    SELECT RAISE(ABORT, 'finalization reservation requires current account authority');
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
                      AND COALESCE(job.initiating_actor_user_id,
                                   job.approving_actor_user_id) = NEW.actor_user_id
                      AND (job.initiating_membership_revision IS NULL
                           OR job.initiating_membership_revision = 1)
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

-- Member lifecycle and bounded account-security audit foundation.
-- Raw setup credentials never enter SQLite. This table contains only the
-- domain-separated digest of the one currently live token for a member.
CREATE TABLE member_setup_tokens (
    token_digest       TEXT PRIMARY KEY
        CHECK (length(token_digest) = 64
               AND token_digest = lower(token_digest)
               AND token_digest NOT GLOB '*[^0-9a-f]*'),
    account_id         TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    user_id            TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_by_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at         TEXT NOT NULL,
    expires_at         TEXT NOT NULL,
    UNIQUE (account_id, user_id),
    FOREIGN KEY (account_id, user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (account_id, created_by_user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT,
    CHECK (expires_at > created_at)
) STRICT;

CREATE INDEX member_setup_tokens_expiry_idx
    ON member_setup_tokens(expires_at, account_id, user_id);

CREATE TRIGGER member_setup_tokens_require_pending_member
BEFORE INSERT ON member_setup_tokens
WHEN EXISTS (
        SELECT 1 FROM member_setup_tokens token
        WHERE token.account_id = NEW.account_id
          AND token.user_id = NEW.user_id
     )
  OR NOT EXISTS (
        SELECT 1
        FROM accounts account
        JOIN account_memberships member
          ON member.account_id = account.id
        JOIN users user ON user.id = member.user_id
        JOIN account_memberships creator
          ON creator.account_id = account.id
        JOIN users creator_user ON creator_user.id = creator.user_id
        WHERE account.id = NEW.account_id
          AND account.status = 'active'
          AND member.user_id = NEW.user_id
          AND member.role = 'member'
          AND member.status = 'active'
          AND user.status = 'disabled'
          AND NOT EXISTS (
              SELECT 1 FROM user_preferences preference
              WHERE preference.user_id = member.user_id
          )
          AND creator.user_id = NEW.created_by_user_id
          AND creator.role = 'owner'
          AND creator.status = 'active'
          AND creator_user.status = 'active'
     )
BEGIN
    SELECT RAISE(ABORT, 'member setup token requires one pending member and active owner');
END;

CREATE TRIGGER member_setup_tokens_reject_update
BEFORE UPDATE ON member_setup_tokens
BEGIN
    SELECT RAISE(ABORT, 'member setup tokens are immutable; rotate by replacement');
END;

-- One permanent rollup, retention policy, and archive checkpoint exist for
-- every account. The rollup digest is a database-local commitment, not an
-- independent tamper-proof anchor.
CREATE TABLE account_audit_rollups (
    account_id        TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE RESTRICT,
    through_sequence  INTEGER NOT NULL CHECK (through_sequence >= 0),
    event_count       INTEGER NOT NULL CHECK (event_count >= 0),
    digest            TEXT NOT NULL
        CHECK (length(digest) = 64 AND digest = lower(digest)
               AND digest NOT GLOB '*[^0-9a-f]*'),
    last_event_hash   TEXT NOT NULL
        CHECK (length(last_event_hash) = 64 AND last_event_hash = lower(last_event_hash)
               AND last_event_hash NOT GLOB '*[^0-9a-f]*'),
    updated_at        TEXT NOT NULL,
    CHECK (through_sequence = event_count)
) STRICT;

CREATE TABLE account_audit_policies (
    account_id       TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE RESTRICT,
    detail_rows      INTEGER NOT NULL CHECK (detail_rows BETWEEN 1 AND 4096),
    legal_hold       INTEGER NOT NULL CHECK (legal_hold IN (0, 1)),
    archive_required INTEGER NOT NULL CHECK (archive_required IN (0, 1)),
    revision         INTEGER NOT NULL CHECK (revision > 0),
    updated_at       TEXT NOT NULL
) STRICT;

CREATE TABLE account_audit_archive_state (
    account_id        TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE RESTRICT,
    through_sequence  INTEGER NOT NULL CHECK (through_sequence >= 0),
    event_hash        TEXT NOT NULL
        CHECK (length(event_hash) = 64 AND event_hash = lower(event_hash)
               AND event_hash NOT GLOB '*[^0-9a-f]*'),
    archive_reference TEXT CHECK (
        archive_reference IS NULL
        OR (length(archive_reference) BETWEEN 1 AND 512
            AND archive_reference = trim(archive_reference))
    ),
    revision          INTEGER NOT NULL CHECK (revision > 0),
    updated_at        TEXT NOT NULL,
    CHECK (
        (through_sequence = 0 AND archive_reference IS NULL)
        OR (through_sequence > 0 AND archive_reference IS NOT NULL)
    )
) STRICT;

CREATE TABLE account_audit_events (
    account_id       TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    sequence         INTEGER NOT NULL CHECK (sequence > 0),
    actor_user_id    TEXT REFERENCES users(id) ON DELETE RESTRICT,
    action           TEXT NOT NULL
        CHECK (length(action) BETWEEN 1 AND 96 AND action = trim(action)),
    outcome          TEXT NOT NULL CHECK (outcome IN ('succeeded', 'rejected')),
    target_kind      TEXT NOT NULL
        CHECK (length(target_kind) BETWEEN 1 AND 64 AND target_kind = trim(target_kind)),
    target_id        TEXT NOT NULL
        CHECK (length(target_id) BETWEEN 1 AND 384 AND target_id = trim(target_id)),
    metadata_json    TEXT NOT NULL
        CHECK (json_valid(metadata_json) AND json_type(metadata_json) = 'object'
               AND length(CAST(metadata_json AS BLOB)) <= 8192),
    occurred_at      TEXT NOT NULL,
    previous_hash    TEXT NOT NULL
        CHECK (length(previous_hash) = 64 AND previous_hash = lower(previous_hash)
               AND previous_hash NOT GLOB '*[^0-9a-f]*'),
    event_hash       TEXT NOT NULL
        CHECK (length(event_hash) = 64 AND event_hash = lower(event_hash)
               AND event_hash NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (account_id, sequence),
    FOREIGN KEY (account_id, actor_user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX account_audit_events_hash_idx
    ON account_audit_events(account_id, event_hash);
CREATE INDEX account_audit_events_time_idx
    ON account_audit_events(account_id, occurred_at DESC, sequence DESC);

INSERT INTO account_audit_rollups(
    account_id, through_sequence, event_count, digest, last_event_hash, updated_at
)
SELECT id, 0, 0,
       '0000000000000000000000000000000000000000000000000000000000000000',
       '0000000000000000000000000000000000000000000000000000000000000000',
       strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
FROM accounts;

-- The Rust migrator seeds account_audit_policies after this batch so the
-- initial durable target uses the validated runtime detail-row ceiling rather
-- than a hard-coded default that may exceed the configured capacity.

INSERT INTO account_audit_archive_state(
    account_id, through_sequence, event_hash, archive_reference, revision, updated_at
)
SELECT id, 0,
       '0000000000000000000000000000000000000000000000000000000000000000',
       NULL, 1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
FROM accounts;

CREATE TRIGGER account_audit_events_require_chain
BEFORE INSERT ON account_audit_events
WHEN NEW.sequence <> COALESCE(
         (SELECT MAX(event.sequence) + 1
          FROM account_audit_events event
          WHERE event.account_id = NEW.account_id),
         (SELECT rollup.through_sequence + 1
          FROM account_audit_rollups rollup
          WHERE rollup.account_id = NEW.account_id)
     )
  OR NEW.previous_hash IS NOT COALESCE(
         (SELECT event.event_hash
          FROM account_audit_events event
          WHERE event.account_id = NEW.account_id
          ORDER BY event.sequence DESC LIMIT 1),
         (SELECT rollup.last_event_hash
          FROM account_audit_rollups rollup
          WHERE rollup.account_id = NEW.account_id)
     )
BEGIN
    SELECT RAISE(ABORT, 'account audit events must extend one contiguous hash chain');
END;

CREATE TRIGGER account_audit_events_reject_update
BEFORE UPDATE ON account_audit_events
BEGIN
    SELECT RAISE(ABORT, 'account audit events are append-only');
END;

CREATE TRIGGER account_audit_events_require_rollup_before_delete
BEFORE DELETE ON account_audit_events
WHEN OLD.sequence > COALESCE((
         SELECT rollup.through_sequence
         FROM account_audit_rollups rollup
         WHERE rollup.account_id = OLD.account_id
     ), 0)
  OR EXISTS (
         SELECT 1 FROM account_audit_policies policy
         WHERE policy.account_id = OLD.account_id AND policy.legal_hold = 1
     )
  OR EXISTS (
         SELECT 1
         FROM account_audit_policies policy
         JOIN account_audit_archive_state archive
           ON archive.account_id = policy.account_id
         WHERE policy.account_id = OLD.account_id
           AND policy.archive_required = 1
           AND archive.through_sequence < OLD.sequence
     )
BEGIN
    SELECT RAISE(ABORT, 'account audit detail requires rollup and retention clearance');
END;

CREATE TRIGGER account_audit_rollups_enforce_forward_update
BEFORE UPDATE ON account_audit_rollups
WHEN NEW.account_id IS NOT OLD.account_id
  OR NEW.through_sequence < OLD.through_sequence
  OR NEW.event_count < OLD.event_count
  OR NEW.updated_at < OLD.updated_at
  OR (NEW.through_sequence = OLD.through_sequence AND (
         NEW.event_count IS NOT OLD.event_count
      OR NEW.digest IS NOT OLD.digest
      OR NEW.last_event_hash IS NOT OLD.last_event_hash
     ))
BEGIN
    SELECT RAISE(ABORT, 'account audit rollup must advance monotonically');
END;

CREATE TRIGGER account_audit_rollups_reject_delete
BEFORE DELETE ON account_audit_rollups
BEGIN
    SELECT RAISE(ABORT, 'account audit rollups are durable');
END;

CREATE TRIGGER account_audit_policies_enforce_revision
BEFORE UPDATE ON account_audit_policies
WHEN NEW.account_id IS NOT OLD.account_id
  OR NEW.revision <> OLD.revision + 1
  OR NEW.updated_at < OLD.updated_at
BEGIN
    SELECT RAISE(ABORT, 'account audit policy requires the next revision');
END;

CREATE TRIGGER account_audit_policies_reject_delete
BEFORE DELETE ON account_audit_policies
BEGIN
    SELECT RAISE(ABORT, 'account audit policies are durable');
END;

CREATE TRIGGER account_audit_archive_state_enforce_revision
BEFORE UPDATE ON account_audit_archive_state
WHEN NEW.account_id IS NOT OLD.account_id
  OR NEW.revision <> OLD.revision + 1
  OR NEW.through_sequence < OLD.through_sequence
  OR NEW.updated_at < OLD.updated_at
BEGIN
    SELECT RAISE(ABORT, 'account audit archive checkpoint requires the next revision');
END;

CREATE TRIGGER account_audit_archive_state_reject_delete
BEFORE DELETE ON account_audit_archive_state
BEGIN
    SELECT RAISE(ABORT, 'account audit archive state is durable');
END;
