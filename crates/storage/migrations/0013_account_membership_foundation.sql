-- Introduce the account boundary without changing the v12 owner-based
-- authorization contract.  v13 supports one deterministic local account and
-- deliberately does not grant existing member users a membership.

-- Fail closed before writing any account state when legacy ownership cannot be
-- proven.  The configured branch requires every durable actor/scope to resolve
-- to the one active legacy owner.  The unconfigured branch permits only the
-- pre-bootstrap NULL/__legacy__ representation.
CREATE TABLE account_membership_preflight_gate (
    ok INTEGER NOT NULL CHECK (ok = 1)
) STRICT;

INSERT INTO account_membership_preflight_gate(ok)
WITH legacy_authority AS (
    SELECT
        COUNT(*) AS user_count,
        COALESCE(SUM(CASE WHEN role = 'owner' THEN 1 ELSE 0 END), 0)
            AS owner_count,
        COALESCE(SUM(
            CASE WHEN role = 'owner' AND status = 'active' THEN 1 ELSE 0 END
        ), 0) AS active_owner_count,
        MAX(CASE WHEN role = 'owner' THEN id END) AS owner_user_id
    FROM users
)
SELECT CASE
    WHEN NOT EXISTS(SELECT 1 FROM pragma_foreign_key_check)
     AND authority.user_count = 0
     AND NOT EXISTS (SELECT 1 FROM auth_sessions)
     AND NOT EXISTS (SELECT 1 FROM user_preferences)
     AND NOT EXISTS (SELECT 1 FROM reply_jobs)
     AND NOT EXISTS (
         SELECT 1 FROM sessions WHERE owner_user_id IS NOT NULL
     )
     AND NOT EXISTS (
         SELECT 1 FROM runs WHERE owner_user_id IS NOT NULL
     )
     AND NOT EXISTS (
         SELECT 1
         FROM session_command_receipts
         WHERE actor_scope <> '__legacy__'
     )
     AND NOT EXISTS (
         SELECT 1
         FROM idempotency_receipts
         WHERE actor_scope <> '__legacy__'
     )
     AND NOT EXISTS (
         SELECT 1
         FROM dispatch_jobs
         WHERE approving_actor_user_id IS NOT NULL
     )
     AND NOT EXISTS (
         SELECT 1
         FROM finalization_reservations
         WHERE scope_id <> '__legacy__'
     )
    THEN 1
    WHEN NOT EXISTS(SELECT 1 FROM pragma_foreign_key_check)
     AND authority.user_count > 0
     AND authority.owner_count = 1
     AND authority.active_owner_count = 1
     AND NOT EXISTS (
         SELECT 1
         FROM sessions
         WHERE owner_user_id IS NOT authority.owner_user_id
     )
     AND NOT EXISTS (
         SELECT 1
         FROM runs
         WHERE owner_user_id IS NOT authority.owner_user_id
     )
     AND NOT EXISTS (
         SELECT 1
         FROM session_runs binding
         JOIN sessions session ON session.id = binding.session_id
         JOIN runs run ON run.id = binding.run_id
         WHERE session.owner_user_id IS NOT authority.owner_user_id
            OR run.owner_user_id IS NOT authority.owner_user_id
     )
     AND NOT EXISTS (
         SELECT 1
         FROM reply_jobs job
         JOIN sessions session ON session.id = job.session_id
         WHERE job.actor_user_id IS NOT authority.owner_user_id
            OR session.owner_user_id IS NOT authority.owner_user_id
     )
     AND NOT EXISTS (
         SELECT 1
         FROM session_command_receipts receipt
         JOIN sessions session ON session.id = receipt.session_id
         WHERE receipt.actor_scope IS NOT authority.owner_user_id
            OR session.owner_user_id IS NOT authority.owner_user_id
     )
     AND NOT EXISTS (
         SELECT 1
         FROM idempotency_receipts receipt
         JOIN runs run ON run.id = receipt.run_id
         WHERE receipt.actor_scope IS NOT authority.owner_user_id
            OR run.owner_user_id IS NOT authority.owner_user_id
     )
     AND NOT EXISTS (
         SELECT 1
         FROM dispatch_jobs job
         JOIN runs run ON run.id = job.run_id
         WHERE job.approving_actor_user_id IS NOT authority.owner_user_id
            OR run.owner_user_id IS NOT authority.owner_user_id
     )
     AND NOT EXISTS (
         SELECT 1
         FROM finalization_reservations reservation
         LEFT JOIN sessions session
           ON reservation.kind = 'session_turn'
          AND session.id = reservation.session_id
         LEFT JOIN runs run
           ON reservation.kind = 'dispatch'
          AND run.id = reservation.run_id
         WHERE (reservation.kind = 'session_turn'
                AND (session.id IS NULL
                     OR session.owner_user_id IS NOT authority.owner_user_id
                     OR reservation.scope_id IS NOT authority.owner_user_id))
            OR (reservation.kind = 'dispatch'
                AND (run.id IS NULL
                     OR run.owner_user_id IS NOT authority.owner_user_id
                     OR reservation.scope_id IS NOT authority.owner_user_id))
     )
     AND NOT EXISTS (
         SELECT 1
         FROM runtime_identity identity
         WHERE NOT EXISTS (
                   SELECT 1
                   FROM sessions session
                   WHERE session.id = identity.primary_session_id
                     AND session.owner_user_id IS authority.owner_user_id
               )
            OR NOT EXISTS (
                   SELECT 1
                   FROM runs run
                   WHERE run.id = identity.primary_run_id
                     AND run.owner_user_id IS authority.owner_user_id
               )
            OR NOT EXISTS (
                   SELECT 1
                   FROM session_runs binding
                   WHERE binding.session_id = identity.primary_session_id
                     AND binding.run_id = identity.primary_run_id
               )
     )
    THEN 1
    ELSE 0
END
FROM legacy_authority authority;

DROP TABLE account_membership_preflight_gate;

CREATE TABLE accounts (
    id         TEXT PRIMARY KEY
        CHECK (length(id) BETWEEN 1 AND 128 AND id = trim(id)),
    name       TEXT NOT NULL
        CHECK (length(name) BETWEEN 1 AND 128 AND name = trim(name)),
    status     TEXT NOT NULL CHECK (status IN ('active', 'suspended')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE account_memberships (
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    role       TEXT NOT NULL CHECK (role IN ('owner', 'member')),
    status     TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    revision   INTEGER NOT NULL CHECK (revision > 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (account_id, user_id)
) STRICT, WITHOUT ROWID;

INSERT INTO accounts(id, name, status, created_at, updated_at)
SELECT 'acc_local', 'Local', 'active', migration_at, migration_at
FROM (
    SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now') AS migration_at
);

-- A configured database receives only its existing owner membership.  Member
-- users stay outside the account until the later member-lifecycle slice.
INSERT INTO account_memberships(
    account_id, user_id, role, status, revision, created_at, updated_at
)
SELECT
    account.id, user.id, 'owner', 'active', 1,
    account.created_at, account.created_at
FROM accounts account
JOIN users user ON user.role = 'owner' AND user.status = 'active'
WHERE account.id = 'acc_local';

-- SQLite cannot add a NOT NULL REFERENCES column to populated tables without
-- a non-NULL default.  Add nullable FKs, backfill atomically, then enforce the
-- logical NOT NULL and immutability contract with triggers.
DROP TRIGGER runtime_identity_reject_update;
DROP TRIGGER runtime_identity_reject_delete;

ALTER TABLE incidents ADD COLUMN account_id TEXT
    REFERENCES accounts(id) ON DELETE RESTRICT
    CHECK (
        account_id IS NULL
        OR (length(account_id) BETWEEN 1 AND 128 AND account_id = trim(account_id))
    );
ALTER TABLE sessions ADD COLUMN account_id TEXT
    REFERENCES accounts(id) ON DELETE RESTRICT
    CHECK (
        account_id IS NULL
        OR (length(account_id) BETWEEN 1 AND 128 AND account_id = trim(account_id))
    );
ALTER TABLE runs ADD COLUMN account_id TEXT
    REFERENCES accounts(id) ON DELETE RESTRICT
    CHECK (
        account_id IS NULL
        OR (length(account_id) BETWEEN 1 AND 128 AND account_id = trim(account_id))
    );
ALTER TABLE runtime_identity ADD COLUMN account_id TEXT
    REFERENCES accounts(id) ON DELETE RESTRICT
    CHECK (
        account_id IS NULL
        OR (length(account_id) BETWEEN 1 AND 128 AND account_id = trim(account_id))
    );

UPDATE incidents SET account_id = 'acc_local';
UPDATE sessions SET account_id = 'acc_local';
UPDATE runs SET account_id = 'acc_local';
UPDATE runtime_identity SET account_id = 'acc_local';

CREATE UNIQUE INDEX incidents_account_id_idx
    ON incidents(account_id, id);
CREATE UNIQUE INDEX sessions_account_id_idx
    ON sessions(account_id, id);
CREATE INDEX sessions_account_updated_idx
    ON sessions(account_id, updated_at DESC, id);
CREATE UNIQUE INDEX runs_account_id_idx
    ON runs(account_id, id);
CREATE INDEX runs_account_started_idx
    ON runs(account_id, started_at DESC, id);
CREATE INDEX runs_account_incident_idx
    ON runs(account_id, incident_id, id);
CREATE INDEX account_memberships_user_idx
    ON account_memberships(user_id, status, account_id);
CREATE INDEX account_memberships_active_owner_idx
    ON account_memberships(account_id, user_id)
    WHERE role = 'owner' AND status = 'active';

-- Durable identities reject INSERT OR REPLACE as well as ordinary updates.
-- This matters because SQLite may perform REPLACE's implicit delete without
-- invoking DELETE triggers when recursive_triggers is disabled.
CREATE TRIGGER accounts_reject_duplicate_insert
BEFORE INSERT ON accounts
WHEN EXISTS (SELECT 1 FROM accounts WHERE id = NEW.id)
BEGIN
    SELECT RAISE(ABORT, 'account identity already exists');
END;

CREATE TRIGGER accounts_reject_identity_update
BEFORE UPDATE OF id, created_at ON accounts
BEGIN
    SELECT RAISE(ABORT, 'account identity is immutable');
END;

CREATE TRIGGER accounts_reject_delete
BEFORE DELETE ON accounts
BEGIN
    SELECT RAISE(ABORT, 'accounts are durable');
END;

CREATE TRIGGER account_memberships_reject_duplicate_insert
BEFORE INSERT ON account_memberships
WHEN EXISTS (
    SELECT 1
    FROM account_memberships membership
    WHERE membership.account_id = NEW.account_id
      AND membership.user_id = NEW.user_id
)
BEGIN
    SELECT RAISE(ABORT, 'account membership identity already exists');
END;

CREATE TRIGGER account_memberships_enforce_revision
BEFORE UPDATE ON account_memberships
WHEN NOT (
    NEW.account_id IS OLD.account_id
    AND NEW.user_id IS OLD.user_id
    AND NEW.created_at IS OLD.created_at
    AND NEW.updated_at >= OLD.updated_at
    AND NEW.revision = OLD.revision + 1
    AND (NEW.role IS NOT OLD.role OR NEW.status IS NOT OLD.status)
)
BEGIN
    SELECT RAISE(ABORT, 'membership authority changes require the next revision');
END;

CREATE TRIGGER account_memberships_preserve_last_active_owner
BEFORE UPDATE ON account_memberships
WHEN OLD.role = 'owner'
 AND OLD.status = 'active'
 AND (NEW.role <> 'owner' OR NEW.status <> 'active')
 AND NOT EXISTS (
     SELECT 1
     FROM account_memberships other
     WHERE other.account_id = OLD.account_id
       AND other.user_id <> OLD.user_id
       AND other.role = 'owner'
       AND other.status = 'active'
 )
BEGIN
    SELECT RAISE(ABORT, 'an account must retain an active owner');
END;

CREATE TRIGGER account_memberships_reject_delete
BEFORE DELETE ON account_memberships
BEGIN
    SELECT RAISE(ABORT, 'account memberships are durable; disable instead');
END;

CREATE TRIGGER incidents_require_account_on_insert
BEFORE INSERT ON incidents
WHEN NEW.account_id IS NULL
  OR EXISTS (SELECT 1 FROM incidents WHERE id = NEW.id)
BEGIN
    SELECT RAISE(ABORT, 'new incidents require an immutable account');
END;

CREATE TRIGGER incidents_account_is_immutable
BEFORE UPDATE OF account_id ON incidents
WHEN NEW.account_id IS NOT OLD.account_id
BEGIN
    SELECT RAISE(ABORT, 'incident account is immutable');
END;

-- runtime_identity is intentionally allowed to precede the primary Session on
-- a fresh start.  If the identity already exists, the later root INSERT must
-- match it; if the root exists first, the identity INSERT checks it below.
CREATE TRIGGER sessions_require_account_on_insert
BEFORE INSERT ON sessions
WHEN NEW.account_id IS NULL
  OR EXISTS (SELECT 1 FROM sessions WHERE id = NEW.id)
  OR EXISTS (
      SELECT 1
      FROM runtime_identity identity
      WHERE identity.primary_session_id = NEW.id
        AND identity.account_id IS NOT NEW.account_id
  )
BEGIN
    SELECT RAISE(ABORT, 'new sessions require the runtime account');
END;

CREATE TRIGGER sessions_account_is_immutable
BEFORE UPDATE OF account_id ON sessions
WHEN NEW.account_id IS NOT OLD.account_id
BEGIN
    SELECT RAISE(ABORT, 'session account is immutable');
END;

CREATE TRIGGER runs_require_account_on_insert
BEFORE INSERT ON runs
WHEN NEW.account_id IS NULL
  OR EXISTS (SELECT 1 FROM runs WHERE id = NEW.id)
  OR NEW.account_id IS NOT (
      SELECT incident.account_id
      FROM incidents incident
      WHERE incident.id = NEW.incident_id
  )
  OR EXISTS (
      SELECT 1
      FROM runtime_identity identity
      WHERE identity.primary_run_id = NEW.id
        AND identity.account_id IS NOT NEW.account_id
  )
BEGIN
    SELECT RAISE(ABORT, 'new runs require the incident and runtime account');
END;

CREATE TRIGGER runs_require_incident_account_on_update
BEFORE UPDATE OF incident_id ON runs
WHEN NEW.account_id IS NOT (
    SELECT incident.account_id
    FROM incidents incident
    WHERE incident.id = NEW.incident_id
)
BEGIN
    SELECT RAISE(ABORT, 'run and incident accounts must match');
END;

CREATE TRIGGER runs_account_is_immutable
BEFORE UPDATE OF account_id ON runs
WHEN NEW.account_id IS NOT OLD.account_id
BEGIN
    SELECT RAISE(ABORT, 'run account is immutable');
END;

CREATE TRIGGER runtime_identity_require_account_on_insert
BEFORE INSERT ON runtime_identity
WHEN NEW.account_id IS NULL
  OR EXISTS (SELECT 1 FROM runtime_identity WHERE singleton = NEW.singleton)
  OR EXISTS (
      SELECT 1
      FROM sessions session
      WHERE session.id = NEW.primary_session_id
        AND session.account_id IS NOT NEW.account_id
  )
  OR EXISTS (
      SELECT 1
      FROM runs run
      WHERE run.id = NEW.primary_run_id
        AND run.account_id IS NOT NEW.account_id
  )
BEGIN
    SELECT RAISE(ABORT, 'runtime identity requires its primary resource account');
END;

CREATE TRIGGER runtime_identity_reject_update
BEFORE UPDATE ON runtime_identity
BEGIN
    SELECT RAISE(ABORT, 'runtime identity is immutable');
END;

CREATE TRIGGER runtime_identity_reject_delete
BEFORE DELETE ON runtime_identity
BEGIN
    SELECT RAISE(ABORT, 'runtime identity is immutable');
END;

CREATE TRIGGER session_runs_require_same_account
BEFORE INSERT ON session_runs
WHEN NOT EXISTS (
    SELECT 1
    FROM sessions session
    JOIN runs run ON run.id = NEW.run_id
    WHERE session.id = NEW.session_id
      AND session.account_id = run.account_id
)
BEGIN
    SELECT RAISE(ABORT, 'session and run accounts must match');
END;
