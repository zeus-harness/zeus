-- A fork owns an independent Session ledger while retaining immutable,
-- inspectable lineage to the exact parent boundary from which its complete
-- conversation turns were copied.
CREATE TABLE session_forks (
    child_session_id              TEXT PRIMARY KEY
        REFERENCES sessions(id) ON DELETE RESTRICT,
    account_id                    TEXT NOT NULL
        REFERENCES accounts(id) ON DELETE RESTRICT,
    parent_session_id             TEXT NOT NULL
        REFERENCES sessions(id) ON DELETE RESTRICT,
    parent_sequence               INTEGER NOT NULL CHECK (parent_sequence > 0),
    inherited_turn_count          INTEGER NOT NULL CHECK (inherited_turn_count >= 0),
    created_by_user_id            TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_by_membership_revision INTEGER NOT NULL
        CHECK (created_by_membership_revision > 0),
    created_at                    TEXT NOT NULL,
    CHECK (child_session_id <> parent_session_id),
    FOREIGN KEY (parent_session_id, parent_sequence)
        REFERENCES session_events(session_id, sequence) ON DELETE RESTRICT,
    FOREIGN KEY (account_id, created_by_user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT
) STRICT;

CREATE INDEX session_forks_parent_idx
    ON session_forks(account_id, parent_session_id, parent_sequence, child_session_id);

CREATE TRIGGER session_forks_validate_insert
BEFORE INSERT ON session_forks
WHEN NOT EXISTS (
        SELECT 1
        FROM sessions child
        JOIN sessions parent ON parent.id = NEW.parent_session_id
        JOIN accounts account ON account.id = NEW.account_id
        JOIN users user ON user.id = NEW.created_by_user_id
        JOIN account_memberships membership
          ON membership.account_id = NEW.account_id
         AND membership.user_id = NEW.created_by_user_id
        WHERE child.id = NEW.child_session_id
          AND child.account_id = NEW.account_id
          AND child.owner_user_id = NEW.created_by_user_id
          AND child.status = 'ready'
          AND child.active_turn_id IS NULL
          AND child.created_at = NEW.created_at
          AND parent.account_id = NEW.account_id
          AND parent.sequence >= NEW.parent_sequence
          AND account.status = 'active'
          AND user.status = 'active'
          AND membership.status = 'active'
          AND membership.revision = NEW.created_by_membership_revision
    )
 OR EXISTS (
        WITH RECURSIVE ancestors(session_id) AS (
            SELECT NEW.parent_session_id
            UNION ALL
            SELECT fork.parent_session_id
            FROM session_forks fork
            JOIN ancestors ON fork.child_session_id = ancestors.session_id
        )
        SELECT 1 FROM ancestors WHERE session_id = NEW.child_session_id
    )
BEGIN
    SELECT RAISE(ABORT, 'session fork requires current same-account lineage');
END;

CREATE TRIGGER session_forks_reject_update
BEFORE UPDATE ON session_forks
BEGIN
    SELECT RAISE(ABORT, 'session fork lineage is immutable');
END;

CREATE TRIGGER session_forks_reject_delete
BEFORE DELETE ON session_forks
BEGIN
    SELECT RAISE(ABORT, 'session fork lineage is durable');
END;

-- One mapping row proves which exact parent turn and event triple produced an
-- inherited child turn. The child event positions are deterministic, while
-- the parent positions remain bounded by the fork's immutable source head.
CREATE TABLE session_fork_turns (
    child_session_id         TEXT NOT NULL,
    child_turn_id            TEXT NOT NULL,
    parent_session_id        TEXT NOT NULL,
    parent_turn_id           TEXT NOT NULL,
    ordinal                  INTEGER NOT NULL CHECK (ordinal > 0),
    parent_turn_ordinal      INTEGER NOT NULL CHECK (parent_turn_ordinal > 0),
    parent_user_sequence     INTEGER NOT NULL CHECK (parent_user_sequence > 0),
    parent_assistant_sequence INTEGER NOT NULL CHECK (parent_assistant_sequence > 0),
    parent_flush_sequence    INTEGER NOT NULL CHECK (parent_flush_sequence > 0),
    child_user_sequence      INTEGER NOT NULL CHECK (child_user_sequence > 0),
    child_assistant_sequence INTEGER NOT NULL CHECK (child_assistant_sequence > 0),
    child_flush_sequence     INTEGER NOT NULL CHECK (child_flush_sequence > 0),
    PRIMARY KEY (child_session_id, ordinal),
    UNIQUE (child_session_id, child_turn_id),
    UNIQUE (child_session_id, parent_session_id, parent_turn_id),
    FOREIGN KEY (child_session_id)
        REFERENCES session_forks(child_session_id) ON DELETE RESTRICT,
    FOREIGN KEY (child_session_id, child_turn_id)
        REFERENCES session_turns(session_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (parent_session_id, parent_turn_id)
        REFERENCES session_turns(session_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (parent_session_id, parent_user_sequence)
        REFERENCES session_events(session_id, sequence) ON DELETE RESTRICT,
    FOREIGN KEY (parent_session_id, parent_assistant_sequence)
        REFERENCES session_events(session_id, sequence) ON DELETE RESTRICT,
    FOREIGN KEY (parent_session_id, parent_flush_sequence)
        REFERENCES session_events(session_id, sequence) ON DELETE RESTRICT,
    FOREIGN KEY (child_session_id, child_user_sequence)
        REFERENCES session_events(session_id, sequence) ON DELETE RESTRICT,
    FOREIGN KEY (child_session_id, child_assistant_sequence)
        REFERENCES session_events(session_id, sequence) ON DELETE RESTRICT,
    FOREIGN KEY (child_session_id, child_flush_sequence)
        REFERENCES session_events(session_id, sequence) ON DELETE RESTRICT,
    CHECK (parent_user_sequence < parent_assistant_sequence),
    CHECK (parent_assistant_sequence < parent_flush_sequence),
    CHECK (child_assistant_sequence = child_user_sequence + 1),
    CHECK (child_flush_sequence = child_assistant_sequence + 1),
    CHECK (child_user_sequence = 2 + ((ordinal - 1) * 3))
) STRICT, WITHOUT ROWID;

CREATE INDEX session_fork_turns_parent_idx
    ON session_fork_turns(parent_session_id, parent_turn_id, child_session_id);

CREATE TRIGGER session_fork_turns_validate_insert
BEFORE INSERT ON session_fork_turns
WHEN NOT EXISTS (
        SELECT 1
        FROM session_forks fork
        JOIN session_turns child
          ON child.session_id = NEW.child_session_id
         AND child.id = NEW.child_turn_id
        JOIN session_turns parent
          ON parent.session_id = NEW.parent_session_id
         AND parent.id = NEW.parent_turn_id
        JOIN session_events parent_user
          ON parent_user.session_id = NEW.parent_session_id
         AND parent_user.sequence = NEW.parent_user_sequence
        JOIN session_events parent_assistant
          ON parent_assistant.session_id = NEW.parent_session_id
         AND parent_assistant.sequence = NEW.parent_assistant_sequence
        JOIN session_events parent_flush
          ON parent_flush.session_id = NEW.parent_session_id
         AND parent_flush.sequence = NEW.parent_flush_sequence
        JOIN session_events child_user
          ON child_user.session_id = NEW.child_session_id
         AND child_user.sequence = NEW.child_user_sequence
        JOIN session_events child_assistant
          ON child_assistant.session_id = NEW.child_session_id
         AND child_assistant.sequence = NEW.child_assistant_sequence
        JOIN session_events child_flush
          ON child_flush.session_id = NEW.child_session_id
         AND child_flush.sequence = NEW.child_flush_sequence
        WHERE fork.child_session_id = NEW.child_session_id
          AND fork.parent_session_id = NEW.parent_session_id
          AND fork.parent_sequence >= NEW.parent_flush_sequence
          AND fork.inherited_turn_count >= NEW.ordinal
          AND child.ordinal = NEW.ordinal
          AND parent.ordinal = NEW.parent_turn_ordinal
          AND child.status = 'flushed'
          AND parent.status = 'flushed'
          AND child.user_message = parent.user_message
          AND child.assistant_message IS parent.assistant_message
          AND child.started_at = parent.started_at
          AND child.completed_at IS parent.completed_at
          AND parent_user.event_kind = 'user_message'
          AND parent_user.turn_id = NEW.parent_turn_id
          AND parent_assistant.event_kind = 'assistant_message'
          AND parent_assistant.turn_id = NEW.parent_turn_id
          AND parent_flush.event_kind = 'turn_flushed'
          AND parent_flush.turn_id = NEW.parent_turn_id
          AND child_user.event_kind = 'user_message'
          AND child_user.turn_id = NEW.child_turn_id
          AND child_assistant.event_kind = 'assistant_message'
          AND child_assistant.turn_id = NEW.child_turn_id
          AND child_flush.event_kind = 'turn_flushed'
          AND child_flush.turn_id = NEW.child_turn_id
    )
BEGIN
    SELECT RAISE(ABORT, 'session fork turn must copy one exact complete parent turn');
END;

CREATE TRIGGER session_fork_turns_reject_update
BEFORE UPDATE ON session_fork_turns
BEGIN
    SELECT RAISE(ABORT, 'session fork turn mapping is immutable');
END;

CREATE TRIGGER session_fork_turns_reject_delete
BEFORE DELETE ON session_fork_turns
BEGIN
    SELECT RAISE(ABORT, 'session fork turn mapping is durable');
END;

-- Add the fork command to the existing actor/account-scoped receipt authority.
DROP TRIGGER session_command_receipts_require_authority;
DROP TRIGGER session_command_receipts_reject_update;
DROP TRIGGER session_command_receipts_reject_delete;
DROP INDEX session_command_receipts_actor_key_idx;
DROP INDEX session_command_receipts_prebootstrap_key_idx;
ALTER TABLE session_command_receipts RENAME TO session_command_receipts_v33;

CREATE TABLE session_command_receipts (
    account_id          TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    actor_user_id       TEXT REFERENCES users(id) ON DELETE RESTRICT,
    idempotency_key     TEXT NOT NULL CHECK (length(trim(idempotency_key)) > 0),
    operation           TEXT NOT NULL CHECK (operation IN (
        'create_session', 'fork_session', 'attach_run', 'start_turn',
        'flush_turn', 'resume_session'
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
SELECT account_id, actor_user_id, idempotency_key, operation,
       request_fingerprint, response_json, session_id, event_sequence, created_at
FROM session_command_receipts_v33;

DROP TABLE session_command_receipts_v33;

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
