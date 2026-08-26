DROP TRIGGER session_command_receipts_reject_update;
DROP TRIGGER session_command_receipts_reject_delete;

ALTER TABLE session_command_receipts RENAME TO session_command_receipts_v4;

CREATE TABLE session_command_receipts (
    actor_scope         TEXT NOT NULL DEFAULT '__legacy__'
        CHECK (length(trim(actor_scope)) > 0),
    idempotency_key     TEXT NOT NULL CHECK (length(trim(idempotency_key)) > 0),
    operation           TEXT NOT NULL CHECK (operation IN (
        'create_session', 'attach_run', 'start_turn', 'flush_turn', 'resume_session'
    )),
    request_fingerprint TEXT NOT NULL CHECK (json_valid(request_fingerprint)),
    response_json       TEXT NOT NULL CHECK (json_valid(response_json)),
    session_id          TEXT NOT NULL,
    event_sequence      INTEGER NOT NULL CHECK (event_sequence > 0),
    created_at          TEXT NOT NULL,
    PRIMARY KEY (actor_scope, operation, idempotency_key),
    FOREIGN KEY (session_id, event_sequence)
        REFERENCES session_events(session_id, sequence) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

INSERT INTO session_command_receipts(
    actor_scope, idempotency_key, operation, request_fingerprint,
    response_json, session_id, event_sequence, created_at
)
SELECT
    '__legacy__', idempotency_key, operation, request_fingerprint,
    response_json, session_id, event_sequence, created_at
FROM session_command_receipts_v4;

DROP TABLE session_command_receipts_v4;

CREATE TRIGGER session_command_receipts_reject_update
BEFORE UPDATE ON session_command_receipts
WHEN NOT (
    OLD.actor_scope = '__legacy__'
    AND NEW.actor_scope <> '__legacy__'
    AND NEW.idempotency_key = OLD.idempotency_key
    AND NEW.operation = OLD.operation
    AND NEW.request_fingerprint = OLD.request_fingerprint
    AND NEW.response_json = OLD.response_json
    AND NEW.session_id = OLD.session_id
    AND NEW.event_sequence = OLD.event_sequence
    AND NEW.created_at = OLD.created_at
)
BEGIN
    SELECT RAISE(ABORT, 'session command receipts are immutable after legacy claim');
END;

CREATE TRIGGER session_command_receipts_reject_delete
BEFORE DELETE ON session_command_receipts
BEGIN
    SELECT RAISE(ABORT, 'session command receipts are durable');
END;

DROP TRIGGER IF EXISTS idempotency_receipts_reject_update;
DROP TRIGGER IF EXISTS idempotency_receipts_reject_delete;

ALTER TABLE idempotency_receipts RENAME TO idempotency_receipts_v1;

CREATE TABLE idempotency_receipts (
    actor_scope            TEXT NOT NULL DEFAULT '__legacy__'
        CHECK (length(trim(actor_scope)) > 0),
    idempotency_key        TEXT NOT NULL CHECK (length(trim(idempotency_key)) > 0),
    operation              TEXT NOT NULL,
    request_fingerprint    TEXT NOT NULL CHECK (json_valid(request_fingerprint)),
    response_json          TEXT NOT NULL CHECK (json_valid(response_json)),
    run_id                 TEXT NOT NULL,
    event_sequence         INTEGER NOT NULL,
    created_at             TEXT NOT NULL,
    PRIMARY KEY (actor_scope, operation, idempotency_key),
    FOREIGN KEY (run_id, event_sequence)
        REFERENCES run_events(run_id, sequence) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

INSERT INTO idempotency_receipts(
    actor_scope, idempotency_key, operation, request_fingerprint,
    response_json, run_id, event_sequence, created_at
)
SELECT
    '__legacy__', idempotency_key, operation, request_fingerprint,
    response_json, run_id, event_sequence, created_at
FROM idempotency_receipts_v1;

DROP TABLE idempotency_receipts_v1;

CREATE TRIGGER idempotency_receipts_reject_update
BEFORE UPDATE ON idempotency_receipts
WHEN NOT (
    OLD.actor_scope = '__legacy__'
    AND NEW.actor_scope <> '__legacy__'
    AND NEW.idempotency_key = OLD.idempotency_key
    AND NEW.operation = OLD.operation
    AND NEW.request_fingerprint = OLD.request_fingerprint
    AND NEW.response_json = OLD.response_json
    AND NEW.run_id = OLD.run_id
    AND NEW.event_sequence = OLD.event_sequence
    AND NEW.created_at = OLD.created_at
)
BEGIN
    SELECT RAISE(ABORT, 'idempotency receipts are immutable after legacy claim');
END;

CREATE TRIGGER idempotency_receipts_reject_delete
BEFORE DELETE ON idempotency_receipts
BEGIN
    SELECT RAISE(ABORT, 'idempotency receipts are durable');
END;
