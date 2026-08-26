CREATE TABLE sessions (
    id                  TEXT PRIMARY KEY CHECK (length(trim(id)) > 0),
    title               TEXT NOT NULL CHECK (length(trim(title)) > 0),
    status              TEXT NOT NULL CHECK (status IN ('ready', 'running', 'needs_attention')),
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    sequence            INTEGER NOT NULL DEFAULT 0 CHECK (sequence >= 0),
    projection_sequence INTEGER NOT NULL DEFAULT 0 CHECK (
        projection_sequence >= 0 AND projection_sequence <= sequence
    ),
    active_turn_id      TEXT,
    CHECK (
        (status = 'running' AND active_turn_id IS NOT NULL)
        OR (status IN ('ready', 'needs_attention') AND active_turn_id IS NULL)
    ),
    FOREIGN KEY (id, active_turn_id)
        REFERENCES session_turns(session_id, id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE session_runs (
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE RESTRICT,
    run_id     TEXT NOT NULL UNIQUE REFERENCES runs(id) ON DELETE RESTRICT,
    attached_at TEXT NOT NULL,
    PRIMARY KEY (session_id, run_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE session_turns (
    id                TEXT PRIMARY KEY CHECK (length(trim(id)) > 0),
    session_id        TEXT NOT NULL REFERENCES sessions(id) ON DELETE RESTRICT,
    ordinal           INTEGER NOT NULL CHECK (ordinal > 0),
    status            TEXT NOT NULL CHECK (status IN ('open', 'flushed', 'interrupted')),
    user_message      TEXT NOT NULL CHECK (length(trim(user_message)) > 0),
    assistant_message TEXT,
    started_at        TEXT NOT NULL,
    completed_at      TEXT,
    UNIQUE (session_id, id),
    UNIQUE (session_id, ordinal),
    CHECK (
        (status = 'open' AND assistant_message IS NULL AND completed_at IS NULL)
        OR (status = 'flushed' AND completed_at IS NOT NULL)
        OR (status = 'interrupted' AND assistant_message IS NULL AND completed_at IS NOT NULL)
    )
) STRICT;

CREATE UNIQUE INDEX session_turns_one_open_idx
    ON session_turns(session_id) WHERE status = 'open';

CREATE TABLE session_events (
    session_id     TEXT NOT NULL REFERENCES sessions(id) ON DELETE RESTRICT,
    sequence       INTEGER NOT NULL CHECK (sequence > 0),
    event_id       TEXT NOT NULL CHECK (length(trim(event_id)) > 0),
    event_kind     TEXT NOT NULL CHECK (event_kind IN (
        'session_created',
        'run_attached',
        'session_resumed',
        'user_message',
        'assistant_message',
        'turn_flushed',
        'turn_interrupted'
    )),
    payload_version INTEGER NOT NULL CHECK (payload_version > 0),
    payload_json   TEXT NOT NULL CHECK (json_valid(payload_json)),
    turn_id        TEXT,
    created_at     TEXT NOT NULL,
    PRIMARY KEY (session_id, sequence),
    UNIQUE (session_id, event_id),
    FOREIGN KEY (session_id, turn_id)
        REFERENCES session_turns(session_id, id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TRIGGER session_events_require_next_sequence
BEFORE INSERT ON session_events
WHEN NEW.sequence <> (
    SELECT sequence + 1 FROM sessions WHERE id = NEW.session_id
)
BEGIN
    SELECT RAISE(ABORT, 'session event sequence must be contiguous');
END;

CREATE TRIGGER session_events_reject_update
BEFORE UPDATE ON session_events
BEGIN
    SELECT RAISE(ABORT, 'session_events are append-only');
END;

CREATE TRIGGER session_events_reject_delete
BEFORE DELETE ON session_events
BEGIN
    SELECT RAISE(ABORT, 'session_events are append-only');
END;

CREATE TRIGGER session_runs_reject_update
BEFORE UPDATE ON session_runs
BEGIN
    SELECT RAISE(ABORT, 'run ownership is immutable');
END;

CREATE TRIGGER session_runs_reject_delete
BEFORE DELETE ON session_runs
BEGIN
    SELECT RAISE(ABORT, 'run ownership is durable');
END;

CREATE TRIGGER session_turns_reject_input_update
BEFORE UPDATE OF id, session_id, ordinal, user_message, started_at ON session_turns
BEGIN
    SELECT RAISE(ABORT, 'session turn input is immutable');
END;

CREATE TRIGGER session_turns_enforce_terminal_transition
BEFORE UPDATE ON session_turns
WHEN NOT (
    OLD.status = 'open'
    AND NEW.status IN ('flushed', 'interrupted')
)
BEGIN
    SELECT RAISE(ABORT, 'invalid session turn state transition');
END;

CREATE TRIGGER session_turns_reject_delete
BEFORE DELETE ON session_turns
BEGIN
    SELECT RAISE(ABORT, 'session turns are durable');
END;

CREATE TABLE session_command_receipts (
    idempotency_key     TEXT PRIMARY KEY CHECK (length(trim(idempotency_key)) > 0),
    operation           TEXT NOT NULL CHECK (operation IN (
        'create_session', 'attach_run', 'start_turn', 'flush_turn', 'resume_session'
    )),
    request_fingerprint TEXT NOT NULL CHECK (json_valid(request_fingerprint)),
    response_json       TEXT NOT NULL CHECK (json_valid(response_json)),
    session_id          TEXT NOT NULL,
    event_sequence      INTEGER NOT NULL CHECK (event_sequence > 0),
    created_at          TEXT NOT NULL,
    FOREIGN KEY (session_id, event_sequence)
        REFERENCES session_events(session_id, sequence) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER session_command_receipts_reject_update
BEFORE UPDATE ON session_command_receipts
BEGIN
    SELECT RAISE(ABORT, 'session command receipts are immutable');
END;

CREATE TRIGGER session_command_receipts_reject_delete
BEFORE DELETE ON session_command_receipts
BEGIN
    SELECT RAISE(ABORT, 'session command receipts are durable');
END;

-- Every pre-v4 run becomes the first (and, initially, only) run of a durable
-- session. No run/event data is rewritten or discarded.
INSERT INTO sessions(
    id, title, status, created_at, updated_at, sequence, projection_sequence, active_turn_id
)
SELECT
    'session-' || r.id,
    i.title,
    'ready',
    r.started_at,
    r.started_at,
    0,
    0,
    NULL
FROM runs r
JOIN incidents i ON i.id = r.incident_id
ORDER BY r.id;

INSERT INTO session_events(
    session_id, sequence, event_id, event_kind, payload_version, payload_json, turn_id, created_at
)
SELECT
    'session-' || r.id,
    1,
    'session-' || r.id || ':event:1',
    'session_created',
    1,
    json_object(
        'sequence', 1,
        'id', 'session-' || r.id || ':event:1',
        'at', r.started_at,
        'data', json_object('kind', 'session_created', 'title', i.title)
    ),
    NULL,
    r.started_at
FROM runs r
JOIN incidents i ON i.id = r.incident_id
ORDER BY r.id;

UPDATE sessions
SET sequence = 1, projection_sequence = 1;

INSERT INTO session_runs(session_id, run_id, attached_at)
SELECT 'session-' || id, id, started_at
FROM runs
ORDER BY id;

INSERT INTO session_events(
    session_id, sequence, event_id, event_kind, payload_version, payload_json, turn_id, created_at
)
SELECT
    'session-' || id,
    2,
    'session-' || id || ':event:2',
    'run_attached',
    1,
    json_object(
        'sequence', 2,
        'id', 'session-' || id || ':event:2',
        'at', started_at,
        'data', json_object('kind', 'run_attached', 'run_id', id)
    ),
    NULL,
    started_at
FROM runs
ORDER BY id;

UPDATE sessions
SET sequence = 2, projection_sequence = 2;

-- Rebuild the singleton so the new immutable primary-session binding is
-- populated deterministically for an existing primary run.
DROP TRIGGER runtime_identity_reject_update;
DROP TRIGGER runtime_identity_reject_delete;
ALTER TABLE runtime_identity RENAME TO runtime_identity_v3;

CREATE TABLE runtime_identity (
    singleton          INTEGER PRIMARY KEY CHECK (singleton = 1),
    profile            TEXT NOT NULL CHECK (
        profile IN ('production-guarded', 'local-development')
    ),
    environment        TEXT NOT NULL CHECK (length(trim(environment)) > 0),
    primary_session_id TEXT NOT NULL CHECK (length(trim(primary_session_id)) > 0),
    primary_run_id     TEXT NOT NULL CHECK (length(trim(primary_run_id)) > 0),
    policy_id          TEXT NOT NULL CHECK (length(trim(policy_id)) > 0),
    policy_revision    TEXT NOT NULL CHECK (length(trim(policy_revision)) > 0),
    bound_at           TEXT NOT NULL
) STRICT;

INSERT INTO runtime_identity(
    singleton, profile, environment, primary_session_id, primary_run_id,
    policy_id, policy_revision, bound_at
)
SELECT
    singleton, profile, environment, 'session-' || primary_run_id, primary_run_id,
    policy_id, policy_revision, bound_at
FROM runtime_identity_v3;

DROP TABLE runtime_identity_v3;

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
