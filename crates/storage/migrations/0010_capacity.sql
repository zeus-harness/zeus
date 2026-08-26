-- Reserve the event slots needed to bring an accepted operation to a durable
-- terminal state. The first capacity slice reserves rows only; byte accounting
-- stays NULL until a later migration can make payload size part of the durable
-- contract.
CREATE TABLE finalization_reservations (
    kind                  TEXT NOT NULL CHECK (
        kind IN ('session_turn', 'dispatch')
    ),
    scope_id              TEXT NOT NULL CHECK (length(trim(scope_id)) > 0),
    session_id            TEXT,
    turn_id               TEXT,
    run_id                 TEXT,
    call_id                TEXT,
    remaining_event_slots INTEGER NOT NULL CHECK (
        remaining_event_slots BETWEEN 0 AND 2
    ),
    reserved_bytes        INTEGER CHECK (reserved_bytes IS NULL),
    created_at            TEXT NOT NULL,
    FOREIGN KEY (session_id, turn_id)
        REFERENCES session_turns(session_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE RESTRICT,
    FOREIGN KEY (call_id) REFERENCES dispatch_jobs(call_id) ON DELETE RESTRICT,
    CHECK (
        (kind = 'session_turn'
            AND session_id IS NOT NULL
            AND turn_id IS NOT NULL
            AND run_id IS NULL
            AND call_id IS NULL)
        OR
        (kind = 'dispatch'
            AND session_id IS NULL
            AND turn_id IS NULL
            AND run_id IS NOT NULL
            AND call_id IS NOT NULL)
    )
) STRICT;

-- NULLs in the inactive binding columns prevent a single table-level UNIQUE
-- constraint from enforcing identity. Partial indexes give each reservation
-- kind its natural durable key without concatenating potentially oversized
-- legacy identifiers.
CREATE UNIQUE INDEX finalization_reservations_turn_idx
    ON finalization_reservations(session_id, turn_id)
    WHERE kind = 'session_turn';

CREATE UNIQUE INDEX finalization_reservations_dispatch_idx
    ON finalization_reservations(run_id, call_id)
    WHERE kind = 'dispatch';

CREATE INDEX finalization_reservations_scope_active_idx
    ON finalization_reservations(scope_id, kind, remaining_event_slots)
    WHERE remaining_event_slots > 0;

CREATE INDEX finalization_reservations_kind_active_idx
    ON finalization_reservations(kind, remaining_event_slots)
    WHERE remaining_event_slots > 0;

-- Global expiry cleanup must not scan every user's sessions. token_hash makes
-- a bounded expiry batch deterministic when multiple rows share expires_at.
CREATE INDEX auth_sessions_expiry_idx
    ON auth_sessions(expires_at, token_hash);

CREATE TRIGGER finalization_reservations_require_dispatch_binding
BEFORE INSERT ON finalization_reservations
WHEN NEW.kind = 'dispatch'
 AND NOT EXISTS (
     SELECT 1
     FROM dispatch_jobs j
     WHERE j.run_id = NEW.run_id
       AND j.call_id = NEW.call_id
 )
BEGIN
    SELECT RAISE(ABORT, 'dispatch reservation must match its durable job');
END;

CREATE TRIGGER finalization_reservations_require_resource_scope_on_insert
BEFORE INSERT ON finalization_reservations
WHEN NOT (
    (NEW.kind = 'session_turn'
        AND NEW.scope_id IS COALESCE((
            SELECT s.owner_user_id
            FROM sessions s
            WHERE s.id = NEW.session_id
        ), '__legacy__'))
    OR
    (NEW.kind = 'dispatch'
        AND NEW.scope_id IS COALESCE((
            SELECT r.owner_user_id
            FROM runs r
            WHERE r.id = NEW.run_id
        ), '__legacy__'))
)
BEGIN
    SELECT RAISE(ABORT, 'reservation scope must match its resource owner');
END;

-- Bootstrap claims unowned sessions and runs before claiming their active
-- reservations. That is the only permitted scope transition.
CREATE TRIGGER finalization_reservations_require_resource_scope_on_claim
BEFORE UPDATE OF scope_id ON finalization_reservations
WHEN OLD.scope_id IS NOT NEW.scope_id
 AND NOT (
     OLD.scope_id = '__legacy__'
     AND NEW.scope_id <> '__legacy__'
     AND (
         (NEW.kind = 'session_turn'
             AND NEW.scope_id IS (
                 SELECT s.owner_user_id
                 FROM sessions s
                 WHERE s.id = NEW.session_id
             ))
         OR
         (NEW.kind = 'dispatch'
             AND NEW.scope_id IS (
                 SELECT r.owner_user_id
                 FROM runs r
                 WHERE r.id = NEW.run_id
             ))
     )
 )
BEGIN
    SELECT RAISE(ABORT, 'reservation can only be claimed by its resource owner');
END;

CREATE TRIGGER finalization_reservations_enforce_update
BEFORE UPDATE ON finalization_reservations
WHEN NOT (
    NEW.kind IS OLD.kind
    AND NEW.session_id IS OLD.session_id
    AND NEW.turn_id IS OLD.turn_id
    AND NEW.run_id IS OLD.run_id
    AND NEW.call_id IS OLD.call_id
    AND NEW.reserved_bytes IS OLD.reserved_bytes
    AND NEW.created_at IS OLD.created_at
    AND (
        (NEW.scope_id IS OLD.scope_id
            AND NEW.remaining_event_slots >= 0
            AND NEW.remaining_event_slots < OLD.remaining_event_slots)
        OR
        (OLD.scope_id = '__legacy__'
            AND NEW.scope_id <> '__legacy__'
            AND NEW.remaining_event_slots = OLD.remaining_event_slots)
    )
)
BEGIN
    SELECT RAISE(ABORT, 'reservation updates must consume slots or claim legacy scope');
END;

-- A terminal transaction may consume all remaining capacity at once and then
-- remove the empty reservation. Live capacity cannot be released early.
CREATE TRIGGER finalization_reservations_reject_live_delete
BEFORE DELETE ON finalization_reservations
WHEN OLD.remaining_event_slots <> 0
BEGIN
    SELECT RAISE(ABORT, 'reservation must be empty before deletion');
END;

-- Existing active work is admitted as-is even when it already exceeds newly
-- configured quotas. Migration reserves every required terminal event so old
-- databases can always drain safely instead of failing to open.
INSERT INTO finalization_reservations(
    kind, scope_id, session_id, turn_id, run_id, call_id,
    remaining_event_slots, reserved_bytes, created_at
)
SELECT
    'session_turn',
    COALESCE(s.owner_user_id, '__legacy__'),
    t.session_id,
    t.id,
    NULL,
    NULL,
    2,
    NULL,
    t.started_at
FROM session_turns t
JOIN sessions s ON s.id = t.session_id
WHERE t.status = 'open'
ORDER BY t.session_id, t.ordinal, t.id;

INSERT INTO finalization_reservations(
    kind, scope_id, session_id, turn_id, run_id, call_id,
    remaining_event_slots, reserved_bytes, created_at
)
SELECT
    'dispatch',
    COALESCE(r.owner_user_id, '__legacy__'),
    NULL,
    NULL,
    j.run_id,
    j.call_id,
    CASE j.status
        WHEN 'queued' THEN 2
        WHEN 'started' THEN 1
    END,
    NULL,
    j.queued_at
FROM dispatch_jobs j
JOIN runs r ON r.id = j.run_id
WHERE j.status IN ('queued', 'started')
ORDER BY j.run_id, j.queued_at, j.call_id;
