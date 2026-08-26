-- Account for the logical UTF-8 bytes stored in immutable event payloads.
-- This is deliberately not a physical SQLite/WAL/disk quota: only the
-- payload_json bytes of session_events and run_events are charged.

-- CAST(TEXT AS BLOB) follows the database encoding. Fail the enclosing
-- migration transaction before changing durable schema if this database does
-- not use the UTF-8 representation required by the byte-accounting contract.
CREATE TABLE event_payload_encoding_gate (
    encoding TEXT NOT NULL CHECK (encoding = 'UTF-8')
) STRICT;
INSERT INTO event_payload_encoding_gate(encoding)
SELECT encoding FROM pragma_encoding;
DROP TABLE event_payload_encoding_gate;

-- The v10 update guard does not know about byte reservations, so remove it
-- before backfilling the new column. Both guards are recreated below with the
-- slot and byte state machines coupled.
DROP TRIGGER finalization_reservations_enforce_update;
DROP TRIGGER finalization_reservations_reject_live_delete;

ALTER TABLE sessions ADD COLUMN event_payload_bytes INTEGER NOT NULL
    DEFAULT 0 CHECK (event_payload_bytes >= 0);
ALTER TABLE runs ADD COLUMN event_payload_bytes INTEGER NOT NULL
    DEFAULT 0 CHECK (event_payload_bytes >= 0);
ALTER TABLE finalization_reservations
    ADD COLUMN remaining_event_payload_bytes INTEGER NOT NULL
    DEFAULT 0 CHECK (remaining_event_payload_bytes >= 0);

-- CAST(... AS BLOB) makes length() count encoded bytes rather than Unicode
-- scalar values. SUM uses checked integer accumulation in SQLite and aborts
-- the enclosing migration transaction on an impossible signed-i64 overflow.
UPDATE sessions
SET event_payload_bytes = COALESCE((
    SELECT SUM(length(CAST(event.payload_json AS BLOB)))
    FROM session_events event
    WHERE event.session_id = sessions.id
), 0);

UPDATE runs
SET event_payload_bytes = COALESCE((
    SELECT SUM(length(CAST(event.payload_json AS BLOB)))
    FROM run_events event
    WHERE event.run_id = runs.id
), 0);

CREATE TABLE event_payload_usage (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    used_bytes INTEGER NOT NULL CHECK (used_bytes >= 0)
) STRICT;

INSERT INTO event_payload_usage(singleton, used_bytes)
SELECT
    1,
    COALESCE((SELECT SUM(event_payload_bytes) FROM sessions), 0)
        + COALESCE((SELECT SUM(event_payload_bytes) FROM runs), 0);

-- Existing work was admitted before byte quotas existed and must retain
-- enough capacity to reach a durable terminal state. Missing reply_jobs are
-- valid for manually opened turns, so their provider/model contribution is
-- zero. The nested CASE expression saturates at i64::MAX without evaluating
-- an overflowing multiplication or addition for oversized legacy values.
WITH session_reservation_sizes AS (
    SELECT
        reservation.rowid AS reservation_rowid,
        length(CAST(reservation.turn_id AS BLOB)) AS turn_bytes,
        length(CAST(COALESCE(job.provider_name, '') AS BLOB)) AS provider_bytes,
        length(CAST(COALESCE(job.model_name, '') AS BLOB)) AS model_bytes
    FROM finalization_reservations reservation
    LEFT JOIN reply_jobs job
      ON job.session_id = reservation.session_id
     AND job.turn_id = reservation.turn_id
    WHERE reservation.kind = 'session_turn'
)
UPDATE finalization_reservations
SET remaining_event_payload_bytes = (
    SELECT CASE
        WHEN sized.turn_bytes
             > ((9223372036854775807 - 524288) / 6) / 2
        THEN 9223372036854775807
        ELSE CASE
            WHEN sized.provider_bytes
                 > (9223372036854775807 - 524288) / 6
                    - 2 * sized.turn_bytes
            THEN 9223372036854775807
            ELSE CASE
                WHEN sized.model_bytes
                     > (9223372036854775807 - 524288) / 6
                        - 2 * sized.turn_bytes
                        - sized.provider_bytes
                THEN 9223372036854775807
                ELSE 524288 + 6 * (
                    2 * sized.turn_bytes
                    + sized.provider_bytes
                    + sized.model_bytes
                )
            END
        END
    END
    FROM session_reservation_sizes sized
    WHERE sized.reservation_rowid = finalization_reservations.rowid
)
WHERE kind = 'session_turn';

-- A queued dispatch still needs both its start and terminal event. A started
-- dispatch needs only its terminal event. The correlated subquery returning
-- NULL for an invalid binding intentionally trips the NOT NULL constraint and
-- aborts migration instead of inventing capacity for corrupt durable state.
UPDATE finalization_reservations
SET remaining_event_payload_bytes = (
    SELECT CASE job.status
        WHEN 'queued' THEN CASE
            WHEN length(CAST(job.call_id AS BLOB))
                 > (9223372036854775807 - 98304) / 12
            THEN 9223372036854775807
            ELSE 98304 + 12 * length(CAST(job.call_id AS BLOB))
        END
        WHEN 'started' THEN CASE
            WHEN length(CAST(job.call_id AS BLOB))
                 > (9223372036854775807 - 65536) / 6
            THEN 9223372036854775807
            ELSE 65536 + 6 * length(CAST(job.call_id AS BLOB))
        END
    END
    FROM dispatch_jobs job
    WHERE job.run_id = finalization_reservations.run_id
      AND job.call_id = finalization_reservations.call_id
      AND job.status IN ('queued', 'started')
)
WHERE kind = 'dispatch';

-- SQLite's INSERT OR REPLACE performs its implicit DELETE without invoking
-- DELETE triggers when recursive_triggers is disabled (the default). Keep the
-- existing trigger names, but reject reuse of an event ID before conflict
-- resolution can remove an immutable historical row and create a ledger gap.
DROP TRIGGER session_events_require_next_sequence;
CREATE TRIGGER session_events_require_next_sequence
BEFORE INSERT ON session_events
BEGIN
    SELECT CASE WHEN NEW.sequence <> (
        SELECT sequence + 1 FROM sessions WHERE id = NEW.session_id
    ) THEN RAISE(ABORT, 'session event sequence must be contiguous') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1
        FROM session_events event
        WHERE event.session_id = NEW.session_id
          AND event.event_id = NEW.event_id
    ) THEN RAISE(ABORT, 'session event ID already exists in this ledger') END;
END;

DROP TRIGGER run_events_require_next_sequence;
CREATE TRIGGER run_events_require_next_sequence
BEFORE INSERT ON run_events
BEGIN
    SELECT CASE WHEN NEW.sequence <> COALESCE((
        SELECT MAX(sequence) + 1
        FROM run_events
        WHERE run_id = NEW.run_id
    ), 1) THEN RAISE(ABORT, 'run event sequence must be contiguous') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1
        FROM run_events event
        WHERE event.run_id = NEW.run_id
          AND event.event_id = NEW.event_id
    ) THEN RAISE(ABORT, 'run event ID already exists in this ledger') END;
END;

-- A turn reservation is inserted before its optional reply job. At reply-job
-- insertion time all provider/model inputs are durable, so extend the existing
-- owner-boundary trigger to require the exact conservative byte reservation.
-- This closes the gap between the manual-turn lower bound and a provider turn.
DROP TRIGGER reply_jobs_require_session_owner;
CREATE TRIGGER reply_jobs_require_session_owner
BEFORE INSERT ON reply_jobs
BEGIN
    SELECT CASE WHEN EXISTS (
        SELECT 1
        FROM reply_jobs job
        WHERE job.id = NEW.id
           OR (job.session_id = NEW.session_id AND job.turn_id = NEW.turn_id)
    ) THEN RAISE(ABORT, 'reply job identity already exists') END;

    SELECT CASE WHEN NEW.actor_user_id IS NOT (
        SELECT owner_user_id FROM sessions WHERE id = NEW.session_id
    ) THEN RAISE(ABORT, 'reply actor must own the session') END;

    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM finalization_reservations reservation
        WHERE reservation.kind = 'session_turn'
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
    ) THEN RAISE(ABORT, 'reply job requires its exact finalization reservation') END;
END;

-- Every live reservation must carry both row and byte capacity. Empty rows
-- may exist only briefly inside the terminal transaction before deletion.
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
                    ELSE 524288
                        + 12 * length(CAST(NEW.turn_id AS BLOB))
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

-- Bootstrap may claim a legacy scope without consuming capacity. Every other
-- update is a consumption step and must strictly decrease both dimensions.
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
        (OLD.scope_id = '__legacy__'
            AND NEW.scope_id <> '__legacy__'
            AND NEW.remaining_event_slots = OLD.remaining_event_slots
            AND NEW.remaining_event_payload_bytes
                = OLD.remaining_event_payload_bytes)
        OR
        (NEW.scope_id IS OLD.scope_id
            AND NEW.remaining_event_payload_bytes
                < OLD.remaining_event_payload_bytes
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
                        ELSE 65536
                            + 6 * length(CAST(NEW.call_id AS BLOB))
                    END
                    AND EXISTS (
                        SELECT 1
                        FROM dispatch_jobs job
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
                        SELECT 1
                        FROM dispatch_jobs job
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
                        SELECT 1
                        FROM dispatch_jobs job
                        WHERE job.run_id = NEW.run_id
                          AND job.call_id = NEW.call_id
                          AND job.status = 'finished'
                    ))
            ))
    )
)
BEGIN
    SELECT RAISE(ABORT, 'reservation updates must consume slots and payload bytes or claim legacy scope');
END;

CREATE TRIGGER finalization_reservations_reject_live_delete
BEFORE DELETE ON finalization_reservations
WHEN OLD.remaining_event_slots <> 0
  OR OLD.remaining_event_payload_bytes <> 0
BEGIN
    SELECT RAISE(ABORT, 'reservation must be empty before deletion');
END;

-- Parent and global counters are append-only accumulators. Readiness also
-- recomputes their exact values, while these guards prevent rollback in the
-- ordinary write path.
CREATE TRIGGER sessions_event_payload_bytes_reject_rollback
BEFORE UPDATE OF event_payload_bytes ON sessions
WHEN NEW.event_payload_bytes < OLD.event_payload_bytes
BEGIN
    SELECT RAISE(ABORT, 'session event payload usage cannot decrease');
END;

CREATE TRIGGER runs_event_payload_bytes_reject_rollback
BEFORE UPDATE OF event_payload_bytes ON runs
WHEN NEW.event_payload_bytes < OLD.event_payload_bytes
BEGIN
    SELECT RAISE(ABORT, 'run event payload usage cannot decrease');
END;

CREATE TRIGGER event_payload_usage_reject_duplicate_insert
BEFORE INSERT ON event_payload_usage
WHEN EXISTS (SELECT 1 FROM event_payload_usage WHERE singleton = 1)
BEGIN
    SELECT RAISE(ABORT, 'event payload usage singleton already exists');
END;

CREATE TRIGGER event_payload_usage_enforce_monotonic_update
BEFORE UPDATE ON event_payload_usage
WHEN NEW.singleton IS NOT OLD.singleton
  OR NEW.used_bytes < OLD.used_bytes
BEGIN
    SELECT RAISE(ABORT, 'event payload usage cannot decrease');
END;

CREATE TRIGGER event_payload_usage_reject_delete
BEFORE DELETE ON event_payload_usage
BEGIN
    SELECT RAISE(ABORT, 'event payload usage is durable');
END;

-- Charge exactly the stored serialized TEXT value once, after every accepted
-- append. Explicit overflow checks keep the counters in the signed-i64 domain;
-- any failure rolls the event INSERT and both triggered updates back together.
CREATE TRIGGER session_events_charge_payload_bytes
AFTER INSERT ON session_events
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM event_payload_usage WHERE singleton = 1
    ) THEN RAISE(ABORT, 'event payload usage singleton is missing') END;
    SELECT CASE WHEN (
        SELECT event_payload_bytes
        FROM sessions
        WHERE id = NEW.session_id
    ) > 9223372036854775807 - length(CAST(NEW.payload_json AS BLOB))
    THEN RAISE(ABORT, 'session event payload usage overflow') END;
    SELECT CASE WHEN (
        SELECT used_bytes
        FROM event_payload_usage
        WHERE singleton = 1
    ) > 9223372036854775807 - length(CAST(NEW.payload_json AS BLOB))
    THEN RAISE(ABORT, 'global event payload usage overflow') END;

    UPDATE sessions
    SET event_payload_bytes = event_payload_bytes
        + length(CAST(NEW.payload_json AS BLOB))
    WHERE id = NEW.session_id;

    UPDATE event_payload_usage
    SET used_bytes = used_bytes + length(CAST(NEW.payload_json AS BLOB))
    WHERE singleton = 1;
END;

CREATE TRIGGER run_events_charge_payload_bytes
AFTER INSERT ON run_events
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM event_payload_usage WHERE singleton = 1
    ) THEN RAISE(ABORT, 'event payload usage singleton is missing') END;
    SELECT CASE WHEN (
        SELECT event_payload_bytes
        FROM runs
        WHERE id = NEW.run_id
    ) > 9223372036854775807 - length(CAST(NEW.payload_json AS BLOB))
    THEN RAISE(ABORT, 'run event payload usage overflow') END;
    SELECT CASE WHEN (
        SELECT used_bytes
        FROM event_payload_usage
        WHERE singleton = 1
    ) > 9223372036854775807 - length(CAST(NEW.payload_json AS BLOB))
    THEN RAISE(ABORT, 'global event payload usage overflow') END;

    UPDATE runs
    SET event_payload_bytes = event_payload_bytes
        + length(CAST(NEW.payload_json AS BLOB))
    WHERE id = NEW.run_id;

    UPDATE event_payload_usage
    SET used_bytes = used_bytes + length(CAST(NEW.payload_json AS BLOB))
    WHERE singleton = 1;
END;
