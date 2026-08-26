CREATE TABLE incidents (
    id          TEXT PRIMARY KEY,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    status      TEXT NOT NULL CHECK (status IN ('investigating', 'mitigating', 'resolved')),
    service     TEXT NOT NULL,
    region      TEXT NOT NULL,
    user_impact TEXT NOT NULL,
    since       TEXT NOT NULL
) STRICT;

CREATE TABLE runs (
    id                     TEXT PRIMARY KEY,
    incident_id            TEXT NOT NULL REFERENCES incidents(id) ON DELETE RESTRICT,
    status                 TEXT NOT NULL CHECK (
        status IN ('waiting_for_approval', 'active', 'succeeded', 'failed', 'cancelled')
    ),
    environment            TEXT NOT NULL,
    started_at             TEXT NOT NULL,
    duration_seconds       INTEGER NOT NULL CHECK (duration_seconds >= 0),
    agent                  TEXT NOT NULL,
    sequence               INTEGER NOT NULL CHECK (sequence >= 0),
    projection_sequence    INTEGER NOT NULL CHECK (
        projection_sequence >= 0 AND projection_sequence <= sequence
    ),
    metrics_json           TEXT NOT NULL CHECK (json_valid(metrics_json)),
    evidence_json          TEXT NOT NULL CHECK (json_valid(evidence_json)),
    tool_policy_json       TEXT CHECK (
        tool_policy_json IS NULL OR json_valid(tool_policy_json)
    )
) STRICT;

CREATE TABLE run_events (
    run_id          TEXT NOT NULL REFERENCES runs(id) ON DELETE RESTRICT,
    sequence        INTEGER NOT NULL CHECK (sequence > 0),
    event_id        TEXT NOT NULL,
    event_kind      TEXT NOT NULL,
    payload_version INTEGER NOT NULL CHECK (payload_version > 0),
    payload_json    TEXT NOT NULL CHECK (json_valid(payload_json)),
    PRIMARY KEY (run_id, sequence),
    UNIQUE (run_id, event_id)
) STRICT, WITHOUT ROWID;

CREATE TRIGGER run_events_reject_update
BEFORE UPDATE ON run_events
BEGIN
    SELECT RAISE(ABORT, 'run_events are append-only');
END;

CREATE TRIGGER run_events_reject_delete
BEFORE DELETE ON run_events
BEGIN
    SELECT RAISE(ABORT, 'run_events are append-only');
END;

CREATE TABLE idempotency_receipts (
    idempotency_key        TEXT PRIMARY KEY,
    operation              TEXT NOT NULL,
    request_fingerprint    TEXT NOT NULL CHECK (json_valid(request_fingerprint)),
    response_json          TEXT NOT NULL CHECK (json_valid(response_json)),
    run_id                 TEXT NOT NULL,
    event_sequence         INTEGER NOT NULL,
    created_at             TEXT NOT NULL,
    FOREIGN KEY (run_id, event_sequence)
        REFERENCES run_events(run_id, sequence) ON DELETE RESTRICT
) STRICT;
