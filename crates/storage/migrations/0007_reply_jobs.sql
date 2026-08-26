CREATE TABLE reply_jobs (
    id              TEXT PRIMARY KEY CHECK (length(trim(id)) > 0),
    actor_user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    session_id      TEXT NOT NULL,
    turn_id         TEXT NOT NULL,
    provider_name   TEXT NOT NULL CHECK (length(trim(provider_name)) > 0),
    model_name      TEXT,
    status          TEXT NOT NULL CHECK (
        status IN ('queued', 'started', 'succeeded', 'failed', 'outcome_unknown')
    ),
    attempt         INTEGER NOT NULL DEFAULT 0 CHECK (attempt IN (0, 1)),
    request_json    TEXT NOT NULL CHECK (json_valid(request_json)),
    response_json   TEXT CHECK (response_json IS NULL OR json_valid(response_json)),
    error_json      TEXT CHECK (error_json IS NULL OR json_valid(error_json)),
    completion_fingerprint TEXT CHECK (
        completion_fingerprint IS NULL OR json_valid(completion_fingerprint)
    ),
    assistant_event_sequence INTEGER,
    terminal_event_sequence  INTEGER,
    queued_at       TEXT NOT NULL,
    started_at      TEXT,
    finished_at     TEXT,
    UNIQUE (session_id, turn_id),
    FOREIGN KEY (session_id, turn_id)
        REFERENCES session_turns(session_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (session_id, assistant_event_sequence)
        REFERENCES session_events(session_id, sequence) ON DELETE RESTRICT,
    FOREIGN KEY (session_id, terminal_event_sequence)
        REFERENCES session_events(session_id, sequence) ON DELETE RESTRICT,
    CHECK (model_name IS NULL OR length(trim(model_name)) > 0),
    CHECK (
        (status = 'queued'
            AND attempt = 0
            AND response_json IS NULL
            AND error_json IS NULL
            AND completion_fingerprint IS NULL
            AND assistant_event_sequence IS NULL
            AND terminal_event_sequence IS NULL
            AND started_at IS NULL
            AND finished_at IS NULL)
        OR
        (status = 'started'
            AND attempt = 1
            AND response_json IS NULL
            AND error_json IS NULL
            AND completion_fingerprint IS NULL
            AND assistant_event_sequence IS NULL
            AND terminal_event_sequence IS NULL
            AND started_at IS NOT NULL
            AND finished_at IS NULL)
        OR
        (status = 'succeeded'
            AND attempt = 1
            AND response_json IS NOT NULL
            AND error_json IS NULL
            AND completion_fingerprint IS NOT NULL
            AND assistant_event_sequence IS NOT NULL
            AND terminal_event_sequence = assistant_event_sequence + 1
            AND started_at IS NOT NULL
            AND finished_at IS NOT NULL)
        OR
        (status IN ('failed', 'outcome_unknown')
            AND attempt = 1
            AND response_json IS NULL
            AND error_json IS NOT NULL
            AND completion_fingerprint IS NOT NULL
            AND assistant_event_sequence IS NULL
            AND terminal_event_sequence IS NOT NULL
            AND started_at IS NOT NULL
            AND finished_at IS NOT NULL)
    )
) STRICT;

CREATE INDEX reply_jobs_ready_idx ON reply_jobs(status, queued_at, id);
CREATE INDEX reply_jobs_actor_idx ON reply_jobs(actor_user_id, status, queued_at, id);

CREATE TRIGGER reply_jobs_reject_input_update
BEFORE UPDATE OF
    id, actor_user_id, session_id, turn_id, provider_name, model_name,
    request_json, queued_at
ON reply_jobs
BEGIN
    SELECT RAISE(ABORT, 'reply job input is immutable');
END;

CREATE TRIGGER reply_jobs_enforce_forward_transition
BEFORE UPDATE ON reply_jobs
WHEN NOT (
    (OLD.status = 'queued' AND NEW.status = 'started')
    OR (OLD.status = 'started' AND NEW.status IN (
        'succeeded', 'failed', 'outcome_unknown'
    ))
)
BEGIN
    SELECT RAISE(ABORT, 'invalid reply job state transition');
END;

CREATE TRIGGER reply_jobs_reject_delete
BEFORE DELETE ON reply_jobs
BEGIN
    SELECT RAISE(ABORT, 'reply jobs are durable records');
END;
