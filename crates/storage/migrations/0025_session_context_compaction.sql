-- Durable conversational compaction. Raw Session events and turn projections
-- remain immutable; a succeeded row only supplies a provider-visible checkpoint
-- for the exact complete-turn prefix bound by source sequences and digest.

CREATE TABLE session_compaction_jobs (
    id                          TEXT PRIMARY KEY
        CHECK (length(trim(id)) BETWEEN 1 AND 384),
    account_id                  TEXT NOT NULL
        REFERENCES accounts(id) ON DELETE RESTRICT,
    actor_user_id               TEXT NOT NULL
        REFERENCES users(id) ON DELETE RESTRICT,
    actor_membership_revision   INTEGER NOT NULL CHECK (actor_membership_revision > 0),
    session_id                  TEXT NOT NULL,
    generation                  INTEGER NOT NULL CHECK (generation > 0),
    previous_job_id             TEXT,
    provider_name               TEXT NOT NULL
        CHECK (length(trim(provider_name)) BETWEEN 1 AND 128),
    model_name                  TEXT NOT NULL
        CHECK (length(trim(model_name)) BETWEEN 1 AND 128),
    status                      TEXT NOT NULL CHECK (
        status IN ('queued', 'started', 'succeeded', 'failed', 'outcome_unknown')
    ),
    attempt                     INTEGER NOT NULL CHECK (attempt IN (0, 1)),
    source_start_sequence       INTEGER NOT NULL CHECK (source_start_sequence > 0),
    source_end_sequence         INTEGER NOT NULL CHECK (
        source_end_sequence >= source_start_sequence
    ),
    source_digest               TEXT NOT NULL CHECK (
        length(source_digest) = 64
        AND source_digest NOT GLOB '*[^0-9a-f]*'
    ),
    source_content_bytes        INTEGER NOT NULL
        CHECK (source_content_bytes BETWEEN 1 AND 262144),
    request_json                TEXT NOT NULL CHECK (
        json_valid(request_json)
        AND json_type(request_json) = 'object'
        AND length(CAST(request_json AS BLOB)) BETWEEN 1 AND 524288
    ),
    response_json               TEXT CHECK (
        response_json IS NULL
        OR (json_valid(response_json)
            AND json_type(response_json) = 'object'
            AND length(CAST(response_json AS BLOB)) BETWEEN 1 AND 524288)
    ),
    summary_text                TEXT CHECK (
        summary_text IS NULL
        OR length(CAST(summary_text AS BLOB)) BETWEEN 1 AND 16343
    ),
    summary_digest              TEXT CHECK (
        summary_digest IS NULL
        OR (length(summary_digest) = 64
            AND summary_digest NOT GLOB '*[^0-9a-f]*')
    ),
    summary_bytes               INTEGER CHECK (
        summary_bytes IS NULL OR summary_bytes BETWEEN 1 AND 16343
    ),
    error_json                  TEXT CHECK (
        error_json IS NULL
        OR (json_valid(error_json)
            AND json_type(error_json) = 'object'
            AND length(CAST(error_json AS BLOB)) BETWEEN 1 AND 32768)
    ),
    queued_at                   TEXT NOT NULL CHECK (length(trim(queued_at)) > 0),
    started_at                  TEXT,
    finished_at                 TEXT,
    UNIQUE (session_id, generation),
    UNIQUE (session_id, id),
    FOREIGN KEY (account_id, actor_user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (account_id, session_id)
        REFERENCES sessions(account_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (session_id, previous_job_id)
        REFERENCES session_compaction_jobs(session_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (session_id, source_start_sequence)
        REFERENCES session_events(session_id, sequence) ON DELETE RESTRICT,
    FOREIGN KEY (session_id, source_end_sequence)
        REFERENCES session_events(session_id, sequence) ON DELETE RESTRICT,
    CHECK (previous_job_id IS NULL OR generation > 1),
    CHECK (
        (status = 'queued' AND attempt = 0
         AND response_json IS NULL AND summary_text IS NULL
         AND summary_digest IS NULL AND summary_bytes IS NULL
         AND error_json IS NULL AND started_at IS NULL AND finished_at IS NULL)
        OR
        (status = 'started' AND attempt = 1
         AND response_json IS NULL AND summary_text IS NULL
         AND summary_digest IS NULL AND summary_bytes IS NULL
         AND error_json IS NULL AND started_at IS NOT NULL AND finished_at IS NULL)
        OR
        (status = 'succeeded' AND attempt = 1
         AND response_json IS NOT NULL AND summary_text IS NOT NULL
         AND summary_digest IS NOT NULL AND summary_bytes IS NOT NULL
         AND summary_bytes = length(CAST(summary_text AS BLOB))
         AND summary_bytes < source_content_bytes
         AND error_json IS NULL AND started_at IS NOT NULL AND finished_at IS NOT NULL)
        OR
        (status IN ('failed', 'outcome_unknown') AND attempt = 1
         AND response_json IS NULL AND summary_text IS NULL
         AND summary_digest IS NULL AND summary_bytes IS NULL
         AND error_json IS NOT NULL AND started_at IS NOT NULL AND finished_at IS NOT NULL)
    )
) STRICT;

CREATE UNIQUE INDEX session_compaction_jobs_one_active_idx
    ON session_compaction_jobs(session_id)
    WHERE status IN ('queued', 'started');

CREATE INDEX session_compaction_jobs_queue_idx
    ON session_compaction_jobs(status, queued_at, id)
    WHERE status = 'queued';

CREATE INDEX session_compaction_jobs_latest_success_idx
    ON session_compaction_jobs(session_id, generation DESC, source_end_sequence DESC)
    WHERE status = 'succeeded';

CREATE TRIGGER session_compaction_jobs_validate_insert
BEFORE INSERT ON session_compaction_jobs
WHEN NOT EXISTS (
        SELECT 1 FROM session_events
        WHERE session_id = NEW.session_id
          AND sequence = NEW.source_start_sequence
          AND event_kind = 'user_message'
    )
    OR NOT EXISTS (
        SELECT 1 FROM session_events
        WHERE session_id = NEW.session_id
          AND sequence = NEW.source_end_sequence
          AND event_kind = 'turn_flushed'
    )
    OR (
        NEW.previous_job_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1 FROM session_compaction_jobs previous
            WHERE previous.session_id = NEW.session_id
              AND previous.id = NEW.previous_job_id
              AND previous.status = 'succeeded'
              AND previous.generation < NEW.generation
              AND previous.source_end_sequence < NEW.source_start_sequence
              AND NOT EXISTS (
                  SELECT 1 FROM session_compaction_jobs later
                  WHERE later.session_id = previous.session_id
                    AND later.status = 'succeeded'
                    AND later.generation > previous.generation
              )
        )
    )
    OR (
        NEW.previous_job_id IS NULL
        AND EXISTS (
            SELECT 1 FROM session_compaction_jobs previous
            WHERE previous.session_id = NEW.session_id
              AND previous.status = 'succeeded'
        )
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid Session compaction source boundary');
END;

CREATE TRIGGER session_compaction_jobs_reject_identity_update
BEFORE UPDATE OF
    id, account_id, actor_user_id, actor_membership_revision, session_id,
    generation, previous_job_id, provider_name, model_name,
    source_start_sequence, source_end_sequence, source_digest,
    source_content_bytes, request_json, queued_at
ON session_compaction_jobs
BEGIN
    SELECT RAISE(ABORT, 'Session compaction identity and source are immutable');
END;

CREATE TRIGGER session_compaction_jobs_enforce_transition
BEFORE UPDATE ON session_compaction_jobs
WHEN NOT (
    (OLD.status = 'queued' AND NEW.status = 'started')
    OR
    (OLD.status = 'started' AND NEW.status IN ('succeeded', 'failed', 'outcome_unknown'))
)
BEGIN
    SELECT RAISE(ABORT, 'invalid Session compaction state transition');
END;

CREATE TRIGGER session_compaction_jobs_reject_delete
BEFORE DELETE ON session_compaction_jobs
BEGIN
    SELECT RAISE(ABORT, 'Session compaction jobs and checkpoints are durable');
END;
