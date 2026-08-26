ALTER TABLE runs ADD COLUMN execution_status TEXT NOT NULL
    DEFAULT 'waiting_for_approval'
    CHECK (execution_status IN (
        'waiting_for_approval',
        'queued',
        'running',
        'blocked',
        'needs_attention',
        'succeeded',
        'failed',
        'cancelled'
    ));

-- A v1 `active` projection has no durable dispatch row and cannot prove
-- whether any side effect started. Mark it for operator attention instead of
-- fabricating a resumable or already-started call.
UPDATE runs
SET execution_status = CASE status
    WHEN 'waiting_for_approval' THEN 'waiting_for_approval'
    WHEN 'active' THEN 'needs_attention'
    WHEN 'succeeded' THEN 'succeeded'
    WHEN 'failed' THEN 'failed'
    WHEN 'cancelled' THEN 'cancelled'
END;

CREATE TABLE dispatch_jobs (
    call_id                    TEXT PRIMARY KEY
        CHECK (length(trim(call_id)) > 0),
    run_id                     TEXT NOT NULL,
    approval_id                TEXT NOT NULL UNIQUE
        CHECK (length(trim(approval_id)) > 0),
    approval_event_sequence    INTEGER NOT NULL CHECK (approval_event_sequence > 0),
    tool_name                  TEXT NOT NULL CHECK (length(trim(tool_name)) > 0),
    tool_version               TEXT NOT NULL CHECK (length(trim(tool_version)) > 0),
    effect                     TEXT NOT NULL CHECK (
        effect IN ('read_only', 'local_write', 'production_write', 'destructive')
    ),
    args_json                  TEXT NOT NULL CHECK (json_valid(args_json)),
    args_digest                TEXT NOT NULL CHECK (length(trim(args_digest)) > 0),
    policy_id                  TEXT NOT NULL CHECK (length(trim(policy_id)) > 0),
    policy_revision            TEXT NOT NULL CHECK (length(trim(policy_revision)) > 0),
    sandbox_profile            TEXT NOT NULL CHECK (
        sandbox_profile IN (
            'read_only', 'workspace_write', 'isolated_container', 'production_guarded'
        )
    ),
    status                     TEXT NOT NULL CHECK (status IN ('queued', 'started', 'finished')),
    attempt                    INTEGER NOT NULL DEFAULT 0 CHECK (attempt IN (0, 1)),
    result_json                TEXT CHECK (result_json IS NULL OR json_valid(result_json)),
    queued_at                  TEXT NOT NULL,
    started_at                 TEXT,
    finished_at                TEXT,
    start_event_sequence       INTEGER CHECK (start_event_sequence > 0),
    result_event_sequence      INTEGER CHECK (result_event_sequence > 0),
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, approval_event_sequence)
        REFERENCES run_events(run_id, sequence) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, start_event_sequence)
        REFERENCES run_events(run_id, sequence) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, result_event_sequence)
        REFERENCES run_events(run_id, sequence) ON DELETE RESTRICT,
    CHECK (
        (status = 'queued'
            AND attempt = 0
            AND result_json IS NULL
            AND started_at IS NULL
            AND finished_at IS NULL
            AND start_event_sequence IS NULL
            AND result_event_sequence IS NULL)
        OR
        (status = 'started'
            AND attempt = 1
            AND result_json IS NULL
            AND started_at IS NOT NULL
            AND finished_at IS NULL
            AND start_event_sequence IS NOT NULL
            AND result_event_sequence IS NULL)
        OR
        (status = 'finished'
            AND attempt = 1
            AND result_json IS NOT NULL
            AND started_at IS NOT NULL
            AND finished_at IS NOT NULL
            AND start_event_sequence IS NOT NULL
            AND result_event_sequence IS NOT NULL)
    )
) STRICT;

CREATE INDEX dispatch_jobs_ready_idx
    ON dispatch_jobs(status, queued_at, call_id);

CREATE INDEX dispatch_jobs_run_idx
    ON dispatch_jobs(run_id, status, call_id);

CREATE TRIGGER dispatch_jobs_reject_input_update
BEFORE UPDATE OF
    call_id,
    run_id,
    approval_id,
    approval_event_sequence,
    tool_name,
    tool_version,
    effect,
    args_json,
    args_digest,
    policy_id,
    policy_revision,
    sandbox_profile,
    queued_at
ON dispatch_jobs
BEGIN
    SELECT RAISE(ABORT, 'dispatch job authorization is immutable');
END;

CREATE TRIGGER dispatch_jobs_enforce_forward_transition
BEFORE UPDATE ON dispatch_jobs
WHEN NOT (
    (OLD.status = 'queued' AND NEW.status = 'started')
    OR (OLD.status = 'started' AND NEW.status = 'finished')
)
BEGIN
    SELECT RAISE(ABORT, 'invalid dispatch job state transition');
END;

CREATE TRIGGER dispatch_jobs_reject_delete
BEFORE DELETE ON dispatch_jobs
BEGIN
    SELECT RAISE(ABORT, 'dispatch jobs are durable records');
END;
