-- Durable prepared claims for Agent model and tool operations. A claim is a
-- single-process SQLite coordination record, not a cross-worker lease: its
-- holder and expiry are immutable, and another attempt uses the next
-- generation only after the active claim is released or expires.

CREATE TABLE agent_operation_claims (
    operation_kind  TEXT NOT NULL CHECK (operation_kind IN ('model', 'tool')),
    operation_id    TEXT NOT NULL CHECK (length(trim(operation_id)) BETWEEN 1 AND 384),
    model_job_id    TEXT REFERENCES agent_model_jobs(id) ON DELETE RESTRICT,
    tool_call_id    TEXT REFERENCES agent_tool_calls(call_id) ON DELETE RESTRICT,
    agent_id        TEXT NOT NULL REFERENCES agent_turns(id) ON DELETE RESTRICT,
    generation      INTEGER NOT NULL CHECK (generation > 0),
    holder_id       TEXT NOT NULL CHECK (length(trim(holder_id)) BETWEEN 1 AND 128),
    phase           TEXT NOT NULL CHECK (
        phase IN ('prepared', 'started', 'released', 'expired')
    ),
    acquired_at     TEXT NOT NULL CHECK (length(trim(acquired_at)) > 0),
    expires_at      TEXT NOT NULL CHECK (length(trim(expires_at)) > 0),
    started_at      TEXT CHECK (started_at IS NULL OR length(trim(started_at)) > 0),
    released_at     TEXT CHECK (released_at IS NULL OR length(trim(released_at)) > 0),
    PRIMARY KEY (operation_kind, operation_id, generation),
    CHECK (
        (operation_kind = 'model'
         AND model_job_id IS NOT NULL
         AND model_job_id = operation_id
         AND tool_call_id IS NULL)
        OR
        (operation_kind = 'tool'
         AND model_job_id IS NULL
         AND tool_call_id IS NOT NULL
         AND tool_call_id = operation_id)
    ),
    CHECK (
        (phase = 'prepared' AND started_at IS NULL AND released_at IS NULL)
        OR
        (phase = 'started' AND started_at IS NOT NULL AND released_at IS NULL)
        OR
        (phase = 'released' AND released_at IS NOT NULL)
        OR
        (phase = 'expired' AND started_at IS NULL AND released_at IS NOT NULL)
    )
) STRICT;

CREATE UNIQUE INDEX agent_operation_claims_one_active_idx
    ON agent_operation_claims(operation_kind, operation_id)
    WHERE phase IN ('prepared', 'started');

CREATE UNIQUE INDEX agent_operation_claims_one_prepared_holder_idx
    ON agent_operation_claims(operation_kind, holder_id)
    WHERE phase = 'prepared';

CREATE INDEX agent_operation_claims_prepared_expiry_idx
    ON agent_operation_claims(expires_at, operation_kind, operation_id, generation)
    WHERE phase = 'prepared';

CREATE TRIGGER agent_operation_claims_require_operation_binding
BEFORE INSERT ON agent_operation_claims
WHEN NOT (
    (NEW.operation_kind = 'model'
     AND NEW.model_job_id = NEW.operation_id
     AND NEW.tool_call_id IS NULL
     AND EXISTS (
         SELECT 1 FROM agent_model_jobs job
         WHERE job.id = NEW.model_job_id AND job.agent_id = NEW.agent_id
     ))
    OR
    (NEW.operation_kind = 'tool'
     AND NEW.model_job_id IS NULL
     AND NEW.tool_call_id = NEW.operation_id
     AND EXISTS (
         SELECT 1 FROM agent_tool_calls call
         WHERE call.call_id = NEW.tool_call_id AND call.agent_id = NEW.agent_id
     ))
)
BEGIN
    SELECT RAISE(ABORT, 'agent operation claim does not match its operation');
END;

CREATE TRIGGER agent_operation_claims_require_next_generation
BEFORE INSERT ON agent_operation_claims
WHEN NEW.generation <> COALESCE((
        SELECT MAX(claim.generation) + 1
        FROM agent_operation_claims claim
        WHERE claim.operation_kind = NEW.operation_kind
          AND claim.operation_id = NEW.operation_id
    ), 1)
BEGIN
    SELECT RAISE(ABORT, 'agent operation claim generation must be contiguous');
END;

CREATE TRIGGER agent_operation_claims_reject_identity_update
BEFORE UPDATE OF operation_kind, operation_id, model_job_id, tool_call_id,
                 agent_id, generation, holder_id, acquired_at, expires_at
ON agent_operation_claims
BEGIN
    SELECT RAISE(ABORT, 'agent operation claim identity is immutable');
END;

CREATE TRIGGER agent_operation_claims_enforce_forward_transition
BEFORE UPDATE ON agent_operation_claims
WHEN NOT (
    (OLD.phase = 'prepared'
     AND NEW.phase = 'started'
     AND NEW.started_at IS NOT NULL
     AND NEW.released_at IS NULL)
    OR
    (OLD.phase = 'prepared'
     AND NEW.phase IN ('released', 'expired')
     AND NEW.started_at IS NULL
     AND NEW.released_at IS NOT NULL)
    OR
    (OLD.phase = 'started'
     AND NEW.phase = 'released'
     AND NEW.started_at IS OLD.started_at
     AND NEW.released_at IS NOT NULL)
)
BEGIN
    SELECT RAISE(ABORT, 'invalid agent operation claim transition');
END;

CREATE TRIGGER agent_operation_claims_reject_delete
BEFORE DELETE ON agent_operation_claims
BEGIN
    SELECT RAISE(ABORT, 'agent operation claims are durable records');
END;

-- v20 recorded only the externally started checkpoint. Preserve that honest
-- boundary under a legacy holder. Started claims are not expiry-reclaimable,
-- so startup recovery or completion can release it; queued and terminal
-- operations did not own an active claim.
INSERT INTO agent_operation_claims(
    operation_kind, operation_id, model_job_id, tool_call_id, agent_id,
    generation, holder_id, phase, acquired_at, expires_at, started_at, released_at
)
SELECT 'model', job.id, job.id, NULL, job.agent_id,
       1, 'legacy-v20', 'started', job.started_at, job.started_at,
       job.started_at, NULL
FROM agent_model_jobs job
WHERE job.status = 'started';

INSERT INTO agent_operation_claims(
    operation_kind, operation_id, model_job_id, tool_call_id, agent_id,
    generation, holder_id, phase, acquired_at, expires_at, started_at, released_at
)
SELECT 'tool', call.call_id, NULL, call.call_id, call.agent_id,
       1, 'legacy-v20', 'started', call.started_at, call.started_at,
       call.started_at, NULL
FROM agent_tool_calls call
WHERE call.status = 'started';
