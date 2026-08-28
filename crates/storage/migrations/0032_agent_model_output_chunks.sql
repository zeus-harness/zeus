-- Durable, append-only display output for started Agent model operations.
-- Chunks do not alter the Session ledger or model transcript; a successful
-- terminal response remains authoritative and must match the exact chunk
-- concatenation when the provider emitted any text deltas.

CREATE TABLE agent_model_output_chunks (
    account_id                  TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    actor_user_id               TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    actor_membership_revision   INTEGER NOT NULL CHECK (actor_membership_revision > 0),
    session_id                  TEXT NOT NULL,
    turn_id                     TEXT NOT NULL,
    agent_id                    TEXT NOT NULL REFERENCES agent_turns(id) ON DELETE RESTRICT,
    job_id                      TEXT NOT NULL REFERENCES agent_model_jobs(id) ON DELETE RESTRICT,
    step                        INTEGER NOT NULL CHECK (step BETWEEN 1 AND 8),
    sequence                    INTEGER NOT NULL CHECK (sequence BETWEEN 1 AND 8192),
    ordinal                     INTEGER NOT NULL CHECK (ordinal BETWEEN 1 AND 1024),
    content                     TEXT NOT NULL CHECK (
        length(CAST(content AS BLOB)) BETWEEN 1 AND 4096
    ),
    cumulative_bytes            INTEGER NOT NULL CHECK (
        cumulative_bytes BETWEEN 1 AND 65536
    ),
    created_at                  TEXT NOT NULL,
    PRIMARY KEY (agent_id, sequence),
    UNIQUE (job_id, ordinal),
    FOREIGN KEY (account_id, actor_user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (account_id, session_id)
        REFERENCES sessions(account_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (session_id, turn_id)
        REFERENCES session_turns(session_id, id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE INDEX agent_model_output_chunks_turn_page_idx
    ON agent_model_output_chunks(account_id, session_id, turn_id, sequence);
CREATE INDEX agent_model_output_chunks_job_idx
    ON agent_model_output_chunks(job_id, ordinal, cumulative_bytes);

CREATE TRIGGER agent_model_output_chunks_validate_insert
BEFORE INSERT ON agent_model_output_chunks
WHEN NEW.sequence <> COALESCE((
        SELECT MAX(prior.sequence) FROM agent_model_output_chunks prior
        WHERE prior.agent_id = NEW.agent_id
     ), 0) + 1
  OR NEW.ordinal <> COALESCE((
        SELECT MAX(prior.ordinal) FROM agent_model_output_chunks prior
        WHERE prior.job_id = NEW.job_id
     ), 0) + 1
  OR NEW.cumulative_bytes <> COALESCE((
        SELECT MAX(prior.cumulative_bytes) FROM agent_model_output_chunks prior
        WHERE prior.job_id = NEW.job_id
     ), 0) + length(CAST(NEW.content AS BLOB))
  OR NOT EXISTS (
        SELECT 1
        FROM agent_model_jobs job
        JOIN agent_turns agent ON agent.id = job.agent_id
        WHERE job.id = NEW.job_id
          AND job.status = 'started'
          AND job.account_id = NEW.account_id
          AND job.actor_user_id = NEW.actor_user_id
          AND job.actor_membership_revision = NEW.actor_membership_revision
          AND job.session_id = NEW.session_id
          AND job.turn_id = NEW.turn_id
          AND job.agent_id = NEW.agent_id
          AND job.step = NEW.step
          AND agent.account_id = NEW.account_id
          AND agent.actor_user_id = NEW.actor_user_id
          AND agent.actor_membership_revision = NEW.actor_membership_revision
          AND agent.session_id = NEW.session_id
          AND agent.turn_id = NEW.turn_id
          AND agent.status = 'model_running'
          AND agent.model_steps = NEW.step
     )
BEGIN
    SELECT RAISE(ABORT, 'invalid Agent model output chunk');
END;

CREATE TRIGGER agent_model_output_chunks_reject_update
BEFORE UPDATE ON agent_model_output_chunks
BEGIN
    SELECT RAISE(ABORT, 'Agent model output chunks are immutable');
END;

CREATE TRIGGER agent_model_output_chunks_reject_delete
BEFORE DELETE ON agent_model_output_chunks
BEGIN
    SELECT RAISE(ABORT, 'Agent model output chunks are durable');
END;
