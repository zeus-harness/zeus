-- Bind every newly admitted Agent turn to one exact, immutable knowledge
-- corpus revision and one account-scoped selection context. The knowledge
-- domain digests are account-neutral; `agent_knowledge_contexts.digest` is a
-- separate storage binding digest over the canonical `binding_json` payload.

CREATE TABLE knowledge_corpus_revisions (
    account_id             TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT
        CHECK (length(account_id) BETWEEN 1 AND 128 AND account_id = trim(account_id)),
    digest                 TEXT NOT NULL CHECK (
        length(digest) = 64
        AND digest NOT GLOB '*[^0-9a-f]*'
    ),
    schema_version         INTEGER NOT NULL CHECK (schema_version = 1),
    entry_count            INTEGER NOT NULL CHECK (entry_count BETWEEN 0 AND 256),
    -- Sum of every entry_id, revision, title, and content UTF-8 byte length.
    aggregate_entry_bytes  INTEGER NOT NULL CHECK (
        aggregate_entry_bytes BETWEEN 0 AND 524288
    ),
    envelope_json          TEXT NOT NULL CHECK (
        json_valid(envelope_json)
        AND json_type(envelope_json) = 'object'
        AND length(CAST(envelope_json AS BLOB)) BETWEEN 1 AND 2097152
        AND COALESCE(json_type(envelope_json, '$.schema_version') = 'integer', 0)
        AND COALESCE(json_extract(envelope_json, '$.schema_version') = schema_version, 0)
        AND COALESCE(json_type(envelope_json, '$.digest') = 'text', 0)
        AND COALESCE(json_extract(envelope_json, '$.digest') = digest, 0)
        AND COALESCE(json_type(envelope_json, '$.entries') = 'array', 0)
        AND COALESCE(json_array_length(envelope_json, '$.entries') = entry_count, 0)
    ),
    created_at             TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
    PRIMARY KEY (account_id, digest)
) STRICT, WITHOUT ROWID;

CREATE INDEX knowledge_corpus_revisions_account_created_idx
    ON knowledge_corpus_revisions(account_id, created_at, digest);

CREATE TRIGGER knowledge_corpus_revisions_reject_update
BEFORE UPDATE ON knowledge_corpus_revisions
BEGIN
    SELECT RAISE(ABORT, 'knowledge corpus revisions are immutable');
END;

CREATE TRIGGER knowledge_corpus_revisions_reject_delete
BEFORE DELETE ON knowledge_corpus_revisions
BEGIN
    SELECT RAISE(ABORT, 'knowledge corpus revisions cannot be deleted');
END;

CREATE TABLE agent_knowledge_contexts (
    digest                       TEXT PRIMARY KEY CHECK (
        length(digest) = 64
        AND digest NOT GLOB '*[^0-9a-f]*'
    ),
    schema_version               INTEGER NOT NULL CHECK (schema_version = 1),
    account_id                   TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT
        CHECK (length(account_id) BETWEEN 1 AND 128 AND account_id = trim(account_id)),
    actor_user_id                TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT
        CHECK (length(trim(actor_user_id)) > 0),
    actor_membership_revision    INTEGER NOT NULL CHECK (actor_membership_revision > 0),
    session_id                   TEXT NOT NULL CHECK (length(trim(session_id)) BETWEEN 1 AND 384),
    turn_id                      TEXT NOT NULL CHECK (length(trim(turn_id)) BETWEEN 1 AND 384),
    agent_id                     TEXT NOT NULL UNIQUE
        CHECK (length(trim(agent_id)) BETWEEN 1 AND 384),
    initial_model_job_id         TEXT NOT NULL UNIQUE
        CHECK (length(trim(initial_model_job_id)) BETWEEN 1 AND 384),
    corpus_digest                TEXT NOT NULL CHECK (
        length(corpus_digest) = 64
        AND corpus_digest NOT GLOB '*[^0-9a-f]*'
    ),
    snapshot_digest              TEXT NOT NULL CHECK (
        length(snapshot_digest) = 64
        AND snapshot_digest NOT GLOB '*[^0-9a-f]*'
    ),
    query_digest                 TEXT NOT NULL CHECK (
        length(query_digest) = 64
        AND query_digest NOT GLOB '*[^0-9a-f]*'
    ),
    context_digest               TEXT NOT NULL CHECK (
        length(context_digest) = 64
        AND context_digest NOT GLOB '*[^0-9a-f]*'
    ),
    context_bytes                INTEGER NOT NULL CHECK (context_bytes BETWEEN 1 AND 16384),
    canonical_context            TEXT NOT NULL CHECK (
        length(CAST(canonical_context AS BLOB)) = context_bytes
    ),
    snapshot_envelope_json       TEXT NOT NULL CHECK (
        json_valid(snapshot_envelope_json)
        AND json_type(snapshot_envelope_json) = 'object'
        AND length(CAST(snapshot_envelope_json AS BLOB)) BETWEEN 1 AND 262144
        AND COALESCE(json_type(snapshot_envelope_json, '$.schema_version') = 'integer', 0)
        AND COALESCE(json_extract(snapshot_envelope_json, '$.schema_version') = 1, 0)
        AND COALESCE(json_type(snapshot_envelope_json, '$.digest') = 'text', 0)
        AND COALESCE(json_extract(snapshot_envelope_json, '$.digest') = snapshot_digest, 0)
        AND COALESCE(json_type(snapshot_envelope_json, '$.snapshot') = 'object', 0)
        AND COALESCE(json_extract(snapshot_envelope_json, '$.snapshot.schema_version') = 1, 0)
        AND COALESCE(json_extract(snapshot_envelope_json, '$.snapshot.corpus_digest') = corpus_digest, 0)
        AND COALESCE(json_extract(snapshot_envelope_json, '$.snapshot.query_digest') = query_digest, 0)
        AND COALESCE(json_extract(snapshot_envelope_json, '$.snapshot.context_digest') = context_digest, 0)
        AND COALESCE(json_extract(snapshot_envelope_json, '$.snapshot.context_bytes') = context_bytes, 0)
        AND COALESCE(json_type(snapshot_envelope_json, '$.snapshot.canonical_context') = 'text', 0)
        AND COALESCE(json_extract(
            snapshot_envelope_json, '$.snapshot.canonical_context'
        ) IS canonical_context, 0)
    ),
    binding_json                 TEXT NOT NULL CHECK (
        json_valid(binding_json)
        AND json_type(binding_json) = 'object'
        AND length(CAST(binding_json AS BLOB)) BETWEEN 1 AND 65536
        AND COALESCE(json_extract(binding_json, '$.schema_version') = schema_version, 0)
        AND COALESCE(json_extract(binding_json, '$.account_id') IS account_id, 0)
        AND COALESCE(json_extract(binding_json, '$.actor_user_id') IS actor_user_id, 0)
        AND COALESCE(json_extract(
            binding_json, '$.actor_membership_revision'
        ) = actor_membership_revision, 0)
        AND COALESCE(json_extract(binding_json, '$.session_id') IS session_id, 0)
        AND COALESCE(json_extract(binding_json, '$.turn_id') IS turn_id, 0)
        AND COALESCE(json_extract(binding_json, '$.agent_id') IS agent_id, 0)
        AND COALESCE(json_extract(
            binding_json, '$.initial_model_job_id'
        ) IS initial_model_job_id, 0)
        AND COALESCE(json_extract(binding_json, '$.corpus_digest') IS corpus_digest, 0)
        AND COALESCE(json_extract(binding_json, '$.snapshot_digest') IS snapshot_digest, 0)
        AND COALESCE(json_extract(binding_json, '$.query_digest') IS query_digest, 0)
        AND COALESCE(json_extract(binding_json, '$.context_digest') IS context_digest, 0)
        AND COALESCE(json_extract(binding_json, '$.context_bytes') = context_bytes, 0)
        AND COALESCE(json_type(binding_json, '$.canonical_context') = 'text', 0)
        AND COALESCE(json_extract(binding_json, '$.canonical_context') IS canonical_context, 0)
        AND COALESCE(json_extract(binding_json, '$.created_at') IS created_at, 0)
    ),
    created_at                   TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
    UNIQUE (account_id, digest),
    FOREIGN KEY (account_id, actor_user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (account_id, session_id)
        REFERENCES sessions(account_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (session_id, turn_id)
        REFERENCES session_turns(session_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (account_id, corpus_digest)
        REFERENCES knowledge_corpus_revisions(account_id, digest) ON DELETE RESTRICT
) STRICT;

CREATE INDEX agent_knowledge_contexts_account_created_idx
    ON agent_knowledge_contexts(account_id, created_at, digest);
CREATE INDEX agent_knowledge_contexts_corpus_idx
    ON agent_knowledge_contexts(account_id, corpus_digest);

CREATE TRIGGER agent_knowledge_contexts_reject_update
BEFORE UPDATE ON agent_knowledge_contexts
BEGIN
    SELECT RAISE(ABORT, 'agent knowledge contexts are immutable');
END;

CREATE TRIGGER agent_knowledge_contexts_reject_delete
BEFORE DELETE ON agent_knowledge_contexts
BEGIN
    SELECT RAISE(ABORT, 'agent knowledge contexts cannot be deleted');
END;

-- Store a domain-separated commitment to the exact legacy set selected by
-- this migration. The Rust migration driver inserts the single row after the
-- per-Agent rows below exist and before schema version 22 commits. Keeping the
-- commitment independent from mutable rowid or wall-clock order prevents a
-- post-v22 Agent from being reclassified by adding one otherwise self-consistent
-- legacy row.
CREATE TABLE agent_knowledge_legacy_boundary (
    singleton       INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version  INTEGER NOT NULL CHECK (schema_version = 1),
    agent_count     INTEGER NOT NULL CHECK (agent_count >= 0),
    set_digest      TEXT NOT NULL CHECK (
        length(set_digest) = 64
        AND set_digest NOT GLOB '*[^0-9a-f]*'
    )
) STRICT, WITHOUT ROWID;

CREATE TRIGGER agent_knowledge_legacy_boundary_reject_insert
BEFORE INSERT ON agent_knowledge_legacy_boundary
WHEN EXISTS (SELECT 1 FROM agent_knowledge_legacy_boundary)
BEGIN
    SELECT RAISE(ABORT, 'legacy Agent knowledge boundary is already sealed');
END;

CREATE TRIGGER agent_knowledge_legacy_boundary_reject_update
BEFORE UPDATE ON agent_knowledge_legacy_boundary
BEGIN
    SELECT RAISE(ABORT, 'legacy Agent knowledge boundary commitment is immutable');
END;

CREATE TRIGGER agent_knowledge_legacy_boundary_reject_delete
BEFORE DELETE ON agent_knowledge_legacy_boundary
BEGIN
    SELECT RAISE(ABORT, 'legacy Agent knowledge boundary commitment cannot be deleted');
END;

-- Freeze the exact set of Agents that existed before knowledge binding was
-- introduced. Nullable v22 columns alone cannot distinguish honest legacy
-- history from a post-v22 binding that was stripped after corruption. The
-- initial job and execution-origin fact make the migration boundary itself
-- tamper-evident during deep verification.
CREATE TABLE agent_knowledge_legacy_agents (
    agent_id                       TEXT PRIMARY KEY
        REFERENCES agent_turns(id) ON DELETE RESTRICT,
    initial_model_job_id           TEXT NOT NULL UNIQUE
        REFERENCES agent_model_jobs(id) ON DELETE RESTRICT,
    execution_origin_fact_digest   TEXT NOT NULL CHECK (
        length(execution_origin_fact_digest) = 64
        AND execution_origin_fact_digest NOT GLOB '*[^0-9a-f]*'
    )
) STRICT, WITHOUT ROWID;

INSERT INTO agent_knowledge_legacy_agents(
    agent_id, initial_model_job_id, execution_origin_fact_digest
)
SELECT agent.id, initial_job.id, origin.fact_digest
FROM agent_turns AS agent
JOIN agent_model_jobs AS initial_job
  ON initial_job.agent_id = agent.id
 AND initial_job.step = 1
JOIN agent_execution_events AS origin
  ON origin.agent_id = agent.id
 AND origin.sequence = 1
ORDER BY agent.id;

CREATE TRIGGER agent_knowledge_legacy_agents_reject_insert
BEFORE INSERT ON agent_knowledge_legacy_agents
BEGIN
    SELECT RAISE(ABORT, 'legacy Agent knowledge boundary cannot grow');
END;

CREATE TRIGGER agent_knowledge_legacy_agents_reject_update
BEFORE UPDATE ON agent_knowledge_legacy_agents
BEGIN
    SELECT RAISE(ABORT, 'legacy Agent knowledge boundary is immutable');
END;

CREATE TRIGGER agent_knowledge_legacy_agents_reject_delete
BEFORE DELETE ON agent_knowledge_legacy_agents
BEGIN
    SELECT RAISE(ABORT, 'legacy Agent knowledge boundary cannot shrink');
END;

-- Keep legacy history readable. Only post-v22 inserts are required to carry a
-- context, and immutable identity/input triggers prevent later rebinding.
ALTER TABLE agent_turns
    ADD COLUMN knowledge_context_digest TEXT
        REFERENCES agent_knowledge_contexts(digest) ON DELETE RESTRICT;

ALTER TABLE agent_model_jobs
    ADD COLUMN knowledge_context_digest TEXT
        REFERENCES agent_knowledge_contexts(digest) ON DELETE RESTRICT;

CREATE INDEX agent_turns_knowledge_context_idx
    ON agent_turns(account_id, knowledge_context_digest)
    WHERE knowledge_context_digest IS NOT NULL;
CREATE INDEX agent_model_jobs_knowledge_context_idx
    ON agent_model_jobs(account_id, knowledge_context_digest)
    WHERE knowledge_context_digest IS NOT NULL;

-- One model step may produce at most one tool proposal. Earlier schemas
-- enforced this in the workflow reducer; make the durable cardinality
-- explicit so an ambiguous predecessor can never be selected during replay.
CREATE UNIQUE INDEX agent_tool_calls_one_per_model_step_idx
    ON agent_tool_calls(agent_id, model_step);

CREATE TRIGGER agent_turns_require_knowledge_context
BEFORE INSERT ON agent_turns
WHEN NEW.knowledge_context_digest IS NULL
  OR NOT EXISTS (
      SELECT 1
      FROM agent_knowledge_contexts context
      WHERE context.digest = NEW.knowledge_context_digest
        AND context.account_id = NEW.account_id
        AND context.actor_user_id = NEW.actor_user_id
        AND context.actor_membership_revision = NEW.actor_membership_revision
        AND context.session_id = NEW.session_id
        AND context.turn_id = NEW.turn_id
        AND context.agent_id = NEW.id
        AND context.created_at = NEW.created_at
  )
BEGIN
    SELECT RAISE(ABORT, 'new agent turn requires its exact knowledge context');
END;

DROP TRIGGER agent_turns_reject_identity_update;

CREATE TRIGGER agent_turns_reject_identity_update
BEFORE UPDATE OF id, account_id, actor_user_id, actor_membership_revision,
                 session_id, turn_id, deployment_manifest_digest,
                 knowledge_context_digest, environment, provider_name,
                 model_name, created_at
ON agent_turns
BEGIN
    SELECT RAISE(ABORT, 'agent turn identity is immutable');
END;

DROP TRIGGER agent_model_jobs_require_current_step;

CREATE TRIGGER agent_model_jobs_require_current_step
BEFORE INSERT ON agent_model_jobs
WHEN NEW.knowledge_context_digest IS NULL
  OR NOT EXISTS (
      SELECT 1
      FROM agent_turns agent
      JOIN agent_knowledge_contexts context
        ON context.digest = agent.knowledge_context_digest
       AND context.account_id = agent.account_id
      WHERE agent.id = NEW.agent_id
        AND agent.account_id = NEW.account_id
        AND agent.session_id = NEW.session_id
        AND agent.turn_id = NEW.turn_id
        AND agent.actor_user_id = NEW.actor_user_id
        AND agent.actor_membership_revision = NEW.actor_membership_revision
        AND agent.provider_name = NEW.provider_name
        AND agent.model_name IS NEW.model_name
        AND agent.knowledge_context_digest = NEW.knowledge_context_digest
        AND agent.status = 'waiting_model'
        AND agent.model_steps + 1 = NEW.step
        AND context.actor_user_id = NEW.actor_user_id
        AND context.actor_membership_revision = NEW.actor_membership_revision
        AND context.session_id = NEW.session_id
        AND context.turn_id = NEW.turn_id
        AND context.agent_id = NEW.agent_id
        AND (
            (NEW.step = 1
             AND context.initial_model_job_id = NEW.id
             AND context.created_at = NEW.queued_at)
            OR
            (NEW.step > 1 AND EXISTS (
                SELECT 1
                FROM agent_model_jobs initial_job
                WHERE initial_job.id = context.initial_model_job_id
                  AND initial_job.agent_id = NEW.agent_id
                  AND initial_job.account_id = NEW.account_id
                  AND initial_job.step = 1
                  AND initial_job.knowledge_context_digest = NEW.knowledge_context_digest
                  AND initial_job.queued_at = context.created_at
            ))
        )
  )
BEGIN
    SELECT RAISE(ABORT, 'agent model job does not match the current step or knowledge context');
END;

DROP TRIGGER agent_model_jobs_reject_input_update;

CREATE TRIGGER agent_model_jobs_reject_input_update
BEFORE UPDATE OF id, agent_id, account_id, actor_user_id, actor_membership_revision,
                 session_id, turn_id, step, provider_name, model_name,
                 request_json, knowledge_context_digest, queued_at
ON agent_model_jobs
BEGIN
    SELECT RAISE(ABORT, 'agent model job input is immutable');
END;
