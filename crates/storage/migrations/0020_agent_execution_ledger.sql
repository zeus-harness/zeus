-- Immutable per-operation authority and an Agent-local append-only execution
-- ledger. Existing Agent turns receive one honest legacy_snapshot in Rust;
-- this migration deliberately does not manufacture their missing history.

CREATE TRIGGER schema_migrations_reject_update
BEFORE UPDATE ON schema_migrations
BEGIN
    SELECT RAISE(ABORT, 'schema migration history is immutable');
END;

CREATE TRIGGER schema_migrations_reject_delete
BEFORE DELETE ON schema_migrations
BEGIN
    SELECT RAISE(ABORT, 'schema migration history is immutable');
END;

CREATE TABLE agent_run_epochs (
    digest                         TEXT PRIMARY KEY CHECK (
        length(digest) = 64 AND digest NOT GLOB '*[^0-9a-f]*'
    ),
    schema_version                 INTEGER NOT NULL CHECK (schema_version = 1),
    agent_id                       TEXT NOT NULL
        REFERENCES agent_turns(id) ON DELETE RESTRICT,
    account_id                     TEXT NOT NULL
        REFERENCES accounts(id) ON DELETE RESTRICT,
    session_id                     TEXT NOT NULL,
    turn_id                        TEXT NOT NULL,
    workflow_revision              INTEGER NOT NULL CHECK (workflow_revision > 0),
    operation_kind                 TEXT NOT NULL CHECK (operation_kind IN ('model', 'tool')),
    model_job_id                   TEXT
        REFERENCES agent_model_jobs(id) ON DELETE RESTRICT,
    tool_call_id                   TEXT
        REFERENCES agent_tool_calls(call_id) ON DELETE RESTRICT,
    bound_manifest_digest          TEXT NOT NULL
        REFERENCES agent_deployment_manifests(digest) ON DELETE RESTRICT,
    observed_manifest_digest       TEXT NOT NULL
        REFERENCES agent_deployment_manifests(digest) ON DELETE RESTRICT,
    deployment_check               TEXT NOT NULL CHECK (deployment_check = 'matched'),
    actor_user_id                  TEXT NOT NULL
        REFERENCES users(id) ON DELETE RESTRICT,
    actor_membership_revision      INTEGER NOT NULL CHECK (actor_membership_revision > 0),
    approving_actor_user_id        TEXT
        REFERENCES users(id) ON DELETE RESTRICT,
    approving_membership_revision  INTEGER CHECK (approving_membership_revision > 0),
    input_digest                    TEXT NOT NULL CHECK (
        length(input_digest) = 64 AND input_digest NOT GLOB '*[^0-9a-f]*'
    ),
    envelope_json                  TEXT NOT NULL CHECK (
        json_valid(envelope_json)
        AND json_type(envelope_json) = 'object'
        AND length(CAST(envelope_json AS BLOB)) <= 33024
        AND COALESCE(json_extract(envelope_json, '$.schema_version') = schema_version, 0)
        AND COALESCE(json_extract(envelope_json, '$.digest') = digest, 0)
        AND COALESCE(json_extract(envelope_json, '$.epoch.schema_version') = 1, 0)
        AND COALESCE(json_extract(envelope_json, '$.epoch.agent_id') = agent_id, 0)
        AND COALESCE(json_extract(envelope_json, '$.epoch.account_id') = account_id, 0)
        AND COALESCE(json_extract(envelope_json, '$.epoch.session_id') = session_id, 0)
        AND COALESCE(json_extract(envelope_json, '$.epoch.turn_id') = turn_id, 0)
        AND COALESCE(
            json_extract(envelope_json, '$.epoch.workflow_revision') = workflow_revision,
            0
        )
        AND COALESCE(json_extract(envelope_json, '$.epoch.operation.kind') = operation_kind, 0)
        AND json_extract(envelope_json, '$.epoch.operation.job_id') IS model_job_id
        AND json_extract(envelope_json, '$.epoch.operation.call_id') IS tool_call_id
        AND COALESCE(
            json_extract(envelope_json, '$.epoch.bound_manifest_digest')
                = bound_manifest_digest,
            0
        )
        AND COALESCE(
            json_extract(envelope_json, '$.epoch.observed_manifest_digest')
                = observed_manifest_digest,
            0
        )
        AND COALESCE(
            json_extract(envelope_json, '$.epoch.deployment_check') = deployment_check,
            0
        )
        AND COALESCE(
            json_extract(envelope_json, '$.epoch.initiator.user_id') = actor_user_id,
            0
        )
        AND COALESCE(
            json_extract(envelope_json, '$.epoch.initiator.membership_revision')
                = actor_membership_revision,
            0
        )
        AND json_extract(envelope_json, '$.epoch.approver.user_id')
            IS approving_actor_user_id
        AND json_extract(envelope_json, '$.epoch.approver.membership_revision')
            IS approving_membership_revision
        AND COALESCE(
            CASE operation_kind
                WHEN 'model' THEN json_extract(
                    envelope_json, '$.epoch.operation.request_digest'
                )
                ELSE json_extract(
                    envelope_json, '$.epoch.operation.arguments_digest'
                )
            END = input_digest,
            0
        )
        AND COALESCE(json_extract(envelope_json, '$.epoch.created_at') = created_at, 0)
    ),
    created_at                     TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
    UNIQUE (agent_id, digest),
    FOREIGN KEY (account_id, actor_user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (account_id, approving_actor_user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (account_id, session_id)
        REFERENCES sessions(account_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (session_id, turn_id)
        REFERENCES session_turns(session_id, id) ON DELETE RESTRICT,
    CHECK (
        (operation_kind = 'model' AND model_job_id IS NOT NULL AND tool_call_id IS NULL)
        OR
        (operation_kind = 'tool' AND model_job_id IS NULL AND tool_call_id IS NOT NULL)
    ),
    CHECK (
        (approving_actor_user_id IS NULL AND approving_membership_revision IS NULL)
        OR
        (approving_actor_user_id IS NOT NULL AND approving_membership_revision IS NOT NULL)
    ),
    CHECK (bound_manifest_digest = observed_manifest_digest)
) STRICT;

CREATE TABLE agent_execution_events (
    agent_id                 TEXT NOT NULL
        REFERENCES agent_turns(id) ON DELETE RESTRICT,
    sequence                 INTEGER NOT NULL CHECK (sequence > 0),
    fact_digest              TEXT NOT NULL CHECK (
        length(fact_digest) = 64 AND fact_digest NOT GLOB '*[^0-9a-f]*'
    ),
    previous_fact_digest     TEXT CHECK (
        previous_fact_digest IS NULL
        OR (length(previous_fact_digest) = 64
            AND previous_fact_digest NOT GLOB '*[^0-9a-f]*')
    ),
    fact_kind                TEXT NOT NULL CHECK (fact_kind IN (
        'agent_admitted', 'legacy_snapshot', 'workflow_transition'
    )),
    payload_version          INTEGER NOT NULL CHECK (payload_version = 1),
    agent_revision           INTEGER NOT NULL CHECK (agent_revision > 0),
    epoch_digest             TEXT,
    operation_kind           TEXT CHECK (operation_kind IN ('model', 'tool')),
    operation_id             TEXT CHECK (
        operation_id IS NULL OR length(trim(operation_id)) BETWEEN 1 AND 384
    ),
    envelope_json            TEXT NOT NULL CHECK (
        json_valid(envelope_json)
        AND json_type(envelope_json) = 'object'
        AND length(CAST(envelope_json AS BLOB)) <= 33024
        AND COALESCE(json_extract(envelope_json, '$.schema_version') = payload_version, 0)
        AND COALESCE(json_extract(envelope_json, '$.digest') = fact_digest, 0)
        AND COALESCE(json_extract(envelope_json, '$.fact.schema_version') = 1, 0)
        AND COALESCE(json_extract(envelope_json, '$.fact.agent_id') = agent_id, 0)
        AND COALESCE(json_extract(envelope_json, '$.fact.sequence') = sequence, 0)
        AND json_extract(envelope_json, '$.fact.previous_fact_digest')
            IS previous_fact_digest
        AND COALESCE(json_extract(envelope_json, '$.fact.data.kind') = fact_kind, 0)
        AND json_extract(envelope_json, '$.fact.data.epoch_digest') IS epoch_digest
        AND json_extract(envelope_json, '$.fact.data.subject.kind') IS operation_kind
        AND CASE operation_kind
            WHEN 'model' THEN json_extract(
                envelope_json, '$.fact.data.subject.job_id'
            ) IS operation_id
            WHEN 'tool' THEN json_extract(
                envelope_json, '$.fact.data.subject.call_id'
            ) IS operation_id
            ELSE operation_id IS NULL
        END
        AND COALESCE(json_extract(envelope_json, '$.fact.recorded_at') = created_at, 0)
        AND CASE fact_kind
            WHEN 'legacy_snapshot' THEN COALESCE(
                json_extract(envelope_json, '$.fact.data.origin_revision') = agent_revision,
                0
            )
            WHEN 'workflow_transition' THEN COALESCE(
                json_extract(envelope_json, '$.fact.data.to_revision') = agent_revision,
                0
            )
            ELSE 1
        END
    ),
    created_at                TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
    PRIMARY KEY (agent_id, sequence),
    FOREIGN KEY (agent_id, epoch_digest)
        REFERENCES agent_run_epochs(agent_id, digest) ON DELETE RESTRICT,
    CHECK (
        (sequence = 1 AND previous_fact_digest IS NULL)
        OR (sequence > 1 AND previous_fact_digest IS NOT NULL)
    ),
    CHECK (
        (operation_kind IS NULL AND operation_id IS NULL)
        OR (operation_kind IS NOT NULL AND operation_id IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE agent_execution_heads (
    agent_id                          TEXT PRIMARY KEY
        REFERENCES agent_turns(id) ON DELETE RESTRICT,
    schema_version                    INTEGER NOT NULL CHECK (schema_version = 1),
    head_sequence                     INTEGER NOT NULL CHECK (head_sequence > 0),
    projected_agent_revision          INTEGER NOT NULL CHECK (projected_agent_revision > 0),
    origin_revision                   INTEGER NOT NULL CHECK (origin_revision > 0),
    history_origin                    TEXT NOT NULL CHECK (
        history_origin IN ('native', 'legacy_snapshot')
    ),
    history_complete                  INTEGER NOT NULL CHECK (history_complete IN (0, 1)),
    head_hash                         TEXT NOT NULL CHECK (
        length(head_hash) = 64 AND head_hash NOT GLOB '*[^0-9a-f]*'
    ),
    committed_payload_bytes           INTEGER NOT NULL CHECK (committed_payload_bytes >= 0),
    created_at                        TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
    updated_at                        TEXT NOT NULL CHECK (length(trim(updated_at)) > 0),
    CHECK (
        (history_origin = 'native' AND history_complete = 1)
        OR (history_origin = 'legacy_snapshot' AND history_complete = 0)
    )
) STRICT;

CREATE UNIQUE INDEX agent_run_epochs_model_job_idx
    ON agent_run_epochs(model_job_id) WHERE model_job_id IS NOT NULL;
CREATE UNIQUE INDEX agent_run_epochs_tool_call_idx
    ON agent_run_epochs(tool_call_id) WHERE tool_call_id IS NOT NULL;
CREATE UNIQUE INDEX agent_run_epochs_agent_revision_idx
    ON agent_run_epochs(agent_id, workflow_revision);
CREATE INDEX agent_run_epochs_agent_created_idx
    ON agent_run_epochs(agent_id, created_at, digest);
CREATE UNIQUE INDEX agent_execution_events_digest_idx
    ON agent_execution_events(fact_digest);
CREATE INDEX agent_execution_events_epoch_idx
    ON agent_execution_events(agent_id, epoch_digest, sequence)
    WHERE epoch_digest IS NOT NULL;
CREATE INDEX agent_execution_events_operation_idx
    ON agent_execution_events(agent_id, operation_kind, operation_id, sequence)
    WHERE operation_id IS NOT NULL;

CREATE TRIGGER agent_run_epochs_require_release_binding
BEFORE INSERT ON agent_run_epochs
WHEN NOT EXISTS (
    SELECT 1
    FROM agent_turns agent
    WHERE agent.id = NEW.agent_id
      AND agent.account_id = NEW.account_id
      AND agent.session_id = NEW.session_id
      AND agent.turn_id = NEW.turn_id
      AND agent.actor_user_id = NEW.actor_user_id
      AND agent.actor_membership_revision = NEW.actor_membership_revision
      AND agent.deployment_manifest_digest = NEW.bound_manifest_digest
      AND NEW.observed_manifest_digest = NEW.bound_manifest_digest
      AND NEW.workflow_revision = agent.revision + 1
      AND (
          (NEW.operation_kind = 'model' AND EXISTS (
              SELECT 1
              FROM agent_model_jobs job
              WHERE job.id = NEW.model_job_id
                AND job.agent_id = NEW.agent_id
                AND job.account_id = NEW.account_id
                AND job.session_id = NEW.session_id
                AND job.turn_id = NEW.turn_id
                AND job.actor_user_id = NEW.actor_user_id
                AND job.actor_membership_revision = NEW.actor_membership_revision
                AND job.status = 'queued'
                AND job.attempt = 0
                AND job.step = json_extract(
                    NEW.envelope_json, '$.epoch.operation.step'
                )
          ))
          OR
          (NEW.operation_kind = 'tool' AND EXISTS (
              SELECT 1
              FROM agent_tool_calls call
              WHERE call.call_id = NEW.tool_call_id
                AND call.agent_id = NEW.agent_id
                AND call.account_id = NEW.account_id
                AND call.session_id = NEW.session_id
                AND call.turn_id = NEW.turn_id
                AND call.status = 'queued'
                AND call.ordinal = json_extract(
                    NEW.envelope_json, '$.epoch.operation.ordinal'
                )
                AND call.model_step = json_extract(
                    NEW.envelope_json, '$.epoch.operation.model_step'
                )
                AND call.tool_name = json_extract(
                    NEW.envelope_json, '$.epoch.operation.tool_name'
                )
                AND call.tool_version = json_extract(
                    NEW.envelope_json, '$.epoch.operation.tool_version'
                )
                AND call.effect = json_extract(
                    NEW.envelope_json, '$.epoch.operation.effect'
                )
                AND call.sandbox_profile = json_extract(
                    NEW.envelope_json, '$.epoch.operation.sandbox_profile'
                )
                AND call.policy_revision = json_extract(
                    NEW.envelope_json, '$.epoch.operation.policy_revision'
                )
                AND call.arguments_digest IN (
                    NEW.input_digest, 'sha256:' || NEW.input_digest
                )
                AND call.approving_actor_user_id IS NEW.approving_actor_user_id
                AND call.approving_membership_revision
                    IS NEW.approving_membership_revision
          ))
      )
)
BEGIN
    SELECT RAISE(ABORT, 'agent RunEpoch lacks a queued release binding');
END;

CREATE TRIGGER agent_execution_events_require_epoch_binding
BEFORE INSERT ON agent_execution_events
WHEN (
        NEW.epoch_digest IS NOT NULL
        OR json_extract(
            NEW.envelope_json, '$.fact.data.external_call.kind'
        ) IN ('model', 'tool')
    )
  AND NOT EXISTS (
      SELECT 1
      FROM agent_run_epochs epoch
      WHERE epoch.agent_id = NEW.agent_id
        AND epoch.digest = NEW.epoch_digest
        AND epoch.operation_kind = NEW.operation_kind
        AND CASE epoch.operation_kind
            WHEN 'model' THEN epoch.model_job_id = NEW.operation_id
            WHEN 'tool' THEN epoch.tool_call_id = NEW.operation_id
            ELSE 0
        END
        AND epoch.input_digest = json_extract(
            NEW.envelope_json, '$.fact.data.input_digest'
        )
        AND (
            json_extract(
                NEW.envelope_json, '$.fact.data.external_call.kind'
            ) IS NULL
            OR (
                epoch.workflow_revision = NEW.agent_revision
                AND epoch.created_at = NEW.created_at
                AND (
                    (epoch.operation_kind = 'model'
                     AND json_extract(
                         NEW.envelope_json, '$.fact.data.command.command'
                     ) = 'start_model'
                     AND json_extract(
                         epoch.envelope_json, '$.epoch.operation.step'
                     ) = json_extract(
                         NEW.envelope_json, '$.fact.data.external_call.step'
                     ))
                    OR
                    (epoch.operation_kind = 'tool'
                     AND json_extract(
                         NEW.envelope_json, '$.fact.data.command.command'
                     ) = 'start_tool'
                     AND json_extract(
                         epoch.envelope_json, '$.epoch.operation.ordinal'
                     ) = json_extract(
                         NEW.envelope_json, '$.fact.data.external_call.call'
                     ))
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM agent_execution_events prior
                    WHERE prior.agent_id = NEW.agent_id
                      AND prior.epoch_digest = NEW.epoch_digest
                      AND json_extract(
                          prior.envelope_json, '$.fact.data.command.command'
                      ) IN ('start_model', 'start_tool')
                )
            )
        )
  )
BEGIN
    SELECT RAISE(ABORT, 'agent execution fact lacks its RunEpoch binding');
END;

CREATE TRIGGER agent_run_epochs_reject_update
BEFORE UPDATE ON agent_run_epochs
BEGIN
    SELECT RAISE(ABORT, 'agent run epochs are immutable');
END;

CREATE TRIGGER agent_run_epochs_reject_delete
BEFORE DELETE ON agent_run_epochs
BEGIN
    SELECT RAISE(ABORT, 'agent run epochs cannot be deleted');
END;

CREATE TRIGGER agent_execution_events_reject_update
BEFORE UPDATE ON agent_execution_events
BEGIN
    SELECT RAISE(ABORT, 'agent execution events are append-only');
END;

CREATE TRIGGER agent_execution_events_reject_delete
BEFORE DELETE ON agent_execution_events
BEGIN
    SELECT RAISE(ABORT, 'agent execution events cannot be deleted');
END;

CREATE TRIGGER agent_execution_events_require_next_sequence
BEFORE INSERT ON agent_execution_events
WHEN NEW.sequence <> COALESCE((
        SELECT head_sequence + 1
        FROM agent_execution_heads
        WHERE agent_id = NEW.agent_id
    ), 1)
BEGIN
    SELECT RAISE(ABORT, 'agent execution sequence must be contiguous');
END;

CREATE TRIGGER agent_execution_events_require_chain
BEFORE INSERT ON agent_execution_events
WHEN (NEW.sequence = 1 AND NEW.previous_fact_digest IS NOT NULL)
  OR (NEW.sequence > 1 AND NEW.previous_fact_digest IS NOT (
        SELECT fact_digest
        FROM agent_execution_events
        WHERE agent_id = NEW.agent_id AND sequence = NEW.sequence - 1
    ))
BEGIN
    SELECT RAISE(ABORT, 'agent execution digest chain is invalid');
END;

CREATE TRIGGER agent_execution_heads_require_origin
BEFORE INSERT ON agent_execution_heads
WHEN NEW.head_sequence <> 1
  OR NOT EXISTS (
        SELECT 1
        FROM agent_execution_events event
        WHERE event.agent_id = NEW.agent_id
          AND event.sequence = 1
          AND event.fact_digest = NEW.head_hash
          AND event.agent_revision = NEW.projected_agent_revision
          AND length(CAST(event.envelope_json AS BLOB)) = NEW.committed_payload_bytes
          AND (
              (NEW.history_origin = 'native' AND event.fact_kind = 'agent_admitted')
              OR
              (NEW.history_origin = 'legacy_snapshot'
               AND event.fact_kind = 'legacy_snapshot'
               AND event.agent_revision = NEW.origin_revision)
          )
    )
BEGIN
    SELECT RAISE(ABORT, 'agent execution head does not match its origin fact');
END;

CREATE TRIGGER agent_execution_heads_enforce_forward_update
BEFORE UPDATE ON agent_execution_heads
WHEN NEW.agent_id IS NOT OLD.agent_id
  OR NEW.schema_version <> OLD.schema_version
  OR NEW.head_sequence <> OLD.head_sequence + 1
  OR NEW.projected_agent_revision <> OLD.projected_agent_revision + 1
  OR NEW.origin_revision <> OLD.origin_revision
  OR NEW.history_origin <> OLD.history_origin
  OR NEW.history_complete <> OLD.history_complete
  OR NEW.created_at <> OLD.created_at
  OR NOT EXISTS (
        SELECT 1
        FROM agent_execution_events event
        WHERE event.agent_id = NEW.agent_id
          AND event.sequence = NEW.head_sequence
          AND event.fact_digest = NEW.head_hash
          AND event.agent_revision = NEW.projected_agent_revision
          AND NEW.committed_payload_bytes =
              OLD.committed_payload_bytes
              + length(CAST(event.envelope_json AS BLOB))
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid agent execution head update');
END;

CREATE TRIGGER agent_execution_heads_reject_delete
BEFORE DELETE ON agent_execution_heads
BEGIN
    SELECT RAISE(ABORT, 'agent execution heads cannot be deleted');
END;

-- Claim-time authorization and deployment checks now happen before the
-- reducer releases external work. Persist the rejected queue item directly as
-- terminal, with attempt=1 proving the claim checkpoint was consumed.
DROP TRIGGER agent_model_jobs_enforce_forward_transition;

CREATE TRIGGER agent_model_jobs_enforce_forward_transition
BEFORE UPDATE ON agent_model_jobs
WHEN NOT (
        (OLD.status = 'queued' AND NEW.status = 'started'
         AND NEW.attempt = 1
         AND EXISTS (
             SELECT 1 FROM agent_turns agent
             WHERE agent.id = OLD.agent_id
               AND agent.status = 'model_running'
               AND agent.model_steps = OLD.step
         )
         AND EXISTS (
             SELECT 1
             FROM agent_run_epochs epoch
             JOIN agent_execution_events event
               ON event.agent_id = epoch.agent_id
              AND event.epoch_digest = epoch.digest
             JOIN agent_execution_heads head
               ON head.agent_id = event.agent_id
              AND head.head_sequence = event.sequence
              AND head.head_hash = event.fact_digest
             WHERE epoch.model_job_id = OLD.id
               AND epoch.operation_kind = 'model'
               AND epoch.workflow_revision = event.agent_revision
               AND json_extract(
                   event.envelope_json, '$.fact.data.command.command'
               ) = 'start_model'
         ))
        OR
        (OLD.status = 'queued' AND NEW.status = 'failed'
         AND NEW.attempt = 1
         AND NOT EXISTS (
             SELECT 1 FROM agent_run_epochs epoch
             WHERE epoch.model_job_id = OLD.id
         )
         AND EXISTS (
             SELECT 1 FROM agent_turns agent
             WHERE agent.id = OLD.agent_id
               AND agent.status = 'failed'
               AND agent.model_steps + 1 = OLD.step
               AND json_extract(
                   agent.workflow_state_json, '$.terminal_reason'
               ) = 'authorization_revoked'
         ))
        OR
        (OLD.status = 'started'
         AND NEW.status IN ('succeeded', 'failed', 'outcome_unknown')
         AND NEW.attempt = 1
         AND EXISTS (
             SELECT 1 FROM agent_turns agent
             WHERE agent.id = OLD.agent_id
               AND agent.model_steps = OLD.step
               AND (
                   (NEW.status = 'succeeded' AND (
                       agent.status IN (
                           'waiting_approval', 'tool_queued', 'waiting_model', 'succeeded'
                       )
                       OR (
                           agent.status = 'failed'
                           AND json_extract(
                               agent.workflow_state_json, '$.terminal_reason'
                           ) IN (
                               'tool_call_limit_reached',
                               'pending_approval_limit_reached',
                               'tool_result_bytes_limit_reached',
                               'model_step_limit_reached',
                               'continuation_unavailable'
                           )
                       )
                   ))
                   OR (NEW.status = 'failed' AND agent.status = 'failed')
                   OR (NEW.status = 'outcome_unknown' AND agent.status = 'needs_attention')
               )
         )
         AND (
             EXISTS (
                 SELECT 1
                 FROM agent_run_epochs epoch
                 JOIN agent_execution_events event
                   ON event.agent_id = epoch.agent_id
                  AND event.epoch_digest = epoch.digest
                 JOIN agent_execution_heads head
                   ON head.agent_id = event.agent_id
                  AND head.head_sequence >= event.sequence
                 WHERE epoch.model_job_id = OLD.id
                   AND epoch.operation_kind = 'model'
                   AND (
                       (NEW.status = 'succeeded' AND json_extract(
                           event.envelope_json, '$.fact.data.command.command'
                       ) IN ('model_final', 'model_tool_proposal'))
                       OR
                       (NEW.status = 'failed' AND json_extract(
                           event.envelope_json, '$.fact.data.command.command'
                       ) = 'model_failed')
                       OR
                       (NEW.status = 'outcome_unknown' AND json_extract(
                           event.envelope_json, '$.fact.data.command.command'
                       ) = 'model_outcome_unknown')
                   )
             )
             OR (
                 NEW.status = 'outcome_unknown'
                 AND NOT EXISTS (
                     SELECT 1 FROM agent_run_epochs epoch
                     WHERE epoch.model_job_id = OLD.id
                 )
                 AND EXISTS (
                     SELECT 1
                     FROM agent_execution_heads head
                     JOIN agent_execution_events event
                       ON event.agent_id = head.agent_id
                      AND event.sequence = head.head_sequence
                      AND event.fact_digest = head.head_hash
                     WHERE head.agent_id = OLD.agent_id
                       AND head.history_origin = 'legacy_snapshot'
                       AND head.head_sequence = 2
                       AND event.epoch_digest IS NULL
                       AND event.operation_kind = 'model'
                       AND event.operation_id = OLD.id
                       AND json_extract(
                           event.envelope_json, '$.fact.data.command.command'
                       ) = 'model_outcome_unknown'
                 )
             )
         ))
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid agent model job transition');
END;

DROP TRIGGER agent_tool_calls_enforce_forward_transition;

CREATE TRIGGER agent_tool_calls_enforce_forward_transition
BEFORE UPDATE ON agent_tool_calls
WHEN NOT (
        (OLD.status = 'waiting_approval'
         AND NEW.status IN ('queued', 'rejected')
         AND EXISTS (
             SELECT 1
             FROM accounts account
             JOIN account_memberships membership
               ON membership.account_id = account.id
              AND membership.user_id = NEW.approving_actor_user_id
             JOIN users user ON user.id = membership.user_id
             WHERE account.id = OLD.account_id
               AND account.status = 'active'
               AND membership.role = 'owner'
               AND membership.status = 'active'
               AND membership.revision = NEW.approving_membership_revision
               AND user.status = 'active'
         )
         AND EXISTS (
             SELECT 1 FROM agent_turns agent
             WHERE agent.id = OLD.agent_id
               AND (
                   (NEW.status = 'queued' AND agent.status = 'tool_queued'
                    AND agent.pending_call_id = OLD.call_id)
                   OR
                   (NEW.status = 'rejected'
                    AND agent.pending_call_id IS NULL
                    AND (
                        agent.status = 'waiting_model'
                        OR (
                            agent.status = 'failed'
                            AND json_extract(
                                agent.workflow_state_json, '$.terminal_reason'
                            ) IN (
                                'tool_result_bytes_limit_reached',
                                'model_step_limit_reached',
                                'continuation_unavailable'
                            )
                        )
                    ))
               )
         ))
        OR
        (OLD.status = 'queued' AND NEW.status = 'started'
         AND EXISTS (
             SELECT 1 FROM agent_turns agent
             WHERE agent.id = OLD.agent_id
               AND agent.status = 'tool_running'
               AND agent.pending_call_id = OLD.call_id
         )
         AND EXISTS (
             SELECT 1
             FROM agent_run_epochs epoch
             JOIN agent_execution_events event
               ON event.agent_id = epoch.agent_id
              AND event.epoch_digest = epoch.digest
             JOIN agent_execution_heads head
               ON head.agent_id = event.agent_id
              AND head.head_sequence = event.sequence
              AND head.head_hash = event.fact_digest
             WHERE epoch.tool_call_id = OLD.call_id
               AND epoch.operation_kind = 'tool'
               AND epoch.workflow_revision = event.agent_revision
               AND json_extract(
                   event.envelope_json, '$.fact.data.command.command'
               ) = 'start_tool'
         ))
        OR
        (OLD.status = 'queued' AND NEW.status = 'not_dispatched'
         AND NEW.started_at IS NULL
         AND NOT EXISTS (
             SELECT 1 FROM agent_run_epochs epoch
             WHERE epoch.tool_call_id = OLD.call_id
         )
         AND EXISTS (
             SELECT 1 FROM agent_turns agent
             WHERE agent.id = OLD.agent_id
               AND agent.status = 'failed'
               AND agent.pending_call_id IS NULL
               AND json_extract(
                   agent.workflow_state_json, '$.terminal_reason'
               ) = 'authorization_revoked'
         ))
        OR
        (OLD.status = 'started'
         AND NEW.status IN ('succeeded', 'failed', 'cancelled', 'not_dispatched', 'outcome_unknown')
         AND EXISTS (
             SELECT 1 FROM agent_turns agent
             WHERE agent.id = OLD.agent_id
               AND (
                   (NEW.status IN ('succeeded', 'failed', 'cancelled', 'not_dispatched')
                    AND agent.pending_call_id IS NULL
                    AND (
                        agent.status = 'waiting_model'
                        OR (
                            agent.status = 'failed'
                            AND json_extract(
                                agent.workflow_state_json, '$.terminal_reason'
                            ) IN (
                                'tool_result_bytes_limit_reached',
                                'model_step_limit_reached',
                                'continuation_unavailable',
                                'authorization_revoked'
                            )
                        )
                    ))
                   OR
                   (NEW.status = 'outcome_unknown'
                    AND agent.status = 'needs_attention'
                    AND agent.pending_call_id IS NULL)
               )
         )
         AND (
             EXISTS (
                 SELECT 1
                 FROM agent_run_epochs epoch
                 JOIN agent_execution_events event
                   ON event.agent_id = epoch.agent_id
                  AND event.epoch_digest = epoch.digest
                 JOIN agent_execution_heads head
                   ON head.agent_id = event.agent_id
                  AND head.head_sequence >= event.sequence
                 WHERE epoch.tool_call_id = OLD.call_id
                   AND epoch.operation_kind = 'tool'
                   AND (
                       (NEW.status IN ('succeeded', 'failed', 'cancelled', 'not_dispatched')
                        AND json_extract(
                            event.envelope_json, '$.fact.data.command.command'
                        ) = 'tool_result_known')
                       OR
                       (NEW.status = 'outcome_unknown' AND json_extract(
                           event.envelope_json, '$.fact.data.command.command'
                       ) = 'tool_outcome_unknown')
                   )
             )
             OR (
                 NEW.status = 'outcome_unknown'
                 AND NOT EXISTS (
                     SELECT 1 FROM agent_run_epochs epoch
                     WHERE epoch.tool_call_id = OLD.call_id
                 )
                 AND EXISTS (
                     SELECT 1
                     FROM agent_execution_heads head
                     JOIN agent_execution_events event
                       ON event.agent_id = head.agent_id
                      AND event.sequence = head.head_sequence
                      AND event.fact_digest = head.head_hash
                     WHERE head.agent_id = OLD.agent_id
                       AND head.history_origin = 'legacy_snapshot'
                       AND head.head_sequence = 2
                       AND event.epoch_digest IS NULL
                       AND event.operation_kind = 'tool'
                       AND event.operation_id = OLD.call_id
                       AND json_extract(
                           event.envelope_json, '$.fact.data.command.command'
                       ) = 'tool_outcome_unknown'
                 )
             )
         ))
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid agent tool call transition');
END;
