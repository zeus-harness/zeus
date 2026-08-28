-- Durable FIFO inbox for ordinary user follow-ups. Enqueue is intentionally
-- separate from the Session event ledger: an item becomes a normal user turn
-- only when the driver atomically binds it to a Session turn and Agent.

CREATE TABLE session_followups (
    account_id                  TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    actor_user_id               TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    actor_membership_revision   INTEGER NOT NULL CHECK (actor_membership_revision > 0),
    session_id                  TEXT NOT NULL,
    turn_id                     TEXT NOT NULL UNIQUE,
    ordinal                     INTEGER NOT NULL CHECK (ordinal > 0),
    user_message                TEXT NOT NULL CHECK (
        length(CAST(user_message AS BLOB)) BETWEEN 1 AND 65536
        AND trim(user_message) = user_message
    ),
    status                      TEXT NOT NULL CHECK (status IN ('queued', 'claimed', 'discarded')),
    claimed_agent_id            TEXT UNIQUE REFERENCES agent_turns(id) ON DELETE RESTRICT,
    enqueued_at                 TEXT NOT NULL,
    claimed_at                  TEXT,
    discarded_at                TEXT,
    discard_reason              TEXT CHECK (
        discard_reason IS NULL OR (
            length(CAST(discard_reason AS BLOB)) BETWEEN 1 AND 256
            AND trim(discard_reason) = discard_reason
        )
    ),
    PRIMARY KEY (session_id, ordinal),
    UNIQUE (session_id, turn_id),
    FOREIGN KEY (account_id, actor_user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (account_id, session_id)
        REFERENCES sessions(account_id, id) ON DELETE RESTRICT,
    CHECK (
        (status = 'queued'
         AND claimed_agent_id IS NULL AND claimed_at IS NULL
         AND discarded_at IS NULL AND discard_reason IS NULL)
        OR
        (status = 'claimed'
         AND claimed_agent_id IS NOT NULL AND claimed_at IS NOT NULL
         AND discarded_at IS NULL AND discard_reason IS NULL)
        OR
        (status = 'discarded'
         AND claimed_agent_id IS NULL AND claimed_at IS NULL
         AND discarded_at IS NOT NULL AND discard_reason IS NOT NULL)
    )
) STRICT;

CREATE INDEX session_followups_ready_idx
    ON session_followups(status, enqueued_at, session_id, ordinal);
CREATE INDEX session_followups_actor_capacity_idx
    ON session_followups(account_id, actor_user_id, status);

CREATE TRIGGER session_followups_validate_insert
BEFORE INSERT ON session_followups
WHEN NEW.status <> 'queued'
  OR NEW.claimed_agent_id IS NOT NULL OR NEW.claimed_at IS NOT NULL
  OR NEW.discarded_at IS NOT NULL OR NEW.discard_reason IS NOT NULL
  OR NEW.ordinal <> COALESCE((
        SELECT MAX(prior.ordinal) FROM session_followups prior
        WHERE prior.session_id = NEW.session_id
     ), 0) + 1
  OR EXISTS (SELECT 1 FROM session_turns turn WHERE turn.id = NEW.turn_id)
  OR NOT EXISTS (
        SELECT 1
        FROM accounts account
        JOIN account_memberships membership
          ON membership.account_id = account.id
        JOIN users user ON user.id = membership.user_id
        JOIN sessions session ON session.account_id = account.id
        WHERE account.id = NEW.account_id
          AND account.status = 'active'
          AND membership.user_id = NEW.actor_user_id
          AND membership.status = 'active'
          AND membership.revision = NEW.actor_membership_revision
          AND user.status = 'active'
          AND session.id = NEW.session_id
     )
BEGIN
    SELECT RAISE(ABORT, 'invalid Session follow-up admission');
END;

CREATE TRIGGER session_followups_enforce_transition
BEFORE UPDATE ON session_followups
WHEN OLD.status <> 'queued'
  OR NEW.account_id IS NOT OLD.account_id
  OR NEW.actor_user_id IS NOT OLD.actor_user_id
  OR NEW.actor_membership_revision IS NOT OLD.actor_membership_revision
  OR NEW.session_id IS NOT OLD.session_id
  OR NEW.turn_id IS NOT OLD.turn_id
  OR NEW.ordinal IS NOT OLD.ordinal
  OR NEW.user_message IS NOT OLD.user_message
  OR NEW.enqueued_at IS NOT OLD.enqueued_at
  OR EXISTS (
        SELECT 1 FROM session_followups prior
        WHERE prior.session_id = OLD.session_id
          AND prior.status = 'queued'
          AND prior.ordinal < OLD.ordinal
     )
  OR NOT (
        (NEW.status = 'claimed'
         AND NEW.claimed_agent_id IS NOT NULL AND NEW.claimed_at IS NOT NULL
         AND NEW.discarded_at IS NULL AND NEW.discard_reason IS NULL
         AND EXISTS (
             SELECT 1
             FROM agent_turns agent
             JOIN session_turns turn
               ON turn.session_id = agent.session_id AND turn.id = agent.turn_id
             JOIN agent_model_jobs job
               ON job.agent_id = agent.id AND job.step = 1
             WHERE agent.id = NEW.claimed_agent_id
               AND agent.account_id = NEW.account_id
               AND agent.actor_user_id = NEW.actor_user_id
               AND agent.actor_membership_revision = NEW.actor_membership_revision
               AND agent.session_id = NEW.session_id
               AND agent.turn_id = NEW.turn_id
               AND agent.status = 'waiting_model'
               AND turn.status = 'open'
               AND job.status = 'queued'
               AND agent.created_at = NEW.claimed_at
               AND turn.started_at = NEW.claimed_at
               AND job.queued_at = NEW.claimed_at
         ))
        OR
        (NEW.status = 'discarded'
         AND NEW.claimed_agent_id IS NULL AND NEW.claimed_at IS NULL
         AND NEW.discarded_at IS NOT NULL AND NEW.discard_reason IS NOT NULL)
     )
BEGIN
    SELECT RAISE(ABORT, 'invalid Session follow-up transition');
END;

CREATE TRIGGER session_followups_reject_delete
BEFORE DELETE ON session_followups
BEGIN
    SELECT RAISE(ABORT, 'Session follow-ups are durable');
END;

CREATE TABLE session_followup_receipts (
    account_id                  TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    actor_user_id               TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    actor_membership_revision   INTEGER NOT NULL CHECK (actor_membership_revision > 0),
    idempotency_key             TEXT NOT NULL CHECK (length(trim(idempotency_key)) BETWEEN 1 AND 256),
    request_fingerprint         TEXT NOT NULL CHECK (json_valid(request_fingerprint)),
    response_json               TEXT NOT NULL CHECK (json_valid(response_json)),
    session_id                  TEXT NOT NULL,
    turn_id                     TEXT NOT NULL,
    created_at                  TEXT NOT NULL,
    PRIMARY KEY (account_id, actor_user_id, idempotency_key),
    FOREIGN KEY (account_id, actor_user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (session_id, turn_id)
        REFERENCES session_followups(session_id, turn_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TRIGGER session_followup_receipts_require_authority
BEFORE INSERT ON session_followup_receipts
WHEN NOT EXISTS (
        SELECT 1
        FROM session_followups followup
        JOIN account_memberships membership
          ON membership.account_id = followup.account_id
         AND membership.user_id = followup.actor_user_id
        JOIN users user ON user.id = membership.user_id
        JOIN accounts account ON account.id = membership.account_id
        WHERE followup.account_id = NEW.account_id
          AND followup.actor_user_id = NEW.actor_user_id
          AND followup.actor_membership_revision = NEW.actor_membership_revision
          AND followup.session_id = NEW.session_id
          AND followup.turn_id = NEW.turn_id
          AND membership.status = 'active'
          AND membership.revision = NEW.actor_membership_revision
          AND user.status = 'active'
          AND account.status = 'active'
     )
BEGIN
    SELECT RAISE(ABORT, 'Session follow-up receipt requires exact active authority');
END;

CREATE TRIGGER session_followup_receipts_reject_update
BEFORE UPDATE ON session_followup_receipts
BEGIN
    SELECT RAISE(ABORT, 'Session follow-up receipts are immutable');
END;

CREATE TRIGGER session_followup_receipts_reject_delete
BEFORE DELETE ON session_followup_receipts
BEGIN
    SELECT RAISE(ABORT, 'Session follow-up receipts are durable');
END;
