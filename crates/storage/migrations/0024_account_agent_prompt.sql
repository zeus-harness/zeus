-- Add one owner-governed account Agent prompt while preserving the exact
-- built-in prompt as implicit revision zero. Existing Agents keep their
-- immutable manifest/request binding and are never rewritten by this catalog.

CREATE TABLE agent_prompt_revisions (
    account_id      TEXT NOT NULL
        REFERENCES accounts(id) ON DELETE RESTRICT,
    digest          TEXT NOT NULL CHECK (
        length(digest) = 64
        AND digest NOT GLOB '*[^0-9a-f]*'
    ),
    content_bytes   INTEGER NOT NULL CHECK (content_bytes BETWEEN 1 AND 16384),
    content         TEXT NOT NULL CHECK (
        length(trim(content)) > 0
        AND length(CAST(content AS BLOB)) = content_bytes
    ),
    created_at      TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
    PRIMARY KEY (account_id, digest)
) STRICT, WITHOUT ROWID;

CREATE INDEX agent_prompt_revisions_account_created_idx
    ON agent_prompt_revisions(account_id, created_at, digest);

CREATE TRIGGER agent_prompt_revisions_reject_update
BEFORE UPDATE ON agent_prompt_revisions
BEGIN
    SELECT RAISE(ABORT, 'Agent prompt revisions are immutable');
END;

CREATE TRIGGER agent_prompt_revisions_reject_delete
BEFORE DELETE ON agent_prompt_revisions
BEGIN
    SELECT RAISE(ABORT, 'Agent prompt revisions cannot be deleted');
END;

CREATE TABLE account_agent_prompt_configs (
    account_id                      TEXT PRIMARY KEY
        REFERENCES accounts(id) ON DELETE RESTRICT
        CHECK (length(account_id) BETWEEN 1 AND 128 AND account_id = trim(account_id)),
    revision                        INTEGER NOT NULL CHECK (revision > 0),
    active_prompt_digest            TEXT NOT NULL CHECK (
        length(active_prompt_digest) = 64
        AND active_prompt_digest NOT GLOB '*[^0-9a-f]*'
    ),
    updated_by_user_id              TEXT NOT NULL
        REFERENCES users(id) ON DELETE RESTRICT
        CHECK (length(trim(updated_by_user_id)) > 0),
    updated_by_membership_revision  INTEGER NOT NULL
        CHECK (updated_by_membership_revision > 0),
    updated_at                      TEXT NOT NULL CHECK (length(trim(updated_at)) > 0),
    FOREIGN KEY (account_id, active_prompt_digest)
        REFERENCES agent_prompt_revisions(account_id, digest) ON DELETE RESTRICT,
    FOREIGN KEY (account_id, updated_by_user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE INDEX account_agent_prompt_configs_active_prompt_idx
    ON account_agent_prompt_configs(account_id, active_prompt_digest);

CREATE TRIGGER account_agent_prompt_configs_require_current_owner
BEFORE INSERT ON account_agent_prompt_configs
WHEN NOT EXISTS (
    SELECT 1
    FROM accounts account
    JOIN account_memberships membership
      ON membership.account_id = account.id
     AND membership.user_id = NEW.updated_by_user_id
    JOIN users user ON user.id = membership.user_id
    WHERE account.id = NEW.account_id
      AND account.status = 'active'
      AND membership.role = 'owner'
      AND membership.status = 'active'
      AND membership.revision = NEW.updated_by_membership_revision
      AND user.status = 'active'
)
BEGIN
    SELECT RAISE(ABORT, 'Agent prompt update requires current owner authority');
END;

CREATE TRIGGER account_agent_prompt_configs_enforce_revision
BEFORE UPDATE ON account_agent_prompt_configs
WHEN NEW.account_id IS NOT OLD.account_id
  OR NEW.revision <> OLD.revision + 1
  OR NEW.active_prompt_digest IS OLD.active_prompt_digest
  OR NOT EXISTS (
      SELECT 1
      FROM accounts account
      JOIN account_memberships membership
        ON membership.account_id = account.id
       AND membership.user_id = NEW.updated_by_user_id
      JOIN users user ON user.id = membership.user_id
      WHERE account.id = OLD.account_id
        AND account.status = 'active'
        AND membership.role = 'owner'
        AND membership.status = 'active'
        AND membership.revision = NEW.updated_by_membership_revision
        AND user.status = 'active'
  )
BEGIN
    SELECT RAISE(ABORT, 'invalid Agent prompt revision transition');
END;

CREATE TRIGGER account_agent_prompt_configs_reject_delete
BEFORE DELETE ON account_agent_prompt_configs
BEGIN
    SELECT RAISE(ABORT, 'Agent prompt configuration cannot be deleted');
END;

CREATE TABLE agent_prompt_config_receipts (
    account_id                  TEXT NOT NULL
        REFERENCES accounts(id) ON DELETE RESTRICT,
    actor_user_id               TEXT NOT NULL
        REFERENCES users(id) ON DELETE RESTRICT,
    actor_membership_revision   INTEGER NOT NULL CHECK (actor_membership_revision > 0),
    idempotency_key             TEXT NOT NULL
        CHECK (length(trim(idempotency_key)) BETWEEN 1 AND 128),
    request_fingerprint         TEXT NOT NULL CHECK (
        json_valid(request_fingerprint)
        AND json_type(request_fingerprint) = 'object'
        AND length(CAST(request_fingerprint AS BLOB)) BETWEEN 1 AND 512
    ),
    prompt_revision             INTEGER NOT NULL CHECK (prompt_revision > 0),
    prompt_digest               TEXT NOT NULL CHECK (
        length(prompt_digest) = 64
        AND prompt_digest NOT GLOB '*[^0-9a-f]*'
    ),
    created_at                  TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
    PRIMARY KEY (account_id, actor_user_id, idempotency_key),
    UNIQUE (account_id, prompt_revision),
    FOREIGN KEY (account_id, actor_user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (account_id, prompt_digest)
        REFERENCES agent_prompt_revisions(account_id, digest) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE INDEX agent_prompt_config_receipts_digest_idx
    ON agent_prompt_config_receipts(account_id, prompt_digest, prompt_revision);

CREATE TRIGGER agent_prompt_config_receipts_require_current_owner
BEFORE INSERT ON agent_prompt_config_receipts
WHEN NOT EXISTS (
    SELECT 1
    FROM accounts account
    JOIN account_memberships membership
      ON membership.account_id = account.id
     AND membership.user_id = NEW.actor_user_id
    JOIN users user ON user.id = membership.user_id
    JOIN account_agent_prompt_configs config
      ON config.account_id = account.id
     AND config.revision = NEW.prompt_revision
     AND config.active_prompt_digest = NEW.prompt_digest
     AND config.updated_by_user_id = NEW.actor_user_id
     AND config.updated_by_membership_revision = NEW.actor_membership_revision
     AND config.updated_at = NEW.created_at
    WHERE account.id = NEW.account_id
      AND account.status = 'active'
      AND membership.role = 'owner'
      AND membership.status = 'active'
      AND membership.revision = NEW.actor_membership_revision
      AND user.status = 'active'
)
BEGIN
    SELECT RAISE(ABORT, 'Agent prompt receipt requires the current owner revision');
END;

CREATE TRIGGER agent_prompt_config_receipts_reject_update
BEFORE UPDATE ON agent_prompt_config_receipts
BEGIN
    SELECT RAISE(ABORT, 'Agent prompt receipts are immutable');
END;

CREATE TRIGGER agent_prompt_config_receipts_reject_delete
BEFORE DELETE ON agent_prompt_config_receipts
BEGIN
    SELECT RAISE(ABORT, 'Agent prompt receipts cannot be deleted');
END;
