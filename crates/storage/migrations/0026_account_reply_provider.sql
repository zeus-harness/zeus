-- Persist only a secret-free selection from the providers registered by the
-- running Zeus service. Endpoints, credentials, and SecretRefs never cross
-- this boundary. Revision zero remains the implicit startup default.

CREATE TABLE account_reply_provider_configs (
    account_id                      TEXT PRIMARY KEY
        REFERENCES accounts(id) ON DELETE RESTRICT
        CHECK (length(account_id) BETWEEN 1 AND 128 AND account_id = trim(account_id)),
    revision                        INTEGER NOT NULL CHECK (revision > 0),
    provider_id                     TEXT NOT NULL CHECK (
        length(provider_id) BETWEEN 1 AND 128
        AND provider_id = trim(provider_id)
    ),
    model                           TEXT CHECK (
        model IS NULL OR (
            length(model) BETWEEN 1 AND 128
            AND model = trim(model)
        )
    ),
    reply_kind                      TEXT NOT NULL CHECK (
        (reply_kind = 'model' AND model IS NOT NULL)
        OR (reply_kind = 'non_model_fallback' AND model IS NULL)
    ),
    updated_by_user_id              TEXT NOT NULL
        REFERENCES users(id) ON DELETE RESTRICT
        CHECK (length(trim(updated_by_user_id)) > 0),
    updated_by_membership_revision  INTEGER NOT NULL CHECK (updated_by_membership_revision > 0),
    updated_at                      TEXT NOT NULL CHECK (length(trim(updated_at)) > 0),
    FOREIGN KEY (account_id, updated_by_user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE INDEX account_reply_provider_configs_provider_idx
    ON account_reply_provider_configs(provider_id, account_id);

CREATE TRIGGER account_reply_provider_configs_require_current_owner
BEFORE INSERT ON account_reply_provider_configs
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
    SELECT RAISE(ABORT, 'reply provider update requires current owner authority');
END;

CREATE TRIGGER account_reply_provider_configs_enforce_revision
BEFORE UPDATE ON account_reply_provider_configs
WHEN NEW.account_id IS NOT OLD.account_id
  OR NEW.revision <> OLD.revision + 1
  OR (
      NEW.provider_id IS OLD.provider_id
      AND NEW.model IS OLD.model
      AND NEW.reply_kind IS OLD.reply_kind
  )
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
    SELECT RAISE(ABORT, 'invalid reply provider revision transition');
END;

CREATE TRIGGER account_reply_provider_configs_reject_delete
BEFORE DELETE ON account_reply_provider_configs
BEGIN
    SELECT RAISE(ABORT, 'reply provider configuration cannot be deleted');
END;

CREATE TABLE account_reply_provider_receipts (
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
    provider_revision           INTEGER NOT NULL CHECK (provider_revision > 0),
    provider_id                 TEXT NOT NULL CHECK (
        length(provider_id) BETWEEN 1 AND 128
        AND provider_id = trim(provider_id)
    ),
    model                       TEXT CHECK (
        model IS NULL OR (
            length(model) BETWEEN 1 AND 128
            AND model = trim(model)
        )
    ),
    reply_kind                  TEXT NOT NULL CHECK (
        (reply_kind = 'model' AND model IS NOT NULL)
        OR (reply_kind = 'non_model_fallback' AND model IS NULL)
    ),
    created_at                  TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
    PRIMARY KEY (account_id, actor_user_id, idempotency_key),
    UNIQUE (account_id, provider_revision),
    FOREIGN KEY (account_id, actor_user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE INDEX account_reply_provider_receipts_provider_idx
    ON account_reply_provider_receipts(account_id, provider_id, provider_revision);

CREATE TRIGGER account_reply_provider_receipts_require_current_owner
BEFORE INSERT ON account_reply_provider_receipts
WHEN NOT EXISTS (
    SELECT 1
    FROM accounts account
    JOIN account_memberships membership
      ON membership.account_id = account.id
     AND membership.user_id = NEW.actor_user_id
    JOIN users user ON user.id = membership.user_id
    JOIN account_reply_provider_configs config
      ON config.account_id = account.id
     AND config.revision = NEW.provider_revision
     AND config.provider_id = NEW.provider_id
     AND config.model IS NEW.model
     AND config.reply_kind = NEW.reply_kind
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
    SELECT RAISE(ABORT, 'reply provider receipt requires the current owner revision');
END;

CREATE TRIGGER account_reply_provider_receipts_reject_update
BEFORE UPDATE ON account_reply_provider_receipts
BEGIN
    SELECT RAISE(ABORT, 'reply provider receipts are immutable');
END;

CREATE TRIGGER account_reply_provider_receipts_reject_delete
BEFORE DELETE ON account_reply_provider_receipts
BEGIN
    SELECT RAISE(ABORT, 'reply provider receipts cannot be deleted');
END;
