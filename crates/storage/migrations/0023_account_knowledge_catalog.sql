-- Expose one account-scoped active knowledge corpus without weakening the
-- immutable corpus and per-Agent snapshot boundaries introduced in v22.
-- Revision zero remains an implicit empty catalog and therefore needs no row.

CREATE TABLE account_knowledge_catalogs (
    account_id                      TEXT PRIMARY KEY
        REFERENCES accounts(id) ON DELETE RESTRICT
        CHECK (length(account_id) BETWEEN 1 AND 128 AND account_id = trim(account_id)),
    revision                        INTEGER NOT NULL CHECK (revision > 0),
    active_corpus_digest            TEXT NOT NULL CHECK (
        length(active_corpus_digest) = 64
        AND active_corpus_digest NOT GLOB '*[^0-9a-f]*'
    ),
    updated_by_user_id              TEXT NOT NULL
        REFERENCES users(id) ON DELETE RESTRICT
        CHECK (length(trim(updated_by_user_id)) > 0),
    updated_by_membership_revision  INTEGER NOT NULL
        CHECK (updated_by_membership_revision > 0),
    updated_at                      TEXT NOT NULL CHECK (length(trim(updated_at)) > 0),
    FOREIGN KEY (account_id, active_corpus_digest)
        REFERENCES knowledge_corpus_revisions(account_id, digest) ON DELETE RESTRICT,
    FOREIGN KEY (account_id, updated_by_user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE INDEX account_knowledge_catalogs_active_corpus_idx
    ON account_knowledge_catalogs(account_id, active_corpus_digest);

CREATE TRIGGER account_knowledge_catalogs_require_current_owner
BEFORE INSERT ON account_knowledge_catalogs
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
    SELECT RAISE(ABORT, 'knowledge catalog update requires current owner authority');
END;

CREATE TRIGGER account_knowledge_catalogs_enforce_revision
BEFORE UPDATE ON account_knowledge_catalogs
WHEN NEW.account_id IS NOT OLD.account_id
  OR NEW.revision <> OLD.revision + 1
  OR NEW.active_corpus_digest IS OLD.active_corpus_digest
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
    SELECT RAISE(ABORT, 'invalid knowledge catalog revision transition');
END;

CREATE TRIGGER account_knowledge_catalogs_reject_delete
BEFORE DELETE ON account_knowledge_catalogs
BEGIN
    SELECT RAISE(ABORT, 'knowledge catalog state cannot be deleted');
END;

CREATE TABLE knowledge_catalog_receipts (
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
    catalog_revision            INTEGER NOT NULL CHECK (catalog_revision > 0),
    corpus_digest               TEXT NOT NULL CHECK (
        length(corpus_digest) = 64
        AND corpus_digest NOT GLOB '*[^0-9a-f]*'
    ),
    created_at                  TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
    PRIMARY KEY (account_id, actor_user_id, idempotency_key),
    UNIQUE (account_id, catalog_revision),
    FOREIGN KEY (account_id, actor_user_id)
        REFERENCES account_memberships(account_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (account_id, corpus_digest)
        REFERENCES knowledge_corpus_revisions(account_id, digest) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE INDEX knowledge_catalog_receipts_corpus_idx
    ON knowledge_catalog_receipts(account_id, corpus_digest, catalog_revision);

CREATE TRIGGER knowledge_catalog_receipts_require_current_owner
BEFORE INSERT ON knowledge_catalog_receipts
WHEN NOT EXISTS (
    SELECT 1
    FROM accounts account
    JOIN account_memberships membership
      ON membership.account_id = account.id
     AND membership.user_id = NEW.actor_user_id
    JOIN users user ON user.id = membership.user_id
    JOIN account_knowledge_catalogs catalog
      ON catalog.account_id = account.id
     AND catalog.revision = NEW.catalog_revision
     AND catalog.active_corpus_digest = NEW.corpus_digest
     AND catalog.updated_by_user_id = NEW.actor_user_id
     AND catalog.updated_by_membership_revision = NEW.actor_membership_revision
     AND catalog.updated_at = NEW.created_at
    WHERE account.id = NEW.account_id
      AND account.status = 'active'
      AND membership.role = 'owner'
      AND membership.status = 'active'
      AND membership.revision = NEW.actor_membership_revision
      AND user.status = 'active'
)
BEGIN
    SELECT RAISE(ABORT, 'knowledge catalog receipt requires the current owner revision');
END;

CREATE TRIGGER knowledge_catalog_receipts_reject_update
BEFORE UPDATE ON knowledge_catalog_receipts
BEGIN
    SELECT RAISE(ABORT, 'knowledge catalog receipts are immutable');
END;

CREATE TRIGGER knowledge_catalog_receipts_reject_delete
BEFORE DELETE ON knowledge_catalog_receipts
BEGIN
    SELECT RAISE(ABORT, 'knowledge catalog receipts cannot be deleted');
END;
