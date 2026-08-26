CREATE TABLE users (
    id            TEXT PRIMARY KEY CHECK (length(trim(id)) > 0),
    username      TEXT NOT NULL COLLATE NOCASE UNIQUE
        CHECK (length(username) BETWEEN 3 AND 64 AND username = trim(username)),
    role          TEXT NOT NULL CHECK (role IN ('owner', 'member')),
    status        TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    password_hash TEXT NOT NULL CHECK (length(trim(password_hash)) > 0),
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
) STRICT;

-- Alpha+ is local-first and has exactly one owner. Member accounts remain a
-- forward-compatible role, but cannot be promoted into a second owner.
CREATE UNIQUE INDEX users_single_owner_idx ON users(role) WHERE role = 'owner';

CREATE TABLE auth_sessions (
    token_hash TEXT PRIMARY KEY CHECK (length(token_hash) = 64),
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_hash  TEXT NOT NULL CHECK (length(csrf_hash) = 64),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
) STRICT;

CREATE INDEX auth_sessions_user_idx ON auth_sessions(user_id, expires_at);

CREATE TABLE bootstrap_tokens (
    token_hash TEXT PRIMARY KEY CHECK (length(token_hash) = 64),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at    TEXT
) STRICT;

CREATE UNIQUE INDEX bootstrap_tokens_one_live_idx
    ON bootstrap_tokens((1)) WHERE used_at IS NULL;

CREATE TABLE user_preferences (
    user_id         TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    theme           TEXT NOT NULL CHECK (theme IN ('system', 'light', 'dark')),
    preferred_model TEXT,
    revision        INTEGER NOT NULL CHECK (revision > 0),
    updated_at      TEXT NOT NULL,
    CHECK (preferred_model IS NULL OR length(trim(preferred_model)) > 0)
) STRICT;

-- Legacy Alpha state is intentionally left unowned until the one-time owner
-- bootstrap transaction claims it. Business routes remain unavailable before
-- bootstrap, so NULL never grants anonymous access.
ALTER TABLE sessions ADD COLUMN owner_user_id TEXT REFERENCES users(id) ON DELETE RESTRICT;
ALTER TABLE runs ADD COLUMN owner_user_id TEXT REFERENCES users(id) ON DELETE RESTRICT;

CREATE INDEX sessions_owner_updated_idx
    ON sessions(owner_user_id, updated_at DESC, id);
CREATE INDEX runs_owner_started_idx
    ON runs(owner_user_id, started_at DESC, id);

CREATE TRIGGER users_reject_identity_update
BEFORE UPDATE OF id, created_at ON users
BEGIN
    SELECT RAISE(ABORT, 'user identity is immutable');
END;

CREATE TRIGGER users_reject_delete_with_history
BEFORE DELETE ON users
WHEN EXISTS (SELECT 1 FROM sessions WHERE owner_user_id = OLD.id)
  OR EXISTS (SELECT 1 FROM runs WHERE owner_user_id = OLD.id)
BEGIN
    SELECT RAISE(ABORT, 'users with durable history cannot be deleted');
END;

CREATE TRIGGER auth_sessions_reject_update
BEFORE UPDATE ON auth_sessions
BEGIN
    SELECT RAISE(ABORT, 'auth sessions are immutable; rotate or revoke instead');
END;

CREATE TRIGGER bootstrap_tokens_enforce_single_use
BEFORE UPDATE ON bootstrap_tokens
WHEN NOT (
    OLD.used_at IS NULL
    AND NEW.used_at IS NOT NULL
    AND NEW.token_hash = OLD.token_hash
    AND NEW.created_at = OLD.created_at
    AND NEW.expires_at = OLD.expires_at
)
BEGIN
    SELECT RAISE(ABORT, 'bootstrap token can only transition to used');
END;

CREATE TRIGGER bootstrap_tokens_reject_delete
BEFORE DELETE ON bootstrap_tokens
BEGIN
    SELECT RAISE(ABORT, 'bootstrap tokens are security audit records');
END;

CREATE TRIGGER user_preferences_enforce_revision
BEFORE UPDATE ON user_preferences
WHEN NEW.user_id <> OLD.user_id OR NEW.revision <> OLD.revision + 1
BEGIN
    SELECT RAISE(ABORT, 'preference updates require the next revision');
END;

CREATE TRIGGER sessions_owner_is_write_once
BEFORE UPDATE OF owner_user_id ON sessions
WHEN OLD.owner_user_id IS NOT NULL OR NEW.owner_user_id IS NULL
BEGIN
    SELECT RAISE(ABORT, 'session ownership is immutable once assigned');
END;

CREATE TRIGGER runs_owner_is_write_once
BEFORE UPDATE OF owner_user_id ON runs
WHEN OLD.owner_user_id IS NOT NULL OR NEW.owner_user_id IS NULL
BEGIN
    SELECT RAISE(ABORT, 'run ownership is immutable once assigned');
END;
