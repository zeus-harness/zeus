-- Separate the live bootstrap credential lifecycle from its bounded detailed
-- audit window. Terminal rows may be compacted into the monotonic rollup, while
-- the one live credential is always retained in detail.

DROP INDEX bootstrap_tokens_one_live_idx;
DROP TRIGGER bootstrap_tokens_enforce_single_use;
DROP TRIGGER bootstrap_tokens_reject_delete;

ALTER TABLE bootstrap_tokens RENAME TO bootstrap_tokens_v11;

CREATE TABLE bootstrap_audit_rollup (
    singleton        INTEGER PRIMARY KEY CHECK (singleton = 1),
    through_sequence INTEGER NOT NULL CHECK (through_sequence >= 0),
    digest           TEXT NOT NULL CHECK (
        length(digest) = 64
        AND digest NOT GLOB '*[^0-9a-f]*'
    ),
    updated_at       TEXT NOT NULL
) STRICT;

INSERT INTO bootstrap_audit_rollup(
    singleton, through_sequence, digest, updated_at
) VALUES (
    1,
    0,
    '0000000000000000000000000000000000000000000000000000000000000000',
    '1970-01-01T00:00:00.000Z'
);

CREATE TABLE bootstrap_tokens (
    sequence        INTEGER PRIMARY KEY AUTOINCREMENT CHECK (sequence > 0),
    token_hash      TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64),
    created_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    terminal_at     TEXT,
    terminal_reason TEXT CHECK (
        terminal_reason IS NULL OR terminal_reason IN (
            'superseded', 'consumed', 'expired', 'legacy_unknown'
        )
    ),
    CHECK (
        (terminal_at IS NULL AND terminal_reason IS NULL)
        OR (terminal_at IS NOT NULL AND terminal_reason IS NOT NULL)
    )
) STRICT;

-- Existing terminal rows predate explicit terminal reasons. Preserve their
-- timestamp and label the reason unknown instead of guessing whether a row was
-- superseded or consumed. Place the sole live row last so the detailed window
-- remains one contiguous suffix.
INSERT INTO bootstrap_tokens(
    token_hash, created_at, expires_at, terminal_at, terminal_reason
)
SELECT
    token_hash,
    created_at,
    expires_at,
    used_at,
    CASE WHEN used_at IS NULL THEN NULL ELSE 'legacy_unknown' END
FROM bootstrap_tokens_v11
ORDER BY used_at IS NULL, rowid;

DROP TABLE bootstrap_tokens_v11;

CREATE UNIQUE INDEX bootstrap_tokens_one_live_idx
    ON bootstrap_tokens((1)) WHERE terminal_at IS NULL;

CREATE INDEX bootstrap_tokens_terminal_sequence_idx
    ON bootstrap_tokens(sequence) WHERE terminal_at IS NOT NULL;

-- AUTOINCREMENT prevents sequence reuse. This guard additionally rejects an
-- explicit insert that skips over the rollup plus detailed-history head.
CREATE TRIGGER bootstrap_tokens_require_next_sequence
AFTER INSERT ON bootstrap_tokens
WHEN NEW.terminal_at IS NOT NULL
  OR NEW.terminal_reason IS NOT NULL
  OR NEW.sequence <> 1 + MAX(
      (SELECT through_sequence FROM bootstrap_audit_rollup WHERE singleton = 1),
      COALESCE((
          SELECT MAX(sequence)
          FROM bootstrap_tokens
          WHERE token_hash <> NEW.token_hash
      ), 0)
  )
BEGIN
    SELECT RAISE(ABORT, 'new bootstrap token must be live and use the next sequence');
END;

CREATE TRIGGER bootstrap_tokens_enforce_terminal_transition
BEFORE UPDATE ON bootstrap_tokens
WHEN NOT (
    OLD.terminal_at IS NULL
    AND OLD.terminal_reason IS NULL
    AND NEW.terminal_at IS NOT NULL
    AND NEW.terminal_reason IN ('superseded', 'consumed', 'expired')
    AND NEW.sequence IS OLD.sequence
    AND NEW.token_hash IS OLD.token_hash
    AND NEW.created_at IS OLD.created_at
    AND NEW.expires_at IS OLD.expires_at
)
BEGIN
    SELECT RAISE(ABORT, 'bootstrap token can only transition once to terminal');
END;

-- The Rust transaction advances the rollup only after hashing a contiguous
-- terminal prefix, then deletes exactly that committed prefix. This trigger
-- enforces structural monotonicity; the canonical digest calculation remains
-- inside the trusted storage path rather than being reimplemented in SQLite.
CREATE TRIGGER bootstrap_tokens_reject_uncommitted_delete
BEFORE DELETE ON bootstrap_tokens
WHEN OLD.terminal_at IS NULL
  OR OLD.terminal_reason IS NULL
  OR OLD.sequence > (
      SELECT through_sequence FROM bootstrap_audit_rollup WHERE singleton = 1
  )
BEGIN
    SELECT RAISE(ABORT, 'bootstrap token must be terminal and included in the audit rollup before deletion');
END;

CREATE TRIGGER bootstrap_audit_rollup_enforce_update
BEFORE UPDATE ON bootstrap_audit_rollup
WHEN NOT (
    NEW.singleton IS OLD.singleton
    AND NEW.through_sequence > OLD.through_sequence
    AND NEW.through_sequence - OLD.through_sequence BETWEEN 1 AND 64
    AND NEW.digest <> OLD.digest
    AND NEW.updated_at >= OLD.updated_at
    AND (
        SELECT COUNT(*)
        FROM bootstrap_tokens token
        WHERE token.sequence > OLD.through_sequence
          AND token.sequence <= NEW.through_sequence
          AND token.terminal_at IS NOT NULL
          AND token.terminal_reason IS NOT NULL
    ) = NEW.through_sequence - OLD.through_sequence
)
BEGIN
    SELECT RAISE(ABORT, 'bootstrap audit rollup must advance over a contiguous terminal prefix');
END;

CREATE TRIGGER bootstrap_audit_rollup_reject_delete
BEFORE DELETE ON bootstrap_audit_rollup
BEGIN
    SELECT RAISE(ABORT, 'bootstrap audit rollup is durable');
END;
