CREATE TABLE runtime_identity (
    singleton       INTEGER PRIMARY KEY CHECK (singleton = 1),
    profile         TEXT NOT NULL CHECK (
        profile IN ('production-guarded', 'local-development')
    ),
    environment     TEXT NOT NULL CHECK (length(trim(environment)) > 0),
    primary_run_id  TEXT NOT NULL CHECK (length(trim(primary_run_id)) > 0),
    policy_id       TEXT NOT NULL CHECK (length(trim(policy_id)) > 0),
    policy_revision TEXT NOT NULL CHECK (length(trim(policy_revision)) > 0),
    bound_at        TEXT NOT NULL
) STRICT;

CREATE TRIGGER runtime_identity_reject_update
BEFORE UPDATE ON runtime_identity
BEGIN
    SELECT RAISE(ABORT, 'runtime identity is immutable');
END;

CREATE TRIGGER runtime_identity_reject_delete
BEFORE DELETE ON runtime_identity
BEGIN
    SELECT RAISE(ABORT, 'runtime identity is immutable');
END;
