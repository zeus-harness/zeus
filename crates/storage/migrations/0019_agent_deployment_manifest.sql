-- Bind each newly admitted Agent turn to one immutable, canonical, secret-free
-- deployment manifest. Existing Agent rows are deliberately left unbound so
-- terminal history remains readable and queued legacy work can fail closed at
-- its first post-upgrade claim checkpoint.

CREATE TABLE agent_deployment_manifests (
    digest          TEXT PRIMARY KEY CHECK (
        length(digest) = 64
        AND digest NOT GLOB '*[^0-9a-f]*'
    ),
    schema_version  INTEGER NOT NULL CHECK (schema_version = 1),
    envelope_json   TEXT NOT NULL CHECK (
        json_valid(envelope_json)
        AND json_type(envelope_json) = 'object'
        AND length(CAST(envelope_json AS BLOB)) <= 262144
        AND COALESCE(json_type(envelope_json, '$.schema_version') = 'integer', 0)
        AND COALESCE(json_extract(envelope_json, '$.schema_version') = schema_version, 0)
        AND COALESCE(json_type(envelope_json, '$.digest') = 'text', 0)
        AND COALESCE(json_extract(envelope_json, '$.digest') = digest, 0)
    ),
    created_at      TEXT NOT NULL CHECK (length(trim(created_at)) > 0)
) STRICT;

CREATE TRIGGER agent_deployment_manifests_reject_update
BEFORE UPDATE ON agent_deployment_manifests
BEGIN
    SELECT RAISE(ABORT, 'agent deployment manifest is immutable');
END;

CREATE TRIGGER agent_deployment_manifests_reject_delete
BEFORE DELETE ON agent_deployment_manifests
BEGIN
    SELECT RAISE(ABORT, 'agent deployment manifest cannot be deleted');
END;

ALTER TABLE agent_turns
    ADD COLUMN deployment_manifest_digest TEXT
        REFERENCES agent_deployment_manifests(digest) ON DELETE RESTRICT;

CREATE INDEX agent_turns_deployment_manifest_idx
    ON agent_turns(deployment_manifest_digest)
    WHERE deployment_manifest_digest IS NOT NULL;

-- The migration cannot make the new column NOT NULL without rewriting legacy
-- history. The trigger applies the non-null contract only to post-v19 inserts.
CREATE TRIGGER agent_turns_require_deployment_manifest
BEFORE INSERT ON agent_turns
WHEN NEW.deployment_manifest_digest IS NULL
BEGIN
    SELECT RAISE(ABORT, 'new agent turn requires a deployment manifest');
END;

-- Include the new binding in the existing immutable Agent identity boundary.
DROP TRIGGER agent_turns_reject_identity_update;

CREATE TRIGGER agent_turns_reject_identity_update
BEFORE UPDATE OF id, account_id, actor_user_id, actor_membership_revision,
                 session_id, turn_id, deployment_manifest_digest,
                 environment, provider_name, model_name, created_at
ON agent_turns
BEGIN
    SELECT RAISE(ABORT, 'agent turn identity is immutable');
END;
