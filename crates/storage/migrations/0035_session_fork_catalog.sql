-- Direct-child traversal is a core Session read path. Keep its keyset order
-- index-backed within one account and parent, including deterministic ties.
CREATE INDEX session_forks_children_idx
    ON session_forks(
        account_id,
        parent_session_id,
        created_at DESC,
        child_session_id ASC
    );
