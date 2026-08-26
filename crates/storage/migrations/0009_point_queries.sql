-- Durable lookup projections are populated by Rust during migration after
-- decoding each existing payload with the same typed decoder used at runtime.
-- They deliberately do not derive authority from SQLite JSON-path semantics.
ALTER TABLE run_events ADD COLUMN data_kind TEXT;
ALTER TABLE run_events ADD COLUMN call_id TEXT;
ALTER TABLE run_events ADD COLUMN approval_id TEXT;
ALTER TABLE run_events ADD COLUMN approval_status TEXT;
ALTER TABLE run_events ADD COLUMN policy_revision TEXT;
