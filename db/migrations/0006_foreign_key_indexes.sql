create index agents_active_version_id_idx on agents (active_version_id);
create index agent_versions_created_by_idx on agent_versions (created_by);
create index workflows_active_version_id_idx on workflows (active_version_id);
create index workflow_versions_created_by_idx on workflow_versions (created_by);

create index work_items_created_by_idx on work_items (created_by);
create index sessions_created_by_idx on sessions (created_by);
create index runs_created_by_idx on runs (created_by);
create index attachments_created_by_idx on attachments (created_by);
create index approvals_decided_by_idx on approvals (decided_by);

create index experience_candidates_reviewed_by_idx on experience_candidates (reviewed_by);
create index experience_entries_published_by_idx on experience_entries (published_by);
