-- Human result reviews are separate from tool authorization and WorkItem completion.
create table work_item_reviews (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  work_item_id uuid not null references work_items(id),
  run_id uuid not null references runs(id),
  workflow_version_id uuid not null references workflow_versions(id),
  work_item_revision bigint not null check (work_item_revision > 0),
  decision text not null check (decision in ('accepted', 'needs_changes')),
  reason text not null check (length(btrim(reason)) between 1 and 4000),
  reviewed_by uuid not null references users(id),
  created_at timestamptz not null default now()
);
create index work_item_reviews_organization_idx on work_item_reviews (organization_id);
create index work_item_reviews_workspace_idx on work_item_reviews (workspace_id);
create index work_item_reviews_item_idx on work_item_reviews (work_item_id, created_at desc, id desc);
create index work_item_reviews_run_idx on work_item_reviews (run_id);
create index work_item_reviews_version_idx on work_item_reviews (workflow_version_id);
create index work_item_reviews_reviewer_idx on work_item_reviews (reviewed_by);
alter table work_item_reviews enable row level security;
alter table work_item_reviews force row level security;
create policy workspace_isolation on work_item_reviews
  using (organization_id = (select zeus_private.current_organization_id())
    and workspace_id = (select zeus_private.current_workspace_id()))
  with check (organization_id = (select zeus_private.current_organization_id())
    and workspace_id = (select zeus_private.current_workspace_id()));
create trigger work_item_reviews_append_only before update or delete on work_item_reviews
  for each row execute function zeus_private.reject_mutation();
grant select, insert on work_item_reviews to zeus_http;
revoke update, delete on work_item_reviews from zeus_http, zeus_runtime;
