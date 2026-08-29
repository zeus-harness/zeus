-- Phase F: reviewed Experience lifecycle and durable runtime injection facts.

alter table experience_candidates
  add constraint experience_candidates_title_length
    check (length(btrim(title)) between 1 and 500),
  add constraint experience_candidates_content_length
    check (length(btrim(content)) between 1 and 100000),
  add constraint experience_candidates_evidence_limit
    check (jsonb_array_length(evidence) between 1 and 100) not valid;

alter table experience_entries
  add column evidence jsonb not null default '[]'::jsonb
    check (jsonb_typeof(evidence) = 'array'),
  add constraint experience_entries_title_length
    check (length(btrim(title)) between 1 and 500),
  add constraint experience_entries_content_length
    check (length(btrim(content)) between 1 and 100000);

create index experience_entries_tags_idx on experience_entries using gin (tags);

create table experience_entry_withdrawals (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid references workspaces(id),
  experience_entry_id uuid not null references experience_entries(id),
  reason text not null,
  withdrawn_by uuid not null references users(id),
  withdrawn_at timestamptz not null default now(),
  unique (experience_entry_id),
  check (length(btrim(reason)) between 1 and 4000)
);
create index experience_entry_withdrawals_organization_id_idx
  on experience_entry_withdrawals (organization_id);
create index experience_entry_withdrawals_workspace_id_idx
  on experience_entry_withdrawals (workspace_id);
create index experience_entry_withdrawals_withdrawn_by_idx
  on experience_entry_withdrawals (withdrawn_by);

alter table experience_entry_withdrawals enable row level security;
alter table experience_entry_withdrawals force row level security;
create policy experience_entry_withdrawals_scope on experience_entry_withdrawals
  using (
    organization_id = (select zeus_private.current_organization_id())
    and (workspace_id is null or workspace_id = (select zeus_private.current_workspace_id()))
  )
  with check (
    organization_id = (select zeus_private.current_organization_id())
    and (workspace_id is null or workspace_id = (select zeus_private.current_workspace_id()))
  );
create trigger experience_entry_withdrawals_append_only
before update or delete on experience_entry_withdrawals
for each row execute function zeus_private.reject_mutation();

create table run_experience_injections (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  run_id uuid not null references runs(id),
  experience_entry_id uuid not null references experience_entries(id),
  experience_version integer not null check (experience_version > 0),
  rank real not null check (rank >= 0),
  query_sha256 bytea not null check (octet_length(query_sha256) = 32),
  injected_at timestamptz not null default now(),
  unique (run_id, experience_entry_id)
);
create index run_experience_injections_organization_id_idx
  on run_experience_injections (organization_id);
create index run_experience_injections_workspace_id_idx
  on run_experience_injections (workspace_id);
create index run_experience_injections_run_id_idx
  on run_experience_injections (run_id, injected_at, id);
create index run_experience_injections_experience_entry_id_idx
  on run_experience_injections (experience_entry_id);

alter table run_experience_injections enable row level security;
alter table run_experience_injections force row level security;
create policy workspace_isolation on run_experience_injections
  using (
    organization_id = (select zeus_private.current_organization_id())
    and workspace_id = (select zeus_private.current_workspace_id())
  )
  with check (
    organization_id = (select zeus_private.current_organization_id())
    and workspace_id = (select zeus_private.current_workspace_id())
  );
create trigger run_experience_injections_append_only
before update or delete on run_experience_injections
for each row execute function zeus_private.reject_mutation();

grant select, insert on table public.experience_entry_withdrawals to zeus_http;
grant select on table public.run_experience_injections to zeus_http;
revoke update, delete on table public.experience_entry_withdrawals,
  public.run_experience_injections from zeus_http;

grant select on table public.work_items,
  public.experience_entry_withdrawals,
  public.run_experience_injections to zeus_runtime;
grant insert on table public.run_experience_injections to zeus_runtime;
revoke update, delete on table public.experience_entry_withdrawals,
  public.run_experience_injections from zeus_runtime;
