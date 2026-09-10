create table experience_candidates (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  source_run_id uuid not null references runs(id),
  proposed_scope text not null check (proposed_scope in ('workspace', 'organization')),
  title text not null,
  content text not null,
  tags text[] not null default '{}',
  evidence jsonb not null default '[]'::jsonb check (jsonb_typeof(evidence) = 'array'),
  status text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
  reviewed_by uuid references users(id),
  reviewed_at timestamptz,
  review_reason text,
  created_at timestamptz not null default now()
);
create index experience_candidates_organization_id_idx on experience_candidates (organization_id);
create index experience_candidates_workspace_id_idx on experience_candidates (workspace_id);
create index experience_candidates_source_run_id_idx on experience_candidates (source_run_id);
create index experience_candidates_pending_idx on experience_candidates (workspace_id, created_at, id)
  where status = 'pending';

create table experience_entries (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid references workspaces(id),
  candidate_id uuid not null references experience_candidates(id),
  scope text not null check (scope in ('workspace', 'organization')),
  version_number integer not null default 1 check (version_number > 0),
  title text not null,
  content text not null,
  tags text[] not null default '{}',
  status text not null default 'published' check (status in ('published', 'withdrawn')),
  published_by uuid not null references users(id),
  published_at timestamptz not null default now(),
  withdrawn_at timestamptz,
  search_vector tsvector generated always as (
    setweight(to_tsvector('simple', coalesce(title, '')), 'A') ||
    setweight(to_tsvector('simple', coalesce(content, '')), 'B')
  ) stored,
  unique (candidate_id, version_number),
  check (
    (scope = 'workspace' and workspace_id is not null)
    or (scope = 'organization' and workspace_id is null)
  )
);
create index experience_entries_organization_id_idx on experience_entries (organization_id);
create index experience_entries_workspace_id_idx on experience_entries (workspace_id);
create index experience_entries_candidate_id_idx on experience_entries (candidate_id);
create index experience_entries_search_idx on experience_entries using gin (search_vector);
create index experience_entries_list_idx on experience_entries (organization_id, workspace_id, published_at desc, id desc)
  where status = 'published';

create trigger experience_entries_immutable
before update or delete on experience_entries
for each row execute function zeus_private.reject_mutation();
