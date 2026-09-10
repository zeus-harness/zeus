create table work_items (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  title text not null,
  description text not null default '',
  status text not null default 'open' check (status in ('open', 'in_progress', 'blocked', 'completed', 'canceled')),
  priority text not null default 'normal' check (priority in ('low', 'normal', 'high', 'urgent')),
  assignee_user_id uuid references users(id),
  source_kind text,
  external_reference text,
  input jsonb not null default '{}'::jsonb check (jsonb_typeof(input) = 'object'),
  output jsonb check (output is null or jsonb_typeof(output) = 'object'),
  idempotency_key text,
  revision bigint not null default 1 check (revision > 0),
  created_by uuid references users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  completed_at timestamptz
);
create index work_items_organization_id_idx on work_items (organization_id);
create index work_items_workspace_id_idx on work_items (workspace_id);
create index work_items_assignee_user_id_idx on work_items (assignee_user_id);
create index work_items_list_idx on work_items (organization_id, workspace_id, created_at desc, id desc);
create unique index work_items_idempotency_unique
  on work_items (workspace_id, idempotency_key) where idempotency_key is not null;

create table sessions (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  work_item_id uuid references work_items(id),
  title text not null default '',
  status text not null default 'active' check (status in ('active', 'closed', 'archived')),
  created_by uuid references users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  closed_at timestamptz
);
create index sessions_organization_id_idx on sessions (organization_id);
create index sessions_workspace_id_idx on sessions (workspace_id);
create index sessions_work_item_id_idx on sessions (work_item_id);
create index sessions_list_idx on sessions (organization_id, workspace_id, created_at desc, id desc);

create table runs (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  workflow_version_id uuid not null references workflow_versions(id),
  work_item_id uuid references work_items(id),
  session_id uuid not null references sessions(id),
  parent_run_id uuid references runs(id),
  retry_of_run_id uuid references runs(id),
  status text not null default 'queued' check (status in ('queued', 'running', 'waiting_approval', 'waiting_child', 'succeeded', 'failed', 'canceled')),
  input jsonb not null default '{}'::jsonb,
  output jsonb,
  error_code text,
  error_detail text,
  idempotency_key text not null,
  available_at timestamptz not null default now(),
  lease_owner text,
  lease_expires_at timestamptz,
  fence_token bigint not null default 0 check (fence_token >= 0),
  attempt_count integer not null default 0 check (attempt_count >= 0),
  cancel_requested_at timestamptz,
  started_at timestamptz,
  finished_at timestamptz,
  created_by uuid references users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (workspace_id, idempotency_key)
);
create index runs_organization_id_idx on runs (organization_id);
create index runs_workspace_id_idx on runs (workspace_id);
create index runs_workflow_version_id_idx on runs (workflow_version_id);
create index runs_work_item_id_idx on runs (work_item_id);
create index runs_session_id_idx on runs (session_id);
create index runs_parent_run_id_idx on runs (parent_run_id);
create index runs_retry_of_run_id_idx on runs (retry_of_run_id);
create index runs_list_idx on runs (organization_id, workspace_id, created_at desc, id desc);
create index runs_claim_idx on runs (available_at, id)
  where status = 'queued' and cancel_requested_at is null;
create index runs_expired_lease_idx on runs (lease_expires_at, id)
  where status = 'running';

create table session_events (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  session_id uuid not null references sessions(id),
  run_id uuid references runs(id),
  sequence bigint not null check (sequence > 0),
  schema_version smallint not null default 1 check (schema_version > 0),
  event_type text not null,
  actor_kind text not null check (actor_kind in ('user', 'service_account', 'agent', 'system')),
  actor_id uuid,
  payload jsonb not null,
  occurred_at timestamptz not null default now(),
  unique (session_id, sequence)
);
create index session_events_organization_id_idx on session_events (organization_id);
create index session_events_workspace_id_idx on session_events (workspace_id);
create index session_events_session_id_idx on session_events (session_id);
create index session_events_run_id_idx on session_events (run_id);
create index session_events_list_idx on session_events (session_id, sequence);
create trigger session_events_append_only
before update or delete on session_events
for each row execute function zeus_private.reject_mutation();

create table run_attempts (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  run_id uuid not null references runs(id),
  attempt_number integer not null check (attempt_number > 0),
  lease_owner text not null,
  fence_token bigint not null check (fence_token > 0),
  status text not null default 'running' check (status in ('running', 'released', 'succeeded', 'failed', 'canceled')),
  started_at timestamptz not null default now(),
  heartbeat_at timestamptz not null default now(),
  finished_at timestamptz,
  error_code text,
  unique (run_id, attempt_number),
  unique (run_id, fence_token)
);
create index run_attempts_organization_id_idx on run_attempts (organization_id);
create index run_attempts_workspace_id_idx on run_attempts (workspace_id);
create index run_attempts_run_id_idx on run_attempts (run_id);

create table run_events (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  run_id uuid not null references runs(id),
  session_event_id uuid references session_events(id),
  sequence bigint not null check (sequence > 0),
  schema_version smallint not null default 1 check (schema_version > 0),
  event_type text not null,
  payload jsonb not null,
  occurred_at timestamptz not null default now(),
  unique (run_id, sequence)
);
create index run_events_organization_id_idx on run_events (organization_id);
create index run_events_workspace_id_idx on run_events (workspace_id);
create index run_events_run_id_idx on run_events (run_id);
create index run_events_session_event_id_idx on run_events (session_event_id);
create index run_events_list_idx on run_events (run_id, sequence);
create trigger run_events_append_only
before update or delete on run_events
for each row execute function zeus_private.reject_mutation();

create table attachments (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  work_item_id uuid references work_items(id),
  session_id uuid references sessions(id),
  run_id uuid references runs(id),
  file_name text not null,
  content_type text not null,
  sha256 bytea not null,
  size_bytes integer not null check (size_bytes between 0 and 5242880),
  data bytea not null,
  created_by uuid references users(id),
  created_at timestamptz not null default now(),
  check (octet_length(data) = size_bytes),
  check (num_nonnulls(work_item_id, session_id, run_id) = 1)
);
create index attachments_organization_id_idx on attachments (organization_id);
create index attachments_workspace_id_idx on attachments (workspace_id);
create index attachments_work_item_id_idx on attachments (work_item_id);
create index attachments_session_id_idx on attachments (session_id);
create index attachments_run_id_idx on attachments (run_id);

create or replace function zeus_private.enforce_work_item_attachment_limit()
returns trigger
language plpgsql
set search_path = ''
as $$
declare
  aggregate_size bigint;
begin
  if new.work_item_id is null then
    return new;
  end if;

  select coalesce(sum(size_bytes), 0) into aggregate_size
  from public.attachments
  where work_item_id = new.work_item_id and id <> new.id;

  if aggregate_size + new.size_bytes > 26214400 then
    raise exception 'work item attachment limit exceeded' using errcode = '22023';
  end if;
  return new;
end
$$;

create trigger attachments_work_item_limit
before insert or update on attachments
for each row execute function zeus_private.enforce_work_item_attachment_limit();

create table tool_calls (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  run_id uuid not null references runs(id),
  session_id uuid not null references sessions(id),
  capability_id uuid not null references capability_definitions(id),
  call_key text not null,
  idempotency_key text,
  fence_token bigint not null,
  status text not null check (status in ('pending_approval', 'ready', 'running', 'succeeded', 'failed', 'denied', 'canceled')),
  input jsonb not null,
  result jsonb,
  error_code text,
  started_at timestamptz,
  finished_at timestamptz,
  created_at timestamptz not null default now(),
  unique (run_id, call_key)
);
create index tool_calls_organization_id_idx on tool_calls (organization_id);
create index tool_calls_workspace_id_idx on tool_calls (workspace_id);
create index tool_calls_run_id_idx on tool_calls (run_id);
create index tool_calls_session_id_idx on tool_calls (session_id);
create index tool_calls_capability_id_idx on tool_calls (capability_id);
create unique index tool_calls_idempotency_unique
  on tool_calls (workspace_id, idempotency_key) where idempotency_key is not null;

create table approvals (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  run_id uuid not null references runs(id),
  tool_call_id uuid not null references tool_calls(id),
  status text not null default 'pending' check (status in ('pending', 'approved', 'rejected', 'expired', 'canceled')),
  requested_at timestamptz not null default now(),
  expires_at timestamptz,
  decided_at timestamptz,
  decided_by uuid references users(id),
  reason text,
  unique (tool_call_id)
);
create index approvals_organization_id_idx on approvals (organization_id);
create index approvals_workspace_id_idx on approvals (workspace_id);
create index approvals_run_id_idx on approvals (run_id);
create index approvals_tool_call_id_idx on approvals (tool_call_id);
create index approvals_pending_idx on approvals (workspace_id, requested_at, id) where status = 'pending';

create table run_links (
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  parent_run_id uuid not null references runs(id),
  child_run_id uuid not null references runs(id),
  relation text not null default 'child' check (relation in ('child', 'retry')),
  created_at timestamptz not null default now(),
  primary key (parent_run_id, child_run_id),
  check (parent_run_id <> child_run_id)
);
create index run_links_organization_id_idx on run_links (organization_id);
create index run_links_workspace_id_idx on run_links (workspace_id);
create index run_links_child_run_id_idx on run_links (child_run_id);

create table outbox_events (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  aggregate_type text not null,
  aggregate_id uuid not null,
  event_type text not null,
  payload jsonb not null,
  idempotency_key text not null,
  available_at timestamptz not null default now(),
  attempt_count integer not null default 0 check (attempt_count >= 0),
  delivered_at timestamptz,
  last_error text,
  created_at timestamptz not null default now(),
  unique (workspace_id, idempotency_key)
);
create index outbox_events_organization_id_idx on outbox_events (organization_id);
create index outbox_events_workspace_id_idx on outbox_events (workspace_id);
create index outbox_events_pending_idx on outbox_events (available_at, id) where delivered_at is null;
