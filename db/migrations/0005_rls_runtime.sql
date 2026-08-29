alter table organizations enable row level security;
alter table organizations force row level security;
create policy organizations_tenant on organizations
  using (id = (select zeus_private.current_organization_id()))
  with check (id = (select zeus_private.current_organization_id()));

alter table users enable row level security;
alter table users force row level security;
create policy users_self on users
  using (id = (select zeus_private.current_user_id()))
  with check (id = (select zeus_private.current_user_id()));

alter table oidc_identities enable row level security;
alter table oidc_identities force row level security;
create policy oidc_identities_self on oidc_identities
  using (user_id = (select zeus_private.current_user_id()))
  with check (user_id = (select zeus_private.current_user_id()));

do $$
declare
  table_name text;
begin
  foreach table_name in array array[
    'workspaces', 'oidc_providers', 'oidc_group_mappings',
    'organization_memberships', 'capability_definitions'
  ]
  loop
    execute format('alter table %I enable row level security', table_name);
    execute format('alter table %I force row level security', table_name);
    execute format(
      'create policy organization_isolation on %I using (organization_id = (select zeus_private.current_organization_id())) with check (organization_id = (select zeus_private.current_organization_id()))',
      table_name
    );
  end loop;
end
$$;

do $$
declare
  table_name text;
begin
  foreach table_name in array array[
    'workspace_memberships', 'connections', 'connection_secrets', 'model_profiles',
    'workspace_capabilities', 'agents', 'agent_versions', 'workflows', 'workflow_versions',
    'schedules', 'webhook_endpoints', 'work_items', 'sessions', 'runs', 'session_events',
    'run_attempts', 'run_events', 'attachments', 'tool_calls', 'approvals', 'run_links',
    'outbox_events', 'experience_candidates'
  ]
  loop
    execute format('alter table %I enable row level security', table_name);
    execute format('alter table %I force row level security', table_name);
    execute format(
      'create policy workspace_isolation on %I using (organization_id = (select zeus_private.current_organization_id()) and workspace_id = (select zeus_private.current_workspace_id())) with check (organization_id = (select zeus_private.current_organization_id()) and workspace_id = (select zeus_private.current_workspace_id()))',
      table_name
    );
  end loop;
end
$$;

alter table web_sessions enable row level security;
alter table web_sessions force row level security;
create policy web_sessions_self on web_sessions
  using (
    user_id = (select zeus_private.current_user_id())
    and organization_id = (select zeus_private.current_organization_id())
  )
  with check (
    user_id = (select zeus_private.current_user_id())
    and organization_id = (select zeus_private.current_organization_id())
  );

alter table service_accounts enable row level security;
alter table service_accounts force row level security;
create policy service_accounts_tenant on service_accounts
  using (
    organization_id = (select zeus_private.current_organization_id())
    and (workspace_id is null or workspace_id = (select zeus_private.current_workspace_id()))
  )
  with check (
    organization_id = (select zeus_private.current_organization_id())
    and (workspace_id is null or workspace_id = (select zeus_private.current_workspace_id()))
  );

alter table audit_events enable row level security;
alter table audit_events force row level security;
create policy audit_events_tenant on audit_events
  using (
    organization_id = (select zeus_private.current_organization_id())
    and (workspace_id is null or workspace_id = (select zeus_private.current_workspace_id()))
  )
  with check (
    organization_id = (select zeus_private.current_organization_id())
    and (workspace_id is null or workspace_id = (select zeus_private.current_workspace_id()))
  );

alter table experience_entries enable row level security;
alter table experience_entries force row level security;
create policy experience_entries_scope on experience_entries
  using (
    organization_id = (select zeus_private.current_organization_id())
    and (workspace_id is null or workspace_id = (select zeus_private.current_workspace_id()))
  )
  with check (
    organization_id = (select zeus_private.current_organization_id())
    and (workspace_id is null or workspace_id = (select zeus_private.current_workspace_id()))
  );

create or replace function zeus_private.claim_run(
  node_id text,
  lease_seconds integer
)
returns table (
  run_id uuid,
  organization_id uuid,
  workspace_id uuid,
  session_id uuid,
  workflow_version_id uuid,
  fence_token bigint,
  attempt_number integer
)
language sql
security definer
set search_path = pg_catalog, public
as $$
  with candidate as (
    select r.id
    from public.runs r
    where (
      (r.status = 'queued' and r.available_at <= now())
      or (r.status = 'running' and r.lease_expires_at < now())
    )
    and r.cancel_requested_at is null
    order by r.available_at, r.id
    limit 1
    for update skip locked
  ), claimed as (
    update public.runs r
    set status = 'running',
        lease_owner = node_id,
        lease_expires_at = now() + make_interval(secs => lease_seconds),
        fence_token = r.fence_token + 1,
        attempt_count = r.attempt_count + 1,
        started_at = coalesce(r.started_at, now()),
        updated_at = now()
    from candidate c
    where r.id = c.id
    returning r.id, r.organization_id, r.workspace_id, r.session_id,
              r.workflow_version_id, r.fence_token, r.attempt_count
  ), attempt as (
    insert into public.run_attempts (
      organization_id, workspace_id, run_id, attempt_number, lease_owner, fence_token
    )
    select c.organization_id, c.workspace_id, c.id, c.attempt_count, node_id, c.fence_token
    from claimed c
    returning run_id
  )
  select c.id, c.organization_id, c.workspace_id, c.session_id,
         c.workflow_version_id, c.fence_token, c.attempt_count
  from claimed c
  join attempt a on a.run_id = c.id
$$;

create or replace function zeus_private.heartbeat_run(
  target_run_id uuid,
  node_id text,
  expected_fence_token bigint,
  lease_seconds integer
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  affected integer;
begin
  update public.runs
  set lease_expires_at = now() + make_interval(secs => lease_seconds),
      updated_at = now()
  where id = target_run_id
    and status = 'running'
    and lease_owner = node_id
    and fence_token = expected_fence_token;

  get diagnostics affected = row_count;
  if affected = 1 then
    update public.run_attempts
    set heartbeat_at = now()
    where run_id = target_run_id and fence_token = expected_fence_token;
    return true;
  end if;
  return false;
end
$$;

create or replace function zeus_private.finish_run(
  target_run_id uuid,
  node_id text,
  expected_fence_token bigint,
  target_status text,
  result jsonb,
  failure_code text,
  failure_detail text
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  affected integer;
begin
  if target_status not in ('queued', 'waiting_approval', 'waiting_child', 'succeeded', 'failed', 'canceled') then
    raise exception 'invalid terminal or release status' using errcode = '22023';
  end if;

  update public.runs
  set status = target_status,
      output = result,
      error_code = failure_code,
      error_detail = failure_detail,
      lease_owner = null,
      lease_expires_at = null,
      available_at = case when target_status = 'queued' then now() else available_at end,
      finished_at = case when target_status in ('succeeded', 'failed', 'canceled') then now() else null end,
      updated_at = now()
  where id = target_run_id
    and status = 'running'
    and lease_owner = node_id
    and fence_token = expected_fence_token;

  get diagnostics affected = row_count;
  if affected = 1 then
    update public.run_attempts
    set status = case
          when target_status = 'queued' then 'released'
          when target_status in ('waiting_approval', 'waiting_child') then 'released'
          else target_status
        end,
        heartbeat_at = now(),
        finished_at = now(),
        error_code = failure_code
    where run_id = target_run_id and fence_token = expected_fence_token;
    return true;
  end if;
  return false;
end
$$;

create or replace function zeus_private.notify_queued_run()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if new.status = 'queued' and (tg_op = 'INSERT' or old.status is distinct from new.status) then
    perform pg_notify('zeus_runs', new.id::text);
  end if;
  return new;
end
$$;

create trigger runs_notify_queued
after insert or update of status on runs
for each row execute function zeus_private.notify_queued_run();

revoke all on function zeus_private.claim_run(text, integer) from public;
revoke all on function zeus_private.heartbeat_run(uuid, text, bigint, integer) from public;
revoke all on function zeus_private.finish_run(uuid, text, bigint, text, jsonb, text, text) from public;
