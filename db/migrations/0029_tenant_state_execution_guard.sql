-- Complete the tenant navigation and execution state boundary.
--
-- A platform support session may select an active Workspace without receiving
-- Membership. Runtime claims also check the Organization state directly, so a
-- queued row cannot bypass suspension even if it was inserted out of band.

drop function zeus_private.validate_platform_tenant_access_grant(uuid, uuid, uuid);

create function zeus_private.validate_platform_tenant_access_grant(
  target_grant_id uuid,
  target_user_id uuid,
  target_session_id uuid
)
returns table (
  grant_id uuid,
  organization_id uuid,
  organization_status text,
  reason text,
  expires_at timestamptz,
  workspace_id uuid
)
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select access_grant.id,
         access_grant.organization_id,
         organization.status,
         access_grant.reason,
         access_grant.expires_at,
         workspace.id
  from public.platform_tenant_access_grants access_grant
  join public.organizations organization
    on organization.id = access_grant.organization_id
  join public.web_sessions session
    on session.id = target_session_id
   and session.user_id = target_user_id
  left join public.workspaces workspace
    on workspace.id = session.active_workspace_id
   and workspace.organization_id = access_grant.organization_id
   and workspace.status = 'active'
  where access_grant.id = target_grant_id
    and zeus_private.platform_tenant_access_is_valid(
      access_grant.id,
      target_user_id,
      target_session_id,
      access_grant.organization_id
    )
$$;

revoke all on function zeus_private.validate_platform_tenant_access_grant(
  uuid, uuid, uuid
) from public;
grant execute on function zeus_private.validate_platform_tenant_access_grant(
  uuid, uuid, uuid
) to zeus_http;

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
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  candidate_id uuid;
  previous_status text;
  claimed public.runs%rowtype;
begin
  if node_id is null or btrim(node_id) = ''
     or lease_seconds is null or lease_seconds not between 5 and 3600 then
    raise exception 'invalid run claim arguments' using errcode = '22023';
  end if;

  select run.id, run.status
    into candidate_id, previous_status
  from public.runs run
  join public.organizations organization
    on organization.id = run.organization_id
   and organization.status = 'active'
  where (
      (run.status = 'queued' and run.available_at <= now())
      or (run.status = 'running' and run.lease_expires_at < now())
    )
    and run.cancel_requested_at is null
  order by run.available_at, run.id
  limit 1
  for update of run skip locked;

  if not found then
    return;
  end if;

  if previous_status = 'running' then
    update public.run_attempts as attempt
    set status = 'released',
        heartbeat_at = now(),
        finished_at = coalesce(attempt.finished_at, now()),
        error_code = coalesce(attempt.error_code, 'lease_expired')
    where attempt.run_id = candidate_id and attempt.status = 'running';
  end if;

  update public.runs as run
  set status = 'running',
      lease_owner = node_id,
      lease_expires_at = now() + make_interval(secs => lease_seconds),
      fence_token = run.fence_token + 1,
      attempt_count = run.attempt_count + 1,
      started_at = coalesce(run.started_at, now()),
      updated_at = now()
  where run.id = candidate_id
  returning run.* into claimed;

  insert into public.run_attempts (
    organization_id,
    workspace_id,
    run_id,
    attempt_number,
    lease_owner,
    fence_token
  )
  values (
    claimed.organization_id,
    claimed.workspace_id,
    claimed.id,
    claimed.attempt_count,
    node_id,
    claimed.fence_token
  );

  perform zeus_private.append_run_event(
    claimed.id,
    'run.claimed',
    jsonb_build_object(
      'attempt_number', claimed.attempt_count,
      'fence_token', claimed.fence_token,
      'recovered', previous_status = 'running'
    )
  );

  return query
  select claimed.id,
         claimed.organization_id,
         claimed.workspace_id,
         claimed.session_id,
         claimed.workflow_version_id,
         claimed.fence_token,
         claimed.attempt_count;
end
$$;

revoke all on function zeus_private.claim_run(text, integer) from public;
grant execute on function zeus_private.claim_run(text, integer) to zeus_runtime;
