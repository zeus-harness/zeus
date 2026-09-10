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

  select r.id, r.status
    into candidate_id, previous_status
  from public.runs r
  where (
      (r.status = 'queued' and r.available_at <= now())
      or (r.status = 'running' and r.lease_expires_at < now())
    )
    and r.cancel_requested_at is null
  order by r.available_at, r.id
  limit 1
  for update skip locked;

  if not found then
    return;
  end if;

  if previous_status = 'running' then
    update public.run_attempts as a
    set status = 'released',
        heartbeat_at = now(),
        finished_at = coalesce(a.finished_at, now()),
        error_code = coalesce(a.error_code, 'lease_expired')
    where a.run_id = candidate_id and a.status = 'running';
  end if;

  update public.runs as r
  set status = 'running',
      lease_owner = node_id,
      lease_expires_at = now() + make_interval(secs => lease_seconds),
      fence_token = r.fence_token + 1,
      attempt_count = r.attempt_count + 1,
      started_at = coalesce(r.started_at, now()),
      updated_at = now()
  where r.id = candidate_id
  returning r.* into claimed;

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
