-- Runtime writes use this function at the start of the same transaction as
-- their mutation. The row lock keeps a lease from changing before commit.
create or replace function zeus_private.lock_runtime_run(
  target_run_id uuid,
  target_node_id text,
  expected_fence_token bigint
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  current_status text;
  current_node_id text;
  current_fence_token bigint;
begin
  if target_node_id is null or btrim(target_node_id) = ''
     or expected_fence_token is null or expected_fence_token <= 0 then
    raise exception 'invalid runtime fence arguments' using errcode = '22023';
  end if;

  select r.status, r.lease_owner, r.fence_token
    into current_status, current_node_id, current_fence_token
  from public.runs r
  where r.id = target_run_id
  for update;

  return found
    and current_status = 'running'
    and current_node_id = target_node_id
    and current_fence_token = expected_fence_token;
end
$$;

-- Closing a Run must never leave a model-visible tool call without a result.
create or replace function zeus_private.synthesize_canceled_tool_results(
  target_run_id uuid
)
returns integer
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  run_session_id uuid;
  tool_call record;
  session_event_id uuid;
  closed_count integer := 0;
begin
  select r.session_id
    into run_session_id
  from public.runs r
  where r.id = target_run_id
  for update;

  if not found then
    return 0;
  end if;

  for tool_call in
    select t.id, t.call_key
    from public.tool_calls t
    where t.run_id = target_run_id
      and t.status in ('pending_approval', 'ready', 'running')
    order by t.created_at, t.id
    for update
  loop
    select event_id
      into session_event_id
    from zeus_private.append_session_event(
      run_session_id,
      'tool_result',
      'system',
      null,
      jsonb_build_object(
        'call_id', tool_call.call_key,
        'result', jsonb_build_object('code', 'run_canceled'),
        'synthetic', true,
        'tool_call_id', tool_call.id
      ),
      target_run_id,
      1
    );

    update public.tool_calls
    set status = 'canceled',
        result = jsonb_build_object('code', 'run_canceled'),
        error_code = 'run_canceled',
        finished_at = coalesce(finished_at, now())
    where id = tool_call.id;

    update public.approvals
    set status = 'canceled',
        decided_at = coalesce(decided_at, now()),
        reason = coalesce(reason, 'run canceled')
    where tool_call_id = tool_call.id and status = 'pending';

    perform zeus_private.append_run_event(
      target_run_id,
      'tool.result',
      jsonb_build_object(
        'tool_call_id', tool_call.id,
        'call_id', tool_call.call_key,
        'status', 'canceled',
        'synthetic', true
      ),
      session_event_id,
      1
    );
    closed_count := closed_count + 1;
  end loop;

  return closed_count;
end
$$;

create or replace function zeus_private.close_tools_when_run_is_canceled()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  if new.status = 'canceled' and old.status <> 'canceled' then
    perform zeus_private.synthesize_canceled_tool_results(new.id);
  end if;
  return new;
end
$$;

create trigger runs_close_canceled_tools
after update of status on runs
for each row execute function zeus_private.close_tools_when_run_is_canceled();

-- Record lease recovery explicitly and close the expired attempt before a new
-- fencing token is issued.
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
    update public.run_attempts
    set status = 'released',
        heartbeat_at = now(),
        finished_at = coalesce(finished_at, now()),
        error_code = coalesce(error_code, 'lease_expired')
    where run_id = candidate_id and status = 'running';
  end if;

  update public.runs r
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

revoke all on function zeus_private.lock_runtime_run(uuid, text, bigint) from public;
revoke all on function zeus_private.synthesize_canceled_tool_results(uuid) from public;
revoke all on function zeus_private.close_tools_when_run_is_canceled() from public;

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'zeus_runtime') then
    execute 'grant execute on function zeus_private.lock_runtime_run(uuid, text, bigint) to zeus_runtime';
    execute 'grant execute on function zeus_private.synthesize_canceled_tool_results(uuid) to zeus_runtime';
  end if;
end
$$;
