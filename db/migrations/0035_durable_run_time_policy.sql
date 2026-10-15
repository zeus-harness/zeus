-- Existing immutable versions retain wall-clock semantics. New API versions
-- explicitly store an active-time policy; each Run snapshots that policy.
alter table workflow_versions add column time_policy jsonb not null default '{}';
alter table workflow_versions add constraint workflow_time_policy_check check (
  time_policy = '{}'::jsonb or (
    jsonb_typeof(time_policy) = 'object'
    and time_policy ?& array['runtime_clock', 'wait_timeout_seconds', 'business_timeout_seconds']
    and time_policy - array['runtime_clock', 'wait_timeout_seconds', 'business_timeout_seconds'] = '{}'
    and time_policy->>'runtime_clock' = 'active'
    and jsonb_typeof(time_policy->'wait_timeout_seconds') = 'number'
    and (time_policy->>'wait_timeout_seconds') ~ '^[0-9]+$'
    and (time_policy->>'wait_timeout_seconds')::numeric between 1 and 31536000
    and jsonb_typeof(time_policy->'business_timeout_seconds') = 'number'
    and (time_policy->>'business_timeout_seconds') ~ '^[0-9]+$'
    and (time_policy->>'business_timeout_seconds')::numeric between 1 and 31536000
  )
);
alter table runs
  add column time_policy jsonb not null default '{}',
  add column active_elapsed_ms bigint not null default 0 check (active_elapsed_ms >= 0),
  add column active_started_at timestamptz,
  add column deadline_at timestamptz,
  add column wait_expires_at timestamptz;
create index runs_deadline_idx on runs (deadline_at, id)
  where status not in ('succeeded', 'failed', 'canceled') and deadline_at is not null;
create index runs_wait_expiry_idx on runs (wait_expires_at, id)
  where status in ('waiting_approval', 'waiting_child');
create index approvals_expiry_idx on approvals (expires_at, run_id) where status = 'pending';

create function zeus_private.track_run_time()
returns trigger language plpgsql security definer set search_path = pg_catalog, public as $$
begin
  if tg_op = 'INSERT' then
    select version.time_policy into new.time_policy from public.workflow_versions version
      where version.id = new.workflow_version_id
        and version.organization_id = new.organization_id and version.workspace_id = new.workspace_id;
    if new.time_policy is null then
      raise exception 'workflow version is outside run scope' using errcode = '23514';
    end if;
    new.deadline_at := new.created_at + make_interval(secs => (new.time_policy->>'business_timeout_seconds')::integer);
    new.active_elapsed_ms := 0;
    new.active_started_at := case when new.status = 'running' then now() else null end;
    new.wait_expires_at := null;
    return new;
  end if;
  -- Policy and deadlines are snapshots, never refreshed by retry or resume.
  new.time_policy := old.time_policy;
  new.deadline_at := old.deadline_at;
  new.active_elapsed_ms := old.active_elapsed_ms;
  if old.status = 'running' and old.active_started_at is not null then
    new.active_elapsed_ms := old.active_elapsed_ms + greatest(0,
      floor(extract(epoch from (least(now(), coalesce(old.lease_expires_at, now())) - old.active_started_at)) * 1000)::bigint);
  end if;
  new.active_started_at := case when new.status = 'running' then now() else null end;
  if new.status in ('waiting_approval', 'waiting_child') then
    if new.status is distinct from old.status then
      new.wait_expires_at := least(new.deadline_at,
        now() + make_interval(secs => (new.time_policy->>'wait_timeout_seconds')::integer));
    else
      new.wait_expires_at := old.wait_expires_at;
    end if;
  else
    new.wait_expires_at := null;
  end if;
  return new;
end $$;
create trigger runs_track_time before insert or update on runs
for each row execute function zeus_private.track_run_time();
revoke all on function zeus_private.track_run_time() from public;

-- Reuse cancellation's state machine, child cascade and event closure. Waiting
-- runs need no executor slot. Running runs receive cancellation cooperatively.
create function zeus_private.expire_run_waits(batch_size integer default 100)
returns integer language plpgsql security definer set search_path = pg_catalog, public as $$
declare candidate record; expired_count integer := 0; expiry_reason text;
begin
  if batch_size is null or batch_size not between 1 and 1000 then
    raise exception 'invalid expiry batch size' using errcode = '22023';
  end if;
  for candidate in
    select r.id, r.deadline_at, r.wait_expires_at, r.status, r.lease_expires_at, r.cancel_requested_at from public.runs r
    where r.status not in ('succeeded', 'failed', 'canceled') and ((r.cancel_requested_at is null
      and (r.deadline_at <= now() or r.wait_expires_at <= now()
        or exists (select 1 from public.approvals a where a.run_id = r.id
          and a.status = 'pending' and a.expires_at <= now())))
      or (r.status = 'running' and r.cancel_requested_at is not null and r.lease_expires_at <= now()))
    order by r.id limit batch_size for update of r skip locked
  loop
    if candidate.cancel_requested_at is not null then
      update public.run_attempts set status = 'released', finished_at = now(), error_code = 'lease_expired'
        where run_id = candidate.id and status = 'running';
      update public.runs set status = 'queued', lease_owner = null, lease_expires_at = null,
        fence_token = fence_token + 1 where id = candidate.id;
      perform zeus_private.request_run_cancel(candidate.id, 'system', null, 'cancellation recovered after lease expiry');
      expired_count := expired_count + 1;
      continue;
    end if;
    expiry_reason := case when candidate.deadline_at <= now() then 'business_deadline_exceeded' else 'wait_timeout' end;
    update public.approvals set status = 'expired', decided_at = now(), reason = expiry_reason
      where run_id = candidate.id and status = 'pending';
    perform zeus_private.append_run_event(candidate.id, 'run.deadline_exceeded', jsonb_build_object('code', expiry_reason));
    -- A dead executor cannot acknowledge cancellation. Fence it out and release
    -- before canceling, otherwise cancel_requested_at would prevent recovery.
    if candidate.status = 'running' and candidate.lease_expires_at <= now() then
      update public.run_attempts set status = 'released', finished_at = now(), error_code = 'lease_expired'
        where run_id = candidate.id and status = 'running';
      update public.runs set status = 'queued', lease_owner = null, lease_expires_at = null,
        fence_token = fence_token + 1 where id = candidate.id;
    end if;
    perform zeus_private.request_run_cancel(candidate.id, 'system', null, expiry_reason);
    expired_count := expired_count + 1;
  end loop;
  return expired_count;
end $$;
revoke all on function zeus_private.expire_run_waits(integer) from public;
grant execute on function zeus_private.expire_run_waits(integer) to zeus_runtime;

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
  committed_status text := target_status;
  event_type text;
begin
  if target_status not in ('queued', 'waiting_approval', 'waiting_child', 'succeeded', 'failed', 'canceled') then
    raise exception 'invalid terminal or release status' using errcode = '22023';
  end if;

  -- Serialize decisions and finish on the Run first. Otherwise a fast approval
  -- can enqueue nothing while this executor subsequently falls asleep.
  perform 1 from public.runs r where r.id = target_run_id
    and r.status = 'running' and r.lease_owner = node_id
    and r.fence_token = expected_fence_token and r.lease_expires_at > now()
    for update;
  if not found then return false; end if;

  if target_status = 'waiting_approval' and not exists (
    select 1 from public.approvals a where a.run_id = target_run_id and a.status = 'pending'
  ) then committed_status := 'queued'; end if;

  if target_status = 'waiting_child'
     and exists (
       select 1
       from public.tool_calls tool
       join public.runs child on child.id = tool.child_run_id
       where tool.run_id = target_run_id
         and tool.status = 'waiting_child'
         and child.status in ('succeeded', 'failed', 'canceled')
     ) then
    committed_status := 'queued';
  end if;

  update public.runs r
  set status = committed_status,
      output = result,
      error_code = failure_code,
      error_detail = failure_detail,
      lease_owner = null,
      lease_expires_at = null,
      available_at = case when committed_status = 'queued' then now() else r.available_at end,
      finished_at = case when committed_status in ('succeeded', 'failed', 'canceled') then now() else null end,
      updated_at = now()
  where r.id = target_run_id
    and r.status = 'running'
    and r.lease_owner = node_id
    and r.fence_token = expected_fence_token
    and (committed_status = 'canceled' or r.cancel_requested_at is null);

  get diagnostics affected = row_count;
  if affected = 1 then
    update public.run_attempts
    set status = case
          when committed_status in ('queued', 'waiting_approval', 'waiting_child') then 'released'
          else committed_status
        end,
        heartbeat_at = now(),
        finished_at = now(),
        error_code = failure_code
    where run_id = target_run_id and fence_token = expected_fence_token;

    event_type := case when committed_status = 'canceled' then 'run.canceled' else 'run.status_changed' end;
    perform zeus_private.append_run_event(
      target_run_id,
      event_type,
      jsonb_build_object(
        'status', committed_status,
        'requested_status', target_status,
        'fence_token', expected_fence_token,
        'error_code', failure_code
      )
    );
    return true;
  end if;
  return false;
end
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
  if lease_seconds is null or lease_seconds not between 5 and 3600 then
    raise exception 'invalid lease duration' using errcode = '22023';
  end if;
  update public.runs
  set lease_expires_at = now() + make_interval(secs => lease_seconds),
      updated_at = now()
  where id = target_run_id
    and status = 'running'
    and lease_owner = node_id
    and fence_token = expected_fence_token
    and lease_expires_at > now();

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

