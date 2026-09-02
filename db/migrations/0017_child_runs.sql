-- Phase G: durable Child Runs with explicit budgets and parent wake-up semantics.

alter table runs
  add column root_run_id uuid references runs(id),
  add column depth smallint not null default 0 check (depth between 0 and 8),
  add column token_budget_override bigint check (token_budget_override > 0),
  add column max_runtime_seconds_override integer
    check (max_runtime_seconds_override between 1 and 86400);

create index runs_root_run_id_idx on runs (root_run_id);
create index runs_parent_depth_idx on runs (parent_run_id, depth, created_at, id)
  where parent_run_id is not null;

alter table tool_calls
  add column child_run_id uuid references runs(id);
create index tool_calls_child_run_id_idx on tool_calls (child_run_id);
create unique index tool_calls_child_run_unique on tool_calls (child_run_id)
  where child_run_id is not null;

alter table tool_calls drop constraint tool_calls_status_check;
alter table tool_calls
  add constraint tool_calls_status_check
    check (status in (
      'pending_approval', 'ready', 'running', 'waiting_child',
      'succeeded', 'failed', 'denied', 'canceled'
    )),
  add constraint tool_calls_child_state_check
    check (
      (status = 'waiting_child' and child_run_id is not null)
      or status <> 'waiting_child'
    );

create or replace function zeus_private.wake_parent_after_child_terminal()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  parent_id uuid;
begin
  if new.status not in ('succeeded', 'failed', 'canceled')
     or old.status in ('succeeded', 'failed', 'canceled') then
    return new;
  end if;

  for parent_id in
    select l.parent_run_id
    from public.run_links l
    where l.child_run_id = new.id and l.relation = 'child'
    order by l.parent_run_id
  loop
    update public.runs parent
    set status = 'queued',
        available_at = now(),
        lease_owner = null,
        lease_expires_at = null,
        updated_at = now()
    where parent.id = parent_id
      and parent.status = 'waiting_child'
      and parent.cancel_requested_at is null
      and not exists (
        select 1
        from public.tool_calls tool
        join public.runs child on child.id = tool.child_run_id
        where tool.run_id = parent.id
          and tool.status = 'waiting_child'
          and child.status not in ('succeeded', 'failed', 'canceled')
      );

    if found then
      perform zeus_private.append_run_event(
        parent_id,
        'child.terminal',
        jsonb_build_object(
          'child_run_id', new.id,
          'child_status', new.status,
          'parent_status', 'queued'
        )
      );
    end if;
  end loop;
  return new;
end
$$;

create trigger runs_wake_parent_after_child_terminal
after update of status on runs
for each row execute function zeus_private.wake_parent_after_child_terminal();

create or replace function zeus_private.cascade_run_cancel_to_children()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  child_id uuid;
begin
  if not (
    (new.cancel_requested_at is not null and old.cancel_requested_at is null)
    or (new.status = 'canceled' and old.status <> 'canceled')
  ) then
    return new;
  end if;

  for child_id in
    select l.child_run_id
    from public.run_links l
    join public.runs child on child.id = l.child_run_id
    where l.parent_run_id = new.id
      and l.relation = 'child'
      and child.status not in ('succeeded', 'failed', 'canceled')
    order by l.child_run_id
  loop
    perform zeus_private.request_run_cancel(
      child_id,
      'system',
      null,
      'parent run canceled'
    );
  end loop;
  return new;
end
$$;

create trigger runs_cascade_cancel_to_children
after update of status, cancel_requested_at on runs
for each row execute function zeus_private.cascade_run_cancel_to_children();

-- A very fast child can finish while its parent still owns the lease. In that
-- case the parent is released directly to queued instead of sleeping forever.
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
  select r.session_id into run_session_id
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
      and t.status in ('pending_approval', 'ready', 'running', 'waiting_child')
    order by t.created_at, t.id
    for update
  loop
    select event_id into session_event_id
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

grant select, insert, update on table public.sessions,
  public.run_links to zeus_runtime;
revoke delete on table public.sessions, public.run_links from zeus_runtime;

revoke all on function zeus_private.wake_parent_after_child_terminal() from public;
revoke all on function zeus_private.cascade_run_cancel_to_children() from public;
