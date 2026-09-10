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
      1::smallint
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
      1::smallint
    );
    closed_count := closed_count + 1;
  end loop;

  return closed_count;
end
$$;

revoke all on function zeus_private.synthesize_canceled_tool_results(uuid) from public;

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'zeus_runtime') then
    execute 'grant execute on function zeus_private.synthesize_canceled_tool_results(uuid) to zeus_runtime';
  end if;
end
$$;
