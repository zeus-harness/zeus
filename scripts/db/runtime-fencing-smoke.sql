\set ON_ERROR_STOP on

begin;

insert into organizations (id, slug, name)
values ('01978888-8888-7888-8888-888888888801', 'runtime-fence', 'Runtime Fence');

insert into workspaces (id, organization_id, slug, name)
values (
  '01978888-8888-7888-8888-888888888802',
  '01978888-8888-7888-8888-888888888801',
  'runtime-fence',
  'Runtime Fence'
);

insert into connections (id, organization_id, workspace_id, name, provider_kind)
values (
  '01978888-8888-7888-8888-888888888803',
  '01978888-8888-7888-8888-888888888801',
  '01978888-8888-7888-8888-888888888802',
  'runtime-model',
  'openai_compatible'
);

insert into model_profiles (
  id, organization_id, workspace_id, connection_id, name, base_url, model
)
values (
  '01978888-8888-7888-8888-888888888804',
  '01978888-8888-7888-8888-888888888801',
  '01978888-8888-7888-8888-888888888802',
  '01978888-8888-7888-8888-888888888803',
  'runtime-model',
  'https://model.invalid/v1',
  'runtime-test'
);

insert into agents (id, organization_id, workspace_id, name)
values (
  '01978888-8888-7888-8888-888888888805',
  '01978888-8888-7888-8888-888888888801',
  '01978888-8888-7888-8888-888888888802',
  'runtime-agent'
);

insert into agent_versions (
  id, organization_id, workspace_id, agent_id, version_number, instructions
)
values (
  '01978888-8888-7888-8888-888888888806',
  '01978888-8888-7888-8888-888888888801',
  '01978888-8888-7888-8888-888888888802',
  '01978888-8888-7888-8888-888888888805',
  1,
  'runtime smoke'
);

insert into workflows (id, organization_id, workspace_id, name)
values (
  '01978888-8888-7888-8888-888888888807',
  '01978888-8888-7888-8888-888888888801',
  '01978888-8888-7888-8888-888888888802',
  'runtime-workflow'
);

insert into workflow_versions (
  id, organization_id, workspace_id, workflow_id, version_number,
  agent_version_id, model_profile_id, input_schema, output_schema
)
values (
  '01978888-8888-7888-8888-888888888808',
  '01978888-8888-7888-8888-888888888801',
  '01978888-8888-7888-8888-888888888802',
  '01978888-8888-7888-8888-888888888807',
  1,
  '01978888-8888-7888-8888-888888888806',
  '01978888-8888-7888-8888-888888888804',
  '{}'::jsonb,
  '{}'::jsonb
);

insert into capability_definitions (
  id, organization_id, registry_key, display_name, description,
  input_schema, output_schema, idempotency_mode, risk_level, executor_key
)
values (
  '01978888-8888-7888-8888-888888888809',
  '01978888-8888-7888-8888-888888888801',
  'test.read',
  'Test read',
  'Runtime fence smoke capability',
  '{}'::jsonb,
  '{}'::jsonb,
  'supported',
  'high',
  'enterprise_http'
);

insert into sessions (id, organization_id, workspace_id, title)
values
  ('01978888-8888-7888-8888-888888888810', '01978888-8888-7888-8888-888888888801', '01978888-8888-7888-8888-888888888802', 'approval cancellation'),
  ('01978888-8888-7888-8888-888888888811', '01978888-8888-7888-8888-888888888801', '01978888-8888-7888-8888-888888888802', 'fence completion'),
  ('01978888-8888-7888-8888-888888888812', '01978888-8888-7888-8888-888888888801', '01978888-8888-7888-8888-888888888802', 'lease recovery');

insert into runs (
  id, organization_id, workspace_id, workflow_version_id, session_id,
  status, idempotency_key, lease_owner, lease_expires_at, fence_token, attempt_count
)
values
  (
    '01978888-8888-7888-8888-888888888813',
    '01978888-8888-7888-8888-888888888801',
    '01978888-8888-7888-8888-888888888802',
    '01978888-8888-7888-8888-888888888808',
    '01978888-8888-7888-8888-888888888810',
    'waiting_approval', 'waiting-cancel', null, null, 1, 1
  ),
  (
    '01978888-8888-7888-8888-888888888814',
    '01978888-8888-7888-8888-888888888801',
    '01978888-8888-7888-8888-888888888802',
    '01978888-8888-7888-8888-888888888808',
    '01978888-8888-7888-8888-888888888811',
    'running', 'fence-completion', 'node-a', now() + interval '5 minutes', 3, 1
  ),
  (
    '01978888-8888-7888-8888-888888888815',
    '01978888-8888-7888-8888-888888888801',
    '01978888-8888-7888-8888-888888888802',
    '01978888-8888-7888-8888-888888888808',
    '01978888-8888-7888-8888-888888888812',
    'running', 'lease-recovery', 'dead-node', now() - interval '1 minute', 5, 1
  );

insert into run_attempts (
  organization_id, workspace_id, run_id, attempt_number, lease_owner, fence_token
)
values
  ('01978888-8888-7888-8888-888888888801', '01978888-8888-7888-8888-888888888802', '01978888-8888-7888-8888-888888888814', 1, 'node-a', 3),
  ('01978888-8888-7888-8888-888888888801', '01978888-8888-7888-8888-888888888802', '01978888-8888-7888-8888-888888888815', 1, 'dead-node', 5);

insert into tool_calls (
  id, organization_id, workspace_id, run_id, session_id, capability_id,
  call_key, idempotency_key, fence_token, status, input
)
values (
  '01978888-8888-7888-8888-888888888816',
  '01978888-8888-7888-8888-888888888801',
  '01978888-8888-7888-8888-888888888802',
  '01978888-8888-7888-8888-888888888813',
  '01978888-8888-7888-8888-888888888810',
  '01978888-8888-7888-8888-888888888809',
  'call-smoke',
  'runtime-fence:call-smoke',
  1,
  'pending_approval',
  '{"record_id":7}'::jsonb
);

insert into approvals (
  id, organization_id, workspace_id, run_id, tool_call_id
)
values (
  '01978888-8888-7888-8888-888888888817',
  '01978888-8888-7888-8888-888888888801',
  '01978888-8888-7888-8888-888888888802',
  '01978888-8888-7888-8888-888888888813',
  '01978888-8888-7888-8888-888888888816'
);

select *
from zeus_private.append_session_event(
  '01978888-8888-7888-8888-888888888810',
  'tool_call',
  'agent',
  null,
  '{"call_id":"call-smoke","capability":"test.read","arguments":{"record_id":7}}'::jsonb,
  '01978888-8888-7888-8888-888888888813'
);

do $$
declare
  claimed record;
begin
  if not zeus_private.lock_runtime_run(
    '01978888-8888-7888-8888-888888888814', 'node-a', 3
  ) then
    raise exception 'current runtime fence was rejected';
  end if;
  if zeus_private.lock_runtime_run(
    '01978888-8888-7888-8888-888888888814', 'node-b', 3
  ) then
    raise exception 'wrong lease owner was accepted';
  end if;
  if zeus_private.finish_run(
    '01978888-8888-7888-8888-888888888814',
    'node-a',
    2,
    'succeeded',
    '{"wrong":true}'::jsonb,
    null,
    null
  ) then
    raise exception 'stale fence committed a terminal result';
  end if;
  if not zeus_private.finish_run(
    '01978888-8888-7888-8888-888888888814',
    'node-a',
    3,
    'succeeded',
    '{"ok":true}'::jsonb,
    null,
    null
  ) then
    raise exception 'current fence did not commit a terminal result';
  end if;

  if not zeus_private.request_run_cancel(
    '01978888-8888-7888-8888-888888888813', 'system', null, 'smoke'
  ) then
    raise exception 'waiting approval run was not canceled';
  end if;
  if not exists (
    select 1 from tool_calls
    where id = '01978888-8888-7888-8888-888888888816'
      and status = 'canceled'
      and result = '{"code":"run_canceled"}'::jsonb
  ) then
    raise exception 'canceled tool call has no synthetic result';
  end if;
  if not exists (
    select 1 from approvals
    where id = '01978888-8888-7888-8888-888888888817' and status = 'canceled'
  ) then
    raise exception 'pending approval was not canceled';
  end if;
  if (
    select count(*) from session_events
    where run_id = '01978888-8888-7888-8888-888888888813'
      and event_type = 'tool_result'
      and payload ->> 'call_id' = 'call-smoke'
      and (payload ->> 'synthetic')::boolean
  ) <> 1 then
    raise exception 'synthetic model-visible tool result was not appended exactly once';
  end if;

  select * into claimed from zeus_private.claim_run('recovery-node', 30);
  if not found
     or claimed.run_id <> '01978888-8888-7888-8888-888888888815'
     or claimed.fence_token <> 6
     or claimed.attempt_number <> 2 then
    raise exception 'expired lease was not recovered with a new fence';
  end if;
  if not exists (
    select 1 from run_attempts
    where run_id = '01978888-8888-7888-8888-888888888815'
      and attempt_number = 1
      and status = 'released'
      and error_code = 'lease_expired'
  ) then
    raise exception 'expired attempt was not released';
  end if;
end
$$;

rollback;

select 'Runtime fencing smoke passed' as result;
