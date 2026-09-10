\set ON_ERROR_STOP on

begin;

insert into organizations (id, slug, name)
values ('01933333-3333-7333-8333-333333333333', 'queue-tenant', 'Queue Tenant');

insert into workspaces (id, organization_id, slug, name)
values (
  '01933333-3333-7333-8333-333333333334',
  '01933333-3333-7333-8333-333333333333',
  'queue-workspace',
  'Queue Workspace'
);

insert into connections (id, organization_id, workspace_id, name, provider_kind)
values (
  '01933333-3333-7333-8333-333333333335',
  '01933333-3333-7333-8333-333333333333',
  '01933333-3333-7333-8333-333333333334',
  'test-model',
  'openai_compatible'
);

insert into model_profiles (
  id, organization_id, workspace_id, connection_id, name, base_url, model
)
values (
  '01933333-3333-7333-8333-333333333336',
  '01933333-3333-7333-8333-333333333333',
  '01933333-3333-7333-8333-333333333334',
  '01933333-3333-7333-8333-333333333335',
  'test-model',
  'https://model.invalid',
  'test'
);

insert into agents (id, organization_id, workspace_id, name)
values (
  '01933333-3333-7333-8333-333333333337',
  '01933333-3333-7333-8333-333333333333',
  '01933333-3333-7333-8333-333333333334',
  'test-agent'
);

insert into agent_versions (
  id, organization_id, workspace_id, agent_id, version_number, instructions
)
values (
  '01933333-3333-7333-8333-333333333338',
  '01933333-3333-7333-8333-333333333333',
  '01933333-3333-7333-8333-333333333334',
  '01933333-3333-7333-8333-333333333337',
  1,
  'test'
);

insert into workflows (id, organization_id, workspace_id, name)
values (
  '01933333-3333-7333-8333-333333333339',
  '01933333-3333-7333-8333-333333333333',
  '01933333-3333-7333-8333-333333333334',
  'test-workflow'
);

insert into workflow_versions (
  id, organization_id, workspace_id, workflow_id, version_number,
  agent_version_id, model_profile_id, input_schema, output_schema
)
values (
  '01933333-3333-7333-8333-333333333340',
  '01933333-3333-7333-8333-333333333333',
  '01933333-3333-7333-8333-333333333334',
  '01933333-3333-7333-8333-333333333339',
  1,
  '01933333-3333-7333-8333-333333333338',
  '01933333-3333-7333-8333-333333333336',
  '{}'::jsonb,
  '{}'::jsonb
);

insert into sessions (id, organization_id, workspace_id, title)
values (
  '01933333-3333-7333-8333-333333333341',
  '01933333-3333-7333-8333-333333333333',
  '01933333-3333-7333-8333-333333333334',
  'queue smoke'
);

insert into runs (
  id, organization_id, workspace_id, workflow_version_id, session_id, idempotency_key
)
values (
  '01933333-3333-7333-8333-333333333342',
  '01933333-3333-7333-8333-333333333333',
  '01933333-3333-7333-8333-333333333334',
  '01933333-3333-7333-8333-333333333340',
  '01933333-3333-7333-8333-333333333341',
  'queue-smoke'
);

set local role zeus_runtime;

do $$
declare
  claimed record;
begin
  select * into strict claimed from zeus_private.claim_run('queue-smoke-node', 60);
  if claimed.run_id <> '01933333-3333-7333-8333-333333333342'::uuid then
    raise exception 'unexpected run claimed';
  end if;
  if claimed.fence_token <> 1 or claimed.attempt_number <> 1 then
    raise exception 'claim did not advance fence and attempt';
  end if;
  if zeus_private.finish_run(
    claimed.run_id, 'queue-smoke-node', 0, 'succeeded', '{}'::jsonb, null, null
  ) then
    raise exception 'stale fence was accepted';
  end if;
  if not zeus_private.heartbeat_run(claimed.run_id, 'queue-smoke-node', 1, 60) then
    raise exception 'valid heartbeat was rejected';
  end if;
  if not zeus_private.finish_run(
    claimed.run_id, 'queue-smoke-node', 1, 'succeeded', '{"ok":true}'::jsonb, null, null
  ) then
    raise exception 'valid finish was rejected';
  end if;
  if (select status from runs where id = claimed.run_id) <> 'succeeded' then
    raise exception 'run did not reach succeeded';
  end if;
end
$$;

reset role;
rollback;
