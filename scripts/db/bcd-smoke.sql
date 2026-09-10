\set ON_ERROR_STOP on

begin;

insert into organizations (id, slug, name)
values ('01977777-7777-7777-8777-777777777771', 'bcd-tenant', 'BCD Tenant');

insert into workspaces (id, organization_id, slug, name)
values (
  '01977777-7777-7777-8777-777777777772',
  '01977777-7777-7777-8777-777777777771',
  'bcd-workspace',
  'BCD Workspace'
);

insert into oidc_providers (
  id, organization_id, issuer_url, client_id,
  encrypted_client_secret, secret_nonce, key_id
)
values (
  '01977777-7777-7777-8777-777777777773',
  '01977777-7777-7777-8777-777777777771',
  'https://issuer.invalid',
  'bcd-client',
  decode(repeat('ab', 32), 'hex'),
  decode(repeat('cd', 12), 'hex'),
  'bcd-key'
);

insert into connections (
  id, organization_id, workspace_id, name, provider_kind
)
values (
  '01977777-7777-7777-8777-777777777774',
  '01977777-7777-7777-8777-777777777771',
  '01977777-7777-7777-8777-777777777772',
  'bcd-connection',
  'openai_compatible'
);

insert into model_profiles (
  id, organization_id, workspace_id, connection_id, name, base_url, model
)
values (
  '01977777-7777-7777-8777-777777777775',
  '01977777-7777-7777-8777-777777777771',
  '01977777-7777-7777-8777-777777777772',
  '01977777-7777-7777-8777-777777777774',
  'bcd-model',
  'https://model.invalid',
  'bcd-test'
);

insert into agents (id, organization_id, workspace_id, name)
values (
  '01977777-7777-7777-8777-777777777776',
  '01977777-7777-7777-8777-777777777771',
  '01977777-7777-7777-8777-777777777772',
  'bcd-agent'
);

insert into agent_versions (
  id, organization_id, workspace_id, agent_id, version_number, instructions
)
values (
  '01977777-7777-7777-8777-777777777777',
  '01977777-7777-7777-8777-777777777771',
  '01977777-7777-7777-8777-777777777772',
  '01977777-7777-7777-8777-777777777776',
  1,
  'bcd smoke'
);

insert into workflows (id, organization_id, workspace_id, name)
values (
  '01977777-7777-7777-8777-777777777778',
  '01977777-7777-7777-8777-777777777771',
  '01977777-7777-7777-8777-777777777772',
  'bcd-workflow'
);

insert into workflow_versions (
  id, organization_id, workspace_id, workflow_id, version_number,
  agent_version_id, model_profile_id, input_schema, output_schema
)
values (
  '01977777-7777-7777-8777-777777777779',
  '01977777-7777-7777-8777-777777777771',
  '01977777-7777-7777-8777-777777777772',
  '01977777-7777-7777-8777-777777777778',
  1,
  '01977777-7777-7777-8777-777777777777',
  '01977777-7777-7777-8777-777777777775',
  '{}'::jsonb,
  '{}'::jsonb
);

insert into sessions (id, organization_id, workspace_id, title)
values
  ('01977777-7777-7777-8777-777777777780', '01977777-7777-7777-8777-777777777771', '01977777-7777-7777-8777-777777777772', 'BCD event session'),
  ('01977777-7777-7777-8777-777777777781', '01977777-7777-7777-8777-777777777771', '01977777-7777-7777-8777-777777777772', 'BCD usage session'),
  ('01977777-7777-7777-8777-777777777782', '01977777-7777-7777-8777-777777777771', '01977777-7777-7777-8777-777777777772', 'BCD cancel session');

insert into runs (
  id, organization_id, workspace_id, workflow_version_id, session_id,
  status, idempotency_key, lease_owner, lease_expires_at, fence_token, attempt_count
)
values
  (
    '01977777-7777-7777-8777-777777777783',
    '01977777-7777-7777-8777-777777777771',
    '01977777-7777-7777-8777-777777777772',
    '01977777-7777-7777-8777-777777777779',
    '01977777-7777-7777-8777-777777777780',
    'queued', 'bcd-event-run', null, null, 0, 0
  ),
  (
    '01977777-7777-7777-8777-777777777784',
    '01977777-7777-7777-8777-777777777771',
    '01977777-7777-7777-8777-777777777772',
    '01977777-7777-7777-8777-777777777779',
    '01977777-7777-7777-8777-777777777781',
    'running', 'bcd-usage-run', 'bcd-node', now() + interval '5 minutes', 7, 1
  ),
  (
    '01977777-7777-7777-8777-777777777785',
    '01977777-7777-7777-8777-777777777771',
    '01977777-7777-7777-8777-777777777772',
    '01977777-7777-7777-8777-777777777779',
    '01977777-7777-7777-8777-777777777782',
    'running', 'bcd-running-cancel', 'bcd-cancel-node', now() + interval '5 minutes', 8, 1
  ),
  (
    '01977777-7777-7777-8777-777777777786',
    '01977777-7777-7777-8777-777777777771',
    '01977777-7777-7777-8777-777777777772',
    '01977777-7777-7777-8777-777777777779',
    '01977777-7777-7777-8777-777777777782',
    'queued', 'bcd-queued-cancel', null, null, 0, 0
  ),
  (
    '01977777-7777-7777-8777-777777777787',
    '01977777-7777-7777-8777-777777777771',
    '01977777-7777-7777-8777-777777777772',
    '01977777-7777-7777-8777-777777777779',
    '01977777-7777-7777-8777-777777777782',
    'waiting_approval', 'bcd-waiting-cancel', null, null, 0, 0
  );

insert into run_attempts (
  id, organization_id, workspace_id, run_id, attempt_number,
  lease_owner, fence_token
)
values (
  '01977777-7777-7777-8777-777777777788',
  '01977777-7777-7777-8777-777777777771',
  '01977777-7777-7777-8777-777777777772',
  '01977777-7777-7777-8777-777777777784',
  1,
  'bcd-node',
  7
);

do $$
begin
  perform zeus_private.create_oidc_login_transaction(
    '01977777-7777-7777-8777-777777777773',
    decode(repeat('11', 32), 'hex'),
    decode(repeat('22', 32), 'hex'),
    decode(repeat('33', 12), 'hex'),
    'bcd-key',
    'https://app.invalid/oidc/callback',
    now() + interval '5 minutes'
  );
end
$$;

select set_config('zeus.organization_id', '01977777-7777-7777-8777-777777777771', true);
select set_config('zeus.workspace_id', '01977777-7777-7777-8777-777777777772', true);

do $$
declare
  consumed record;
begin
  select * into consumed
  from zeus_private.consume_oidc_login_transaction(
    '01977777-7777-7777-8777-777777777773',
    decode(repeat('11', 32), 'hex')
  );
  if not found then
    raise exception 'OIDC transaction was not consumed';
  end if;
  if consumed.redirect_uri <> 'https://app.invalid/oidc/callback'
     or consumed.pkce_verifier_key_id <> 'bcd-key' then
    raise exception 'OIDC transaction returned the wrong callback data';
  end if;
  if exists (
    select 1
    from zeus_private.consume_oidc_login_transaction(
      '01977777-7777-7777-8777-777777777773',
      decode(repeat('11', 32), 'hex')
    )
  ) then
    raise exception 'OIDC transaction was consumed twice';
  end if;
end
$$;

do $$
declare
  reservation record;
  conflict_seen boolean := false;
begin
  select * into reservation
  from zeus_private.begin_http_idempotency(
    '01977777-7777-7777-8777-777777777771',
    '01977777-7777-7777-8777-777777777772',
    'system',
    '01977777-7777-7777-8777-777777777799',
    'POST',
    '/api/v1/bcd',
    'bcd-idempotency-key',
    decode(repeat('44', 32), 'hex'),
    300
  );
  if not found or reservation.replayed then
    raise exception 'HTTP idempotency reservation was not new';
  end if;
  if not zeus_private.complete_http_idempotency(
    reservation.id,
    decode(repeat('44', 32), 'hex'),
    'completed',
    201,
    '{"ok":true}'::jsonb
  ) then
    raise exception 'HTTP idempotency reservation did not complete';
  end if;

  begin
    perform 1
    from zeus_private.begin_http_idempotency(
      '01977777-7777-7777-8777-777777777771',
      '01977777-7777-7777-8777-777777777772',
      'system',
      '01977777-7777-7777-8777-777777777799',
      'POST',
      '/api/v1/bcd',
      'bcd-idempotency-key',
      decode(repeat('55', 32), 'hex'),
      300
    );
  exception
    when sqlstate '22023' then
      conflict_seen := true;
  end;
  if not conflict_seen then
    raise exception 'HTTP idempotency hash conflict was accepted';
  end if;

  select * into reservation
  from zeus_private.begin_http_idempotency(
    '01977777-7777-7777-8777-777777777771',
    '01977777-7777-7777-8777-777777777772',
    'system',
    '01977777-7777-7777-8777-777777777799',
    'POST',
    '/api/v1/bcd',
    'bcd-idempotency-key',
    decode(repeat('44', 32), 'hex'),
    300
  );
  if not reservation.replayed or reservation.status <> 'completed'
     or reservation.response_status <> 201 then
    raise exception 'HTTP idempotency replay was not returned';
  end if;
end
$$;

do $$
declare
  first_sequence bigint;
  second_sequence bigint;
begin
  select event_sequence into first_sequence
  from zeus_private.append_session_event(
    '01977777-7777-7777-8777-777777777780',
    'user_message',
    'system',
    '01977777-7777-7777-8777-777777777799',
    '{"text":"first"}'::jsonb
  );
  select event_sequence into second_sequence
  from zeus_private.append_session_event(
    '01977777-7777-7777-8777-777777777780',
    'assistant_message',
    'system',
    '01977777-7777-7777-8777-777777777799',
    '{"text":"second"}'::jsonb
  );
  if first_sequence <> 1 or second_sequence <> 2 then
    raise exception 'session event sequence was not continuous';
  end if;

  select event_sequence into first_sequence
  from zeus_private.append_run_event(
    '01977777-7777-7777-8777-777777777783',
    'run_started',
    '{}'::jsonb
  );
  select event_sequence into second_sequence
  from zeus_private.append_run_event(
    '01977777-7777-7777-8777-777777777783',
    'run_observed',
    '{}'::jsonb
  );
  if first_sequence <> 1 or second_sequence <> 2 then
    raise exception 'run event sequence was not continuous';
  end if;
end
$$;

do $$
declare
  usage_id uuid;
begin
  usage_id := zeus_private.append_run_usage(
    '01977777-7777-7777-8777-777777777784',
    'provider-request-1',
    10,
    20,
    3,
    'bcd-node',
    7
  );
  if usage_id is null then
    raise exception 'run usage was not appended';
  end if;
end
$$;

do $$
begin
  if (select prompt_tokens from run_usage where provider_request_id = 'provider-request-1') <> 10
     or (select completion_tokens from run_usage where provider_request_id = 'provider-request-1') <> 20
     or (select cache_tokens from run_usage where provider_request_id = 'provider-request-1') <> 3 then
    raise exception 'run usage values were not persisted';
  end if;
  begin
    update run_usage
    set prompt_tokens = prompt_tokens + 1
    where provider_request_id = 'provider-request-1';
    raise exception 'run usage update was accepted';
  exception
    when sqlstate '55000' then
      null;
  end;
  begin
    delete from run_usage where provider_request_id = 'provider-request-1';
    raise exception 'run usage delete was accepted';
  exception
    when sqlstate '55000' then
      null;
  end;
end
$$;

do $$
begin
  if not zeus_private.request_run_cancel(
    '01977777-7777-7777-8777-777777777785',
    'system',
    '01977777-7777-7777-8777-777777777799',
    'bcd cancel'
  ) then
    raise exception 'running cancel request was rejected';
  end if;
  if (select status from runs where id = '01977777-7777-7777-8777-777777777785') <> 'running'
     or not exists (
       select 1 from runs
       where id = '01977777-7777-7777-8777-777777777785'
         and cancel_requested_at is not null
     ) then
    raise exception 'running cancel changed the wrong state';
  end if;
  if not zeus_private.request_run_cancel(
    '01977777-7777-7777-8777-777777777786',
    'system',
    '01977777-7777-7777-8777-777777777799',
    'bcd cancel'
  ) then
    raise exception 'queued run cancel request was rejected';
  end if;
  if (select status from runs where id = '01977777-7777-7777-8777-777777777786') <> 'canceled' then
    raise exception 'queued run was not canceled immediately';
  end if;
  if not zeus_private.request_run_cancel(
    '01977777-7777-7777-8777-777777777787',
    'system',
    '01977777-7777-7777-8777-777777777799',
    'bcd cancel'
  ) then
    raise exception 'waiting run cancel request was rejected';
  end if;
  if (select status from runs where id = '01977777-7777-7777-8777-777777777787') <> 'canceled' then
    raise exception 'waiting run was not canceled immediately';
  end if;
  if (select count(*) from run_events where run_id in (
    '01977777-7777-7777-8777-777777777785',
    '01977777-7777-7777-8777-777777777786',
    '01977777-7777-7777-8777-777777777787'
  )) <> 3 then
    raise exception 'cancel did not append one run event per request';
  end if;
end
$$;

do $$
begin
  if not zeus_private.is_run_cancel_requested('01977777-7777-7777-8777-777777777785') then
    raise exception 'runtime could not read cancellation state';
  end if;
  if zeus_private.finish_run(
    '01977777-7777-7777-8777-777777777784',
    'bcd-node',
    6,
    'succeeded',
    '{"stale":true}'::jsonb,
    null,
    null
  ) then
    raise exception 'stale fence was accepted';
  end if;
  if (select status from runs where id = '01977777-7777-7777-8777-777777777784') <> 'running' then
    raise exception 'stale fence changed run state';
  end if;
  if not zeus_private.finish_run(
    '01977777-7777-7777-8777-777777777784',
    'bcd-node',
    7,
    'succeeded',
    '{"ok":true}'::jsonb,
    null,
    null
  ) then
    raise exception 'valid fence was rejected';
  end if;
end
$$;

do $$
declare
  rls_enabled boolean;
  rls_forced boolean;
begin
  select c.relrowsecurity, c.relforcerowsecurity
    into rls_enabled, rls_forced
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = 'public' and c.relname = 'oidc_login_transactions';
  if not rls_enabled or not rls_forced then
    raise exception 'OIDC login transaction RLS is incomplete';
  end if;
  select c.relrowsecurity, c.relforcerowsecurity
    into rls_enabled, rls_forced
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = 'public' and c.relname = 'http_idempotency_keys';
  if not rls_enabled or not rls_forced then
    raise exception 'HTTP idempotency RLS is incomplete';
  end if;
  select c.relrowsecurity, c.relforcerowsecurity
    into rls_enabled, rls_forced
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = 'public' and c.relname = 'run_usage';
  if not rls_enabled or not rls_forced then
    raise exception 'run usage RLS is incomplete';
  end if;
  if exists (
    select 1
    from information_schema.columns
    where table_schema = 'public'
      and table_name = 'oidc_login_transactions'
      and column_name in ('state', 'pkce_verifier')
  ) then
    raise exception 'OIDC plaintext credential columns exist';
  end if;
  if has_table_privilege('public', 'public.oidc_login_transactions', 'SELECT')
     or has_table_privilege('public', 'public.http_idempotency_keys', 'SELECT')
     or has_table_privilege('public', 'public.run_usage', 'SELECT') then
    raise exception 'public can read a BCD table';
  end if;
end
$$;

do $$
declare
  roles_present boolean;
begin
  select exists (select 1 from pg_roles where rolname = 'zeus_http')
         and exists (select 1 from pg_roles where rolname = 'zeus_runtime')
    into roles_present;
  if roles_present then
    if has_table_privilege('zeus_http', 'public.oidc_login_transactions', 'SELECT')
       or has_table_privilege('zeus_http', 'public.http_idempotency_keys', 'SELECT')
       or has_table_privilege('zeus_http', 'public.run_usage', 'SELECT') then
      raise exception 'HTTP role can read a BCD table directly';
    end if;
    if has_table_privilege('zeus_runtime', 'public.run_usage', 'INSERT')
       or has_table_privilege('zeus_runtime', 'public.run_usage', 'UPDATE')
       or has_table_privilege('zeus_runtime', 'public.run_usage', 'DELETE') then
      raise exception 'runtime has direct run usage write privileges';
    end if;
    if not has_function_privilege(
      'zeus_runtime',
      'zeus_private.is_run_cancel_requested(uuid)',
      'EXECUTE'
    ) then
      raise exception 'runtime lacks cancel read function privilege';
    end if;
  end if;
end
$$;

rollback;

select 'BCD PostgreSQL smoke passed' as result;
