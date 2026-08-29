-- Keep database privileges aligned with the HTTP and embedded runtime boundaries.

create or replace function zeus_private.read_run_usage(target_run_id uuid)
returns table (
  id uuid,
  run_id uuid,
  provider_request_id text,
  prompt_tokens bigint,
  completion_tokens bigint,
  cache_tokens bigint,
  occurred_at timestamptz
)
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select u.id,
         u.run_id,
         u.provider_request_id,
         u.prompt_tokens,
         u.completion_tokens,
         u.cache_tokens,
         u.created_at
  from public.run_usage u
  where u.run_id = target_run_id
    and u.organization_id = zeus_private.current_organization_id()
    and u.workspace_id = zeus_private.current_workspace_id()
  order by u.created_at, u.id
$$;

revoke all on function zeus_private.read_run_usage(uuid) from public;

grant usage on schema public, zeus_private to zeus_http;
grant select, insert, update on all tables in schema public to zeus_http;
grant usage, select on all sequences in schema public to zeus_http;

revoke all on table public.oidc_login_transactions,
  public.http_idempotency_keys,
  public.run_usage
  from zeus_http;
revoke insert, update, delete on table public.session_events,
  public.run_events
  from zeus_http;

grant execute on function zeus_private.authenticate_web_session(bytea) to zeus_http;
grant execute on function zeus_private.lookup_service_account(text) to zeus_http;
grant execute on function zeus_private.touch_service_account(uuid) to zeus_http;
grant execute on function zeus_private.get_oidc_provider_for_login(uuid) to zeus_http;
grant execute on function zeus_private.jit_oidc_identity(uuid, text, text, text, text, boolean, jsonb) to zeus_http;
grant execute on function zeus_private.create_web_session(uuid, uuid, uuid, bytea, integer) to zeus_http;
grant execute on function zeus_private.revoke_web_session(bytea) to zeus_http;
grant execute on function zeus_private.select_web_session_workspace(uuid, uuid, uuid) to zeus_http;
grant execute on function zeus_private.create_organization_for_user(uuid, text, text, text, text) to zeus_http;
grant execute on function zeus_private.create_oidc_login_transaction(uuid, bytea, bytea, bytea, text, text, timestamptz) to zeus_http;
grant execute on function zeus_private.consume_oidc_login_transaction(uuid, bytea) to zeus_http;
grant execute on function zeus_private.begin_http_idempotency(uuid, uuid, text, uuid, text, text, text, bytea, integer) to zeus_http;
grant execute on function zeus_private.complete_http_idempotency(uuid, bytea, text, integer, jsonb) to zeus_http;
grant execute on function zeus_private.append_session_event(uuid, text, text, uuid, jsonb, uuid, smallint) to zeus_http;
grant execute on function zeus_private.append_run_event(uuid, text, jsonb, uuid, smallint) to zeus_http;
grant execute on function zeus_private.request_run_cancel(uuid, text, uuid, text) to zeus_http;
grant execute on function zeus_private.read_run_usage(uuid) to zeus_http;

grant usage on schema public, zeus_private to zeus_runtime;
grant select on table public.workflows,
  public.workflow_versions,
  public.agent_versions,
  public.model_profiles,
  public.connections,
  public.connection_secrets,
  public.capability_definitions,
  public.workspace_capabilities,
  public.sessions,
  public.session_events,
  public.experience_entries,
  public.run_usage
  to zeus_runtime;
grant select, insert, update on table public.runs,
  public.run_attempts,
  public.run_events,
  public.session_events,
  public.tool_calls,
  public.approvals,
  public.outbox_events
  to zeus_runtime;
grant insert on table public.audit_events to zeus_runtime;

revoke all on table public.oidc_login_transactions,
  public.http_idempotency_keys
  from zeus_runtime;
revoke insert, update, delete on table public.run_usage from zeus_runtime;
revoke update, delete on table public.session_events,
  public.run_events
  from zeus_runtime;

grant execute on function zeus_private.claim_run(text, integer) to zeus_runtime;
grant execute on function zeus_private.heartbeat_run(uuid, text, bigint, integer) to zeus_runtime;
grant execute on function zeus_private.finish_run(uuid, text, bigint, text, jsonb, text, text) to zeus_runtime;
grant execute on function zeus_private.append_run_usage(uuid, text, bigint, bigint, bigint, text, bigint) to zeus_runtime;
grant execute on function zeus_private.append_session_event(uuid, text, text, uuid, jsonb, uuid, smallint) to zeus_runtime;
grant execute on function zeus_private.append_run_event(uuid, text, jsonb, uuid, smallint) to zeus_runtime;
grant execute on function zeus_private.is_run_cancel_requested(uuid) to zeus_runtime;
grant execute on function zeus_private.lock_runtime_run(uuid, text, bigint) to zeus_runtime;
grant execute on function zeus_private.synthesize_canceled_tool_results(uuid) to zeus_runtime;
