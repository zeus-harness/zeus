-- Phase B/C/D: OIDC callback state, HTTP idempotency, and durable runtime facts.

create table oidc_login_transactions (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  provider_id uuid not null references oidc_providers(id),
  state_hash bytea not null,
  pkce_verifier_ciphertext bytea not null,
  pkce_verifier_nonce bytea not null,
  pkce_verifier_key_id text not null,
  redirect_uri text not null,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now(),
  unique (provider_id, state_hash),
  check (octet_length(state_hash) = 32),
  check (octet_length(pkce_verifier_ciphertext) > 0),
  check (octet_length(pkce_verifier_nonce) > 0),
  check (btrim(pkce_verifier_key_id) <> ''),
  check (btrim(redirect_uri) <> ''),
  check (expires_at > created_at),
  check (consumed_at is null or consumed_at >= created_at)
);
create index oidc_login_transactions_organization_id_idx
  on oidc_login_transactions (organization_id);
create index oidc_login_transactions_provider_id_idx
  on oidc_login_transactions (provider_id);
create index oidc_login_transactions_active_idx
  on oidc_login_transactions (provider_id, state_hash, expires_at)
  where consumed_at is null;

create or replace function zeus_private.guard_oidc_login_transaction()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if old.organization_id is distinct from new.organization_id
     or old.provider_id is distinct from new.provider_id
     or old.state_hash is distinct from new.state_hash
     or old.pkce_verifier_ciphertext is distinct from new.pkce_verifier_ciphertext
     or old.pkce_verifier_nonce is distinct from new.pkce_verifier_nonce
     or old.pkce_verifier_key_id is distinct from new.pkce_verifier_key_id
     or old.redirect_uri is distinct from new.redirect_uri
     or old.expires_at is distinct from new.expires_at
     or old.created_at is distinct from new.created_at then
    raise exception 'OIDC login transaction credentials are immutable' using errcode = '55000';
  end if;

  if old.consumed_at is not null
     and new.consumed_at is distinct from old.consumed_at then
    raise exception 'OIDC login transaction was already consumed' using errcode = '55000';
  end if;
  return new;
end
$$;

create trigger oidc_login_transactions_consumption_guard
before update on oidc_login_transactions
for each row execute function zeus_private.guard_oidc_login_transaction();

create or replace function zeus_private.create_oidc_login_transaction(
  target_provider_id uuid,
  target_state_hash bytea,
  target_pkce_verifier_ciphertext bytea,
  target_pkce_verifier_nonce bytea,
  target_pkce_verifier_key_id text,
  target_redirect_uri text,
  target_expires_at timestamptz
)
returns uuid
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  provider_organization_id uuid;
  transaction_id uuid;
begin
  if target_state_hash is null or octet_length(target_state_hash) <> 32 then
    raise exception 'invalid OIDC state hash' using errcode = '22023';
  end if;
  if target_pkce_verifier_ciphertext is null
     or octet_length(target_pkce_verifier_ciphertext) = 0
     or target_pkce_verifier_nonce is null
     or octet_length(target_pkce_verifier_nonce) = 0 then
    raise exception 'invalid encrypted PKCE verifier' using errcode = '22023';
  end if;
  if target_expires_at is null or target_expires_at <= now() then
    raise exception 'OIDC login transaction must not be expired' using errcode = '22023';
  end if;

  select p.organization_id
    into provider_organization_id
  from public.oidc_providers p
  where p.id = target_provider_id
    and p.enabled;

  if not found then
    raise exception 'OIDC provider is unavailable' using errcode = '22023';
  end if;
  if zeus_private.current_organization_id() is not null
     and provider_organization_id <> zeus_private.current_organization_id() then
    raise exception 'organization context does not match OIDC provider' using errcode = '42501';
  end if;

  insert into public.oidc_login_transactions (
    organization_id,
    provider_id,
    state_hash,
    pkce_verifier_ciphertext,
    pkce_verifier_nonce,
    pkce_verifier_key_id,
    redirect_uri,
    expires_at
  )
  values (
    provider_organization_id,
    target_provider_id,
    target_state_hash,
    target_pkce_verifier_ciphertext,
    target_pkce_verifier_nonce,
    target_pkce_verifier_key_id,
    target_redirect_uri,
    target_expires_at
  )
  returning id into transaction_id;

  return transaction_id;
end
$$;

create or replace function zeus_private.consume_oidc_login_transaction(
  target_provider_id uuid,
  target_state_hash bytea
)
returns table (
  transaction_id uuid,
  organization_id uuid,
  provider_id uuid,
  redirect_uri text,
  pkce_verifier_ciphertext bytea,
  pkce_verifier_nonce bytea,
  pkce_verifier_key_id text,
  consumed_at timestamptz
)
language sql
security definer
set search_path = pg_catalog, public
as $$
  update public.oidc_login_transactions as t
  set consumed_at = now()
  where t.provider_id = $1
    and t.state_hash = $2
    and t.consumed_at is null
    and t.expires_at > now()
    and (
      zeus_private.current_organization_id() is null
      or t.organization_id = zeus_private.current_organization_id()
    )
  returning t.id,
            t.organization_id,
            t.provider_id,
            t.redirect_uri,
            t.pkce_verifier_ciphertext,
            t.pkce_verifier_nonce,
            t.pkce_verifier_key_id,
            t.consumed_at
$$;

create table http_idempotency_keys (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid references workspaces(id),
  actor_kind text not null default 'user'
    check (actor_kind in ('user', 'service_account', 'agent', 'system')),
  actor_id uuid not null,
  method text not null
    check (method = upper(method) and method in (
      'CONNECT', 'DELETE', 'GET', 'HEAD', 'OPTIONS', 'PATCH', 'POST', 'PUT', 'TRACE'
    )),
  path text not null check (btrim(path) = path and length(path) between 1 and 2048),
  idempotency_key text not null
    check (btrim(idempotency_key) = idempotency_key and length(idempotency_key) between 1 and 255),
  request_hash bytea not null check (octet_length(request_hash) = 32),
  status text not null default 'in_progress'
    check (status in ('in_progress', 'completed', 'failed')),
  response_status integer check (response_status is null or response_status between 100 and 599),
  response_body jsonb,
  expires_at timestamptz not null,
  completed_at timestamptz,
  created_at timestamptz not null default now(),
  constraint http_idempotency_keys_scope_unique
    unique nulls not distinct (
      organization_id,
      workspace_id,
      actor_kind,
      actor_id,
      method,
      path,
      idempotency_key
    ),
  check (expires_at > created_at),
  check (completed_at is null or completed_at >= created_at),
  check (
    (status = 'in_progress' and completed_at is null and response_status is null and response_body is null)
    or (status in ('completed', 'failed') and completed_at is not null and response_status is not null)
  )
);
create index http_idempotency_keys_organization_id_idx
  on http_idempotency_keys (organization_id);
create index http_idempotency_keys_workspace_id_idx
  on http_idempotency_keys (workspace_id);
create index http_idempotency_keys_active_idx
  on http_idempotency_keys (organization_id, workspace_id, expires_at)
  where status = 'in_progress';

create or replace function zeus_private.guard_http_idempotency_key()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if old.organization_id is distinct from new.organization_id
     or old.workspace_id is distinct from new.workspace_id
     or old.actor_kind is distinct from new.actor_kind
     or old.actor_id is distinct from new.actor_id
     or old.method is distinct from new.method
     or old.path is distinct from new.path
     or old.idempotency_key is distinct from new.idempotency_key then
    raise exception 'HTTP idempotency scope is immutable' using errcode = '55000';
  end if;

  if old.request_hash is distinct from new.request_hash and old.expires_at > now() then
    raise exception 'HTTP idempotency request hash is immutable while active' using errcode = '55000';
  end if;
  return new;
end
$$;

create trigger http_idempotency_keys_scope_guard
before update on http_idempotency_keys
for each row execute function zeus_private.guard_http_idempotency_key();

create or replace function zeus_private.begin_http_idempotency(
  target_organization_id uuid,
  target_workspace_id uuid,
  target_actor_kind text,
  target_actor_id uuid,
  target_method text,
  target_path text,
  target_idempotency_key text,
  target_request_hash bytea,
  target_ttl_seconds integer default 86400
)
returns table (
  id uuid,
  status text,
  request_hash bytea,
  response_status integer,
  response_body jsonb,
  replayed boolean
)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  inserted_row public.http_idempotency_keys%rowtype;
  existing_row public.http_idempotency_keys%rowtype;
  normalized_actor_kind text := lower(btrim(target_actor_kind));
  normalized_method text := upper(btrim(target_method));
  current_organization_id uuid := zeus_private.current_organization_id();
  current_workspace_id uuid := zeus_private.current_workspace_id();
begin
  if target_organization_id is null
     or target_actor_id is null
     or target_method is null
     or target_path is null
     or target_idempotency_key is null
     or target_request_hash is null
     or octet_length(target_request_hash) <> 32 then
    raise exception 'invalid HTTP idempotency arguments' using errcode = '22023';
  end if;
  if target_actor_kind is null
     or normalized_actor_kind not in ('user', 'service_account', 'agent', 'system') then
    raise exception 'invalid HTTP idempotency actor' using errcode = '22023';
  end if;
  if target_method <> btrim(target_method)
     or normalized_method not in (
       'CONNECT', 'DELETE', 'GET', 'HEAD', 'OPTIONS', 'PATCH', 'POST', 'PUT', 'TRACE'
     ) then
    raise exception 'invalid HTTP method' using errcode = '22023';
  end if;
  if target_path <> btrim(target_path)
     or length(target_path) not between 1 and 2048 then
    raise exception 'invalid HTTP path' using errcode = '22023';
  end if;
  if target_idempotency_key <> btrim(target_idempotency_key)
     or length(target_idempotency_key) not between 1 and 255 then
    raise exception 'invalid HTTP idempotency key' using errcode = '22023';
  end if;
  if target_ttl_seconds is null or target_ttl_seconds not between 1 and 2592000 then
    raise exception 'invalid HTTP idempotency retention' using errcode = '22023';
  end if;

  if current_organization_id is not null
     and target_organization_id <> current_organization_id then
    raise exception 'organization context does not match HTTP idempotency scope' using errcode = '42501';
  end if;
  if current_workspace_id is not null
     and target_workspace_id is distinct from current_workspace_id then
    raise exception 'workspace context does not match HTTP idempotency scope' using errcode = '42501';
  end if;
  if normalized_actor_kind = 'user'
     and zeus_private.current_user_id() is not null
     and target_actor_id <> zeus_private.current_user_id() then
    raise exception 'actor context does not match HTTP idempotency scope' using errcode = '42501';
  end if;
  if target_workspace_id is not null and not exists (
    select 1
    from public.workspaces w
    where w.id = target_workspace_id
      and w.organization_id = target_organization_id
  ) then
    raise exception 'workspace does not belong to organization' using errcode = '22023';
  end if;

  insert into public.http_idempotency_keys (
    organization_id,
    workspace_id,
    actor_kind,
    actor_id,
    method,
    path,
    idempotency_key,
    request_hash,
    expires_at
  )
  values (
    target_organization_id,
    target_workspace_id,
    normalized_actor_kind,
    target_actor_id,
    normalized_method,
    target_path,
    target_idempotency_key,
    target_request_hash,
    now() + make_interval(secs => target_ttl_seconds)
  )
  on conflict on constraint http_idempotency_keys_scope_unique do nothing
  returning * into inserted_row;

  if found then
    return query
    select inserted_row.id,
           inserted_row.status,
           inserted_row.request_hash,
           inserted_row.response_status,
           inserted_row.response_body,
           false;
    return;
  end if;

  select h.*
    into existing_row
  from public.http_idempotency_keys h
  where h.organization_id = target_organization_id
    and h.workspace_id is not distinct from target_workspace_id
    and h.actor_kind = normalized_actor_kind
    and h.actor_id = target_actor_id
    and h.method = normalized_method
    and h.path = target_path
    and h.idempotency_key = target_idempotency_key
  for update;

  if not found then
    raise exception 'HTTP idempotency reservation disappeared' using errcode = '40001';
  end if;

  if existing_row.expires_at <= now() then
    update public.http_idempotency_keys h
    set request_hash = target_request_hash,
        status = 'in_progress',
        response_status = null,
        response_body = null,
        completed_at = null,
        expires_at = now() + make_interval(secs => target_ttl_seconds),
        created_at = now()
    where h.id = existing_row.id
    returning h.* into existing_row;

    return query
    select existing_row.id,
           existing_row.status,
           existing_row.request_hash,
           existing_row.response_status,
           existing_row.response_body,
           false;
    return;
  end if;

  if existing_row.request_hash is distinct from target_request_hash then
    raise exception 'HTTP idempotency key reused with a different request hash'
      using errcode = '22023';
  end if;

  return query
  select existing_row.id,
         existing_row.status,
         existing_row.request_hash,
         existing_row.response_status,
         existing_row.response_body,
         true;
end
$$;

create or replace function zeus_private.complete_http_idempotency(
  target_id uuid,
  target_request_hash bytea,
  target_status text,
  target_response_status integer,
  target_response_body jsonb
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  existing_row public.http_idempotency_keys%rowtype;
begin
  if target_request_hash is null or octet_length(target_request_hash) <> 32
     or target_status not in ('completed', 'failed')
     or target_response_status is null
     or target_response_status not between 100 and 599 then
    raise exception 'invalid HTTP idempotency response' using errcode = '22023';
  end if;

  select h.*
    into existing_row
  from public.http_idempotency_keys h
  where h.id = target_id
  for update;

  if not found then
    return false;
  end if;
  if zeus_private.current_organization_id() is not null
     and existing_row.organization_id <> zeus_private.current_organization_id() then
    raise exception 'organization context does not match HTTP idempotency record' using errcode = '42501';
  end if;
  if zeus_private.current_workspace_id() is not null
     and existing_row.workspace_id is distinct from zeus_private.current_workspace_id() then
    raise exception 'workspace context does not match HTTP idempotency record' using errcode = '42501';
  end if;
  if existing_row.request_hash is distinct from target_request_hash then
    raise exception 'HTTP idempotency request hash does not match reservation'
      using errcode = '22023';
  end if;
  if existing_row.status <> 'in_progress' or existing_row.expires_at <= now() then
    return false;
  end if;

  update public.http_idempotency_keys
  set status = target_status,
      response_status = target_response_status,
      response_body = target_response_body,
      completed_at = now()
  where id = target_id;
  return true;
end
$$;

create table run_usage (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  run_id uuid not null references runs(id),
  provider_request_id text not null check (btrim(provider_request_id) <> ''),
  prompt_tokens bigint not null default 0 check (prompt_tokens >= 0),
  completion_tokens bigint not null default 0 check (completion_tokens >= 0),
  cache_tokens bigint not null default 0 check (cache_tokens >= 0),
  created_at timestamptz not null default now(),
  constraint run_usage_run_provider_request_unique
    unique (run_id, provider_request_id)
);
create index run_usage_organization_id_idx on run_usage (organization_id);
create index run_usage_workspace_id_idx on run_usage (workspace_id);
create index run_usage_run_id_idx on run_usage (run_id);
create index run_usage_provider_request_id_idx on run_usage (provider_request_id);

create trigger run_usage_append_only
before update or delete on run_usage
for each row execute function zeus_private.reject_mutation();

create or replace function zeus_private.append_run_usage(
  target_run_id uuid,
  target_provider_request_id text,
  target_prompt_tokens bigint,
  target_completion_tokens bigint,
  target_cache_tokens bigint,
  target_node_id text default null,
  expected_fence_token bigint default null
)
returns uuid
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  run_row public.runs%rowtype;
  existing_usage public.run_usage%rowtype;
  usage_id uuid;
begin
  if target_provider_request_id is null or btrim(target_provider_request_id) = ''
     or target_prompt_tokens is null or target_prompt_tokens < 0
     or target_completion_tokens is null or target_completion_tokens < 0
     or target_cache_tokens is null or target_cache_tokens < 0 then
    raise exception 'invalid run usage' using errcode = '22023';
  end if;
  if (target_node_id is null) <> (expected_fence_token is null) then
    raise exception 'node and fence token must be supplied together' using errcode = '22023';
  end if;

  select r.*
    into run_row
  from public.runs r
  where r.id = target_run_id
  for update;

  if not found then
    raise exception 'run not found' using errcode = 'P0002';
  end if;
  if zeus_private.current_organization_id() is not null
     and run_row.organization_id <> zeus_private.current_organization_id() then
    raise exception 'organization context does not match run' using errcode = '42501';
  end if;
  if zeus_private.current_workspace_id() is not null
     and run_row.workspace_id <> zeus_private.current_workspace_id() then
    raise exception 'workspace context does not match run' using errcode = '42501';
  end if;
  if expected_fence_token is not null
     and (
       target_node_id = ''
       or run_row.status <> 'running'
       or run_row.lease_owner is distinct from target_node_id
       or run_row.fence_token <> expected_fence_token
     ) then
    raise exception 'stale run fence' using errcode = '40001';
  end if;

  insert into public.run_usage (
    organization_id,
    workspace_id,
    run_id,
    provider_request_id,
    prompt_tokens,
    completion_tokens,
    cache_tokens
  )
  values (
    run_row.organization_id,
    run_row.workspace_id,
    run_row.id,
    target_provider_request_id,
    target_prompt_tokens,
    target_completion_tokens,
    target_cache_tokens
  )
  on conflict on constraint run_usage_run_provider_request_unique do nothing
  returning id into usage_id;

  if found then
    return usage_id;
  end if;

  select u.*
    into existing_usage
  from public.run_usage u
  where u.run_id = target_run_id
    and u.provider_request_id = target_provider_request_id;
  if existing_usage.prompt_tokens <> target_prompt_tokens
     or existing_usage.completion_tokens <> target_completion_tokens
     or existing_usage.cache_tokens <> target_cache_tokens then
    raise exception 'provider request usage does not match existing ledger row'
      using errcode = '22023';
  end if;
  return existing_usage.id;
end
$$;

create or replace function zeus_private.append_session_event(
  target_session_id uuid,
  target_event_type text,
  target_actor_kind text,
  target_actor_id uuid,
  target_payload jsonb,
  target_run_id uuid default null,
  target_schema_version smallint default 1
)
returns table (
  event_id uuid,
  event_sequence bigint
)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  session_organization_id uuid;
  session_workspace_id uuid;
  run_organization_id uuid;
  run_workspace_id uuid;
  run_session_id uuid;
  next_sequence bigint;
  new_event_id uuid;
begin
  if target_event_type is null or btrim(target_event_type) = ''
     or target_actor_kind is null
     or target_actor_kind not in ('user', 'service_account', 'agent', 'system')
     or target_payload is null
     or target_schema_version is null or target_schema_version <= 0 then
    raise exception 'invalid session event' using errcode = '22023';
  end if;
  if target_actor_kind = 'user'
     and zeus_private.current_user_id() is not null
     and target_actor_id is distinct from zeus_private.current_user_id() then
    raise exception 'actor context does not match session event' using errcode = '42501';
  end if;

  select s.organization_id, s.workspace_id
    into session_organization_id, session_workspace_id
  from public.sessions s
  where s.id = target_session_id
  for update;
  if not found then
    raise exception 'session not found' using errcode = 'P0002';
  end if;
  if zeus_private.current_organization_id() is not null
     and session_organization_id <> zeus_private.current_organization_id() then
    raise exception 'organization context does not match session' using errcode = '42501';
  end if;
  if zeus_private.current_workspace_id() is not null
     and session_workspace_id <> zeus_private.current_workspace_id() then
    raise exception 'workspace context does not match session' using errcode = '42501';
  end if;

  if target_run_id is not null then
    select r.organization_id, r.workspace_id, r.session_id
      into run_organization_id, run_workspace_id, run_session_id
    from public.runs r
    where r.id = target_run_id;
    if not found
       or run_session_id <> target_session_id
       or run_organization_id <> session_organization_id
       or run_workspace_id <> session_workspace_id then
      raise exception 'run does not belong to session' using errcode = '22023';
    end if;
  end if;

  select coalesce(max(e.sequence), 0) + 1
    into next_sequence
  from public.session_events e
  where e.session_id = target_session_id;

  insert into public.session_events (
    organization_id,
    workspace_id,
    session_id,
    run_id,
    sequence,
    schema_version,
    event_type,
    actor_kind,
    actor_id,
    payload
  )
  values (
    session_organization_id,
    session_workspace_id,
    target_session_id,
    target_run_id,
    next_sequence,
    target_schema_version,
    target_event_type,
    target_actor_kind,
    target_actor_id,
    target_payload
  )
  returning id into new_event_id;

  return query select new_event_id, next_sequence;
end
$$;

create or replace function zeus_private.append_run_event(
  target_run_id uuid,
  target_event_type text,
  target_payload jsonb,
  target_session_event_id uuid default null,
  target_schema_version smallint default 1
)
returns table (
  event_id uuid,
  event_sequence bigint
)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  run_organization_id uuid;
  run_workspace_id uuid;
  run_session_id uuid;
  session_event_organization_id uuid;
  session_event_workspace_id uuid;
  session_event_session_id uuid;
  next_sequence bigint;
  new_event_id uuid;
begin
  if target_event_type is null or btrim(target_event_type) = ''
     or target_payload is null
     or target_schema_version is null or target_schema_version <= 0 then
    raise exception 'invalid run event' using errcode = '22023';
  end if;

  select r.organization_id, r.workspace_id, r.session_id
    into run_organization_id, run_workspace_id, run_session_id
  from public.runs r
  where r.id = target_run_id
  for update;
  if not found then
    raise exception 'run not found' using errcode = 'P0002';
  end if;
  if zeus_private.current_organization_id() is not null
     and run_organization_id <> zeus_private.current_organization_id() then
    raise exception 'organization context does not match run' using errcode = '42501';
  end if;
  if zeus_private.current_workspace_id() is not null
     and run_workspace_id <> zeus_private.current_workspace_id() then
    raise exception 'workspace context does not match run' using errcode = '42501';
  end if;

  if target_session_event_id is not null then
    select e.organization_id, e.workspace_id, e.session_id
      into session_event_organization_id, session_event_workspace_id, session_event_session_id
    from public.session_events e
    where e.id = target_session_event_id;
    if not found
       or session_event_organization_id <> run_organization_id
       or session_event_workspace_id <> run_workspace_id
       or session_event_session_id <> run_session_id then
      raise exception 'session event does not belong to run' using errcode = '22023';
    end if;
  end if;

  select coalesce(max(e.sequence), 0) + 1
    into next_sequence
  from public.run_events e
  where e.run_id = target_run_id;

  insert into public.run_events (
    organization_id,
    workspace_id,
    run_id,
    session_event_id,
    sequence,
    schema_version,
    event_type,
    payload
  )
  values (
    run_organization_id,
    run_workspace_id,
    target_run_id,
    target_session_event_id,
    next_sequence,
    target_schema_version,
    target_event_type,
    target_payload
  )
  returning id into new_event_id;

  return query select new_event_id, next_sequence;
end
$$;

create or replace function zeus_private.request_run_cancel(
  target_run_id uuid,
  target_actor_kind text default 'system',
  target_actor_id uuid default null,
  target_reason text default null
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  run_organization_id uuid;
  run_workspace_id uuid;
  run_status text;
  previous_status text;
  cancel_event_type text;
begin
  if target_actor_kind is null
     or target_actor_kind not in ('user', 'service_account', 'agent', 'system') then
    raise exception 'invalid cancellation actor' using errcode = '22023';
  end if;
  if target_actor_kind = 'user'
     and zeus_private.current_user_id() is not null
     and target_actor_id is distinct from zeus_private.current_user_id() then
    raise exception 'actor context does not match cancellation' using errcode = '42501';
  end if;

  select r.organization_id, r.workspace_id, r.status
    into run_organization_id, run_workspace_id, run_status
  from public.runs r
  where r.id = target_run_id
  for update;
  if not found then
    return false;
  end if;
  if zeus_private.current_organization_id() is not null
     and run_organization_id <> zeus_private.current_organization_id() then
    raise exception 'organization context does not match run' using errcode = '42501';
  end if;
  if zeus_private.current_workspace_id() is not null
     and run_workspace_id <> zeus_private.current_workspace_id() then
    raise exception 'workspace context does not match run' using errcode = '42501';
  end if;

  if run_status in ('succeeded', 'failed', 'canceled') then
    return false;
  end if;
  if run_status = 'running'
     and exists (
       select 1 from public.runs r
       where r.id = target_run_id and r.cancel_requested_at is not null
     ) then
    return true;
  end if;

  previous_status := run_status;
  if run_status = 'running' then
    update public.runs
    set cancel_requested_at = coalesce(cancel_requested_at, now()),
        updated_at = now()
    where id = target_run_id;
    cancel_event_type := 'run.cancel_requested';
  elsif run_status in ('queued', 'waiting_approval', 'waiting_child') then
    update public.runs
    set status = 'canceled',
        cancel_requested_at = coalesce(cancel_requested_at, now()),
        lease_owner = null,
        lease_expires_at = null,
        finished_at = coalesce(finished_at, now()),
        updated_at = now()
    where id = target_run_id;
    cancel_event_type := 'run.canceled';
  else
    raise exception 'run is not cancelable' using errcode = '22023';
  end if;

  perform zeus_private.append_run_event(
    target_run_id,
    cancel_event_type,
    jsonb_build_object(
      'previous_status', previous_status,
      'status', case when previous_status = 'running' then 'running' else 'canceled' end,
      'actor_kind', target_actor_kind,
      'actor_id', target_actor_id,
      'reason', target_reason
    )
  );
  return true;
end
$$;

create or replace function zeus_private.is_run_cancel_requested(
  target_run_id uuid
)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select coalesce((
    select r.cancel_requested_at is not null or r.status = 'canceled'
    from public.runs r
    where r.id = $1
  ), false)
$$;

-- Keep the existing fenced finish API, but make cancellation observable and durable.
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
  target_session_id uuid;
  event_type text;
begin
  if target_status not in ('queued', 'waiting_approval', 'waiting_child', 'succeeded', 'failed', 'canceled') then
    raise exception 'invalid terminal or release status' using errcode = '22023';
  end if;

  update public.runs r
  set status = target_status,
      output = result,
      error_code = failure_code,
      error_detail = failure_detail,
      lease_owner = null,
      lease_expires_at = null,
      available_at = case when target_status = 'queued' then now() else r.available_at end,
      finished_at = case when target_status in ('succeeded', 'failed', 'canceled') then now() else null end,
      updated_at = now()
  where r.id = target_run_id
    and r.status = 'running'
    and r.lease_owner = node_id
    and r.fence_token = expected_fence_token
    and (target_status = 'canceled' or r.cancel_requested_at is null)
  returning r.session_id into target_session_id;

  get diagnostics affected = row_count;
  if affected = 1 then
    update public.run_attempts
    set status = case
          when target_status = 'queued' then 'released'
          when target_status in ('waiting_approval', 'waiting_child') then 'released'
          else target_status
        end,
        heartbeat_at = now(),
        finished_at = now(),
        error_code = failure_code
    where run_id = target_run_id and fence_token = expected_fence_token;

    event_type := case when target_status = 'canceled' then 'run.canceled' else 'run.status_changed' end;
    perform zeus_private.append_run_event(
      target_run_id,
      event_type,
      jsonb_build_object(
        'status', target_status,
        'fence_token', expected_fence_token,
        'error_code', failure_code
      )
    );
    return true;
  end if;
  return false;
end
$$;

alter table oidc_login_transactions enable row level security;
alter table oidc_login_transactions force row level security;
create policy oidc_login_transactions_organization_isolation on oidc_login_transactions
  using (organization_id = (select zeus_private.current_organization_id()))
  with check (organization_id = (select zeus_private.current_organization_id()));

alter table http_idempotency_keys enable row level security;
alter table http_idempotency_keys force row level security;
create policy http_idempotency_keys_tenant_isolation on http_idempotency_keys
  using (
    organization_id = (select zeus_private.current_organization_id())
    and (workspace_id is null or workspace_id = (select zeus_private.current_workspace_id()))
  )
  with check (
    organization_id = (select zeus_private.current_organization_id())
    and (workspace_id is null or workspace_id = (select zeus_private.current_workspace_id()))
  );

alter table run_usage enable row level security;
alter table run_usage force row level security;
create policy run_usage_workspace_isolation on run_usage
  using (
    organization_id = (select zeus_private.current_organization_id())
    and workspace_id = (select zeus_private.current_workspace_id())
  )
  with check (
    organization_id = (select zeus_private.current_organization_id())
    and workspace_id = (select zeus_private.current_workspace_id())
  );

revoke all on table oidc_login_transactions, http_idempotency_keys, run_usage from public;
revoke all on function zeus_private.guard_oidc_login_transaction() from public;
revoke all on function zeus_private.create_oidc_login_transaction(uuid, bytea, bytea, bytea, text, text, timestamptz) from public;
revoke all on function zeus_private.consume_oidc_login_transaction(uuid, bytea) from public;
revoke all on function zeus_private.guard_http_idempotency_key() from public;
revoke all on function zeus_private.begin_http_idempotency(uuid, uuid, text, uuid, text, text, text, bytea, integer) from public;
revoke all on function zeus_private.complete_http_idempotency(uuid, bytea, text, integer, jsonb) from public;
revoke all on function zeus_private.append_run_usage(uuid, text, bigint, bigint, bigint, text, bigint) from public;
revoke all on function zeus_private.append_session_event(uuid, text, text, uuid, jsonb, uuid, smallint) from public;
revoke all on function zeus_private.append_run_event(uuid, text, jsonb, uuid, smallint) from public;
revoke all on function zeus_private.request_run_cancel(uuid, text, uuid, text) from public;
revoke all on function zeus_private.is_run_cancel_requested(uuid) from public;
revoke all on function zeus_private.finish_run(uuid, text, bigint, text, jsonb, text, text) from public;

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'zeus_http') then
    execute 'grant usage on schema zeus_private to zeus_http';
    execute 'revoke all on table public.oidc_login_transactions, public.http_idempotency_keys, public.run_usage from zeus_http';
    execute 'revoke insert, update, delete on table public.session_events, public.run_events from zeus_http';
    execute 'grant execute on function zeus_private.create_oidc_login_transaction(uuid, bytea, bytea, bytea, text, text, timestamptz) to zeus_http';
    execute 'grant execute on function zeus_private.consume_oidc_login_transaction(uuid, bytea) to zeus_http';
    execute 'grant execute on function zeus_private.begin_http_idempotency(uuid, uuid, text, uuid, text, text, text, bytea, integer) to zeus_http';
    execute 'grant execute on function zeus_private.complete_http_idempotency(uuid, bytea, text, integer, jsonb) to zeus_http';
    execute 'grant execute on function zeus_private.append_session_event(uuid, text, text, uuid, jsonb, uuid, smallint) to zeus_http';
    execute 'grant execute on function zeus_private.append_run_event(uuid, text, jsonb, uuid, smallint) to zeus_http';
    execute 'grant execute on function zeus_private.request_run_cancel(uuid, text, uuid, text) to zeus_http';
  end if;

  if exists (select 1 from pg_roles where rolname = 'zeus_runtime') then
    execute 'grant usage on schema zeus_private to zeus_runtime';
    execute 'revoke all on table public.oidc_login_transactions, public.http_idempotency_keys, public.run_usage from zeus_runtime';
    execute 'revoke insert, update, delete on table public.session_events, public.run_events from zeus_runtime';
    execute 'grant execute on function zeus_private.append_run_usage(uuid, text, bigint, bigint, bigint, text, bigint) to zeus_runtime';
    execute 'grant execute on function zeus_private.append_session_event(uuid, text, text, uuid, jsonb, uuid, smallint) to zeus_runtime';
    execute 'grant execute on function zeus_private.append_run_event(uuid, text, jsonb, uuid, smallint) to zeus_runtime';
    execute 'grant execute on function zeus_private.is_run_cancel_requested(uuid) to zeus_runtime';
    execute 'grant execute on function zeus_private.finish_run(uuid, text, bigint, text, jsonb, text, text) to zeus_runtime';
  end if;
end
$$;
