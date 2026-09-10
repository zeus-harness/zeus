-- Phase B/C identity entry points and control-plane revision metadata.

alter table capability_definitions
  add column revision bigint not null default 1 check (revision > 0),
  add column updated_at timestamptz not null default now();

create or replace function zeus_private.authenticate_web_session(target_token_hash bytea)
returns table (
  session_id uuid,
  user_id uuid,
  organization_id uuid,
  workspace_id uuid,
  organization_role text,
  workspace_role text,
  email text,
  display_name text
)
language sql
security definer
set search_path = pg_catalog, public
as $$
  with touched as (
    update public.web_sessions as s
    set last_seen_at = now()
    where s.token_hash = target_token_hash
      and s.revoked_at is null
      and s.expires_at > now()
    returning s.*
  )
  select t.id,
         t.user_id,
         t.organization_id,
         case when wm.user_id is not null then t.workspace_id else null end,
         om.role,
         wm.role,
         u.email,
         u.display_name
  from touched t
  join public.users u
    on u.id = t.user_id and u.status = 'active'
  join public.organization_memberships om
    on om.organization_id = t.organization_id
   and om.user_id = t.user_id
   and om.status = 'active'
  left join public.workspace_memberships wm
    on wm.organization_id = t.organization_id
   and wm.workspace_id = t.workspace_id
   and wm.user_id = t.user_id
   and wm.status = 'active'
$$;

create or replace function zeus_private.lookup_service_account(target_token_prefix text)
returns table (
  service_account_id uuid,
  organization_id uuid,
  workspace_id uuid,
  name text,
  token_hash text,
  scopes text[]
)
language sql
security definer
set search_path = pg_catalog, public
as $$
  select s.id, s.organization_id, s.workspace_id, s.name, s.token_hash, s.scopes
  from public.service_accounts s
  where s.token_prefix = target_token_prefix
    and s.revoked_at is null
    and (s.expires_at is null or s.expires_at > now())
$$;

create or replace function zeus_private.touch_service_account(target_service_account_id uuid)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  affected integer;
begin
  update public.service_accounts
  set last_used_at = now()
  where id = target_service_account_id
    and revoked_at is null
    and (expires_at is null or expires_at > now());
  get diagnostics affected = row_count;
  return affected = 1;
end
$$;

create or replace function zeus_private.get_oidc_provider_for_login(target_provider_id uuid)
returns table (
  id uuid,
  organization_id uuid,
  issuer_url text,
  client_id text,
  encrypted_client_secret bytea,
  secret_nonce bytea,
  key_id text,
  scopes text[],
  group_claim text
)
language sql
security definer
set search_path = pg_catalog, public
as $$
  select p.id,
         p.organization_id,
         p.issuer_url,
         p.client_id,
         p.encrypted_client_secret,
         p.secret_nonce,
         p.key_id,
         p.scopes,
         p.group_claim
  from public.oidc_providers p
  join public.organizations o on o.id = p.organization_id
  where p.id = target_provider_id
    and p.enabled
    and o.status = 'active'
$$;

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
  active_count bigint;
begin
  if target_state_hash is null or octet_length(target_state_hash) <> 32 then
    raise exception 'invalid OIDC state hash' using errcode = '22023';
  end if;
  if target_pkce_verifier_ciphertext is null
     or octet_length(target_pkce_verifier_ciphertext) = 0
     or target_pkce_verifier_nonce is null
     or octet_length(target_pkce_verifier_nonce) = 0
     or btrim(coalesce(target_pkce_verifier_key_id, '')) = '' then
    raise exception 'invalid encrypted PKCE verifier' using errcode = '22023';
  end if;
  if target_expires_at is null
     or target_expires_at <= now()
     or target_expires_at > now() + interval '30 minutes' then
    raise exception 'invalid OIDC login transaction expiry' using errcode = '22023';
  end if;

  select p.organization_id
    into provider_organization_id
  from public.oidc_providers p
  join public.organizations o on o.id = p.organization_id
  where p.id = target_provider_id
    and p.enabled
    and o.status = 'active';
  if not found then
    raise exception 'OIDC provider is unavailable' using errcode = '22023';
  end if;

  delete from public.oidc_login_transactions t
  where t.provider_id = target_provider_id
    and t.expires_at < now() - interval '1 day';

  select count(*) into active_count
  from public.oidc_login_transactions t
  where t.provider_id = target_provider_id
    and t.consumed_at is null
    and t.expires_at > now();
  if active_count >= 10000 then
    raise exception 'too many pending OIDC login transactions' using errcode = '54000';
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
  ) values (
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

create or replace function zeus_private.jit_oidc_identity(
  target_provider_id uuid,
  target_issuer text,
  target_subject text,
  target_email text,
  target_display_name text,
  target_email_verified boolean,
  target_claims jsonb
)
returns table (
  user_id uuid,
  organization_id uuid,
  workspace_id uuid
)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  provider_row public.oidc_providers%rowtype;
  resolved_user_id uuid;
  resolved_workspace_id uuid;
  mapped_organization_role text;
begin
  if btrim(coalesce(target_issuer, '')) = ''
     or btrim(coalesce(target_subject, '')) = ''
     or btrim(coalesce(target_email, '')) = ''
     or btrim(coalesce(target_display_name, '')) = ''
     or target_claims is null
     or jsonb_typeof(target_claims) <> 'object'
     or jsonb_typeof(coalesce(target_claims -> 'groups', '[]'::jsonb)) <> 'array' then
    raise exception 'invalid OIDC identity claims' using errcode = '22023';
  end if;

  select * into provider_row
  from public.oidc_providers p
  where p.id = target_provider_id and p.enabled
  for share;
  if not found or rtrim(provider_row.issuer_url, '/') <> rtrim(target_issuer, '/') then
    raise exception 'OIDC issuer does not match provider' using errcode = '42501';
  end if;

  select i.user_id into resolved_user_id
  from public.oidc_identities i
  where i.provider_id = target_provider_id
    and i.issuer = target_issuer
    and i.subject = target_subject
  for update;

  if found then
    update public.oidc_identities
    set claims = target_claims, last_login_at = now()
    where provider_id = target_provider_id
      and issuer = target_issuer
      and subject = target_subject;
    update public.users
    set display_name = target_display_name,
        last_seen_at = now(),
        updated_at = now()
    where id = resolved_user_id and status = 'active';
    if not found then
      raise exception 'OIDC user is disabled' using errcode = '42501';
    end if;
  else
    select u.id into resolved_user_id
    from public.users u
    where lower(u.email) = lower(target_email)
    for update;

    if found and not target_email_verified then
      raise exception 'verified email is required to link an existing user' using errcode = '42501';
    end if;
    if not found then
      insert into public.users (email, display_name, last_seen_at)
      values (lower(target_email), target_display_name, now())
      returning id into resolved_user_id;
    end if;

    insert into public.oidc_identities (
      user_id, provider_id, issuer, subject, claims
    ) values (
      resolved_user_id, target_provider_id, target_issuer, target_subject, target_claims
    );
  end if;

  select m.organization_role into mapped_organization_role
  from public.oidc_group_mappings m
  where m.provider_id = target_provider_id
    and m.organization_role is not null
    and m.group_value in (
      select jsonb_array_elements_text(coalesce(target_claims -> 'groups', '[]'::jsonb))
    )
  order by case m.organization_role
    when 'owner' then 1
    when 'admin' then 2
    when 'member' then 3
    else 4
  end
  limit 1;

  insert into public.organization_memberships (
    organization_id, user_id, role, status
  ) values (
    provider_row.organization_id,
    resolved_user_id,
    coalesce(mapped_organization_role, 'member'),
    'active'
  )
  on conflict (organization_id, user_id) do update
  set status = 'active', updated_at = now();

  insert into public.workspace_memberships (
    organization_id, workspace_id, user_id, role, status
  )
  select provider_row.organization_id,
         selected.workspace_id,
         resolved_user_id,
         selected.workspace_role,
         'active'
  from (
    select distinct on (m.workspace_id)
           m.workspace_id,
           m.workspace_role
    from public.oidc_group_mappings m
    join public.workspaces w
      on w.id = m.workspace_id
     and w.organization_id = provider_row.organization_id
     and w.status = 'active'
    where m.provider_id = target_provider_id
      and m.workspace_id is not null
      and m.group_value in (
        select jsonb_array_elements_text(coalesce(target_claims -> 'groups', '[]'::jsonb))
      )
    order by m.workspace_id,
      case m.workspace_role
        when 'admin' then 1
        when 'builder' then 2
        when 'operator' then 3
        else 4
      end
  ) selected
  on conflict (workspace_id, user_id) do update
  set status = 'active', updated_at = now();

  select wm.workspace_id into resolved_workspace_id
  from public.workspace_memberships wm
  join public.workspaces w on w.id = wm.workspace_id and w.status = 'active'
  where wm.organization_id = provider_row.organization_id
    and wm.user_id = resolved_user_id
    and wm.status = 'active'
  order by wm.created_at, wm.workspace_id
  limit 1;

  return query
  select resolved_user_id, provider_row.organization_id, resolved_workspace_id;
end
$$;

create or replace function zeus_private.create_web_session(
  target_user_id uuid,
  target_organization_id uuid,
  target_workspace_id uuid,
  target_token_hash bytea,
  target_ttl_seconds integer
)
returns uuid
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  new_session_id uuid;
begin
  if target_token_hash is null or octet_length(target_token_hash) <> 32
     or target_ttl_seconds not between 300 and 2592000 then
    raise exception 'invalid web session arguments' using errcode = '22023';
  end if;
  if not exists (
    select 1 from public.organization_memberships m
    join public.users u on u.id = m.user_id and u.status = 'active'
    where m.organization_id = target_organization_id
      and m.user_id = target_user_id
      and m.status = 'active'
  ) then
    raise exception 'user is not an active organization member' using errcode = '42501';
  end if;
  if target_workspace_id is not null and not exists (
    select 1 from public.workspace_memberships m
    where m.organization_id = target_organization_id
      and m.workspace_id = target_workspace_id
      and m.user_id = target_user_id
      and m.status = 'active'
  ) then
    raise exception 'user is not an active workspace member' using errcode = '42501';
  end if;

  insert into public.web_sessions (
    user_id, organization_id, workspace_id, token_hash, expires_at
  ) values (
    target_user_id,
    target_organization_id,
    target_workspace_id,
    target_token_hash,
    now() + make_interval(secs => target_ttl_seconds)
  ) returning id into new_session_id;
  return new_session_id;
end
$$;

create or replace function zeus_private.revoke_web_session(target_token_hash bytea)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  affected integer;
begin
  update public.web_sessions
  set revoked_at = coalesce(revoked_at, now())
  where token_hash = target_token_hash;
  get diagnostics affected = row_count;
  return affected = 1;
end
$$;

create or replace function zeus_private.select_web_session_workspace(
  target_session_id uuid,
  target_user_id uuid,
  target_workspace_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  affected integer;
begin
  update public.web_sessions s
  set workspace_id = target_workspace_id, last_seen_at = now()
  where s.id = target_session_id
    and s.user_id = target_user_id
    and s.revoked_at is null
    and s.expires_at > now()
    and exists (
      select 1 from public.workspace_memberships m
      where m.organization_id = s.organization_id
        and m.workspace_id = target_workspace_id
        and m.user_id = target_user_id
        and m.status = 'active'
    );
  get diagnostics affected = row_count;
  return affected = 1;
end
$$;

create or replace function zeus_private.create_organization_for_user(
  target_user_id uuid,
  target_slug text,
  target_name text,
  target_workspace_slug text,
  target_workspace_name text
)
returns table (organization_id uuid, workspace_id uuid)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  new_organization_id uuid;
  new_workspace_id uuid;
begin
  if not exists (
    select 1 from public.users u where u.id = target_user_id and u.status = 'active'
  ) then
    raise exception 'active user is required' using errcode = '42501';
  end if;
  insert into public.organizations (slug, name)
  values (target_slug, target_name)
  returning id into new_organization_id;
  insert into public.workspaces (organization_id, slug, name)
  values (new_organization_id, target_workspace_slug, target_workspace_name)
  returning id into new_workspace_id;
  insert into public.organization_memberships (organization_id, user_id, role)
  values (new_organization_id, target_user_id, 'owner');
  insert into public.workspace_memberships (
    organization_id, workspace_id, user_id, role
  ) values (
    new_organization_id, new_workspace_id, target_user_id, 'admin'
  );
  return query select new_organization_id, new_workspace_id;
end
$$;

create policy users_organization_members on users
for select
using (
  exists (
    select 1
    from organization_memberships m
    where m.organization_id = (select zeus_private.current_organization_id())
      and m.user_id = users.id
  )
);

revoke all on function zeus_private.authenticate_web_session(bytea) from public;
revoke all on function zeus_private.lookup_service_account(text) from public;
revoke all on function zeus_private.touch_service_account(uuid) from public;
revoke all on function zeus_private.get_oidc_provider_for_login(uuid) from public;
revoke all on function zeus_private.jit_oidc_identity(uuid, text, text, text, text, boolean, jsonb) from public;
revoke all on function zeus_private.create_web_session(uuid, uuid, uuid, bytea, integer) from public;
revoke all on function zeus_private.revoke_web_session(bytea) from public;
revoke all on function zeus_private.select_web_session_workspace(uuid, uuid, uuid) from public;
revoke all on function zeus_private.create_organization_for_user(uuid, text, text, text, text) from public;

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'zeus_http') then
    execute 'grant execute on function zeus_private.authenticate_web_session(bytea) to zeus_http';
    execute 'grant execute on function zeus_private.lookup_service_account(text) to zeus_http';
    execute 'grant execute on function zeus_private.touch_service_account(uuid) to zeus_http';
    execute 'grant execute on function zeus_private.get_oidc_provider_for_login(uuid) to zeus_http';
    execute 'grant execute on function zeus_private.jit_oidc_identity(uuid, text, text, text, text, boolean, jsonb) to zeus_http';
    execute 'grant execute on function zeus_private.create_web_session(uuid, uuid, uuid, bytea, integer) to zeus_http';
    execute 'grant execute on function zeus_private.revoke_web_session(bytea) to zeus_http';
    execute 'grant execute on function zeus_private.select_web_session_workspace(uuid, uuid, uuid) to zeus_http';
    execute 'grant execute on function zeus_private.create_organization_for_user(uuid, text, text, text, text) to zeus_http';
  end if;
end
$$;
