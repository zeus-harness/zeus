-- Security-definer entry points for native identity and user-level sessions.

drop function zeus_private.authenticate_web_session(bytea);
drop function zeus_private.create_web_session(uuid, uuid, uuid, bytea, integer);
drop function zeus_private.select_web_session_workspace(uuid, uuid, uuid);

create or replace function zeus_private.has_platform_admin()
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select exists (
    select 1
    from public.platform_role_assignments p
    join public.users u on u.id = p.user_id
    where p.role = 'platform_admin'
      and p.revoked_at is null
      and u.status <> 'anonymized'
  )
$$;

create or replace function zeus_private.bootstrap_native_identity(
  target_email text,
  target_display_name text,
  target_password_hash text,
  target_organization_slug text,
  target_organization_name text,
  target_workspace_slug text,
  target_workspace_name text,
  target_session_token_hash bytea,
  target_csrf_token_hash bytea,
  target_idle_seconds integer,
  target_absolute_seconds integer
)
returns table (
  user_id uuid,
  organization_id uuid,
  workspace_id uuid,
  session_id uuid
)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  new_user_id uuid;
  new_organization_id uuid;
  new_workspace_id uuid;
  new_session_id uuid;
begin
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('zeus.native-identity.setup', 0));

  if zeus_private.has_platform_admin() then
    raise exception 'setup already completed' using errcode = '23505';
  end if;
  if target_email is null
     or target_email <> lower(btrim(target_email))
     or octet_length(target_email) <> length(target_email)
     or target_email !~ '^[!-~]+@[!-~]+$'
     or length(target_email) not between 3 and 320
     or btrim(coalesce(target_display_name, '')) = ''
     or length(target_display_name) > 120
     or target_password_hash not like '$argon2id$%'
     or target_session_token_hash is null
     or octet_length(target_session_token_hash) <> 32
     or target_csrf_token_hash is null
     or octet_length(target_csrf_token_hash) <> 32
     or target_idle_seconds not between 300 and 43200
     or target_absolute_seconds not between target_idle_seconds and 2592000 then
    raise exception 'invalid setup arguments' using errcode = '22023';
  end if;

  insert into public.users (email, display_name, status)
  values (target_email, btrim(target_display_name), 'pending_verification')
  returning id into new_user_id;

  insert into public.user_password_credentials (user_id, password_hash)
  values (new_user_id, target_password_hash);

  insert into public.platform_role_assignments (user_id, role, assigned_by)
  values (new_user_id, 'platform_admin', new_user_id);

  insert into public.organizations (slug, name)
  values (target_organization_slug, target_organization_name)
  returning id into new_organization_id;

  insert into public.workspaces (organization_id, slug, name)
  values (new_organization_id, target_workspace_slug, target_workspace_name)
  returning id into new_workspace_id;

  insert into public.organization_identity_policies (organization_id, updated_by)
  values (new_organization_id, new_user_id);

  insert into public.organization_memberships (organization_id, user_id, role)
  values (new_organization_id, new_user_id, 'owner');

  insert into public.workspace_memberships (
    organization_id, workspace_id, user_id, role
  ) values (
    new_organization_id, new_workspace_id, new_user_id, 'admin'
  );

  insert into public.web_sessions (
    user_id,
    active_organization_id,
    active_workspace_id,
    token_hash,
    csrf_token_hash,
    auth_methods,
    authenticated_at,
    idle_expires_at,
    absolute_expires_at
  ) values (
    new_user_id,
    new_organization_id,
    new_workspace_id,
    target_session_token_hash,
    target_csrf_token_hash,
    array['password'],
    now(),
    now() + make_interval(secs => target_idle_seconds),
    now() + make_interval(secs => target_absolute_seconds)
  ) returning id into new_session_id;

  insert into public.security_events (
    organization_id, workspace_id, user_id, actor_user_id, event_type, outcome
  ) values (
    new_organization_id,
    new_workspace_id,
    new_user_id,
    new_user_id,
    'setup.completed',
    'success'
  );

  return query
  select new_user_id, new_organization_id, new_workspace_id, new_session_id;
end
$$;

create or replace function zeus_private.authenticate_user_session(target_token_hash bytea)
returns table (
  session_id uuid,
  user_id uuid,
  active_organization_id uuid,
  active_workspace_id uuid,
  organization_role text,
  workspace_role text,
  email text,
  display_name text,
  email_verified_at timestamptz,
  platform_roles text[],
  auth_methods text[],
  authenticated_at timestamptz,
  mfa_satisfied_at timestamptz,
  idle_expires_at timestamptz,
  absolute_expires_at timestamptz,
  csrf_token_hash bytea
)
language sql
security definer
set search_path = pg_catalog, public
as $$
  with touched as (
    update public.web_sessions as s
    set last_seen_at = now(),
        idle_expires_at = least(now() + interval '2 hours', s.absolute_expires_at)
    where s.token_hash = target_token_hash
      and target_token_hash is not null
      and octet_length(target_token_hash) = 32
      and s.revoked_at is null
      and s.idle_expires_at > now()
      and s.absolute_expires_at > now()
    returning s.*
  )
  select t.id,
         t.user_id,
         case when om.user_id is not null then t.active_organization_id else null end,
         case when wm.user_id is not null then t.active_workspace_id else null end,
         om.role,
         wm.role,
         u.email,
         u.display_name,
         u.email_verified_at,
         coalesce((
           select array_agg(p.role order by p.role)
           from public.platform_role_assignments p
           where p.user_id = t.user_id and p.revoked_at is null
         ), '{}'::text[]),
         t.auth_methods,
         t.authenticated_at,
         t.mfa_satisfied_at,
         t.idle_expires_at,
         t.absolute_expires_at,
         t.csrf_token_hash
  from touched t
  join public.users u
    on u.id = t.user_id
   and u.status in ('pending_verification', 'active')
  left join public.organization_memberships om
    on om.organization_id = t.active_organization_id
   and om.user_id = t.user_id
   and om.status = 'active'
  left join public.workspace_memberships wm
    on wm.organization_id = t.active_organization_id
   and wm.workspace_id = t.active_workspace_id
   and wm.user_id = t.user_id
   and wm.status = 'active'
$$;

create or replace function zeus_private.create_user_session(
  target_user_id uuid,
  target_organization_id uuid,
  target_workspace_id uuid,
  target_token_hash bytea,
  target_csrf_token_hash bytea,
  target_auth_methods text[],
  target_mfa_satisfied_at timestamptz,
  target_idle_seconds integer,
  target_absolute_seconds integer
)
returns uuid
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  new_session_id uuid;
begin
  if target_token_hash is null
     or octet_length(target_token_hash) <> 32
     or target_csrf_token_hash is null
     or octet_length(target_csrf_token_hash) <> 32
     or target_auth_methods is null
     or cardinality(target_auth_methods) = 0
     or target_idle_seconds not between 300 and 43200
     or target_absolute_seconds not between target_idle_seconds and 2592000 then
    raise exception 'invalid user session arguments' using errcode = '22023';
  end if;
  if not exists (
    select 1 from public.users u
    where u.id = target_user_id and u.status in ('pending_verification', 'active')
  ) then
    raise exception 'active user is required' using errcode = '42501';
  end if;
  if target_organization_id is not null and not exists (
    select 1 from public.organization_memberships m
    join public.organizations o on o.id = m.organization_id and o.status = 'active'
    where m.organization_id = target_organization_id
      and m.user_id = target_user_id
      and m.status = 'active'
  ) then
    raise exception 'user is not an active organization member' using errcode = '42501';
  end if;
  if target_workspace_id is not null and not exists (
    select 1 from public.workspace_memberships m
    join public.workspaces w on w.id = m.workspace_id and w.status = 'active'
    where m.organization_id = target_organization_id
      and m.workspace_id = target_workspace_id
      and m.user_id = target_user_id
      and m.status = 'active'
  ) then
    raise exception 'user is not an active workspace member' using errcode = '42501';
  end if;

  insert into public.web_sessions (
    user_id,
    active_organization_id,
    active_workspace_id,
    token_hash,
    csrf_token_hash,
    auth_methods,
    authenticated_at,
    mfa_satisfied_at,
    idle_expires_at,
    absolute_expires_at
  ) values (
    target_user_id,
    target_organization_id,
    target_workspace_id,
    target_token_hash,
    target_csrf_token_hash,
    target_auth_methods,
    now(),
    target_mfa_satisfied_at,
    now() + make_interval(secs => target_idle_seconds),
    now() + make_interval(secs => target_absolute_seconds)
  ) returning id into new_session_id;
  return new_session_id;
end
$$;

create or replace function zeus_private.rotate_user_session_context(
  target_session_id uuid,
  target_user_id uuid,
  target_organization_id uuid,
  target_workspace_id uuid,
  target_token_hash bytea,
  target_csrf_token_hash bytea
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  affected integer;
begin
  if target_token_hash is null
     or octet_length(target_token_hash) <> 32
     or target_csrf_token_hash is null
     or octet_length(target_csrf_token_hash) <> 32 then
    raise exception 'invalid session rotation arguments' using errcode = '22023';
  end if;
  if target_organization_id is not null and not exists (
    select 1 from public.organization_memberships m
    join public.organizations o on o.id = m.organization_id and o.status = 'active'
    where m.organization_id = target_organization_id
      and m.user_id = target_user_id
      and m.status = 'active'
  ) then
    return false;
  end if;
  if target_workspace_id is not null and not exists (
    select 1 from public.workspace_memberships m
    join public.workspaces w on w.id = m.workspace_id and w.status = 'active'
    where m.organization_id = target_organization_id
      and m.workspace_id = target_workspace_id
      and m.user_id = target_user_id
      and m.status = 'active'
  ) then
    return false;
  end if;

  update public.web_sessions s
  set active_organization_id = target_organization_id,
      active_workspace_id = target_workspace_id,
      token_hash = target_token_hash,
      csrf_token_hash = target_csrf_token_hash,
      token_rotated_at = now(),
      last_seen_at = now()
  where s.id = target_session_id
    and s.user_id = target_user_id
    and s.revoked_at is null
    and s.idle_expires_at > now()
    and s.absolute_expires_at > now();
  get diagnostics affected = row_count;
  return affected = 1;
end
$$;

create or replace function zeus_private.rotate_user_session_token(
  target_session_id uuid,
  target_user_id uuid,
  target_token_hash bytea,
  target_csrf_token_hash bytea,
  target_mfa_satisfied_at timestamptz,
  target_auth_method text
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  affected integer;
begin
  if target_token_hash is null
     or octet_length(target_token_hash) <> 32
     or target_csrf_token_hash is null
     or octet_length(target_csrf_token_hash) <> 32
     or btrim(coalesce(target_auth_method, '')) = '' then
    raise exception 'invalid session rotation arguments' using errcode = '22023';
  end if;
  update public.web_sessions s
  set token_hash = target_token_hash,
      csrf_token_hash = target_csrf_token_hash,
      auth_methods = case
        when target_auth_method = any(s.auth_methods) then s.auth_methods
        else array_append(s.auth_methods, target_auth_method)
      end,
      mfa_satisfied_at = coalesce(target_mfa_satisfied_at, s.mfa_satisfied_at),
      token_rotated_at = now(),
      last_seen_at = now()
  where s.id = target_session_id
    and s.user_id = target_user_id
    and s.revoked_at is null
    and s.idle_expires_at > now()
    and s.absolute_expires_at > now();
  get diagnostics affected = row_count;
  return affected = 1;
end
$$;

create or replace function zeus_private.lookup_native_login(target_email text)
returns table (
  user_id uuid,
  email text,
  display_name text,
  status text,
  email_verified_at timestamptz,
  password_hash text,
  totp_enabled boolean
)
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select u.id,
         u.email,
         u.display_name,
         u.status,
         u.email_verified_at,
         p.password_hash,
         exists (
           select 1 from public.user_totp_credentials t
           where t.user_id = u.id and t.confirmed_at is not null
         )
  from public.users u
  join public.user_password_credentials p on p.user_id = u.id
  where u.email = target_email
$$;

create or replace function zeus_private.update_password_hash_after_login(
  target_user_id uuid,
  target_old_hash text,
  target_new_hash text
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  affected integer;
begin
  if target_new_hash not like '$argon2id$%' then
    raise exception 'invalid password hash' using errcode = '22023';
  end if;
  update public.user_password_credentials
  set password_hash = target_new_hash, updated_at = now()
  where user_id = target_user_id and password_hash = target_old_hash;
  get diagnostics affected = row_count;
  return affected = 1;
end
$$;

create or replace function zeus_private.create_native_registration(
  target_email text,
  target_display_name text,
  target_password_hash text,
  target_invitation_token_hash bytea
)
returns table (
  user_id uuid,
  email_verified boolean,
  organization_id uuid,
  workspace_id uuid
)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  registration_mode text;
  invitation public.organization_invitations%rowtype;
  new_user_id uuid;
  selected_workspace_id uuid;
begin
  select s.registration_mode into registration_mode
  from public.system_identity_settings s
  where s.singleton;

  if registration_mode = 'disabled' then
    raise exception 'registration is disabled' using errcode = '42501';
  end if;
  if target_email is null
     or target_email <> lower(btrim(target_email))
     or octet_length(target_email) <> length(target_email)
     or target_email !~ '^[!-~]+@[!-~]+$'
     or length(target_email) not between 3 and 320
     or btrim(coalesce(target_display_name, '')) = ''
     or length(target_display_name) > 120
     or target_password_hash not like '$argon2id$%' then
    raise exception 'invalid registration arguments' using errcode = '22023';
  end if;
  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('zeus.registration:' || target_email, 0)
  );

  if target_invitation_token_hash is not null then
    if octet_length(target_invitation_token_hash) <> 32 then
      raise exception 'invalid invitation token' using errcode = '22023';
    end if;
    select i.* into invitation
    from public.organization_invitations i
    join public.organizations o on o.id = i.organization_id and o.status = 'active'
    where i.token_hash = target_invitation_token_hash
      and i.email = target_email
      and i.status = 'pending'
      and i.expires_at > now()
    for update of i;
    if not found then
      raise exception 'invitation is unavailable' using errcode = '42501';
    end if;
  elsif registration_mode = 'invite_only' then
    raise exception 'an invitation is required' using errcode = '42501';
  end if;

  insert into public.users (
    email, display_name, status, email_verified_at
  ) values (
    target_email,
    btrim(target_display_name),
    case when invitation.id is null then 'pending_verification' else 'active' end,
    case when invitation.id is null then null else now() end
  ) returning id into new_user_id;

  insert into public.user_password_credentials (user_id, password_hash)
  values (new_user_id, target_password_hash);

  if invitation.id is not null then
    insert into public.organization_memberships (
      organization_id, user_id, role, status
    ) values (
      invitation.organization_id, new_user_id, invitation.organization_role, 'active'
    );

    insert into public.workspace_memberships (
      organization_id, workspace_id, user_id, role, status
    )
    select g.organization_id, g.workspace_id, new_user_id, g.workspace_role, 'active'
    from public.organization_invitation_workspaces g
    where g.invitation_id = invitation.id;

    select g.workspace_id into selected_workspace_id
    from public.organization_invitation_workspaces g
    where g.invitation_id = invitation.id
    order by g.workspace_id
    limit 1;

    update public.organization_invitations
    set status = 'accepted',
        accepted_by = new_user_id,
        accepted_at = now(),
        updated_at = now()
    where id = invitation.id;
  end if;

  insert into public.security_events (
    organization_id, workspace_id, user_id, actor_user_id, event_type, outcome
  ) values (
    invitation.organization_id,
    selected_workspace_id,
    new_user_id,
    new_user_id,
    'user.registered',
    'success'
  );

  return query select
    new_user_id,
    invitation.id is not null,
    invitation.organization_id,
    selected_workspace_id;
end
$$;

create or replace function zeus_private.create_email_verification_token(
  target_user_id uuid,
  target_token_hash bytea,
  target_expires_at timestamptz
)
returns uuid
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  new_token_id uuid;
  target_email text;
begin
  if target_token_hash is null
     or octet_length(target_token_hash) <> 32
     or target_expires_at <= now()
     or target_expires_at > now() + interval '24 hours' then
    raise exception 'invalid email verification token' using errcode = '22023';
  end if;
  select u.email into target_email
  from public.users u
  where u.id = target_user_id
    and u.status = 'pending_verification'
    and u.email_verified_at is null;
  if not found then
    raise exception 'user does not require email verification' using errcode = '22023';
  end if;
  update public.email_verification_tokens
  set consumed_at = coalesce(consumed_at, now())
  where user_id = target_user_id and consumed_at is null;
  insert into public.email_verification_tokens (
    user_id, token_hash, email, expires_at
  ) values (
    target_user_id, target_token_hash, target_email, target_expires_at
  ) returning id into new_token_id;
  return new_token_id;
end
$$;

create or replace function zeus_private.confirm_email_verification(target_token_hash bytea)
returns uuid
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  token_row public.email_verification_tokens%rowtype;
begin
  update public.email_verification_tokens t
  set consumed_at = now()
  where t.token_hash = target_token_hash
    and target_token_hash is not null
    and octet_length(target_token_hash) = 32
    and t.consumed_at is null
    and t.expires_at > now()
  returning t.* into token_row;
  if not found then
    return null;
  end if;
  update public.users
  set email_verified_at = now(), status = 'active', updated_at = now()
  where id = token_row.user_id
    and email = token_row.email
    and status = 'pending_verification';
  if not found then
    return null;
  end if;
  insert into public.security_events (user_id, actor_user_id, event_type, outcome)
  values (token_row.user_id, token_row.user_id, 'email.verified', 'success');
  return token_row.user_id;
end
$$;

create or replace function zeus_private.lookup_password_reset_user(target_email text)
returns uuid
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select u.id
  from public.users u
  join public.user_password_credentials p on p.user_id = u.id
  where u.email = target_email
    and u.status = 'active'
    and u.email_verified_at is not null
$$;

create or replace function zeus_private.create_password_reset_token(
  target_user_id uuid,
  target_token_hash bytea,
  target_expires_at timestamptz
)
returns uuid
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  new_token_id uuid;
begin
  if target_token_hash is null
     or octet_length(target_token_hash) <> 32
     or target_expires_at <= now()
     or target_expires_at > now() + interval '30 minutes' then
    raise exception 'invalid password reset token' using errcode = '22023';
  end if;
  if not exists (
    select 1 from public.users u
    where u.id = target_user_id and u.status = 'active' and u.email_verified_at is not null
  ) then
    return null;
  end if;
  update public.password_reset_tokens
  set consumed_at = coalesce(consumed_at, now())
  where user_id = target_user_id and consumed_at is null;
  insert into public.password_reset_tokens (user_id, token_hash, expires_at)
  values (target_user_id, target_token_hash, target_expires_at)
  returning id into new_token_id;
  return new_token_id;
end
$$;

create or replace function zeus_private.consume_password_reset_token(
  target_token_hash bytea,
  target_password_hash text
)
returns uuid
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  token_row public.password_reset_tokens%rowtype;
begin
  if target_password_hash not like '$argon2id$%' then
    raise exception 'invalid password hash' using errcode = '22023';
  end if;
  update public.password_reset_tokens t
  set consumed_at = now()
  where t.token_hash = target_token_hash
    and target_token_hash is not null
    and octet_length(target_token_hash) = 32
    and t.consumed_at is null
    and t.expires_at > now()
  returning t.* into token_row;
  if not found then
    return null;
  end if;
  update public.user_password_credentials
  set password_hash = target_password_hash,
      password_changed_at = now(),
      updated_at = now()
  where user_id = token_row.user_id;
  update public.web_sessions
  set revoked_at = coalesce(revoked_at, now())
  where user_id = token_row.user_id and revoked_at is null;
  insert into public.security_events (user_id, actor_user_id, event_type, outcome)
  values (token_row.user_id, token_row.user_id, 'password.reset', 'success');
  return token_row.user_id;
end
$$;

create or replace function zeus_private.store_pending_totp(
  target_user_id uuid,
  target_encrypted_secret bytea,
  target_secret_nonce bytea,
  target_key_id text
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  if target_encrypted_secret is null
     or octet_length(target_encrypted_secret) = 0
     or target_secret_nonce is null
     or octet_length(target_secret_nonce) = 0
     or btrim(coalesce(target_key_id, '')) = '' then
    raise exception 'invalid TOTP envelope' using errcode = '22023';
  end if;
  if not exists (
    select 1 from public.users u
    where u.id = target_user_id and u.status in ('pending_verification', 'active')
  ) then
    return false;
  end if;
  insert into public.user_totp_credentials (
    user_id, encrypted_secret, secret_nonce, key_id
  ) values (
    target_user_id, target_encrypted_secret, target_secret_nonce, target_key_id
  )
  on conflict (user_id) do update
  set encrypted_secret = excluded.encrypted_secret,
      secret_nonce = excluded.secret_nonce,
      key_id = excluded.key_id,
      last_used_counter = null,
      confirmed_at = null,
      updated_at = now();
  delete from public.user_recovery_codes where user_id = target_user_id;
  return true;
end
$$;

create or replace function zeus_private.load_totp_credential(target_user_id uuid)
returns table (
  encrypted_secret bytea,
  secret_nonce bytea,
  key_id text,
  last_used_counter bigint,
  confirmed_at timestamptz
)
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select t.encrypted_secret,
         t.secret_nonce,
         t.key_id,
         t.last_used_counter,
         t.confirmed_at
  from public.user_totp_credentials t
  where t.user_id = target_user_id
$$;

create or replace function zeus_private.confirm_totp_credential(
  target_user_id uuid,
  target_counter bigint,
  target_recovery_code_hashes bytea[]
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  affected integer;
begin
  if target_counter < 0
     or cardinality(target_recovery_code_hashes) <> 10
     or exists (
       select 1 from unnest(target_recovery_code_hashes) h
       where h is null or octet_length(h) <> 32
     ) then
    raise exception 'invalid TOTP confirmation' using errcode = '22023';
  end if;
  update public.user_totp_credentials
  set confirmed_at = now(),
      last_used_counter = target_counter,
      updated_at = now()
  where user_id = target_user_id and confirmed_at is null;
  get diagnostics affected = row_count;
  if affected <> 1 then
    return false;
  end if;
  delete from public.user_recovery_codes where user_id = target_user_id;
  insert into public.user_recovery_codes (user_id, code_hash)
  select target_user_id, h from unnest(target_recovery_code_hashes) h;
  insert into public.security_events (user_id, actor_user_id, event_type, outcome)
  values (target_user_id, target_user_id, 'mfa.totp.enabled', 'success');
  return true;
end
$$;

create or replace function zeus_private.consume_totp_counter(
  target_user_id uuid,
  target_counter bigint
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  affected integer;
begin
  update public.user_totp_credentials
  set last_used_counter = target_counter, updated_at = now()
  where user_id = target_user_id
    and confirmed_at is not null
    and target_counter >= 0
    and (last_used_counter is null or last_used_counter < target_counter);
  get diagnostics affected = row_count;
  return affected = 1;
end
$$;

create or replace function zeus_private.consume_recovery_code(
  target_user_id uuid,
  target_code_hash bytea
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  affected integer;
begin
  update public.user_recovery_codes
  set used_at = now()
  where user_id = target_user_id
    and code_hash = target_code_hash
    and target_code_hash is not null
    and octet_length(target_code_hash) = 32
    and used_at is null;
  get diagnostics affected = row_count;
  return affected = 1;
end
$$;

create or replace function zeus_private.disable_totp(target_user_id uuid)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  affected integer;
begin
  delete from public.user_recovery_codes where user_id = target_user_id;
  delete from public.user_totp_credentials where user_id = target_user_id;
  get diagnostics affected = row_count;
  if affected = 1 then
    insert into public.security_events (user_id, actor_user_id, event_type, outcome)
    values (target_user_id, target_user_id, 'mfa.totp.disabled', 'success');
  end if;
  return affected = 1;
end
$$;

create or replace function zeus_private.identity_throttle_retry_after(
  target_kind text,
  target_key_hash bytea
)
returns integer
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select greatest(
    0,
    ceil(extract(epoch from max(t.blocked_until) - now()))::integer
  )
  from public.auth_throttles t
  where t.throttle_kind = target_kind
    and t.key_hash = target_key_hash
    and t.blocked_until > now()
$$;

create or replace function zeus_private.record_identity_throttle_failure(
  target_kind text,
  target_key_hash bytea,
  target_window_seconds integer,
  target_max_attempts integer,
  target_block_seconds integer
)
returns integer
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  window_start timestamptz;
  retry_after integer;
begin
  if btrim(coalesce(target_kind, '')) = ''
     or target_key_hash is null
     or octet_length(target_key_hash) <> 32
     or target_window_seconds not between 1 and 86400
     or target_max_attempts not between 1 and 10000
     or target_block_seconds not between 1 and 86400 then
    raise exception 'invalid throttle arguments' using errcode = '22023';
  end if;
  window_start := to_timestamp(
    floor(extract(epoch from now()) / target_window_seconds) * target_window_seconds
  );
  insert into public.auth_throttles (
    throttle_kind,
    key_hash,
    window_started_at,
    window_seconds,
    attempt_count,
    blocked_until
  ) values (
    target_kind,
    target_key_hash,
    window_start,
    target_window_seconds,
    1,
    case when target_max_attempts = 1 then now() + make_interval(secs => target_block_seconds) end
  )
  on conflict (throttle_kind, key_hash, window_started_at) do update
  set attempt_count = public.auth_throttles.attempt_count + 1,
      blocked_until = case
        when public.auth_throttles.attempt_count + 1 >= target_max_attempts
          then greatest(
            coalesce(public.auth_throttles.blocked_until, '-infinity'::timestamptz),
            now() + make_interval(secs => target_block_seconds)
          )
        else public.auth_throttles.blocked_until
      end,
      updated_at = now()
  returning greatest(
    0,
    ceil(extract(epoch from blocked_until - now()))::integer
  ) into retry_after;
  return coalesce(retry_after, 0);
end
$$;

create or replace function zeus_private.clear_identity_throttle(
  target_kind text,
  target_key_hash bytea
)
returns void
language sql
security definer
set search_path = pg_catalog, public
as $$
  delete from public.auth_throttles
  where throttle_kind = target_kind and key_hash = target_key_hash
$$;

create or replace function zeus_private.queue_identity_email(
  target_message_kind text,
  target_recipient_email text,
  target_encrypted_subject bytea,
  target_subject_nonce bytea,
  target_encrypted_body bytea,
  target_body_nonce bytea,
  target_key_id text,
  target_available_at timestamptz
)
returns uuid
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  new_message_id uuid;
begin
  insert into public.email_outbox (
    message_kind,
    recipient_email,
    encrypted_subject,
    subject_nonce,
    encrypted_body,
    body_nonce,
    key_id,
    available_at
  ) values (
    target_message_kind,
    target_recipient_email,
    target_encrypted_subject,
    target_subject_nonce,
    target_encrypted_body,
    target_body_nonce,
    target_key_id,
    coalesce(target_available_at, now())
  ) returning id into new_message_id;
  perform pg_notify('zeus_identity_email', new_message_id::text);
  return new_message_id;
end
$$;

create or replace function zeus_private.claim_identity_email(
  target_node_id text,
  target_lease_seconds integer
)
returns table (
  email_id uuid,
  message_kind text,
  recipient_email text,
  encrypted_subject bytea,
  subject_nonce bytea,
  encrypted_body bytea,
  body_nonce bytea,
  key_id text,
  fence_token bigint,
  attempt_count integer
)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  if btrim(coalesce(target_node_id, '')) = ''
     or target_lease_seconds not between 10 and 600 then
    raise exception 'invalid email lease arguments' using errcode = '22023';
  end if;
  update public.email_outbox
  set status = 'queued',
      lease_owner = null,
      lease_expires_at = null,
      available_at = now(),
      updated_at = now(),
      last_error_code = coalesce(last_error_code, 'lease_expired')
  where status = 'sending' and lease_expires_at <= now();

  return query
  with selected as (
    select e.id
    from public.email_outbox e
    where e.status = 'queued' and e.available_at <= now()
    order by e.available_at, e.created_at, e.id
    for update skip locked
    limit 1
  )
  update public.email_outbox e
  set status = 'sending',
      lease_owner = target_node_id,
      lease_expires_at = now() + make_interval(secs => target_lease_seconds),
      fence_token = e.fence_token + 1,
      attempt_count = e.attempt_count + 1,
      updated_at = now()
  from selected
  where e.id = selected.id
  returning e.id,
            e.message_kind,
            e.recipient_email,
            e.encrypted_subject,
            e.subject_nonce,
            e.encrypted_body,
            e.body_nonce,
            e.key_id,
            e.fence_token,
            e.attempt_count;
end
$$;

create or replace function zeus_private.finish_identity_email(
  target_email_id uuid,
  target_node_id text,
  target_fence_token bigint,
  target_status text,
  target_provider_message_id text,
  target_error_code text,
  target_retry_seconds integer
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  affected integer;
begin
  if target_status not in ('sent', 'failed', 'queued')
     or target_retry_seconds not between 0 and 86400 then
    raise exception 'invalid email completion arguments' using errcode = '22023';
  end if;
  update public.email_outbox
  set status = target_status,
      lease_owner = null,
      lease_expires_at = null,
      provider_message_id = case when target_status = 'sent' then target_provider_message_id else provider_message_id end,
      last_error_code = case when target_status = 'sent' then null else target_error_code end,
      available_at = case when target_status = 'queued'
        then now() + make_interval(secs => target_retry_seconds)
        else available_at
      end,
      sent_at = case when target_status = 'sent' then now() else sent_at end,
      updated_at = now()
  where id = target_email_id
    and status = 'sending'
    and lease_owner = target_node_id
    and fence_token = target_fence_token;
  get diagnostics affected = row_count;
  return affected = 1;
end
$$;

create or replace function zeus_private.revoke_user_session(
  target_session_id uuid,
  target_user_id uuid
)
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
  where id = target_session_id and user_id = target_user_id;
  get diagnostics affected = row_count;
  return affected = 1;
end
$$;

create or replace function zeus_private.guard_last_organization_owner()
returns trigger
language plpgsql
set search_path = pg_catalog, public
as $$
begin
  if old.role = 'owner'
     and old.status = 'active'
     and (
       tg_op = 'DELETE'
       or new.role <> 'owner'
       or new.status <> 'active'
     )
     and not exists (
       select 1
       from public.organization_memberships m
       where m.organization_id = old.organization_id
         and m.user_id <> old.user_id
         and m.role = 'owner'
         and m.status = 'active'
     ) then
    raise exception 'organization must keep an active owner' using errcode = '23514';
  end if;
  if tg_op = 'DELETE' then
    return old;
  end if;
  return new;
end
$$;

create trigger organization_memberships_last_owner_guard
before update or delete on organization_memberships
for each row execute function zeus_private.guard_last_organization_owner();

create or replace function zeus_private.guard_owner_user_status()
returns trigger
language plpgsql
set search_path = pg_catalog, public
as $$
begin
  if old.status in ('pending_verification', 'active')
     and new.status in ('disabled', 'anonymization_pending', 'anonymized')
     and exists (
       select 1
       from public.organization_memberships owned
       where owned.user_id = old.id
         and owned.role = 'owner'
         and owned.status = 'active'
         and not exists (
           select 1
           from public.organization_memberships replacement
           where replacement.organization_id = owned.organization_id
             and replacement.user_id <> old.id
             and replacement.role = 'owner'
             and replacement.status = 'active'
         )
     ) then
    raise exception 'last organization owner cannot be disabled' using errcode = '23514';
  end if;
  return new;
end
$$;

create trigger users_owner_status_guard
before update of status on users
for each row execute function zeus_private.guard_owner_user_status();

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
    select 1
    from public.users u
    cross join public.system_identity_settings s
    where u.id = target_user_id
      and u.status = 'active'
      and u.email_verified_at is not null
      and s.singleton
      and s.registration_mode = 'open'
  ) then
    raise exception 'verified user cannot create an organization under the current policy'
      using errcode = '42501';
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
  insert into public.organization_identity_policies (organization_id, updated_by)
  values (new_organization_id, target_user_id);
  return query select new_organization_id, new_workspace_id;
end
$$;

revoke all on function zeus_private.has_platform_admin() from public;
revoke all on function zeus_private.bootstrap_native_identity(text, text, text, text, text, text, text, bytea, bytea, integer, integer) from public;
revoke all on function zeus_private.authenticate_user_session(bytea) from public;
revoke all on function zeus_private.create_user_session(uuid, uuid, uuid, bytea, bytea, text[], timestamptz, integer, integer) from public;
revoke all on function zeus_private.rotate_user_session_context(uuid, uuid, uuid, uuid, bytea, bytea) from public;
revoke all on function zeus_private.rotate_user_session_token(uuid, uuid, bytea, bytea, timestamptz, text) from public;
revoke all on function zeus_private.lookup_native_login(text) from public;
revoke all on function zeus_private.update_password_hash_after_login(uuid, text, text) from public;
revoke all on function zeus_private.create_native_registration(text, text, text, bytea) from public;
revoke all on function zeus_private.create_email_verification_token(uuid, bytea, timestamptz) from public;
revoke all on function zeus_private.confirm_email_verification(bytea) from public;
revoke all on function zeus_private.lookup_password_reset_user(text) from public;
revoke all on function zeus_private.create_password_reset_token(uuid, bytea, timestamptz) from public;
revoke all on function zeus_private.consume_password_reset_token(bytea, text) from public;
revoke all on function zeus_private.store_pending_totp(uuid, bytea, bytea, text) from public;
revoke all on function zeus_private.load_totp_credential(uuid) from public;
revoke all on function zeus_private.confirm_totp_credential(uuid, bigint, bytea[]) from public;
revoke all on function zeus_private.consume_totp_counter(uuid, bigint) from public;
revoke all on function zeus_private.consume_recovery_code(uuid, bytea) from public;
revoke all on function zeus_private.disable_totp(uuid) from public;
revoke all on function zeus_private.identity_throttle_retry_after(text, bytea) from public;
revoke all on function zeus_private.record_identity_throttle_failure(text, bytea, integer, integer, integer) from public;
revoke all on function zeus_private.clear_identity_throttle(text, bytea) from public;
revoke all on function zeus_private.queue_identity_email(text, text, bytea, bytea, bytea, bytea, text, timestamptz) from public;
revoke all on function zeus_private.claim_identity_email(text, integer) from public;
revoke all on function zeus_private.finish_identity_email(uuid, text, bigint, text, text, text, integer) from public;
revoke all on function zeus_private.revoke_user_session(uuid, uuid) from public;
revoke all on function zeus_private.guard_last_organization_owner() from public;
revoke all on function zeus_private.guard_owner_user_status() from public;
revoke all on function zeus_private.create_organization_for_user(uuid, text, text, text, text) from public;

grant execute on function zeus_private.has_platform_admin() to zeus_http;
grant execute on function zeus_private.bootstrap_native_identity(text, text, text, text, text, text, text, bytea, bytea, integer, integer) to zeus_http;
grant execute on function zeus_private.authenticate_user_session(bytea) to zeus_http;
grant execute on function zeus_private.create_user_session(uuid, uuid, uuid, bytea, bytea, text[], timestamptz, integer, integer) to zeus_http;
grant execute on function zeus_private.rotate_user_session_context(uuid, uuid, uuid, uuid, bytea, bytea) to zeus_http;
grant execute on function zeus_private.rotate_user_session_token(uuid, uuid, bytea, bytea, timestamptz, text) to zeus_http;
grant execute on function zeus_private.lookup_native_login(text) to zeus_http;
grant execute on function zeus_private.update_password_hash_after_login(uuid, text, text) to zeus_http;
grant execute on function zeus_private.create_native_registration(text, text, text, bytea) to zeus_http;
grant execute on function zeus_private.create_email_verification_token(uuid, bytea, timestamptz) to zeus_http;
grant execute on function zeus_private.confirm_email_verification(bytea) to zeus_http;
grant execute on function zeus_private.lookup_password_reset_user(text) to zeus_http;
grant execute on function zeus_private.create_password_reset_token(uuid, bytea, timestamptz) to zeus_http;
grant execute on function zeus_private.consume_password_reset_token(bytea, text) to zeus_http;
grant execute on function zeus_private.store_pending_totp(uuid, bytea, bytea, text) to zeus_http;
grant execute on function zeus_private.load_totp_credential(uuid) to zeus_http;
grant execute on function zeus_private.confirm_totp_credential(uuid, bigint, bytea[]) to zeus_http;
grant execute on function zeus_private.consume_totp_counter(uuid, bigint) to zeus_http;
grant execute on function zeus_private.consume_recovery_code(uuid, bytea) to zeus_http;
grant execute on function zeus_private.disable_totp(uuid) to zeus_http;
grant execute on function zeus_private.identity_throttle_retry_after(text, bytea) to zeus_http;
grant execute on function zeus_private.record_identity_throttle_failure(text, bytea, integer, integer, integer) to zeus_http;
grant execute on function zeus_private.clear_identity_throttle(text, bytea) to zeus_http;
grant execute on function zeus_private.queue_identity_email(text, text, bytea, bytea, bytea, bytea, text, timestamptz) to zeus_http;
grant execute on function zeus_private.claim_identity_email(text, integer) to zeus_http;
grant execute on function zeus_private.finish_identity_email(uuid, text, bigint, text, text, text, integer) to zeus_http;
grant execute on function zeus_private.revoke_web_session(bytea) to zeus_http;
grant execute on function zeus_private.revoke_user_session(uuid, uuid) to zeus_http;
grant execute on function zeus_private.create_organization_for_user(uuid, text, text, text, text) to zeus_http;
