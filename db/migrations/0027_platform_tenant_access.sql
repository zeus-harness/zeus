-- Platform Organization lifecycle and bounded tenant support access.
--
-- Platform operations stay behind SECURITY DEFINER functions. Tenant support
-- requests continue to use zeus_http, tenant RLS, and the real platform actor.

create or replace function zeus_private.current_session_id()
returns uuid
language sql
stable
set search_path = ''
as $$
  select nullif(current_setting('zeus.session_id', true), '')::uuid
$$;

create or replace function zeus_private.current_platform_tenant_access_grant_id()
returns uuid
language sql
stable
set search_path = ''
as $$
  select nullif(current_setting('zeus.tenant_access_grant_id', true), '')::uuid
$$;

create table platform_tenant_access_grants (
  id uuid primary key default uuidv7(),
  platform_user_id uuid not null references users(id),
  web_session_id uuid not null references web_sessions(id),
  organization_id uuid not null references organizations(id),
  reason text not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  revoked_at timestamptz,
  revoked_by uuid references users(id),
  revoked_reason text,
  check (reason = btrim(reason) and length(reason) between 10 and 500),
  check (expires_at > created_at and expires_at <= created_at + interval '60 minutes'),
  check ((revoked_at is null) = (revoked_by is null)),
  check (revoked_reason is null or (revoked_reason = btrim(revoked_reason) and length(revoked_reason) between 1 and 500))
);

create unique index platform_tenant_access_grants_one_active_session
  on platform_tenant_access_grants (web_session_id)
  where revoked_at is null;
create index platform_tenant_access_grants_user_idx
  on platform_tenant_access_grants (platform_user_id, created_at desc, id desc);
create index platform_tenant_access_grants_organization_idx
  on platform_tenant_access_grants (organization_id, created_at desc, id desc);
create index platform_tenant_access_grants_expiry_idx
  on platform_tenant_access_grants (expires_at, id)
  where revoked_at is null;

create table platform_http_idempotency_keys (
  id uuid primary key default uuidv7(),
  actor_user_id uuid not null references users(id),
  operation text not null,
  idempotency_key text not null,
  request_hash bytea not null,
  organization_id uuid references organizations(id),
  workspace_id uuid references workspaces(id),
  invitation_id uuid references organization_invitations(id),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '24 hours'),
  unique (actor_user_id, operation, idempotency_key),
  check (operation = btrim(operation) and length(operation) between 1 and 120),
  check (idempotency_key = btrim(idempotency_key) and length(idempotency_key) between 1 and 255),
  check (octet_length(request_hash) = 32),
  check (expires_at > created_at),
  check (
    (organization_id is null and workspace_id is null and invitation_id is null)
    or (organization_id is not null and workspace_id is not null and invitation_id is not null)
  )
);

create index platform_http_idempotency_expiry_idx
  on platform_http_idempotency_keys (expires_at, id);

alter table platform_tenant_access_grants enable row level security;
alter table platform_tenant_access_grants force row level security;
alter table platform_http_idempotency_keys enable row level security;
alter table platform_http_idempotency_keys force row level security;

revoke all on table platform_tenant_access_grants, platform_http_idempotency_keys from public;
revoke all on table platform_tenant_access_grants, platform_http_idempotency_keys
  from zeus_http, zeus_runtime;

create or replace function zeus_private.platform_session_is_admin(
  target_user_id uuid,
  target_session_id uuid,
  require_recent_mfa boolean
)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select exists (
    select 1
    from public.web_sessions s
    join public.users u
      on u.id = s.user_id
     and u.status = 'active'
     and u.email_verified_at is not null
    join public.platform_role_assignments p
      on p.user_id = u.id
     and p.role = 'platform_admin'
     and p.revoked_at is null
    join public.user_totp_credentials t
      on t.user_id = u.id
     and t.confirmed_at is not null
    where s.id = target_session_id
      and s.user_id = target_user_id
      and s.revoked_at is null
      and s.idle_expires_at > now()
      and s.absolute_expires_at > now()
      and s.mfa_satisfied_at is not null
      and (not require_recent_mfa or s.mfa_satisfied_at >= now() - interval '10 minutes')
  )
$$;

create or replace function zeus_private.platform_tenant_access_is_valid(
  target_grant_id uuid,
  target_user_id uuid,
  target_session_id uuid,
  target_organization_id uuid
)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select exists (
    select 1
    from public.platform_tenant_access_grants g
    join public.organizations o
      on o.id = g.organization_id
     and o.status in ('active', 'suspended')
    where g.id = target_grant_id
      and g.platform_user_id = target_user_id
      and g.web_session_id = target_session_id
      and g.organization_id = target_organization_id
      and g.revoked_at is null
      and g.expires_at > now()
      and zeus_private.platform_session_is_admin(
        target_user_id, target_session_id, false
      )
  )
$$;

create or replace function zeus_private.current_platform_tenant_access_is_valid(
  target_organization_id uuid
)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select zeus_private.platform_tenant_access_is_valid(
    zeus_private.current_platform_tenant_access_grant_id(),
    zeus_private.current_user_id(),
    zeus_private.current_session_id(),
    target_organization_id
  )
$$;

create or replace function zeus_private.validate_platform_tenant_access_grant(
  target_grant_id uuid,
  target_user_id uuid,
  target_session_id uuid
)
returns table (
  grant_id uuid,
  organization_id uuid,
  organization_status text,
  reason text,
  expires_at timestamptz
)
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select g.id, g.organization_id, o.status, g.reason, g.expires_at
  from public.platform_tenant_access_grants g
  join public.organizations o on o.id = g.organization_id
  where g.id = target_grant_id
    and zeus_private.platform_tenant_access_is_valid(
      g.id, target_user_id, target_session_id, g.organization_id
    )
$$;

create or replace function zeus_private.create_platform_tenant_access_grant(
  target_user_id uuid,
  target_session_id uuid,
  target_organization_id uuid,
  target_reason text,
  target_duration_minutes integer,
  target_session_token_hash bytea,
  target_csrf_token_hash bytea
)
returns table (
  grant_id uuid,
  organization_id uuid,
  organization_name text,
  organization_status text,
  reason text,
  expires_at timestamptz
)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  new_grant_id uuid;
  new_expires_at timestamptz;
  target_organization_name text;
  target_organization_status text;
begin
  if target_reason is null
     or target_reason <> btrim(target_reason)
     or length(target_reason) not between 10 and 500
     or target_duration_minutes not between 1 and 60
     or target_session_token_hash is null
     or octet_length(target_session_token_hash) <> 32
     or target_csrf_token_hash is null
     or octet_length(target_csrf_token_hash) <> 32 then
    raise exception 'invalid platform tenant access grant arguments' using errcode = '22023';
  end if;
  if not exists (
    select 1
    from public.web_sessions s
    join public.users u
      on u.id = s.user_id
     and u.status = 'active'
     and u.email_verified_at is not null
    join public.platform_role_assignments p
      on p.user_id = u.id
     and p.role = 'platform_admin'
     and p.revoked_at is null
    join public.user_totp_credentials t
      on t.user_id = u.id
     and t.confirmed_at is not null
    where s.id = target_session_id
      and s.user_id = target_user_id
      and s.revoked_at is null
      and s.idle_expires_at > now()
      and s.absolute_expires_at > now()
  ) then
    raise exception 'platform administrator session required' using errcode = '42501';
  end if;

  select o.name, o.status
  into target_organization_name, target_organization_status
  from public.organizations o
  where o.id = target_organization_id
    and o.status in ('active', 'suspended')
  for update;
  if not found then
    raise exception 'organization is unavailable for support access' using errcode = 'ZX003';
  end if;

  update public.platform_tenant_access_grants
  set revoked_at = coalesce(revoked_at, now()),
      revoked_by = coalesce(revoked_by, target_user_id),
      revoked_reason = coalesce(revoked_reason, 'superseded')
  where web_session_id = target_session_id and revoked_at is null;

  select least(
    now() + make_interval(mins => target_duration_minutes),
    s.idle_expires_at,
    s.absolute_expires_at
  ) into new_expires_at
  from public.web_sessions s
  where s.id = target_session_id and s.user_id = target_user_id
  for update;
  if new_expires_at is null or new_expires_at <= now() then
    raise exception 'platform administrator session expired' using errcode = '42501';
  end if;

  update public.web_sessions
  set token_hash = target_session_token_hash,
      csrf_token_hash = target_csrf_token_hash,
      auth_methods = (
        select array_agg(distinct method order by method)
        from unnest(auth_methods || array['password', 'totp']) as method
      ),
      authenticated_at = now(),
      mfa_satisfied_at = now(),
      token_rotated_at = now(),
      last_seen_at = now()
  where id = target_session_id
    and user_id = target_user_id
    and revoked_at is null
    and idle_expires_at > now()
    and absolute_expires_at > now();
  if not found then
    raise exception 'platform administrator session expired' using errcode = '42501';
  end if;

  insert into public.platform_tenant_access_grants (
    platform_user_id, web_session_id, organization_id, reason, expires_at
  ) values (
    target_user_id, target_session_id, target_organization_id,
    target_reason, new_expires_at
  ) returning id into new_grant_id;

  insert into public.audit_events (
    organization_id, actor_kind, actor_id, action, target_type, target_id, metadata
  ) values (
    target_organization_id, 'user', target_user_id,
    'platform.tenant_access_granted', 'organization', target_organization_id,
    jsonb_build_object('grant_id', new_grant_id, 'reason', target_reason,
                       'expires_at', new_expires_at)
  );
  insert into public.security_events (
    organization_id, user_id, actor_user_id, event_type, outcome, metadata
  ) values (
    target_organization_id, target_user_id, target_user_id,
    'platform.tenant_access_granted', 'success',
    jsonb_build_object('grant_id', new_grant_id, 'reason', target_reason,
                       'expires_at', new_expires_at)
  );

  return query select new_grant_id, target_organization_id,
    target_organization_name, target_organization_status,
    target_reason, new_expires_at;
end
$$;

create or replace function zeus_private.revoke_platform_tenant_access_grant(
  target_user_id uuid,
  target_session_id uuid,
  target_grant_id uuid,
  target_reason text
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  grant_organization_id uuid;
  grant_reason text;
begin
  if not zeus_private.platform_session_is_admin(
    target_user_id, target_session_id, false
  ) then
    return false;
  end if;
  update public.platform_tenant_access_grants
  set revoked_at = now(), revoked_by = target_user_id,
      revoked_reason = coalesce(nullif(btrim(target_reason), ''), 'revoked by platform administrator')
  where id = target_grant_id
    and platform_user_id = target_user_id
    and web_session_id = target_session_id
    and revoked_at is null
  returning organization_id, reason into grant_organization_id, grant_reason;
  if not found then
    return false;
  end if;
  insert into public.audit_events (
    organization_id, actor_kind, actor_id, action, target_type, target_id, metadata
  ) values (
    grant_organization_id, 'user', target_user_id,
    'platform.tenant_access_revoked', 'organization', grant_organization_id,
    jsonb_build_object('grant_id', target_grant_id, 'reason', grant_reason)
  );
  insert into public.security_events (
    organization_id, user_id, actor_user_id, event_type, outcome, metadata
  ) values (
    grant_organization_id, target_user_id, target_user_id,
    'platform.tenant_access_revoked', 'success',
    jsonb_build_object('grant_id', target_grant_id, 'reason', grant_reason)
  );
  return true;
end
$$;

create or replace function zeus_private.record_platform_support_operation(
  target_user_id uuid,
  target_session_id uuid,
  target_grant_id uuid,
  target_organization_id uuid,
  target_workspace_id uuid,
  target_action text,
  target_type text,
  target_id uuid,
  target_reason text
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  if not zeus_private.platform_tenant_access_is_valid(
    target_grant_id, target_user_id, target_session_id, target_organization_id
  ) then
    return false;
  end if;
  insert into public.security_events (
    organization_id, workspace_id, user_id, actor_user_id,
    event_type, outcome, metadata
  ) values (
    target_organization_id, target_workspace_id, target_user_id, target_user_id,
    'platform.support_operation', 'success',
    jsonb_build_object(
      'grant_id', target_grant_id,
      'reason', target_reason,
      'action', target_action,
      'target_type', target_type,
      'target_id', target_id
    )
  );
  return true;
end
$$;

create or replace function zeus_private.list_platform_organizations(
  target_user_id uuid,
  target_session_id uuid
)
returns table (
  id uuid,
  slug text,
  name text,
  status text,
  revision bigint,
  identity_settings_mode text,
  governance_revision bigint,
  workspace_count bigint,
  active_owner_count bigint,
  pending_owner_invitation_id uuid,
  pending_owner_email text,
  created_at timestamptz,
  updated_at timestamptz,
  archived_at timestamptz
)
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select o.id, o.slug, o.name, o.status, o.revision,
         g.identity_settings_mode, g.revision,
         (select count(*) from public.workspaces w where w.organization_id = o.id),
         (select count(*) from public.organization_memberships m
          where m.organization_id = o.id and m.role = 'owner' and m.status = 'active'),
         pending.id, pending.email,
         o.created_at, o.updated_at, o.archived_at
  from public.organizations o
  join public.organization_governance g on g.organization_id = o.id
  left join lateral (
    select i.id, i.email
    from public.organization_invitations i
    where i.organization_id = o.id
      and i.invitation_kind = 'provisioning_owner'
      and i.status = 'pending'
      and i.expires_at > now()
    order by i.created_at desc, i.id desc
    limit 1
  ) pending on true
  where zeus_private.platform_session_is_admin(
    target_user_id, target_session_id, false
  )
  order by o.created_at desc, o.id desc
  limit 500
$$;

create or replace function zeus_private.load_platform_organization(
  target_user_id uuid,
  target_session_id uuid,
  target_organization_id uuid
)
returns table (
  id uuid,
  slug text,
  name text,
  status text,
  revision bigint,
  identity_settings_mode text,
  governance_revision bigint,
  workspace_count bigint,
  active_owner_count bigint,
  pending_owner_invitation_id uuid,
  pending_owner_email text,
  created_at timestamptz,
  updated_at timestamptz,
  archived_at timestamptz
)
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select listed.*
  from zeus_private.list_platform_organizations(target_user_id, target_session_id) listed
  where listed.id = target_organization_id
$$;

create or replace function zeus_private.create_platform_organization(
  target_user_id uuid,
  target_session_id uuid,
  target_idempotency_key text,
  target_request_hash bytea,
  target_slug text,
  target_name text,
  target_workspace_slug text,
  target_workspace_name text,
  target_owner_email text,
  target_invitation_token_hash bytea,
  target_identity_settings_mode text
)
returns table (
  organization_id uuid,
  organization_slug text,
  organization_name text,
  organization_status text,
  organization_revision bigint,
  identity_settings_mode text,
  workspace_id uuid,
  workspace_slug text,
  workspace_name text,
  invitation_id uuid,
  owner_email text,
  invitation_expires_at timestamptz,
  replayed boolean
)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  key_row public.platform_http_idempotency_keys%rowtype;
  new_organization_id uuid;
  new_workspace_id uuid;
  new_invitation_id uuid;
  new_invitation_expires_at timestamptz;
  inserted_key_id uuid;
begin
  if not zeus_private.platform_session_is_admin(
    target_user_id, target_session_id, true
  ) then
    raise exception 'recent platform administrator MFA required' using errcode = '42501';
  end if;
  if target_idempotency_key is null
     or target_idempotency_key <> btrim(target_idempotency_key)
     or length(target_idempotency_key) not between 1 and 255
     or target_request_hash is null
     or octet_length(target_request_hash) <> 32
     or target_owner_email <> lower(btrim(target_owner_email))
     or octet_length(target_owner_email) <> length(target_owner_email)
     or target_owner_email !~ '^[!-~]+@[!-~]+$'
     or target_identity_settings_mode not in ('self_service', 'platform_managed')
     or target_invitation_token_hash is null
     or octet_length(target_invitation_token_hash) <> 32 then
    raise exception 'invalid platform organization arguments' using errcode = '22023';
  end if;

  insert into public.platform_http_idempotency_keys (
    actor_user_id, operation, idempotency_key, request_hash
  ) values (
    target_user_id, 'platform.organization.create',
    target_idempotency_key, target_request_hash
  ) on conflict (actor_user_id, operation, idempotency_key) do nothing
  returning id into inserted_key_id;

  select * into key_row
  from public.platform_http_idempotency_keys k
  where k.actor_user_id = target_user_id
    and k.operation = 'platform.organization.create'
    and k.idempotency_key = target_idempotency_key
  for update;
  if key_row.request_hash <> target_request_hash then
    raise exception 'platform idempotency key reused with another request' using errcode = 'ZX001';
  end if;
  if key_row.organization_id is not null then
    return query
    select o.id, o.slug, o.name, o.status, o.revision,
           g.identity_settings_mode,
           w.id, w.slug, w.name,
           i.id, i.email, i.expires_at, true
    from public.organizations o
    join public.organization_governance g on g.organization_id = o.id
    join public.workspaces w on w.id = key_row.workspace_id
    join public.organization_invitations i on i.id = key_row.invitation_id
    where o.id = key_row.organization_id;
    return;
  end if;

  insert into public.organizations (slug, name, status)
  values (target_slug, target_name, 'provisioning')
  returning id into new_organization_id;
  insert into public.organization_governance (
    organization_id, identity_settings_mode, updated_by
  ) values (
    new_organization_id, target_identity_settings_mode, target_user_id
  );
  insert into public.organization_identity_policies (organization_id, updated_by)
  values (new_organization_id, target_user_id);
  insert into public.workspaces (organization_id, slug, name)
  values (new_organization_id, target_workspace_slug, target_workspace_name)
  returning id into new_workspace_id;
  new_invitation_expires_at := now() + interval '7 days';
  insert into public.organization_invitations (
    organization_id, invited_by, email, organization_role,
    invitation_kind, token_hash, expires_at
  ) values (
    new_organization_id, target_user_id, target_owner_email, 'owner',
    'provisioning_owner', target_invitation_token_hash, new_invitation_expires_at
  ) returning id into new_invitation_id;
  insert into public.organization_invitation_workspaces (
    invitation_id, organization_id, workspace_id, workspace_role
  ) values (
    new_invitation_id, new_organization_id, new_workspace_id, 'owner'
  );
  update public.platform_http_idempotency_keys
  set organization_id = new_organization_id,
      workspace_id = new_workspace_id,
      invitation_id = new_invitation_id
  where id = key_row.id;

  insert into public.audit_events (
    organization_id, actor_kind, actor_id, action, target_type, target_id, metadata
  ) values (
    new_organization_id, 'user', target_user_id,
    'platform.organization_created', 'organization', new_organization_id,
    jsonb_build_object('workspace_id', new_workspace_id,
                       'invitation_id', new_invitation_id,
                       'identity_settings_mode', target_identity_settings_mode)
  );
  insert into public.security_events (
    organization_id, actor_user_id, event_type, outcome, metadata
  ) values (
    new_organization_id, target_user_id,
    'platform.organization_created', 'success',
    jsonb_build_object('workspace_id', new_workspace_id,
                       'invitation_id', new_invitation_id,
                       'identity_settings_mode', target_identity_settings_mode)
  );

  return query select new_organization_id, target_slug, target_name,
    'provisioning'::text, 1::bigint, target_identity_settings_mode,
    new_workspace_id, target_workspace_slug, target_workspace_name,
    new_invitation_id, target_owner_email, new_invitation_expires_at, false;
end
$$;

create or replace function zeus_private.update_platform_organization(
  target_user_id uuid,
  target_session_id uuid,
  target_organization_id uuid,
  target_revision bigint,
  target_name text,
  target_slug text,
  target_identity_settings_mode text
)
returns table (
  id uuid,
  slug text,
  name text,
  status text,
  revision bigint,
  identity_settings_mode text,
  governance_revision bigint,
  created_at timestamptz,
  updated_at timestamptz,
  archived_at timestamptz
)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  current_organization public.organizations%rowtype;
begin
  if not zeus_private.platform_session_is_admin(
    target_user_id, target_session_id, true
  ) then
    raise exception 'recent platform administrator MFA required' using errcode = '42501';
  end if;
  if target_revision <= 0
     or (target_identity_settings_mode is not null
         and target_identity_settings_mode not in ('self_service', 'platform_managed')) then
    raise exception 'invalid platform organization update' using errcode = '22023';
  end if;
  select * into current_organization
  from public.organizations o
  where o.id = target_organization_id
  for update;
  if not found then
    raise exception 'organization not found' using errcode = 'P0002';
  end if;
  if current_organization.revision <> target_revision then
    raise exception 'organization revision mismatch' using errcode = 'ZX002';
  end if;
  if current_organization.status = 'archived' then
    raise exception 'restore archived organization before editing' using errcode = 'ZX003';
  end if;

  update public.organizations o
  set name = coalesce(target_name, o.name),
      slug = coalesce(target_slug, o.slug),
      revision = o.revision + 1,
      updated_at = now()
  where o.id = target_organization_id;
  if target_identity_settings_mode is not null then
    update public.organization_governance g
    set identity_settings_mode = target_identity_settings_mode,
        revision = g.revision + 1,
        updated_by = target_user_id,
        updated_at = now()
    where g.organization_id = target_organization_id;
  end if;
  insert into public.audit_events (
    organization_id, actor_kind, actor_id, action, target_type, target_id, metadata
  ) values (
    target_organization_id, 'user', target_user_id,
    'platform.organization_updated', 'organization', target_organization_id,
    jsonb_build_object('identity_settings_mode', target_identity_settings_mode)
  );
  insert into public.security_events (
    organization_id, actor_user_id, event_type, outcome, metadata
  ) values (
    target_organization_id, target_user_id,
    'platform.organization_updated', 'success',
    jsonb_build_object('identity_settings_mode', target_identity_settings_mode)
  );
  return query
  select o.id, o.slug, o.name, o.status, o.revision,
         g.identity_settings_mode, g.revision,
         o.created_at, o.updated_at, o.archived_at
  from public.organizations o
  join public.organization_governance g on g.organization_id = o.id
  where o.id = target_organization_id;
end
$$;

create or replace function zeus_private.transition_platform_organization(
  target_user_id uuid,
  target_session_id uuid,
  target_organization_id uuid,
  target_revision bigint,
  target_action text
)
returns table (
  id uuid,
  slug text,
  name text,
  status text,
  revision bigint,
  identity_settings_mode text,
  governance_revision bigint,
  created_at timestamptz,
  updated_at timestamptz,
  archived_at timestamptz
)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  current_organization public.organizations%rowtype;
  next_status text;
begin
  if not zeus_private.platform_session_is_admin(
    target_user_id, target_session_id, true
  ) then
    raise exception 'recent platform administrator MFA required' using errcode = '42501';
  end if;
  select * into current_organization
  from public.organizations o
  where o.id = target_organization_id
  for update;
  if not found then
    raise exception 'organization not found' using errcode = 'P0002';
  end if;
  if current_organization.revision <> target_revision then
    raise exception 'organization revision mismatch' using errcode = 'ZX002';
  end if;
  next_status := case
    when target_action = 'suspend' and current_organization.status = 'active' then 'suspended'
    when target_action = 'resume' and current_organization.status = 'suspended' then 'active'
    when target_action = 'archive'
      and current_organization.status in ('provisioning', 'active', 'suspended') then 'archived'
    when target_action = 'restore' and current_organization.status = 'archived' then 'suspended'
    else null
  end;
  if next_status is null then
    raise exception 'invalid organization state transition' using errcode = 'ZX003';
  end if;

  update public.organizations o
  set status = next_status,
      revision = o.revision + 1,
      updated_at = now(),
      archived_at = case
        when next_status = 'archived' then coalesce(o.archived_at, now())
        when target_action = 'restore' then null
        else o.archived_at
      end
  where o.id = target_organization_id;
  if next_status in ('suspended', 'archived') then
    update public.runs r
    set cancel_requested_at = coalesce(r.cancel_requested_at, now()),
        updated_at = now()
    where r.organization_id = target_organization_id
      and r.status in ('queued', 'running', 'waiting_approval', 'waiting_child');
  end if;
  update public.platform_tenant_access_grants
  set revoked_at = now(), revoked_by = target_user_id,
      revoked_reason = 'organization archived'
  where organization_id = target_organization_id
    and revoked_at is null
    and next_status = 'archived';

  insert into public.audit_events (
    organization_id, actor_kind, actor_id, action, target_type, target_id, metadata
  ) values (
    target_organization_id, 'user', target_user_id,
    'platform.organization_' || target_action,
    'organization', target_organization_id,
    jsonb_build_object('previous_status', current_organization.status,
                       'new_status', next_status)
  );
  insert into public.security_events (
    organization_id, actor_user_id, event_type, outcome, metadata
  ) values (
    target_organization_id, target_user_id,
    'platform.organization_' || target_action, 'success',
    jsonb_build_object('previous_status', current_organization.status,
                       'new_status', next_status)
  );
  return query
  select o.id, o.slug, o.name, o.status, o.revision,
         g.identity_settings_mode, g.revision,
         o.created_at, o.updated_at, o.archived_at
  from public.organizations o
  join public.organization_governance g on g.organization_id = o.id
  where o.id = target_organization_id;
end
$$;

create or replace function zeus_private.rotate_platform_owner_invitation(
  target_user_id uuid,
  target_session_id uuid,
  target_organization_id uuid,
  target_revision bigint,
  target_mode text,
  target_replacement_email text,
  target_token_hash bytea
)
returns table (
  organization_id uuid,
  organization_name text,
  organization_revision bigint,
  invitation_id uuid,
  owner_email text,
  invitation_expires_at timestamptz
)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  current_organization public.organizations%rowtype;
  current_invitation public.organization_invitations%rowtype;
  initial_workspace_id uuid;
  next_invitation_id uuid;
  next_owner_email text;
  next_expires_at timestamptz;
begin
  if not zeus_private.platform_session_is_admin(
    target_user_id, target_session_id, true
  ) then
    raise exception 'recent platform administrator MFA required' using errcode = '42501';
  end if;
  if target_mode not in ('resend', 'replace')
     or target_token_hash is null
     or octet_length(target_token_hash) <> 32 then
    raise exception 'invalid provisioning invitation operation' using errcode = '22023';
  end if;
  select * into current_organization
  from public.organizations o
  where o.id = target_organization_id
  for update;
  if not found then
    raise exception 'organization not found' using errcode = 'P0002';
  end if;
  if current_organization.revision <> target_revision then
    raise exception 'organization revision mismatch' using errcode = 'ZX002';
  end if;
  if current_organization.status <> 'provisioning' then
    raise exception 'initial owner invitation only exists during provisioning' using errcode = 'ZX003';
  end if;
  select * into current_invitation
  from public.organization_invitations i
  where i.organization_id = target_organization_id
    and i.invitation_kind = 'provisioning_owner'
    and i.status = 'pending'
  order by i.created_at desc, i.id desc
  limit 1
  for update;
  if not found then
    raise exception 'pending initial owner invitation not found' using errcode = 'P0002';
  end if;
  select g.workspace_id into initial_workspace_id
  from public.organization_invitation_workspaces g
  where g.invitation_id = current_invitation.id
    and g.organization_id = target_organization_id
    and g.workspace_role = 'owner'
  limit 1;
  if initial_workspace_id is null then
    raise exception 'initial workspace owner grant not found' using errcode = '23514';
  end if;
  next_expires_at := now() + interval '7 days';
  if target_mode = 'resend' then
    update public.organization_invitations
    set token_hash = target_token_hash,
        expires_at = next_expires_at,
        updated_at = now()
    where id = current_invitation.id;
    next_invitation_id := current_invitation.id;
    next_owner_email := current_invitation.email;
  else
    if target_replacement_email is null
       or target_replacement_email <> lower(btrim(target_replacement_email))
       or octet_length(target_replacement_email) <> length(target_replacement_email)
       or target_replacement_email !~ '^[!-~]+@[!-~]+$' then
      raise exception 'invalid replacement owner email' using errcode = '22023';
    end if;
    update public.organization_invitations
    set status = 'revoked', revoked_at = now(), updated_at = now()
    where id = current_invitation.id;
    insert into public.organization_invitations (
      organization_id, invited_by, email, organization_role,
      invitation_kind, token_hash, expires_at
    ) values (
      target_organization_id, target_user_id, target_replacement_email,
      'owner', 'provisioning_owner', target_token_hash, next_expires_at
    ) returning id, email into next_invitation_id, next_owner_email;
    insert into public.organization_invitation_workspaces (
      invitation_id, organization_id, workspace_id, workspace_role
    ) values (
      next_invitation_id, target_organization_id, initial_workspace_id, 'owner'
    );
  end if;
  update public.organizations
  set revision = revision + 1, updated_at = now()
  where id = target_organization_id;
  insert into public.audit_events (
    organization_id, actor_kind, actor_id, action, target_type, target_id, metadata
  ) values (
    target_organization_id, 'user', target_user_id,
    'platform.owner_invitation_' || target_mode,
    'organization_invitation', next_invitation_id,
    jsonb_build_object('previous_invitation_id', current_invitation.id)
  );
  insert into public.security_events (
    organization_id, actor_user_id, event_type, outcome, metadata
  ) values (
    target_organization_id, target_user_id,
    'platform.owner_invitation_' || target_mode, 'success',
    jsonb_build_object('invitation_id', next_invitation_id,
                       'previous_invitation_id', current_invitation.id)
  );
  return query select target_organization_id, current_organization.name,
    current_organization.revision + 1, next_invitation_id,
    next_owner_email, next_expires_at;
end
$$;

-- Platform-managed identity resources remain hidden from Organization Owners.
-- A validated support Grant opens only the same tenant RLS rows.
drop policy organization_isolation on federated_identity_providers;
create policy organization_isolation on federated_identity_providers
  using (
    organization_id = (select zeus_private.current_organization_id())
    and (
      exists (
        select 1 from organization_governance g
        where g.organization_id = federated_identity_providers.organization_id
          and g.identity_settings_mode = 'self_service'
      )
      or zeus_private.current_platform_tenant_access_is_valid(organization_id)
    )
  )
  with check (
    organization_id = (select zeus_private.current_organization_id())
    and (
      exists (
        select 1 from organization_governance g
        where g.organization_id = federated_identity_providers.organization_id
          and g.identity_settings_mode = 'self_service'
      )
      or zeus_private.current_platform_tenant_access_is_valid(organization_id)
    )
  );

drop policy organization_isolation on federated_group_mappings;
create policy organization_isolation on federated_group_mappings
  using (
    organization_id = (select zeus_private.current_organization_id())
    and (
      exists (
        select 1 from organization_governance g
        where g.organization_id = federated_group_mappings.organization_id
          and g.identity_settings_mode = 'self_service'
      )
      or zeus_private.current_platform_tenant_access_is_valid(organization_id)
    )
  )
  with check (
    organization_id = (select zeus_private.current_organization_id())
    and (
      exists (
        select 1 from organization_governance g
        where g.organization_id = federated_group_mappings.organization_id
          and g.identity_settings_mode = 'self_service'
      )
      or zeus_private.current_platform_tenant_access_is_valid(organization_id)
    )
  );

drop policy organization_domains_tenant on organization_domains;
create policy organization_domains_tenant on organization_domains
  using (
    organization_id = (select zeus_private.current_organization_id())
    and (
      exists (
        select 1 from organization_governance g
        where g.organization_id = organization_domains.organization_id
          and g.identity_settings_mode = 'self_service'
      )
      or zeus_private.current_platform_tenant_access_is_valid(organization_id)
    )
  )
  with check (
    organization_id = (select zeus_private.current_organization_id())
    and (
      exists (
        select 1 from organization_governance g
        where g.organization_id = organization_domains.organization_id
          and g.identity_settings_mode = 'self_service'
      )
      or zeus_private.current_platform_tenant_access_is_valid(organization_id)
    )
  );

drop policy organization_identity_policies_tenant on organization_identity_policies;
create policy organization_identity_policies_tenant on organization_identity_policies
  using (
    organization_id = (select zeus_private.current_organization_id())
    and (
      exists (
        select 1 from organization_governance g
        where g.organization_id = organization_identity_policies.organization_id
          and g.identity_settings_mode = 'self_service'
      )
      or zeus_private.current_platform_tenant_access_is_valid(organization_id)
    )
  )
  with check (
    organization_id = (select zeus_private.current_organization_id())
    and (
      exists (
        select 1 from organization_governance g
        where g.organization_id = organization_identity_policies.organization_id
          and g.identity_settings_mode = 'self_service'
      )
      or zeus_private.current_platform_tenant_access_is_valid(organization_id)
    )
  );

drop policy oidc_clients_tenant on oidc_clients;
create policy oidc_clients_tenant on oidc_clients
  using (
    organization_id = (select zeus_private.current_organization_id())
    and (
      exists (
        select 1 from organization_governance g
        where g.organization_id = oidc_clients.organization_id
          and g.identity_settings_mode = 'self_service'
      )
      or zeus_private.current_platform_tenant_access_is_valid(organization_id)
    )
  )
  with check (
    organization_id = (select zeus_private.current_organization_id())
    and (
      exists (
        select 1 from organization_governance g
        where g.organization_id = oidc_clients.organization_id
          and g.identity_settings_mode = 'self_service'
      )
      or zeus_private.current_platform_tenant_access_is_valid(organization_id)
    )
  );

drop policy oidc_client_redirect_uris_tenant on oidc_client_redirect_uris;
create policy oidc_client_redirect_uris_tenant on oidc_client_redirect_uris
  using (
    organization_id = (select zeus_private.current_organization_id())
    and (
      exists (
        select 1 from organization_governance g
        where g.organization_id = oidc_client_redirect_uris.organization_id
          and g.identity_settings_mode = 'self_service'
      )
      or zeus_private.current_platform_tenant_access_is_valid(organization_id)
    )
  )
  with check (
    organization_id = (select zeus_private.current_organization_id())
    and (
      exists (
        select 1 from organization_governance g
        where g.organization_id = oidc_client_redirect_uris.organization_id
          and g.identity_settings_mode = 'self_service'
      )
      or zeus_private.current_platform_tenant_access_is_valid(organization_id)
    )
  );

revoke all on function zeus_private.platform_session_is_admin(uuid, uuid, boolean) from public;
revoke all on function zeus_private.platform_tenant_access_is_valid(uuid, uuid, uuid, uuid) from public;
revoke all on function zeus_private.current_platform_tenant_access_is_valid(uuid) from public;
revoke all on function zeus_private.validate_platform_tenant_access_grant(uuid, uuid, uuid) from public;
revoke all on function zeus_private.create_platform_tenant_access_grant(
  uuid, uuid, uuid, text, integer, bytea, bytea
) from public;
revoke all on function zeus_private.revoke_platform_tenant_access_grant(
  uuid, uuid, uuid, text
) from public;
revoke all on function zeus_private.record_platform_support_operation(
  uuid, uuid, uuid, uuid, uuid, text, text, uuid, text
) from public;
revoke all on function zeus_private.list_platform_organizations(uuid, uuid) from public;
revoke all on function zeus_private.load_platform_organization(uuid, uuid, uuid) from public;
revoke all on function zeus_private.create_platform_organization(
  uuid, uuid, text, bytea, text, text, text, text, text, bytea, text
) from public;
revoke all on function zeus_private.update_platform_organization(
  uuid, uuid, uuid, bigint, text, text, text
) from public;
revoke all on function zeus_private.transition_platform_organization(
  uuid, uuid, uuid, bigint, text
) from public;
revoke all on function zeus_private.rotate_platform_owner_invitation(
  uuid, uuid, uuid, bigint, text, text, bytea
) from public;

grant execute on function zeus_private.validate_platform_tenant_access_grant(uuid, uuid, uuid)
  to zeus_http;
grant execute on function zeus_private.current_platform_tenant_access_is_valid(uuid)
  to zeus_http;
grant execute on function zeus_private.create_platform_tenant_access_grant(
  uuid, uuid, uuid, text, integer, bytea, bytea
) to zeus_http;
grant execute on function zeus_private.revoke_platform_tenant_access_grant(
  uuid, uuid, uuid, text
) to zeus_http;
grant execute on function zeus_private.record_platform_support_operation(
  uuid, uuid, uuid, uuid, uuid, text, text, uuid, text
) to zeus_http;
grant execute on function zeus_private.list_platform_organizations(uuid, uuid) to zeus_http;
grant execute on function zeus_private.load_platform_organization(uuid, uuid, uuid) to zeus_http;
grant execute on function zeus_private.create_platform_organization(
  uuid, uuid, text, bytea, text, text, text, text, text, bytea, text
) to zeus_http;
grant execute on function zeus_private.update_platform_organization(
  uuid, uuid, uuid, bigint, text, text, text
) to zeus_http;
grant execute on function zeus_private.transition_platform_organization(
  uuid, uuid, uuid, bigint, text
) to zeus_http;
grant execute on function zeus_private.rotate_platform_owner_invitation(
  uuid, uuid, uuid, bigint, text, text, bytea
) to zeus_http;
