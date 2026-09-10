-- Unify tenant administrator roles around explicit owners and add the
-- organization-level identity governance switch.

alter table organizations drop constraint if exists organizations_status_check;
alter table organizations
  add constraint organizations_status_check
  check (status in ('provisioning', 'active', 'suspended', 'archived'));

alter table organization_memberships
  drop constraint if exists organization_memberships_role_check;
alter table workspace_memberships
  drop constraint if exists workspace_memberships_role_check;
alter table federated_group_mappings
  drop constraint if exists oidc_group_mappings_organization_role_check;
alter table federated_group_mappings
  drop constraint if exists oidc_group_mappings_workspace_role_check;
alter table federated_group_mappings
  drop constraint if exists federated_group_mappings_organization_role_check;
alter table federated_group_mappings
  drop constraint if exists federated_group_mappings_workspace_role_check;
alter table organization_invitations
  drop constraint if exists organization_invitations_organization_role_check;
alter table organization_invitation_workspaces
  drop constraint if exists organization_invitation_workspaces_workspace_role_check;

update organization_memberships set role = 'owner' where role = 'admin';
update workspace_memberships set role = 'owner' where role = 'admin';
update federated_group_mappings
set organization_role = 'owner'
where organization_role = 'admin';
update federated_group_mappings
set workspace_role = 'owner'
where workspace_role = 'admin';
update organization_invitations
set organization_role = 'owner'
where organization_role = 'admin';
update organization_invitation_workspaces
set workspace_role = 'owner'
where workspace_role = 'admin';

alter table organization_memberships
  add constraint organization_memberships_role_check
  check (role in ('owner', 'member', 'auditor'));
alter table workspace_memberships
  add constraint workspace_memberships_role_check
  check (role in ('owner', 'builder', 'operator', 'viewer'));
alter table federated_group_mappings
  add constraint federated_group_mappings_organization_role_check
  check (organization_role in ('owner', 'member', 'auditor'));
alter table federated_group_mappings
  add constraint federated_group_mappings_workspace_role_check
  check (workspace_role in ('owner', 'builder', 'operator', 'viewer'));
alter table organization_invitations
  add constraint organization_invitations_organization_role_check
  check (organization_role in ('owner', 'member', 'auditor'));
alter table organization_invitation_workspaces
  add constraint organization_invitation_workspaces_workspace_role_check
  check (workspace_role in ('owner', 'builder', 'operator', 'viewer'));

alter table organization_invitations
  add column invitation_kind text not null default 'membership',
  add constraint organization_invitations_kind_check
    check (invitation_kind in ('membership', 'provisioning_owner')),
  add constraint organization_invitations_provisioning_owner_check
    check (invitation_kind <> 'provisioning_owner' or organization_role = 'owner');

create table organization_governance (
  organization_id uuid primary key references organizations(id),
  identity_settings_mode text not null default 'self_service'
    check (identity_settings_mode in ('self_service', 'platform_managed')),
  revision bigint not null default 1 check (revision > 0),
  updated_by uuid references users(id),
  updated_at timestamptz not null default now()
);

create index organization_governance_updated_by_idx
  on organization_governance (updated_by)
  where updated_by is not null;

insert into organization_governance (organization_id, identity_settings_mode)
select id, 'self_service' from organizations;

alter table organization_governance enable row level security;
alter table organization_governance force row level security;
create policy organization_governance_tenant on organization_governance
  using (organization_id = (select zeus_private.current_organization_id()))
  with check (organization_id = (select zeus_private.current_organization_id()));

revoke all on table organization_governance from public;
grant select on organization_governance to zeus_http;

create or replace function zeus_private.assert_active_organization_has_owners(
  target_organization_id uuid
)
returns void
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  if exists (
    select 1 from public.organizations o
    where o.id = target_organization_id and o.status = 'active'
  ) then
    if not exists (
      select 1 from public.organization_memberships m
      where m.organization_id = target_organization_id
        and m.role = 'owner'
        and m.status = 'active'
    ) then
      raise exception 'active organization must keep an active owner'
        using errcode = '23514';
    end if;

    if exists (
      select 1
      from public.workspaces w
      where w.organization_id = target_organization_id
        and w.status = 'active'
        and not exists (
          select 1
          from public.workspace_memberships m
          where m.organization_id = target_organization_id
            and m.workspace_id = w.id
            and m.role = 'owner'
            and m.status = 'active'
        )
    ) then
      raise exception 'active workspace must keep an active owner'
        using errcode = '23514';
    end if;
  end if;
end
$$;

create or replace function zeus_private.enforce_organization_owner_state()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  if tg_op = 'INSERT' then
    perform zeus_private.assert_active_organization_has_owners(new.id);
  elsif tg_op = 'UPDATE' then
    perform zeus_private.assert_active_organization_has_owners(new.id);
    if old.id <> new.id then
      perform zeus_private.assert_active_organization_has_owners(old.id);
    end if;
  else
    perform zeus_private.assert_active_organization_has_owners(old.id);
  end if;
  return null;
end
$$;

create or replace function zeus_private.enforce_child_owner_state()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  if tg_op = 'INSERT' then
    perform zeus_private.assert_active_organization_has_owners(new.organization_id);
  elsif tg_op = 'UPDATE' then
    perform zeus_private.assert_active_organization_has_owners(new.organization_id);
    if old.organization_id <> new.organization_id then
      perform zeus_private.assert_active_organization_has_owners(old.organization_id);
    end if;
  else
    perform zeus_private.assert_active_organization_has_owners(old.organization_id);
  end if;
  return null;
end
$$;

create constraint trigger organizations_active_owner_guard
after insert or update of status on organizations
deferrable initially deferred
for each row execute function zeus_private.enforce_organization_owner_state();

create constraint trigger workspaces_active_owner_guard
after insert or update of organization_id, status or delete on workspaces
deferrable initially deferred
for each row execute function zeus_private.enforce_child_owner_state();

create constraint trigger organization_memberships_active_owner_guard
after insert or update or delete on organization_memberships
deferrable initially deferred
for each row execute function zeus_private.enforce_child_owner_state();

create constraint trigger workspace_memberships_active_owner_guard
after insert or update or delete on workspace_memberships
deferrable initially deferred
for each row execute function zeus_private.enforce_child_owner_state();

create or replace function zeus_private.guard_last_workspace_owner()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  if old.role = 'owner'
     and old.status = 'active'
     and (tg_op = 'DELETE' or new.role <> 'owner' or new.status <> 'active')
     and exists (
       select 1 from public.organizations o
       where o.id = old.organization_id and o.status = 'active'
     )
     and not exists (
       select 1
       from public.workspace_memberships m
       where m.organization_id = old.organization_id
         and m.workspace_id = old.workspace_id
         and m.user_id <> old.user_id
         and m.role = 'owner'
         and m.status = 'active'
     ) then
    raise exception 'workspace must keep an active owner' using errcode = '23514';
  end if;
  if tg_op = 'DELETE' then
    return old;
  end if;
  return new;
end
$$;

create trigger workspace_memberships_last_owner_guard
before update or delete on workspace_memberships
for each row execute function zeus_private.guard_last_workspace_owner();

create or replace function zeus_private.guard_owner_user_status()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  if old.status in ('pending_verification', 'active')
     and new.status in ('disabled', 'anonymization_pending', 'anonymized')
     and (
       exists (
         select 1
         from public.organization_memberships owned
         join public.organizations o
           on o.id = owned.organization_id and o.status = 'active'
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
       )
       or exists (
         select 1
         from public.workspace_memberships owned
         join public.workspaces w
           on w.id = owned.workspace_id and w.status = 'active'
         join public.organizations o
           on o.id = owned.organization_id and o.status = 'active'
         where owned.user_id = old.id
           and owned.role = 'owner'
           and owned.status = 'active'
           and not exists (
             select 1
             from public.workspace_memberships replacement
             where replacement.organization_id = owned.organization_id
               and replacement.workspace_id = owned.workspace_id
               and replacement.user_id <> old.id
               and replacement.role = 'owner'
               and replacement.status = 'active'
           )
       )
     ) then
    raise exception 'last tenant owner cannot be disabled' using errcode = '23514';
  end if;
  return new;
end
$$;

create or replace function zeus_private.guard_organization_slug()
returns trigger
language plpgsql
set search_path = pg_catalog, public
as $$
begin
  if old.status <> 'provisioning' and new.slug <> old.slug then
    raise exception 'organization slug is immutable after activation' using errcode = '23514';
  end if;
  return new;
end
$$;

create trigger organizations_slug_guard
before update of slug on organizations
for each row execute function zeus_private.guard_organization_slug();

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
  insert into public.organization_governance (organization_id, updated_by)
  values (new_organization_id, new_user_id);
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
    new_organization_id, new_workspace_id, new_user_id, 'owner'
  );
  insert into public.web_sessions (
    user_id, active_organization_id, active_workspace_id,
    token_hash, csrf_token_hash, auth_methods, authenticated_at,
    idle_expires_at, absolute_expires_at
  ) values (
    new_user_id, new_organization_id, new_workspace_id,
    target_session_token_hash, target_csrf_token_hash, array['password'], now(),
    now() + make_interval(secs => target_idle_seconds),
    now() + make_interval(secs => target_absolute_seconds)
  ) returning id into new_session_id;
  insert into public.security_events (
    organization_id, workspace_id, user_id, actor_user_id, event_type, outcome
  ) values (
    new_organization_id, new_workspace_id, new_user_id, new_user_id,
    'setup.completed', 'success'
  );
  return query
  select new_user_id, new_organization_id, new_workspace_id, new_session_id;
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
  insert into public.organization_governance (organization_id, updated_by)
  values (new_organization_id, target_user_id);
  insert into public.workspaces (organization_id, slug, name)
  values (new_organization_id, target_workspace_slug, target_workspace_name)
  returning id into new_workspace_id;
  insert into public.organization_memberships (organization_id, user_id, role)
  values (new_organization_id, target_user_id, 'owner');
  insert into public.workspace_memberships (
    organization_id, workspace_id, user_id, role
  ) values (
    new_organization_id, new_workspace_id, target_user_id, 'owner'
  );
  insert into public.organization_identity_policies (organization_id, updated_by)
  values (new_organization_id, target_user_id);
  return query select new_organization_id, new_workspace_id;
end
$$;

create or replace function zeus_private.accept_organization_invitation(
  target_user_id uuid,
  target_session_id uuid,
  target_token_hash bytea
)
returns table (organization_id uuid, workspace_id uuid)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  invitation public.organization_invitations%rowtype;
  selected_workspace_id uuid;
  session_email text;
begin
  select u.email into session_email
  from public.web_sessions s
  join public.users u on u.id = s.user_id
  where s.id = target_session_id
    and s.user_id = target_user_id
    and s.revoked_at is null
    and s.idle_expires_at > now()
    and s.absolute_expires_at > now()
    and u.status = 'active'
    and u.email_verified_at is not null;
  if not found then
    raise exception 'active verified session required' using errcode = '42501';
  end if;

  select i.* into invitation
  from public.organization_invitations i
  join public.organizations o on o.id = i.organization_id
  where i.token_hash = target_token_hash
    and i.email = session_email
    and i.status = 'pending'
    and i.expires_at > now()
    and (
      (i.invitation_kind = 'membership' and o.status = 'active')
      or (i.invitation_kind = 'provisioning_owner' and o.status = 'provisioning')
    )
  for update of i;
  if not found then
    raise exception 'invitation is unavailable' using errcode = '42501';
  end if;

  if invitation.invitation_kind = 'provisioning_owner' and (
    invitation.organization_role <> 'owner'
    or 1 <> (
      select count(*)
      from public.organization_invitation_workspaces g
      join public.workspaces w
        on w.id = g.workspace_id
       and w.organization_id = invitation.organization_id
       and w.status = 'active'
      where g.invitation_id = invitation.id
        and g.organization_id = invitation.organization_id
        and g.workspace_role = 'owner'
    )
  ) then
    raise exception 'provisioning invitation must grant one initial workspace owner role'
      using errcode = '23514';
  end if;

  insert into public.organization_memberships (organization_id, user_id, role, status)
  values (invitation.organization_id, target_user_id, invitation.organization_role, 'active')
  on conflict on constraint organization_memberships_pkey do update
    set role = excluded.role, status = 'active', updated_at = now();
  insert into public.workspace_memberships (
    organization_id, workspace_id, user_id, role, status
  )
  select g.organization_id, g.workspace_id, target_user_id, g.workspace_role, 'active'
  from public.organization_invitation_workspaces g
  where g.invitation_id = invitation.id
  on conflict on constraint workspace_memberships_pkey do update
    set role = excluded.role, status = 'active', updated_at = now();
  update public.organization_invitations
  set status = 'accepted', accepted_by = target_user_id,
      accepted_at = now(), updated_at = now()
  where id = invitation.id;

  if invitation.invitation_kind = 'provisioning_owner' then
    update public.organizations
    set status = 'active', revision = revision + 1, updated_at = now()
    where id = invitation.organization_id and status = 'provisioning';
  end if;

  select g.workspace_id into selected_workspace_id
  from public.organization_invitation_workspaces g
  where g.invitation_id = invitation.id
  order by g.workspace_id
  limit 1;
  return query select invitation.organization_id, selected_workspace_id;
end
$$;

drop policy organization_isolation on federated_identity_providers;
create policy organization_isolation on federated_identity_providers
  using (
    organization_id = (select zeus_private.current_organization_id())
    and exists (
      select 1 from organization_governance g
      where g.organization_id = federated_identity_providers.organization_id
        and g.identity_settings_mode = 'self_service'
    )
  )
  with check (
    organization_id = (select zeus_private.current_organization_id())
    and exists (
      select 1 from organization_governance g
      where g.organization_id = federated_identity_providers.organization_id
        and g.identity_settings_mode = 'self_service'
    )
  );

drop policy organization_isolation on federated_group_mappings;
create policy organization_isolation on federated_group_mappings
  using (
    organization_id = (select zeus_private.current_organization_id())
    and exists (
      select 1 from organization_governance g
      where g.organization_id = federated_group_mappings.organization_id
        and g.identity_settings_mode = 'self_service'
    )
  )
  with check (
    organization_id = (select zeus_private.current_organization_id())
    and exists (
      select 1 from organization_governance g
      where g.organization_id = federated_group_mappings.organization_id
        and g.identity_settings_mode = 'self_service'
    )
  );

drop policy organization_domains_tenant on organization_domains;
create policy organization_domains_tenant on organization_domains
  using (
    organization_id = (select zeus_private.current_organization_id())
    and exists (
      select 1 from organization_governance g
      where g.organization_id = organization_domains.organization_id
        and g.identity_settings_mode = 'self_service'
    )
  )
  with check (
    organization_id = (select zeus_private.current_organization_id())
    and exists (
      select 1 from organization_governance g
      where g.organization_id = organization_domains.organization_id
        and g.identity_settings_mode = 'self_service'
    )
  );

drop policy organization_identity_policies_tenant on organization_identity_policies;
create policy organization_identity_policies_tenant on organization_identity_policies
  using (
    organization_id = (select zeus_private.current_organization_id())
    and exists (
      select 1 from organization_governance g
      where g.organization_id = organization_identity_policies.organization_id
        and g.identity_settings_mode = 'self_service'
    )
  )
  with check (
    organization_id = (select zeus_private.current_organization_id())
    and exists (
      select 1 from organization_governance g
      where g.organization_id = organization_identity_policies.organization_id
        and g.identity_settings_mode = 'self_service'
    )
  );

drop policy oidc_clients_tenant on oidc_clients;
create policy oidc_clients_tenant on oidc_clients
  using (
    organization_id = (select zeus_private.current_organization_id())
    and exists (
      select 1 from organization_governance g
      where g.organization_id = oidc_clients.organization_id
        and g.identity_settings_mode = 'self_service'
    )
  )
  with check (
    organization_id = (select zeus_private.current_organization_id())
    and exists (
      select 1 from organization_governance g
      where g.organization_id = oidc_clients.organization_id
        and g.identity_settings_mode = 'self_service'
    )
  );

drop policy oidc_client_redirect_uris_tenant on oidc_client_redirect_uris;
create policy oidc_client_redirect_uris_tenant on oidc_client_redirect_uris
  using (
    organization_id = (select zeus_private.current_organization_id())
    and exists (
      select 1 from organization_governance g
      where g.organization_id = oidc_client_redirect_uris.organization_id
        and g.identity_settings_mode = 'self_service'
    )
  )
  with check (
    organization_id = (select zeus_private.current_organization_id())
    and exists (
      select 1 from organization_governance g
      where g.organization_id = oidc_client_redirect_uris.organization_id
        and g.identity_settings_mode = 'self_service'
    )
  );

revoke insert, update, delete on organizations from zeus_http;
grant update (name, revision, updated_at) on organizations to zeus_http;

revoke all on function zeus_private.assert_active_organization_has_owners(uuid) from public;
revoke all on function zeus_private.enforce_organization_owner_state() from public;
revoke all on function zeus_private.enforce_child_owner_state() from public;
revoke all on function zeus_private.guard_last_workspace_owner() from public;
revoke all on function zeus_private.guard_owner_user_status() from public;
revoke all on function zeus_private.guard_organization_slug() from public;

do $$
declare
  target record;
begin
  if exists (select 1 from public.organization_memberships where role = 'admin')
     or exists (select 1 from public.workspace_memberships where role = 'admin')
     or exists (
       select 1 from public.federated_group_mappings
       where organization_role = 'admin' or workspace_role = 'admin'
     )
     or exists (
       select 1 from public.organization_invitations
       where organization_role = 'admin'
     )
     or exists (
       select 1 from public.organization_invitation_workspaces
       where workspace_role = 'admin'
     ) then
    raise exception 'tenant admin role migration is incomplete' using errcode = '23514';
  end if;

  for target in select id from public.organizations where status = 'active'
  loop
    perform zeus_private.assert_active_organization_has_owners(target.id);
  end loop;
end
$$;
