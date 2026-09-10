-- Split the upstream account fact from each Organization's trust decision.
--
-- This is a pre-production cutover migration. Old API processes must be stopped
-- before it runs because the old federated_identities table and functions are
-- removed in the same transaction.

alter table federated_identity_providers
  add constraint federated_identity_providers_organization_id_unique
  unique (organization_id, id);

create table external_identities (
  id uuid primary key default uuidv7(),
  user_id uuid not null references users(id),
  issuer text not null,
  subject text not null,
  status text not null default 'active' check (status in ('active', 'revoked')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  last_login_at timestamptz not null default now(),
  revoked_at timestamptz,
  unique (issuer, subject),
  check (btrim(issuer) <> ''),
  check (btrim(subject) <> ''),
  check ((status = 'revoked') = (revoked_at is not null))
);

create index external_identities_user_id_idx
  on external_identities (user_id, status, created_at, id);

create table organization_federated_bindings (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  provider_id uuid not null,
  external_identity_id uuid not null references external_identities(id),
  claims jsonb not null default '{}'::jsonb check (jsonb_typeof(claims) = 'object'),
  binding_source text not null
    check (binding_source in ('migration', 'login', 'explicit', 'jit')),
  status text not null default 'active' check (status in ('active', 'revoked')),
  linked_at timestamptz not null default now(),
  last_login_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  revoked_at timestamptz,
  foreign key (organization_id, provider_id)
    references federated_identity_providers(organization_id, id),
  constraint organization_federated_bindings_identity_unique
    unique (organization_id, provider_id, external_identity_id),
  check ((status = 'revoked') = (revoked_at is not null))
);

create index organization_federated_bindings_external_identity_idx
  on organization_federated_bindings (external_identity_id, status, linked_at, id);
create index organization_federated_bindings_provider_id_idx
  on organization_federated_bindings (provider_id);

insert into external_identities (
  id, user_id, issuer, subject, status, created_at, updated_at, last_login_at
)
select id, user_id, issuer, subject, 'active', created_at, linked_at, last_login_at
from federated_identities;

insert into organization_federated_bindings (
  organization_id, provider_id, external_identity_id, claims, binding_source,
  status, linked_at, last_login_at, updated_at
)
select organization_id, provider_id, id, claims, 'migration',
       'active', linked_at, last_login_at, greatest(linked_at, last_login_at)
from federated_identities;

alter table external_identities enable row level security;
alter table external_identities force row level security;
create policy external_identities_self on external_identities
  using (user_id = (select zeus_private.current_user_id()))
  with check (user_id = (select zeus_private.current_user_id()));

alter table organization_federated_bindings enable row level security;
alter table organization_federated_bindings force row level security;
create policy organization_federated_bindings_tenant on organization_federated_bindings
  using (organization_id = (select zeus_private.current_organization_id()))
  with check (organization_id = (select zeus_private.current_organization_id()));

revoke all on table external_identities, organization_federated_bindings from public;
revoke all on table external_identities, organization_federated_bindings
  from zeus_http, zeus_runtime;

drop function zeus_private.resolve_federated_identity(
  uuid, text, uuid, text, text, text, text, boolean, jsonb, text[]
);
drop function zeus_private.list_user_federated_identities(uuid, uuid);
drop function zeus_private.unlink_federated_identity(uuid, uuid, uuid);
drop function zeus_private.list_user_organizations(uuid, uuid);
drop table federated_identities;

create or replace function zeus_private.list_user_organizations(
  target_user_id uuid,
  target_session_id uuid
)
returns table (
  organization_id uuid,
  organization_slug text,
  organization_name text,
  organization_status text,
  organization_role text,
  workspaces jsonb
)
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select o.id,
         o.slug,
         o.name,
         o.status,
         m.role,
         coalesce((
           select jsonb_agg(jsonb_build_object(
             'id', w.id,
             'slug', w.slug,
             'name', w.name,
             'status', w.status,
             'role', wm.role
           ) order by w.created_at, w.id)
           from public.workspace_memberships wm
           join public.workspaces w on w.id = wm.workspace_id
           where wm.organization_id = o.id
             and wm.user_id = target_user_id
             and wm.status = 'active'
         ), '[]'::jsonb)
  from public.web_sessions s
  join public.organization_memberships m
    on m.user_id = s.user_id and m.status = 'active'
  join public.organizations o on o.id = m.organization_id
  where s.id = target_session_id
    and s.user_id = target_user_id
    and s.revoked_at is null
    and s.idle_expires_at > now()
    and s.absolute_expires_at > now()
  order by o.created_at, o.id
$$;

create or replace function zeus_private.resolve_external_identity(
  target_provider_id uuid,
  target_purpose text,
  target_initiating_user_id uuid,
  target_issuer text,
  target_subject text,
  target_email text,
  target_display_name text,
  target_email_verified boolean,
  target_claims jsonb,
  target_groups text[]
)
returns table (
  disposition text,
  resolved_user_id uuid,
  resolved_organization_id uuid,
  resolved_workspace_id uuid
)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  provider public.federated_identity_providers%rowtype;
  external_identity_id uuid;
  identity_user_id uuid;
  identity_status text;
  existing_email_user_id uuid;
  invitation public.organization_invitations%rowtype;
  selected_organization_role text;
  selected_workspace_id uuid;
  normalized_groups text[] := coalesce(target_groups, '{}');
  email_domain text;
  jit_allowed boolean := false;
  created_user boolean := false;
begin
  select p.* into provider
  from public.federated_identity_providers p
  join public.organizations o on o.id = p.organization_id and o.status = 'active'
  where p.id = target_provider_id and p.enabled
  for share of p;
  if not found then
    raise exception 'federated provider is unavailable' using errcode = '42501';
  end if;
  if target_purpose not in ('login', 'link')
     or target_issuer <> provider.issuer_url
     or btrim(coalesce(target_subject, '')) = ''
     or target_email <> lower(btrim(target_email))
     or target_email !~ '^[!-~]+@[!-~]+$'
     or target_claims is null
     or jsonb_typeof(target_claims) <> 'object' then
    raise exception 'invalid federated identity claims' using errcode = '22023';
  end if;

  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended(target_issuer || ':' || target_subject, 0)
  );

  select i.id, i.user_id, i.status
  into external_identity_id, identity_user_id, identity_status
  from public.external_identities i
  where i.issuer = target_issuer and i.subject = target_subject
  for update of i;

  if target_purpose = 'link' then
    if target_initiating_user_id is null or not exists (
      select 1
      from public.users u
      join public.organization_memberships m
        on m.user_id = u.id
       and m.organization_id = provider.organization_id
       and m.status = 'active'
      where u.id = target_initiating_user_id
        and u.status = 'active'
        and u.email_verified_at is not null
    ) then
      raise exception 'link target is not an active verified organization member'
        using errcode = '42501';
    end if;
    if external_identity_id is not null and identity_user_id <> target_initiating_user_id then
      raise exception 'external identity is linked to another account' using errcode = '23505';
    end if;
    if external_identity_id is null then
      insert into public.external_identities (user_id, issuer, subject)
      values (target_initiating_user_id, target_issuer, target_subject)
      returning id into external_identity_id;
    else
      update public.external_identities
      set status = 'active', revoked_at = null, last_login_at = now(), updated_at = now()
      where id = external_identity_id;
    end if;
    insert into public.organization_federated_bindings (
      organization_id, provider_id, external_identity_id, claims,
      binding_source, status
    ) values (
      provider.organization_id, provider.id, external_identity_id, target_claims,
      'explicit', 'active'
    )
    on conflict on constraint organization_federated_bindings_identity_unique do update
      set claims = excluded.claims,
          binding_source = excluded.binding_source,
          status = 'active',
          last_login_at = now(),
          updated_at = now(),
          revoked_at = null;
    insert into public.security_events (
      organization_id, user_id, actor_user_id, event_type, outcome, metadata
    ) values (
      provider.organization_id, target_initiating_user_id, target_initiating_user_id,
      'federated.binding_linked', 'success',
      jsonb_build_object('provider_id', provider.id, 'external_identity_id', external_identity_id)
    );
    return query
      select 'linked', target_initiating_user_id, provider.organization_id, null::uuid;
    return;
  end if;

  if external_identity_id is not null then
    if identity_status <> 'active' then
      insert into public.security_events (
        organization_id, user_id, event_type, outcome, metadata
      ) values (
        provider.organization_id, identity_user_id, 'federated.login', 'blocked',
        jsonb_build_object('provider_id', provider.id, 'reason', 'external_identity_revoked')
      );
      return query
        select 'account_link_required', null::uuid, provider.organization_id, null::uuid;
      return;
    end if;
    if not exists (
      select 1 from public.users u
      where u.id = identity_user_id and u.status = 'active'
    ) then
      raise exception 'external identity account is not active' using errcode = '42501';
    end if;
    if exists (
      select 1 from public.organization_memberships m
      where m.organization_id = provider.organization_id
        and m.user_id = identity_user_id
        and m.status = 'active'
    ) then
      update public.external_identities
      set last_login_at = now(), updated_at = now()
      where id = external_identity_id;
      insert into public.organization_federated_bindings (
        organization_id, provider_id, external_identity_id, claims,
        binding_source, status
      ) values (
        provider.organization_id, provider.id, external_identity_id, target_claims,
        'login', 'active'
      )
      on conflict on constraint organization_federated_bindings_identity_unique do update
        set claims = excluded.claims,
            binding_source = excluded.binding_source,
            status = 'active',
            last_login_at = now(),
            updated_at = now(),
            revoked_at = null;
      select wm.workspace_id into selected_workspace_id
      from public.workspace_memberships wm
      join public.workspaces w on w.id = wm.workspace_id and w.status = 'active'
      where wm.organization_id = provider.organization_id
        and wm.user_id = identity_user_id
        and wm.status = 'active'
      order by wm.created_at, wm.workspace_id
      limit 1;
      insert into public.security_events (
        organization_id, user_id, actor_user_id, event_type, outcome, metadata
      ) values (
        provider.organization_id, identity_user_id, identity_user_id,
        'federated.login', 'success',
        jsonb_build_object('provider_id', provider.id, 'external_identity_id', external_identity_id)
      );
      return query
        select 'authenticated', identity_user_id, provider.organization_id, selected_workspace_id;
      return;
    end if;
    if exists (
      select 1 from public.organization_memberships m
      where m.organization_id = provider.organization_id
        and m.user_id = identity_user_id
    ) then
      raise exception 'suspended organization membership cannot be restored by JIT'
        using errcode = '42501';
    end if;
  else
    select u.id into existing_email_user_id
    from public.users u
    where lower(u.email) = target_email
    limit 1;
    if existing_email_user_id is not null then
      insert into public.security_events (
        organization_id, user_id, event_type, outcome, metadata
      ) values (
        provider.organization_id, existing_email_user_id,
        'federated.login', 'blocked',
        jsonb_build_object('provider_id', provider.id, 'reason', 'account_link_required')
      );
      return query
        select 'account_link_required', null::uuid, provider.organization_id, null::uuid;
      return;
    end if;
  end if;

  if not provider.jit_enabled or not target_email_verified then
    insert into public.security_events (
      organization_id, user_id, event_type, outcome, metadata
    ) values (
      provider.organization_id, identity_user_id, 'federated.login', 'blocked',
      jsonb_build_object('provider_id', provider.id, 'reason', 'jit_not_allowed')
    );
    return query select 'jit_not_allowed', null::uuid, provider.organization_id, null::uuid;
    return;
  end if;

  select i.* into invitation
  from public.organization_invitations i
  where i.organization_id = provider.organization_id
    and i.invitation_kind = 'membership'
    and i.email = target_email
    and i.status = 'pending'
    and i.expires_at > now()
  order by i.created_at
  limit 1
  for update of i;
  if found then
    jit_allowed := true;
    selected_organization_role := invitation.organization_role;
  end if;

  if not jit_allowed and exists (
    select 1
    from public.federated_group_mappings m
    where m.organization_id = provider.organization_id
      and m.provider_id = provider.id
      and m.group_value = any(normalized_groups)
  ) then
    jit_allowed := true;
    select m.organization_role into selected_organization_role
    from public.federated_group_mappings m
    where m.organization_id = provider.organization_id
      and m.provider_id = provider.id
      and m.group_value = any(normalized_groups)
      and m.organization_role is not null
    order by m.created_at, m.id
    limit 1;
  end if;

  email_domain := split_part(target_email, '@', 2);
  if not jit_allowed and exists (
    select 1 from public.organization_domains d
    where d.organization_id = provider.organization_id
      and d.domain = email_domain
      and d.status = 'verified'
  ) then
    jit_allowed := true;
  end if;

  if not jit_allowed then
    insert into public.security_events (
      organization_id, user_id, event_type, outcome, metadata
    ) values (
      provider.organization_id, identity_user_id, 'federated.login', 'blocked',
      jsonb_build_object('provider_id', provider.id, 'reason', 'jit_policy_miss')
    );
    return query select 'jit_not_allowed', null::uuid, provider.organization_id, null::uuid;
    return;
  end if;

  if external_identity_id is null then
    insert into public.users (email, display_name, status, email_verified_at)
    values (target_email, btrim(target_display_name), 'active', now())
    returning id into identity_user_id;
    created_user := true;
    insert into public.external_identities (user_id, issuer, subject)
    values (identity_user_id, target_issuer, target_subject)
    returning id into external_identity_id;
  else
    update public.external_identities
    set last_login_at = now(), updated_at = now()
    where id = external_identity_id;
  end if;

  insert into public.organization_federated_bindings (
    organization_id, provider_id, external_identity_id, claims,
    binding_source, status
  ) values (
    provider.organization_id, provider.id, external_identity_id, target_claims,
    'jit', 'active'
  )
  on conflict on constraint organization_federated_bindings_identity_unique do update
    set claims = excluded.claims,
        binding_source = excluded.binding_source,
        status = 'active',
        last_login_at = now(),
        updated_at = now(),
        revoked_at = null;

  insert into public.organization_memberships (organization_id, user_id, role, status)
  values (
    provider.organization_id,
    identity_user_id,
    coalesce(selected_organization_role, 'member'),
    'active'
  )
  on conflict on constraint organization_memberships_pkey do nothing;

  if invitation.id is not null then
    insert into public.workspace_memberships (
      organization_id, workspace_id, user_id, role, status
    )
    select g.organization_id, g.workspace_id, identity_user_id, g.workspace_role, 'active'
    from public.organization_invitation_workspaces g
    where g.invitation_id = invitation.id
    on conflict on constraint workspace_memberships_pkey do nothing;
    update public.organization_invitations
    set status = 'accepted', accepted_by = identity_user_id,
        accepted_at = now(), updated_at = now()
    where id = invitation.id;
  end if;

  insert into public.workspace_memberships (
    organization_id, workspace_id, user_id, role, status
  )
  select m.organization_id, m.workspace_id, identity_user_id, m.workspace_role, 'active'
  from public.federated_group_mappings m
  join public.workspaces w
    on w.id = m.workspace_id
   and w.organization_id = provider.organization_id
   and w.status = 'active'
  where m.organization_id = provider.organization_id
    and m.provider_id = provider.id
    and m.group_value = any(normalized_groups)
    and m.workspace_id is not null
  on conflict on constraint workspace_memberships_pkey do nothing;

  select wm.workspace_id into selected_workspace_id
  from public.workspace_memberships wm
  join public.workspaces w on w.id = wm.workspace_id and w.status = 'active'
  where wm.organization_id = provider.organization_id
    and wm.user_id = identity_user_id
    and wm.status = 'active'
  order by wm.created_at, wm.workspace_id
  limit 1;

  insert into public.security_events (
    organization_id, workspace_id, user_id, actor_user_id,
    event_type, outcome, metadata
  ) values (
    provider.organization_id, selected_workspace_id, identity_user_id, identity_user_id,
    case when created_user then 'federated.jit_created' else 'federated.jit_joined' end,
    'success',
    jsonb_build_object('provider_id', provider.id, 'external_identity_id', external_identity_id)
  );

  return query
    select case when created_user then 'jit_created' else 'jit_joined' end,
           identity_user_id,
           provider.organization_id,
           selected_workspace_id;
end
$$;

create or replace function zeus_private.list_user_external_identities(
  target_user_id uuid,
  target_session_id uuid
)
returns table (
  identity_id uuid,
  issuer text,
  subject text,
  identity_status text,
  identity_created_at timestamptz,
  identity_last_login_at timestamptz,
  binding_id uuid,
  organization_id uuid,
  organization_name text,
  provider_id uuid,
  provider_slug text,
  binding_status text,
  binding_source text,
  binding_linked_at timestamptz,
  binding_last_login_at timestamptz
)
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select i.id,
         i.issuer,
         i.subject,
         i.status,
         i.created_at,
         i.last_login_at,
         b.id,
         b.organization_id,
         o.name,
         b.provider_id,
         p.slug,
         b.status,
         b.binding_source,
         b.linked_at,
         b.last_login_at
  from public.web_sessions s
  join public.external_identities i on i.user_id = s.user_id
  left join public.organization_federated_bindings b
    on b.external_identity_id = i.id
  left join public.organizations o on o.id = b.organization_id
  left join public.federated_identity_providers p
    on p.organization_id = b.organization_id and p.id = b.provider_id
  where s.id = target_session_id
    and s.user_id = target_user_id
    and s.revoked_at is null
    and s.idle_expires_at > now()
    and s.absolute_expires_at > now()
  order by i.created_at, i.id, b.linked_at, b.id
$$;

create or replace function zeus_private.list_user_available_federated_providers(
  target_user_id uuid,
  target_session_id uuid
)
returns table (
  provider_id uuid,
  organization_id uuid,
  organization_name text,
  provider_slug text,
  issuer text
)
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select p.id, o.id, o.name, p.slug, p.issuer_url
  from public.web_sessions s
  join public.organization_memberships m
    on m.user_id = s.user_id and m.status = 'active'
  join public.organizations o
    on o.id = m.organization_id and o.status = 'active'
  join public.federated_identity_providers p
    on p.organization_id = o.id and p.enabled
  where s.id = target_session_id
    and s.user_id = target_user_id
    and s.revoked_at is null
    and s.idle_expires_at > now()
    and s.absolute_expires_at > now()
  order by o.created_at, o.id, p.created_at, p.id
$$;

create or replace function zeus_private.unlink_organization_federated_binding(
  target_user_id uuid,
  target_session_id uuid,
  target_identity_id uuid,
  target_binding_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  binding_organization_id uuid;
  binding_provider_id uuid;
begin
  if not exists (
    select 1 from public.web_sessions s
    where s.id = target_session_id
      and s.user_id = target_user_id
      and s.revoked_at is null
      and s.idle_expires_at > now()
      and s.absolute_expires_at > now()
  ) then
    return false;
  end if;

  select b.organization_id, b.provider_id
  into binding_organization_id, binding_provider_id
  from public.organization_federated_bindings b
  join public.external_identities i on i.id = b.external_identity_id
  where b.id = target_binding_id
    and b.external_identity_id = target_identity_id
    and i.user_id = target_user_id
  for update of b;
  if not found then
    return false;
  end if;

  update public.organization_federated_bindings
  set status = 'revoked', revoked_at = coalesce(revoked_at, now()), updated_at = now()
  where id = target_binding_id and status = 'active';
  if found then
    insert into public.security_events (
      organization_id, user_id, actor_user_id, event_type, outcome, metadata
    ) values (
      binding_organization_id, target_user_id, target_user_id,
      'federated.binding_revoked', 'success',
      jsonb_build_object(
        'provider_id', binding_provider_id,
        'external_identity_id', target_identity_id,
        'binding_id', target_binding_id
      )
    );
  end if;
  return true;
end
$$;

create or replace function zeus_private.revoke_external_identity(
  target_user_id uuid,
  target_session_id uuid,
  target_identity_id uuid
)
returns text
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  current_status text;
begin
  if not exists (
    select 1 from public.web_sessions s
    where s.id = target_session_id
      and s.user_id = target_user_id
      and s.revoked_at is null
      and s.idle_expires_at > now()
      and s.absolute_expires_at > now()
  ) then
    return 'not_found';
  end if;

  select i.status into current_status
  from public.external_identities i
  where i.id = target_identity_id and i.user_id = target_user_id
  for update of i;
  if not found then
    return 'not_found';
  end if;
  if current_status = 'revoked' then
    return 'revoked';
  end if;
  if exists (
    select 1 from public.organization_federated_bindings b
    where b.external_identity_id = target_identity_id and b.status = 'active'
  ) then
    return 'active_bindings';
  end if;
  if not exists (
    select 1 from public.user_password_credentials p
    where p.user_id = target_user_id
  ) and not exists (
    select 1 from public.external_identities alternative
    where alternative.user_id = target_user_id
      and alternative.id <> target_identity_id
      and alternative.status = 'active'
  ) then
    return 'last_sign_in_method';
  end if;

  update public.external_identities
  set status = 'revoked', revoked_at = now(), updated_at = now()
  where id = target_identity_id;
  insert into public.security_events (
    user_id, actor_user_id, event_type, outcome, metadata
  ) values (
    target_user_id, target_user_id, 'external_identity.revoked', 'success',
    jsonb_build_object('external_identity_id', target_identity_id)
  );
  return 'revoked';
end
$$;

revoke all on function zeus_private.list_user_organizations(uuid, uuid) from public;
revoke all on function zeus_private.resolve_external_identity(
  uuid, text, uuid, text, text, text, text, boolean, jsonb, text[]
) from public;
revoke all on function zeus_private.list_user_external_identities(uuid, uuid) from public;
revoke all on function zeus_private.list_user_available_federated_providers(uuid, uuid) from public;
revoke all on function zeus_private.unlink_organization_federated_binding(
  uuid, uuid, uuid, uuid
) from public;
revoke all on function zeus_private.revoke_external_identity(uuid, uuid, uuid) from public;

grant execute on function zeus_private.list_user_organizations(uuid, uuid) to zeus_http;
grant execute on function zeus_private.resolve_external_identity(
  uuid, text, uuid, text, text, text, text, boolean, jsonb, text[]
) to zeus_http;
grant execute on function zeus_private.list_user_external_identities(uuid, uuid) to zeus_http;
grant execute on function zeus_private.list_user_available_federated_providers(uuid, uuid)
  to zeus_http;
grant execute on function zeus_private.unlink_organization_federated_binding(
  uuid, uuid, uuid, uuid
) to zeus_http;
grant execute on function zeus_private.revoke_external_identity(uuid, uuid, uuid) to zeus_http;

do $$
begin
  if exists (
    select 1
    from public.organization_federated_bindings b
    join public.federated_identity_providers p on p.id = b.provider_id
    where p.organization_id <> b.organization_id
  ) then
    raise exception 'cross-organization federated binding detected' using errcode = '23514';
  end if;
end
$$;
