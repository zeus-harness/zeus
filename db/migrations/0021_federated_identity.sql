-- Enterprise upstream identity is a login proof. Zeus remains the user authority.

alter table oidc_providers rename to federated_identity_providers;
alter table oidc_identities rename to federated_identities;
alter table oidc_group_mappings rename to federated_group_mappings;
alter table oidc_login_transactions rename to federated_login_transactions;

alter index oidc_providers_organization_id_idx
  rename to federated_identity_providers_organization_id_idx;
alter index oidc_identities_user_id_idx
  rename to federated_identities_user_id_idx;
alter index oidc_identities_provider_id_idx
  rename to federated_identities_provider_id_idx;
alter index oidc_group_mappings_organization_id_idx
  rename to federated_group_mappings_organization_id_idx;
alter index oidc_group_mappings_provider_id_idx
  rename to federated_group_mappings_provider_id_idx;
alter index oidc_group_mappings_workspace_id_idx
  rename to federated_group_mappings_workspace_id_idx;
alter index oidc_login_transactions_organization_id_idx
  rename to federated_login_transactions_organization_id_idx;
alter index oidc_login_transactions_provider_id_idx
  rename to federated_login_transactions_provider_id_idx;
alter index oidc_login_transactions_active_idx
  rename to federated_login_transactions_active_idx;

alter table federated_identity_providers
  add column slug text,
  add column jit_enabled boolean not null default false,
  add column trusted_acr text[] not null default '{}',
  add column trusted_amr text[] not null default '{}';

update federated_identity_providers
set slug = 'provider-' || left(id::text, 8)
where slug is null;

alter table federated_identity_providers
  alter column slug set not null,
  add constraint federated_identity_providers_slug_check
    check (
      slug = lower(slug)
      and length(slug) between 3 and 63
      and slug ~ '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$'
    ),
  add constraint federated_identity_providers_trusted_acr_check
    check (array_position(trusted_acr, '') is null),
  add constraint federated_identity_providers_trusted_amr_check
    check (array_position(trusted_amr, '') is null),
  add constraint federated_identity_providers_organization_slug_unique
    unique (organization_id, slug);

alter table federated_identities
  add column organization_id uuid references organizations(id),
  add column linked_at timestamptz not null default now();

update federated_identities i
set organization_id = p.organization_id
from federated_identity_providers p
where p.id = i.provider_id and i.organization_id is null;

alter table federated_identities
  alter column organization_id set not null,
  add constraint federated_identities_provider_user_unique unique (provider_id, user_id);

create index federated_identities_organization_id_idx
  on federated_identities (organization_id);

alter table federated_login_transactions
  add column purpose text not null default 'login',
  add column initiating_user_id uuid references users(id),
  add column initiating_session_id uuid references web_sessions(id),
  add constraint federated_login_transactions_purpose_check
    check (
      (purpose = 'login' and initiating_user_id is null and initiating_session_id is null)
      or
      (purpose = 'link' and initiating_user_id is not null and initiating_session_id is not null)
    );

create index federated_login_transactions_initiating_user_idx
  on federated_login_transactions (initiating_user_id, expires_at)
  where purpose = 'link' and consumed_at is null;

create table organization_domains (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  domain text not null,
  verification_token_hash bytea not null,
  status text not null default 'pending' check (status in ('pending', 'verified', 'revoked')),
  verified_at timestamptz,
  created_by uuid not null references users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (domain = lower(btrim(domain))),
  check (domain ~ '^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$'),
  check (domain like '%.%' and length(domain) between 3 and 253),
  check (octet_length(verification_token_hash) = 32),
  check ((status = 'verified') = (verified_at is not null)),
  unique (domain)
);

create index organization_domains_organization_id_idx
  on organization_domains (organization_id, created_at desc, id desc);

alter table organization_identity_policies
  add column federated_required boolean not null default false,
  add column required_federated_provider_id uuid references federated_identity_providers(id),
  add constraint organization_identity_policies_federated_check
    check (
      (not federated_required and required_federated_provider_id is null)
      or (federated_required and required_federated_provider_id is not null)
    );

create or replace function zeus_private.guard_federated_policy_provider()
returns trigger
language plpgsql
set search_path = pg_catalog, public
as $$
begin
  if new.required_federated_provider_id is not null and not exists (
    select 1
    from public.federated_identity_providers p
    where p.id = new.required_federated_provider_id
      and p.organization_id = new.organization_id
      and p.enabled
  ) then
    raise exception 'required federated provider must belong to the organization'
      using errcode = '23514';
  end if;
  return new;
end
$$;

create trigger organization_identity_policies_federated_provider_guard
before insert or update of organization_id, required_federated_provider_id, federated_required
on organization_identity_policies
for each row execute function zeus_private.guard_federated_policy_provider();

alter table organization_domains enable row level security;
alter table organization_domains force row level security;
create policy organization_domains_tenant on organization_domains
  using (organization_id = (select zeus_private.current_organization_id()))
  with check (organization_id = (select zeus_private.current_organization_id()));

drop function if exists zeus_private.get_oidc_provider_for_login(uuid);
drop function if exists zeus_private.create_oidc_login_transaction(
  uuid, bytea, bytea, bytea, text, text, timestamptz
);
drop function if exists zeus_private.consume_oidc_login_transaction(uuid, bytea);
drop function if exists zeus_private.jit_oidc_identity(
  uuid, text, text, text, text, boolean, jsonb
);

create or replace function zeus_private.get_federated_provider_for_login(
  target_organization_slug text,
  target_provider_slug text
)
returns table (
  id uuid,
  organization_id uuid,
  organization_slug text,
  provider_slug text,
  issuer_url text,
  client_id text,
  encrypted_client_secret bytea,
  secret_nonce bytea,
  key_id text,
  scopes text[],
  group_claim text,
  trusted_acr text[],
  trusted_amr text[]
)
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select p.id,
         p.organization_id,
         o.slug,
         p.slug,
         p.issuer_url,
         p.client_id,
         p.encrypted_client_secret,
         p.secret_nonce,
         p.key_id,
         p.scopes,
         p.group_claim,
         p.trusted_acr,
         p.trusted_amr
  from public.federated_identity_providers p
  join public.organizations o on o.id = p.organization_id
  where o.slug = target_organization_slug
    and p.slug = target_provider_slug
    and p.enabled
    and o.status = 'active'
$$;

create or replace function zeus_private.get_federated_provider_for_link(
  target_provider_id uuid,
  target_user_id uuid,
  target_session_id uuid
)
returns table (
  id uuid,
  organization_id uuid,
  organization_slug text,
  provider_slug text,
  issuer_url text,
  client_id text,
  encrypted_client_secret bytea,
  secret_nonce bytea,
  key_id text,
  scopes text[],
  group_claim text,
  trusted_acr text[],
  trusted_amr text[]
)
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select p.id,
         p.organization_id,
         o.slug,
         p.slug,
         p.issuer_url,
         p.client_id,
         p.encrypted_client_secret,
         p.secret_nonce,
         p.key_id,
         p.scopes,
         p.group_claim,
         p.trusted_acr,
         p.trusted_amr
  from public.web_sessions s
  join public.organization_memberships m
    on m.user_id = s.user_id and m.status = 'active'
  join public.organizations o
    on o.id = m.organization_id and o.status = 'active'
  join public.federated_identity_providers p
    on p.organization_id = o.id and p.id = target_provider_id and p.enabled
  where s.id = target_session_id
    and s.user_id = target_user_id
    and s.revoked_at is null
    and s.idle_expires_at > now()
    and s.absolute_expires_at > now()
$$;

create or replace function zeus_private.create_federated_login_transaction(
  target_provider_id uuid,
  target_purpose text,
  target_initiating_user_id uuid,
  target_initiating_session_id uuid,
  target_state_hash bytea,
  target_ciphertext bytea,
  target_nonce bytea,
  target_key_id text,
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
  if target_purpose not in ('login', 'link')
     or target_state_hash is null
     or octet_length(target_state_hash) <> 32
     or target_ciphertext is null
     or octet_length(target_ciphertext) = 0
     or target_nonce is null
     or octet_length(target_nonce) = 0
     or btrim(coalesce(target_key_id, '')) = ''
     or target_expires_at <= now()
     or target_expires_at > now() + interval '30 minutes' then
    raise exception 'invalid federated login transaction' using errcode = '22023';
  end if;

  select p.organization_id into provider_organization_id
  from public.federated_identity_providers p
  join public.organizations o on o.id = p.organization_id and o.status = 'active'
  where p.id = target_provider_id and p.enabled;
  if not found then
    raise exception 'federated provider is unavailable' using errcode = '22023';
  end if;

  if target_purpose = 'login' then
    if target_initiating_user_id is not null or target_initiating_session_id is not null then
      raise exception 'login transaction cannot carry a user' using errcode = '22023';
    end if;
  elsif target_initiating_user_id is null or target_initiating_session_id is null or not exists (
    select 1
    from public.web_sessions s
    join public.organization_memberships m
      on m.organization_id = provider_organization_id
     and m.user_id = s.user_id
     and m.status = 'active'
    where s.id = target_initiating_session_id
      and s.user_id = target_initiating_user_id
      and s.revoked_at is null
      and s.idle_expires_at > now()
      and s.absolute_expires_at > now()
  ) then
    raise exception 'link transaction requires an active organization member session'
      using errcode = '42501';
  end if;

  delete from public.federated_login_transactions t
  where t.provider_id = target_provider_id
    and t.expires_at < now() - interval '1 day';

  select count(*) into active_count
  from public.federated_login_transactions t
  where t.provider_id = target_provider_id
    and t.consumed_at is null
    and t.expires_at > now();
  if active_count >= 10000 then
    raise exception 'too many pending federated login transactions' using errcode = '54000';
  end if;

  insert into public.federated_login_transactions (
    organization_id, provider_id, purpose, initiating_user_id, initiating_session_id,
    state_hash, pkce_verifier_ciphertext, pkce_verifier_nonce,
    pkce_verifier_key_id, redirect_uri, expires_at
  ) values (
    provider_organization_id, target_provider_id, target_purpose,
    target_initiating_user_id, target_initiating_session_id,
    target_state_hash, target_ciphertext, target_nonce,
    target_key_id, target_redirect_uri, target_expires_at
  ) returning id into transaction_id;
  return transaction_id;
end
$$;

create or replace function zeus_private.consume_federated_login_transaction(
  target_provider_id uuid,
  target_state_hash bytea
)
returns table (
  purpose text,
  initiating_user_id uuid,
  initiating_session_id uuid,
  ciphertext bytea,
  nonce bytea,
  key_id text
)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  return query
  update public.federated_login_transactions t
  set consumed_at = now()
  where t.provider_id = target_provider_id
    and t.state_hash = target_state_hash
    and t.consumed_at is null
    and t.expires_at > now()
  returning t.purpose,
            t.initiating_user_id,
            t.initiating_session_id,
            t.pkce_verifier_ciphertext,
            t.pkce_verifier_nonce,
            t.pkce_verifier_key_id;
end
$$;

create or replace function zeus_private.resolve_federated_identity(
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
  identity_user_id uuid;
  existing_email_user_id uuid;
  invitation public.organization_invitations%rowtype;
  selected_organization_role text;
  selected_workspace_id uuid;
  normalized_groups text[] := coalesce(target_groups, '{}');
  email_domain text;
  jit_allowed boolean := false;
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

  select i.user_id into identity_user_id
  from public.federated_identities i
  where i.issuer = target_issuer and i.subject = target_subject
  for update of i;

  if identity_user_id is not null then
    if target_purpose = 'link' and identity_user_id <> target_initiating_user_id then
      raise exception 'federated identity is linked to another account' using errcode = '23505';
    end if;
    if not exists (
      select 1
      from public.users u
      join public.organization_memberships m
        on m.user_id = u.id
       and m.organization_id = provider.organization_id
       and m.status = 'active'
      where u.id = identity_user_id and u.status = 'active'
    ) then
      raise exception 'federated account is not an active organization member'
        using errcode = '42501';
    end if;
    update public.federated_identities
    set claims = target_claims, last_login_at = now()
    where issuer = target_issuer and subject = target_subject;
    insert into public.security_events (
      organization_id, user_id, actor_user_id, event_type, outcome, metadata
    ) values (
      provider.organization_id,
      identity_user_id,
      identity_user_id,
      case when target_purpose = 'link' then 'federated.link' else 'federated.login' end,
      'success',
      jsonb_build_object('provider_id', provider.id)
    );
    select wm.workspace_id into selected_workspace_id
    from public.workspace_memberships wm
    join public.workspaces w on w.id = wm.workspace_id and w.status = 'active'
    where wm.organization_id = provider.organization_id
      and wm.user_id = identity_user_id
      and wm.status = 'active'
    order by wm.created_at, wm.workspace_id
    limit 1;
    return query select
      case when target_purpose = 'link' then 'linked' else 'authenticated' end,
      identity_user_id,
      provider.organization_id,
      selected_workspace_id;
    return;
  end if;

  if target_purpose = 'link' then
    if target_initiating_user_id is null or not exists (
      select 1
      from public.users u
      join public.organization_memberships m
        on m.user_id = u.id
       and m.organization_id = provider.organization_id
       and m.status = 'active'
      where u.id = target_initiating_user_id and u.status = 'active'
    ) then
      raise exception 'link target is not an active organization member' using errcode = '42501';
    end if;
    insert into public.federated_identities (
      organization_id, user_id, provider_id, issuer, subject, claims
    ) values (
      provider.organization_id, target_initiating_user_id, provider.id,
      target_issuer, target_subject, target_claims
    );
    insert into public.security_events (
      organization_id, user_id, actor_user_id, event_type, outcome, metadata
    ) values (
      provider.organization_id, target_initiating_user_id, target_initiating_user_id,
      'federated.link', 'success', jsonb_build_object('provider_id', provider.id)
    );
    return query select 'linked', target_initiating_user_id, provider.organization_id, null::uuid;
    return;
  end if;

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
    return query select 'account_link_required', null::uuid, provider.organization_id, null::uuid;
    return;
  end if;

  if not provider.jit_enabled or not target_email_verified then
    insert into public.security_events (
      organization_id, event_type, outcome, metadata
    ) values (
      provider.organization_id, 'federated.login', 'blocked',
      jsonb_build_object('provider_id', provider.id, 'reason', 'jit_not_allowed')
    );
    return query select 'jit_not_allowed', null::uuid, provider.organization_id, null::uuid;
    return;
  end if;

  select i.* into invitation
  from public.organization_invitations i
  where i.organization_id = provider.organization_id
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
    where m.provider_id = provider.id
      and m.group_value = any(normalized_groups)
  ) then
    jit_allowed := true;
    select m.organization_role into selected_organization_role
    from public.federated_group_mappings m
    where m.provider_id = provider.id
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
      organization_id, event_type, outcome, metadata
    ) values (
      provider.organization_id, 'federated.login', 'blocked',
      jsonb_build_object('provider_id', provider.id, 'reason', 'jit_policy_miss')
    );
    return query select 'jit_not_allowed', null::uuid, provider.organization_id, null::uuid;
    return;
  end if;

  insert into public.users (email, display_name, status, email_verified_at)
  values (target_email, btrim(target_display_name), 'active', now())
  returning id into identity_user_id;
  insert into public.federated_identities (
    organization_id, user_id, provider_id, issuer, subject, claims
  ) values (
    provider.organization_id, identity_user_id, provider.id,
    target_issuer, target_subject, target_claims
  );
  insert into public.organization_memberships (organization_id, user_id, role, status)
  values (
    provider.organization_id,
    identity_user_id,
    coalesce(selected_organization_role, 'member'),
    'active'
  );

  if invitation.id is not null then
    insert into public.workspace_memberships (
      organization_id, workspace_id, user_id, role, status
    )
    select g.organization_id, g.workspace_id, identity_user_id, g.workspace_role, 'active'
    from public.organization_invitation_workspaces g
    where g.invitation_id = invitation.id
    on conflict (workspace_id, user_id) do update
      set role = excluded.role, status = 'active', updated_at = now();
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
  join public.workspaces w on w.id = m.workspace_id and w.status = 'active'
  where m.provider_id = provider.id
    and m.group_value = any(normalized_groups)
    and m.workspace_id is not null
  on conflict (workspace_id, user_id) do update
    set role = excluded.role, status = 'active', updated_at = now();

  select wm.workspace_id into selected_workspace_id
  from public.workspace_memberships wm
  join public.workspaces w on w.id = wm.workspace_id and w.status = 'active'
  where wm.organization_id = provider.organization_id
    and wm.user_id = identity_user_id
    and wm.status = 'active'
  order by wm.created_at, wm.workspace_id
  limit 1;

  insert into public.security_events (
    organization_id, workspace_id, user_id, actor_user_id, event_type, outcome, metadata
  ) values (
    provider.organization_id, selected_workspace_id, identity_user_id, identity_user_id,
    'federated.jit_created', 'success', jsonb_build_object('provider_id', provider.id)
  );

  return query select 'jit_created', identity_user_id, provider.organization_id, selected_workspace_id;
end
$$;

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
  workspaces jsonb,
  identity_providers jsonb
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
         ), '[]'::jsonb),
         coalesce((
           select jsonb_agg(jsonb_build_object(
             'id', p.id,
             'organization_id', p.organization_id,
             'slug', p.slug,
             'issuer_url', p.issuer_url,
             'enabled', p.enabled
           ) order by p.created_at, p.id)
           from public.federated_identity_providers p
           where p.organization_id = o.id and p.enabled
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
  join public.organizations o on o.id = i.organization_id and o.status = 'active'
  where i.token_hash = target_token_hash
    and i.email = session_email
    and i.status = 'pending'
    and i.expires_at > now()
  for update of i;
  if not found then
    raise exception 'invitation is unavailable' using errcode = '42501';
  end if;
  insert into public.organization_memberships (organization_id, user_id, role, status)
  values (invitation.organization_id, target_user_id, invitation.organization_role, 'active')
  on conflict (organization_id, user_id) do update
    set role = excluded.role, status = 'active', updated_at = now();
  insert into public.workspace_memberships (
    organization_id, workspace_id, user_id, role, status
  )
  select g.organization_id, g.workspace_id, target_user_id, g.workspace_role, 'active'
  from public.organization_invitation_workspaces g
  where g.invitation_id = invitation.id
  on conflict (workspace_id, user_id) do update
    set role = excluded.role, status = 'active', updated_at = now();
  update public.organization_invitations
  set status = 'accepted', accepted_by = target_user_id,
      accepted_at = now(), updated_at = now()
  where id = invitation.id;
  select g.workspace_id into selected_workspace_id
  from public.organization_invitation_workspaces g
  where g.invitation_id = invitation.id
  order by g.created_at, g.workspace_id
  limit 1;
  return query select invitation.organization_id, selected_workspace_id;
end
$$;

create or replace function zeus_private.list_user_federated_identities(
  target_user_id uuid,
  target_session_id uuid
)
returns table (
  identity_id uuid,
  provider_id uuid,
  organization_id uuid,
  organization_name text,
  provider_slug text,
  issuer text,
  subject text,
  linked_at timestamptz,
  last_login_at timestamptz
)
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select i.id, i.provider_id, i.organization_id, o.name, p.slug,
         i.issuer, i.subject, i.linked_at, i.last_login_at
  from public.web_sessions s
  join public.federated_identities i on i.user_id = s.user_id
  join public.federated_identity_providers p on p.id = i.provider_id
  join public.organizations o on o.id = i.organization_id
  where s.id = target_session_id
    and s.user_id = target_user_id
    and s.revoked_at is null
    and s.idle_expires_at > now()
    and s.absolute_expires_at > now()
  order by i.linked_at, i.id
$$;

create or replace function zeus_private.unlink_federated_identity(
  target_user_id uuid,
  target_session_id uuid,
  target_identity_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  affected integer;
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
  if not exists (
    select 1 from public.user_password_credentials p where p.user_id = target_user_id
  ) and (select count(*) from public.federated_identities i where i.user_id = target_user_id) <= 1 then
    raise exception 'cannot remove the last sign-in method' using errcode = '23514';
  end if;
  delete from public.federated_identities
  where id = target_identity_id and user_id = target_user_id;
  get diagnostics affected = row_count;
  return affected = 1;
end
$$;

create or replace function zeus_private.set_initial_native_password(
  target_user_id uuid,
  target_session_id uuid,
  target_password_hash text
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  if target_password_hash not like '$argon2id$%'
     or not exists (
       select 1 from public.web_sessions s
       where s.id = target_session_id
         and s.user_id = target_user_id
         and s.revoked_at is null
         and s.idle_expires_at > now()
         and s.absolute_expires_at > now()
         and exists (
           select 1 from unnest(s.auth_methods) method
           where method like 'federated:%'
         )
     ) then
    return false;
  end if;
  insert into public.user_password_credentials (user_id, password_hash)
  values (target_user_id, target_password_hash)
  on conflict (user_id) do nothing;
  return found;
end
$$;

create or replace function zeus_private.user_has_native_password(
  target_user_id uuid,
  target_session_id uuid
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
    join public.user_password_credentials p on p.user_id = s.user_id
    where s.id = target_session_id
      and s.user_id = target_user_id
      and s.revoked_at is null
      and s.idle_expires_at > now()
      and s.absolute_expires_at > now()
  )
$$;

revoke all on table federated_login_transactions from zeus_http, zeus_runtime;
revoke all on table organization_domains from public;
revoke all on function zeus_private.guard_federated_policy_provider() from public;
revoke all on function zeus_private.get_federated_provider_for_login(text, text) from public;
revoke all on function zeus_private.get_federated_provider_for_link(uuid, uuid, uuid) from public;
revoke all on function zeus_private.create_federated_login_transaction(
  uuid, text, uuid, uuid, bytea, bytea, bytea, text, text, timestamptz
) from public;
revoke all on function zeus_private.consume_federated_login_transaction(uuid, bytea) from public;
revoke all on function zeus_private.resolve_federated_identity(
  uuid, text, uuid, text, text, text, text, boolean, jsonb, text[]
) from public;
revoke all on function zeus_private.list_user_organizations(uuid, uuid) from public;
revoke all on function zeus_private.accept_organization_invitation(uuid, uuid, bytea) from public;
revoke all on function zeus_private.list_user_federated_identities(uuid, uuid) from public;
revoke all on function zeus_private.unlink_federated_identity(uuid, uuid, uuid) from public;
revoke all on function zeus_private.set_initial_native_password(uuid, uuid, text) from public;
revoke all on function zeus_private.user_has_native_password(uuid, uuid) from public;

grant execute on function zeus_private.get_federated_provider_for_login(text, text) to zeus_http;
grant execute on function zeus_private.get_federated_provider_for_link(uuid, uuid, uuid) to zeus_http;
grant execute on function zeus_private.create_federated_login_transaction(
  uuid, text, uuid, uuid, bytea, bytea, bytea, text, text, timestamptz
) to zeus_http;
grant execute on function zeus_private.consume_federated_login_transaction(uuid, bytea) to zeus_http;
grant execute on function zeus_private.resolve_federated_identity(
  uuid, text, uuid, text, text, text, text, boolean, jsonb, text[]
) to zeus_http;
grant execute on function zeus_private.list_user_organizations(uuid, uuid) to zeus_http;
grant execute on function zeus_private.accept_organization_invitation(uuid, uuid, bytea) to zeus_http;
grant execute on function zeus_private.list_user_federated_identities(uuid, uuid) to zeus_http;
grant execute on function zeus_private.unlink_federated_identity(uuid, uuid, uuid) to zeus_http;
grant execute on function zeus_private.set_initial_native_password(uuid, uuid, text) to zeus_http;
grant execute on function zeus_private.user_has_native_password(uuid, uuid) to zeus_http;
