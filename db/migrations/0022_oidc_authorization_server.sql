-- Zeus OIDC authorization server state. Opaque credentials are stored only as digests.

create table oidc_clients (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  client_id text not null unique,
  name text not null,
  client_type text not null check (client_type in ('public', 'confidential')),
  client_secret_hash text,
  trusted boolean not null default false,
  allowed_scopes text[] not null default array[
    'openid', 'profile', 'email', 'zeus.organization', 'zeus.workspace'
  ],
  status text not null default 'active' check (status in ('active', 'revoked')),
  revision bigint not null default 1 check (revision > 0),
  created_by uuid not null references users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  revoked_at timestamptz,
  check (client_id ~ '^zoc_[A-Za-z0-9_-]{20,120}$'),
  check (btrim(name) <> '' and length(name) <= 120),
  check (
    (client_type = 'public' and client_secret_hash is null)
    or (client_type = 'confidential' and client_secret_hash like '$argon2id$%')
  ),
  check (cardinality(allowed_scopes) between 1 and 5),
  check ('openid' = any(allowed_scopes)),
  check (allowed_scopes <@ array[
    'openid', 'profile', 'email', 'zeus.organization', 'zeus.workspace'
  ]::text[]),
  check ((status = 'revoked') = (revoked_at is not null))
);
create index oidc_clients_organization_id_idx on oidc_clients (organization_id);
create index oidc_clients_list_idx
  on oidc_clients (organization_id, created_at desc, id desc);

create table oidc_client_redirect_uris (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  client_id uuid not null references oidc_clients(id) on delete cascade,
  uri_kind text not null check (uri_kind in ('authorization', 'post_logout')),
  redirect_uri text not null,
  created_at timestamptz not null default now(),
  unique (client_id, uri_kind, redirect_uri),
  check (length(redirect_uri) between 1 and 2048),
  check (redirect_uri = btrim(redirect_uri))
);
create index oidc_client_redirect_uris_organization_id_idx
  on oidc_client_redirect_uris (organization_id);
create index oidc_client_redirect_uris_client_id_idx
  on oidc_client_redirect_uris (client_id);

create table oidc_subjects (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  user_id uuid not null references users(id),
  subject uuid not null default uuidv4(),
  created_at timestamptz not null default now(),
  unique (organization_id, user_id),
  unique (organization_id, subject)
);
create index oidc_subjects_organization_id_idx on oidc_subjects (organization_id);
create index oidc_subjects_user_id_idx on oidc_subjects (user_id);

create table oidc_consents (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  client_id uuid not null references oidc_clients(id) on delete cascade,
  user_id uuid not null references users(id) on delete cascade,
  scopes text[] not null,
  granted_at timestamptz not null default now(),
  last_used_at timestamptz not null default now(),
  revoked_at timestamptz,
  unique (client_id, user_id),
  check (cardinality(scopes) between 1 and 5),
  check ('openid' = any(scopes)),
  check (scopes <@ array[
    'openid', 'profile', 'email', 'zeus.organization', 'zeus.workspace'
  ]::text[]),
  check (revoked_at is null or revoked_at >= granted_at)
);
create index oidc_consents_organization_id_idx on oidc_consents (organization_id);
create index oidc_consents_user_id_idx on oidc_consents (user_id);
create index oidc_consents_client_id_idx on oidc_consents (client_id);

create table oidc_authorization_transactions (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  client_id uuid not null references oidc_clients(id) on delete cascade,
  user_id uuid not null references users(id) on delete cascade,
  session_id uuid not null references web_sessions(id) on delete cascade,
  request_token_hash bytea not null unique,
  redirect_uri text not null,
  scopes text[] not null,
  state text,
  nonce text,
  code_challenge text not null,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  denied_at timestamptz,
  created_at timestamptz not null default now(),
  check (octet_length(request_token_hash) = 32),
  check (length(redirect_uri) between 1 and 2048),
  check (cardinality(scopes) between 1 and 5),
  check ('openid' = any(scopes)),
  check (length(code_challenge) = 43),
  check (expires_at > created_at),
  check (num_nonnulls(consumed_at, denied_at) <= 1)
);
create index oidc_authorization_transactions_organization_id_idx
  on oidc_authorization_transactions (organization_id);
create index oidc_authorization_transactions_client_id_idx
  on oidc_authorization_transactions (client_id);
create index oidc_authorization_transactions_user_id_idx
  on oidc_authorization_transactions (user_id);
create index oidc_authorization_transactions_expiry_idx
  on oidc_authorization_transactions (expires_at)
  where consumed_at is null and denied_at is null;

create table oidc_authorization_codes (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  client_id uuid not null references oidc_clients(id) on delete cascade,
  user_id uuid not null references users(id) on delete cascade,
  subject uuid not null,
  code_hash bytea not null unique,
  redirect_uri text not null,
  scopes text[] not null,
  nonce text,
  code_challenge text not null,
  auth_time timestamptz not null,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now(),
  check (octet_length(code_hash) = 32),
  check (length(redirect_uri) between 1 and 2048),
  check (cardinality(scopes) between 1 and 5),
  check ('openid' = any(scopes)),
  check (length(code_challenge) = 43),
  check (expires_at > created_at),
  check (consumed_at is null or consumed_at >= created_at)
);
create index oidc_authorization_codes_organization_id_idx
  on oidc_authorization_codes (organization_id);
create index oidc_authorization_codes_client_id_idx on oidc_authorization_codes (client_id);
create index oidc_authorization_codes_user_id_idx on oidc_authorization_codes (user_id);
create index oidc_authorization_codes_expiry_idx
  on oidc_authorization_codes (expires_at) where consumed_at is null;

create table oidc_refresh_token_families (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  client_id uuid not null references oidc_clients(id) on delete cascade,
  user_id uuid not null references users(id) on delete cascade,
  subject uuid not null,
  scopes text[] not null,
  auth_time timestamptz not null,
  status text not null default 'active' check (status in ('active', 'revoked', 'expired')),
  absolute_expires_at timestamptz not null,
  idle_expires_at timestamptz not null,
  revoked_at timestamptz,
  revoke_reason text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (cardinality(scopes) between 1 and 5),
  check ('openid' = any(scopes)),
  check (idle_expires_at <= absolute_expires_at),
  check (absolute_expires_at > created_at),
  check ((status = 'revoked') = (revoked_at is not null))
);
create index oidc_refresh_token_families_organization_id_idx
  on oidc_refresh_token_families (organization_id);
create index oidc_refresh_token_families_client_id_idx
  on oidc_refresh_token_families (client_id);
create index oidc_refresh_token_families_user_id_idx
  on oidc_refresh_token_families (user_id);
create index oidc_refresh_token_families_expiry_idx
  on oidc_refresh_token_families (idle_expires_at, absolute_expires_at)
  where status = 'active';

create table oidc_refresh_tokens (
  id uuid primary key default uuidv7(),
  family_id uuid not null references oidc_refresh_token_families(id) on delete cascade,
  token_hash bytea not null unique,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  revoked_at timestamptz,
  replaced_by_id uuid references oidc_refresh_tokens(id),
  created_at timestamptz not null default now(),
  check (octet_length(token_hash) = 32),
  check (expires_at > created_at),
  check (num_nonnulls(consumed_at, revoked_at) <= 1)
);
create index oidc_refresh_tokens_family_id_idx on oidc_refresh_tokens (family_id);
create index oidc_refresh_tokens_expiry_idx
  on oidc_refresh_tokens (expires_at) where consumed_at is null and revoked_at is null;

create table oidc_signing_keys (
  id uuid primary key default uuidv7(),
  key_id text not null unique,
  algorithm text not null default 'RS256' check (algorithm = 'RS256'),
  key_use text not null default 'sig' check (key_use = 'sig'),
  encrypted_private_key bytea not null,
  private_key_nonce bytea not null,
  envelope_key_id text not null,
  public_modulus text not null,
  public_exponent text not null,
  activates_at timestamptz not null,
  rotates_at timestamptz not null,
  public_expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  check (key_id ~ '^[A-Za-z0-9_-]{20,120}$'),
  check (octet_length(encrypted_private_key) > 0),
  check (octet_length(private_key_nonce) > 0),
  check (btrim(envelope_key_id) <> ''),
  check (btrim(public_modulus) <> '' and btrim(public_exponent) <> ''),
  check (activates_at <= created_at),
  check (rotates_at > created_at),
  check (public_expires_at > rotates_at)
);
create index oidc_signing_keys_rotation_idx on oidc_signing_keys (rotates_at desc);
create index oidc_signing_keys_public_idx on oidc_signing_keys (public_expires_at, created_at desc);

create table oidc_access_token_revocations (
  jwt_id text primary key,
  organization_id uuid not null references organizations(id),
  client_id uuid not null references oidc_clients(id) on delete cascade,
  user_id uuid not null references users(id) on delete cascade,
  expires_at timestamptz not null,
  revoked_at timestamptz not null default now(),
  check (length(jwt_id) between 1 and 255),
  check (expires_at > revoked_at)
);
create index oidc_access_token_revocations_organization_id_idx
  on oidc_access_token_revocations (organization_id);
create index oidc_access_token_revocations_client_id_idx
  on oidc_access_token_revocations (client_id);
create index oidc_access_token_revocations_user_id_idx
  on oidc_access_token_revocations (user_id);
create index oidc_access_token_revocations_expiry_idx
  on oidc_access_token_revocations (expires_at);

alter table oidc_clients enable row level security;
alter table oidc_clients force row level security;
create policy oidc_clients_tenant on oidc_clients
  using (organization_id = (select zeus_private.current_organization_id()))
  with check (organization_id = (select zeus_private.current_organization_id()));

alter table oidc_client_redirect_uris enable row level security;
alter table oidc_client_redirect_uris force row level security;
create policy oidc_client_redirect_uris_tenant on oidc_client_redirect_uris
  using (organization_id = (select zeus_private.current_organization_id()))
  with check (organization_id = (select zeus_private.current_organization_id()));

alter table oidc_subjects enable row level security;
alter table oidc_subjects force row level security;
create policy oidc_subjects_self on oidc_subjects
  for select using (user_id = (select zeus_private.current_user_id()));

alter table oidc_consents enable row level security;
alter table oidc_consents force row level security;
create policy oidc_consents_self on oidc_consents
  using (user_id = (select zeus_private.current_user_id()))
  with check (user_id = (select zeus_private.current_user_id()));

-- Protocol state never has a direct HTTP-role policy. SECURITY DEFINER functions below
-- expose only bounded, single-purpose transitions.
alter table oidc_authorization_transactions enable row level security;
alter table oidc_authorization_transactions force row level security;
alter table oidc_authorization_codes enable row level security;
alter table oidc_authorization_codes force row level security;
alter table oidc_refresh_token_families enable row level security;
alter table oidc_refresh_token_families force row level security;
alter table oidc_refresh_tokens enable row level security;
alter table oidc_refresh_tokens force row level security;
alter table oidc_signing_keys enable row level security;
alter table oidc_signing_keys force row level security;
alter table oidc_access_token_revocations enable row level security;
alter table oidc_access_token_revocations force row level security;

create or replace function zeus_private.load_oidc_client(target_client_id text)
returns table (
  id uuid,
  organization_id uuid,
  organization_name text,
  client_id text,
  name text,
  client_type text,
  client_secret_hash text,
  trusted boolean,
  allowed_scopes text[],
  redirect_uris text[],
  post_logout_redirect_uris text[]
)
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select c.id,
         c.organization_id,
         o.name,
         c.client_id,
         c.name,
         c.client_type,
         c.client_secret_hash,
         c.trusted,
         c.allowed_scopes,
         coalesce(array_agg(r.redirect_uri order by r.redirect_uri)
           filter (where r.uri_kind = 'authorization'), '{}'::text[]),
         coalesce(array_agg(r.redirect_uri order by r.redirect_uri)
           filter (where r.uri_kind = 'post_logout'), '{}'::text[])
  from public.oidc_clients c
  join public.organizations o on o.id = c.organization_id and o.status = 'active'
  left join public.oidc_client_redirect_uris r on r.client_id = c.id
  where c.client_id = target_client_id and c.status = 'active'
  group by c.id, o.name
$$;

create or replace function zeus_private.oidc_user_is_member(
  target_organization_id uuid,
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
    from public.organization_memberships m
    join public.users u on u.id = m.user_id and u.status = 'active'
    join public.web_sessions s
      on s.id = target_session_id
     and s.user_id = target_user_id
     and s.revoked_at is null
     and s.idle_expires_at > now()
     and s.absolute_expires_at > now()
    where m.organization_id = target_organization_id
      and m.user_id = target_user_id
      and m.status = 'active'
  )
$$;

create or replace function zeus_private.load_oidc_organization_policy(
  target_organization_id uuid,
  target_user_id uuid,
  target_session_id uuid
)
returns table (
  mfa_required boolean,
  federated_required boolean,
  required_provider_id uuid,
  organization_slug text,
  provider_slug text
)
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select p.mfa_required,
         p.federated_required,
         p.required_federated_provider_id,
         o.slug,
         fp.slug
  from public.organization_identity_policies p
  join public.organizations o
    on o.id = p.organization_id and o.status = 'active'
  left join public.federated_identity_providers fp
    on fp.id = p.required_federated_provider_id
   and fp.organization_id = p.organization_id
   and fp.enabled
  where p.organization_id = target_organization_id
    and zeus_private.oidc_user_is_member(
      target_organization_id, target_user_id, target_session_id
    )
$$;

create or replace function zeus_private.get_or_create_oidc_subject(
  target_organization_id uuid,
  target_user_id uuid
)
returns uuid
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  resolved_subject uuid;
begin
  if not exists (
    select 1 from public.organization_memberships m
    where m.organization_id = target_organization_id
      and m.user_id = target_user_id
      and m.status = 'active'
  ) then
    raise exception 'active organization membership is required' using errcode = '42501';
  end if;
  insert into public.oidc_subjects (organization_id, user_id)
  values (target_organization_id, target_user_id)
  on conflict (organization_id, user_id) do nothing;
  select s.subject into strict resolved_subject
  from public.oidc_subjects s
  where s.organization_id = target_organization_id and s.user_id = target_user_id;
  return resolved_subject;
end
$$;

create or replace function zeus_private.oidc_consent_covers(
  target_client_id uuid,
  target_user_id uuid,
  target_scopes text[]
)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select coalesce((
    select c.trusted or (
      co.revoked_at is null and co.scopes @> target_scopes
    )
    from public.oidc_clients c
    left join public.oidc_consents co
      on co.client_id = c.id and co.user_id = target_user_id
    where c.id = target_client_id
      and c.status = 'active'
      and c.allowed_scopes @> target_scopes
  ), false)
$$;

create or replace function zeus_private.create_oidc_authorization_transaction(
  target_organization_id uuid,
  target_client_id uuid,
  target_user_id uuid,
  target_session_id uuid,
  target_request_token_hash bytea,
  target_redirect_uri text,
  target_scopes text[],
  target_state text,
  target_nonce text,
  target_code_challenge text,
  target_expires_at timestamptz
)
returns uuid
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  transaction_id uuid;
begin
  if not zeus_private.oidc_user_is_member(
    target_organization_id, target_user_id, target_session_id
  ) then
    raise exception 'active organization membership is required' using errcode = '42501';
  end if;
  if not exists (
    select 1 from public.oidc_clients c
    join public.oidc_client_redirect_uris r on r.client_id = c.id
    where c.id = target_client_id
      and c.organization_id = target_organization_id
      and c.status = 'active'
      and c.allowed_scopes @> target_scopes
      and r.uri_kind = 'authorization'
      and r.redirect_uri = target_redirect_uri
  ) then
    raise exception 'OIDC request is not allowed' using errcode = '42501';
  end if;
  insert into public.oidc_authorization_transactions (
    organization_id, client_id, user_id, session_id, request_token_hash,
    redirect_uri, scopes, state, nonce, code_challenge, expires_at
  ) values (
    target_organization_id, target_client_id, target_user_id, target_session_id,
    target_request_token_hash, target_redirect_uri, target_scopes, target_state,
    target_nonce, target_code_challenge, target_expires_at
  ) returning id into transaction_id;
  return transaction_id;
end
$$;

create or replace function zeus_private.load_oidc_authorization_transaction(
  target_transaction_id uuid,
  target_user_id uuid,
  target_session_id uuid
)
returns table (
  transaction_id uuid,
  organization_id uuid,
  organization_name text,
  client_id uuid,
  client_public_id text,
  client_name text,
  redirect_uri text,
  scopes text[],
  state text,
  nonce text,
  code_challenge text,
  auth_time timestamptz
)
language sql
security definer
set search_path = pg_catalog, public
as $$
  select t.id,
         t.organization_id,
         o.name,
         t.client_id,
         c.client_id,
         c.name,
         t.redirect_uri,
         t.scopes,
         t.state,
         t.nonce,
         t.code_challenge,
         s.authenticated_at
  from public.oidc_authorization_transactions t
  join public.oidc_clients c on c.id = t.client_id and c.status = 'active'
  join public.organizations o on o.id = t.organization_id and o.status = 'active'
  join public.web_sessions s
    on s.id = t.session_id
   and s.user_id = t.user_id
   and s.revoked_at is null
   and s.idle_expires_at > now()
   and s.absolute_expires_at > now()
  where t.id = target_transaction_id
    and t.user_id = target_user_id
    and t.session_id = target_session_id
    and t.expires_at > now()
    and t.consumed_at is null
    and t.denied_at is null
$$;

create or replace function zeus_private.consume_oidc_authorization_transaction(
  target_transaction_id uuid,
  target_user_id uuid,
  target_session_id uuid,
  target_approved boolean,
  target_code_hash bytea
)
returns table (
  disposition text,
  organization_id uuid,
  client_id uuid,
  client_public_id text,
  redirect_uri text,
  scopes text[],
  state text,
  nonce text,
  code_challenge text,
  subject uuid,
  auth_time timestamptz
)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  pending public.oidc_authorization_transactions%rowtype;
  resolved_subject uuid;
  resolved_auth_time timestamptz;
  resolved_client_public_id text;
begin
  select t.* into pending
  from public.oidc_authorization_transactions t
  where t.id = target_transaction_id
    and t.user_id = target_user_id
    and t.session_id = target_session_id
    and t.expires_at > now()
    and t.consumed_at is null
    and t.denied_at is null
  for update;
  if not found then
    return;
  end if;
  select s.authenticated_at into resolved_auth_time
  from public.web_sessions s
  where s.id = pending.session_id
    and s.user_id = pending.user_id
    and s.revoked_at is null
    and s.idle_expires_at > now()
    and s.absolute_expires_at > now();
  if resolved_auth_time is null then
    return;
  end if;
  select c.client_id into resolved_client_public_id
  from public.oidc_clients c
  where c.id = pending.client_id and c.status = 'active';
  if resolved_client_public_id is null then
    return;
  end if;
  if not target_approved then
    update public.oidc_authorization_transactions
    set denied_at = now() where id = pending.id;
    return query select 'denied'::text, pending.organization_id, pending.client_id,
      resolved_client_public_id, pending.redirect_uri, pending.scopes, pending.state,
      pending.nonce, pending.code_challenge, null::uuid, resolved_auth_time;
    return;
  end if;
  if target_code_hash is null or octet_length(target_code_hash) <> 32 then
    raise exception 'authorization code hash is invalid' using errcode = '22023';
  end if;
  resolved_subject := zeus_private.get_or_create_oidc_subject(
    pending.organization_id, pending.user_id
  );
  insert into public.oidc_consents (
    organization_id, client_id, user_id, scopes, granted_at, last_used_at, revoked_at
  ) values (
    pending.organization_id, pending.client_id, pending.user_id,
    pending.scopes, now(), now(), null
  ) on conflict on constraint oidc_consents_client_id_user_id_key do update
    set scopes = excluded.scopes,
        granted_at = now(),
        last_used_at = now(),
        revoked_at = null;
  insert into public.oidc_authorization_codes (
    organization_id, client_id, user_id, subject, code_hash, redirect_uri,
    scopes, nonce, code_challenge, auth_time, expires_at
  ) values (
    pending.organization_id, pending.client_id, pending.user_id, resolved_subject,
    target_code_hash, pending.redirect_uri, pending.scopes, pending.nonce,
    pending.code_challenge, resolved_auth_time, now() + interval '5 minutes'
  );
  update public.oidc_authorization_transactions
  set consumed_at = now() where id = pending.id;
  return query select 'approved'::text, pending.organization_id, pending.client_id,
    resolved_client_public_id, pending.redirect_uri, pending.scopes, pending.state,
    pending.nonce, pending.code_challenge, resolved_subject, resolved_auth_time;
end
$$;

create or replace function zeus_private.issue_oidc_authorization_code(
  target_organization_id uuid,
  target_client_id uuid,
  target_user_id uuid,
  target_session_id uuid,
  target_code_hash bytea,
  target_redirect_uri text,
  target_scopes text[],
  target_nonce text,
  target_code_challenge text
)
returns table (subject uuid, auth_time timestamptz)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  resolved_subject uuid;
  resolved_auth_time timestamptz;
begin
  if not zeus_private.oidc_user_is_member(
    target_organization_id, target_user_id, target_session_id
  ) then
    raise exception 'active organization membership is required' using errcode = '42501';
  end if;
  if not zeus_private.oidc_consent_covers(target_client_id, target_user_id, target_scopes) then
    raise exception 'consent is required' using errcode = '42501';
  end if;
  select s.authenticated_at into strict resolved_auth_time
  from public.web_sessions s where s.id = target_session_id and s.user_id = target_user_id;
  resolved_subject := zeus_private.get_or_create_oidc_subject(
    target_organization_id, target_user_id
  );
  insert into public.oidc_authorization_codes (
    organization_id, client_id, user_id, subject, code_hash, redirect_uri,
    scopes, nonce, code_challenge, auth_time, expires_at
  ) values (
    target_organization_id, target_client_id, target_user_id, resolved_subject,
    target_code_hash, target_redirect_uri, target_scopes, target_nonce,
    target_code_challenge, resolved_auth_time, now() + interval '5 minutes'
  );
  update public.oidc_consents set last_used_at = now()
  where client_id = target_client_id and user_id = target_user_id and revoked_at is null;
  return query select resolved_subject, resolved_auth_time;
end
$$;

create or replace function zeus_private.claim_oidc_authorization_code(
  target_code_hash bytea,
  target_client_id uuid,
  target_redirect_uri text
)
returns table (
  organization_id uuid,
  client_id uuid,
  user_id uuid,
  subject uuid,
  scopes text[],
  nonce text,
  code_challenge text,
  auth_time timestamptz
)
language sql
security definer
set search_path = pg_catalog, public
as $$
  update public.oidc_authorization_codes c
  set consumed_at = now()
  where c.code_hash = target_code_hash
    and c.client_id = target_client_id
    and c.redirect_uri = target_redirect_uri
    and c.consumed_at is null
    and c.expires_at > now()
  returning c.organization_id, c.client_id, c.user_id, c.subject, c.scopes,
            c.nonce, c.code_challenge, c.auth_time
$$;

create or replace function zeus_private.create_oidc_refresh_family(
  target_organization_id uuid,
  target_client_id uuid,
  target_user_id uuid,
  target_subject uuid,
  target_scopes text[],
  target_auth_time timestamptz,
  target_token_hash bytea
)
returns uuid
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  new_family_id uuid;
begin
  insert into public.oidc_refresh_token_families (
    organization_id, client_id, user_id, subject, scopes, auth_time,
    absolute_expires_at, idle_expires_at
  ) values (
    target_organization_id, target_client_id, target_user_id, target_subject,
    target_scopes, target_auth_time, now() + interval '30 days', now() + interval '7 days'
  ) returning id into new_family_id;
  insert into public.oidc_refresh_tokens (family_id, token_hash, expires_at)
  values (new_family_id, target_token_hash, now() + interval '7 days');
  return new_family_id;
end
$$;

create or replace function zeus_private.rotate_oidc_refresh_token(
  target_token_hash bytea,
  target_client_id uuid,
  target_new_token_hash bytea
)
returns table (
  disposition text,
  organization_id uuid,
  client_id uuid,
  user_id uuid,
  subject uuid,
  scopes text[],
  auth_time timestamptz
)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  old_token public.oidc_refresh_tokens%rowtype;
  family public.oidc_refresh_token_families%rowtype;
  new_token_id uuid;
  next_expiry timestamptz;
begin
  select t.* into old_token
  from public.oidc_refresh_tokens t
  where t.token_hash = target_token_hash
  for update;
  if not found then
    return query select 'invalid'::text, null::uuid, null::uuid, null::uuid,
      null::uuid, null::text[], null::timestamptz;
    return;
  end if;
  select f.* into strict family
  from public.oidc_refresh_token_families f
  where f.id = old_token.family_id
  for update;
  if family.client_id <> target_client_id then
    return query select 'invalid'::text, null::uuid, null::uuid, null::uuid,
      null::uuid, null::text[], null::timestamptz;
    return;
  end if;
  if old_token.consumed_at is not null or old_token.revoked_at is not null then
    update public.oidc_refresh_token_families
    set status = 'revoked', revoked_at = now(), revoke_reason = 'refresh_token_replay',
        updated_at = now()
    where id = family.id and status <> 'revoked';
    update public.oidc_refresh_tokens set revoked_at = coalesce(revoked_at, now())
    where family_id = family.id and consumed_at is null;
    return query select 'replay'::text, family.organization_id, family.client_id,
      family.user_id, family.subject, family.scopes, family.auth_time;
    return;
  end if;
  if family.status <> 'active'
     or family.absolute_expires_at <= now()
     or family.idle_expires_at <= now()
     or old_token.expires_at <= now() then
    update public.oidc_refresh_token_families
    set status = case when status = 'active' then 'expired' else status end,
        updated_at = now()
    where id = family.id;
    return query select 'invalid'::text, family.organization_id, family.client_id,
      family.user_id, family.subject, family.scopes, family.auth_time;
    return;
  end if;
  next_expiry := least(now() + interval '7 days', family.absolute_expires_at);
  insert into public.oidc_refresh_tokens (family_id, token_hash, expires_at)
  values (family.id, target_new_token_hash, next_expiry)
  returning id into new_token_id;
  update public.oidc_refresh_tokens
  set consumed_at = now(), replaced_by_id = new_token_id
  where id = old_token.id;
  update public.oidc_refresh_token_families
  set idle_expires_at = next_expiry, updated_at = now()
  where id = family.id;
  return query select 'rotated'::text, family.organization_id, family.client_id,
    family.user_id, family.subject, family.scopes, family.auth_time;
end
$$;

create or replace function zeus_private.revoke_oidc_refresh_token(
  target_token_hash bytea,
  target_client_id uuid,
  target_reason text
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  target_family_id uuid;
begin
  select t.family_id into target_family_id
  from public.oidc_refresh_tokens t
  join public.oidc_refresh_token_families f on f.id = t.family_id
  where t.token_hash = target_token_hash and f.client_id = target_client_id;
  if target_family_id is null then
    return false;
  end if;
  update public.oidc_refresh_token_families
  set status = 'revoked', revoked_at = coalesce(revoked_at, now()),
      revoke_reason = coalesce(revoke_reason, target_reason), updated_at = now()
  where id = target_family_id;
  update public.oidc_refresh_tokens
  set revoked_at = coalesce(revoked_at, now())
  where family_id = target_family_id and consumed_at is null;
  return true;
end
$$;

create or replace function zeus_private.install_oidc_signing_key(
  target_key_id text,
  target_encrypted_private_key bytea,
  target_private_key_nonce bytea,
  target_envelope_key_id text,
  target_public_modulus text,
  target_public_exponent text
)
returns table (
  key_id text,
  encrypted_private_key bytea,
  private_key_nonce bytea,
  envelope_key_id text,
  public_modulus text,
  public_exponent text,
  rotates_at timestamptz,
  public_expires_at timestamptz
)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('zeus.oidc.signing-key', 0));
  return query
  select k.key_id, k.encrypted_private_key, k.private_key_nonce, k.envelope_key_id,
         k.public_modulus, k.public_exponent, k.rotates_at, k.public_expires_at
  from public.oidc_signing_keys k
  where k.rotates_at > now()
  order by k.created_at desc limit 1;
  if found then
    return;
  end if;
  insert into public.oidc_signing_keys (
    key_id, encrypted_private_key, private_key_nonce, envelope_key_id,
    public_modulus, public_exponent, activates_at, rotates_at, public_expires_at
  ) values (
    target_key_id, target_encrypted_private_key, target_private_key_nonce,
    target_envelope_key_id, target_public_modulus, target_public_exponent,
    now(), now() + interval '90 days', now() + interval '97 days'
  );
  return query
  select k.key_id, k.encrypted_private_key, k.private_key_nonce, k.envelope_key_id,
         k.public_modulus, k.public_exponent, k.rotates_at, k.public_expires_at
  from public.oidc_signing_keys k where k.key_id = target_key_id;
end
$$;

create or replace function zeus_private.load_current_oidc_signing_key()
returns table (
  key_id text,
  encrypted_private_key bytea,
  private_key_nonce bytea,
  envelope_key_id text,
  public_modulus text,
  public_exponent text,
  rotates_at timestamptz,
  public_expires_at timestamptz
)
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select k.key_id, k.encrypted_private_key, k.private_key_nonce, k.envelope_key_id,
         k.public_modulus, k.public_exponent, k.rotates_at, k.public_expires_at
  from public.oidc_signing_keys k
  where k.rotates_at > now()
  order by k.created_at desc limit 1
$$;

create or replace function zeus_private.list_oidc_public_keys()
returns table (
  key_id text,
  algorithm text,
  key_use text,
  public_modulus text,
  public_exponent text
)
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select k.key_id, k.algorithm, k.key_use, k.public_modulus, k.public_exponent
  from public.oidc_signing_keys k
  where k.public_expires_at > now() and k.activates_at <= now()
  order by k.created_at desc
$$;

create or replace function zeus_private.cleanup_oidc_protocol_state()
returns void
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  delete from public.oidc_authorization_transactions
  where expires_at < now() - interval '1 day';

  delete from public.oidc_authorization_codes
  where expires_at < now() - interval '1 day';

  delete from public.oidc_refresh_token_families
  where absolute_expires_at < now() - interval '7 days'
     or (status <> 'active' and updated_at < now() - interval '7 days');

  delete from public.oidc_access_token_revocations
  where expires_at < now();

  delete from public.oidc_signing_keys
  where public_expires_at < now();
end
$$;

create or replace function zeus_private.load_oidc_userinfo(
  target_user_id uuid,
  target_organization_id uuid
)
returns table (
  email text,
  email_verified boolean,
  display_name text,
  organization_name text,
  workspace_ids uuid[]
)
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select u.email,
         u.email_verified_at is not null,
         u.display_name,
         o.name,
         coalesce(array_agg(wm.workspace_id order by wm.workspace_id)
           filter (where wm.workspace_id is not null), '{}'::uuid[])
  from public.users u
  join public.organization_memberships om
    on om.user_id = u.id
   and om.organization_id = target_organization_id
   and om.status = 'active'
  join public.organizations o on o.id = om.organization_id and o.status = 'active'
  left join public.workspace_memberships wm
    on wm.user_id = u.id
   and wm.organization_id = target_organization_id
   and wm.status = 'active'
  where u.id = target_user_id and u.status = 'active'
  group by u.id, o.id
$$;

create or replace function zeus_private.list_oidc_user_grants(target_user_id uuid)
returns table (
  client_id uuid,
  client_public_id text,
  client_name text,
  organization_id uuid,
  organization_name text,
  scopes text[],
  granted_at timestamptz,
  last_used_at timestamptz
)
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select c.id,
         c.client_id,
         c.name,
         c.organization_id,
         o.name,
         co.scopes,
         co.granted_at,
         co.last_used_at
  from public.oidc_consents co
  join public.oidc_clients c on c.id = co.client_id and c.status = 'active'
  join public.organizations o on o.id = c.organization_id
  where co.user_id = target_user_id and co.revoked_at is null
  order by co.last_used_at desc, co.id desc
$$;

create or replace function zeus_private.revoke_oidc_user_grant(
  target_user_id uuid,
  target_client_id uuid
)
returns boolean
language sql
security definer
set search_path = pg_catalog, public
as $$
  with revoked_consent as (
    update public.oidc_consents co
    set revoked_at = now()
    where co.user_id = target_user_id
      and co.client_id = target_client_id
      and co.revoked_at is null
    returning co.client_id
  ), revoked_families as (
    update public.oidc_refresh_token_families f
    set status = 'revoked', revoked_at = now(), revoke_reason = 'consent_revoked',
        updated_at = now()
    where f.user_id = target_user_id
      and f.client_id = target_client_id
      and f.status = 'active'
    returning f.id
  ), revoked_tokens as (
    update public.oidc_refresh_tokens t
    set revoked_at = coalesce(t.revoked_at, now())
    where t.family_id in (select id from revoked_families)
      and t.consumed_at is null
    returning t.id
  )
  select exists (select 1 from revoked_consent)
$$;

create or replace function zeus_private.record_oidc_access_revocation(
  target_jwt_id text,
  target_organization_id uuid,
  target_client_id uuid,
  target_user_id uuid,
  target_expires_at timestamptz
)
returns void
language sql
security definer
set search_path = pg_catalog, public
as $$
  insert into public.oidc_access_token_revocations (
    jwt_id, organization_id, client_id, user_id, expires_at
  ) values (
    target_jwt_id, target_organization_id, target_client_id, target_user_id, target_expires_at
  ) on conflict (jwt_id) do nothing
$$;

create or replace function zeus_private.oidc_access_token_is_revoked(target_jwt_id text)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select exists (
    select 1 from public.oidc_access_token_revocations r
    where r.jwt_id = target_jwt_id and r.expires_at > now()
  )
$$;
