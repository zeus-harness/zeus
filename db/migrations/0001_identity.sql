create schema if not exists zeus_private;
revoke all on schema zeus_private from public;

create or replace function zeus_private.current_user_id()
returns uuid
language sql
stable
set search_path = ''
as $$
  select nullif(current_setting('zeus.user_id', true), '')::uuid
$$;

create or replace function zeus_private.current_organization_id()
returns uuid
language sql
stable
set search_path = ''
as $$
  select nullif(current_setting('zeus.organization_id', true), '')::uuid
$$;

create or replace function zeus_private.current_workspace_id()
returns uuid
language sql
stable
set search_path = ''
as $$
  select nullif(current_setting('zeus.workspace_id', true), '')::uuid
$$;

create or replace function zeus_private.reject_mutation()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  raise exception '% is append-only', tg_table_name using errcode = '55000';
end
$$;

create table organizations (
  id uuid primary key default uuidv7(),
  slug text not null,
  name text not null,
  status text not null default 'active' check (status in ('active', 'suspended', 'archived')),
  revision bigint not null default 1 check (revision > 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  archived_at timestamptz,
  check (slug = lower(slug)),
  check (slug ~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$')
);
create unique index organizations_slug_unique on organizations (lower(slug));

create table workspaces (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  slug text not null,
  name text not null,
  status text not null default 'active' check (status in ('active', 'archived')),
  revision bigint not null default 1 check (revision > 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  archived_at timestamptz,
  unique (organization_id, slug),
  check (slug = lower(slug)),
  check (slug ~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$')
);
create index workspaces_organization_id_idx on workspaces (organization_id);
create index workspaces_list_idx on workspaces (organization_id, created_at desc, id desc);

create table users (
  id uuid primary key default uuidv7(),
  email text not null,
  display_name text not null,
  status text not null default 'active' check (status in ('active', 'disabled')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  last_seen_at timestamptz
);
create unique index users_email_unique on users (lower(email));

create table oidc_providers (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  issuer_url text not null,
  client_id text not null,
  encrypted_client_secret bytea not null,
  secret_nonce bytea not null,
  key_id text not null,
  scopes text[] not null default array['openid', 'profile', 'email'],
  group_claim text,
  enabled boolean not null default true,
  revision bigint not null default 1 check (revision > 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (organization_id, issuer_url)
);
create index oidc_providers_organization_id_idx on oidc_providers (organization_id);

create table oidc_identities (
  id uuid primary key default uuidv7(),
  user_id uuid not null references users(id),
  provider_id uuid not null references oidc_providers(id),
  issuer text not null,
  subject text not null,
  claims jsonb not null default '{}'::jsonb check (jsonb_typeof(claims) = 'object'),
  created_at timestamptz not null default now(),
  last_login_at timestamptz not null default now(),
  unique (issuer, subject)
);
create index oidc_identities_user_id_idx on oidc_identities (user_id);
create index oidc_identities_provider_id_idx on oidc_identities (provider_id);

create table oidc_group_mappings (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  provider_id uuid not null references oidc_providers(id),
  group_value text not null,
  organization_role text check (organization_role in ('owner', 'admin', 'member', 'auditor')),
  workspace_id uuid references workspaces(id),
  workspace_role text check (workspace_role in ('admin', 'builder', 'operator', 'viewer')),
  created_at timestamptz not null default now(),
  unique (provider_id, group_value, workspace_id),
  check (
    (organization_role is not null and workspace_id is null and workspace_role is null)
    or (organization_role is null and workspace_id is not null and workspace_role is not null)
  )
);
create index oidc_group_mappings_organization_id_idx on oidc_group_mappings (organization_id);
create index oidc_group_mappings_provider_id_idx on oidc_group_mappings (provider_id);
create index oidc_group_mappings_workspace_id_idx on oidc_group_mappings (workspace_id);

create table organization_memberships (
  organization_id uuid not null references organizations(id),
  user_id uuid not null references users(id),
  role text not null check (role in ('owner', 'admin', 'member', 'auditor')),
  status text not null default 'active' check (status in ('active', 'suspended')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (organization_id, user_id)
);
create index organization_memberships_user_id_idx on organization_memberships (user_id);

create table workspace_memberships (
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  user_id uuid not null references users(id),
  role text not null check (role in ('admin', 'builder', 'operator', 'viewer')),
  status text not null default 'active' check (status in ('active', 'suspended')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (workspace_id, user_id)
);
create index workspace_memberships_organization_id_idx on workspace_memberships (organization_id);
create index workspace_memberships_user_id_idx on workspace_memberships (user_id);

create table web_sessions (
  id uuid primary key default uuidv7(),
  user_id uuid not null references users(id),
  organization_id uuid not null references organizations(id),
  workspace_id uuid references workspaces(id),
  token_hash bytea not null unique,
  created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  expires_at timestamptz not null,
  revoked_at timestamptz,
  check (expires_at > created_at)
);
create index web_sessions_user_id_idx on web_sessions (user_id);
create index web_sessions_organization_id_idx on web_sessions (organization_id);
create index web_sessions_workspace_id_idx on web_sessions (workspace_id);
create index web_sessions_active_idx on web_sessions (expires_at) where revoked_at is null;

create table service_accounts (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid references workspaces(id),
  name text not null,
  token_prefix text not null unique,
  token_hash text not null,
  scopes text[] not null default '{}',
  created_at timestamptz not null default now(),
  expires_at timestamptz,
  revoked_at timestamptz,
  last_used_at timestamptz
);
create index service_accounts_organization_id_idx on service_accounts (organization_id);
create index service_accounts_workspace_id_idx on service_accounts (workspace_id);

create table audit_events (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid references workspaces(id),
  actor_kind text not null check (actor_kind in ('user', 'service_account', 'agent', 'system')),
  actor_id uuid,
  action text not null,
  target_type text not null,
  target_id uuid,
  request_id uuid,
  metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object'),
  occurred_at timestamptz not null default now()
);
create index audit_events_organization_id_idx on audit_events (organization_id);
create index audit_events_workspace_id_idx on audit_events (workspace_id);
create index audit_events_list_idx on audit_events (organization_id, workspace_id, occurred_at desc, id desc);
create index audit_events_actor_idx on audit_events (organization_id, actor_kind, actor_id, occurred_at desc);

create trigger audit_events_append_only
before update or delete on audit_events
for each row execute function zeus_private.reject_mutation();
