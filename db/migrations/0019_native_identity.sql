-- Native Zeus accounts, user-level sessions, invitations, and durable identity jobs.

alter table users
  drop constraint users_status_check;

alter table users
  add column email_verified_at timestamptz,
  add column disabled_at timestamptz,
  add column anonymization_requested_at timestamptz,
  add column anonymized_at timestamptz,
  add constraint users_status_check
    check (status in (
      'pending_verification', 'active', 'disabled', 'anonymization_pending', 'anonymized'
    )),
  add constraint users_anonymized_state_check
    check (
      (status = 'anonymized' and anonymized_at is not null)
      or (status <> 'anonymized' and anonymized_at is null)
    );

update users
set email = lower(btrim(email)),
    email_verified_at = coalesce(email_verified_at, created_at)
where true;

alter table users
  add constraint users_email_canonical_check
    check (
      email = lower(btrim(email))
      and octet_length(email) = length(email)
      and email ~ '^[!-~]+@[!-~]+$'
      and length(email) between 3 and 320
    );

create table user_password_credentials (
  user_id uuid primary key references users(id) on delete cascade,
  password_hash text not null,
  password_changed_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (password_hash like '$argon2id$%')
);

create table user_totp_credentials (
  user_id uuid primary key references users(id) on delete cascade,
  encrypted_secret bytea not null,
  secret_nonce bytea not null,
  key_id text not null,
  last_used_counter bigint,
  confirmed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (octet_length(encrypted_secret) > 0),
  check (octet_length(secret_nonce) > 0),
  check (btrim(key_id) <> ''),
  check (last_used_counter is null or last_used_counter >= 0)
);

create table user_recovery_codes (
  id uuid primary key default uuidv7(),
  user_id uuid not null references users(id) on delete cascade,
  code_hash bytea not null,
  used_at timestamptz,
  created_at timestamptz not null default now(),
  unique (user_id, code_hash),
  check (octet_length(code_hash) = 32),
  check (used_at is null or used_at >= created_at)
);
create index user_recovery_codes_user_id_idx on user_recovery_codes (user_id);
create index user_recovery_codes_active_idx
  on user_recovery_codes (user_id, created_at desc)
  where used_at is null;

create table platform_role_assignments (
  user_id uuid not null references users(id) on delete cascade,
  role text not null check (role = 'platform_admin'),
  assigned_by uuid references users(id),
  assigned_at timestamptz not null default now(),
  revoked_at timestamptz,
  primary key (user_id, role),
  check (revoked_at is null or revoked_at >= assigned_at)
);
create index platform_role_assignments_assigned_by_idx
  on platform_role_assignments (assigned_by);
create index platform_role_assignments_active_idx
  on platform_role_assignments (role, user_id)
  where revoked_at is null;

create table system_identity_settings (
  singleton boolean primary key default true check (singleton),
  registration_mode text not null default 'invite_only'
    check (registration_mode in ('open', 'invite_only', 'disabled')),
  revision bigint not null default 1 check (revision > 0),
  updated_by uuid references users(id),
  updated_at timestamptz not null default now()
);
insert into system_identity_settings (singleton) values (true);

create table organization_identity_policies (
  organization_id uuid primary key references organizations(id),
  mfa_required boolean not null default false,
  revision bigint not null default 1 check (revision > 0),
  updated_by uuid references users(id),
  updated_at timestamptz not null default now()
);

create table email_verification_tokens (
  id uuid primary key default uuidv7(),
  user_id uuid not null references users(id) on delete cascade,
  token_hash bytea not null unique,
  email text not null,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now(),
  check (octet_length(token_hash) = 32),
  check (email = lower(btrim(email)) and length(email) between 3 and 320),
  check (expires_at > created_at),
  check (consumed_at is null or consumed_at >= created_at)
);
create index email_verification_tokens_user_id_idx on email_verification_tokens (user_id);
create index email_verification_tokens_active_idx
  on email_verification_tokens (user_id, expires_at)
  where consumed_at is null;

create table password_reset_tokens (
  id uuid primary key default uuidv7(),
  user_id uuid not null references users(id) on delete cascade,
  token_hash bytea not null unique,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now(),
  check (octet_length(token_hash) = 32),
  check (expires_at > created_at),
  check (consumed_at is null or consumed_at >= created_at)
);
create index password_reset_tokens_user_id_idx on password_reset_tokens (user_id);
create index password_reset_tokens_active_idx
  on password_reset_tokens (user_id, expires_at)
  where consumed_at is null;

create table organization_invitations (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  invited_by uuid not null references users(id),
  accepted_by uuid references users(id),
  email text not null,
  organization_role text not null
    check (organization_role in ('owner', 'admin', 'member', 'auditor')),
  token_hash bytea not null unique,
  status text not null default 'pending'
    check (status in ('pending', 'accepted', 'revoked', 'expired')),
  expires_at timestamptz not null,
  accepted_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (email = lower(btrim(email)) and length(email) between 3 and 320),
  check (octet_length(token_hash) = 32),
  check (expires_at > created_at),
  check ((status = 'accepted') = (accepted_at is not null)),
  check ((status = 'revoked') = (revoked_at is not null)),
  check (accepted_at is null or accepted_at >= created_at),
  check (revoked_at is null or revoked_at >= created_at)
);
create index organization_invitations_organization_id_idx
  on organization_invitations (organization_id);
create index organization_invitations_invited_by_idx
  on organization_invitations (invited_by);
create index organization_invitations_accepted_by_idx
  on organization_invitations (accepted_by);
create index organization_invitations_email_idx
  on organization_invitations (email, created_at desc);
create index organization_invitations_pending_idx
  on organization_invitations (organization_id, expires_at, id)
  where status = 'pending';

create table organization_invitation_workspaces (
  invitation_id uuid not null references organization_invitations(id) on delete cascade,
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  workspace_role text not null check (workspace_role in ('admin', 'builder', 'operator', 'viewer')),
  primary key (invitation_id, workspace_id)
);
create index organization_invitation_workspaces_organization_id_idx
  on organization_invitation_workspaces (organization_id);
create index organization_invitation_workspaces_workspace_id_idx
  on organization_invitation_workspaces (workspace_id);

create table email_outbox (
  id uuid primary key default uuidv7(),
  message_kind text not null,
  recipient_email text not null,
  encrypted_subject bytea not null,
  subject_nonce bytea not null,
  encrypted_body bytea not null,
  body_nonce bytea not null,
  key_id text not null,
  status text not null default 'queued'
    check (status in ('queued', 'sending', 'sent', 'failed', 'canceled')),
  available_at timestamptz not null default now(),
  lease_owner text,
  lease_expires_at timestamptz,
  fence_token bigint not null default 0 check (fence_token >= 0),
  attempt_count integer not null default 0 check (attempt_count >= 0),
  provider_message_id text,
  last_error_code text,
  sent_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (recipient_email = lower(btrim(recipient_email)) and length(recipient_email) between 3 and 320),
  check (octet_length(encrypted_subject) > 0),
  check (octet_length(subject_nonce) > 0),
  check (octet_length(encrypted_body) > 0),
  check (octet_length(body_nonce) > 0),
  check (btrim(key_id) <> ''),
  check ((lease_owner is null) = (lease_expires_at is null)),
  check (sent_at is null or sent_at >= created_at)
);
create index email_outbox_claim_idx
  on email_outbox (available_at, created_at, id)
  where status = 'queued';
create index email_outbox_lease_idx
  on email_outbox (lease_expires_at)
  where status = 'sending';

create table security_events (
  id uuid primary key default uuidv7(),
  organization_id uuid references organizations(id),
  workspace_id uuid references workspaces(id),
  user_id uuid references users(id),
  actor_user_id uuid references users(id),
  event_type text not null,
  outcome text not null check (outcome in ('success', 'failure', 'blocked', 'unknown')),
  request_id uuid,
  source_ip_hash bytea,
  user_agent_hash bytea,
  metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object'),
  occurred_at timestamptz not null default now(),
  check (source_ip_hash is null or octet_length(source_ip_hash) = 32),
  check (user_agent_hash is null or octet_length(user_agent_hash) = 32)
);
create index security_events_organization_id_idx on security_events (organization_id);
create index security_events_workspace_id_idx on security_events (workspace_id);
create index security_events_user_id_idx on security_events (user_id);
create index security_events_actor_user_id_idx on security_events (actor_user_id);
create index security_events_list_idx on security_events (occurred_at desc, id desc);
create index security_events_user_list_idx
  on security_events (user_id, occurred_at desc, id desc);
create trigger security_events_append_only
before update or delete on security_events
for each row execute function zeus_private.reject_mutation();

create table auth_throttles (
  throttle_kind text not null,
  key_hash bytea not null,
  window_started_at timestamptz not null,
  window_seconds integer not null check (window_seconds between 1 and 86400),
  attempt_count integer not null default 0 check (attempt_count >= 0),
  blocked_until timestamptz,
  updated_at timestamptz not null default now(),
  primary key (throttle_kind, key_hash, window_started_at),
  check (octet_length(key_hash) = 32),
  check (btrim(throttle_kind) <> '')
);
create index auth_throttles_cleanup_idx on auth_throttles (updated_at);
create index auth_throttles_blocked_idx
  on auth_throttles (blocked_until)
  where blocked_until is not null;

alter table web_sessions
  rename column organization_id to active_organization_id;
alter table web_sessions
  rename column workspace_id to active_workspace_id;
alter table web_sessions
  rename column expires_at to absolute_expires_at;

alter table web_sessions
  alter column active_organization_id drop not null,
  add column auth_methods text[] not null default array['federated'],
  add column authenticated_at timestamptz not null default now(),
  add column mfa_satisfied_at timestamptz,
  add column idle_expires_at timestamptz not null default (now() + interval '2 hours'),
  add column csrf_token_hash bytea,
  add column token_rotated_at timestamptz not null default now(),
  add constraint web_sessions_csrf_token_hash_check
    check (csrf_token_hash is null or octet_length(csrf_token_hash) = 32),
  add constraint web_sessions_auth_methods_check
    check (cardinality(auth_methods) > 0),
  add constraint web_sessions_context_check
    check (active_workspace_id is null or active_organization_id is not null),
  add constraint web_sessions_idle_expiry_check
    check (idle_expires_at > created_at and idle_expires_at <= absolute_expires_at),
  add constraint web_sessions_mfa_time_check
    check (mfa_satisfied_at is null or mfa_satisfied_at >= authenticated_at);

alter table web_sessions
  drop constraint web_sessions_check;
alter table web_sessions
  add constraint web_sessions_absolute_expiry_check
    check (absolute_expires_at > created_at);

drop policy web_sessions_self on web_sessions;
create policy web_sessions_self on web_sessions
  using (user_id = (select zeus_private.current_user_id()))
  with check (user_id = (select zeus_private.current_user_id()));

drop index web_sessions_organization_id_idx;
drop index web_sessions_workspace_id_idx;
drop index web_sessions_active_idx;
create index web_sessions_active_organization_id_idx
  on web_sessions (active_organization_id);
create index web_sessions_active_workspace_id_idx
  on web_sessions (active_workspace_id);
create index web_sessions_active_idx
  on web_sessions (idle_expires_at, absolute_expires_at)
  where revoked_at is null;

alter table user_password_credentials enable row level security;
alter table user_password_credentials force row level security;
create policy user_password_credentials_self on user_password_credentials
  using (user_id = (select zeus_private.current_user_id()))
  with check (user_id = (select zeus_private.current_user_id()));

alter table user_totp_credentials enable row level security;
alter table user_totp_credentials force row level security;
create policy user_totp_credentials_self on user_totp_credentials
  using (user_id = (select zeus_private.current_user_id()))
  with check (user_id = (select zeus_private.current_user_id()));

alter table user_recovery_codes enable row level security;
alter table user_recovery_codes force row level security;
create policy user_recovery_codes_self on user_recovery_codes
  using (user_id = (select zeus_private.current_user_id()))
  with check (user_id = (select zeus_private.current_user_id()));

alter table platform_role_assignments enable row level security;
alter table platform_role_assignments force row level security;
create policy platform_role_assignments_self on platform_role_assignments
  for select using (user_id = (select zeus_private.current_user_id()));

alter table organization_invitations enable row level security;
alter table organization_invitations force row level security;
create policy organization_invitations_tenant on organization_invitations
  using (organization_id = (select zeus_private.current_organization_id()))
  with check (organization_id = (select zeus_private.current_organization_id()));

alter table organization_identity_policies enable row level security;
alter table organization_identity_policies force row level security;
create policy organization_identity_policies_tenant on organization_identity_policies
  using (organization_id = (select zeus_private.current_organization_id()))
  with check (organization_id = (select zeus_private.current_organization_id()));

alter table organization_invitation_workspaces enable row level security;
alter table organization_invitation_workspaces force row level security;
create policy organization_invitation_workspaces_tenant on organization_invitation_workspaces
  using (organization_id = (select zeus_private.current_organization_id()))
  with check (organization_id = (select zeus_private.current_organization_id()));

alter table security_events enable row level security;
alter table security_events force row level security;
create policy security_events_tenant on security_events
  for select using (organization_id = (select zeus_private.current_organization_id()));

revoke all on table user_password_credentials,
  user_totp_credentials,
  user_recovery_codes,
  platform_role_assignments,
  system_identity_settings,
  email_verification_tokens,
  password_reset_tokens,
  organization_identity_policies,
  organization_invitations,
  organization_invitation_workspaces,
  email_outbox,
  security_events,
  auth_throttles
  from public;

revoke all on table user_password_credentials,
  user_totp_credentials,
  user_recovery_codes,
  platform_role_assignments,
  system_identity_settings,
  email_verification_tokens,
  password_reset_tokens,
  email_outbox,
  auth_throttles
  from zeus_http;

revoke insert, update, delete on table security_events from zeus_http;
