create table connections (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  name text not null,
  provider_kind text not null,
  configuration jsonb not null default '{}'::jsonb check (jsonb_typeof(configuration) = 'object'),
  revision bigint not null default 1 check (revision > 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  archived_at timestamptz,
  unique (workspace_id, name)
);
create index connections_organization_id_idx on connections (organization_id);
create index connections_workspace_id_idx on connections (workspace_id);
create index connections_list_idx on connections (organization_id, workspace_id, created_at desc, id desc);

create table connection_secrets (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  connection_id uuid not null references connections(id),
  secret_name text not null,
  ciphertext bytea not null,
  nonce bytea not null,
  key_id text not null,
  created_at timestamptz not null default now(),
  rotated_at timestamptz,
  unique (connection_id, secret_name)
);
create index connection_secrets_organization_id_idx on connection_secrets (organization_id);
create index connection_secrets_workspace_id_idx on connection_secrets (workspace_id);
create index connection_secrets_connection_id_idx on connection_secrets (connection_id);

create table model_profiles (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  connection_id uuid not null references connections(id),
  name text not null,
  provider_kind text not null default 'openai_compatible' check (provider_kind in ('openai_compatible')),
  base_url text not null,
  model text not null,
  configuration jsonb not null default '{}'::jsonb check (jsonb_typeof(configuration) = 'object'),
  revision bigint not null default 1 check (revision > 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  archived_at timestamptz,
  unique (workspace_id, name)
);
create index model_profiles_organization_id_idx on model_profiles (organization_id);
create index model_profiles_workspace_id_idx on model_profiles (workspace_id);
create index model_profiles_connection_id_idx on model_profiles (connection_id);

create table capability_definitions (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  registry_key text not null,
  display_name text not null,
  description text not null,
  input_schema jsonb not null check (jsonb_typeof(input_schema) = 'object'),
  output_schema jsonb not null check (jsonb_typeof(output_schema) = 'object'),
  idempotency_mode text not null check (idempotency_mode in ('required', 'supported', 'unavailable')),
  risk_level text not null check (risk_level in ('low', 'medium', 'high')),
  executor_key text not null,
  created_at timestamptz not null default now(),
  archived_at timestamptz,
  unique (organization_id, registry_key)
);
create index capability_definitions_organization_id_idx on capability_definitions (organization_id);

create table workspace_capabilities (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  capability_id uuid not null references capability_definitions(id),
  connection_id uuid references connections(id),
  enabled boolean not null default true,
  approval_required boolean not null default false,
  timeout_seconds integer not null default 60 check (timeout_seconds between 1 and 3600),
  policy jsonb not null default '{}'::jsonb check (jsonb_typeof(policy) = 'object'),
  revision bigint not null default 1 check (revision > 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (workspace_id, capability_id)
);
create index workspace_capabilities_organization_id_idx on workspace_capabilities (organization_id);
create index workspace_capabilities_workspace_id_idx on workspace_capabilities (workspace_id);
create index workspace_capabilities_capability_id_idx on workspace_capabilities (capability_id);
create index workspace_capabilities_connection_id_idx on workspace_capabilities (connection_id);

create table agents (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  name text not null,
  description text not null default '',
  active_version_id uuid,
  revision bigint not null default 1 check (revision > 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  archived_at timestamptz,
  unique (workspace_id, name)
);
create index agents_organization_id_idx on agents (organization_id);
create index agents_workspace_id_idx on agents (workspace_id);
create index agents_list_idx on agents (organization_id, workspace_id, created_at desc, id desc);

create table agent_versions (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  agent_id uuid not null references agents(id),
  version_number integer not null check (version_number > 0),
  instructions text not null,
  configuration jsonb not null default '{}'::jsonb check (jsonb_typeof(configuration) = 'object'),
  created_by uuid references users(id),
  created_at timestamptz not null default now(),
  unique (agent_id, version_number),
  unique (agent_id, id)
);
create index agent_versions_organization_id_idx on agent_versions (organization_id);
create index agent_versions_workspace_id_idx on agent_versions (workspace_id);
create index agent_versions_agent_id_idx on agent_versions (agent_id);
alter table agents add constraint agents_active_version_fk
  foreign key (id, active_version_id) references agent_versions(agent_id, id);

create trigger agent_versions_immutable
before update or delete on agent_versions
for each row execute function zeus_private.reject_mutation();

create table workflows (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  name text not null,
  description text not null default '',
  active_version_id uuid,
  revision bigint not null default 1 check (revision > 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  archived_at timestamptz,
  unique (workspace_id, name)
);
create index workflows_organization_id_idx on workflows (organization_id);
create index workflows_workspace_id_idx on workflows (workspace_id);
create index workflows_list_idx on workflows (organization_id, workspace_id, created_at desc, id desc);

create table workflow_versions (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  workflow_id uuid not null references workflows(id),
  version_number integer not null check (version_number > 0),
  agent_version_id uuid not null references agent_versions(id),
  model_profile_id uuid not null references model_profiles(id),
  input_schema jsonb not null check (jsonb_typeof(input_schema) = 'object'),
  output_schema jsonb not null check (jsonb_typeof(output_schema) = 'object'),
  capability_policy jsonb not null default '{}'::jsonb check (jsonb_typeof(capability_policy) = 'object'),
  approval_policy jsonb not null default '{"require_high_risk":true,"fail_on_denial":false}'::jsonb,
  experience_policy jsonb not null default '{"include_workspace":true,"include_organization":true,"max_entries":8}'::jsonb,
  max_steps integer not null default 32 check (max_steps between 1 and 1024),
  max_runtime_seconds integer not null default 900 check (max_runtime_seconds between 1 and 86400),
  token_budget bigint check (token_budget > 0),
  retry_policy jsonb not null default '{"model_network_attempts":2,"capability_attempts":0}'::jsonb,
  created_by uuid references users(id),
  created_at timestamptz not null default now(),
  unique (workflow_id, version_number),
  unique (workflow_id, id)
);
create index workflow_versions_organization_id_idx on workflow_versions (organization_id);
create index workflow_versions_workspace_id_idx on workflow_versions (workspace_id);
create index workflow_versions_workflow_id_idx on workflow_versions (workflow_id);
create index workflow_versions_agent_version_id_idx on workflow_versions (agent_version_id);
create index workflow_versions_model_profile_id_idx on workflow_versions (model_profile_id);
alter table workflows add constraint workflows_active_version_fk
  foreign key (id, active_version_id) references workflow_versions(workflow_id, id);

create trigger workflow_versions_immutable
before update or delete on workflow_versions
for each row execute function zeus_private.reject_mutation();

create table schedules (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  workflow_id uuid not null references workflows(id),
  name text not null,
  cron_expression text not null,
  timezone text not null default 'UTC',
  input jsonb not null default '{}'::jsonb,
  enabled boolean not null default true,
  next_run_at timestamptz,
  revision bigint not null default 1 check (revision > 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (workspace_id, name)
);
create index schedules_organization_id_idx on schedules (organization_id);
create index schedules_workspace_id_idx on schedules (workspace_id);
create index schedules_workflow_id_idx on schedules (workflow_id);
create index schedules_due_idx on schedules (next_run_at, id) where enabled;

create table webhook_endpoints (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  workflow_id uuid not null references workflows(id),
  public_key text not null unique,
  secret_hash bytea not null,
  enabled boolean not null default true,
  revision bigint not null default 1 check (revision > 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index webhook_endpoints_organization_id_idx on webhook_endpoints (organization_id);
create index webhook_endpoints_workspace_id_idx on webhook_endpoints (workspace_id);
create index webhook_endpoints_workflow_id_idx on webhook_endpoints (workflow_id);
