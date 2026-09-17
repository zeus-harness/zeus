-- Model providers and their models are shared inside one Organization.
-- Preserve IDs, ciphertext/AAD, historical Agent/Workflow versions and Runs.
alter table connections alter column workspace_id drop not null;
alter table connection_secrets alter column workspace_id drop not null;
alter table model_profiles alter column workspace_id drop not null;

-- Only model connections move; unrelated Workspace tool connections stay local.
update connection_secrets s set workspace_id = null
where exists (
  select 1 from connections c where c.id = s.connection_id
  and (c.provider_kind = 'openai_compatible' or exists (select 1 from model_profiles m where m.connection_id = c.id))
);
update connections c set workspace_id = null
where c.provider_kind = 'openai_compatible'
   or exists (select 1 from model_profiles m where m.connection_id = c.id);
update model_profiles set workspace_id = null;

-- Different Workspaces may have used the same display name. Do not merge credentials.
update connections c set name = left(c.name, 100) || ' [' || c.id::text || ']'
where c.workspace_id is null and exists (
  select 1 from connections other where other.workspace_id is null
    and other.organization_id = c.organization_id and other.name = c.name and other.id <> c.id
);
update model_profiles m set name = left(m.name, 100) || ' [' || m.id::text || ']'
where exists (select 1 from model_profiles other
  where other.organization_id = m.organization_id and other.name = m.name and other.id <> m.id);

create unique index connections_organization_name_idx on connections (organization_id, name) where workspace_id is null;
create unique index model_profiles_organization_name_idx on model_profiles (organization_id, name);
alter table model_profiles add constraint model_profiles_organization_scope check (workspace_id is null);
alter table connections add constraint connections_organization_id_id_key unique (organization_id, id);
alter table model_profiles add constraint model_profiles_organization_id_id_key unique (organization_id, id);
alter table model_profiles add constraint model_profiles_organization_connection_fk
  foreign key (organization_id, connection_id) references connections (organization_id, id);
alter table connection_secrets add constraint connection_secrets_organization_connection_fk
  foreign key (organization_id, connection_id) references connections (organization_id, id);
alter table workflow_versions add constraint workflow_versions_organization_model_fk
  foreign key (organization_id, model_profile_id) references model_profiles (organization_id, id);

drop policy workspace_isolation on connections;
create policy connection_scope on connections
  using (organization_id = (select zeus_private.current_organization_id())
    and (workspace_id is null or workspace_id = (select zeus_private.current_workspace_id())))
  with check (organization_id = (select zeus_private.current_organization_id())
    and (workspace_id is null or workspace_id = (select zeus_private.current_workspace_id())));
drop policy workspace_isolation on connection_secrets;
create policy connection_secret_scope on connection_secrets
  using (organization_id = (select zeus_private.current_organization_id())
    and (workspace_id is null or workspace_id = (select zeus_private.current_workspace_id())))
  with check (organization_id = (select zeus_private.current_organization_id())
    and (workspace_id is null or workspace_id = (select zeus_private.current_workspace_id())));
drop policy workspace_isolation on model_profiles;
create policy organization_isolation on model_profiles
  using (organization_id = (select zeus_private.current_organization_id()))
  with check (organization_id = (select zeus_private.current_organization_id()));

-- Historical versions have no selected model; their Workflow binding stays intact.
alter table agent_versions add column model_profile_id uuid;
alter table agent_versions add constraint agent_versions_organization_model_fk
  foreign key (organization_id, model_profile_id) references model_profiles (organization_id, id);
create index agent_versions_model_profile_id_idx on agent_versions (model_profile_id);
