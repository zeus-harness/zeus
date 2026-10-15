-- Persist the effective model revision without duplicating configuration or credentials.
-- Changed model configuration requires a new Run; credentials may still be rotated/revoked.
create table run_model_configuration_bindings (
  run_id uuid primary key references runs(id),
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  model_profile_id uuid not null references model_profiles(id),
  model_profile_revision bigint not null,
  model_connection_id uuid not null references connections(id),
  model_connection_revision bigint not null,
  configuration_sha256 bytea not null check (octet_length(configuration_sha256)=32),
  created_at timestamptz not null default clock_timestamp()
);
create index run_model_configuration_bindings_org_idx on run_model_configuration_bindings(organization_id);
create index run_model_configuration_bindings_workspace_idx on run_model_configuration_bindings(workspace_id);
create index run_model_configuration_bindings_profile_idx on run_model_configuration_bindings(model_profile_id);
create index run_model_configuration_bindings_connection_idx on run_model_configuration_bindings(model_connection_id);
alter table run_model_configuration_bindings enable row level security;
alter table run_model_configuration_bindings force row level security;
create policy workspace_isolation on run_model_configuration_bindings
 using(organization_id=(select zeus_private.current_organization_id()) and workspace_id=(select zeus_private.current_workspace_id()));
create trigger run_model_configuration_bindings_append_only before update or delete on run_model_configuration_bindings
 for each row execute function zeus_private.reject_mutation();
grant select on run_model_configuration_bindings to zeus_http;
grant select on run_model_configuration_bindings to zeus_runtime;

create function zeus_private.bind_run_model_configuration() returns trigger
language plpgsql security definer set search_path=pg_catalog,public as $$
begin
 insert into run_model_configuration_bindings(run_id,organization_id,workspace_id,
   model_profile_id,model_profile_revision,model_connection_id,model_connection_revision,configuration_sha256)
 select new.id,new.organization_id,new.workspace_id,mp.id,mp.revision,c.id,c.revision,
   sha256(convert_to(jsonb_build_array(mp.base_url,mp.model,mp.configuration,c.configuration)::text,'UTF8'))
 from workflow_versions wv join model_profiles mp on mp.id=wv.model_profile_id
 join connections c on c.id=mp.connection_id
 where wv.id=new.workflow_version_id and wv.organization_id=new.organization_id and wv.workspace_id=new.workspace_id
   and mp.organization_id=new.organization_id and mp.workspace_id is null
   and c.organization_id=new.organization_id and c.workspace_id is null;
 return new;
end $$;
create trigger runs_bind_model_configuration after insert on runs
 for each row execute function zeus_private.bind_run_model_configuration();
revoke all on function zeus_private.bind_run_model_configuration() from public;

-- Existing Runs cannot reconstruct historical revisions. Bind the current revision explicitly.
insert into run_model_configuration_bindings(run_id,organization_id,workspace_id,
 model_profile_id,model_profile_revision,model_connection_id,model_connection_revision,configuration_sha256)
select r.id,r.organization_id,r.workspace_id,mp.id,mp.revision,c.id,c.revision,
 sha256(convert_to(jsonb_build_array(mp.base_url,mp.model,mp.configuration,c.configuration)::text,'UTF8'))
from runs r join workflow_versions wv on wv.id=r.workflow_version_id
join model_profiles mp on mp.id=wv.model_profile_id join connections c on c.id=mp.connection_id
where mp.organization_id=r.organization_id and mp.workspace_id is null
 and c.organization_id=r.organization_id and c.workspace_id is null;
