-- Optional reusable source binding; code state belongs to each Run, never to a version.
alter table workflow_versions add column code_repository jsonb;
alter table workflow_versions add constraint workflow_code_repository_check check (
  code_repository is null or (
    jsonb_typeof(code_repository) = 'object'
    and code_repository ?& array['repository_id', 'commit']
    and code_repository - array['repository_id', 'commit'] = '{}'
    and jsonb_typeof(code_repository->'repository_id') = 'string'
    and jsonb_typeof(code_repository->'commit') = 'string'
    and (code_repository->>'repository_id') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    and (code_repository->>'commit') ~ '^[0-9a-f]{40}$'
  )
);
create table run_code_checkpoints (
  id uuid primary key,
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  run_id uuid not null references runs(id),
  fence_token bigint not null check (fence_token > 0),
  repository_id uuid not null,
  base_commit text not null check (base_commit ~ '^[0-9a-f]{40}$'),
  checkpoint_commit text not null check (checkpoint_commit ~ '^[0-9a-f]{40}$'),
  created_at timestamptz not null default now()
);
create index run_code_checkpoint_org_idx on run_code_checkpoints (organization_id);
create index run_code_checkpoint_workspace_idx on run_code_checkpoints (workspace_id);
create index run_code_checkpoint_run_idx on run_code_checkpoints (run_id, created_at desc, id desc);
alter table run_code_checkpoints enable row level security;
alter table run_code_checkpoints force row level security;
create policy workspace_isolation on run_code_checkpoints
  using (organization_id = (select zeus_private.current_organization_id())
    and workspace_id = (select zeus_private.current_workspace_id()));
create trigger run_code_checkpoints_append_only before update or delete on run_code_checkpoints
  for each row execute function zeus_private.reject_mutation();
grant select on run_code_checkpoints to zeus_http, zeus_runtime;

create function zeus_private.save_code_checkpoint(
  target_run uuid, node_id text, expected_fence bigint, checkpoint_id uuid, commit_hash text
) returns uuid language plpgsql security definer set search_path = pg_catalog, public as $$
declare current_run public.runs%rowtype; binding jsonb;
begin
  select * into current_run from public.runs where id = target_run for update;
  if not found or node_id is null or expected_fence is null
     or current_run.status <> 'running' or current_run.lease_owner is distinct from node_id
     or current_run.fence_token <> expected_fence or current_run.lease_expires_at is null
     or current_run.lease_expires_at <= clock_timestamp()
     or current_run.cancel_requested_at is not null then
    raise exception 'stale code checkpoint fence' using errcode = '42501';
  end if;
  select code_repository into binding from public.workflow_versions where id = current_run.workflow_version_id;
  if binding is null then raise exception 'no repository binding' using errcode = '23514'; end if;
  insert into public.run_code_checkpoints (id, organization_id, workspace_id, run_id, fence_token,
    repository_id, base_commit, checkpoint_commit)
    values (checkpoint_id, current_run.organization_id, current_run.workspace_id, target_run, expected_fence,
      (binding->>'repository_id')::uuid, binding->>'commit', commit_hash);
  perform zeus_private.append_run_event(target_run, 'code.checkpoint_saved', jsonb_build_object(
    'checkpoint_id', checkpoint_id, 'repository_id', binding->>'repository_id', 'commit', commit_hash));
  return checkpoint_id;
end $$;
revoke all on function zeus_private.save_code_checkpoint(uuid, text, bigint, uuid, text) from public;
grant execute on function zeus_private.save_code_checkpoint(uuid, text, bigint, uuid, text) to zeus_runtime;
