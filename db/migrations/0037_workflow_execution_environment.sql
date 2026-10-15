-- Immutable sandbox image identity; scripts cannot choose their own runtime image.
alter table workflow_versions add column execution_environment text;
alter table workflow_versions add constraint workflow_execution_environment_check check (
  execution_environment is null or
  (execution_environment ~ '^sha256:[0-9a-f]{64}$' and code_repository is not null)
);

-- Runtime receives only the decision, not broader identity-table read access.
create function zeus_private.sandbox_execution_authorized(
  target_run uuid, target_organization uuid, target_workspace uuid,
  target_fence bigint, target_owner text, target_tool uuid
) returns boolean
language sql volatile security definer
set search_path = pg_catalog, public
as $$
  select exists (
    select 1 from public.runs r
    join public.organizations o on o.id = r.organization_id
    join public.workspaces w on w.id = r.workspace_id and w.organization_id = r.organization_id
    join public.approvals a on a.run_id = r.id and a.tool_call_id = target_tool
    join public.tool_calls t on t.id = a.tool_call_id and t.run_id = r.id
    join public.capability_definitions d on d.id = t.capability_id and d.organization_id = r.organization_id
    join public.workspace_capabilities c on c.capability_id = t.capability_id
      and c.organization_id = r.organization_id and c.workspace_id = r.workspace_id
    where r.id = target_run and r.organization_id = target_organization
      and r.workspace_id = target_workspace and r.fence_token = target_fence
      and r.lease_owner = target_owner and r.status = 'running'
      and r.cancel_requested_at is null and r.lease_expires_at > clock_timestamp()
      and (r.deadline_at is null or r.deadline_at > clock_timestamp())
      and o.status = 'active' and w.status = 'active' and c.enabled
      and d.archived_at is null and d.executor_key = 'builtin.sandbox_exec'
      and a.status = 'approved' and t.status = 'running' and t.fence_token = r.fence_token
  )
$$;
revoke all on function zeus_private.sandbox_execution_authorized(uuid, uuid, uuid, bigint, text, uuid) from public;
grant execute on function zeus_private.sandbox_execution_authorized(uuid, uuid, uuid, bigint, text, uuid) to zeus_runtime;
