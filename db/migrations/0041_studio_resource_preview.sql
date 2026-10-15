-- A bounded chat tool. It can create resources, never publish or execute them.
-- The caller cannot supply tenant, actor, resource id, permissions or a workflow version.
create or replace function zeus_private.create_studio_resource(
  target_run uuid, node_id text, expected_fence bigint, target_tool uuid
) returns jsonb language plpgsql security definer set search_path = pg_catalog, public as $$
declare
  r public.runs%rowtype; t public.tool_calls%rowtype; v public.workflow_versions%rowtype;
  d public.capability_definitions%rowtype; c public.workspace_capabilities%rowtype;
  member_role text; resource_kind text; resource_title text; resource_description text; created_id uuid;
begin
  select * into r from public.runs where id = target_run for update;
  if not found or node_id is null or expected_fence is null
    or r.lease_owner is distinct from node_id or r.fence_token <> expected_fence
    or r.status <> 'running' or r.lease_expires_at is null or r.lease_expires_at <= clock_timestamp()
    or r.cancel_requested_at is not null or (r.deadline_at is not null and r.deadline_at <= clock_timestamp()) then
    raise exception 'studio execution unavailable' using errcode = '42501';
  end if;
  select * into t from public.tool_calls where id = target_tool and run_id = r.id
    and organization_id = r.organization_id and workspace_id = r.workspace_id and session_id = r.session_id for update;
  if not found or t.status <> 'running' or t.fence_token <> expected_fence then
    raise exception 'studio tool unavailable' using errcode = '42501';
  end if;
  select * into v from public.workflow_versions where id = r.workflow_version_id;
  select * into d from public.capability_definitions where id = t.capability_id and organization_id = r.organization_id;
  select * into c from public.workspace_capabilities where capability_id = t.capability_id
    and organization_id = r.organization_id and workspace_id = r.workspace_id;
  if d.executor_key is distinct from 'builtin.studio_resource_create' or d.archived_at is not null
    or c.enabled is distinct from true
    or not (coalesce((v.capability_policy->>'allow_all')::boolean, false)
      or coalesce(v.capability_policy->'allowed', '[]') ?| array[d.id::text, d.registry_key]
      or coalesce(v.capability_policy->'allowed_capabilities', '[]') ?| array[d.id::text, d.registry_key])
    or ((c.approval_required or (d.risk_level = 'high' and coalesce((v.approval_policy->>'require_high_risk')::boolean, true)))
      and not exists(select 1 from public.approvals where tool_call_id = t.id and run_id = r.id and status = 'approved')) then
    raise exception 'studio capability unavailable' using errcode = '42501';
  end if;
  select m.role into member_role from public.workspace_memberships m
    join public.organizations o on o.id = m.organization_id and o.status = 'active'
    join public.workspaces w on w.id = m.workspace_id and w.organization_id = m.organization_id and w.status = 'active'
    join public.organization_memberships om on om.organization_id = m.organization_id and om.user_id = m.user_id and om.status = 'active'
    join public.users u on u.id = m.user_id and u.status = 'active'
    where m.organization_id = r.organization_id and m.workspace_id = r.workspace_id
      and m.user_id = r.created_by and m.status = 'active';
  if member_role is null or member_role not in ('owner', 'builder', 'operator') then
    raise exception 'studio actor unauthorized' using errcode = '42501';
  end if;
  if jsonb_typeof(t.input) <> 'object' or not (t.input ?& array['kind','title','description'])
    or t.input - array['kind','title','description'] <> '{}'::jsonb
    or jsonb_typeof(t.input->'kind') <> 'string' or jsonb_typeof(t.input->'title') <> 'string'
    or jsonb_typeof(t.input->'description') <> 'string' then
    raise exception 'invalid studio input' using errcode = '22023';
  end if;
  resource_kind := t.input->>'kind'; resource_title := btrim(t.input->>'title');
  resource_description := btrim(t.input->>'description');
  if resource_kind not in ('work_item', 'workflow') or length(resource_title) not between 1 and 160
    or length(resource_description) not between 1 and 50000 then
    raise exception 'invalid studio input' using errcode = '22023';
  end if;
  if resource_kind = 'workflow' and member_role not in ('owner','builder') then
    raise exception 'studio builder required' using errcode = '42501';
  end if;
  -- Creation authority is supplied by the authenticated UI for this run, never by tool arguments.
  if r.input->>'studio_resource_mode' is distinct from 'create' then
    return jsonb_build_object('id', t.id, 'kind', resource_kind, 'title', resource_title,
      'description', resource_description, 'status', 'proposed');
  end if;
  -- A tool call keeps the same id after a crash/retry. Resource and audit commit atomically.
  if resource_kind = 'work_item' then
    insert into public.work_items(id, organization_id, workspace_id, title, description, source_kind,
      external_reference, idempotency_key, created_by)
      values (t.id, r.organization_id, r.workspace_id, resource_title, resource_description,
        'studio_discussion', r.id::text, 'studio-tool:' || t.id::text, r.created_by)
      on conflict (id) do nothing returning id into created_id;
  else
    insert into public.workflows(id, organization_id, workspace_id, name, description)
      values (t.id, r.organization_id, r.workspace_id, resource_title, resource_description)
      on conflict (id) do nothing returning id into created_id;
  end if;
  if created_id is not null then
    insert into public.audit_events(organization_id, workspace_id, actor_kind, actor_id, action, target_type, target_id, metadata)
      values (r.organization_id, r.workspace_id, 'user', r.created_by, 'studio.resource_created', resource_kind, t.id,
        jsonb_build_object('run_id', r.id, 'session_id', r.session_id, 'tool_call_id', t.id));
  end if;
  return jsonb_build_object('id', t.id, 'kind', resource_kind, 'title', resource_title,
    'status', case when resource_kind = 'workflow' then 'unpublished' else 'open' end);
end $$;
revoke all on function zeus_private.create_studio_resource(uuid, text, bigint, uuid) from public;
grant execute on function zeus_private.create_studio_resource(uuid, text, bigint, uuid) to zeus_runtime;
