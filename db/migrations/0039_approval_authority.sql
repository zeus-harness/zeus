-- Historical approvals keep their original operator policy. New requests are explicit.
alter table approvals drop constraint approvals_tool_call_id_key;
alter table approvals add column kind text not null default 'legacy_tool'
  check (kind in ('legacy_tool', 'execution', 'resource_access'));
alter table approvals add column requested_by uuid references users(id);
alter table approvals add column input_snapshot jsonb;
alter table approvals add column capability_revision bigint;
alter table approvals add column binding_revision bigint;
alter table approvals add column authorized_until timestamptz;
alter table approvals add column revoked_at timestamptz;
alter table approvals add column revoked_by uuid references users(id);
alter table approvals add constraint approvals_call_kind_key unique(tool_call_id, kind);
create index approvals_requested_by_idx on approvals(requested_by);
create index approvals_revoked_by_idx on approvals(revoked_by);
update approvals a set requested_by = r.created_by from runs r where r.id = a.run_id;

-- A grant is the approved resource_access record itself, scoped to an immutable
-- tool call and its exact input. It never creates membership or general permissions.
create function zeus_private.tool_authority_valid(target_tool uuid) returns boolean
language sql stable security definer set search_path = pg_catalog, public as $$
 select exists (
   select 1 from tool_calls t join runs r on r.id=t.run_id
   join workspace_capabilities c on c.capability_id=t.capability_id
     and c.organization_id=t.organization_id and c.workspace_id=t.workspace_id
   join capability_definitions d on d.id=t.capability_id and d.organization_id=t.organization_id
   where t.id=target_tool and r.organization_id=t.organization_id and r.workspace_id=t.workspace_id
     and r.session_id=t.session_id and c.enabled
     and exists(select 1 from organizations o where o.id=r.organization_id and o.status='active')
     and exists(select 1 from workspaces w where w.id=r.workspace_id and w.status='active') and d.archived_at is null
     and not exists (select 1 from approvals a where a.tool_call_id=t.id and a.kind <> 'legacy_tool'
       and (a.capability_revision is distinct from d.revision or a.binding_revision is distinct from c.revision
         or a.requested_by is distinct from r.created_by or a.status <> 'approved' or a.input_snapshot is distinct from t.input or a.revoked_at is not null
         or (a.kind='resource_access' and (a.authorized_until is null or a.authorized_until <= clock_timestamp()))))
     and (not (c.approval_required or d.executor_key='builtin.sandbox_exec'
         or exists(select 1 from approvals a where a.tool_call_id=t.id and a.kind='resource_access'))
       or exists(select 1 from approvals a where a.tool_call_id=t.id and a.kind in ('execution','legacy_tool') and a.status='approved'))
     and (coalesce(c.policy->>'resource_authorization_required','false') = 'false'
       or exists (select 1 from approvals a where a.tool_call_id=t.id and a.kind='resource_access'
         and a.status='approved' and a.revoked_at is null and a.authorized_until > clock_timestamp()
         and a.input_snapshot=t.input))
     and (not exists(select 1 from approvals a where a.tool_call_id=t.id and a.kind <> 'legacy_tool')
       or exists(select 1 from workspace_memberships m join organization_memberships om
         on om.organization_id=m.organization_id and om.user_id=m.user_id
         join users u on u.id=m.user_id
         where m.workspace_id=r.workspace_id and m.organization_id=r.organization_id
           and m.user_id=r.created_by and m.status='active' and om.status='active' and u.status='active'
           and m.role in ('owner','builder','operator')))
     and not exists(select 1 from approvals a where a.tool_call_id=t.id and a.kind='resource_access'
       and not exists(select 1 from workspace_memberships m join organization_memberships om
         on om.organization_id=m.organization_id and om.user_id=m.user_id
         join users u on u.id=m.user_id
         where m.workspace_id=r.workspace_id and m.organization_id=r.organization_id
           and m.user_id=a.decided_by and m.role='owner' and m.status='active'
           and om.status='active' and u.status='active'))
 )
$$;
revoke all on function zeus_private.tool_authority_valid(uuid) from public;
grant execute on function zeus_private.tool_authority_valid(uuid) to zeus_runtime, zeus_http;
