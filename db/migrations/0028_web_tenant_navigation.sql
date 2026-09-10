-- Workspace-scoped Web navigation and platform support context selection.
--
-- The organization chooser exposes governance metadata without exposing IdP
-- configuration. A valid platform support grant contributes a temporary
-- Organization and its active Workspaces without creating memberships.

drop function zeus_private.list_user_organizations(uuid, uuid);

create or replace function zeus_private.list_user_organizations(
  target_user_id uuid,
  target_session_id uuid
)
returns table (
  organization_id uuid,
  organization_slug text,
  organization_name text,
  organization_status text,
  organization_role text,
  identity_settings_mode text,
  support_access boolean,
  can_manage_organization boolean,
  can_manage_identity_settings boolean,
  workspaces jsonb
)
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select o.id,
         o.slug,
         o.name,
         o.status,
         membership.role,
         governance.identity_settings_mode,
         support.active,
         membership.role = 'owner' or support.active,
         support.active or (
           membership.role = 'owner'
           and governance.identity_settings_mode = 'self_service'
         ),
         coalesce((
           select jsonb_agg(jsonb_build_object(
             'id', w.id,
             'slug', w.slug,
             'name', w.name,
             'status', w.status,
             'role', case when support.active then
               coalesce(workspace_membership.role, 'platform_support')
             else workspace_membership.role end,
             'support_access', support.active
           ) order by w.created_at, w.id)
           from public.workspaces w
           left join public.workspace_memberships workspace_membership
             on workspace_membership.organization_id = w.organization_id
            and workspace_membership.workspace_id = w.id
            and workspace_membership.user_id = target_user_id
            and workspace_membership.status = 'active'
           where w.organization_id = o.id
             and (
               (support.active and w.status = 'active')
               or (not support.active and workspace_membership.user_id is not null)
             )
         ), '[]'::jsonb)
  from public.web_sessions session
  join public.organizations o on true
  join public.organization_governance governance
    on governance.organization_id = o.id
  left join public.organization_memberships membership
    on membership.organization_id = o.id
   and membership.user_id = target_user_id
   and membership.status = 'active'
  cross join lateral (
    select coalesce(bool_or(
      zeus_private.platform_tenant_access_is_valid(
        access_grant.id, target_user_id, target_session_id, o.id
      )
    ), false) as active
    from public.platform_tenant_access_grants access_grant
    where access_grant.platform_user_id = target_user_id
      and access_grant.web_session_id = target_session_id
      and access_grant.organization_id = o.id
      and access_grant.revoked_at is null
      and access_grant.expires_at > now()
  ) support
  where session.id = target_session_id
    and session.user_id = target_user_id
    and session.revoked_at is null
    and session.idle_expires_at > now()
    and session.absolute_expires_at > now()
    and (membership.user_id is not null or support.active)
    and (membership.user_id is not null or o.status in ('active', 'suspended'))
  order by o.created_at, o.id
$$;

create or replace function zeus_private.rotate_user_session_context_with_access(
  target_session_id uuid,
  target_user_id uuid,
  target_organization_id uuid,
  target_workspace_id uuid,
  target_token_hash bytea,
  target_csrf_token_hash bytea,
  target_grant_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  affected integer;
  support_access boolean := false;
begin
  if target_token_hash is null
     or octet_length(target_token_hash) <> 32
     or target_csrf_token_hash is null
     or octet_length(target_csrf_token_hash) <> 32
     or (target_workspace_id is not null and target_organization_id is null) then
    raise exception 'invalid session rotation arguments' using errcode = '22023';
  end if;

  if target_grant_id is not null and target_organization_id is not null then
    support_access := zeus_private.platform_tenant_access_is_valid(
      target_grant_id,
      target_user_id,
      target_session_id,
      target_organization_id
    );
    if not support_access then
      return false;
    end if;
  end if;

  if target_organization_id is not null and not support_access and not exists (
    select 1
    from public.organization_memberships membership
    join public.organizations organization
      on organization.id = membership.organization_id
     and organization.status = 'active'
    where membership.organization_id = target_organization_id
      and membership.user_id = target_user_id
      and membership.status = 'active'
  ) then
    return false;
  end if;

  if target_workspace_id is not null and support_access and not exists (
    select 1
    from public.workspaces workspace
    where workspace.organization_id = target_organization_id
      and workspace.id = target_workspace_id
      and workspace.status = 'active'
  ) then
    return false;
  end if;

  if target_workspace_id is not null and not support_access and not exists (
    select 1
    from public.workspace_memberships membership
    join public.workspaces workspace
      on workspace.id = membership.workspace_id
     and workspace.status = 'active'
    where membership.organization_id = target_organization_id
      and membership.workspace_id = target_workspace_id
      and membership.user_id = target_user_id
      and membership.status = 'active'
  ) then
    return false;
  end if;

  update public.web_sessions session
  set active_organization_id = target_organization_id,
      active_workspace_id = target_workspace_id,
      token_hash = target_token_hash,
      csrf_token_hash = target_csrf_token_hash,
      token_rotated_at = now(),
      last_seen_at = now()
  where session.id = target_session_id
    and session.user_id = target_user_id
    and session.revoked_at is null
    and session.idle_expires_at > now()
    and session.absolute_expires_at > now();
  get diagnostics affected = row_count;
  return affected = 1;
end
$$;

create or replace function zeus_private.revoke_platform_tenant_access_grant(
  target_user_id uuid,
  target_session_id uuid,
  target_grant_id uuid,
  target_reason text
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  grant_organization_id uuid;
  grant_reason text;
begin
  if not zeus_private.platform_session_is_admin(
    target_user_id, target_session_id, false
  ) then
    return false;
  end if;
  update public.platform_tenant_access_grants
  set revoked_at = now(), revoked_by = target_user_id,
      revoked_reason = coalesce(nullif(btrim(target_reason), ''), 'revoked by platform administrator')
  where id = target_grant_id
    and platform_user_id = target_user_id
    and web_session_id = target_session_id
    and revoked_at is null
  returning organization_id, reason into grant_organization_id, grant_reason;
  if not found then
    return false;
  end if;

  update public.web_sessions session
  set active_organization_id = null,
      active_workspace_id = null,
      last_seen_at = now()
  where session.id = target_session_id
    and session.user_id = target_user_id
    and session.active_organization_id = grant_organization_id;

  insert into public.audit_events (
    organization_id, actor_kind, actor_id, action, target_type, target_id, metadata
  ) values (
    grant_organization_id, 'user', target_user_id,
    'platform.tenant_access_revoked', 'organization', grant_organization_id,
    jsonb_build_object('grant_id', target_grant_id, 'reason', grant_reason)
  );
  insert into public.security_events (
    organization_id, user_id, actor_user_id, event_type, outcome, metadata
  ) values (
    grant_organization_id, target_user_id, target_user_id,
    'platform.tenant_access_revoked', 'success',
    jsonb_build_object('grant_id', target_grant_id, 'reason', grant_reason)
  );
  return true;
end
$$;

revoke all on function zeus_private.list_user_organizations(uuid, uuid) from public;
revoke all on function zeus_private.rotate_user_session_context_with_access(
  uuid, uuid, uuid, uuid, bytea, bytea, uuid
) from public;
revoke all on function zeus_private.revoke_platform_tenant_access_grant(
  uuid, uuid, uuid, text
) from public;

grant execute on function zeus_private.list_user_organizations(uuid, uuid) to zeus_http;
grant execute on function zeus_private.rotate_user_session_context_with_access(
  uuid, uuid, uuid, uuid, bytea, bytea, uuid
) to zeus_http;
grant execute on function zeus_private.revoke_platform_tenant_access_grant(
  uuid, uuid, uuid, text
) to zeus_http;
