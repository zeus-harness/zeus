-- Self-service registration provisions an owned tenant atomically with the account.
-- Existing explicitly disabled registration remains disabled.
alter table system_identity_settings alter column registration_mode set default 'open';
update system_identity_settings set registration_mode = 'open', revision = revision + 1, updated_at = now()
where registration_mode = 'invite_only';

create index users_created_at_id_idx on users (created_at desc, id desc);

create or replace function zeus_private.create_native_registration(
  target_email text,
  target_display_name text,
  target_password_hash text,
  target_invitation_token_hash bytea
)
returns table (
  user_id uuid,
  email_verified boolean,
  organization_id uuid,
  workspace_id uuid
)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  registration_mode text;
  invitation public.organization_invitations%rowtype;
  new_user_id uuid;
  selected_workspace_id uuid;
  selected_organization_id uuid;
begin
  select s.registration_mode into registration_mode
  from public.system_identity_settings s
  where s.singleton;

  if registration_mode = 'disabled' then
    raise exception 'registration is disabled' using errcode = '42501';
  end if;
  if target_email is null
     or target_email <> lower(btrim(target_email))
     or octet_length(target_email) <> length(target_email)
     or target_email !~ '^[!-~]+@[!-~]+$'
     or length(target_email) not between 3 and 320
     or btrim(coalesce(target_display_name, '')) = ''
     or length(target_display_name) > 120
     or target_password_hash not like '$argon2id$%' then
    raise exception 'invalid registration arguments' using errcode = '22023';
  end if;
  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('zeus.registration:' || target_email, 0)
  );

  if target_invitation_token_hash is not null then
    if octet_length(target_invitation_token_hash) <> 32 then
      raise exception 'invalid invitation token' using errcode = '22023';
    end if;
    select i.* into invitation
    from public.organization_invitations i
    join public.organizations o on o.id = i.organization_id
      and ((i.invitation_kind = 'membership' and o.status = 'active')
        or (i.invitation_kind = 'provisioning_owner' and o.status = 'provisioning'))
    where i.token_hash = target_invitation_token_hash
      and i.email = target_email
      and i.status = 'pending'
      and i.expires_at > now()
    for update of i;
    if not found then
      raise exception 'invitation is unavailable' using errcode = '42501';
    end if;
  elsif registration_mode = 'invite_only' then
    raise exception 'an invitation is required' using errcode = '42501';
  end if;

  if invitation.invitation_kind = 'provisioning_owner' and (
    invitation.organization_role <> 'owner'
    or 1 <> (
      select count(*)
      from public.organization_invitation_workspaces g
      join public.workspaces w
        on w.id = g.workspace_id
       and w.organization_id = invitation.organization_id
       and w.status = 'active'
      where g.invitation_id = invitation.id
        and g.organization_id = invitation.organization_id
        and g.workspace_role = 'owner'
    )
  ) then
    raise exception 'provisioning invitation must grant one initial workspace owner role'
      using errcode = '23514';
  end if;

  insert into public.users (
    email, display_name, status, email_verified_at
  ) values (
    target_email,
    btrim(target_display_name),
    case when invitation.id is null then 'pending_verification' else 'active' end,
    case when invitation.id is null then null else now() end
  ) returning id into new_user_id;

  insert into public.user_password_credentials (user_id, password_hash)
  values (new_user_id, target_password_hash);

  if invitation.id is not null then
    selected_organization_id := invitation.organization_id;
    insert into public.organization_memberships (
      organization_id, user_id, role, status
    ) values (
      invitation.organization_id, new_user_id, invitation.organization_role, 'active'
    );

    insert into public.workspace_memberships (
      organization_id, workspace_id, user_id, role, status
    )
    select g.organization_id, g.workspace_id, new_user_id, g.workspace_role, 'active'
    from public.organization_invitation_workspaces g
    where g.invitation_id = invitation.id;

    select g.workspace_id into selected_workspace_id
    from public.organization_invitation_workspaces g
    where g.invitation_id = invitation.id
    order by g.workspace_id
    limit 1;

    update public.organization_invitations
    set status = 'accepted',
        accepted_by = new_user_id,
        accepted_at = now(),
        updated_at = now()
    where id = invitation.id;
    if invitation.invitation_kind = 'provisioning_owner' then
      update public.organizations set status = 'active', revision = revision + 1, updated_at = now()
      where id = invitation.organization_id and status = 'provisioning';
    end if;
  else
    insert into public.organizations (slug, name)
    values ('personal-' || replace(new_user_id::text, '-', ''), btrim(target_display_name) || ' 的组织')
    returning id into selected_organization_id;
    insert into public.organization_governance (organization_id, updated_by)
    values (selected_organization_id, new_user_id);
    insert into public.organization_identity_policies (organization_id, updated_by)
    values (selected_organization_id, new_user_id);
    insert into public.workspaces (organization_id, slug, name)
    values (selected_organization_id, 'default', '默认工作空间') returning id into selected_workspace_id;
    insert into public.organization_memberships (organization_id, user_id, role, status)
    values (selected_organization_id, new_user_id, 'owner', 'active');
    insert into public.workspace_memberships (organization_id, workspace_id, user_id, role, status)
    values (selected_organization_id, selected_workspace_id, new_user_id, 'owner', 'active');
  end if;

  insert into public.security_events (
    organization_id, workspace_id, user_id, actor_user_id, event_type, outcome
  ) values (
    selected_organization_id,
    selected_workspace_id,
    new_user_id,
    new_user_id,
    'user.registered',
    'success'
  );

  return query select
    new_user_id,
    invitation.id is not null,
    selected_organization_id,
    selected_workspace_id;
end
$$;

create or replace function zeus_private.list_platform_users(
  target_user_id uuid, target_session_id uuid,
  before_created_at timestamptz, before_id uuid, page_limit integer, search_email text
)
returns table (
  id uuid, email text, display_name text, status text,
  email_verified boolean, mfa_enabled boolean, created_at timestamptz
)
language plpgsql stable security definer
set search_path = pg_catalog, public
as $$
begin
  if not zeus_private.platform_session_is_owner(target_user_id, target_session_id, false) then
    return;
  end if;
  if search_email is not null then
    return query
      select u.id, u.email, u.display_name, u.status,
        u.email_verified_at is not null,
        exists(select 1 from public.user_totp_credentials t where t.user_id=u.id and t.confirmed_at is not null),
        u.created_at
      from public.users u
      where lower(u.email) = search_email
        and (u.created_at,u.id) < (coalesce(before_created_at,'infinity'::timestamptz),coalesce(before_id,'ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid));
  else
    return query
      select u.id, u.email, u.display_name, u.status,
        u.email_verified_at is not null,
        exists(select 1 from public.user_totp_credentials t where t.user_id=u.id and t.confirmed_at is not null),
        u.created_at
      from public.users u
      where (u.created_at,u.id) < (coalesce(before_created_at,'infinity'::timestamptz),coalesce(before_id,'ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid))
      order by u.created_at desc,u.id desc
      limit greatest(1,least(coalesce(page_limit,51),101));
  end if;
end
$$;
revoke all on function zeus_private.list_platform_users(uuid, uuid, timestamptz, uuid, integer, text) from public;
grant execute on function zeus_private.list_platform_users(uuid, uuid, timestamptz, uuid, integer, text) to zeus_http;
