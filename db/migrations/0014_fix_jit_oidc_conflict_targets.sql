-- Use named constraints so PL/pgSQL output columns cannot shadow conflict targets.

create or replace function zeus_private.jit_oidc_identity(
  target_provider_id uuid,
  target_issuer text,
  target_subject text,
  target_email text,
  target_display_name text,
  target_email_verified boolean,
  target_claims jsonb
)
returns table (
  user_id uuid,
  organization_id uuid,
  workspace_id uuid
)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  provider_row public.oidc_providers%rowtype;
  resolved_user_id uuid;
  resolved_workspace_id uuid;
  mapped_organization_role text;
begin
  if btrim(coalesce(target_issuer, '')) = ''
     or btrim(coalesce(target_subject, '')) = ''
     or btrim(coalesce(target_email, '')) = ''
     or btrim(coalesce(target_display_name, '')) = ''
     or target_claims is null
     or jsonb_typeof(target_claims) <> 'object'
     or jsonb_typeof(coalesce(target_claims -> 'groups', '[]'::jsonb)) <> 'array' then
    raise exception 'invalid OIDC identity claims' using errcode = '22023';
  end if;

  select * into provider_row
  from public.oidc_providers p
  where p.id = target_provider_id and p.enabled
  for share;
  if not found or rtrim(provider_row.issuer_url, '/') <> rtrim(target_issuer, '/') then
    raise exception 'OIDC issuer does not match provider' using errcode = '42501';
  end if;

  select i.user_id into resolved_user_id
  from public.oidc_identities i
  where i.provider_id = target_provider_id
    and i.issuer = target_issuer
    and i.subject = target_subject
  for update;

  if found then
    update public.oidc_identities
    set claims = target_claims, last_login_at = now()
    where provider_id = target_provider_id
      and issuer = target_issuer
      and subject = target_subject;
    update public.users
    set display_name = target_display_name,
        last_seen_at = now(),
        updated_at = now()
    where id = resolved_user_id and status = 'active';
    if not found then
      raise exception 'OIDC user is disabled' using errcode = '42501';
    end if;
  else
    select u.id into resolved_user_id
    from public.users u
    where lower(u.email) = lower(target_email)
    for update;

    if found and not target_email_verified then
      raise exception 'verified email is required to link an existing user' using errcode = '42501';
    end if;
    if not found then
      insert into public.users (email, display_name, last_seen_at)
      values (lower(target_email), target_display_name, now())
      returning id into resolved_user_id;
    end if;

    insert into public.oidc_identities (
      user_id, provider_id, issuer, subject, claims
    ) values (
      resolved_user_id, target_provider_id, target_issuer, target_subject, target_claims
    );
  end if;

  select m.organization_role into mapped_organization_role
  from public.oidc_group_mappings m
  where m.provider_id = target_provider_id
    and m.organization_role is not null
    and m.group_value in (
      select jsonb_array_elements_text(coalesce(target_claims -> 'groups', '[]'::jsonb))
    )
  order by case m.organization_role
    when 'owner' then 1
    when 'admin' then 2
    when 'member' then 3
    else 4
  end
  limit 1;

  insert into public.organization_memberships (
    organization_id, user_id, role, status
  ) values (
    provider_row.organization_id,
    resolved_user_id,
    coalesce(mapped_organization_role, 'member'),
    'active'
  )
  on conflict on constraint organization_memberships_pkey do update
  set status = 'active', updated_at = now();

  insert into public.workspace_memberships (
    organization_id, workspace_id, user_id, role, status
  )
  select provider_row.organization_id,
         selected.workspace_id,
         resolved_user_id,
         selected.workspace_role,
         'active'
  from (
    select distinct on (m.workspace_id)
           m.workspace_id,
           m.workspace_role
    from public.oidc_group_mappings m
    join public.workspaces w
      on w.id = m.workspace_id
     and w.organization_id = provider_row.organization_id
     and w.status = 'active'
    where m.provider_id = target_provider_id
      and m.workspace_id is not null
      and m.group_value in (
        select jsonb_array_elements_text(coalesce(target_claims -> 'groups', '[]'::jsonb))
      )
    order by m.workspace_id,
      case m.workspace_role
        when 'admin' then 1
        when 'builder' then 2
        when 'operator' then 3
        else 4
      end
  ) selected
  on conflict on constraint workspace_memberships_pkey do update
  set status = 'active', updated_at = now();

  select wm.workspace_id into resolved_workspace_id
  from public.workspace_memberships wm
  join public.workspaces w on w.id = wm.workspace_id and w.status = 'active'
  where wm.organization_id = provider_row.organization_id
    and wm.user_id = resolved_user_id
    and wm.status = 'active'
  order by wm.created_at, wm.workspace_id
  limit 1;

  return query
  select resolved_user_id, provider_row.organization_id, resolved_workspace_id;
end
$$;

revoke all on function zeus_private.jit_oidc_identity(uuid, text, text, text, text, boolean, jsonb) from public;
grant execute on function zeus_private.jit_oidc_identity(uuid, text, text, text, text, boolean, jsonb) to zeus_http;
