-- Rename the global platform governance role without rewriting prior migrations.
--
-- This is a hard cutover. Existing assignments are migrated in place and the
-- previous private function names are removed in the same transaction.

alter table public.platform_role_assignments
  drop constraint platform_role_assignments_role_check;

update public.platform_role_assignments
set role = 'platform_owner'
where role = 'platform_admin';

alter table public.platform_role_assignments
  add constraint platform_role_assignments_role_check
  check (role = 'platform_owner');

alter function zeus_private.has_platform_admin()
  rename to has_platform_owner;

create or replace function zeus_private.has_platform_owner()
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select exists (
    select 1
    from public.platform_role_assignments p
    join public.users u on u.id = p.user_id
    where p.role = 'platform_owner'
      and p.revoked_at is null
      and u.status <> 'anonymized'
  )
$$;

do $migration$
declare
  definition text;
begin
  select pg_catalog.pg_get_functiondef(
    'zeus_private.bootstrap_native_identity(text,text,text,text,text,text,text,bytea,bytea,integer,integer)'::regprocedure
  ) into definition;

  definition := replace(definition, 'has_platform_admin', 'has_platform_owner');
  definition := replace(definition, '''platform_admin''', '''platform_owner''');
  execute definition;
end
$migration$;

alter function zeus_private.platform_session_is_admin(uuid, uuid, boolean)
  rename to platform_session_is_owner;

create or replace function zeus_private.platform_session_is_owner(
  target_user_id uuid,
  target_session_id uuid,
  require_recent_mfa boolean
)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select exists (
    select 1
    from public.web_sessions s
    join public.users u
      on u.id = s.user_id
     and u.status = 'active'
     and u.email_verified_at is not null
    join public.platform_role_assignments p
      on p.user_id = u.id
     and p.role = 'platform_owner'
     and p.revoked_at is null
    join public.user_totp_credentials t
      on t.user_id = u.id
     and t.confirmed_at is not null
    where s.id = target_session_id
      and s.user_id = target_user_id
      and s.revoked_at is null
      and s.idle_expires_at > now()
      and s.absolute_expires_at > now()
      and s.mfa_satisfied_at is not null
      and (not require_recent_mfa or s.mfa_satisfied_at >= now() - interval '10 minutes')
  )
$$;

do $migration$
declare
  target regprocedure;
  definition text;
begin
  foreach target in array array[
    'zeus_private.platform_tenant_access_is_valid(uuid,uuid,uuid,uuid)'::regprocedure,
    'zeus_private.create_platform_tenant_access_grant(uuid,uuid,uuid,text,integer,bytea,bytea)'::regprocedure,
    'zeus_private.revoke_platform_tenant_access_grant(uuid,uuid,uuid,text)'::regprocedure,
    'zeus_private.list_platform_organizations(uuid,uuid)'::regprocedure,
    'zeus_private.create_platform_organization(uuid,uuid,text,bytea,text,text,text,text,text,bytea,text)'::regprocedure,
    'zeus_private.update_platform_organization(uuid,uuid,uuid,bigint,text,text,text)'::regprocedure,
    'zeus_private.transition_platform_organization(uuid,uuid,uuid,bigint,text)'::regprocedure,
    'zeus_private.rotate_platform_owner_invitation(uuid,uuid,uuid,bigint,text,text,bytea)'::regprocedure
  ] loop
    definition := pg_catalog.pg_get_functiondef(target);
    definition := replace(
      definition,
      'platform_session_is_admin',
      'platform_session_is_owner'
    );
    definition := replace(definition, '''platform_admin''', '''platform_owner''');
    definition := replace(definition, 'platform administrator', 'platform owner');
    execute definition;
  end loop;
end
$migration$;

revoke all on function zeus_private.has_platform_owner() from public;
grant execute on function zeus_private.has_platform_owner() to zeus_http;
revoke all on function zeus_private.platform_session_is_owner(uuid, uuid, boolean) from public;
