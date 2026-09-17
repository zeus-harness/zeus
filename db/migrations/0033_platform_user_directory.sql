-- Global identity directory, independent of tenant memberships.
create or replace function zeus_private.list_platform_users(
  target_user_id uuid, target_session_id uuid,
  before_created_at timestamptz, before_id uuid, page_limit integer
)
returns table (
  id uuid, email text, display_name text, status text,
  email_verified boolean, mfa_enabled boolean, created_at timestamptz
)
language sql stable security definer
set search_path = pg_catalog, public
as $$
  select u.id, u.email, u.display_name, u.status,
    u.email_verified_at is not null,
    exists(select 1 from public.user_totp_credentials t where t.user_id = u.id and t.confirmed_at is not null),
    u.created_at
  from public.users u
  where zeus_private.platform_session_is_owner(target_user_id, target_session_id, false)
    and (before_created_at is null or (u.created_at, u.id) < (before_created_at, before_id))
  order by u.created_at desc, u.id desc
  limit greatest(1, least(coalesce(page_limit, 51), 101))
$$;
revoke all on function zeus_private.list_platform_users(uuid, uuid, timestamptz, uuid, integer) from public;
grant execute on function zeus_private.list_platform_users(uuid, uuid, timestamptz, uuid, integer) to zeus_http;
