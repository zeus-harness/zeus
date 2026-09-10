-- Expose only aggregate identity health to the HTTP process. The function
-- deliberately returns no tenant, user, email, provider, or key identifier.

create or replace function zeus_private.identity_operational_metrics()
returns table (
  email_backlog bigint,
  email_oldest_pending_age_seconds bigint,
  signing_key_present boolean,
  signing_key_age_seconds bigint
)
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  with pending_email as (
    select count(*)::bigint as backlog, min(created_at) as oldest_created_at
    from public.email_outbox
    where status in ('queued', 'sending')
  ), current_key as (
    select created_at
    from public.oidc_signing_keys
    where activates_at <= now() and rotates_at > now()
    order by created_at desc
    limit 1
  )
  select
    pending_email.backlog,
    coalesce(
      greatest(
        0,
        floor(extract(epoch from now() - pending_email.oldest_created_at))::bigint
      ),
      0
    ),
    current_key.created_at is not null,
    coalesce(
      greatest(
        0,
        floor(extract(epoch from now() - current_key.created_at))::bigint
      ),
      0
    )
  from pending_email
  left join current_key on true
$$;

revoke all on function zeus_private.identity_operational_metrics() from public;
grant execute on function zeus_private.identity_operational_metrics() to zeus_http;

-- The operator connection can request an early rotation without reading or
-- rewriting encrypted private-key material. Application roles get no grant.
create or replace function zeus_private.request_oidc_signing_key_rotation(
  target_reason text
)
returns bigint
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  affected bigint;
begin
  if target_reason not in ('scheduled', 'compromise', 'restore', 'manual_test') then
    raise exception 'invalid OIDC signing-key rotation reason' using errcode = '22023';
  end if;

  with rotated as (
    update public.oidc_signing_keys
    set rotates_at = greatest(created_at + interval '1 microsecond', now()),
        public_expires_at = greatest(
          created_at + interval '2 microseconds',
          case
            when target_reason = 'compromise' then now() + interval '1 second'
            else now() + interval '7 days'
          end
        )
    where rotates_at > now()
    returning id
  )
  select count(*)::bigint into affected from rotated;

  insert into public.security_events (event_type, outcome, metadata)
  values (
    'oidc.signing_key.rotation_requested',
    'success',
    jsonb_build_object('reason', target_reason, 'key_count', affected)
  );
  return affected;
end
$$;

revoke all on function zeus_private.request_oidc_signing_key_rotation(text) from public;
