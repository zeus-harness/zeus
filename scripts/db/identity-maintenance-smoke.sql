\set ON_ERROR_STOP on

begin;

do $identity_smoke$
declare
  email_id uuid;
  first_claim record;
  second_claim record;
  old_completion boolean;
  current_completion boolean;
  observed_backlog bigint;
begin
  if exists (
    select 1 from email_outbox where status in ('queued', 'sending')
  ) then
    raise exception 'identity maintenance smoke test requires an empty email backlog';
  end if;

  select zeus_private.queue_identity_email(
    'identity_smoke',
    'identity-smoke@example.invalid',
    decode('01', 'hex'),
    decode('02', 'hex'),
    decode('03', 'hex'),
    decode('04', 'hex'),
    'identity-smoke-key',
    now()
  ) into email_id;

  select * into first_claim
  from zeus_private.claim_identity_email('identity-smoke-a', 10);
  if first_claim.email_id is distinct from email_id then
    raise exception 'first identity email claim did not return the test message';
  end if;

  update email_outbox
  set lease_expires_at = now() - interval '1 second'
  where id = email_id;

  select * into second_claim
  from zeus_private.claim_identity_email('identity-smoke-b', 10);
  if second_claim.email_id is distinct from email_id
     or second_claim.fence_token <= first_claim.fence_token then
    raise exception 'expired identity email lease was not recovered with a new fence';
  end if;

  select email_backlog into observed_backlog
  from zeus_private.identity_operational_metrics();
  if observed_backlog <> 1 then
    raise exception 'identity email backlog metric did not observe the leased message';
  end if;

  select zeus_private.finish_identity_email(
    email_id,
    'identity-smoke-a',
    first_claim.fence_token,
    'sent',
    null,
    null,
    0
  ) into old_completion;
  if old_completion then
    raise exception 'stale identity email fence completed the message';
  end if;

  select zeus_private.finish_identity_email(
    email_id,
    'identity-smoke-b',
    second_claim.fence_token,
    'sent',
    null,
    null,
    0
  ) into current_completion;
  if not current_completion then
    raise exception 'current identity email fence could not complete the message';
  end if;
end
$identity_smoke$;

rollback;
