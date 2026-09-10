-- Keep OIDC protocol credentials behind purpose-built SECURITY DEFINER functions.

revoke all on table oidc_clients,
  oidc_client_redirect_uris,
  oidc_subjects,
  oidc_consents,
  oidc_authorization_transactions,
  oidc_authorization_codes,
  oidc_refresh_token_families,
  oidc_refresh_tokens,
  oidc_signing_keys,
  oidc_access_token_revocations
  from public;

revoke all on table oidc_clients,
  oidc_consents,
  oidc_subjects,
  oidc_authorization_transactions,
  oidc_authorization_codes,
  oidc_refresh_token_families,
  oidc_refresh_tokens,
  oidc_signing_keys,
  oidc_access_token_revocations
  from zeus_http;

grant select (id, organization_id, client_id, name, client_type, trusted,
  allowed_scopes, status, revision, created_by, created_at, updated_at, revoked_at),
  insert (organization_id, client_id, name, client_type, client_secret_hash,
    trusted, allowed_scopes, created_by),
  update (name, trusted, allowed_scopes, status, revision, updated_at, revoked_at)
  on oidc_clients to zeus_http;
grant select, insert, update, delete on oidc_client_redirect_uris to zeus_http;

-- These RLS-protected identity tables were created after the original HTTP-role
-- grant baseline. Keep their write surface aligned with the existing handlers.
grant select, update on organization_identity_policies to zeus_http;
grant select, insert, update on organization_invitations to zeus_http;
grant insert on organization_invitation_workspaces to zeus_http;
grant select, insert, update on organization_domains to zeus_http;

revoke all on function zeus_private.load_oidc_client(text) from public;
revoke all on function zeus_private.oidc_user_is_member(uuid, uuid, uuid) from public;
revoke all on function zeus_private.load_oidc_organization_policy(uuid, uuid, uuid) from public;
revoke all on function zeus_private.get_or_create_oidc_subject(uuid, uuid) from public;
revoke all on function zeus_private.oidc_consent_covers(uuid, uuid, text[]) from public;
revoke all on function zeus_private.create_oidc_authorization_transaction(
  uuid, uuid, uuid, uuid, bytea, text, text[], text, text, text, timestamptz
) from public;
revoke all on function zeus_private.load_oidc_authorization_transaction(uuid, uuid, uuid) from public;
revoke all on function zeus_private.consume_oidc_authorization_transaction(
  uuid, uuid, uuid, boolean, bytea
) from public;
revoke all on function zeus_private.issue_oidc_authorization_code(
  uuid, uuid, uuid, uuid, bytea, text, text[], text, text
) from public;
revoke all on function zeus_private.claim_oidc_authorization_code(bytea, uuid, text) from public;
revoke all on function zeus_private.create_oidc_refresh_family(
  uuid, uuid, uuid, uuid, text[], timestamptz, bytea
) from public;
revoke all on function zeus_private.rotate_oidc_refresh_token(bytea, uuid, bytea) from public;
revoke all on function zeus_private.revoke_oidc_refresh_token(bytea, uuid, text) from public;
revoke all on function zeus_private.install_oidc_signing_key(
  text, bytea, bytea, text, text, text
) from public;
revoke all on function zeus_private.load_current_oidc_signing_key() from public;
revoke all on function zeus_private.list_oidc_public_keys() from public;
revoke all on function zeus_private.cleanup_oidc_protocol_state() from public;
revoke all on function zeus_private.load_oidc_userinfo(uuid, uuid) from public;
revoke all on function zeus_private.list_oidc_user_grants(uuid) from public;
revoke all on function zeus_private.revoke_oidc_user_grant(uuid, uuid) from public;
revoke all on function zeus_private.record_oidc_access_revocation(
  text, uuid, uuid, uuid, timestamptz
) from public;
revoke all on function zeus_private.oidc_access_token_is_revoked(text) from public;

grant execute on function zeus_private.load_oidc_client(text) to zeus_http;
grant execute on function zeus_private.oidc_user_is_member(uuid, uuid, uuid) to zeus_http;
grant execute on function zeus_private.load_oidc_organization_policy(uuid, uuid, uuid) to zeus_http;
grant execute on function zeus_private.get_or_create_oidc_subject(uuid, uuid) to zeus_http;
grant execute on function zeus_private.oidc_consent_covers(uuid, uuid, text[]) to zeus_http;
grant execute on function zeus_private.create_oidc_authorization_transaction(
  uuid, uuid, uuid, uuid, bytea, text, text[], text, text, text, timestamptz
) to zeus_http;
grant execute on function zeus_private.load_oidc_authorization_transaction(uuid, uuid, uuid) to zeus_http;
grant execute on function zeus_private.consume_oidc_authorization_transaction(
  uuid, uuid, uuid, boolean, bytea
) to zeus_http;
grant execute on function zeus_private.issue_oidc_authorization_code(
  uuid, uuid, uuid, uuid, bytea, text, text[], text, text
) to zeus_http;
grant execute on function zeus_private.claim_oidc_authorization_code(bytea, uuid, text) to zeus_http;
grant execute on function zeus_private.create_oidc_refresh_family(
  uuid, uuid, uuid, uuid, text[], timestamptz, bytea
) to zeus_http;
grant execute on function zeus_private.rotate_oidc_refresh_token(bytea, uuid, bytea) to zeus_http;
grant execute on function zeus_private.revoke_oidc_refresh_token(bytea, uuid, text) to zeus_http;
grant execute on function zeus_private.install_oidc_signing_key(
  text, bytea, bytea, text, text, text
) to zeus_http;
grant execute on function zeus_private.load_current_oidc_signing_key() to zeus_http;
grant execute on function zeus_private.list_oidc_public_keys() to zeus_http;
grant execute on function zeus_private.cleanup_oidc_protocol_state() to zeus_http;
grant execute on function zeus_private.load_oidc_userinfo(uuid, uuid) to zeus_http;
grant execute on function zeus_private.list_oidc_user_grants(uuid) to zeus_http;
grant execute on function zeus_private.revoke_oidc_user_grant(uuid, uuid) to zeus_http;
grant execute on function zeus_private.record_oidc_access_revocation(
  text, uuid, uuid, uuid, timestamptz
) to zeus_http;
grant execute on function zeus_private.oidc_access_token_is_revoked(text) to zeus_http;
