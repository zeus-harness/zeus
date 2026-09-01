use serde_json::json;
use uuid::Uuid;
use zeus_api::{
    HTTP_DATABASE_ROLE, RUNTIME_DATABASE_ROLE, connect_pool, connect_pool_as_role,
    crypto::sha256,
    database::{TenantScope, begin_tenant},
    migrate,
};

#[tokio::test]
#[ignore = "requires ZEUS_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)] // One matrix verifies control-plane and RLS grant boundaries.
async fn platform_tenant_access_is_session_bound_audited_and_membership_free() {
    let database_url = std::env::var("ZEUS_TEST_DATABASE_URL")
        .expect("ZEUS_TEST_DATABASE_URL is required for this ignored test");
    let owner_pool = connect_pool(&database_url, 3)
        .await
        .expect("owner database connects");
    migrate(&owner_pool).await.expect("test database migrates");
    let http_pool = connect_pool_as_role(&database_url, 3, HTTP_DATABASE_ROLE)
        .await
        .expect("HTTP role connects");
    let runtime_pool = connect_pool_as_role(&database_url, 1, RUNTIME_DATABASE_ROLE)
        .await
        .expect("Runtime role connects");

    let platform_user_id = Uuid::now_v7();
    let platform_session_id = Uuid::now_v7();
    let tenant_owner_id = Uuid::now_v7();
    let organization_id = Uuid::now_v7();
    let workspace_id = Uuid::now_v7();
    let provider_id = Uuid::now_v7();

    sqlx::query(
        "insert into users (id, email, display_name, status, email_verified_at)
         values
           ($1, $2, 'Platform Admin', 'active', now()),
           ($3, $4, 'Tenant Owner', 'active', now())",
    )
    .bind(platform_user_id)
    .bind(format!("platform-{platform_user_id}@example.test"))
    .bind(tenant_owner_id)
    .bind(format!("owner-{tenant_owner_id}@example.test"))
    .execute(&owner_pool)
    .await
    .expect("users insert");
    sqlx::query(
        "insert into platform_role_assignments (user_id, role, assigned_by)
         values ($1, 'platform_admin', $1)",
    )
    .bind(platform_user_id)
    .execute(&owner_pool)
    .await
    .expect("platform role inserts");
    sqlx::query(
        "insert into user_totp_credentials (
           user_id, encrypted_secret, secret_nonce, key_id, confirmed_at
         ) values ($1, decode('01', 'hex'), decode('02', 'hex'), 'test', now())",
    )
    .bind(platform_user_id)
    .execute(&owner_pool)
    .await
    .expect("platform TOTP inserts");
    sqlx::query(
        "insert into web_sessions (
           id, user_id, token_hash, csrf_token_hash, auth_methods,
           authenticated_at, mfa_satisfied_at, idle_expires_at, absolute_expires_at
         ) values (
           $1, $2, $3, $4, array['password', 'totp'], now(), now(),
           now() + interval '2 hours', now() + interval '12 hours'
         )",
    )
    .bind(platform_session_id)
    .bind(platform_user_id)
    .bind(sha256(
        format!("platform-session-{platform_session_id}").as_bytes(),
    ))
    .bind(sha256(
        format!("platform-csrf-{platform_session_id}").as_bytes(),
    ))
    .execute(&owner_pool)
    .await
    .expect("platform session inserts");

    let provision_slug = format!("provision-{platform_session_id}");
    let provision_workspace_slug = format!("initial-{platform_session_id}");
    let provision_owner_email = format!("provision-owner-{platform_session_id}@example.test");
    let provision_hash = sha256(b"platform organization request");
    let created = sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            String,
            String,
            i64,
            String,
            Uuid,
            String,
            String,
            Uuid,
            String,
            time::OffsetDateTime,
            bool,
        ),
    >(
        "select * from zeus_private.create_platform_organization(
           $1, $2, 'provision-request', $3, $4, 'Provisioned Tenant',
           $5, 'Initial Workspace', $6, $7, 'platform_managed'
         )",
    )
    .bind(platform_user_id)
    .bind(platform_session_id)
    .bind(&provision_hash)
    .bind(&provision_slug)
    .bind(&provision_workspace_slug)
    .bind(&provision_owner_email)
    .bind(sha256(b"provision-owner-token"))
    .fetch_one(&http_pool)
    .await
    .expect("platform Organization creates");
    assert_eq!(created.3, "provisioning");
    assert_eq!(created.5, "platform_managed");
    assert!(!created.12);

    let replay_result = sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            String,
            String,
            i64,
            String,
            Uuid,
            String,
            String,
            Uuid,
            String,
            time::OffsetDateTime,
            bool,
        ),
    >(
        "select * from zeus_private.create_platform_organization(
           $1, $2, 'provision-request', $3, $4, 'Provisioned Tenant',
           $5, 'Initial Workspace', $6, $7, 'platform_managed'
         )",
    )
    .bind(platform_user_id)
    .bind(platform_session_id)
    .bind(&provision_hash)
    .bind(&provision_slug)
    .bind(&provision_workspace_slug)
    .bind(&provision_owner_email)
    .bind(sha256(b"ignored-replay-token"))
    .fetch_one(&http_pool)
    .await
    .expect("platform Organization replay returns");
    assert_eq!(replay_result.0, created.0);
    assert_eq!(replay_result.6, created.6);
    assert_eq!(replay_result.9, created.9);
    assert!(replay_result.12);

    let mismatch = sqlx::query(
        "select * from zeus_private.create_platform_organization(
           $1, $2, 'provision-request', $3, $4, 'Provisioned Tenant',
           $5, 'Initial Workspace', $6, $7, 'platform_managed'
         )",
    )
    .bind(platform_user_id)
    .bind(platform_session_id)
    .bind(sha256(b"different platform organization request"))
    .bind(&provision_slug)
    .bind(&provision_workspace_slug)
    .bind(&provision_owner_email)
    .bind(sha256(b"mismatch-token"))
    .execute(&http_pool)
    .await
    .expect_err("idempotency mismatch rejects");
    assert_eq!(
        mismatch
            .as_database_error()
            .and_then(|error| error.code().map(std::borrow::Cow::into_owned))
            .as_deref(),
        Some("ZX001")
    );

    let resent = sqlx::query_as::<_, (Uuid, String, i64, Uuid, String, time::OffsetDateTime)>(
        "select * from zeus_private.rotate_platform_owner_invitation(
           $1, $2, $3, 1, 'resend', null, $4
         )",
    )
    .bind(platform_user_id)
    .bind(platform_session_id)
    .bind(created.0)
    .bind(sha256(b"resent-owner-token"))
    .fetch_one(&http_pool)
    .await
    .expect("initial Owner invitation resends");
    assert_eq!(resent.2, 2);
    assert_eq!(resent.3, created.9);

    let replacement_email = format!("replacement-{platform_session_id}@example.test");
    let replaced = sqlx::query_as::<_, (Uuid, String, i64, Uuid, String, time::OffsetDateTime)>(
        "select * from zeus_private.rotate_platform_owner_invitation(
           $1, $2, $3, 2, 'replace', $4, $5
         )",
    )
    .bind(platform_user_id)
    .bind(platform_session_id)
    .bind(created.0)
    .bind(&replacement_email)
    .bind(sha256(b"replacement-owner-token"))
    .fetch_one(&http_pool)
    .await
    .expect("initial Owner invitation replaces");
    assert_eq!(replaced.2, 3);
    assert_ne!(replaced.3, created.9);
    assert_eq!(replaced.4, replacement_email);

    let updated = sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            String,
            String,
            i64,
            String,
            i64,
            time::OffsetDateTime,
            time::OffsetDateTime,
            Option<time::OffsetDateTime>,
        ),
    >(
        "select * from zeus_private.update_platform_organization(
           $1, $2, $3, 3, 'Provisioned Tenant Updated', null, 'self_service'
         )",
    )
    .bind(platform_user_id)
    .bind(platform_session_id)
    .bind(created.0)
    .fetch_one(&http_pool)
    .await
    .expect("platform Organization updates with revision");
    assert_eq!(updated.4, 4);
    assert_eq!(updated.5, "self_service");

    let archived = sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            String,
            String,
            i64,
            String,
            i64,
            time::OffsetDateTime,
            time::OffsetDateTime,
            Option<time::OffsetDateTime>,
        ),
    >(
        "select * from zeus_private.transition_platform_organization(
           $1, $2, $3, 4, 'archive'
         )",
    )
    .bind(platform_user_id)
    .bind(platform_session_id)
    .bind(created.0)
    .fetch_one(&http_pool)
    .await
    .expect("provisioning Organization archives");
    assert_eq!(archived.3, "archived");
    assert_eq!(archived.4, 5);

    let restored_status: String = sqlx::query_scalar(
        "select status from zeus_private.transition_platform_organization(
           $1, $2, $3, 5, 'restore'
         )",
    )
    .bind(platform_user_id)
    .bind(platform_session_id)
    .bind(created.0)
    .fetch_one(&http_pool)
    .await
    .expect("archived Organization restores to suspended");
    assert_eq!(restored_status, "suspended");

    let mut tenant = owner_pool.begin().await.expect("tenant transaction starts");
    sqlx::query(
        "insert into organizations (id, slug, name, status)
         values ($1, $2, 'Support Target', 'provisioning')",
    )
    .bind(organization_id)
    .bind(format!("support-{organization_id}"))
    .execute(&mut *tenant)
    .await
    .expect("organization inserts");
    sqlx::query(
        "insert into organization_governance (
           organization_id, identity_settings_mode, updated_by
         ) values ($1, 'platform_managed', $2)",
    )
    .bind(organization_id)
    .bind(platform_user_id)
    .execute(&mut *tenant)
    .await
    .expect("governance inserts");
    sqlx::query(
        "insert into organization_identity_policies (organization_id, updated_by)
         values ($1, $2)",
    )
    .bind(organization_id)
    .bind(platform_user_id)
    .execute(&mut *tenant)
    .await
    .expect("identity policy inserts");
    sqlx::query(
        "insert into workspaces (id, organization_id, slug, name)
         values ($1, $2, $3, 'Support Workspace')",
    )
    .bind(workspace_id)
    .bind(organization_id)
    .bind(format!("workspace-{workspace_id}"))
    .execute(&mut *tenant)
    .await
    .expect("workspace inserts");
    sqlx::query(
        "insert into organization_memberships (organization_id, user_id, role)
         values ($1, $2, 'owner')",
    )
    .bind(organization_id)
    .bind(tenant_owner_id)
    .execute(&mut *tenant)
    .await
    .expect("Organization Owner inserts");
    sqlx::query(
        "insert into workspace_memberships (organization_id, workspace_id, user_id, role)
         values ($1, $2, $3, 'owner')",
    )
    .bind(organization_id)
    .bind(workspace_id)
    .bind(tenant_owner_id)
    .execute(&mut *tenant)
    .await
    .expect("Workspace Owner inserts");
    sqlx::query("update organizations set status = 'active' where id = $1")
        .bind(organization_id)
        .execute(&mut *tenant)
        .await
        .expect("organization activates");
    sqlx::query(
        "insert into federated_identity_providers (
           id, organization_id, slug, issuer_url, client_id,
           encrypted_client_secret, secret_nonce, key_id
         ) values (
           $1, $2, 'support-idp', 'https://idp.example.test', 'support-client',
           decode('01', 'hex'), decode('02', 'hex'), 'test'
         )",
    )
    .bind(provider_id)
    .bind(organization_id)
    .execute(&mut *tenant)
    .await
    .expect("platform-managed provider inserts");
    tenant.commit().await.expect("tenant transaction commits");

    let grant = sqlx::query_as::<_, (Uuid, Uuid, String, String, String, time::OffsetDateTime)>(
        "select * from zeus_private.create_platform_tenant_access_grant(
           $1, $2, $3, $4, 60, $5, $6
         )",
    )
    .bind(platform_user_id)
    .bind(platform_session_id)
    .bind(organization_id)
    .bind("Investigate tenant identity configuration")
    .bind(sha256(b"rotated-platform-session"))
    .bind(sha256(b"rotated-platform-csrf"))
    .fetch_one(&http_pool)
    .await
    .expect("support grant creates");
    assert_eq!(grant.1, organization_id);
    assert_eq!(grant.3, "active");

    let listed = sqlx::query_as::<_, (Uuid, Option<String>, bool, bool, bool, serde_json::Value)>(
        "select organization_id, organization_role, support_access,
                can_manage_organization, can_manage_identity_settings, workspaces
         from zeus_private.list_user_organizations($1, $2)",
    )
    .bind(platform_user_id)
    .bind(platform_session_id)
    .fetch_all(&http_pool)
    .await
    .expect("support Workspace selector loads");
    let support_organization = listed
        .iter()
        .find(|row| row.0 == organization_id)
        .expect("support Organization is listed without Membership");
    assert_eq!(support_organization.1, None);
    assert!(support_organization.2);
    assert!(support_organization.3);
    assert!(support_organization.4);
    let support_workspaces = support_organization
        .5
        .as_array()
        .expect("support Workspaces are an array");
    assert_eq!(support_workspaces.len(), 1);
    assert_eq!(support_workspaces[0]["id"], workspace_id.to_string());
    assert_eq!(support_workspaces[0]["role"], "platform_support");

    let context_rotated: bool = sqlx::query_scalar(
        "select zeus_private.rotate_user_session_context_with_access(
           $1, $2, $3, $4, $5, $6, $7
         )",
    )
    .bind(platform_session_id)
    .bind(platform_user_id)
    .bind(organization_id)
    .bind(workspace_id)
    .bind(sha256(b"workspace-platform-session"))
    .bind(sha256(b"workspace-platform-csrf"))
    .bind(grant.0)
    .fetch_one(&http_pool)
    .await
    .expect("support Workspace context rotates");
    assert!(context_rotated);
    let selected_context: (Option<Uuid>, Option<Uuid>) = sqlx::query_as(
        "select active_organization_id, active_workspace_id
         from web_sessions where id = $1",
    )
    .bind(platform_session_id)
    .fetch_one(&owner_pool)
    .await
    .expect("support Session context reads");
    assert_eq!(
        selected_context,
        (Some(organization_id), Some(workspace_id))
    );
    let validated_workspace: Option<Uuid> = sqlx::query_scalar(
        "select workspace_id
         from zeus_private.validate_platform_tenant_access_grant($1, $2, $3)",
    )
    .bind(grant.0)
    .bind(platform_user_id)
    .bind(platform_session_id)
    .fetch_one(&http_pool)
    .await
    .expect("support Grant retains selected Workspace");
    assert_eq!(validated_workspace, Some(workspace_id));

    let membership_exists: bool = sqlx::query_scalar(
        "select exists (
           select 1 from organization_memberships
           where organization_id = $1 and user_id = $2
         )",
    )
    .bind(organization_id)
    .bind(platform_user_id)
    .fetch_one(&owner_pool)
    .await
    .expect("membership absence reads");
    assert!(
        !membership_exists,
        "support Grant must not create Membership"
    );

    let mut granted = begin_tenant(
        &http_pool,
        TenantScope {
            user_id: Some(platform_user_id),
            session_id: Some(platform_session_id),
            organization_id,
            workspace_id: None,
            tenant_access_grant_id: Some(grant.0),
        },
    )
    .await
    .expect("grant RLS transaction starts");
    let visible_provider: Option<Uuid> =
        sqlx::query_scalar("select id from federated_identity_providers where id = $1")
            .bind(provider_id)
            .fetch_optional(&mut *granted)
            .await
            .expect("grant RLS query succeeds");
    assert_eq!(visible_provider, Some(provider_id));
    granted
        .commit()
        .await
        .expect("grant RLS transaction commits");

    let wrong_session_id = Uuid::now_v7();
    let mut wrong_session = begin_tenant(
        &http_pool,
        TenantScope {
            user_id: Some(platform_user_id),
            session_id: Some(wrong_session_id),
            organization_id,
            workspace_id: None,
            tenant_access_grant_id: Some(grant.0),
        },
    )
    .await
    .expect("wrong-session RLS transaction starts");
    let hidden_provider: Option<Uuid> =
        sqlx::query_scalar("select id from federated_identity_providers where id = $1")
            .bind(provider_id)
            .fetch_optional(&mut *wrong_session)
            .await
            .expect("wrong-session RLS query succeeds");
    assert_eq!(hidden_provider, None);
    wrong_session
        .commit()
        .await
        .expect("wrong-session transaction commits");

    let support_event_recorded: bool = sqlx::query_scalar(
        "select zeus_private.record_platform_support_operation(
           $1, $2, $3, $4, null, 'identity_policy.updated',
           'organization_identity_policy', $4, $5
         )",
    )
    .bind(platform_user_id)
    .bind(platform_session_id)
    .bind(grant.0)
    .bind(organization_id)
    .bind("Investigate tenant identity configuration")
    .fetch_one(&http_pool)
    .await
    .expect("support security event records");
    assert!(support_event_recorded);

    let queued_run_id =
        insert_queued_run(&owner_pool, organization_id, workspace_id, tenant_owner_id).await;
    let suspended_status: String = sqlx::query_scalar(
        "select status from zeus_private.transition_platform_organization(
           $1, $2, $3, 1, 'suspend'
         )",
    )
    .bind(platform_user_id)
    .bind(platform_session_id)
    .bind(organization_id)
    .fetch_one(&http_pool)
    .await
    .expect("active Organization suspends");
    assert_eq!(suspended_status, "suspended");
    let cancellation_requested: bool =
        sqlx::query_scalar("select cancel_requested_at is not null from runs where id = $1")
            .bind(queued_run_id)
            .fetch_one(&owner_pool)
            .await
            .expect("suspended Run cancellation reads");
    assert!(cancellation_requested);

    sqlx::query(
        "update runs
         set cancel_requested_at = null, available_at = '1900-01-01 00:00:00+00'
         where id = $1",
    )
    .bind(queued_run_id)
    .execute(&owner_pool)
    .await
    .expect("out-of-band queued Run fixture resets cancellation");
    let mut runtime_transaction = runtime_pool
        .begin()
        .await
        .expect("Runtime claim transaction starts");
    let claimed: Option<Uuid> =
        sqlx::query_scalar("select run_id from zeus_private.claim_run('tenant-state-test', 30)")
            .fetch_optional(&mut *runtime_transaction)
            .await
            .expect("Runtime claim checks Organization state");
    assert_ne!(claimed, Some(queued_run_id));
    runtime_transaction
        .rollback()
        .await
        .expect("Runtime claim fixture rolls back");

    let revoked: bool = sqlx::query_scalar(
        "select zeus_private.revoke_platform_tenant_access_grant($1, $2, $3, $4)",
    )
    .bind(platform_user_id)
    .bind(platform_session_id)
    .bind(grant.0)
    .bind("test completed")
    .fetch_one(&http_pool)
    .await
    .expect("grant revokes");
    assert!(revoked);
    let valid_after_revoke: bool =
        sqlx::query_scalar("select zeus_private.platform_tenant_access_is_valid($1, $2, $3, $4)")
            .bind(grant.0)
            .bind(platform_user_id)
            .bind(platform_session_id)
            .bind(organization_id)
            .fetch_one(&owner_pool)
            .await
            .expect("grant validity reads");
    assert!(!valid_after_revoke);
    let revoked_context: (Option<Uuid>, Option<Uuid>) = sqlx::query_as(
        "select active_organization_id, active_workspace_id
         from web_sessions where id = $1",
    )
    .bind(platform_session_id)
    .fetch_one(&owner_pool)
    .await
    .expect("revoked support Session context reads");
    assert_eq!(revoked_context, (None, None));

    let event_count: i64 = sqlx::query_scalar(
        "select count(*) from audit_events
         where organization_id = $1
           and action in ('platform.tenant_access_granted', 'platform.tenant_access_revoked')
           and metadata ->> 'grant_id' = $2",
    )
    .bind(organization_id)
    .bind(grant.0.to_string())
    .fetch_one(&owner_pool)
    .await
    .expect("grant audit reads");
    assert_eq!(event_count, 2);
    let security_event_count: i64 = sqlx::query_scalar(
        "select count(*) from security_events
         where organization_id = $1
           and event_type = 'platform.support_operation'
           and metadata ->> 'grant_id' = $2",
    )
    .bind(organization_id)
    .bind(grant.0.to_string())
    .fetch_one(&owner_pool)
    .await
    .expect("support security event reads");
    assert_eq!(security_event_count, 1);
}

#[allow(clippy::too_many_lines)] // The fixture keeps every required Run foreign key explicit.
async fn insert_queued_run(
    pool: &sqlx::PgPool,
    organization_id: Uuid,
    workspace_id: Uuid,
    user_id: Uuid,
) -> Uuid {
    let connection_id = Uuid::now_v7();
    let model_profile_id = Uuid::now_v7();
    let agent_id = Uuid::now_v7();
    let agent_version_id = Uuid::now_v7();
    let workflow_id = Uuid::now_v7();
    let workflow_version_id = Uuid::now_v7();
    let session_id = Uuid::now_v7();
    let run_id = Uuid::now_v7();

    sqlx::query(
        "insert into connections (
           id, organization_id, workspace_id, name, provider_kind
         ) values ($1, $2, $3, $4, 'openai_compatible')",
    )
    .bind(connection_id)
    .bind(organization_id)
    .bind(workspace_id)
    .bind(format!("tenant-state-{connection_id}"))
    .execute(pool)
    .await
    .expect("Run fixture Connection inserts");
    sqlx::query(
        "insert into model_profiles (
           id, organization_id, workspace_id, connection_id, name,
           base_url, model
         ) values ($1, $2, $3, $4, $5, 'https://model.example.test', 'test')",
    )
    .bind(model_profile_id)
    .bind(organization_id)
    .bind(workspace_id)
    .bind(connection_id)
    .bind(format!("tenant-state-{model_profile_id}"))
    .execute(pool)
    .await
    .expect("Run fixture Model Profile inserts");
    sqlx::query(
        "insert into agents (id, organization_id, workspace_id, name)
         values ($1, $2, $3, $4)",
    )
    .bind(agent_id)
    .bind(organization_id)
    .bind(workspace_id)
    .bind(format!("tenant-state-{agent_id}"))
    .execute(pool)
    .await
    .expect("Run fixture Agent inserts");
    sqlx::query(
        "insert into agent_versions (
           id, organization_id, workspace_id, agent_id, version_number,
           instructions, created_by
         ) values ($1, $2, $3, $4, 1, 'test', $5)",
    )
    .bind(agent_version_id)
    .bind(organization_id)
    .bind(workspace_id)
    .bind(agent_id)
    .bind(user_id)
    .execute(pool)
    .await
    .expect("Run fixture Agent Version inserts");
    sqlx::query(
        "insert into workflows (id, organization_id, workspace_id, name)
         values ($1, $2, $3, $4)",
    )
    .bind(workflow_id)
    .bind(organization_id)
    .bind(workspace_id)
    .bind(format!("tenant-state-{workflow_id}"))
    .execute(pool)
    .await
    .expect("Run fixture Workflow inserts");
    sqlx::query(
        "insert into workflow_versions (
           id, organization_id, workspace_id, workflow_id, version_number,
           agent_version_id, model_profile_id, input_schema, output_schema, created_by
         ) values ($1, $2, $3, $4, 1, $5, $6, $7, $7, $8)",
    )
    .bind(workflow_version_id)
    .bind(organization_id)
    .bind(workspace_id)
    .bind(workflow_id)
    .bind(agent_version_id)
    .bind(model_profile_id)
    .bind(json!({ "type": "object" }))
    .bind(user_id)
    .execute(pool)
    .await
    .expect("Run fixture Workflow Version inserts");
    sqlx::query(
        "insert into sessions (
           id, organization_id, workspace_id, title, created_by
         ) values ($1, $2, $3, 'Tenant state test', $4)",
    )
    .bind(session_id)
    .bind(organization_id)
    .bind(workspace_id)
    .bind(user_id)
    .execute(pool)
    .await
    .expect("Run fixture Session inserts");
    sqlx::query(
        "insert into runs (
           id, organization_id, workspace_id, workflow_version_id,
           session_id, idempotency_key, created_by
         ) values ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(run_id)
    .bind(organization_id)
    .bind(workspace_id)
    .bind(workflow_version_id)
    .bind(session_id)
    .bind(format!("tenant-state-{run_id}"))
    .bind(user_id)
    .execute(pool)
    .await
    .expect("Run fixture Run inserts");

    run_id
}
