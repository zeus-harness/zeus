use time::OffsetDateTime;
use uuid::Uuid;
use zeus_api::{connect_pool, crypto::sha256, migrate};

#[tokio::test]
#[ignore = "requires ZEUS_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)] // One transaction contract covers provisioning and owner guards.
async fn provisioning_invitation_activates_exactly_one_owner_contract() {
    let database_url = std::env::var("ZEUS_TEST_DATABASE_URL")
        .expect("ZEUS_TEST_DATABASE_URL is required for this ignored test");
    let pool = connect_pool(&database_url, 3)
        .await
        .expect("owner database connects");
    migrate(&pool).await.expect("test database migrates");

    let platform_user_id = Uuid::now_v7();
    let invited_user_id = Uuid::now_v7();
    let organization_id = Uuid::now_v7();
    let workspace_id = Uuid::now_v7();
    let invitation_id = Uuid::now_v7();
    let session_id = Uuid::now_v7();
    let invited_email = format!("provisioned-{invited_user_id}@example.test");
    let invitation_token = format!("provisioning-invitation-{invitation_id}");

    sqlx::query(
        "insert into users (id, email, display_name, status, email_verified_at)
         values
           ($1, $2, 'Platform User', 'active', now()),
           ($3, $4, 'Invited Owner', 'active', now())",
    )
    .bind(platform_user_id)
    .bind(format!("platform-{platform_user_id}@example.test"))
    .bind(invited_user_id)
    .bind(&invited_email)
    .execute(&pool)
    .await
    .expect("users insert");
    sqlx::query(
        "insert into organizations (id, slug, name, status)
         values ($1, $2, 'Provisioning Test', 'provisioning')",
    )
    .bind(organization_id)
    .bind(format!("provisioning-{organization_id}"))
    .execute(&pool)
    .await
    .expect("provisioning organization inserts");
    sqlx::query(
        "insert into organization_governance (
           organization_id, identity_settings_mode, updated_by
         ) values ($1, 'platform_managed', $2)",
    )
    .bind(organization_id)
    .bind(platform_user_id)
    .execute(&pool)
    .await
    .expect("organization governance inserts");
    sqlx::query(
        "insert into workspaces (id, organization_id, slug, name)
         values ($1, $2, $3, 'Initial Workspace')",
    )
    .bind(workspace_id)
    .bind(organization_id)
    .bind(format!("initial-{workspace_id}"))
    .execute(&pool)
    .await
    .expect("initial workspace inserts");
    sqlx::query(
        "insert into web_sessions (
           id, user_id, token_hash, csrf_token_hash, auth_methods,
           authenticated_at, idle_expires_at, absolute_expires_at
         ) values (
           $1, $2, $3, $4, array['password'], now(),
           now() + interval '2 hours', now() + interval '12 hours'
         )",
    )
    .bind(session_id)
    .bind(invited_user_id)
    .bind(sha256(format!("session-{session_id}").as_bytes()))
    .bind(sha256(format!("csrf-{session_id}").as_bytes()))
    .execute(&pool)
    .await
    .expect("invited user session inserts");
    sqlx::query(
        "insert into organization_invitations (
           id, organization_id, invited_by, email, organization_role,
           invitation_kind, token_hash, expires_at
         ) values (
           $1, $2, $3, $4, 'owner', 'provisioning_owner', $5,
           now() + interval '7 days'
         )",
    )
    .bind(invitation_id)
    .bind(organization_id)
    .bind(platform_user_id)
    .bind(&invited_email)
    .bind(sha256(invitation_token.as_bytes()))
    .execute(&pool)
    .await
    .expect("provisioning invitation inserts");
    sqlx::query(
        "insert into organization_invitation_workspaces (
           invitation_id, organization_id, workspace_id, workspace_role
         ) values ($1, $2, $3, 'owner')",
    )
    .bind(invitation_id)
    .bind(organization_id)
    .bind(workspace_id)
    .execute(&pool)
    .await
    .expect("provisioning workspace grant inserts");

    let accepted = sqlx::query_as::<_, (Uuid, Option<Uuid>)>(
        "select * from zeus_private.accept_organization_invitation($1, $2, $3)",
    )
    .bind(invited_user_id)
    .bind(session_id)
    .bind(sha256(invitation_token.as_bytes()))
    .fetch_one(&pool)
    .await
    .expect("provisioning invitation accepts");
    assert_eq!(accepted, (organization_id, Some(workspace_id)));

    let state = sqlx::query_as::<_, (String, String, String, String, Option<OffsetDateTime>)>(
        "select o.status, om.role, wm.role, i.status, i.accepted_at
         from organizations o
         join organization_memberships om
           on om.organization_id = o.id and om.user_id = $2
         join workspace_memberships wm
           on wm.organization_id = o.id and wm.workspace_id = $3 and wm.user_id = $2
         join organization_invitations i on i.id = $4
         where o.id = $1",
    )
    .bind(organization_id)
    .bind(invited_user_id)
    .bind(workspace_id)
    .bind(invitation_id)
    .fetch_one(&pool)
    .await
    .expect("activated owner state reads");
    assert_eq!(state.0, "active");
    assert_eq!(state.1, "owner");
    assert_eq!(state.2, "owner");
    assert_eq!(state.3, "accepted");
    assert!(state.4.is_some());

    let replay =
        sqlx::query("select * from zeus_private.accept_organization_invitation($1, $2, $3)")
            .bind(invited_user_id)
            .bind(session_id)
            .bind(sha256(invitation_token.as_bytes()))
            .execute(&pool)
            .await
            .expect_err("provisioning invitation is single use");
    assert_eq!(database_code(&replay).as_deref(), Some("42501"));

    let workspace_demotion = sqlx::query(
        "update workspace_memberships
         set role = 'builder'
         where workspace_id = $1 and user_id = $2",
    )
    .bind(workspace_id)
    .bind(invited_user_id)
    .execute(&pool)
    .await
    .expect_err("last workspace owner cannot be demoted");
    assert_eq!(database_code(&workspace_demotion).as_deref(), Some("23514"));

    let organization_demotion = sqlx::query(
        "update organization_memberships
         set role = 'member'
         where organization_id = $1 and user_id = $2",
    )
    .bind(organization_id)
    .bind(invited_user_id)
    .execute(&pool)
    .await
    .expect_err("last organization owner cannot be demoted");
    assert_eq!(
        database_code(&organization_demotion).as_deref(),
        Some("23514")
    );

    let stale_admin_values: i64 = sqlx::query_scalar(
        "select
           (select count(*) from organization_memberships where role = 'admin')
           + (select count(*) from workspace_memberships where role = 'admin')
           + (select count(*) from organization_invitations where organization_role = 'admin')
           + (select count(*) from organization_invitation_workspaces where workspace_role = 'admin')",
    )
    .fetch_one(&pool)
    .await
    .expect("legacy role count reads");
    assert_eq!(stale_admin_values, 0);
}

fn database_code(error: &sqlx::Error) -> Option<String> {
    error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
}
