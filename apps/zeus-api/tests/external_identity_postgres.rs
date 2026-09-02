use serde_json::json;
use uuid::Uuid;
use zeus_api::{HTTP_DATABASE_ROLE, connect_pool, connect_pool_as_role, crypto::sha256, migrate};

#[tokio::test]
#[ignore = "requires ZEUS_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)] // One matrix verifies the global identity and tenant binding split.
async fn one_external_identity_can_hold_independent_organization_bindings() {
    let database_url = std::env::var("ZEUS_TEST_DATABASE_URL")
        .expect("ZEUS_TEST_DATABASE_URL is required for this ignored test");
    let pool = connect_pool(&database_url, 3)
        .await
        .expect("owner database connects");
    migrate(&pool).await.expect("test database migrates");
    let http_pool = connect_pool_as_role(&database_url, 2, HTTP_DATABASE_ROLE)
        .await
        .expect("HTTP role connects");

    let user_id = Uuid::now_v7();
    let session_id = Uuid::now_v7();
    let organization_a = Uuid::now_v7();
    let organization_b = Uuid::now_v7();
    let workspace_a = Uuid::now_v7();
    let workspace_b = Uuid::now_v7();
    let provider_a = Uuid::now_v7();
    let provider_b = Uuid::now_v7();
    let subject = format!("google-subject-{user_id}");
    let email = format!("external-{user_id}@example.test");
    let issuer = "https://accounts.example.test";

    sqlx::query(
        "insert into users (id, email, display_name, status, email_verified_at)
         values ($1, $2, 'External Identity User', 'active', now())",
    )
    .bind(user_id)
    .bind(&email)
    .execute(&pool)
    .await
    .expect("user inserts");

    for (organization_id, workspace_id, label) in [
        (organization_a, workspace_a, "a"),
        (organization_b, workspace_b, "b"),
    ] {
        sqlx::query(
            "insert into organizations (id, slug, name, status)
             values ($1, $2, $3, 'provisioning')",
        )
        .bind(organization_id)
        .bind(format!("external-{label}-{organization_id}"))
        .bind(format!("External Organization {label}"))
        .execute(&pool)
        .await
        .expect("organization inserts");
        sqlx::query(
            "insert into organization_governance (organization_id, updated_by)
             values ($1, $2)",
        )
        .bind(organization_id)
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("organization governance inserts");
        sqlx::query(
            "insert into organization_identity_policies (organization_id, updated_by)
             values ($1, $2)",
        )
        .bind(organization_id)
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("organization identity policy inserts");
        sqlx::query(
            "insert into workspaces (id, organization_id, slug, name)
             values ($1, $2, $3, $4)",
        )
        .bind(workspace_id)
        .bind(organization_id)
        .bind(format!("workspace-{label}-{workspace_id}"))
        .bind(format!("Workspace {label}"))
        .execute(&pool)
        .await
        .expect("workspace inserts");
        sqlx::query(
            "insert into organization_memberships (organization_id, user_id, role, status)
             values ($1, $2, 'owner', 'active')",
        )
        .bind(organization_id)
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("organization owner inserts");
        sqlx::query(
            "insert into workspace_memberships (
               organization_id, workspace_id, user_id, role, status
             ) values ($1, $2, $3, 'owner', 'active')",
        )
        .bind(organization_id)
        .bind(workspace_id)
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("workspace owner inserts");
        sqlx::query("update organizations set status = 'active' where id = $1")
            .bind(organization_id)
            .execute(&pool)
            .await
            .expect("organization activates");
    }

    for (provider_id, organization_id, slug, client_id) in [
        (provider_a, organization_a, "google-a", "google-client-a"),
        (provider_b, organization_b, "google-b", "google-client-b"),
    ] {
        sqlx::query(
            "insert into federated_identity_providers (
               id, organization_id, slug, issuer_url, client_id,
               encrypted_client_secret, secret_nonce, key_id
             ) values ($1, $2, $3, $4, $5, $6, $7, 'test-v1')",
        )
        .bind(provider_id)
        .bind(organization_id)
        .bind(slug)
        .bind(issuer)
        .bind(client_id)
        .bind(vec![1_u8; 32])
        .bind(vec![2_u8; 12])
        .execute(&pool)
        .await
        .expect("federated provider inserts");
    }

    sqlx::query(
        "insert into web_sessions (
           id, user_id, active_organization_id, active_workspace_id,
           token_hash, csrf_token_hash, auth_methods, authenticated_at,
           idle_expires_at, absolute_expires_at
         ) values (
           $1, $2, $3, $4, $5, $6, array['password'], now(),
           now() + interval '2 hours', now() + interval '12 hours'
         )",
    )
    .bind(session_id)
    .bind(user_id)
    .bind(organization_a)
    .bind(workspace_a)
    .bind(sha256(format!("session-{session_id}").as_bytes()))
    .bind(sha256(format!("csrf-{session_id}").as_bytes()))
    .execute(&pool)
    .await
    .expect("session inserts");

    let tenant_choices = sqlx::query_as::<_, (Uuid, Option<String>, serde_json::Value)>(
        "select organization_id, organization_role, workspaces
         from zeus_private.list_user_organizations($1, $2)",
    )
    .bind(user_id)
    .bind(session_id)
    .fetch_all(&http_pool)
    .await
    .expect("multi-Organization Workspace selector loads");
    assert_eq!(tenant_choices.len(), 2);
    for (organization_id, organization_role, workspaces) in &tenant_choices {
        assert_eq!(organization_role.as_deref(), Some("owner"));
        let workspaces = workspaces.as_array().expect("Workspaces are an array");
        assert_eq!(workspaces.len(), 1);
        assert_eq!(workspaces[0]["role"], "owner");
        assert!(
            [organization_a, organization_b].contains(organization_id),
            "selector must not introduce an unrelated Organization"
        );
    }

    let rotated_to_b: bool = sqlx::query_scalar(
        "select zeus_private.rotate_user_session_context_with_access(
           $1, $2, $3, $4, $5, $6, null
         )",
    )
    .bind(session_id)
    .bind(user_id)
    .bind(organization_b)
    .bind(workspace_b)
    .bind(sha256(b"external-session-rotated-b"))
    .bind(sha256(b"external-csrf-rotated-b"))
    .fetch_one(&http_pool)
    .await
    .expect("user rotates to the second Organization Workspace");
    assert!(rotated_to_b);
    let cross_organization_context: bool = sqlx::query_scalar(
        "select zeus_private.rotate_user_session_context_with_access(
           $1, $2, $3, $4, $5, $6, null
         )",
    )
    .bind(session_id)
    .bind(user_id)
    .bind(organization_a)
    .bind(workspace_b)
    .bind(sha256(b"external-session-cross-organization"))
    .bind(sha256(b"external-csrf-cross-organization"))
    .fetch_one(&http_pool)
    .await
    .expect("cross-Organization Workspace mismatch returns a stable result");
    assert!(!cross_organization_context);
    let selected_context: (Option<Uuid>, Option<Uuid>) = sqlx::query_as(
        "select active_organization_id, active_workspace_id
         from web_sessions where id = $1",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await
    .expect("rotated multi-tenant Session reads");
    assert_eq!(selected_context, (Some(organization_b), Some(workspace_b)));

    let linked = resolve(
        &pool,
        ResolveInput {
            provider_id: provider_a,
            purpose: "link",
            initiating_user_id: Some(user_id),
            issuer,
            subject: &subject,
            email: &email,
            claims: json!({ "tenant": "a" }),
        },
    )
    .await;
    assert_eq!(linked.0, "linked");
    assert_eq!(linked.1, Some(user_id));

    let authenticated = resolve(
        &pool,
        ResolveInput {
            provider_id: provider_b,
            purpose: "login",
            initiating_user_id: None,
            issuer,
            subject: &subject,
            email: &email,
            claims: json!({ "tenant": "b" }),
        },
    )
    .await;
    assert_eq!(authenticated.0, "authenticated");
    assert_eq!(authenticated.1, Some(user_id));
    assert_eq!(authenticated.2, organization_b);

    let identity_id: Uuid =
        sqlx::query_scalar("select id from external_identities where issuer = $1 and subject = $2")
            .bind(issuer)
            .bind(&subject)
            .fetch_one(&pool)
            .await
            .expect("global external identity reads");
    let bindings = sqlx::query_as::<_, (Uuid, Uuid, String, serde_json::Value)>(
        "select id, organization_id, status, claims
         from organization_federated_bindings
         where external_identity_id = $1
         order by organization_id",
    )
    .bind(identity_id)
    .fetch_all(&pool)
    .await
    .expect("organization bindings read");
    assert_eq!(bindings.len(), 2);
    assert!(bindings.iter().all(|binding| binding.2 == "active"));
    assert!(
        bindings
            .iter()
            .any(|binding| binding.3 == json!({ "tenant": "a" }))
    );
    assert!(
        bindings
            .iter()
            .any(|binding| binding.3 == json!({ "tenant": "b" }))
    );

    let binding_a = bindings
        .iter()
        .find(|binding| binding.1 == organization_a)
        .expect("organization A binding exists")
        .0;
    let binding_b = bindings
        .iter()
        .find(|binding| binding.1 == organization_b)
        .expect("organization B binding exists")
        .0;

    let cross_organization = sqlx::query(
        "insert into organization_federated_bindings (
           organization_id, provider_id, external_identity_id, claims, binding_source
         ) values ($1, $2, $3, '{}'::jsonb, 'explicit')",
    )
    .bind(organization_b)
    .bind(provider_a)
    .bind(identity_id)
    .execute(&pool)
    .await
    .expect_err("provider cannot be trusted outside its Organization");
    assert_eq!(database_code(&cross_organization).as_deref(), Some("23503"));

    let unlinked_a: bool = sqlx::query_scalar(
        "select zeus_private.unlink_organization_federated_binding($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(session_id)
    .bind(identity_id)
    .bind(binding_a)
    .fetch_one(&pool)
    .await
    .expect("Organization A binding unlinks");
    assert!(unlinked_a);
    let statuses = sqlx::query_as::<_, (Uuid, String)>(
        "select organization_id, status
         from organization_federated_bindings
         where external_identity_id = $1",
    )
    .bind(identity_id)
    .fetch_all(&pool)
    .await
    .expect("binding statuses read");
    assert!(statuses.contains(&(organization_a, "revoked".to_owned())));
    assert!(statuses.contains(&(organization_b, "active".to_owned())));

    let blocked_revoke: String =
        sqlx::query_scalar("select zeus_private.revoke_external_identity($1, $2, $3)")
            .bind(user_id)
            .bind(session_id)
            .bind(identity_id)
            .fetch_one(&pool)
            .await
            .expect("active binding blocks global revocation");
    assert_eq!(blocked_revoke, "active_bindings");

    let unlinked_b: bool = sqlx::query_scalar(
        "select zeus_private.unlink_organization_federated_binding($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(session_id)
    .bind(identity_id)
    .bind(binding_b)
    .fetch_one(&pool)
    .await
    .expect("Organization B binding unlinks");
    assert!(unlinked_b);
    let last_method: String =
        sqlx::query_scalar("select zeus_private.revoke_external_identity($1, $2, $3)")
            .bind(user_id)
            .bind(session_id)
            .bind(identity_id)
            .fetch_one(&pool)
            .await
            .expect("last login method is protected");
    assert_eq!(last_method, "last_sign_in_method");

    sqlx::query(
        "insert into user_password_credentials (user_id, password_hash)
         values ($1, '$argon2id$test-only')",
    )
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("alternative native sign-in method inserts");
    let revoked: String =
        sqlx::query_scalar("select zeus_private.revoke_external_identity($1, $2, $3)")
            .bind(user_id)
            .bind(session_id)
            .bind(identity_id)
            .fetch_one(&pool)
            .await
            .expect("global external identity revokes");
    assert_eq!(revoked, "revoked");
}

struct ResolveInput<'a> {
    provider_id: Uuid,
    purpose: &'a str,
    initiating_user_id: Option<Uuid>,
    issuer: &'a str,
    subject: &'a str,
    email: &'a str,
    claims: serde_json::Value,
}

async fn resolve(
    pool: &sqlx::PgPool,
    input: ResolveInput<'_>,
) -> (String, Option<Uuid>, Uuid, Option<Uuid>) {
    sqlx::query_as(
        "select * from zeus_private.resolve_external_identity(
           $1, $2, $3, $4, $5, $6, 'External Identity User', true, $7, '{}'::text[]
         )",
    )
    .bind(input.provider_id)
    .bind(input.purpose)
    .bind(input.initiating_user_id)
    .bind(input.issuer)
    .bind(input.subject)
    .bind(input.email)
    .bind(input.claims)
    .fetch_one(pool)
    .await
    .expect("external identity resolves")
}

fn database_code(error: &sqlx::Error) -> Option<String> {
    error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
}
