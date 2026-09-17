use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    http::{Method, Request, Response, StatusCode, header},
};
use http_body_util::BodyExt;
use secrecy::SecretString;
use serde_json::{Value, json};
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;
use zeus_api::{
    AppState, ExecutionRuntimeConfig, ExternalClients, HTTP_DATABASE_ROLE, IdentityRuntimeConfig,
    PlatformServices, connect_pool, connect_pool_as_role,
    crypto::{LocalEnvelopeCipher, hash_service_account_token, sha256},
    http, migrate,
    supervisor::SupervisorMetrics,
};
use zeus_identity::{PasswordExecutor, PasswordPolicy};

#[tokio::test]
#[ignore = "requires ZEUS_TEST_DATABASE_URL and ZEUS_TEST_ENVELOPE_KEY"]
#[allow(clippy::too_many_lines)] // One end-to-end flow verifies the complete tenant contract.
async fn control_plane_uses_rls_and_supports_versioned_resources() {
    let database_url = std::env::var("ZEUS_TEST_DATABASE_URL")
        .expect("ZEUS_TEST_DATABASE_URL is required for this ignored test");
    let envelope_key = SecretString::from(
        std::env::var("ZEUS_TEST_ENVELOPE_KEY")
            .expect("ZEUS_TEST_ENVELOPE_KEY is required for this ignored test"),
    );
    let owner_pool = connect_pool(&database_url, 3)
        .await
        .expect("owner database connects");
    migrate(&owner_pool).await.expect("test database migrates");

    let organization_id = Uuid::now_v7();
    let workspace_id = Uuid::now_v7();
    let other_workspace_id = Uuid::now_v7();
    sqlx::query(
        "insert into organizations (id, slug, name, status)
         values ($1, $2, 'Control Test', 'provisioning')",
    )
    .bind(organization_id)
    .bind(format!("control-{organization_id}"))
    .execute(&owner_pool)
    .await
    .expect("organization inserts");
    sqlx::query("insert into organization_governance (organization_id) values ($1)")
        .bind(organization_id)
        .execute(&owner_pool)
        .await
        .expect("organization governance inserts");
    sqlx::query(
        "insert into organization_identity_policies (organization_id)
         values ($1)",
    )
    .bind(organization_id)
    .execute(&owner_pool)
    .await
    .expect("organization identity policy inserts");
    for (id, name) in [
        (workspace_id, "Primary Workspace"),
        (other_workspace_id, "Other Workspace"),
    ] {
        sqlx::query(
            "insert into workspaces (id, organization_id, slug, name)
             values ($1, $2, $3, $4)",
        )
        .bind(id)
        .bind(organization_id)
        .bind(format!("workspace-{id}"))
        .bind(name)
        .execute(&owner_pool)
        .await
        .expect("workspace inserts");
    }

    let federated_provider_id = Uuid::now_v7();
    sqlx::query(
        "insert into federated_identity_providers (
            id, organization_id, slug, issuer_url, client_id,
            encrypted_client_secret, secret_nonce, key_id, jit_enabled
         ) values (
            $1, $2, 'control-provider', 'https://issuer.example.test',
            'control-client', $3, $4, 'test-v1', true
         )",
    )
    .bind(federated_provider_id)
    .bind(organization_id)
    .bind(vec![0_u8; 32])
    .bind(vec![0_u8; 12])
    .execute(&owner_pool)
    .await
    .expect("federated provider inserts");
    sqlx::query(
        "insert into federated_group_mappings (
            organization_id, provider_id, group_value, organization_role
         ) values ($1, $2, 'zeus-owners', 'owner')",
    )
    .bind(organization_id)
    .bind(federated_provider_id)
    .execute(&owner_pool)
    .await
    .expect("organization group mapping inserts");
    sqlx::query(
        "insert into federated_group_mappings (
            organization_id, provider_id, group_value, workspace_id, workspace_role
         ) values ($1, $2, 'zeus-builders', $3, 'builder')",
    )
    .bind(organization_id)
    .bind(federated_provider_id)
    .bind(workspace_id)
    .execute(&owner_pool)
    .await
    .expect("workspace group mapping inserts");

    let service_account_id = Uuid::now_v7();
    let token_prefix = format!("zsa_{}", &service_account_id.simple().to_string()[..12]);
    let token = format!("{token_prefix}.abcdefghijklmnopqrstuvwxyz1234567890ABCD");
    let token_hash = hash_service_account_token(&SecretString::from(token.clone()))
        .expect("service account token hashes");
    sqlx::query(
        "insert into service_accounts (
            id, organization_id, workspace_id, name, token_prefix, token_hash, scopes
         ) values ($1, $2, $3, 'Control Test', $4, $5, $6)",
    )
    .bind(service_account_id)
    .bind(organization_id)
    .bind(workspace_id)
    .bind(&token_prefix)
    .bind(token_hash)
    .bind(vec![
        "organization:manage",
        "workspace:manage",
        "workspace:read",
        "workflow:write",
        "run:operate",
        "approval:write",
        "audit:read",
    ])
    .execute(&owner_pool)
    .await
    .expect("service account inserts");

    let organization_service_account_id = Uuid::now_v7();
    let organization_token_prefix = format!(
        "zsa_{}",
        &organization_service_account_id.simple().to_string()[..12]
    );
    let organization_token =
        format!("{organization_token_prefix}.abcdefghijklmnopqrstuvwxyz1234567890WXYZ");
    let organization_token_hash =
        hash_service_account_token(&SecretString::from(organization_token.clone()))
            .expect("organization service account token hashes");
    sqlx::query(
        "insert into service_accounts (
            id, organization_id, name, token_prefix, token_hash, scopes
         ) values ($1, $2, 'Organization Control Test', $3, $4, $5)",
    )
    .bind(organization_service_account_id)
    .bind(organization_id)
    .bind(&organization_token_prefix)
    .bind(organization_token_hash)
    .bind(vec!["organization:manage"])
    .execute(&owner_pool)
    .await
    .expect("organization service account inserts");

    let http_pool = connect_pool_as_role(&database_url, 5, HTTP_DATABASE_ROLE)
        .await
        .expect("HTTP role database connects");
    let current_role: String = sqlx::query_scalar("select current_user")
        .fetch_one(&http_pool)
        .await
        .expect("HTTP role can query its identity");
    assert_eq!(current_role, HTTP_DATABASE_ROLE);

    let existing_user_id = Uuid::now_v7();
    let existing_email = format!("existing-{existing_user_id}@example.test");
    let existing_subject = format!("existing-subject-{existing_user_id}");
    sqlx::query(
        "insert into users (id, email, display_name, status, email_verified_at)
         values ($1, $2, 'Existing User', 'active', now())",
    )
    .bind(existing_user_id)
    .bind(&existing_email)
    .execute(&owner_pool)
    .await
    .expect("existing Zeus user inserts");
    sqlx::query(
        "insert into organization_memberships (organization_id, user_id, role, status)
         values ($1, $2, 'owner', 'active')",
    )
    .bind(organization_id)
    .bind(existing_user_id)
    .execute(&owner_pool)
    .await
    .expect("existing Zeus user joins organization");
    for target_workspace_id in [workspace_id, other_workspace_id] {
        sqlx::query(
            "insert into workspace_memberships (
               organization_id, workspace_id, user_id, role, status
             ) values ($1, $2, $3, 'owner', 'active')",
        )
        .bind(organization_id)
        .bind(target_workspace_id)
        .bind(existing_user_id)
        .execute(&owner_pool)
        .await
        .expect("workspace owner membership inserts");
    }
    sqlx::query("update organizations set status = 'active' where id = $1")
        .bind(organization_id)
        .execute(&owner_pool)
        .await
        .expect("organization activates after owners exist");
    let account_link_required = sqlx::query_as::<_, (String, Option<Uuid>, Uuid, Option<Uuid>)>(
        "select * from zeus_private.resolve_external_identity(
           $1, 'login', null, $2, $3, $4, $5, true, $6, $7
         )",
    )
    .bind(federated_provider_id)
    .bind("https://issuer.example.test")
    .bind(&existing_subject)
    .bind(&existing_email)
    .bind("Existing User")
    .bind(json!({ "groups": ["zeus-owners"] }))
    .bind(vec!["zeus-owners"])
    .fetch_one(&http_pool)
    .await
    .expect("same-email federated login is resolved safely");
    assert_eq!(account_link_required.0, "account_link_required");
    assert_eq!(account_link_required.1, None);
    let identity_count: i64 = sqlx::query_scalar(
        "select count(*) from external_identities
         where issuer = 'https://issuer.example.test' and subject = $1",
    )
    .bind(&existing_subject)
    .fetch_one(&owner_pool)
    .await
    .expect("federated identity count reads");
    assert_eq!(
        identity_count, 0,
        "same email must not auto-link an account"
    );

    let linked = sqlx::query_as::<_, (String, Option<Uuid>, Uuid, Option<Uuid>)>(
        "select * from zeus_private.resolve_external_identity(
           $1, 'link', $2, $3, $4, $5, $6, true, $7, $8
         )",
    )
    .bind(federated_provider_id)
    .bind(existing_user_id)
    .bind("https://issuer.example.test")
    .bind(&existing_subject)
    .bind(&existing_email)
    .bind("Existing User")
    .bind(json!({ "groups": ["zeus-owners"] }))
    .bind(vec!["zeus-owners"])
    .fetch_one(&http_pool)
    .await
    .expect("explicit link binds the upstream identity");
    assert_eq!(linked.0, "linked");
    assert_eq!(linked.1, Some(existing_user_id));

    let authenticated = sqlx::query_as::<_, (String, Option<Uuid>, Uuid, Option<Uuid>)>(
        "select * from zeus_private.resolve_external_identity(
           $1, 'login', null, $2, $3, $4, $5, true, $6, $7
         )",
    )
    .bind(federated_provider_id)
    .bind("https://issuer.example.test")
    .bind(&existing_subject)
    .bind(&existing_email)
    .bind("Existing User")
    .bind(json!({ "groups": ["zeus-owners"] }))
    .bind(vec!["zeus-owners"])
    .fetch_one(&http_pool)
    .await
    .expect("linked upstream identity authenticates the Zeus user");
    assert_eq!(authenticated.0, "authenticated");
    assert_eq!(authenticated.1, Some(existing_user_id));

    let existing_session_id = Uuid::now_v7();
    let existing_session_token = format!("integration-user-session-{existing_session_id}");
    let existing_csrf_token = format!("integration-user-csrf-{existing_session_id}");
    sqlx::query(
        "insert into web_sessions (
           id, user_id, active_organization_id, active_workspace_id,
           token_hash, csrf_token_hash,
           auth_methods, authenticated_at, idle_expires_at, absolute_expires_at
         ) values (
           $1, $2, $3, $4, $5, $6, array['password'], now(),
           now() + interval '2 hours', now() + interval '12 hours'
         )",
    )
    .bind(existing_session_id)
    .bind(existing_user_id)
    .bind(organization_id)
    .bind(workspace_id)
    .bind(sha256(existing_session_token.as_bytes()))
    .bind(sha256(existing_csrf_token.as_bytes()))
    .execute(&owner_pool)
    .await
    .expect("existing user session inserts");
    let linkable_provider = sqlx::query_as::<_, (Uuid, Uuid)>(
        "select id, organization_id
         from zeus_private.get_federated_provider_for_link($1, $2, $3)",
    )
    .bind(federated_provider_id)
    .bind(existing_user_id)
    .bind(existing_session_id)
    .fetch_one(&http_pool)
    .await
    .expect("a member session can load its provider without active tenant RLS context");
    assert_eq!(linkable_provider, (federated_provider_id, organization_id));

    let other_organization_id = Uuid::now_v7();
    sqlx::query(
        "insert into organizations (id, slug, name, status)
         values ($1, $2, 'Other Federated Organization', 'provisioning')",
    )
    .bind(other_organization_id)
    .bind(format!("federated-other-{other_organization_id}"))
    .execute(&owner_pool)
    .await
    .expect("other federated organization inserts");
    sqlx::query("insert into organization_governance (organization_id) values ($1)")
        .bind(other_organization_id)
        .execute(&owner_pool)
        .await
        .expect("other organization governance inserts");
    let other_owner_id = Uuid::now_v7();
    sqlx::query(
        "insert into users (id, email, display_name, status, email_verified_at)
         values ($1, $2, 'Other Owner', 'active', now())",
    )
    .bind(other_owner_id)
    .bind(format!("other-owner-{other_owner_id}@example.test"))
    .execute(&owner_pool)
    .await
    .expect("other owner inserts");
    sqlx::query(
        "insert into organization_memberships (organization_id, user_id, role, status)
         values ($1, $2, 'owner', 'active')",
    )
    .bind(other_organization_id)
    .bind(other_owner_id)
    .execute(&owner_pool)
    .await
    .expect("other organization owner membership inserts");
    sqlx::query("update organizations set status = 'active' where id = $1")
        .bind(other_organization_id)
        .execute(&owner_pool)
        .await
        .expect("other organization activates");
    let other_provider_id = Uuid::now_v7();
    sqlx::query(
        "insert into federated_identity_providers (
           id, organization_id, slug, issuer_url, client_id,
           encrypted_client_secret, secret_nonce, key_id
         ) values (
           $1, $2, 'other-provider', 'https://other-issuer.example.test',
           'other-client', $3, $4, 'test-v1'
         )",
    )
    .bind(other_provider_id)
    .bind(other_organization_id)
    .bind(vec![11_u8; 32])
    .bind(vec![12_u8; 12])
    .execute(&owner_pool)
    .await
    .expect("other federated provider inserts");
    let cross_organization_link = sqlx::query_scalar::<_, Uuid>(
        "select zeus_private.create_federated_login_transaction(
           $1, 'link', $2, $3, $4, $5, $6, 'test-v1',
           '/account/federation', $7
         )",
    )
    .bind(other_provider_id)
    .bind(existing_user_id)
    .bind(existing_session_id)
    .bind(vec![13_u8; 32])
    .bind(vec![14_u8; 32])
    .bind(vec![15_u8; 12])
    .bind(time::OffsetDateTime::now_utc() + time::Duration::minutes(10))
    .fetch_one(&http_pool)
    .await
    .expect_err("a session from another organization cannot start a provider link");
    assert_eq!(
        cross_organization_link
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code),
        Some(std::borrow::Cow::Borrowed("42501"))
    );

    let jit_subject = format!("control-subject-{organization_id}");
    let jit_email = format!("builder-{organization_id}@example.test");
    let jit_identity = sqlx::query_as::<_, (String, Option<Uuid>, Uuid, Option<Uuid>)>(
        "select * from zeus_private.resolve_external_identity(
           $1, 'login', null, $2, $3, $4, $5, $6, $7, $8
         )",
    )
    .bind(federated_provider_id)
    .bind("https://issuer.example.test")
    .bind(jit_subject)
    .bind(jit_email)
    .bind("Control Builder")
    .bind(true)
    .bind(json!({ "groups": ["zeus-owners", "zeus-builders"] }))
    .bind(vec!["zeus-owners", "zeus-builders"])
    .fetch_one(&http_pool)
    .await
    .expect("federated identity is JIT provisioned through the HTTP role");
    assert_eq!(jit_identity.0, "jit_created");
    assert_eq!(jit_identity.2, organization_id);
    assert_eq!(jit_identity.3, Some(workspace_id));
    let jit_user_id = jit_identity.1.expect("JIT creates a user");
    let roles = sqlx::query_as::<_, (String, String)>(
        "select om.role, wm.role
         from organization_memberships om
         join workspace_memberships wm on wm.user_id = om.user_id
         where om.user_id = $1 and om.organization_id = $2 and wm.workspace_id = $3",
    )
    .bind(jit_user_id)
    .bind(organization_id)
    .bind(workspace_id)
    .fetch_one(&owner_pool)
    .await
    .expect("JIT memberships read");
    assert_eq!(roles, ("owner".to_owned(), "builder".to_owned()));

    let envelope = LocalEnvelopeCipher::from_encoded("test-v1".to_owned(), &envelope_key)
        .expect("test envelope key is valid");
    let state = AppState {
        platform: Arc::new(PlatformServices {
            database: http_pool,
            envelope: Arc::new(envelope),
            metrics: Arc::new(SupervisorMetrics::default()),
            version: "0.1.0-test",
        }),
        identity: Arc::new(IdentityRuntimeConfig {
            public_url: Url::parse("http://127.0.0.1:8080").expect("public URL parses"),
            session_idle_ttl: Duration::from_hours(2),
            session_absolute_ttl: Duration::from_hours(12),
            oidc_state_ttl: Duration::from_mins(10),
            cookie_secure: false,
            allow_private_oidc_issuers: false,
            bootstrap_token: None,
            identity_hash_key: envelope_key,
            trust_proxy_headers: false,
            password_executor: PasswordExecutor::new(4, 4, PasswordPolicy::default())
                .expect("password executor builds"),
        }),
        external: Arc::new(ExternalClients {
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("HTTP client builds"),
        }),
        execution: Arc::new(ExecutionRuntimeConfig {
            allow_private_model_endpoints: false,
        }),
    };
    let app = http::router(state);

    let me = send(&app, Method::GET, "/api/v1/auth/me", &token, None, &[]).await;
    let (_, me) = expect_json(me, StatusCode::OK).await;
    assert_eq!(me["principal_kind"], "service_account");
    assert_eq!(me["workspace_id"], workspace_id.to_string());

    let user_organizations = send_user(
        &app,
        Method::GET,
        "/api/v1/users/me/organizations",
        &existing_session_token,
        &existing_csrf_token,
        None,
        &[],
    )
    .await;
    let (_, user_organizations) = expect_json(user_organizations, StatusCode::OK).await;
    assert_eq!(
        user_organizations[0]["organization_id"],
        organization_id.to_string()
    );
    assert!(
        user_organizations[0].get("identity_providers").is_none(),
        "tenant selection does not expose identity provider metadata"
    );

    let external_identities = send_user(
        &app,
        Method::GET,
        "/api/v1/users/me/external-identities",
        &existing_session_token,
        &existing_csrf_token,
        None,
        &[],
    )
    .await;
    let (_, external_identities) = expect_json(external_identities, StatusCode::OK).await;
    assert_eq!(
        external_identities["identities"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(
        external_identities["available_providers"][0]["provider_id"],
        federated_provider_id.to_string()
    );

    let created_workspace_account = send_user(
        &app,
        Method::POST,
        &format!("/api/v1/workspaces/{workspace_id}/service-accounts"),
        &existing_session_token,
        &existing_csrf_token,
        Some(json!({
            "name": "Workspace automation",
            "scopes": ["workspace:read", "run:operate"],
            "expires_at": null
        })),
        &[],
    )
    .await;
    let (_, created_workspace_account) =
        expect_json(created_workspace_account, StatusCode::CREATED).await;
    let created_workspace_account_id = json_uuid(&created_workspace_account, "id");
    assert_eq!(
        created_workspace_account["workspace_id"],
        workspace_id.to_string()
    );
    assert!(
        created_workspace_account["token"]
            .as_str()
            .is_some_and(|value| value.starts_with("zsa_"))
    );

    let workspace_accounts = send_user(
        &app,
        Method::GET,
        &format!("/api/v1/workspaces/{workspace_id}/service-accounts"),
        &existing_session_token,
        &existing_csrf_token,
        None,
        &[],
    )
    .await;
    let (_, workspace_accounts) = expect_json(workspace_accounts, StatusCode::OK).await;
    assert!(
        workspace_accounts
            .as_array()
            .is_some_and(|accounts| accounts.iter().any(|account| {
                account["id"] == created_workspace_account_id.to_string()
                    && account.get("token").is_none()
            }))
    );
    assert!(workspace_accounts.as_array().is_some_and(|accounts| {
        accounts
            .iter()
            .all(|account| account["workspace_id"] == workspace_id.to_string())
    }));

    let revoked_workspace_account = send_user(
        &app,
        Method::POST,
        &format!(
            "/api/v1/workspaces/{workspace_id}/service-accounts/{created_workspace_account_id}/revoke"
        ),
        &existing_session_token,
        &existing_csrf_token,
        None,
        &[],
    )
    .await;
    assert_eq!(revoked_workspace_account.status(), StatusCode::NO_CONTENT);

    let providers = send(
        &app,
        Method::GET,
        &format!("/api/v1/organizations/{organization_id}/identity-providers"),
        &organization_token,
        None,
        &[],
    )
    .await;
    let (_, providers) = expect_json(providers, StatusCode::OK).await;
    assert_eq!(providers.as_array().map(Vec::len), Some(1));
    assert_eq!(providers[0]["id"], federated_provider_id.to_string());

    let domain = send_user(
        &app,
        Method::POST,
        &format!("/api/v1/organizations/{organization_id}/domains"),
        &existing_session_token,
        &existing_csrf_token,
        Some(json!({
            "domain": format!("control-{organization_id}.example.test")
        })),
        &[],
    )
    .await;
    let (_, domain) = expect_json(domain, StatusCode::CREATED).await;
    assert_eq!(domain["status"], "pending");
    assert!(
        domain["txt_record_value"]
            .as_str()
            .is_some_and(|value| value.starts_with("zeus-domain-verification="))
    );

    let policy = send_user(
        &app,
        Method::GET,
        &format!("/api/v1/organizations/{organization_id}/identity-policy"),
        &existing_session_token,
        &existing_csrf_token,
        None,
        &[],
    )
    .await;
    let (_, policy) = expect_json(policy, StatusCode::OK).await;
    assert_eq!(policy["revision"], 1);
    let policy = send_user(
        &app,
        Method::PUT,
        &format!("/api/v1/organizations/{organization_id}/identity-policy"),
        &existing_session_token,
        &existing_csrf_token,
        Some(json!({
            "mfa_required": false,
            "federated_required": true,
            "required_federated_provider_id": federated_provider_id
        })),
        &[(header::IF_MATCH.as_str(), "\"revision-1\"")],
    )
    .await;
    let (_, policy) = expect_json(policy, StatusCode::OK).await;
    assert_eq!(policy["revision"], 2);
    assert_eq!(
        policy["required_federated_provider_id"],
        federated_provider_id.to_string()
    );

    sqlx::query(
        "update organization_governance
         set identity_settings_mode = 'platform_managed', revision = revision + 1
         where organization_id = $1",
    )
    .bind(organization_id)
    .execute(&owner_pool)
    .await
    .expect("identity settings switch updates");
    let managed_identity_settings = send(
        &app,
        Method::GET,
        &format!("/api/v1/organizations/{organization_id}/identity-providers"),
        &organization_token,
        None,
        &[],
    )
    .await;
    let (_, managed_identity_settings) =
        expect_json(managed_identity_settings, StatusCode::FORBIDDEN).await;
    assert_eq!(
        managed_identity_settings["code"],
        "organization_identity_settings_managed"
    );

    let last_workspace_owner = sqlx::query(
        "update workspace_memberships
         set role = 'builder'
         where organization_id = $1 and workspace_id = $2 and user_id = $3",
    )
    .bind(organization_id)
    .bind(workspace_id)
    .bind(existing_user_id)
    .execute(&owner_pool)
    .await
    .expect_err("the last active workspace owner cannot be demoted");
    assert_eq!(
        last_workspace_owner
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code),
        Some(std::borrow::Cow::Borrowed("23514"))
    );

    let forbidden = send(
        &app,
        Method::GET,
        &format!("/api/v1/workspaces/{other_workspace_id}/agents"),
        &token,
        None,
        &[],
    )
    .await;
    let _ = expect_json(forbidden, StatusCode::FORBIDDEN).await;

    let connection = send(
        &app,
        Method::POST,
        &format!("/api/v1/organizations/{organization_id}/model-providers"),
        &organization_token,
        Some(json!({
            "name": "OpenAI compatible",
            "provider_kind": "openai_compatible",
            "configuration": { "api_key_secret_name": "api_key" },
            "secrets": { "api_key": "integration-test-only" }
        })),
        &[],
    )
    .await;
    let (_, connection) = expect_json(connection, StatusCode::CREATED).await;
    assert!(connection.get("secrets").is_none());
    let connection_id = json_uuid(&connection, "id");

    let profile = send(
        &app,
        Method::POST,
        &format!("/api/v1/organizations/{organization_id}/model-profiles"),
        &organization_token,
        Some(json!({
            "connection_id": connection_id,
            "name": "Primary model",
            "provider_kind": "openai_compatible",
            "base_url": "https://models.example.test/v1",
            "model": "test-model",
            "configuration": {}
        })),
        &[],
    )
    .await;
    let (_, profile) = expect_json(profile, StatusCode::CREATED).await;
    let model_profile_id = json_uuid(&profile, "id");
    let diagnostic_url =
        format!("/api/v1/organizations/{organization_id}/model-profiles/{model_profile_id}/test");
    let denied = send(
        &app,
        Method::POST,
        &diagnostic_url,
        &token,
        None,
        &[("if-match", "\"revision-1\"")],
    )
    .await;
    let _ = expect_json(denied, StatusCode::FORBIDDEN).await;
    let outdated_response = send(
        &app,
        Method::POST,
        &diagnostic_url,
        &organization_token,
        None,
        &[("if-match", "\"revision-999\"")],
    )
    .await;
    let _ = expect_json(outdated_response, StatusCode::PRECONDITION_FAILED).await;
    // The provider is a loopback-only fixture; no real model or credential is used.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fixture listener");
    let fixture_url = format!(
        "http://{}/v1",
        listener.local_addr().expect("fixture address")
    );
    let fixture = Router::new().route(
        "/v1/models",
        axum::routing::get(|| async { axum::Json(json!({ "data": [{ "id": "test-model" }] })) }),
    );
    let fixture_task = tokio::spawn(async move {
        axum::serve(listener, fixture)
            .await
            .expect("fixture server");
    });
    sqlx::query("update model_profiles set base_url=$1 where id=$2")
        .bind(&fixture_url)
        .bind(model_profile_id)
        .execute(&owner_pool)
        .await
        .expect("test-only endpoint");
    let tested = send(
        &app,
        Method::POST,
        &diagnostic_url,
        &organization_token,
        None,
        &[("if-match", "\"revision-1\"")],
    )
    .await;
    let (_, tested) = expect_json(tested, StatusCode::OK).await;
    assert_eq!(tested["success"], true);
    assert_eq!(tested["code"], "ok");
    assert!(tested.get("assistant_text").is_none());
    assert!(!tested.to_string().contains("integration-test-only"));
    fixture_task.abort();
    sqlx::query("update model_profiles set base_url='https://models.example.test/v1' where id=$1")
        .bind(model_profile_id)
        .execute(&owner_pool)
        .await
        .expect("restore fixture endpoint");

    // Organization ownership is independent of Workspace management scopes.
    for endpoint in [
        format!("/api/v1/organizations/{organization_id}/model-providers"),
        format!("/api/v1/organizations/{organization_id}/model-profiles"),
    ] {
        let denied = send(&app, Method::POST, &endpoint, &token,
            Some(json!({ "name": "Denied", "provider_kind": "openai_compatible", "connection_id": connection_id,
                "base_url": "https://models.example.test/v1", "model": "test" })), &[]).await;
        let _ = expect_json(denied, StatusCode::FORBIDDEN).await;
    }
    let second_profile = send(&app, Method::POST,
        &format!("/api/v1/organizations/{organization_id}/model-profiles"), &organization_token,
        Some(json!({ "connection_id": connection_id, "name": "Second model", "base_url": "https://models.example.test/v1", "model": "second-model" })), &[]).await;
    let (_, second_profile) = expect_json(second_profile, StatusCode::CREATED).await;
    let second_model_id = json_uuid(&second_profile, "id");
    assert_eq!(second_profile["connection_id"], connection_id.to_string());
    assert!(second_profile["workspace_id"].is_null());
    for selected_workspace in [workspace_id, other_workspace_id] {
        sqlx::query("update service_accounts set workspace_id = $1 where id = $2")
            .bind(selected_workspace)
            .bind(service_account_id)
            .execute(&owner_pool)
            .await
            .expect("test account context");
        let directory = send(
            &app,
            Method::GET,
            &format!("/api/v1/workspaces/{selected_workspace}/model-profiles"),
            &token,
            None,
            &[],
        )
        .await;
        let (_, directory) = expect_json(directory, StatusCode::OK).await;
        assert_eq!(directory["items"].as_array().expect("directory").len(), 2);
    }
    sqlx::query("update service_accounts set workspace_id = $1 where id = $2")
        .bind(workspace_id)
        .bind(service_account_id)
        .execute(&owner_pool)
        .await
        .expect("restore test context");
    let other_organization = Uuid::now_v7();
    let cross_tenant = send(
        &app,
        Method::GET,
        &format!("/api/v1/organizations/{other_organization}/model-profiles"),
        &organization_token,
        None,
        &[],
    )
    .await;
    let _ = expect_json(cross_tenant, StatusCode::FORBIDDEN).await;

    let capability = send(
        &app,
        Method::POST,
        &format!("/api/v1/organizations/{organization_id}/capability-definitions"),
        &organization_token,
        Some(json!({
            "registry_key": "test.echo",
            "display_name": "Echo",
            "description": "Returns validated input",
            "input_schema": { "type": "object" },
            "output_schema": { "type": "object" },
            "idempotency_mode": "supported",
            "risk_level": "low",
            "executor_key": "builtin.echo"
        })),
        &[],
    )
    .await;
    let (capability_headers, capability) = expect_json(capability, StatusCode::CREATED).await;
    let capability_id = json_uuid(&capability, "id");
    let revision_one = capability_headers
        .get(header::ETAG)
        .expect("capability create returns ETag")
        .to_str()
        .expect("ETag is ASCII")
        .to_owned();

    let updated = send(
        &app,
        Method::PATCH,
        &format!("/api/v1/organizations/{organization_id}/capability-definitions/{capability_id}"),
        &organization_token,
        Some(json!({ "display_name": "Echo API" })),
        &[(header::IF_MATCH.as_str(), revision_one.as_str())],
    )
    .await;
    let (_, updated) = expect_json(updated, StatusCode::OK).await;
    assert_eq!(updated["revision"], 2);

    let stale_response = send(
        &app,
        Method::PATCH,
        &format!("/api/v1/organizations/{organization_id}/capability-definitions/{capability_id}"),
        &organization_token,
        Some(json!({ "display_name": "Stale write" })),
        &[(header::IF_MATCH.as_str(), revision_one.as_str())],
    )
    .await;
    let _ = expect_json(stale_response, StatusCode::PRECONDITION_FAILED).await;

    let workspace_capability = send(
        &app,
        Method::POST,
        &format!("/api/v1/workspaces/{workspace_id}/capabilities"),
        &token,
        Some(json!({
            "capability_id": capability_id,
            "connection_id": null,
            "enabled": true,
            "approval_required": false,
            "timeout_seconds": 30,
            "policy": {}
        })),
        &[],
    )
    .await;
    let _ = expect_json(workspace_capability, StatusCode::CREATED).await;

    let agent = send(
        &app,
        Method::POST,
        &format!("/api/v1/workspaces/{workspace_id}/agents"),
        &token,
        Some(json!({ "name": "Control Agent", "description": "Test agent" })),
        &[],
    )
    .await;
    let (_, agent) = expect_json(agent, StatusCode::CREATED).await;
    let agent_id = json_uuid(&agent, "id");

    let agent_version = send(
        &app,
        Method::POST,
        &format!("/api/v1/workspaces/{workspace_id}/agents/{agent_id}/versions"),
        &token,
        Some(json!({ "instructions": "Reply briefly.", "configuration": {}, "model_profile_id": model_profile_id })),
        &[],
    )
    .await;
    let (_, agent_version) = expect_json(agent_version, StatusCode::CREATED).await;
    let agent_version_id = json_uuid(&agent_version, "id");

    let workflow = send(
        &app,
        Method::POST,
        &format!("/api/v1/workspaces/{workspace_id}/workflows"),
        &token,
        Some(json!({ "name": "Control Workflow", "description": "Test workflow" })),
        &[],
    )
    .await;
    let (_, workflow) = expect_json(workflow, StatusCode::CREATED).await;
    let workflow_id = json_uuid(&workflow, "id");

    let override_model = send(
        &app,
        Method::POST,
        &format!("/api/v1/workspaces/{workspace_id}/workflows/{workflow_id}/versions"),
        &token,
        Some(json!({ "agent_version_id": agent_version_id, "model_profile_id": second_model_id })),
        &[],
    )
    .await;
    let _ = expect_json(override_model, StatusCode::UNPROCESSABLE_ENTITY).await;
    let workflow_version = send(
        &app,
        Method::POST,
        &format!("/api/v1/workspaces/{workspace_id}/workflows/{workflow_id}/versions"),
        &token,
        Some(json!({
            "agent_version_id": agent_version_id,
            "capability_policy": { "allowed": ["test.echo"] }
        })),
        &[],
    )
    .await;
    let (_, workflow_version) = expect_json(workflow_version, StatusCode::CREATED).await;
    let workflow_version_id = json_uuid(&workflow_version, "id");

    let activated = send(
        &app,
        Method::POST,
        &format!("/api/v1/workspaces/{workspace_id}/workflows/{workflow_id}/active-version"),
        &token,
        Some(json!({ "version_id": workflow_version_id })),
        &[(header::IF_MATCH.as_str(), "\"revision-1\"")],
    )
    .await;
    let _ = expect_json(activated, StatusCode::OK).await;

    let work_item = send(
        &app,
        Method::POST,
        &format!("/api/v1/workspaces/{workspace_id}/work-items"),
        &token,
        Some(json!({
            "title": "Investigate a customer escalation",
            "description": "Exercise the atomic WorkItem launch contract.",
            "priority": "high",
            "input": { "ticket": "TEST-42" }
        })),
        &[("idempotency-key", "control-work-item-1")],
    )
    .await;
    let (_, work_item) = expect_json(work_item, StatusCode::CREATED).await;
    let work_item_id = json_uuid(&work_item, "id");
    let unassigned = send(
        &app,
        Method::GET,
        &format!("/api/v1/workspaces/{workspace_id}/work-items?unassigned=true"),
        &token,
        None,
        &[],
    )
    .await;
    let (_, unassigned) = expect_json(unassigned, StatusCode::OK).await;
    assert!(
        unassigned["items"]
            .as_array()
            .expect("items")
            .iter()
            .any(|item| item["id"] == work_item_id.to_string())
    );
    let not_created = send(
        &app,
        Method::GET,
        &format!(
            "/api/v1/workspaces/{workspace_id}/work-items?created_by={}",
            Uuid::now_v7()
        ),
        &token,
        None,
        &[],
    )
    .await;
    let (_, not_created) = expect_json(not_created, StatusCode::OK).await;
    assert!(not_created["items"].as_array().expect("items").is_empty());

    for (search, should_match) in [
        ("CUSTOMER", true),
        ("not-a-matching-title", false),
        ("%25", false),
    ] {
        let response = send(
            &app,
            Method::GET,
            &format!(
                "/api/v1/workspaces/{workspace_id}/work-items?q={search}&unassigned=true&limit=1"
            ),
            &token,
            None,
            &[],
        )
        .await;
        let (_, result) = expect_json(response, StatusCode::OK).await;
        assert_eq!(
            result["items"]
                .as_array()
                .expect("items")
                .iter()
                .any(|item| item["id"] == work_item_id.to_string()),
            should_match
        );
    }

    let dormant_workflow = send(
        &app,
        Method::POST,
        &format!("/api/v1/workspaces/{workspace_id}/workflows"),
        &token,
        Some(json!({
            "name": "Dormant Workflow",
            "description": "Has no active version"
        })),
        &[],
    )
    .await;
    let (_, dormant_workflow) = expect_json(dormant_workflow, StatusCode::CREATED).await;
    let dormant_workflow_id = json_uuid(&dormant_workflow, "id");
    let sessions_before: i64 = sqlx::query_scalar("select count(*) from sessions")
        .fetch_one(&owner_pool)
        .await
        .expect("session count reads");
    let runs_before: i64 = sqlx::query_scalar("select count(*) from runs")
        .fetch_one(&owner_pool)
        .await
        .expect("run count reads");
    let missing_active_version = send(
        &app,
        Method::POST,
        &format!("/api/v1/workspaces/{workspace_id}/work-items/{work_item_id}/runs"),
        &token,
        Some(json!({
            "workflow_id": dormant_workflow_id,
            "input": {},
            "message": "Start"
        })),
        &[("idempotency-key", "control-work-item-run-dormant")],
    )
    .await;
    let (_, problem) = expect_json(missing_active_version, StatusCode::CONFLICT).await;
    assert_eq!(problem["code"], "conflict");
    let sessions_after: i64 = sqlx::query_scalar("select count(*) from sessions")
        .fetch_one(&owner_pool)
        .await
        .expect("session count reads after rollback");
    let runs_after: i64 = sqlx::query_scalar("select count(*) from runs")
        .fetch_one(&owner_pool)
        .await
        .expect("run count reads after rollback");
    assert_eq!(sessions_after, sessions_before);
    assert_eq!(runs_after, runs_before);

    let cross_workspace_launch = send(
        &app,
        Method::POST,
        &format!("/api/v1/workspaces/{other_workspace_id}/work-items/{work_item_id}/runs"),
        &token,
        Some(json!({
            "workflow_id": workflow_id,
            "input": {},
            "message": "Start"
        })),
        &[("idempotency-key", "control-work-item-run-cross-workspace")],
    )
    .await;
    let _ = expect_json(cross_workspace_launch, StatusCode::FORBIDDEN).await;

    let launch_body = json!({
        "workflow_id": workflow_id,
        "input": { "ticket": "TEST-42" },
        "message": "Investigate the escalation"
    });
    let launched = send(
        &app,
        Method::POST,
        &format!("/api/v1/workspaces/{workspace_id}/work-items/{work_item_id}/runs"),
        &token,
        Some(launch_body.clone()),
        &[("idempotency-key", "control-work-item-run-1")],
    )
    .await;
    let (_, launched) = expect_json(launched, StatusCode::CREATED).await;
    let linked_session_id = json_uuid(&launched["session"], "id");
    let linked_run_id = json_uuid(&launched["run"], "id");
    assert_eq!(
        launched["session"]["work_item_id"],
        work_item_id.to_string()
    );
    assert_eq!(launched["run"]["work_item_id"], work_item_id.to_string());

    let replayed = send(
        &app,
        Method::POST,
        &format!("/api/v1/workspaces/{workspace_id}/work-items/{work_item_id}/runs"),
        &token,
        Some(launch_body),
        &[("idempotency-key", "control-work-item-run-1")],
    )
    .await;
    let (_, replayed) = expect_json(replayed, StatusCode::CREATED).await;
    assert_eq!(json_uuid(&replayed["session"], "id"), linked_session_id);
    assert_eq!(json_uuid(&replayed["run"], "id"), linked_run_id);

    let filtered_runs = send(
        &app,
        Method::GET,
        &format!(
            "/api/v1/workspaces/{workspace_id}/runs?work_item_id={work_item_id}&status=queued"
        ),
        &token,
        None,
        &[],
    )
    .await;
    let (_, filtered_runs) = expect_json(filtered_runs, StatusCode::OK).await;
    assert_eq!(filtered_runs["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(filtered_runs["items"][0]["id"], linked_run_id.to_string());

    let tool_call_id: Uuid = sqlx::query_scalar(
        "insert into tool_calls (
           organization_id, workspace_id, run_id, session_id, capability_id,
           call_key, fence_token, status, input
         ) values ($1, $2, $3, $4, $5, 'approval-test', 0, 'pending_approval', '{}')
         returning id",
    )
    .bind(organization_id)
    .bind(workspace_id)
    .bind(linked_run_id)
    .bind(linked_session_id)
    .bind(capability_id)
    .fetch_one(&owner_pool)
    .await
    .expect("pending tool call inserts");
    sqlx::query(
        "insert into approvals (
           organization_id, workspace_id, run_id, tool_call_id
         ) values ($1, $2, $3, $4)",
    )
    .bind(organization_id)
    .bind(workspace_id)
    .bind(linked_run_id)
    .bind(tool_call_id)
    .execute(&owner_pool)
    .await
    .expect("approval inserts");

    let filtered_approvals = send(
        &app,
        Method::GET,
        &format!(
            "/api/v1/workspaces/{workspace_id}/approvals?work_item_id={work_item_id}&status=pending"
        ),
        &token,
        None,
        &[],
    )
    .await;
    let (_, filtered_approvals) = expect_json(filtered_approvals, StatusCode::OK).await;
    assert_eq!(filtered_approvals.as_array().map(Vec::len), Some(1));
    assert_eq!(filtered_approvals[0]["run_id"], linked_run_id.to_string());

    let unrelated_work_item_id = Uuid::now_v7();
    let unrelated_approvals = send(
        &app,
        Method::GET,
        &format!(
            "/api/v1/workspaces/{workspace_id}/approvals?work_item_id={unrelated_work_item_id}&status=pending"
        ),
        &token,
        None,
        &[],
    )
    .await;
    let (_, unrelated_approvals) = expect_json(unrelated_approvals, StatusCode::OK).await;
    assert_eq!(unrelated_approvals, json!([]));

    // Human result acceptance is tenant-scoped, append-only, and revision protected.
    let review_url = format!("/api/v1/workspaces/{workspace_id}/work-items/{work_item_id}/reviews");
    let review_body =
        json!({"run_id": linked_run_id, "decision": "accepted", "reason": "Synthetic review"});
    let service_review = send(
        &app,
        Method::POST,
        &review_url,
        &token,
        Some(review_body.clone()),
        &[("if-match", "\"revision-1\"")],
    )
    .await;
    assert_eq!(service_review.status(), StatusCode::FORBIDDEN);
    let running_review = send_user(
        &app,
        Method::POST,
        &review_url,
        &existing_session_token,
        &existing_csrf_token,
        Some(review_body),
        &[("if-match", "\"revision-1\"")],
    )
    .await;
    assert_eq!(running_review.status(), StatusCode::CONFLICT);
    let review_run = Uuid::now_v7();
    sqlx::query("insert into runs (id, organization_id, workspace_id, workflow_version_id, work_item_id, session_id, status, output, idempotency_key, finished_at)
      select $1, organization_id, workspace_id, workflow_version_id, work_item_id, session_id, 'succeeded', '{\"content\":\"Synthetic result\"}'::jsonb, $2, now() from runs where id = $3")
      .bind(review_run).bind(format!("review-{review_run}")).bind(linked_run_id).execute(&owner_pool).await.expect("completed review fixture");
    let body = json!({"run_id": review_run, "decision": "accepted", "reason": "Facts checked"});
    let accepted = send_user(
        &app,
        Method::POST,
        &review_url,
        &existing_session_token,
        &existing_csrf_token,
        Some(body.clone()),
        &[("if-match", "\"revision-1\"")],
    )
    .await;
    let (_, accepted) = expect_json(accepted, StatusCode::CREATED).await;
    assert_eq!(accepted["run_id"], review_run.to_string());
    assert_eq!(accepted["work_item_revision"], 1);
    let duplicate = send_user(
        &app,
        Method::POST,
        &review_url,
        &existing_session_token,
        &existing_csrf_token,
        Some(body.clone()),
        &[("if-match", "\"revision-1\"")],
    )
    .await;
    assert_eq!(duplicate.status(), StatusCode::PRECONDITION_FAILED);
    let invalid = send_user(
        &app,
        Method::POST,
        &review_url,
        &existing_session_token,
        &existing_csrf_token,
        Some(json!({"run_id":review_run,"decision":"accepted","reason":" "})),
        &[("if-match", "\"revision-2\"")],
    )
    .await;
    assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let other_item_review = send_user(
        &app,
        Method::POST,
        &format!("/api/v1/workspaces/{workspace_id}/work-items/{unrelated_work_item_id}/reviews"),
        &existing_session_token,
        &existing_csrf_token,
        Some(body.clone()),
        &[("if-match", "\"revision-1\"")],
    )
    .await;
    assert_eq!(other_item_review.status(), StatusCode::NOT_FOUND);
    let cross_workspace = send_user(
        &app,
        Method::POST,
        &format!("/api/v1/workspaces/{other_workspace_id}/work-items/{work_item_id}/reviews"),
        &existing_session_token,
        &existing_csrf_token,
        Some(body),
        &[("if-match", "\"revision-2\"")],
    )
    .await;
    assert_ne!(cross_workspace.status(), StatusCode::CREATED);
    let listed = send(&app, Method::GET, &review_url, &token, None, &[]).await;
    let (_, listed) = expect_json(listed, StatusCode::OK).await;
    assert_eq!(listed["items"].as_array().map(Vec::len), Some(1));
    assert!(
        sqlx::query("update work_item_reviews set reason = 'changed' where id = $1")
            .bind(json_uuid(&accepted, "id"))
            .execute(&owner_pool)
            .await
            .is_err()
    );
    let item_after = send(
        &app,
        Method::GET,
        &format!("/api/v1/workspaces/{workspace_id}/work-items/{work_item_id}"),
        &token,
        None,
        &[],
    )
    .await;
    let (_, item_after) = expect_json(item_after, StatusCode::OK).await;
    assert_eq!(item_after["status"], work_item["status"]);

    // Reprocessing resolves immutable review data server-side and creates a separate Run.
    let accepted_url = format!("{review_url}/{}/runs", json_uuid(&accepted, "id"));
    let rejected = send_user(
        &app,
        Method::POST,
        &accepted_url,
        &existing_session_token,
        &existing_csrf_token,
        None,
        &[
            ("if-match", "\"revision-2\""),
            ("idempotency-key", "accepted-reprocess"),
        ],
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::CONFLICT);
    let changes = send_user(&app, Method::POST, &review_url, &existing_session_token,
        &existing_csrf_token, Some(json!({"run_id": review_run, "decision": "needs_changes", "reason": "Add missing acceptance criteria"})),
        &[("if-match", "\"revision-2\"")]).await;
    let (_, changes) = expect_json(changes, StatusCode::CREATED).await;
    let reprocess_url = format!("{review_url}/{}/runs", json_uuid(&changes, "id"));
    let outdated_reprocess = send_user(
        &app,
        Method::POST,
        &reprocess_url,
        &existing_session_token,
        &existing_csrf_token,
        None,
        &[
            ("if-match", "\"revision-2\""),
            ("idempotency-key", "stale-reprocess"),
        ],
    )
    .await;
    assert_eq!(outdated_reprocess.status(), StatusCode::PRECONDITION_FAILED);
    let service = send(
        &app,
        Method::POST,
        &reprocess_url,
        &token,
        None,
        &[
            ("if-match", "\"revision-3\""),
            ("idempotency-key", "service-reprocess"),
        ],
    )
    .await;
    assert_eq!(service.status(), StatusCode::FORBIDDEN);
    let wrong_item_url = format!(
        "/api/v1/workspaces/{workspace_id}/work-items/{work_item_id}/reviews/{}/runs",
        Uuid::now_v7()
    );
    let missing = send_user(
        &app,
        Method::POST,
        &wrong_item_url,
        &existing_session_token,
        &existing_csrf_token,
        None,
        &[
            ("if-match", "\"revision-3\""),
            ("idempotency-key", "missing-reprocess"),
        ],
    )
    .await;
    assert_eq!(missing.status(), StatusCode::CONFLICT);
    let other_item_id = Uuid::now_v7();
    sqlx::query("insert into work_items (id, organization_id, workspace_id, title) values ($1, $2, $3, 'Other synthetic item')")
        .bind(other_item_id).bind(organization_id).bind(workspace_id).execute(&owner_pool).await.expect("other work item");
    let other_item_url = format!(
        "/api/v1/workspaces/{workspace_id}/work-items/{other_item_id}/reviews/{}/runs",
        json_uuid(&changes, "id")
    );
    let other_item_attempt = send_user(
        &app,
        Method::POST,
        &other_item_url,
        &existing_session_token,
        &existing_csrf_token,
        None,
        &[
            ("if-match", "\"revision-1\""),
            ("idempotency-key", "other-item-reprocess"),
        ],
    )
    .await;
    assert_eq!(other_item_attempt.status(), StatusCode::CONFLICT);
    let other_workspace_url = format!(
        "/api/v1/workspaces/{other_workspace_id}/work-items/{work_item_id}/reviews/{}/runs",
        json_uuid(&changes, "id")
    );
    let other_workspace_attempt = send_user(
        &app,
        Method::POST,
        &other_workspace_url,
        &existing_session_token,
        &existing_csrf_token,
        None,
        &[
            ("if-match", "\"revision-3\""),
            ("idempotency-key", "other-workspace-reprocess"),
        ],
    )
    .await;
    assert_ne!(other_workspace_attempt.status(), StatusCode::CREATED);
    let new_run = send_user(
        &app,
        Method::POST,
        &reprocess_url,
        &existing_session_token,
        &existing_csrf_token,
        None,
        &[
            ("if-match", "\"revision-3\""),
            ("idempotency-key", "review-reprocess"),
        ],
    )
    .await;
    let (_, new_run) = expect_json(new_run, StatusCode::CREATED).await;
    assert_ne!(new_run["run"]["id"], review_run.to_string());
    assert_eq!(
        new_run["run"]["input"]["work_item"]["input"],
        work_item["input"]
    );
    assert_eq!(
        new_run["run"]["input"]["work_item"]["title"],
        work_item["title"]
    );
    assert_ne!(new_run["session"]["id"], linked_session_id.to_string());
    assert_eq!(
        new_run["run"]["workflow_version_id"],
        changes["workflow_version_id"]
    );
    assert_eq!(
        new_run["run"]["input"]["reprocessing"]["review_id"],
        changes["id"]
    );
    assert_eq!(
        new_run["run"]["input"]["reprocessing"]["source_run_id"],
        review_run.to_string()
    );
    assert_eq!(
        new_run["run"]["input"]["reprocessing"]["work_item_revision"],
        3
    );
    assert_eq!(
        new_run["run"]["input"]["original_output"]["content"],
        "Synthetic result"
    );
    let replay = send_user(
        &app,
        Method::POST,
        &reprocess_url,
        &existing_session_token,
        &existing_csrf_token,
        None,
        &[
            ("if-match", "\"revision-3\""),
            ("idempotency-key", "review-reprocess"),
        ],
    )
    .await;
    let (_, replay) = expect_json(replay, StatusCode::CREATED).await;
    assert_eq!(new_run["run"]["id"], replay["run"]["id"]);
    let message: String = sqlx::query_scalar("select payload ->> 'content' from session_events where run_id = $1 and event_type = 'user_message'")
        .bind(json_uuid(&new_run["run"], "id")).fetch_one(&owner_pool).await.expect("reprocessing message saved");
    assert!(message.contains("Add missing acceptance criteria"));
    assert!(message.contains("Synthetic result"));

    let schedule = send(
        &app,
        Method::POST,
        &format!("/api/v1/workspaces/{workspace_id}/schedules"),
        &token,
        Some(json!({
            "workflow_id": workflow_id,
            "name": "Hourly",
            "cron_expression": "0 * * * *",
            "timezone": "UTC",
            "input": {},
            "enabled": true,
            "next_run_at": null
        })),
        &[],
    )
    .await;
    let _ = expect_json(schedule, StatusCode::CREATED).await;

    let webhook = send(
        &app,
        Method::POST,
        &format!("/api/v1/workspaces/{workspace_id}/webhook-endpoints"),
        &token,
        Some(json!({ "workflow_id": workflow_id, "enabled": true })),
        &[("idempotency-key", "control-webhook-1")],
    )
    .await;
    let (_, webhook) = expect_json(webhook, StatusCode::CREATED).await;
    assert!(
        webhook["secret"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );

    let session = send(
        &app,
        Method::POST,
        &format!("/api/v1/workspaces/{workspace_id}/sessions"),
        &token,
        Some(json!({ "work_item_id": null, "title": "Control session" })),
        &[],
    )
    .await;
    let (_, session) = expect_json(session, StatusCode::CREATED).await;
    let session_id = json_uuid(&session, "id");

    let run = send(
        &app,
        Method::POST,
        &format!("/api/v1/workspaces/{workspace_id}/runs"),
        &token,
        Some(json!({
            "workflow_version_id": workflow_version_id,
            "session_id": session_id,
            "work_item_id": null,
            "input": { "message": "hello" },
            "message": "hello"
        })),
        &[("idempotency-key", "control-run-1")],
    )
    .await;
    let (_, run) = expect_json(run, StatusCode::CREATED).await;
    let run_id = json_uuid(&run, "id");

    let usage = send(
        &app,
        Method::GET,
        &format!("/api/v1/workspaces/{workspace_id}/runs/{run_id}/usage"),
        &token,
        None,
        &[],
    )
    .await;
    let (_, usage) = expect_json(usage, StatusCode::OK).await;
    assert_eq!(usage["prompt_tokens"], 0);
    assert_eq!(usage["entries"], json!([]));

    let canceled = send(
        &app,
        Method::POST,
        &format!("/api/v1/workspaces/{workspace_id}/runs/{run_id}/cancel"),
        &token,
        Some(json!({ "reason": "integration test cleanup" })),
        &[],
    )
    .await;
    assert_eq!(canceled.status(), StatusCode::ACCEPTED);

    let linked_canceled = send(
        &app,
        Method::POST,
        &format!("/api/v1/workspaces/{workspace_id}/runs/{linked_run_id}/cancel"),
        &token,
        Some(json!({ "reason": "integration test cleanup" })),
        &[],
    )
    .await;
    assert_eq!(linked_canceled.status(), StatusCode::ACCEPTED);

    sqlx::query("update organizations set status = 'suspended' where id = $1")
        .bind(organization_id)
        .execute(&owner_pool)
        .await
        .expect("Organization suspends for tenant write guards");
    let suspended_schedule = send(
        &app,
        Method::POST,
        &format!("/api/v1/workspaces/{workspace_id}/schedules"),
        &token,
        Some(json!({
            "workflow_id": workflow_id,
            "name": "Blocked while suspended",
            "cron_expression": "0 * * * *",
            "timezone": "UTC",
            "input": {},
            "enabled": true,
            "next_run_at": null
        })),
        &[],
    )
    .await;
    let (_, suspended_schedule) = expect_json(suspended_schedule, StatusCode::LOCKED).await;
    assert_eq!(suspended_schedule["code"], "organization_suspended");
    let suspended_webhook = send(
        &app,
        Method::POST,
        &format!("/api/v1/workspaces/{workspace_id}/webhook-endpoints"),
        &token,
        Some(json!({ "workflow_id": workflow_id, "enabled": true })),
        &[("idempotency-key", "control-webhook-suspended")],
    )
    .await;
    let (_, suspended_webhook) = expect_json(suspended_webhook, StatusCode::LOCKED).await;
    assert_eq!(suspended_webhook["code"], "organization_suspended");
}

async fn send(
    app: &Router,
    method: Method,
    uri: &str,
    token: &str,
    body: Option<Value>,
    headers: &[(&str, &str)],
) -> Response<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let body = match body {
        Some(body) => {
            request = request.header(header::CONTENT_TYPE, "application/json");
            Body::from(body.to_string())
        }
        None => Body::empty(),
    };
    app.clone()
        .oneshot(request.body(body).expect("request builds"))
        .await
        .expect("router responds")
}

async fn send_user(
    app: &Router,
    method: Method,
    uri: &str,
    session_token: &str,
    csrf_token: &str,
    body: Option<Value>,
    headers: &[(&str, &str)],
) -> Response<Body> {
    let is_write = !matches!(method, Method::GET | Method::HEAD | Method::OPTIONS);
    let mut request = Request::builder().method(method).uri(uri).header(
        header::COOKIE,
        format!("zeus_session={session_token}; zeus_csrf={csrf_token}"),
    );
    if is_write {
        request = request
            .header(header::ORIGIN, "http://127.0.0.1:8080")
            .header("x-zeus-csrf", csrf_token);
    }
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let body = match body {
        Some(body) => {
            request = request.header(header::CONTENT_TYPE, "application/json");
            Body::from(body.to_string())
        }
        None => Body::empty(),
    };
    app.clone()
        .oneshot(request.body(body).expect("request builds"))
        .await
        .expect("router responds")
}

async fn expect_json(
    response: Response<Body>,
    expected: StatusCode,
) -> (axum::http::HeaderMap, Value) {
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("response body reads")
        .to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
        panic!(
            "response body is not JSON: {}",
            String::from_utf8_lossy(&bytes)
        )
    });
    assert_eq!(status, expected, "unexpected response: {body}");
    (headers, body)
}

fn json_uuid(value: &Value, field: &str) -> Uuid {
    value[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} is missing"))
        .parse()
        .unwrap_or_else(|_| panic!("{field} is not a UUID"))
}
