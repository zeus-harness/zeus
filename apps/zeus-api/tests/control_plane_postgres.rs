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
    sqlx::query("insert into organizations (id, slug, name) values ($1, $2, 'Control Test')")
        .bind(organization_id)
        .bind(format!("control-{organization_id}"))
        .execute(&owner_pool)
        .await
        .expect("organization inserts");
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
         ) values ($1, $2, 'zeus-admins', 'admin')",
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
    sqlx::query(
        "insert into users (id, email, display_name, status, email_verified_at)
         values ($1, 'existing@example.test', 'Existing User', 'active', now())",
    )
    .bind(existing_user_id)
    .execute(&owner_pool)
    .await
    .expect("existing Zeus user inserts");
    sqlx::query(
        "insert into organization_memberships (organization_id, user_id, role, status)
         values ($1, $2, 'admin', 'active')",
    )
    .bind(organization_id)
    .bind(existing_user_id)
    .execute(&owner_pool)
    .await
    .expect("existing Zeus user joins organization");
    let account_link_required = sqlx::query_as::<_, (String, Option<Uuid>, Uuid, Option<Uuid>)>(
        "select * from zeus_private.resolve_federated_identity(
           $1, 'login', null, $2, $3, $4, $5, true, $6, $7
         )",
    )
    .bind(federated_provider_id)
    .bind("https://issuer.example.test")
    .bind("existing-subject")
    .bind("existing@example.test")
    .bind("Existing User")
    .bind(json!({ "groups": ["zeus-admins"] }))
    .bind(vec!["zeus-admins"])
    .fetch_one(&http_pool)
    .await
    .expect("same-email federated login is resolved safely");
    assert_eq!(account_link_required.0, "account_link_required");
    assert_eq!(account_link_required.1, None);
    let identity_count: i64 = sqlx::query_scalar(
        "select count(*) from federated_identities
         where issuer = 'https://issuer.example.test' and subject = 'existing-subject'",
    )
    .fetch_one(&owner_pool)
    .await
    .expect("federated identity count reads");
    assert_eq!(
        identity_count, 0,
        "same email must not auto-link an account"
    );

    let linked = sqlx::query_as::<_, (String, Option<Uuid>, Uuid, Option<Uuid>)>(
        "select * from zeus_private.resolve_federated_identity(
           $1, 'link', $2, $3, $4, $5, $6, true, $7, $8
         )",
    )
    .bind(federated_provider_id)
    .bind(existing_user_id)
    .bind("https://issuer.example.test")
    .bind("existing-subject")
    .bind("existing@example.test")
    .bind("Existing User")
    .bind(json!({ "groups": ["zeus-admins"] }))
    .bind(vec!["zeus-admins"])
    .fetch_one(&http_pool)
    .await
    .expect("explicit link binds the upstream identity");
    assert_eq!(linked.0, "linked");
    assert_eq!(linked.1, Some(existing_user_id));

    let authenticated = sqlx::query_as::<_, (String, Option<Uuid>, Uuid, Option<Uuid>)>(
        "select * from zeus_private.resolve_federated_identity(
           $1, 'login', null, $2, $3, $4, $5, true, $6, $7
         )",
    )
    .bind(federated_provider_id)
    .bind("https://issuer.example.test")
    .bind("existing-subject")
    .bind("existing@example.test")
    .bind("Existing User")
    .bind(json!({ "groups": ["zeus-admins"] }))
    .bind(vec!["zeus-admins"])
    .fetch_one(&http_pool)
    .await
    .expect("linked upstream identity authenticates the Zeus user");
    assert_eq!(authenticated.0, "authenticated");
    assert_eq!(authenticated.1, Some(existing_user_id));

    let existing_session_id = Uuid::now_v7();
    let existing_session_token = "integration-user-session-token";
    let existing_csrf_token = "integration-user-csrf-token";
    sqlx::query(
        "insert into web_sessions (
           id, user_id, active_organization_id, token_hash, csrf_token_hash,
           auth_methods, authenticated_at, idle_expires_at, absolute_expires_at
         ) values (
           $1, $2, $3, $4, $5, array['password'], now(),
           now() + interval '2 hours', now() + interval '12 hours'
         )",
    )
    .bind(existing_session_id)
    .bind(existing_user_id)
    .bind(organization_id)
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
        "insert into organizations (id, slug, name)
         values ($1, $2, 'Other Federated Organization')",
    )
    .bind(other_organization_id)
    .bind(format!("federated-other-{other_organization_id}"))
    .execute(&owner_pool)
    .await
    .expect("other federated organization inserts");
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

    let jit_identity = sqlx::query_as::<_, (String, Option<Uuid>, Uuid, Option<Uuid>)>(
        "select * from zeus_private.resolve_federated_identity(
           $1, 'login', null, $2, $3, $4, $5, $6, $7, $8
         )",
    )
    .bind(federated_provider_id)
    .bind("https://issuer.example.test")
    .bind("control-subject")
    .bind("builder@example.test")
    .bind("Control Builder")
    .bind(true)
    .bind(json!({ "groups": ["zeus-admins", "zeus-builders"] }))
    .bind(vec!["zeus-admins", "zeus-builders"])
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
    assert_eq!(roles, ("admin".to_owned(), "builder".to_owned()));

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
        existing_session_token,
        existing_csrf_token,
        None,
        &[],
    )
    .await;
    let (_, user_organizations) = expect_json(user_organizations, StatusCode::OK).await;
    assert_eq!(
        user_organizations[0]["organization_id"],
        organization_id.to_string()
    );
    assert_eq!(
        user_organizations[0]["identity_providers"][0]["id"],
        federated_provider_id.to_string()
    );

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
        existing_session_token,
        existing_csrf_token,
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
        existing_session_token,
        existing_csrf_token,
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
        existing_session_token,
        existing_csrf_token,
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
        &format!("/api/v1/workspaces/{workspace_id}/connections"),
        &token,
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
        &format!("/api/v1/workspaces/{workspace_id}/model-profiles"),
        &token,
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
        Some(json!({ "instructions": "Reply briefly.", "configuration": {} })),
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

    let workflow_version = send(
        &app,
        Method::POST,
        &format!("/api/v1/workspaces/{workspace_id}/workflows/{workflow_id}/versions"),
        &token,
        Some(json!({
            "agent_version_id": agent_version_id,
            "model_profile_id": model_profile_id,
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
