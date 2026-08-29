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
    AppState, HTTP_DATABASE_ROLE, connect_pool, connect_pool_as_role,
    crypto::{LocalEnvelopeCipher, hash_service_account_token},
    http, migrate,
    supervisor::SupervisorMetrics,
};

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

    let oidc_provider_id = Uuid::now_v7();
    sqlx::query(
        "insert into oidc_providers (
            id, organization_id, issuer_url, client_id,
            encrypted_client_secret, secret_nonce, key_id
         ) values ($1, $2, 'https://issuer.example.test', 'control-client', $3, $4, 'test-v1')",
    )
    .bind(oidc_provider_id)
    .bind(organization_id)
    .bind(vec![0_u8; 32])
    .bind(vec![0_u8; 12])
    .execute(&owner_pool)
    .await
    .expect("OIDC provider inserts");
    sqlx::query(
        "insert into oidc_group_mappings (
            organization_id, provider_id, group_value, organization_role
         ) values ($1, $2, 'zeus-admins', 'admin')",
    )
    .bind(organization_id)
    .bind(oidc_provider_id)
    .execute(&owner_pool)
    .await
    .expect("organization group mapping inserts");
    sqlx::query(
        "insert into oidc_group_mappings (
            organization_id, provider_id, group_value, workspace_id, workspace_role
         ) values ($1, $2, 'zeus-builders', $3, 'builder')",
    )
    .bind(organization_id)
    .bind(oidc_provider_id)
    .bind(workspace_id)
    .execute(&owner_pool)
    .await
    .expect("workspace group mapping inserts");

    let service_account_id = Uuid::now_v7();
    let token_prefix = "zsa_control01";
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
    .bind(token_prefix)
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

    let http_pool = connect_pool_as_role(&database_url, 5, HTTP_DATABASE_ROLE)
        .await
        .expect("HTTP role database connects");
    let current_role: String = sqlx::query_scalar("select current_user")
        .fetch_one(&http_pool)
        .await
        .expect("HTTP role can query its identity");
    assert_eq!(current_role, HTTP_DATABASE_ROLE);
    let jit_identity = sqlx::query_as::<_, (Uuid, Uuid, Option<Uuid>)>(
        "select * from zeus_private.jit_oidc_identity($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(oidc_provider_id)
    .bind("https://issuer.example.test")
    .bind("control-subject")
    .bind("builder@example.test")
    .bind("Control Builder")
    .bind(true)
    .bind(json!({ "groups": ["zeus-admins", "zeus-builders"] }))
    .fetch_one(&http_pool)
    .await
    .expect("OIDC identity is JIT provisioned through the HTTP role");
    assert_eq!(jit_identity.1, organization_id);
    assert_eq!(jit_identity.2, Some(workspace_id));
    let roles = sqlx::query_as::<_, (String, String)>(
        "select om.role, wm.role
         from organization_memberships om
         join workspace_memberships wm on wm.user_id = om.user_id
         where om.user_id = $1 and om.organization_id = $2 and wm.workspace_id = $3",
    )
    .bind(jit_identity.0)
    .bind(organization_id)
    .bind(workspace_id)
    .fetch_one(&owner_pool)
    .await
    .expect("JIT memberships read");
    assert_eq!(roles, ("admin".to_owned(), "builder".to_owned()));

    let envelope = LocalEnvelopeCipher::from_encoded("test-v1".to_owned(), &envelope_key)
        .expect("test envelope key is valid");
    let state = AppState {
        database: http_pool,
        envelope: Arc::new(envelope),
        http_client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("HTTP client builds"),
        metrics: Arc::new(SupervisorMetrics::default()),
        public_url: Url::parse("http://127.0.0.1:8080").expect("public URL parses"),
        session_ttl: Duration::from_hours(12),
        oidc_state_ttl: Duration::from_mins(10),
        cookie_secure: false,
        allow_private_oidc_issuers: false,
        allow_private_model_endpoints: false,
        version: "0.1.0-test",
    };
    let app = http::router(state);

    let me = send(&app, Method::GET, "/api/v1/auth/me", &token, None, &[]).await;
    let (_, me) = expect_json(me, StatusCode::OK).await;
    assert_eq!(me["principal_kind"], "service_account");
    assert_eq!(me["workspace_id"], workspace_id.to_string());

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
        &token,
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
        &token,
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
        &token,
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
