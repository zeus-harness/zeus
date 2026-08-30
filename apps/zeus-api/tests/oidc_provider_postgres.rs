use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    http::{Method, Request, Response, StatusCode, header},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use secrecy::SecretString;
use serde_json::{Value, json};
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;
use zeus_api::{
    AppState, HTTP_DATABASE_ROLE, connect_pool, connect_pool_as_role,
    crypto::{LocalEnvelopeCipher, hash_service_account_token, sha256},
    http, migrate,
    supervisor::SupervisorMetrics,
};
use zeus_identity::{PasswordExecutor, PasswordPolicy, pkce_s256_challenge};

const SESSION_TOKEN: &str = "oidc-provider-integration-session-token";
const CSRF_TOKEN: &str = "oidc-provider-integration-csrf-token";
const PUBLIC_URL: &str = "http://127.0.0.1:3000";
const PUBLIC_REDIRECT: &str = "http://127.0.0.1:43121/callback";
const CONFIDENTIAL_REDIRECT: &str = "http://127.0.0.1:43122/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

#[tokio::test]
#[ignore = "requires ZEUS_TEST_DATABASE_URL and ZEUS_TEST_ENVELOPE_KEY"]
#[allow(clippy::too_many_lines)] // One protocol flow proves single-use and rotation semantics.
async fn oidc_provider_supports_public_confidential_and_refresh_replay_protection() {
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
    let user_id = Uuid::now_v7();
    let session_id = Uuid::now_v7();
    sqlx::query("insert into organizations (id, slug, name) values ($1, $2, 'OIDC Test')")
        .bind(organization_id)
        .bind(format!("oidc-{organization_id}"))
        .execute(&owner_pool)
        .await
        .expect("organization inserts");
    sqlx::query("insert into organization_identity_policies (organization_id) values ($1)")
        .bind(organization_id)
        .execute(&owner_pool)
        .await
        .expect("identity policy inserts");
    sqlx::query(
        "insert into workspaces (id, organization_id, slug, name)
         values ($1, $2, $3, 'OIDC Workspace')",
    )
    .bind(workspace_id)
    .bind(organization_id)
    .bind(format!("oidc-{workspace_id}"))
    .execute(&owner_pool)
    .await
    .expect("workspace inserts");
    sqlx::query(
        "insert into users (id, email, display_name, status, email_verified_at)
         values ($1, 'oidc-user@example.test', 'OIDC User', 'active', now())",
    )
    .bind(user_id)
    .execute(&owner_pool)
    .await
    .expect("user inserts");
    sqlx::query(
        "insert into organization_memberships (organization_id, user_id, role, status)
         values ($1, $2, 'owner', 'active')",
    )
    .bind(organization_id)
    .bind(user_id)
    .execute(&owner_pool)
    .await
    .expect("organization membership inserts");
    sqlx::query(
        "insert into workspace_memberships (organization_id, workspace_id, user_id, role, status)
         values ($1, $2, $3, 'admin', 'active')",
    )
    .bind(organization_id)
    .bind(workspace_id)
    .bind(user_id)
    .execute(&owner_pool)
    .await
    .expect("workspace membership inserts");
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
    .bind(organization_id)
    .bind(workspace_id)
    .bind(sha256(SESSION_TOKEN.as_bytes()))
    .bind(sha256(CSRF_TOKEN.as_bytes()))
    .execute(&owner_pool)
    .await
    .expect("web session inserts");

    let public_client_id = format!("zoc_{}", "P".repeat(32));
    let public_internal_id = insert_client(
        &owner_pool,
        organization_id,
        user_id,
        &public_client_id,
        "public",
        None,
        false,
        PUBLIC_REDIRECT,
    )
    .await;
    let confidential_client_id = format!("zoc_{}", "C".repeat(32));
    let confidential_secret = "zocs_confidential-test-secret-with-enough-entropy";
    let confidential_hash = hash_service_account_token(&SecretString::from(confidential_secret))
        .expect("client secret hashes");
    insert_client(
        &owner_pool,
        organization_id,
        user_id,
        &confidential_client_id,
        "confidential",
        Some(confidential_hash),
        true,
        CONFIDENTIAL_REDIRECT,
    )
    .await;

    let http_pool = connect_pool_as_role(&database_url, 8, HTTP_DATABASE_ROLE)
        .await
        .expect("HTTP role database connects");
    let state = AppState {
        database: http_pool,
        envelope: Arc::new(
            LocalEnvelopeCipher::from_encoded("test-v1".to_owned(), &envelope_key)
                .expect("test envelope key is valid"),
        ),
        http_client: reqwest::Client::new(),
        metrics: Arc::new(SupervisorMetrics::default()),
        public_url: Url::parse(PUBLIC_URL).expect("public URL parses"),
        session_idle_ttl: Duration::from_hours(2),
        session_absolute_ttl: Duration::from_hours(12),
        oidc_state_ttl: Duration::from_mins(10),
        cookie_secure: false,
        allow_private_oidc_issuers: false,
        allow_private_model_endpoints: false,
        bootstrap_token: None,
        identity_hash_key: envelope_key,
        trust_proxy_headers: false,
        password_executor: PasswordExecutor::new(4, 4, PasswordPolicy::default())
            .expect("password executor builds"),
        version: "0.1.0-test",
    };
    let app = http::router(state);
    let challenge = pkce_s256_challenge(VERIFIER).expect("PKCE challenge computes");

    let consent_location = authorize(
        &app,
        &public_client_id,
        PUBLIC_REDIRECT,
        &challenge,
        "public-state",
    )
    .await;
    assert!(consent_location.starts_with("/oauth/consent?request="));
    let consent_url =
        Url::parse(&format!("{PUBLIC_URL}{consent_location}")).expect("consent URL parses");
    let request_id: Uuid = consent_url
        .query_pairs()
        .find(|(key, _)| key == "request")
        .expect("consent request is present")
        .1
        .parse()
        .expect("consent request is a UUID");
    let consent = send_json(
        &app,
        Method::GET,
        &format!("/api/v1/users/me/oidc-authorization-requests/{request_id}"),
        None,
    )
    .await;
    let consent = expect_json(consent, StatusCode::OK).await;
    assert_eq!(consent["client_public_id"], public_client_id);
    let decision = send_json(
        &app,
        Method::POST,
        &format!("/api/v1/users/me/oidc-authorization-requests/{request_id}"),
        Some(json!({"approved": true})),
    )
    .await;
    let decision = expect_json(decision, StatusCode::OK).await;
    let public_code = query_value(
        decision["redirect_url"]
            .as_str()
            .expect("redirect URL is returned"),
        "code",
    );

    let public_tokens =
        exchange_code(&app, &public_client_id, None, PUBLIC_REDIRECT, &public_code).await;
    let access_token = public_tokens["access_token"]
        .as_str()
        .expect("access token is returned");
    let first_refresh = public_tokens["refresh_token"]
        .as_str()
        .expect("refresh token is returned");
    assert_eq!(public_tokens["token_type"], "Bearer");
    assert_eq!(public_tokens["expires_in"], 300);
    assert!(
        public_tokens["id_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );

    let replayed_code =
        exchange_code_response(&app, &public_client_id, None, PUBLIC_REDIRECT, &public_code).await;
    let replayed_code = expect_json(replayed_code, StatusCode::BAD_REQUEST).await;
    assert_eq!(replayed_code["error"], "invalid_grant");

    let userinfo = send_bearer(&app, Method::GET, "/oauth2/userinfo", access_token).await;
    let userinfo = expect_json(userinfo, StatusCode::OK).await;
    assert_eq!(userinfo["sub"].as_str().map(str::is_empty), Some(false));
    assert_eq!(userinfo["email"], "oidc-user@example.test");
    assert_eq!(
        userinfo["zeus.organization"]["id"],
        organization_id.to_string()
    );

    let refreshed = exchange_refresh(&app, &public_client_id, None, first_refresh).await;
    let second_refresh = refreshed["refresh_token"]
        .as_str()
        .expect("rotated refresh token is returned");
    assert_ne!(first_refresh, second_refresh);
    let replay = exchange_refresh_response(&app, &public_client_id, None, first_refresh).await;
    let replay = expect_json(replay, StatusCode::BAD_REQUEST).await;
    assert_eq!(replay["error"], "invalid_grant");
    let revoked_descendant =
        exchange_refresh_response(&app, &public_client_id, None, second_refresh).await;
    let revoked_descendant = expect_json(revoked_descendant, StatusCode::BAD_REQUEST).await;
    assert_eq!(revoked_descendant["error"], "invalid_grant");

    let grants = send_json(&app, Method::GET, "/api/v1/users/me/oidc-grants", None).await;
    let grants = expect_json(grants, StatusCode::OK).await;
    assert_eq!(grants.as_array().map(Vec::len), Some(1));
    assert_eq!(grants[0]["client_id"], public_internal_id.to_string());
    let revoked = send_json(
        &app,
        Method::DELETE,
        &format!("/api/v1/users/me/oidc-grants/{public_internal_id}"),
        None,
    )
    .await;
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);

    let confidential_location = authorize(
        &app,
        &confidential_client_id,
        CONFIDENTIAL_REDIRECT,
        &challenge,
        "confidential-state",
    )
    .await;
    assert!(confidential_location.starts_with(CONFIDENTIAL_REDIRECT));
    let confidential_code = query_value(&confidential_location, "code");
    let confidential_tokens = exchange_code(
        &app,
        &confidential_client_id,
        Some(confidential_secret),
        CONFIDENTIAL_REDIRECT,
        &confidential_code,
    )
    .await;
    assert!(
        confidential_tokens["access_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );

    let jwks = send_public(&app, Method::GET, "/oauth2/jwks.json", None, &[]).await;
    let jwks = expect_json(jwks, StatusCode::OK).await;
    assert_eq!(jwks["keys"][0]["alg"], "RS256");
    assert_eq!(jwks["keys"][0]["use"], "sig");
    assert!(
        jwks["keys"][0]["n"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );

    let discovery = send_public(
        &app,
        Method::GET,
        "/.well-known/openid-configuration",
        None,
        &[],
    )
    .await;
    let discovery = expect_json(discovery, StatusCode::OK).await;
    assert_eq!(discovery["issuer"], PUBLIC_URL);
    assert_eq!(discovery["code_challenge_methods_supported"][0], "S256");

    let preflight = send_public(
        &app,
        Method::OPTIONS,
        "/oauth2/token",
        None,
        &[
            (header::ORIGIN.as_str(), "https://spa.example.test"),
            ("access-control-request-method", "POST"),
            ("access-control-request-headers", "content-type"),
        ],
    )
    .await;
    assert!(preflight.status().is_success());
    assert_eq!(
        preflight
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("*")
    );

    let logout_form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", &public_client_id)
        .finish();
    let session_cookie = format!("zeus_session={SESSION_TOKEN}; zeus_csrf={CSRF_TOKEN}");
    let logout = send_public(
        &app,
        Method::POST,
        "/oauth2/logout",
        Some(logout_form),
        &[
            (header::COOKIE.as_str(), &session_cookie),
            (header::ORIGIN.as_str(), PUBLIC_URL),
            ("x-zeus-csrf", CSRF_TOKEN),
        ],
    )
    .await;
    assert_eq!(logout.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        logout
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/")
    );
    let session_revoked: bool =
        sqlx::query_scalar("select revoked_at is not null from web_sessions where id = $1")
            .bind(session_id)
            .fetch_one(&owner_pool)
            .await
            .expect("logout session state reads");
    assert!(session_revoked);
}

#[allow(clippy::too_many_arguments)]
async fn insert_client(
    pool: &sqlx::PgPool,
    organization_id: Uuid,
    user_id: Uuid,
    public_id: &str,
    client_type: &str,
    secret_hash: Option<String>,
    trusted: bool,
    redirect_uri: &str,
) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "insert into oidc_clients (
           organization_id, client_id, name, client_type, client_secret_hash,
           trusted, created_by
         ) values ($1, $2, $3, $4, $5, $6, $7)
         returning id",
    )
    .bind(organization_id)
    .bind(public_id)
    .bind(format!("{client_type} test client"))
    .bind(client_type)
    .bind(secret_hash)
    .bind(trusted)
    .bind(user_id)
    .fetch_one(pool)
    .await
    .expect("OIDC client inserts");
    sqlx::query(
        "insert into oidc_client_redirect_uris (
           organization_id, client_id, uri_kind, redirect_uri
         ) values ($1, $2, 'authorization', $3)",
    )
    .bind(organization_id)
    .bind(id)
    .bind(redirect_uri)
    .execute(pool)
    .await
    .expect("redirect URI inserts");
    id
}

async fn authorize(
    app: &Router,
    client_id: &str,
    redirect_uri: &str,
    challenge: &str,
    state: &str,
) -> String {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair(
            "scope",
            "openid profile email zeus.organization zeus.workspace",
        )
        .append_pair("state", state)
        .append_pair("nonce", "integration-nonce")
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256")
        .finish();
    let response = send_public(
        app,
        Method::GET,
        &format!("/oauth2/authorize?{query}"),
        None,
        &[(
            header::COOKIE.as_str(),
            &format!("zeus_session={SESSION_TOKEN}"),
        )],
    )
    .await;
    if response.status() != StatusCode::SEE_OTHER {
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("authorization error body reads")
            .to_bytes();
        panic!(
            "authorization returned {status}: {}",
            String::from_utf8_lossy(&body)
        );
    }
    response
        .headers()
        .get(header::LOCATION)
        .expect("authorization redirect is present")
        .to_str()
        .expect("authorization redirect is valid")
        .to_owned()
}

async fn exchange_code(
    app: &Router,
    client_id: &str,
    secret: Option<&str>,
    redirect_uri: &str,
    code: &str,
) -> Value {
    let response = exchange_code_response(app, client_id, secret, redirect_uri, code).await;
    expect_json(response, StatusCode::OK).await
}

async fn exchange_code_response(
    app: &Router,
    client_id: &str,
    secret: Option<&str>,
    redirect_uri: &str,
    code: &str,
) -> Response<Body> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("client_id", client_id)
        .append_pair("code", code)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("code_verifier", VERIFIER)
        .finish();
    let authorization =
        secret.map(|secret| format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}"))));
    let mut headers = Vec::new();
    if let Some(authorization) = authorization.as_deref() {
        headers.push((header::AUTHORIZATION.as_str(), authorization));
    }
    send_public(app, Method::POST, "/oauth2/token", Some(body), &headers).await
}

async fn exchange_refresh(
    app: &Router,
    client_id: &str,
    secret: Option<&str>,
    refresh_token: &str,
) -> Value {
    let response = exchange_refresh_response(app, client_id, secret, refresh_token).await;
    expect_json(response, StatusCode::OK).await
}

async fn exchange_refresh_response(
    app: &Router,
    client_id: &str,
    secret: Option<&str>,
    refresh_token: &str,
) -> Response<Body> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "refresh_token")
        .append_pair("client_id", client_id)
        .append_pair("refresh_token", refresh_token)
        .finish();
    let authorization =
        secret.map(|secret| format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}"))));
    let mut headers = Vec::new();
    if let Some(authorization) = authorization.as_deref() {
        headers.push((header::AUTHORIZATION.as_str(), authorization));
    }
    send_public(app, Method::POST, "/oauth2/token", Some(body), &headers).await
}

async fn send_json(app: &Router, method: Method, uri: &str, body: Option<Value>) -> Response<Body> {
    let is_write = !matches!(method, Method::GET | Method::HEAD | Method::OPTIONS);
    let mut request = Request::builder().method(method).uri(uri).header(
        header::COOKIE,
        format!("zeus_session={SESSION_TOKEN}; zeus_csrf={CSRF_TOKEN}"),
    );
    if is_write {
        request = request
            .header(header::ORIGIN, PUBLIC_URL)
            .header("x-zeus-csrf", CSRF_TOKEN);
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

async fn send_bearer(app: &Router, method: Method, uri: &str, token: &str) -> Response<Body> {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request builds");
    app.clone().oneshot(request).await.expect("router responds")
}

async fn send_public(
    app: &Router,
    method: Method,
    uri: &str,
    form: Option<String>,
    headers: &[(&str, &str)],
) -> Response<Body> {
    let mut request = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let body = match form {
        Some(form) => {
            request = request.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            Body::from(form)
        }
        None => Body::empty(),
    };
    app.clone()
        .oneshot(request.body(body).expect("request builds"))
        .await
        .expect("router responds")
}

async fn expect_json(response: Response<Body>, expected: StatusCode) -> Value {
    let status = response.status();
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
    body
}

fn query_value(url: &str, key: &str) -> String {
    Url::parse(url)
        .expect("redirect URL parses")
        .query_pairs()
        .find(|(candidate, _)| candidate == key)
        .unwrap_or_else(|| panic!("{key} is missing from redirect URL"))
        .1
        .into_owned()
}
