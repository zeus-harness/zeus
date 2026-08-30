use axum::{
    Form, Json, Router,
    extract::{Query, State, rejection::FormRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use jsonwebtoken::{Algorithm, Header, Validation, decode, decode_header, encode};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;
use zeus_identity::{generate_opaque_token, sha256_digest, verify_pkce_s256};

use super::{ProtocolClient, keys, load_protocol_client};
use crate::{AppState, error::ApiError};

const TOKEN_LIFETIME_SECONDS: u64 = 300;

#[derive(Deserialize)]
pub(crate) struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    refresh_token: String,
    id_token: String,
    scope: String,
}

#[derive(Debug, FromRow)]
struct ClaimedCode {
    organization_id: Uuid,
    client_id: Uuid,
    user_id: Uuid,
    subject: Uuid,
    scopes: Vec<String>,
    nonce: Option<String>,
    code_challenge: String,
    auth_time: OffsetDateTime,
}

#[derive(Debug, FromRow)]
struct RotatedRefresh {
    disposition: String,
    organization_id: Option<Uuid>,
    client_id: Option<Uuid>,
    user_id: Option<Uuid>,
    subject: Option<Uuid>,
    scopes: Option<Vec<String>>,
    auth_time: Option<OffsetDateTime>,
}

#[derive(Debug, FromRow)]
struct UserInfoRow {
    email: String,
    email_verified: bool,
    display_name: String,
    organization_name: String,
    workspace_ids: Vec<Uuid>,
}

#[derive(Clone, Deserialize, Serialize)]
struct AccessTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
    iat: u64,
    nbf: u64,
    jti: String,
    client_id: String,
    scope: String,
    uid: Uuid,
    oid: Uuid,
}

#[derive(Clone, Deserialize, Serialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
    iat: u64,
    auth_time: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    zeus_organization: Option<OrganizationClaim>,
}

#[derive(Clone, Deserialize, Serialize)]
struct OrganizationClaim {
    id: Uuid,
    name: String,
}

#[derive(Deserialize)]
pub(crate) struct RevocationRequest {
    token: String,
    token_type_hint: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LogoutQuery {
    id_token_hint: Option<String>,
    client_id: Option<String>,
    post_logout_redirect_uri: Option<String>,
    state: Option<String>,
}

#[derive(Serialize)]
struct OAuthErrorBody {
    error: &'static str,
    error_description: &'static str,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct OAuthError {
    status: StatusCode,
    code: &'static str,
    description: &'static str,
    authenticate: bool,
}

impl OAuthError {
    const fn invalid_request(description: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_request",
            description,
            authenticate: false,
        }
    }

    const fn invalid_client() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_client",
            description: "client authentication failed",
            authenticate: true,
        }
    }

    const fn invalid_grant(description: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_grant",
            description,
            authenticate: false,
        }
    }

    const fn unsupported_grant() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "unsupported_grant_type",
            description: "grant_type is unsupported",
            authenticate: false,
        }
    }

    const fn invalid_token() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_token",
            description: "the access token is invalid",
            authenticate: true,
        }
    }

    const fn server_error() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "server_error",
            description: "the authorization server could not complete the request",
            authenticate: false,
        }
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::PRAGMA, "no-cache"),
            ],
            Json(OAuthErrorBody {
                error: self.code,
                error_description: self.description,
            }),
        )
            .into_response();
        if self.authenticate {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"Zeus OIDC\""),
            );
        }
        response
    }
}

pub(crate) async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Result<Form<TokenRequest>, FormRejection>,
) -> Result<Response, OAuthError> {
    let Form(request) =
        request.map_err(|_| OAuthError::invalid_request("token request is invalid"))?;
    let client = authenticate_client(
        &state,
        &headers,
        request.client_id.as_deref(),
        request.client_secret.as_deref(),
    )
    .await?;
    let signing_key = keys::ensure_signing_key(&state)
        .await
        .map_err(|_| OAuthError::server_error())?;
    let response = match request.grant_type.as_str() {
        "authorization_code" => {
            exchange_authorization_code(&state, &client, &signing_key, request).await?
        }
        "refresh_token" => exchange_refresh_token(&state, &client, &signing_key, request).await?,
        _ => return Err(OAuthError::unsupported_grant()),
    };
    Ok((
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(response),
    )
        .into_response())
}

pub(crate) async fn userinfo(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, OAuthError> {
    let token = bearer_token(&headers).ok_or_else(OAuthError::invalid_token)?;
    let (claims, _) = validate_access_token(&state, token).await?;
    let user = load_userinfo(&state, claims.uid, claims.oid).await?;
    let scopes = claims.scope.split_whitespace().collect::<Vec<_>>();
    let mut body = serde_json::Map::new();
    body.insert("sub".to_owned(), serde_json::Value::String(claims.sub));
    if scopes.contains(&"profile") {
        body.insert(
            "name".to_owned(),
            serde_json::Value::String(user.display_name),
        );
    }
    if scopes.contains(&"email") {
        body.insert("email".to_owned(), serde_json::Value::String(user.email));
        body.insert(
            "email_verified".to_owned(),
            serde_json::Value::Bool(user.email_verified),
        );
    }
    if scopes.contains(&"zeus.organization") {
        body.insert(
            "zeus.organization".to_owned(),
            serde_json::json!({"id": claims.oid, "name": user.organization_name}),
        );
    }
    if scopes.contains(&"zeus.workspace") {
        body.insert(
            "zeus.workspaces".to_owned(),
            serde_json::to_value(user.workspace_ids).map_err(|_| OAuthError::server_error())?,
        );
    }
    Ok((
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::Value::Object(body)),
    )
        .into_response())
}

pub(crate) async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Result<Form<RevocationRequest>, FormRejection>,
) -> Result<Response, OAuthError> {
    let Form(request) =
        request.map_err(|_| OAuthError::invalid_request("revocation request is invalid"))?;
    if request.token.len() > 8192 {
        return Err(OAuthError::invalid_request("token is too long"));
    }
    let client = authenticate_client(
        &state,
        &headers,
        request.client_id.as_deref(),
        request.client_secret.as_deref(),
    )
    .await?;
    let hint = request.token_type_hint.as_deref();
    if hint.is_none() || hint == Some("refresh_token") {
        let revoked: bool = sqlx::query_scalar(
            "select zeus_private.revoke_oidc_refresh_token($1, $2, 'client_revocation')",
        )
        .bind(sha256_digest(&request.token).to_vec())
        .bind(client.id)
        .fetch_one(&state.database)
        .await
        .map_err(|_| OAuthError::server_error())?;
        if revoked {
            return Ok(empty_ok());
        }
    }
    if (hint.is_none() || hint == Some("access_token"))
        && let Ok((claims, token_client)) = validate_access_token(&state, &request.token).await
        && token_client.id == client.id
        && let Ok(expires_at) =
            OffsetDateTime::from_unix_timestamp(i64::try_from(claims.exp).unwrap_or(i64::MAX))
    {
        let _ =
            sqlx::query("select zeus_private.record_oidc_access_revocation($1, $2, $3, $4, $5)")
                .bind(claims.jti)
                .bind(claims.oid)
                .bind(client.id)
                .bind(claims.uid)
                .bind(expires_at)
                .execute(&state.database)
                .await;
    }
    Ok(empty_ok())
}

pub(crate) async fn logout_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<LogoutQuery>,
) -> Result<Response, ApiError> {
    logout_inner(state, headers, query).await
}

pub(crate) async fn logout_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(query): Form<LogoutQuery>,
) -> Result<Response, ApiError> {
    logout_inner(state, headers, query).await
}

async fn logout_inner(
    state: AppState,
    headers: HeaderMap,
    query: LogoutQuery,
) -> Result<Response, ApiError> {
    if query
        .state
        .as_deref()
        .is_some_and(|state| state.len() > 1024)
    {
        return Err(ApiError::BadRequest("logout state is too long".to_owned()));
    }
    let hinted_client = if let Some(id_token) = query.id_token_hint.as_deref() {
        let (claims, client) = validate_id_token(&state, id_token)
            .await
            .map_err(|_| ApiError::BadRequest("id_token_hint is invalid".to_owned()))?;
        if query
            .client_id
            .as_deref()
            .is_some_and(|client_id| client_id != claims.aud)
        {
            return Err(ApiError::BadRequest(
                "logout client_id does not match the ID Token".to_owned(),
            ));
        }
        Some(client)
    } else if let Some(client_id) = query.client_id.as_deref() {
        Some(load_protocol_client(&state, client_id).await?)
    } else {
        None
    };
    let redirect_to = match query.post_logout_redirect_uri.as_deref() {
        Some(uri) => {
            let client = hinted_client.as_ref().ok_or_else(|| {
                ApiError::BadRequest(
                    "post_logout_redirect_uri requires a client or ID Token".to_owned(),
                )
            })?;
            if !client
                .post_logout_redirect_uris
                .iter()
                .any(|value| value == uri)
            {
                return Err(ApiError::BadRequest(
                    "post_logout_redirect_uri is not registered".to_owned(),
                ));
            }
            append_state(uri, query.state.as_deref())?
        }
        None => "/".to_owned(),
    };
    let mut response = crate::auth::logout(State(state), headers).await?;
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&redirect_to).map_err(|_| ApiError::Internal)?,
    );
    Ok(response)
}

pub fn protocol_routes() -> Router<AppState> {
    Router::new()
        .route("/oauth2/token", post(token))
        .route("/oauth2/userinfo", get(userinfo).post(userinfo))
        .route("/oauth2/revoke", post(revoke))
}

pub fn logout_routes() -> Router<AppState> {
    Router::new().route("/oauth2/logout", get(logout_get).post(logout_post))
}

async fn exchange_authorization_code(
    state: &AppState,
    client: &ProtocolClient,
    signing_key: &keys::SigningKey,
    request: TokenRequest,
) -> Result<TokenResponse, OAuthError> {
    let code = required_value(request.code, "authorization code is required")?;
    let redirect_uri = required_value(request.redirect_uri, "redirect_uri is required")?;
    let verifier = required_value(request.code_verifier, "code_verifier is required")?;
    if request.refresh_token.is_some() {
        return Err(OAuthError::invalid_request(
            "refresh_token is not valid for this grant",
        ));
    }
    let claimed = sqlx::query_as::<_, ClaimedCode>(
        "select * from zeus_private.claim_oidc_authorization_code($1, $2, $3)",
    )
    .bind(sha256_digest(&code).to_vec())
    .bind(client.id)
    .bind(&redirect_uri)
    .fetch_optional(&state.database)
    .await
    .map_err(|_| OAuthError::server_error())?
    .ok_or_else(|| OAuthError::invalid_grant("authorization code is invalid or already used"))?;
    verify_pkce_s256(&verifier, &claimed.code_challenge)
        .map_err(|_| OAuthError::invalid_grant("PKCE verification failed"))?;
    if claimed.client_id != client.id || claimed.organization_id != client.organization_id {
        return Err(OAuthError::invalid_grant(
            "authorization code client mismatch",
        ));
    }
    let refresh = generate_opaque_token().map_err(|_| OAuthError::server_error())?;
    let response = issue_signed_tokens(
        state,
        client,
        signing_key,
        claimed.user_id,
        claimed.subject,
        &claimed.scopes,
        claimed.auth_time,
        claimed.nonce,
        refresh.plaintext().to_owned(),
    )
    .await?;
    sqlx::query_scalar::<_, Uuid>(
        "select zeus_private.create_oidc_refresh_family($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(claimed.organization_id)
    .bind(client.id)
    .bind(claimed.user_id)
    .bind(claimed.subject)
    .bind(&claimed.scopes)
    .bind(claimed.auth_time)
    .bind(refresh.digest().to_vec())
    .fetch_one(&state.database)
    .await
    .map_err(|_| OAuthError::server_error())?;
    Ok(response)
}

async fn exchange_refresh_token(
    state: &AppState,
    client: &ProtocolClient,
    signing_key: &keys::SigningKey,
    request: TokenRequest,
) -> Result<TokenResponse, OAuthError> {
    if request.code.is_some() || request.redirect_uri.is_some() || request.code_verifier.is_some() {
        return Err(OAuthError::invalid_request(
            "authorization code fields are not valid for this grant",
        ));
    }
    let old_token = required_value(request.refresh_token, "refresh_token is required")?;
    let next_token = generate_opaque_token().map_err(|_| OAuthError::server_error())?;
    let rotated = sqlx::query_as::<_, RotatedRefresh>(
        "select * from zeus_private.rotate_oidc_refresh_token($1, $2, $3)",
    )
    .bind(sha256_digest(&old_token).to_vec())
    .bind(client.id)
    .bind(next_token.digest().to_vec())
    .fetch_one(&state.database)
    .await
    .map_err(|_| OAuthError::server_error())?;
    if rotated.disposition == "replay" {
        state.metrics.record_oidc_refresh_replay();
    }
    if rotated.disposition != "rotated" {
        return Err(OAuthError::invalid_grant(
            "refresh token is invalid, expired, revoked, or replayed",
        ));
    }
    let organization_id = rotated
        .organization_id
        .ok_or_else(OAuthError::server_error)?;
    if organization_id != client.organization_id || rotated.client_id != Some(client.id) {
        return Err(OAuthError::invalid_grant("refresh token client mismatch"));
    }
    issue_signed_tokens(
        state,
        client,
        signing_key,
        rotated.user_id.ok_or_else(OAuthError::server_error)?,
        rotated.subject.ok_or_else(OAuthError::server_error)?,
        &rotated.scopes.ok_or_else(OAuthError::server_error)?,
        rotated.auth_time.ok_or_else(OAuthError::server_error)?,
        None,
        next_token.plaintext().to_owned(),
    )
    .await
}

#[allow(clippy::too_many_arguments)] // Claims are the persisted authorization-code boundary.
async fn issue_signed_tokens(
    state: &AppState,
    client: &ProtocolClient,
    signing_key: &keys::SigningKey,
    user_id: Uuid,
    subject: Uuid,
    scopes: &[String],
    auth_time: OffsetDateTime,
    nonce: Option<String>,
    refresh_token: String,
) -> Result<TokenResponse, OAuthError> {
    let user = load_userinfo(state, user_id, client.organization_id).await?;
    let now = u64::try_from(OffsetDateTime::now_utc().unix_timestamp())
        .map_err(|_| OAuthError::server_error())?;
    let expiry = now + TOKEN_LIFETIME_SECONDS;
    let scope = scopes.join(" ");
    let subject = subject.to_string();
    let access_claims = AccessTokenClaims {
        iss: keys::issuer(state),
        sub: subject.clone(),
        aud: client.client_id.clone(),
        exp: expiry,
        iat: now,
        nbf: now,
        jti: Uuid::now_v7().to_string(),
        client_id: client.client_id.clone(),
        scope: scope.clone(),
        uid: user_id,
        oid: client.organization_id,
    };
    let access_token = sign_jwt(signing_key, "at+jwt", &access_claims)?;
    let has_scope = |scope: &str| scopes.iter().any(|value| value == scope);
    let id_claims = IdTokenClaims {
        iss: keys::issuer(state),
        sub: subject,
        aud: client.client_id.clone(),
        exp: expiry,
        iat: now,
        auth_time: u64::try_from(auth_time.unix_timestamp())
            .map_err(|_| OAuthError::server_error())?,
        nonce,
        name: has_scope("profile").then_some(user.display_name),
        email: has_scope("email").then_some(user.email),
        email_verified: has_scope("email").then_some(user.email_verified),
        zeus_organization: has_scope("zeus.organization").then_some(OrganizationClaim {
            id: client.organization_id,
            name: user.organization_name,
        }),
    };
    let id_token = sign_jwt(signing_key, "JWT", &id_claims)?;
    Ok(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: TOKEN_LIFETIME_SECONDS,
        refresh_token,
        id_token,
        scope,
    })
}

fn sign_jwt<T: Serialize>(
    signing_key: &keys::SigningKey,
    token_type: &str,
    claims: &T,
) -> Result<String, OAuthError> {
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some(token_type.to_owned());
    header.kid = Some(signing_key.key_id.clone());
    encode(&header, claims, &signing_key.encoding_key).map_err(|_| OAuthError::server_error())
}

async fn authenticate_client(
    state: &AppState,
    headers: &HeaderMap,
    form_client_id: Option<&str>,
    form_client_secret: Option<&str>,
) -> Result<ProtocolClient, OAuthError> {
    let basic = parse_basic_client(headers)?;
    if basic.is_some() && form_client_secret.is_some() {
        return Err(OAuthError::invalid_client());
    }
    let client_id = match basic.as_ref() {
        Some((client_id, _)) => {
            if form_client_id.is_some_and(|form| form != client_id) {
                return Err(OAuthError::invalid_client());
            }
            client_id.as_str()
        }
        None => form_client_id.ok_or_else(OAuthError::invalid_client)?,
    };
    let client = load_protocol_client(state, client_id)
        .await
        .map_err(|_| OAuthError::invalid_client())?;
    match client.client_type.as_str() {
        "confidential" => {
            let supplied_secret = match basic {
                Some((_, secret)) => secret,
                None => form_client_secret
                    .filter(|secret| !secret.is_empty())
                    .ok_or_else(OAuthError::invalid_client)?
                    .to_owned(),
            };
            let expected = client
                .client_secret_hash
                .clone()
                .ok_or_else(OAuthError::invalid_client)?;
            let verification = state
                .password_executor
                .verify(SecretString::from(supplied_secret), expected)
                .await
                .map_err(|_| OAuthError::invalid_client())?;
            if !verification.valid {
                return Err(OAuthError::invalid_client());
            }
        }
        "public" => {
            if basic.is_some() || form_client_secret.is_some() {
                return Err(OAuthError::invalid_client());
            }
        }
        _ => return Err(OAuthError::invalid_client()),
    }
    Ok(client)
}

fn parse_basic_client(headers: &HeaderMap) -> Result<Option<(String, String)>, OAuthError> {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| OAuthError::invalid_client())?;
    let encoded = value
        .strip_prefix("Basic ")
        .ok_or_else(OAuthError::invalid_client)?;
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| OAuthError::invalid_client())?;
    let decoded = String::from_utf8(decoded).map_err(|_| OAuthError::invalid_client())?;
    let (client_id, client_secret) = decoded
        .split_once(':')
        .ok_or_else(OAuthError::invalid_client)?;
    if client_id.is_empty() || client_secret.is_empty() {
        return Err(OAuthError::invalid_client());
    }
    Ok(Some((client_id.to_owned(), client_secret.to_owned())))
}

async fn validate_access_token(
    state: &AppState,
    token: &str,
) -> Result<(AccessTokenClaims, ProtocolClient), OAuthError> {
    if token.len() > 8192 {
        return Err(OAuthError::invalid_token());
    }
    let untrusted = jsonwebtoken::dangerous::insecure_decode::<AccessTokenClaims>(token)
        .map_err(|_| OAuthError::invalid_token())?;
    let header = decode_header(token).map_err(|_| OAuthError::invalid_token())?;
    if header.alg != Algorithm::RS256 || header.typ.as_deref() != Some("at+jwt") {
        return Err(OAuthError::invalid_token());
    }
    let key_id = header
        .kid
        .as_deref()
        .ok_or_else(OAuthError::invalid_token)?;
    let client = load_protocol_client(state, &untrusted.claims.client_id)
        .await
        .map_err(|_| OAuthError::invalid_token())?;
    let decoding_key = keys::decoding_key(state, key_id)
        .await
        .map_err(|_| OAuthError::invalid_token())?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.leeway = 30;
    validation.validate_nbf = true;
    validation.set_required_spec_claims(&["iss", "sub", "aud", "exp", "nbf"]);
    validation.set_issuer(&[keys::issuer(state)]);
    validation.set_audience(&[client.client_id.as_str()]);
    let claims = decode::<AccessTokenClaims>(token, &decoding_key, &validation)
        .map_err(|_| OAuthError::invalid_token())?
        .claims;
    if claims.oid != client.organization_id
        || claims.client_id != client.client_id
        || claims.aud != client.client_id
    {
        return Err(OAuthError::invalid_token());
    }
    let revoked: bool = sqlx::query_scalar("select zeus_private.oidc_access_token_is_revoked($1)")
        .bind(&claims.jti)
        .fetch_one(&state.database)
        .await
        .map_err(|_| OAuthError::server_error())?;
    if revoked {
        return Err(OAuthError::invalid_token());
    }
    Ok((claims, client))
}

async fn validate_id_token(
    state: &AppState,
    token: &str,
) -> Result<(IdTokenClaims, ProtocolClient), OAuthError> {
    if token.len() > 8192 {
        return Err(OAuthError::invalid_token());
    }
    let untrusted = jsonwebtoken::dangerous::insecure_decode::<IdTokenClaims>(token)
        .map_err(|_| OAuthError::invalid_token())?;
    let header = decode_header(token).map_err(|_| OAuthError::invalid_token())?;
    if header.alg != Algorithm::RS256 || header.typ.as_deref() != Some("JWT") {
        return Err(OAuthError::invalid_token());
    }
    let client = load_protocol_client(state, &untrusted.claims.aud)
        .await
        .map_err(|_| OAuthError::invalid_token())?;
    let key_id = header
        .kid
        .as_deref()
        .ok_or_else(OAuthError::invalid_token)?;
    let decoding_key = keys::decoding_key(state, key_id)
        .await
        .map_err(|_| OAuthError::invalid_token())?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.leeway = 30;
    validation.set_required_spec_claims(&["iss", "sub", "aud", "exp"]);
    validation.set_issuer(&[keys::issuer(state)]);
    validation.set_audience(&[client.client_id.as_str()]);
    let claims = decode::<IdTokenClaims>(token, &decoding_key, &validation)
        .map_err(|_| OAuthError::invalid_token())?
        .claims;
    Ok((claims, client))
}

async fn load_userinfo(
    state: &AppState,
    user_id: Uuid,
    organization_id: Uuid,
) -> Result<UserInfoRow, OAuthError> {
    sqlx::query_as::<_, UserInfoRow>("select * from zeus_private.load_oidc_userinfo($1, $2)")
        .bind(user_id)
        .bind(organization_id)
        .fetch_optional(&state.database)
        .await
        .map_err(|_| OAuthError::server_error())?
        .ok_or_else(OAuthError::invalid_token)
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
}

fn required_value<T>(value: Option<T>, description: &'static str) -> Result<T, OAuthError> {
    value.ok_or_else(|| OAuthError::invalid_request(description))
}

fn empty_ok() -> Response {
    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
    )
        .into_response()
}

fn append_state(uri: &str, state: Option<&str>) -> Result<String, ApiError> {
    let mut url = Url::parse(uri)
        .map_err(|_| ApiError::BadRequest("post logout URI is invalid".to_owned()))?;
    if let Some(state) = state {
        url.query_pairs_mut().append_pair("state", state);
    }
    Ok(url.into())
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, header};
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    use super::parse_basic_client;

    #[test]
    fn basic_client_auth_rejects_malformed_credentials() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", STANDARD.encode("client:secret"))).unwrap(),
        );
        assert_eq!(
            parse_basic_client(&headers).unwrap(),
            Some(("client".to_owned(), "secret".to_owned()))
        );
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer token"),
        );
        assert!(parse_basic_client(&headers).is_err());
    }
}
