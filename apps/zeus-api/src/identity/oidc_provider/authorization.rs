use axum::{
    Json, Router,
    extract::{OriginalUri, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use url::Url;
use utoipa::ToSchema;
use uuid::Uuid;
use zeus_identity::{OidcScopes, generate_opaque_token};

use super::{ProtocolClient, load_protocol_client};
use crate::{
    AppState,
    auth::{PrincipalContext, authenticate_user_headers, principal_requires_mfa, user_has_totp},
    crypto::{random_token, sha256},
    error::ApiError,
};

#[derive(Debug, Deserialize)]
pub struct AuthorizationQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: String,
    code_challenge_method: String,
    prompt: Option<String>,
}

#[derive(Debug, FromRow)]
struct OrganizationAuthorizationPolicy {
    mfa_required: bool,
    federated_required: bool,
    required_provider_id: Option<Uuid>,
    organization_slug: String,
    provider_slug: Option<String>,
}

#[derive(Debug, FromRow)]
struct AuthorizationTransactionRow {
    transaction_id: Uuid,
    organization_id: Uuid,
    organization_name: String,
    client_id: Uuid,
    client_public_id: String,
    client_name: String,
    scopes: Vec<String>,
}

#[derive(Debug, FromRow)]
struct ConsumedAuthorizationRow {
    disposition: String,
    redirect_uri: String,
    state: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthorizationRequestResponse {
    pub request_id: Uuid,
    pub organization_id: Uuid,
    pub organization_name: String,
    pub client_id: Uuid,
    pub client_public_id: String,
    pub client_name: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AuthorizationDecisionRequest {
    pub approved: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthorizationDecisionResponse {
    pub redirect_url: String,
}

#[derive(Debug, Serialize)]
struct OAuthAuthorizationError {
    error: &'static str,
    error_description: &'static str,
}

pub async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    OriginalUri(original_uri): OriginalUri,
    Query(query): Query<AuthorizationQuery>,
) -> Response {
    match authorize_inner(&state, &headers, &original_uri, query).await {
        Ok(response) => response,
        Err(AuthorizationFailure::Direct(code, description)) => {
            oauth_direct_error(code, description)
        }
        Err(AuthorizationFailure::Redirect {
            redirect_uri,
            state,
            code,
            description,
        }) => oauth_redirect_error(&redirect_uri, state.as_deref(), code, description)
            .unwrap_or_else(|_| oauth_direct_error("invalid_request", "redirect URI is invalid")),
        Err(AuthorizationFailure::Api) => {
            oauth_direct_error("server_error", "authorization could not be completed")
        }
    }
}

#[allow(clippy::too_many_lines)] // Protocol validation stays in wire-order for auditability.
async fn authorize_inner(
    state: &AppState,
    headers: &HeaderMap,
    original_uri: &http::Uri,
    query: AuthorizationQuery,
) -> Result<Response, AuthorizationFailure> {
    if query.client_id.len() > 128 {
        return Err(AuthorizationFailure::Direct(
            "invalid_request",
            "client_id is invalid",
        ));
    }
    let client = load_protocol_client(state, &query.client_id)
        .await
        .map_err(|_| AuthorizationFailure::Direct("invalid_request", "client is unknown"))?;
    if !client.redirect_uris.contains(&query.redirect_uri) {
        return Err(AuthorizationFailure::Direct(
            "invalid_request",
            "redirect_uri is not registered",
        ));
    }
    let failure = |code, description| AuthorizationFailure::Redirect {
        redirect_uri: query.redirect_uri.clone(),
        state: query.state.clone(),
        code,
        description,
    };
    validate_authorization_query(&query, &client)
        .map_err(|(code, description)| failure(code, description))?;
    let return_to = safe_authorize_return_to(original_uri)?;
    let prompt = parse_prompt(query.prompt.as_deref())
        .map_err(|(code, description)| failure(code, description))?;

    let principal = match authenticate_user_headers(state, headers).await {
        Ok(principal) => principal,
        Err(_) if prompt.none => {
            return Err(failure("login_required", "the user is not signed in"));
        }
        Err(_) => return redirect_to_login(&return_to),
    };
    let user_id = principal
        .user_id
        .ok_or_else(|| failure("access_denied", "user login is required"))?;
    let session_id = principal
        .session_id
        .ok_or_else(|| failure("access_denied", "user login is required"))?;
    if principal.email_verified_at.is_none() {
        if prompt.none {
            return Err(failure(
                "interaction_required",
                "email verification is required",
            ));
        }
        return redirect_to_local("/verify-email", &return_to);
    }
    let member: bool = sqlx::query_scalar("select zeus_private.oidc_user_is_member($1, $2, $3)")
        .bind(client.organization_id)
        .bind(user_id)
        .bind(session_id)
        .fetch_one(&state.platform.database)
        .await
        .map_err(ApiError::from)?;
    if !member {
        return Err(failure(
            "access_denied",
            "the user is not an organization member",
        ));
    }
    let policy = organization_policy(state, &principal, client.organization_id).await?;
    let account_mfa_required = principal_requires_mfa(state, &principal).await?;
    if (policy.mfa_required
        || account_mfa_required
        || principal.platform_roles.contains("platform_admin"))
        && principal.mfa_satisfied_at.is_none()
    {
        if prompt.none {
            return Err(failure(
                "interaction_required",
                "multi-factor authentication is required",
            ));
        }
        let destination = if user_has_totp(state, user_id).await? {
            "/mfa"
        } else {
            "/account/security?setup_totp=1"
        };
        return redirect_to_local(destination, &return_to);
    }
    if policy.federated_required {
        let provider_id = policy
            .required_provider_id
            .ok_or(AuthorizationFailure::Api)?;
        if !principal
            .auth_methods
            .contains(&format!("federated:{provider_id}"))
        {
            if prompt.none {
                return Err(failure(
                    "interaction_required",
                    "federated login is required",
                ));
            }
            let provider_slug = policy.provider_slug.ok_or(AuthorizationFailure::Api)?;
            let path = format!(
                "/auth/federated/{}/{}",
                policy.organization_slug, provider_slug
            );
            return redirect_to_local(&path, &return_to);
        }
    }

    let scopes = OidcScopes::from_space_delimited(&query.scope, true)
        .map_err(|_| failure("invalid_scope", "scope is invalid"))?
        .as_slice()
        .to_vec();
    let consent_covers: bool =
        sqlx::query_scalar("select zeus_private.oidc_consent_covers($1, $2, $3)")
            .bind(client.id)
            .bind(user_id)
            .bind(&scopes)
            .fetch_one(&state.platform.database)
            .await
            .map_err(ApiError::from)?;
    if !consent_covers || prompt.consent {
        if prompt.none {
            return Err(failure("consent_required", "user consent is required"));
        }
        let internal_token = random_token(32).map_err(|_| ApiError::Internal)?;
        let transaction_id: Uuid = sqlx::query_scalar(
            "select zeus_private.create_oidc_authorization_transaction(
               $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now() + interval '5 minutes'
             )",
        )
        .bind(client.organization_id)
        .bind(client.id)
        .bind(user_id)
        .bind(session_id)
        .bind(sha256(internal_token.expose_secret().as_bytes()))
        .bind(&query.redirect_uri)
        .bind(&scopes)
        .bind(&query.state)
        .bind(&query.nonce)
        .bind(&query.code_challenge)
        .fetch_one(&state.platform.database)
        .await
        .map_err(ApiError::from)?;
        return redirect_response(&format!("/oauth/consent?request={transaction_id}"));
    }

    let code = generate_opaque_token().map_err(|_| ApiError::Internal)?;
    sqlx::query(
        "select * from zeus_private.issue_oidc_authorization_code(
           $1, $2, $3, $4, $5, $6, $7, $8, $9
         )",
    )
    .bind(client.organization_id)
    .bind(client.id)
    .bind(user_id)
    .bind(session_id)
    .bind(code.digest().to_vec())
    .bind(&query.redirect_uri)
    .bind(&scopes)
    .bind(&query.nonce)
    .bind(&query.code_challenge)
    .execute(&state.platform.database)
    .await
    .map_err(ApiError::from)?;
    let location = success_redirect(
        &query.redirect_uri,
        code.plaintext(),
        query.state.as_deref(),
    )?;
    redirect_response(&location)
}

#[utoipa::path(
    get,
    path = "/api/v1/users/me/oidc-authorization-requests/{request_id}",
    tag = "identity",
    params(("request_id" = Uuid, Path)),
    responses((status = 200, description = "Pending OIDC authorization request", body = AuthorizationRequestResponse))
)]
pub async fn get_authorization_request(
    State(state): State<AppState>,
    principal: PrincipalContext,
    Path(request_id): Path<Uuid>,
) -> Result<Json<AuthorizationRequestResponse>, ApiError> {
    let row = load_transaction(&state, &principal, request_id).await?;
    Ok(Json(AuthorizationRequestResponse {
        request_id: row.transaction_id,
        organization_id: row.organization_id,
        organization_name: row.organization_name,
        client_id: row.client_id,
        client_public_id: row.client_public_id,
        client_name: row.client_name,
        scopes: row.scopes,
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/users/me/oidc-authorization-requests/{request_id}",
    tag = "identity",
    params(("request_id" = Uuid, Path)),
    request_body = AuthorizationDecisionRequest,
    responses((status = 200, description = "OIDC authorization decision recorded", body = AuthorizationDecisionResponse))
)]
pub async fn decide_authorization_request(
    State(state): State<AppState>,
    principal: PrincipalContext,
    Path(request_id): Path<Uuid>,
    Json(request): Json<AuthorizationDecisionRequest>,
) -> Result<Json<AuthorizationDecisionResponse>, ApiError> {
    let user_id = principal.user_id.ok_or(ApiError::Forbidden)?;
    let session_id = principal.session_id.ok_or(ApiError::Forbidden)?;
    let code = request
        .approved
        .then(generate_opaque_token)
        .transpose()
        .map_err(|_| ApiError::Internal)?;
    let code_hash = code.as_ref().map(|token| token.digest().to_vec());
    let row = sqlx::query_as::<_, ConsumedAuthorizationRow>(
        "select * from zeus_private.consume_oidc_authorization_transaction($1, $2, $3, $4, $5)",
    )
    .bind(request_id)
    .bind(user_id)
    .bind(session_id)
    .bind(request.approved)
    .bind(code_hash)
    .fetch_optional(&state.platform.database)
    .await?
    .ok_or(ApiError::NotFound)?;
    let redirect_url = if row.disposition == "approved" {
        let code = code.ok_or(ApiError::Internal)?;
        success_redirect(&row.redirect_uri, code.plaintext(), row.state.as_deref())?
    } else {
        error_redirect(
            &row.redirect_uri,
            row.state.as_deref(),
            "access_denied",
            "the user denied the authorization request",
        )?
    };
    Ok(Json(AuthorizationDecisionResponse { redirect_url }))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/oauth2/authorize", get(authorize))
        .route(
            "/api/v1/users/me/oidc-authorization-requests/{request_id}",
            get(get_authorization_request).post(decide_authorization_request),
        )
}

async fn load_transaction(
    state: &AppState,
    principal: &PrincipalContext,
    request_id: Uuid,
) -> Result<AuthorizationTransactionRow, ApiError> {
    let user_id = principal.user_id.ok_or(ApiError::Forbidden)?;
    let session_id = principal.session_id.ok_or(ApiError::Forbidden)?;
    sqlx::query_as::<_, AuthorizationTransactionRow>(
        "select * from zeus_private.load_oidc_authorization_transaction($1, $2, $3)",
    )
    .bind(request_id)
    .bind(user_id)
    .bind(session_id)
    .fetch_optional(&state.platform.database)
    .await?
    .ok_or(ApiError::NotFound)
}

async fn organization_policy(
    state: &AppState,
    principal: &PrincipalContext,
    organization_id: Uuid,
) -> Result<OrganizationAuthorizationPolicy, AuthorizationFailure> {
    let user_id = principal.user_id.ok_or(AuthorizationFailure::Api)?;
    let session_id = principal.session_id.ok_or(AuthorizationFailure::Api)?;
    let policy = sqlx::query_as::<_, OrganizationAuthorizationPolicy>(
        "select * from zeus_private.load_oidc_organization_policy($1, $2, $3)",
    )
    .bind(organization_id)
    .bind(user_id)
    .bind(session_id)
    .fetch_one(&state.platform.database)
    .await
    .map_err(ApiError::from)?;
    Ok(policy)
}

fn validate_authorization_query(
    query: &AuthorizationQuery,
    client: &ProtocolClient,
) -> Result<(), (&'static str, &'static str)> {
    if query.response_type != "code" {
        return Err((
            "unsupported_response_type",
            "only the code response type is supported",
        ));
    }
    if query.code_challenge_method != "S256" || !valid_pkce_challenge(&query.code_challenge) {
        return Err(("invalid_request", "S256 PKCE is required"));
    }
    if query
        .state
        .as_deref()
        .is_some_and(|value| value.len() > 1024)
        || query
            .nonce
            .as_deref()
            .is_some_and(|value| value.len() > 512)
    {
        return Err(("invalid_request", "state or nonce is too long"));
    }
    let scopes = OidcScopes::from_space_delimited(&query.scope, true)
        .map_err(|_| ("invalid_scope", "scope is invalid"))?;
    if scopes
        .as_slice()
        .iter()
        .any(|scope| !client.allowed_scopes.contains(scope))
    {
        return Err(("invalid_scope", "scope is not allowed for this client"));
    }
    Ok(())
}

#[derive(Clone, Copy, Default)]
struct Prompt {
    none: bool,
    consent: bool,
}

fn parse_prompt(value: Option<&str>) -> Result<Prompt, (&'static str, &'static str)> {
    let Some(value) = value else {
        return Ok(Prompt::default());
    };
    let values = value.split_whitespace().collect::<Vec<_>>();
    if values.is_empty() || values.len() > 2 {
        return Err(("invalid_request", "prompt is invalid"));
    }
    let prompt = Prompt {
        none: values.contains(&"none"),
        consent: values.contains(&"consent"),
    };
    if (prompt.none && values.len() != 1)
        || values
            .iter()
            .any(|value| !matches!(*value, "none" | "consent"))
    {
        return Err(("invalid_request", "prompt is unsupported"));
    }
    Ok(prompt)
}

fn valid_pkce_challenge(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn safe_authorize_return_to(uri: &http::Uri) -> Result<String, AuthorizationFailure> {
    let value =
        uri.path_and_query()
            .map(ToString::to_string)
            .ok_or(AuthorizationFailure::Direct(
                "invalid_request",
                "authorization request is invalid",
            ))?;
    if !value.starts_with("/oauth2/authorize?") || value.len() > 8192 {
        return Err(AuthorizationFailure::Direct(
            "invalid_request",
            "authorization request is invalid",
        ));
    }
    Ok(value)
}

fn redirect_to_login(return_to: &str) -> Result<Response, AuthorizationFailure> {
    redirect_to_local("/login", return_to)
}

fn redirect_to_local(path: &str, return_to: &str) -> Result<Response, AuthorizationFailure> {
    let separator = if path.contains('?') { '&' } else { '?' };
    let encoded = url::form_urlencoded::byte_serialize(return_to.as_bytes()).collect::<String>();
    redirect_response(&format!("{path}{separator}return_to={encoded}"))
}

fn success_redirect(
    redirect_uri: &str,
    code: &str,
    state: Option<&str>,
) -> Result<String, ApiError> {
    let mut url = Url::parse(redirect_uri).map_err(|_| ApiError::Internal)?;
    url.query_pairs_mut().append_pair("code", code);
    if let Some(state) = state {
        url.query_pairs_mut().append_pair("state", state);
    }
    Ok(url.into())
}

fn error_redirect(
    redirect_uri: &str,
    state: Option<&str>,
    code: &str,
    description: &str,
) -> Result<String, ApiError> {
    let mut url = Url::parse(redirect_uri).map_err(|_| ApiError::Internal)?;
    url.query_pairs_mut()
        .append_pair("error", code)
        .append_pair("error_description", description);
    if let Some(state) = state {
        url.query_pairs_mut().append_pair("state", state);
    }
    Ok(url.into())
}

fn redirect_response(location: &str) -> Result<Response, AuthorizationFailure> {
    let value = HeaderValue::from_str(location).map_err(|_| AuthorizationFailure::Api)?;
    Ok((StatusCode::SEE_OTHER, [(header::LOCATION, value)]).into_response())
}

fn oauth_redirect_error(
    redirect_uri: &str,
    state: Option<&str>,
    code: &'static str,
    description: &'static str,
) -> Result<Response, ApiError> {
    let location = error_redirect(redirect_uri, state, code, description)?;
    let value = HeaderValue::from_str(&location).map_err(|_| ApiError::Internal)?;
    Ok((StatusCode::SEE_OTHER, [(header::LOCATION, value)]).into_response())
}

fn oauth_direct_error(code: &'static str, description: &'static str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(OAuthAuthorizationError {
            error: code,
            error_description: description,
        }),
    )
        .into_response()
}

enum AuthorizationFailure {
    Direct(&'static str, &'static str),
    Redirect {
        redirect_uri: String,
        state: Option<String>,
        code: &'static str,
        description: &'static str,
    },
    Api,
}

impl From<ApiError> for AuthorizationFailure {
    fn from(error: ApiError) -> Self {
        let _ = error;
        Self::Api
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_prompt, valid_pkce_challenge};

    #[test]
    fn prompt_and_pkce_reject_downgrades() {
        assert!(parse_prompt(Some("none consent")).is_err());
        assert!(parse_prompt(Some("login")).is_err());
        assert!(parse_prompt(Some("consent")).unwrap().consent);
        assert!(valid_pkce_challenge(&"A".repeat(43)));
        assert!(!valid_pkce_challenge("plain"));
    }
}
