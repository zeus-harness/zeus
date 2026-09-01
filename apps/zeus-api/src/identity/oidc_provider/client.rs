use std::collections::BTreeSet;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    routing::{delete, get},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;
use zeus_identity::OidcScopes;

use crate::{
    AppState,
    api_support::{required_revision, revision_etag},
    auth::{AuthContext, PrincipalContext, insert_audit, require_self_service_identity_settings},
    crypto::random_token,
    database::{TenantScope, begin_tenant},
    error::ApiError,
};

const KNOWN_SCOPES: [&str; 5] = [
    "openid",
    "profile",
    "email",
    "zeus.organization",
    "zeus.workspace",
];

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct OidcClientResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub client_id: String,
    pub name: String,
    pub client_type: String,
    pub trusted: bool,
    pub allowed_scopes: Vec<String>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub status: String,
    pub revision: i64,
    pub created_by: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateOidcClientRequest {
    pub name: String,
    pub client_type: String,
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    pub trusted: bool,
    #[serde(default = "default_scopes")]
    pub allowed_scopes: Vec<String>,
}

#[derive(Serialize, ToSchema)]
pub struct CreatedOidcClientResponse {
    #[serde(flatten)]
    pub client: OidcClientResponse,
    #[schema(value_type = Option<String>, write_only)]
    pub client_secret: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateOidcClientRequest {
    pub name: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    pub trusted: Option<bool>,
    pub allowed_scopes: Option<Vec<String>>,
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct OidcGrantResponse {
    pub client_id: Uuid,
    pub client_public_id: String,
    pub client_name: String,
    pub organization_id: Uuid,
    pub organization_name: String,
    pub scopes: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub granted_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_used_at: OffsetDateTime,
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{organization_id}/oidc-clients",
    tag = "identity",
    params(("organization_id" = Uuid, Path)),
    responses((status = 200, description = "Organization OIDC clients", body = [OidcClientResponse]))
)]
pub async fn list_clients(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<OidcClientResponse>>, ApiError> {
    require_self_service_identity_settings(&state, &auth, organization_id).await?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let clients = sqlx::query_as::<_, OidcClientResponse>(
        "select c.id, c.organization_id, c.client_id, c.name, c.client_type,
                c.trusted, c.allowed_scopes,
                coalesce(array_agg(r.redirect_uri order by r.redirect_uri)
                  filter (where r.uri_kind = 'authorization'), '{}'::text[]) as redirect_uris,
                coalesce(array_agg(r.redirect_uri order by r.redirect_uri)
                  filter (where r.uri_kind = 'post_logout'), '{}'::text[]) as post_logout_redirect_uris,
                c.status, c.revision, c.created_by, c.created_at, c.updated_at
         from oidc_clients c
         left join oidc_client_redirect_uris r on r.client_id = c.id
         where c.organization_id = $1
         group by c.id
         order by c.created_at desc, c.id desc",
    )
    .bind(organization_id)
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(clients))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{organization_id}/oidc-clients",
    tag = "identity",
    params(("organization_id" = Uuid, Path)),
    request_body = CreateOidcClientRequest,
    responses((status = 201, description = "OIDC client created", body = CreatedOidcClientResponse))
)]
pub async fn create_client(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(organization_id): Path<Uuid>,
    Json(request): Json<CreateOidcClientRequest>,
) -> Result<(StatusCode, Json<CreatedOidcClientResponse>), ApiError> {
    require_self_service_identity_settings(&state, &auth, organization_id).await?;
    auth.require_recent_authentication()?;
    let user_id = auth.user_id.ok_or(ApiError::Forbidden)?;
    let name = validate_name(&request.name)?;
    validate_client_type(&request.client_type)?;
    let scopes = validate_scopes(&request.allowed_scopes)?;
    let redirect_uris = validate_redirect_uris(&state, &request.redirect_uris, false)?;
    let post_logout_redirect_uris =
        validate_redirect_uris(&state, &request.post_logout_redirect_uris, true)?;
    let public_id = random_token(24).map_err(|_| ApiError::Internal)?;
    let client_id = format!("zoc_{}", public_id.expose_secret());
    let (client_secret, client_secret_hash) = if request.client_type == "confidential" {
        let secret = random_token(32).map_err(|_| ApiError::Internal)?;
        let secret = SecretString::from(format!("zocs_{}", secret.expose_secret()));
        let hash = state
            .identity
            .password_executor
            .hash(secret.clone())
            .await
            .map_err(|_| ApiError::Internal)?;
        (Some(secret), Some(hash))
    } else {
        (None, None)
    };

    let mut transaction = begin_tenant(
        &state.platform.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let created_id: Uuid = sqlx::query_scalar(
        "insert into oidc_clients (
           organization_id, client_id, name, client_type, client_secret_hash,
           trusted, allowed_scopes, created_by
         ) values ($1, $2, $3, $4, $5, $6, $7, $8)
         returning id",
    )
    .bind(organization_id)
    .bind(&client_id)
    .bind(name)
    .bind(&request.client_type)
    .bind(client_secret_hash)
    .bind(request.trusted)
    .bind(scopes)
    .bind(user_id)
    .fetch_one(&mut *transaction)
    .await?;
    replace_redirect_uris(
        &mut transaction,
        organization_id,
        created_id,
        &redirect_uris,
        &post_logout_redirect_uris,
    )
    .await?;
    let client = load_client(&mut transaction, organization_id, created_id).await?;
    insert_audit(
        &mut transaction,
        &auth,
        None,
        "oidc_client.created",
        "oidc_client",
        created_id,
    )
    .await?;
    transaction.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(CreatedOidcClientResponse {
            client,
            client_secret: client_secret.map(|secret| secret.expose_secret().to_owned()),
        }),
    ))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{organization_id}/oidc-clients/{client_id}",
    tag = "identity",
    params(("organization_id" = Uuid, Path), ("client_id" = Uuid, Path)),
    request_body = UpdateOidcClientRequest,
    responses((status = 200, description = "OIDC client updated", body = OidcClientResponse))
)]
pub async fn update_client(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((organization_id, client_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<UpdateOidcClientRequest>,
) -> Result<(HeaderMap, Json<OidcClientResponse>), ApiError> {
    require_self_service_identity_settings(&state, &auth, organization_id).await?;
    auth.require_recent_authentication()?;
    let revision = required_revision(&headers)?;
    let name = request.name.as_deref().map(validate_name).transpose()?;
    let scopes = request
        .allowed_scopes
        .as_deref()
        .map(validate_scopes)
        .transpose()?;
    let redirect_uris = request
        .redirect_uris
        .as_deref()
        .map(|values| validate_redirect_uris(&state, values, false))
        .transpose()?;
    let post_logout_redirect_uris = request
        .post_logout_redirect_uris
        .as_deref()
        .map(|values| validate_redirect_uris(&state, values, true))
        .transpose()?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let updated = sqlx::query_scalar::<_, Uuid>(
        "update oidc_clients
         set name = coalesce($1, name),
             trusted = coalesce($2, trusted),
             allowed_scopes = coalesce($3, allowed_scopes),
             revision = revision + 1,
             updated_at = now()
         where id = $4 and organization_id = $5 and revision = $6 and status = 'active'
         returning id",
    )
    .bind(name)
    .bind(request.trusted)
    .bind(scopes)
    .bind(client_id)
    .bind(organization_id)
    .bind(revision)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(ApiError::PreconditionFailed)?;
    if redirect_uris.is_some() || post_logout_redirect_uris.is_some() {
        let current = load_client(&mut transaction, organization_id, client_id).await?;
        replace_redirect_uris(
            &mut transaction,
            organization_id,
            client_id,
            redirect_uris.as_deref().unwrap_or(&current.redirect_uris),
            post_logout_redirect_uris
                .as_deref()
                .unwrap_or(&current.post_logout_redirect_uris),
        )
        .await?;
    }
    let client = load_client(&mut transaction, organization_id, updated).await?;
    insert_audit(
        &mut transaction,
        &auth,
        None,
        "oidc_client.updated",
        "oidc_client",
        client_id,
    )
    .await?;
    transaction.commit().await?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(header::ETAG, revision_etag(client.revision)?);
    Ok((response_headers, Json(client)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{organization_id}/oidc-clients/{client_id}",
    tag = "identity",
    params(("organization_id" = Uuid, Path), ("client_id" = Uuid, Path)),
    responses((status = 204, description = "OIDC client revoked"))
)]
pub async fn revoke_client(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((organization_id, client_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    require_self_service_identity_settings(&state, &auth, organization_id).await?;
    auth.require_recent_authentication()?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let result = sqlx::query(
        "update oidc_clients
         set status = 'revoked', revoked_at = now(), revision = revision + 1, updated_at = now()
         where id = $1 and organization_id = $2 and status = 'active'",
    )
    .bind(client_id)
    .bind(organization_id)
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() != 1 {
        return Err(ApiError::NotFound);
    }
    insert_audit(
        &mut transaction,
        &auth,
        None,
        "oidc_client.revoked",
        "oidc_client",
        client_id,
    )
    .await?;
    transaction.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/api/v1/users/me/oidc-grants",
    tag = "identity",
    responses((status = 200, description = "Current user's OIDC grants", body = [OidcGrantResponse]))
)]
pub async fn list_grants(
    State(state): State<AppState>,
    principal: PrincipalContext,
) -> Result<Json<Vec<OidcGrantResponse>>, ApiError> {
    let user_id = principal.user_id.ok_or(ApiError::Forbidden)?;
    let grants = sqlx::query_as::<_, OidcGrantResponse>(
        "select * from zeus_private.list_oidc_user_grants($1)",
    )
    .bind(user_id)
    .fetch_all(&state.platform.database)
    .await?;
    Ok(Json(grants))
}

#[utoipa::path(
    delete,
    path = "/api/v1/users/me/oidc-grants/{client_id}",
    tag = "identity",
    params(("client_id" = Uuid, Path)),
    responses((status = 204, description = "OIDC grant revoked"))
)]
pub async fn revoke_grant(
    State(state): State<AppState>,
    principal: PrincipalContext,
    Path(client_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let user_id = principal.user_id.ok_or(ApiError::Forbidden)?;
    let revoked: bool = sqlx::query_scalar("select zeus_private.revoke_oidc_user_grant($1, $2)")
        .bind(user_id)
        .bind(client_id)
        .fetch_one(&state.platform.database)
        .await?;
    if !revoked {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/organizations/{organization_id}/oidc-clients",
            get(list_clients).post(create_client),
        )
        .route(
            "/api/v1/organizations/{organization_id}/oidc-clients/{client_id}",
            delete(revoke_client).patch(update_client),
        )
        .route("/api/v1/users/me/oidc-grants", get(list_grants))
        .route(
            "/api/v1/users/me/oidc-grants/{client_id}",
            delete(revoke_grant),
        )
}

async fn load_client(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: Uuid,
    client_id: Uuid,
) -> Result<OidcClientResponse, ApiError> {
    sqlx::query_as::<_, OidcClientResponse>(
        "select c.id, c.organization_id, c.client_id, c.name, c.client_type,
                c.trusted, c.allowed_scopes,
                coalesce(array_agg(r.redirect_uri order by r.redirect_uri)
                  filter (where r.uri_kind = 'authorization'), '{}'::text[]) as redirect_uris,
                coalesce(array_agg(r.redirect_uri order by r.redirect_uri)
                  filter (where r.uri_kind = 'post_logout'), '{}'::text[]) as post_logout_redirect_uris,
                c.status, c.revision, c.created_by, c.created_at, c.updated_at
         from oidc_clients c
         left join oidc_client_redirect_uris r on r.client_id = c.id
         where c.organization_id = $1 and c.id = $2
         group by c.id",
    )
    .bind(organization_id)
    .bind(client_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(Into::into)
}

async fn replace_redirect_uris(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: Uuid,
    client_id: Uuid,
    redirect_uris: &[String],
    post_logout_redirect_uris: &[String],
) -> Result<(), ApiError> {
    sqlx::query("delete from oidc_client_redirect_uris where client_id = $1")
        .bind(client_id)
        .execute(&mut **transaction)
        .await?;
    for (kind, values) in [
        ("authorization", redirect_uris),
        ("post_logout", post_logout_redirect_uris),
    ] {
        for value in values {
            sqlx::query(
                "insert into oidc_client_redirect_uris (
                   organization_id, client_id, uri_kind, redirect_uri
                 ) values ($1, $2, $3, $4)",
            )
            .bind(organization_id)
            .bind(client_id)
            .bind(kind)
            .bind(value)
            .execute(&mut **transaction)
            .await?;
        }
    }
    Ok(())
}

fn validate_name(value: &str) -> Result<String, ApiError> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > 120 || value.chars().any(char::is_control) {
        return Err(ApiError::Validation("client name is invalid".to_owned()));
    }
    Ok(value.to_owned())
}

fn validate_client_type(value: &str) -> Result<(), ApiError> {
    if matches!(value, "public" | "confidential") {
        Ok(())
    } else {
        Err(ApiError::Validation("client_type is invalid".to_owned()))
    }
}

fn validate_scopes(values: &[String]) -> Result<Vec<String>, ApiError> {
    let scopes = OidcScopes::new(values)
        .map_err(|_| ApiError::Validation("allowed_scopes are invalid".to_owned()))?;
    if scopes.len() > KNOWN_SCOPES.len()
        || scopes
            .as_slice()
            .iter()
            .any(|scope| !KNOWN_SCOPES.contains(&scope.as_str()))
    {
        return Err(ApiError::Validation(
            "allowed_scopes are invalid".to_owned(),
        ));
    }
    Ok(scopes.as_slice().to_vec())
}

fn validate_redirect_uris(
    state: &AppState,
    values: &[String],
    allow_empty: bool,
) -> Result<Vec<String>, ApiError> {
    if values.len() > 20 || (!allow_empty && values.is_empty()) {
        return Err(ApiError::Validation(
            "redirect URI count is invalid".to_owned(),
        ));
    }
    let mut normalized = Vec::with_capacity(values.len());
    let mut seen = BTreeSet::new();
    for value in values {
        let parsed = url::Url::parse(value)
            .map_err(|_| ApiError::Validation("redirect URI is invalid".to_owned()))?;
        if parsed.fragment().is_some()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(ApiError::Validation("redirect URI is invalid".to_owned()));
        }
        let secure = parsed.scheme() == "https" && parsed.host_str().is_some();
        let loopback_http = parsed.scheme() == "http"
            && parsed.host_str().is_some_and(|host| {
                host.eq_ignore_ascii_case("localhost")
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            });
        let local_deployment = state.identity.public_url.scheme() == "http"
            && state.identity.public_url.host_str().is_some_and(|host| {
                host.eq_ignore_ascii_case("localhost")
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            });
        if !(secure || local_deployment && loopback_http) {
            return Err(ApiError::Validation(
                "redirect URI must use HTTPS or a local loopback address".to_owned(),
            ));
        }
        let canonical = parsed.to_string();
        if !seen.insert(canonical.clone()) {
            return Err(ApiError::Validation(
                "redirect URIs must be unique".to_owned(),
            ));
        }
        normalized.push(canonical);
    }
    Ok(normalized)
}

fn default_scopes() -> Vec<String> {
    KNOWN_SCOPES.iter().map(ToString::to_string).collect()
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;
    use url::Url;

    use super::{validate_redirect_uris, validate_scopes};
    use crate::{
        AppState, ExecutionRuntimeConfig, ExternalClients, IdentityRuntimeConfig, PlatformServices,
        crypto::LocalEnvelopeCipher, supervisor::SupervisorMetrics,
    };

    fn state(public_url: &str) -> AppState {
        let key = SecretString::from("11".repeat(32));
        AppState {
            platform: std::sync::Arc::new(PlatformServices {
                database: sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap(),
                envelope: std::sync::Arc::new(
                    LocalEnvelopeCipher::from_encoded("test".to_owned(), &key).unwrap(),
                ),
                metrics: std::sync::Arc::new(SupervisorMetrics::default()),
                version: "test",
            }),
            identity: std::sync::Arc::new(IdentityRuntimeConfig {
                public_url: Url::parse(public_url).unwrap(),
                session_idle_ttl: std::time::Duration::from_hours(2),
                session_absolute_ttl: std::time::Duration::from_hours(12),
                oidc_state_ttl: std::time::Duration::from_mins(10),
                cookie_secure: false,
                allow_private_oidc_issuers: false,
                bootstrap_token: None,
                identity_hash_key: key,
                trust_proxy_headers: false,
                password_executor: zeus_identity::PasswordExecutor::new(
                    1,
                    1,
                    zeus_identity::PasswordPolicy::default(),
                )
                .unwrap(),
            }),
            external: std::sync::Arc::new(ExternalClients {
                http: reqwest::Client::new(),
            }),
            execution: std::sync::Arc::new(ExecutionRuntimeConfig {
                allow_private_model_endpoints: false,
            }),
        }
    }

    #[tokio::test]
    async fn scopes_and_redirects_are_bounded() {
        assert!(validate_scopes(&["openid".to_owned(), "email".to_owned()]).is_ok());
        assert!(validate_scopes(&["openid".to_owned(), "unknown".to_owned()]).is_err());
        assert!(
            validate_redirect_uris(
                &state("http://127.0.0.1:3000"),
                &["http://127.0.0.1:43123/callback".to_owned()],
                false,
            )
            .is_ok()
        );
        assert!(
            validate_redirect_uris(
                &state("https://zeus.example.com"),
                &["http://127.0.0.1:43123/callback".to_owned()],
                false,
            )
            .is_err()
        );
    }
}
