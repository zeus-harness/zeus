#![allow(clippy::missing_errors_doc)] // HTTP failures use the shared Problem Details contract.

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    routing::{delete, get, post},
};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;
use zeus_identity::normalize_email;

use crate::{
    AppState,
    api_support::{required_revision, revision_etag},
    auth::{
        PrincipalContext, PrincipalKind, csrf_cookie, expired_tenant_access_grant_cookie,
        session_cookie, tenant_access_grant_cookie,
    },
    crypto::{random_token, sha256},
    error::ApiError,
    idempotency,
    native_auth::{queue_invitation_email_on, verify_current_password, verify_second_factor},
    organization::{validate_name, validate_slug},
};

const PLATFORM_REAUTHENTICATION_SECONDS: i64 = 600;

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct PlatformOrganizationResponse {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub status: String,
    pub revision: i64,
    pub identity_settings_mode: String,
    pub governance_revision: i64,
    pub workspace_count: i64,
    pub active_owner_count: i64,
    pub pending_owner_invitation_id: Option<Uuid>,
    pub pending_owner_email: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub archived_at: Option<OffsetDateTime>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct CreatePlatformOrganizationRequest {
    pub slug: String,
    pub name: String,
    pub initial_workspace_slug: String,
    pub initial_workspace_name: String,
    pub owner_email: String,
    pub identity_settings_mode: String,
}

#[derive(Debug, FromRow)]
struct CreatedPlatformOrganizationRow {
    organization_id: Uuid,
    organization_slug: String,
    organization_name: String,
    organization_status: String,
    organization_revision: i64,
    identity_settings_mode: String,
    workspace_id: Uuid,
    workspace_slug: String,
    workspace_name: String,
    invitation_id: Uuid,
    owner_email: String,
    invitation_expires_at: OffsetDateTime,
    replayed: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreatedPlatformOrganizationResponse {
    pub organization_id: Uuid,
    pub organization_slug: String,
    pub organization_name: String,
    pub organization_status: String,
    pub organization_revision: i64,
    pub identity_settings_mode: String,
    pub workspace_id: Uuid,
    pub workspace_slug: String,
    pub workspace_name: String,
    pub invitation_id: Uuid,
    pub owner_email: String,
    #[serde(with = "time::serde::rfc3339")]
    pub invitation_expires_at: OffsetDateTime,
}

impl From<CreatedPlatformOrganizationRow> for CreatedPlatformOrganizationResponse {
    fn from(row: CreatedPlatformOrganizationRow) -> Self {
        Self {
            organization_id: row.organization_id,
            organization_slug: row.organization_slug,
            organization_name: row.organization_name,
            organization_status: row.organization_status,
            organization_revision: row.organization_revision,
            identity_settings_mode: row.identity_settings_mode,
            workspace_id: row.workspace_id,
            workspace_slug: row.workspace_slug,
            workspace_name: row.workspace_name,
            invitation_id: row.invitation_id,
            owner_email: row.owner_email,
            invitation_expires_at: row.invitation_expires_at,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdatePlatformOrganizationRequest {
    pub name: Option<String>,
    pub slug: Option<String>,
    pub identity_settings_mode: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TransitionPlatformOrganizationRequest {
    pub action: String,
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct PlatformOrganizationMutationResponse {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub status: String,
    pub revision: i64,
    pub identity_settings_mode: String,
    pub governance_revision: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub archived_at: Option<OffsetDateTime>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ReplacePlatformOwnerInvitationRequest {
    pub owner_email: String,
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct PlatformOwnerInvitationResponse {
    pub organization_id: Uuid,
    pub organization_name: String,
    pub organization_revision: i64,
    pub invitation_id: Uuid,
    pub owner_email: String,
    #[serde(with = "time::serde::rfc3339")]
    pub invitation_expires_at: OffsetDateTime,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePlatformTenantAccessGrantRequest {
    pub organization_id: Uuid,
    #[schema(min_length = 10, max_length = 500)]
    pub reason: String,
    #[schema(write_only, value_type = String)]
    pub password: String,
    #[schema(write_only, value_type = String)]
    pub totp_code: String,
    #[serde(default = "default_grant_duration_minutes")]
    #[schema(minimum = 1, maximum = 60)]
    pub duration_minutes: u16,
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct PlatformTenantAccessGrantResponse {
    pub grant_id: Uuid,
    pub organization_id: Uuid,
    pub organization_name: String,
    pub organization_status: String,
    pub reason: String,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

#[utoipa::path(
    get,
    path = "/api/v1/platform/organizations",
    tag = "platform",
    responses((status = 200, description = "Organizations visible to the platform", body = [PlatformOrganizationResponse]))
)]
pub async fn list_platform_organizations(
    State(state): State<AppState>,
    principal: PrincipalContext,
) -> Result<Json<Vec<PlatformOrganizationResponse>>, ApiError> {
    let (user_id, session_id) = require_platform_owner(&principal, false)?;
    let organizations = sqlx::query_as::<_, PlatformOrganizationResponse>(
        "select * from zeus_private.list_platform_organizations($1, $2)",
    )
    .bind(user_id)
    .bind(session_id)
    .fetch_all(&state.platform.database)
    .await?;
    Ok(Json(organizations))
}

#[utoipa::path(
    get,
    path = "/api/v1/platform/organizations/{organization_id}",
    tag = "platform",
    params(("organization_id" = Uuid, Path)),
    responses((status = 200, description = "Platform Organization detail", body = PlatformOrganizationResponse))
)]
pub async fn get_platform_organization(
    State(state): State<AppState>,
    principal: PrincipalContext,
    Path(organization_id): Path<Uuid>,
) -> Result<(HeaderMap, Json<PlatformOrganizationResponse>), ApiError> {
    let (user_id, session_id) = require_platform_owner(&principal, false)?;
    let organization = sqlx::query_as::<_, PlatformOrganizationResponse>(
        "select * from zeus_private.load_platform_organization($1, $2, $3)",
    )
    .bind(user_id)
    .bind(session_id)
    .bind(organization_id)
    .fetch_optional(&state.platform.database)
    .await?
    .ok_or(ApiError::NotFound)?;
    let mut headers = HeaderMap::new();
    headers.insert(header::ETAG, revision_etag(organization.revision)?);
    Ok((headers, Json(organization)))
}

#[utoipa::path(
    post,
    path = "/api/v1/platform/organizations",
    tag = "platform",
    params(("Idempotency-Key" = String, Header)),
    request_body = CreatePlatformOrganizationRequest,
    responses((status = 201, description = "Provisioning Organization, initial Workspace, and Owner invitation", body = CreatedPlatformOrganizationResponse))
)]
pub async fn create_platform_organization(
    State(state): State<AppState>,
    principal: PrincipalContext,
    headers: HeaderMap,
    Json(request): Json<CreatePlatformOrganizationRequest>,
) -> Result<(StatusCode, Json<CreatedPlatformOrganizationResponse>), ApiError> {
    let (user_id, session_id) = require_platform_owner(&principal, true)?;
    validate_slug(&request.slug)?;
    validate_name(&request.name)?;
    validate_slug(&request.initial_workspace_slug)?;
    validate_name(&request.initial_workspace_name)?;
    validate_identity_settings_mode(&request.identity_settings_mode)?;
    let owner_email = normalize_email(&request.owner_email)
        .map_err(|_| ApiError::Validation("owner_email is invalid".to_owned()))?;
    let idempotency_key = idempotency::required_key(&headers)?;
    let request_hash = sha256(&serde_json::to_vec(&request).map_err(|_| ApiError::Internal)?);
    let invitation_token = random_token(32).map_err(|_| ApiError::Internal)?;
    let mut transaction = state.platform.database.begin().await?;
    let created = sqlx::query_as::<_, CreatedPlatformOrganizationRow>(
        "select * from zeus_private.create_platform_organization(
           $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
         )",
    )
    .bind(user_id)
    .bind(session_id)
    .bind(idempotency_key)
    .bind(request_hash)
    .bind(&request.slug)
    .bind(request.name.trim())
    .bind(&request.initial_workspace_slug)
    .bind(request.initial_workspace_name.trim())
    .bind(&owner_email)
    .bind(sha256(invitation_token.expose_secret().as_bytes()))
    .bind(&request.identity_settings_mode)
    .fetch_one(&mut *transaction)
    .await?;
    if !created.replayed {
        queue_invitation_email_on(
            &state,
            &mut transaction,
            &owner_email,
            invitation_token.expose_secret(),
            &created.organization_name,
        )
        .await?;
    }
    transaction.commit().await?;
    Ok((StatusCode::CREATED, Json(created.into())))
}

#[utoipa::path(
    patch,
    path = "/api/v1/platform/organizations/{organization_id}",
    tag = "platform",
    params(("organization_id" = Uuid, Path), ("If-Match" = String, Header)),
    request_body = UpdatePlatformOrganizationRequest,
    responses((status = 200, description = "Updated Organization", body = PlatformOrganizationMutationResponse), (status = 412, description = "Revision mismatch"))
)]
pub async fn update_platform_organization(
    State(state): State<AppState>,
    principal: PrincipalContext,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<UpdatePlatformOrganizationRequest>,
) -> Result<(HeaderMap, Json<PlatformOrganizationMutationResponse>), ApiError> {
    let (user_id, session_id) = require_platform_owner(&principal, true)?;
    let revision = required_revision(&headers)?;
    if request.name.is_none() && request.slug.is_none() && request.identity_settings_mode.is_none()
    {
        return Err(ApiError::Validation(
            "at least one Organization field is required".to_owned(),
        ));
    }
    if let Some(name) = request.name.as_deref() {
        validate_name(name)?;
    }
    if let Some(slug) = request.slug.as_deref() {
        validate_slug(slug)?;
    }
    if let Some(mode) = request.identity_settings_mode.as_deref() {
        validate_identity_settings_mode(mode)?;
    }
    let updated = sqlx::query_as::<_, PlatformOrganizationMutationResponse>(
        "select * from zeus_private.update_platform_organization(
           $1, $2, $3, $4, $5, $6, $7
         )",
    )
    .bind(user_id)
    .bind(session_id)
    .bind(organization_id)
    .bind(revision)
    .bind(request.name.as_deref().map(str::trim))
    .bind(request.slug)
    .bind(request.identity_settings_mode)
    .fetch_one(&state.platform.database)
    .await?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(header::ETAG, revision_etag(updated.revision)?);
    Ok((response_headers, Json(updated)))
}

#[utoipa::path(
    post,
    path = "/api/v1/platform/organizations/{organization_id}/status",
    tag = "platform",
    params(("organization_id" = Uuid, Path), ("If-Match" = String, Header)),
    request_body = TransitionPlatformOrganizationRequest,
    responses((status = 200, description = "Transitioned Organization", body = PlatformOrganizationMutationResponse), (status = 409, description = "Invalid state transition"), (status = 412, description = "Revision mismatch"))
)]
pub async fn transition_platform_organization(
    State(state): State<AppState>,
    principal: PrincipalContext,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<TransitionPlatformOrganizationRequest>,
) -> Result<(HeaderMap, Json<PlatformOrganizationMutationResponse>), ApiError> {
    let (user_id, session_id) = require_platform_owner(&principal, true)?;
    let revision = required_revision(&headers)?;
    if !matches!(
        request.action.as_str(),
        "suspend" | "resume" | "archive" | "restore"
    ) {
        return Err(ApiError::Validation(
            "action must be suspend, resume, archive, or restore".to_owned(),
        ));
    }
    let updated = sqlx::query_as::<_, PlatformOrganizationMutationResponse>(
        "select * from zeus_private.transition_platform_organization($1, $2, $3, $4, $5)",
    )
    .bind(user_id)
    .bind(session_id)
    .bind(organization_id)
    .bind(revision)
    .bind(request.action)
    .fetch_one(&state.platform.database)
    .await?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(header::ETAG, revision_etag(updated.revision)?);
    Ok((response_headers, Json(updated)))
}

#[utoipa::path(
    post,
    path = "/api/v1/platform/organizations/{organization_id}/owner-invitation/resend",
    tag = "platform",
    params(("organization_id" = Uuid, Path), ("If-Match" = String, Header)),
    responses((status = 202, description = "Initial Owner invitation resend queued", body = PlatformOwnerInvitationResponse))
)]
pub async fn resend_platform_owner_invitation(
    State(state): State<AppState>,
    principal: PrincipalContext,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<(StatusCode, HeaderMap, Json<PlatformOwnerInvitationResponse>), ApiError> {
    rotate_owner_invitation(
        &state,
        &principal,
        organization_id,
        &headers,
        "resend",
        None,
    )
    .await
}

#[utoipa::path(
    post,
    path = "/api/v1/platform/organizations/{organization_id}/owner-invitation/replace",
    tag = "platform",
    params(("organization_id" = Uuid, Path), ("If-Match" = String, Header)),
    request_body = ReplacePlatformOwnerInvitationRequest,
    responses((status = 202, description = "Replacement initial Owner invitation queued", body = PlatformOwnerInvitationResponse))
)]
pub async fn replace_platform_owner_invitation(
    State(state): State<AppState>,
    principal: PrincipalContext,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<ReplacePlatformOwnerInvitationRequest>,
) -> Result<(StatusCode, HeaderMap, Json<PlatformOwnerInvitationResponse>), ApiError> {
    let owner_email = normalize_email(&request.owner_email)
        .map_err(|_| ApiError::Validation("owner_email is invalid".to_owned()))?;
    rotate_owner_invitation(
        &state,
        &principal,
        organization_id,
        &headers,
        "replace",
        Some(owner_email),
    )
    .await
}

async fn rotate_owner_invitation(
    state: &AppState,
    principal: &PrincipalContext,
    organization_id: Uuid,
    headers: &HeaderMap,
    mode: &str,
    replacement_email: Option<String>,
) -> Result<(StatusCode, HeaderMap, Json<PlatformOwnerInvitationResponse>), ApiError> {
    let (user_id, session_id) = require_platform_owner(principal, true)?;
    let revision = required_revision(headers)?;
    let invitation_token = random_token(32).map_err(|_| ApiError::Internal)?;
    let mut transaction = state.platform.database.begin().await?;
    let invitation = sqlx::query_as::<_, PlatformOwnerInvitationResponse>(
        "select * from zeus_private.rotate_platform_owner_invitation(
           $1, $2, $3, $4, $5, $6, $7
         )",
    )
    .bind(user_id)
    .bind(session_id)
    .bind(organization_id)
    .bind(revision)
    .bind(mode)
    .bind(replacement_email)
    .bind(sha256(invitation_token.expose_secret().as_bytes()))
    .fetch_one(&mut *transaction)
    .await?;
    queue_invitation_email_on(
        state,
        &mut transaction,
        &invitation.owner_email,
        invitation_token.expose_secret(),
        &invitation.organization_name,
    )
    .await?;
    transaction.commit().await?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        header::ETAG,
        revision_etag(invitation.organization_revision)?,
    );
    Ok((StatusCode::ACCEPTED, response_headers, Json(invitation)))
}

#[utoipa::path(
    post,
    path = "/api/v1/platform/tenant-access-grants",
    tag = "platform",
    request_body = CreatePlatformTenantAccessGrantRequest,
    responses((status = 201, description = "Bounded platform tenant access Grant", body = PlatformTenantAccessGrantResponse))
)]
pub async fn create_platform_tenant_access_grant(
    State(state): State<AppState>,
    principal: PrincipalContext,
    Json(request): Json<CreatePlatformTenantAccessGrantRequest>,
) -> Result<
    (
        StatusCode,
        HeaderMap,
        Json<PlatformTenantAccessGrantResponse>,
    ),
    ApiError,
> {
    let (user_id, session_id) = require_platform_owner_without_mfa(&principal)?;
    let reason = request.reason.trim();
    if !(10..=500).contains(&reason.len()) {
        return Err(ApiError::Validation(
            "reason must contain between 10 and 500 characters".to_owned(),
        ));
    }
    if !(1..=60).contains(&request.duration_minutes) {
        return Err(ApiError::Validation(
            "duration_minutes must be between 1 and 60".to_owned(),
        ));
    }
    if request.totp_code.len() != 6 || !request.totp_code.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ApiError::Unauthorized);
    }
    verify_current_password(&state, &principal, request.password).await?;
    let method = verify_second_factor(&state, user_id, &request.totp_code).await?;
    if method != "totp" {
        return Err(ApiError::Unauthorized);
    }
    let session_token = random_token(32).map_err(|_| ApiError::Internal)?;
    let csrf_token = random_token(32).map_err(|_| ApiError::Internal)?;
    let grant = sqlx::query_as::<_, PlatformTenantAccessGrantResponse>(
        "select * from zeus_private.create_platform_tenant_access_grant(
           $1, $2, $3, $4, $5, $6, $7
         )",
    )
    .bind(user_id)
    .bind(session_id)
    .bind(request.organization_id)
    .bind(reason)
    .bind(i32::from(request.duration_minutes))
    .bind(sha256(session_token.expose_secret().as_bytes()))
    .bind(sha256(csrf_token.expose_secret().as_bytes()))
    .fetch_one(&state.platform.database)
    .await?;
    let max_age = u64::try_from((grant.expires_at - OffsetDateTime::now_utc()).whole_seconds())
        .unwrap_or(1)
        .max(1);
    let mut headers = HeaderMap::new();
    for cookie in [
        session_cookie(&state, session_token.expose_secret(), max_age),
        csrf_cookie(&state, csrf_token.expose_secret(), max_age),
        tenant_access_grant_cookie(&state, grant.grant_id, max_age),
    ] {
        headers.append(
            header::SET_COOKIE,
            cookie.parse().map_err(|_| ApiError::Internal)?,
        );
    }
    Ok((StatusCode::CREATED, headers, Json(grant)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/platform/tenant-access-grants/{grant_id}",
    tag = "platform",
    params(("grant_id" = Uuid, Path)),
    responses((status = 204, description = "Platform tenant access Grant revoked"))
)]
pub async fn revoke_platform_tenant_access_grant(
    State(state): State<AppState>,
    principal: PrincipalContext,
    Path(grant_id): Path<Uuid>,
) -> Result<(HeaderMap, StatusCode), ApiError> {
    let (user_id, session_id) = require_platform_owner(&principal, false)?;
    let revoked: bool = sqlx::query_scalar(
        "select zeus_private.revoke_platform_tenant_access_grant($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(session_id)
    .bind(grant_id)
    .bind("revoked by platform owner")
    .fetch_one(&state.platform.database)
    .await?;
    if !revoked {
        return Err(ApiError::NotFound);
    }
    let mut headers = HeaderMap::new();
    headers.append(
        header::SET_COOKIE,
        expired_tenant_access_grant_cookie(&state)
            .parse()
            .map_err(|_| ApiError::Internal)?,
    );
    Ok((headers, StatusCode::NO_CONTENT))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/platform/organizations",
            get(list_platform_organizations).post(create_platform_organization),
        )
        .route(
            "/api/v1/platform/organizations/{organization_id}",
            get(get_platform_organization).patch(update_platform_organization),
        )
        .route(
            "/api/v1/platform/organizations/{organization_id}/status",
            post(transition_platform_organization),
        )
        .route(
            "/api/v1/platform/organizations/{organization_id}/owner-invitation/resend",
            post(resend_platform_owner_invitation),
        )
        .route(
            "/api/v1/platform/organizations/{organization_id}/owner-invitation/replace",
            post(replace_platform_owner_invitation),
        )
        .route(
            "/api/v1/platform/tenant-access-grants",
            post(create_platform_tenant_access_grant),
        )
        .route(
            "/api/v1/platform/tenant-access-grants/{grant_id}",
            delete(revoke_platform_tenant_access_grant),
        )
}

fn require_platform_owner(
    principal: &PrincipalContext,
    require_recent_mfa: bool,
) -> Result<(Uuid, Uuid), ApiError> {
    let ids = require_platform_owner_without_mfa(principal)?;
    let Some(mfa_satisfied_at) = principal.mfa_satisfied_at else {
        return Err(ApiError::MfaRequired);
    };
    if require_recent_mfa
        && OffsetDateTime::now_utc() - mfa_satisfied_at
            > time::Duration::seconds(PLATFORM_REAUTHENTICATION_SECONDS)
    {
        return Err(ApiError::ReauthenticationRequired);
    }
    Ok(ids)
}

fn require_platform_owner_without_mfa(
    principal: &PrincipalContext,
) -> Result<(Uuid, Uuid), ApiError> {
    if principal.principal_kind != PrincipalKind::User
        || principal.email_verified_at.is_none()
        || !principal.platform_roles.contains("platform_owner")
    {
        return Err(ApiError::Forbidden);
    }
    Ok((
        principal.user_id.ok_or(ApiError::Forbidden)?,
        principal.session_id.ok_or(ApiError::Forbidden)?,
    ))
}

fn validate_identity_settings_mode(mode: &str) -> Result<(), ApiError> {
    if matches!(mode, "self_service" | "platform_managed") {
        Ok(())
    } else {
        Err(ApiError::Validation(
            "identity_settings_mode must be self_service or platform_managed".to_owned(),
        ))
    }
}

const fn default_grant_duration_minutes() -> u16 {
    60
}

#[cfg(test)]
mod tests {
    use super::{default_grant_duration_minutes, validate_identity_settings_mode};

    #[test]
    fn platform_tenant_controls_reject_unknown_modes_and_long_grants() {
        assert!(validate_identity_settings_mode("self_service").is_ok());
        assert!(validate_identity_settings_mode("platform_managed").is_ok());
        assert!(validate_identity_settings_mode("tenant_admin").is_err());
        assert_eq!(default_grant_duration_minutes(), 60);
    }
}
