#![allow(clippy::missing_errors_doc)] // HTTP failures use the shared Problem Details contract.

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    routing::{get, post},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use subtle::ConstantTimeEq;
use utoipa::ToSchema;
use uuid::Uuid;
use zeus_identity::{PasswordExecutorError, normalize_email};

use crate::{
    AppState,
    auth::{csrf_cookie, session_cookie},
    crypto::{random_token, sha256},
    error::ApiError,
};

#[derive(Debug, Serialize, ToSchema)]
pub struct SetupStatusResponse {
    pub setup_required: bool,
    pub bootstrap_token_configured: bool,
}

#[derive(Deserialize, ToSchema)]
pub struct SetupRequest {
    #[schema(write_only, value_type = String)]
    pub bootstrap_token: String,
    pub email: String,
    pub display_name: String,
    #[schema(write_only, value_type = String, min_length = 15, max_length = 128)]
    pub password: String,
    pub organization_slug: String,
    pub organization_name: String,
    pub workspace_slug: String,
    pub workspace_name: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SetupResponse {
    pub user_id: Uuid,
    pub organization_id: Uuid,
    pub workspace_id: Uuid,
    pub session_id: Uuid,
    pub email_verification_required: bool,
    pub totp_setup_required: bool,
}

#[derive(Debug, FromRow)]
#[allow(clippy::struct_field_names)] // Field names mirror the SQL function result.
struct SetupRow {
    user_id: Uuid,
    organization_id: Uuid,
    workspace_id: Uuid,
    session_id: Uuid,
}

#[utoipa::path(
    get,
    path = "/api/v1/setup/status",
    tag = "identity",
    responses((status = 200, description = "Native identity setup state", body = SetupStatusResponse))
)]
pub async fn setup_status(
    State(state): State<AppState>,
) -> Result<Json<SetupStatusResponse>, ApiError> {
    let has_platform_admin: bool = sqlx::query_scalar("select zeus_private.has_platform_admin()")
        .fetch_one(&state.database)
        .await?;
    Ok(Json(SetupStatusResponse {
        setup_required: !has_platform_admin,
        bootstrap_token_configured: state.bootstrap_token.is_some(),
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/setup",
    tag = "identity",
    request_body = SetupRequest,
    responses(
        (status = 201, description = "Platform admin and first tenant created", body = SetupResponse),
        (status = 409, description = "Setup was already completed", body = crate::error::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub async fn setup(
    State(state): State<AppState>,
    Json(request): Json<SetupRequest>,
) -> Result<(StatusCode, HeaderMap, Json<SetupResponse>), ApiError> {
    let has_platform_admin: bool = sqlx::query_scalar("select zeus_private.has_platform_admin()")
        .fetch_one(&state.database)
        .await?;
    if has_platform_admin {
        return Err(ApiError::Conflict("setup is already complete".to_owned()));
    }
    verify_bootstrap_token(&state, &request.bootstrap_token)?;

    let email = normalize_email(&request.email)
        .map_err(|_| ApiError::Validation("email is invalid".to_owned()))?;
    validate_display_name(&request.display_name)?;
    validate_slug(&request.organization_slug)?;
    validate_slug(&request.workspace_slug)?;
    validate_name(&request.organization_name)?;
    validate_name(&request.workspace_name)?;

    let password_hash = state
        .password_executor
        .hash(SecretString::from(request.password))
        .await
        .map_err(map_password_error)?;
    let session_token = random_token(32).map_err(|_| ApiError::Internal)?;
    let csrf_token = random_token(32).map_err(|_| ApiError::Internal)?;
    let mut transaction = state.database.begin().await?;
    let setup = sqlx::query_as::<_, SetupRow>(
        "select * from zeus_private.bootstrap_native_identity(
           $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
         )",
    )
    .bind(&email)
    .bind(request.display_name.trim())
    .bind(password_hash)
    .bind(request.organization_slug)
    .bind(request.organization_name.trim())
    .bind(request.workspace_slug)
    .bind(request.workspace_name.trim())
    .bind(sha256(session_token.expose_secret().as_bytes()))
    .bind(sha256(csrf_token.expose_secret().as_bytes()))
    .bind(i32::try_from(state.session_idle_ttl.as_secs()).unwrap_or(i32::MAX))
    .bind(i32::try_from(state.session_absolute_ttl.as_secs()).unwrap_or(i32::MAX))
    .fetch_one(&mut *transaction)
    .await?;
    crate::native_auth::queue_email_verification_on(
        &state,
        &mut transaction,
        setup.user_id,
        &email,
    )
    .await?;
    transaction.commit().await?;

    let mut headers = HeaderMap::new();
    headers.append(
        header::SET_COOKIE,
        session_cookie(
            &state,
            session_token.expose_secret(),
            state.session_absolute_ttl.as_secs(),
        )
        .parse()
        .map_err(|_| ApiError::Internal)?,
    );
    headers.append(
        header::SET_COOKIE,
        csrf_cookie(
            &state,
            csrf_token.expose_secret(),
            state.session_absolute_ttl.as_secs(),
        )
        .parse()
        .map_err(|_| ApiError::Internal)?,
    );
    headers.insert(
        header::LOCATION,
        "/verify-email".parse().map_err(|_| ApiError::Internal)?,
    );
    Ok((
        StatusCode::CREATED,
        headers,
        Json(SetupResponse {
            user_id: setup.user_id,
            organization_id: setup.organization_id,
            workspace_id: setup.workspace_id,
            session_id: setup.session_id,
            email_verification_required: true,
            totp_setup_required: true,
        }),
    ))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/setup/status", get(setup_status))
        .route("/api/v1/setup", post(setup))
}

fn verify_bootstrap_token(state: &AppState, supplied: &str) -> Result<(), ApiError> {
    let expected = state
        .bootstrap_token
        .as_ref()
        .ok_or_else(|| ApiError::Conflict("bootstrap token is not configured".to_owned()))?;
    let expected_digest = sha256(expected.expose_secret().as_bytes());
    let supplied_digest = sha256(supplied.as_bytes());
    if expected_digest
        .as_slice()
        .ct_eq(supplied_digest.as_slice())
        .unwrap_u8()
        != 1
    {
        return Err(ApiError::Unauthorized);
    }
    Ok(())
}

fn map_password_error(error: PasswordExecutorError) -> ApiError {
    match error {
        PasswordExecutorError::QueueFull => ApiError::RateLimited(1),
        PasswordExecutorError::Password(_) => {
            ApiError::Validation("password does not meet the configured policy".to_owned())
        }
        PasswordExecutorError::InvalidQueueCapacity
        | PasswordExecutorError::InvalidConcurrency
        | PasswordExecutorError::TaskFailed
        | PasswordExecutorError::ExecutorClosed => ApiError::Internal,
    }
}

fn validate_slug(value: &str) -> Result<(), ApiError> {
    let bytes = value.as_bytes();
    if !(3..=63).contains(&bytes.len())
        || value != value.to_ascii_lowercase()
        || !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        || bytes
            .iter()
            .any(|byte| !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && *byte != b'-')
    {
        return Err(ApiError::Validation(
            "slug must use 3-63 lowercase letters, digits, or internal hyphens".to_owned(),
        ));
    }
    Ok(())
}

fn validate_display_name(value: &str) -> Result<(), ApiError> {
    if value.trim().is_empty() || value.chars().count() > 120 {
        return Err(ApiError::Validation(
            "display_name must contain between 1 and 120 characters".to_owned(),
        ));
    }
    Ok(())
}

fn validate_name(value: &str) -> Result<(), ApiError> {
    if value.trim().is_empty() || value.chars().count() > 160 {
        return Err(ApiError::Validation(
            "name must contain between 1 and 160 characters".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_display_name, validate_name, validate_slug};

    #[test]
    fn setup_names_and_slugs_are_bounded() {
        assert!(validate_slug("team-one").is_ok());
        assert!(validate_slug("Team One").is_err());
        assert!(validate_display_name("Admin").is_ok());
        assert!(validate_display_name(" ").is_err());
        assert!(validate_name("Main workspace").is_ok());
    }
}
