#![allow(clippy::missing_errors_doc)] // HTTP failures use the shared Problem Details contract.

use std::{convert::Infallible, net::SocketAddr};

use axum::{
    Json, Router,
    extract::{ConnectInfo, FromRequestParts, Path, State},
    http::{HeaderMap, StatusCode, header, request::Parts},
    routing::{delete, get, post, put},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgConnection};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;
use zeus_identity::{
    PasswordExecutorError, Totp, generate_recovery_codes, normalize_email, recovery_code_digest,
};

use crate::{
    AppState,
    auth::{
        PrincipalContext, csrf_cookie, expired_csrf_cookie, expired_session_cookie,
        required_federated_provider, session_cookie,
    },
    crypto::{SealedSecret, privacy_digest, random_token, sha256},
    database::begin_user,
    error::ApiError,
};

const EMAIL_VERIFICATION_TTL_HOURS: i64 = 24;
const PASSWORD_RESET_TTL_MINUTES: i64 = 30;
const RECENT_AUTHENTICATION_SECONDS: i64 = 600;
const GENERIC_EMAIL_ACCEPTED: &str =
    "If the request can be completed, Zeus will send an email with the next step.";

#[derive(Clone, Copy, Debug)]
pub struct ClientAddress(Option<std::net::IpAddr>);

impl FromRequestParts<AppState> for ClientAddress {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let forwarded = state
            .trust_proxy_headers
            .then(|| {
                parts
                    .headers
                    .get("x-forwarded-for")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.split(',').next())
                    .map(str::trim)
                    .and_then(|value| value.parse().ok())
            })
            .flatten();
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|value| value.0.ip());
        Ok(Self(forwarded.or(peer)))
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AcceptedIdentityResponse {
    pub accepted: bool,
    pub detail: &'static str,
}

impl AcceptedIdentityResponse {
    pub(crate) const fn generic() -> Self {
        Self {
            accepted: true,
            detail: GENERIC_EMAIL_ACCEPTED,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterRequest {
    pub email: String,
    pub display_name: String,
    #[schema(write_only, value_type = String, min_length = 15, max_length = 128)]
    pub password: String,
    #[schema(write_only, value_type = Option<String>)]
    pub invitation_token: Option<String>,
}

#[derive(Debug, FromRow)]
struct RegistrationRow {
    user_id: Uuid,
    email_verified: bool,
    organization_id: Option<Uuid>,
    workspace_id: Option<Uuid>,
}

#[utoipa::path(post, path = "/api/v1/auth/register", tag = "identity",
    request_body = RegisterRequest,
    responses((status = 202, description = "Registration request accepted", body = AcceptedIdentityResponse))
)]
pub async fn register(
    State(state): State<AppState>,
    address: ClientAddress,
    Json(request): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<AcceptedIdentityResponse>), ApiError> {
    let email = normalize_email(&request.email)
        .map_err(|_| ApiError::Validation("email is invalid".to_owned()))?;
    validate_display_name(&request.display_name)?;
    enforce_email_request_limits(&state, "registration", &email, address).await?;

    let password_hash = state
        .password_executor
        .hash(SecretString::from(request.password))
        .await
        .map_err(map_password_error)?;
    let invitation_hash = request
        .invitation_token
        .filter(|value| !value.is_empty())
        .map(|value| sha256(value.as_bytes()));

    let registration = sqlx::query_as::<_, RegistrationRow>(
        "select * from zeus_private.create_native_registration($1, $2, $3, $4)",
    )
    .bind(&email)
    .bind(request.display_name.trim())
    .bind(password_hash)
    .bind(invitation_hash)
    .fetch_one(&state.database)
    .await;

    match registration {
        Ok(row) => {
            if !row.email_verified {
                queue_email_verification(&state, row.user_id, &email).await?;
            }
            let _ = (row.organization_id, row.workspace_id);
        }
        Err(error) if has_database_code(&error, "23505") || has_database_code(&error, "42501") => {}
        Err(error) => return Err(error.into()),
    }

    Ok((
        StatusCode::ACCEPTED,
        Json(AcceptedIdentityResponse::generic()),
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NativeLoginRequest {
    pub email: String,
    #[schema(write_only, value_type = String)]
    pub password: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct NativeLoginResponse {
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub email_verification_required: bool,
    pub mfa_required: bool,
    pub totp_setup_required: bool,
}

#[derive(Debug, FromRow)]
struct NativeLoginRow {
    user_id: Uuid,
    status: String,
    email_verified_at: Option<OffsetDateTime>,
    password_hash: String,
    totp_enabled: bool,
}

#[utoipa::path(post, path = "/api/v1/auth/login", tag = "identity",
    request_body = NativeLoginRequest,
    responses(
        (status = 200, description = "Native login completed or awaiting MFA", body = NativeLoginResponse),
        (status = 401, description = "Credentials rejected", body = crate::error::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub async fn native_login(
    State(state): State<AppState>,
    address: ClientAddress,
    Json(request): Json<NativeLoginRequest>,
) -> Result<(HeaderMap, Json<NativeLoginResponse>), ApiError> {
    let email = normalize_email(&request.email).map_err(|_| ApiError::Unauthorized)?;
    let account_key = throttle_key(&state, "password-account", &email);
    let ip_key = address_throttle_key(&state, "password-ip", address);
    ensure_not_throttled(&state, "password_account", &account_key).await?;
    ensure_not_throttled(&state, "password_ip", &ip_key).await?;

    let row =
        sqlx::query_as::<_, NativeLoginRow>("select * from zeus_private.lookup_native_login($1)")
            .bind(&email)
            .fetch_optional(&state.database)
            .await?;

    let Some(row) = row else {
        consume_dummy_password_work(&state).await?;
        record_password_failure(&state, &account_key, &ip_key).await?;
        return Err(ApiError::Unauthorized);
    };
    let password = SecretString::from(request.password);
    let password_for_rehash = password.clone();
    let verification = state
        .password_executor
        .verify(password, row.password_hash.clone())
        .await
        .map_err(map_password_error)?;
    if !verification.valid || !matches!(row.status.as_str(), "pending_verification" | "active") {
        record_password_failure(&state, &account_key, &ip_key).await?;
        return Err(ApiError::Unauthorized);
    }
    clear_throttle(&state, "password_account", &account_key).await?;
    clear_throttle(&state, "password_ip", &ip_key).await?;

    if verification.needs_rehash {
        let replacement = state
            .password_executor
            .hash(password_for_rehash)
            .await
            .map_err(map_password_error)?;
        sqlx::query_scalar::<_, bool>(
            "select zeus_private.update_password_hash_after_login($1, $2, $3)",
        )
        .bind(row.user_id)
        .bind(&row.password_hash)
        .bind(replacement)
        .fetch_one(&state.database)
        .await?;
    }

    let session_token = random_token(32).map_err(|_| ApiError::Internal)?;
    let csrf_token = random_token(32).map_err(|_| ApiError::Internal)?;
    let session_digest = sha256(session_token.expose_secret().as_bytes());
    let session_id = sqlx::query_scalar::<_, Uuid>(
        "select zeus_private.create_user_session($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(row.user_id)
    .bind(Option::<Uuid>::None)
    .bind(Option::<Uuid>::None)
    .bind(&session_digest)
    .bind(sha256(csrf_token.expose_secret().as_bytes()))
    .bind(vec!["password".to_owned()])
    .bind(Option::<OffsetDateTime>::None)
    .bind(ttl_seconds(state.session_idle_ttl))
    .bind(ttl_seconds(state.session_absolute_ttl))
    .fetch_one(&state.database)
    .await?;
    let platform_roles = sqlx::query_scalar::<_, Vec<String>>(
        "select platform_roles from zeus_private.authenticate_user_session($1)",
    )
    .bind(session_digest)
    .fetch_one(&state.database)
    .await?;
    let is_platform_admin = platform_roles.iter().any(|role| role == "platform_admin");

    let mut headers = auth_cookie_headers(&state, &session_token, &csrf_token)?;
    headers.insert(
        header::CACHE_CONTROL,
        "no-store".parse().map_err(|_| ApiError::Internal)?,
    );
    Ok((
        headers,
        Json(NativeLoginResponse {
            user_id: row.user_id,
            session_id,
            email_verification_required: row.email_verified_at.is_none(),
            mfa_required: row.totp_enabled || is_platform_admin,
            totp_setup_required: is_platform_admin && !row.totp_enabled,
        }),
    ))
}

#[utoipa::path(post, path = "/api/v1/auth/logout", tag = "identity",
    responses((status = 204, description = "Current web session revoked"))
)]
pub async fn native_logout(
    State(state): State<AppState>,
    principal: PrincipalContext,
) -> Result<(HeaderMap, StatusCode), ApiError> {
    let session_id = principal.session_id.ok_or(ApiError::Forbidden)?;
    let user_id = principal.user_id.ok_or(ApiError::Forbidden)?;
    sqlx::query_scalar::<_, bool>("select zeus_private.revoke_user_session($1, $2)")
        .bind(session_id)
        .bind(user_id)
        .fetch_one(&state.database)
        .await?;
    Ok((expired_auth_cookie_headers(&state)?, StatusCode::NO_CONTENT))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct EmailAddressRequest {
    pub email: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TokenConfirmationRequest {
    #[schema(write_only, value_type = String)]
    pub token: String,
}

#[utoipa::path(post, path = "/api/v1/auth/email-verifications", tag = "identity",
    request_body = EmailAddressRequest,
    responses((status = 202, description = "Verification request accepted", body = AcceptedIdentityResponse))
)]
pub async fn request_email_verification(
    State(state): State<AppState>,
    address: ClientAddress,
    Json(request): Json<EmailAddressRequest>,
) -> Result<(StatusCode, Json<AcceptedIdentityResponse>), ApiError> {
    let normalized = normalize_email(&request.email).ok();
    let key_value = normalized.as_deref().unwrap_or(request.email.trim());
    enforce_email_request_limits(&state, "email-verification", key_value, address).await?;
    if let Some(email) = normalized
        && let Some(row) = sqlx::query_as::<_, NativeLoginRow>(
            "select * from zeus_private.lookup_native_login($1)",
        )
        .bind(&email)
        .fetch_optional(&state.database)
        .await?
        && row.email_verified_at.is_none()
        && row.status == "pending_verification"
    {
        queue_email_verification(&state, row.user_id, &email).await?;
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(AcceptedIdentityResponse::generic()),
    ))
}

#[utoipa::path(post, path = "/api/v1/auth/email-verifications/confirm", tag = "identity",
    request_body = TokenConfirmationRequest,
    responses((status = 204, description = "Email verified"))
)]
pub async fn confirm_email_verification(
    State(state): State<AppState>,
    Json(request): Json<TokenConfirmationRequest>,
) -> Result<StatusCode, ApiError> {
    validate_opaque_token(&request.token)?;
    let user_id =
        sqlx::query_scalar::<_, Option<Uuid>>("select zeus_private.confirm_email_verification($1)")
            .bind(sha256(request.token.as_bytes()))
            .fetch_one(&state.database)
            .await?;
    user_id.ok_or_else(|| ApiError::BadRequest("verification token is invalid".to_owned()))?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(post, path = "/api/v1/auth/password-resets", tag = "identity",
    request_body = EmailAddressRequest,
    responses((status = 202, description = "Password reset request accepted", body = AcceptedIdentityResponse))
)]
pub async fn request_password_reset(
    State(state): State<AppState>,
    address: ClientAddress,
    Json(request): Json<EmailAddressRequest>,
) -> Result<(StatusCode, Json<AcceptedIdentityResponse>), ApiError> {
    let normalized = normalize_email(&request.email).ok();
    let key_value = normalized.as_deref().unwrap_or(request.email.trim());
    enforce_email_request_limits(&state, "password-reset", key_value, address).await?;
    if let Some(email) = normalized
        && let Some(user_id) = sqlx::query_scalar::<_, Option<Uuid>>(
            "select zeus_private.lookup_password_reset_user($1)",
        )
        .bind(&email)
        .fetch_one(&state.database)
        .await?
    {
        queue_password_reset(&state, user_id, &email).await?;
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(AcceptedIdentityResponse::generic()),
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PasswordResetConfirmationRequest {
    #[schema(write_only, value_type = String)]
    pub token: String,
    #[schema(write_only, value_type = String, min_length = 15, max_length = 128)]
    pub password: String,
}

#[utoipa::path(post, path = "/api/v1/auth/password-resets/confirm", tag = "identity",
    request_body = PasswordResetConfirmationRequest,
    responses((status = 204, description = "Password reset completed"))
)]
pub async fn confirm_password_reset(
    State(state): State<AppState>,
    Json(request): Json<PasswordResetConfirmationRequest>,
) -> Result<StatusCode, ApiError> {
    validate_opaque_token(&request.token)?;
    let password_hash = state
        .password_executor
        .hash(SecretString::from(request.password))
        .await
        .map_err(map_password_error)?;
    let user_id = sqlx::query_scalar::<_, Option<Uuid>>(
        "select zeus_private.consume_password_reset_token($1, $2)",
    )
    .bind(sha256(request.token.as_bytes()))
    .bind(password_hash)
    .fetch_one(&state.database)
    .await?;
    user_id.ok_or_else(|| ApiError::BadRequest("password reset token is invalid".to_owned()))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct MfaVerificationRequest {
    #[schema(write_only, value_type = String)]
    pub code: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MfaVerificationResponse {
    pub verified: bool,
    pub method: String,
}

#[utoipa::path(post, path = "/api/v1/auth/mfa/verify", tag = "identity",
    request_body = MfaVerificationRequest,
    responses((status = 200, description = "MFA verified", body = MfaVerificationResponse))
)]
pub async fn verify_mfa(
    State(state): State<AppState>,
    principal: PrincipalContext,
    Json(request): Json<MfaVerificationRequest>,
) -> Result<(HeaderMap, Json<MfaVerificationResponse>), ApiError> {
    let user_id = principal.user_id.ok_or(ApiError::Forbidden)?;
    let session_id = principal.session_id.ok_or(ApiError::Forbidden)?;
    let account_key = throttle_key(&state, "totp-account", &user_id.to_string());
    ensure_not_throttled(&state, "totp_account", &account_key).await?;
    let method = match verify_second_factor(&state, user_id, &request.code).await {
        Ok(method) => method,
        Err(ApiError::Unauthorized) => {
            record_throttle(&state, "totp_account", &account_key, 300, 5, 300).await?;
            return Err(ApiError::Unauthorized);
        }
        Err(error) => return Err(error),
    };
    clear_throttle(&state, "totp_account", &account_key).await?;
    let headers = rotate_authenticated_session(
        &state,
        session_id,
        user_id,
        Some(OffsetDateTime::now_utc()),
        method,
    )
    .await?;
    Ok((
        headers,
        Json(MfaVerificationResponse {
            verified: true,
            method: method.to_owned(),
        }),
    ))
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct WebSessionResponse {
    pub id: Uuid,
    pub active_organization_id: Option<Uuid>,
    pub active_workspace_id: Option<Uuid>,
    pub auth_methods: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub authenticated_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub mfa_satisfied_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub last_seen_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub idle_expires_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub absolute_expires_at: OffsetDateTime,
    pub current: bool,
}

#[utoipa::path(get, path = "/api/v1/auth/sessions", tag = "identity",
    responses((status = 200, description = "Active web sessions", body = [WebSessionResponse]))
)]
pub async fn list_web_sessions(
    State(state): State<AppState>,
    principal: PrincipalContext,
) -> Result<Json<Vec<WebSessionResponse>>, ApiError> {
    let user_id = principal.user_id.ok_or(ApiError::Forbidden)?;
    let current_session_id = principal.session_id.ok_or(ApiError::Forbidden)?;
    let mut transaction = begin_user(&state.database, user_id).await?;
    let sessions = sqlx::query_as::<_, WebSessionResponse>(
        "select id, active_organization_id, active_workspace_id, auth_methods,
                authenticated_at, mfa_satisfied_at, last_seen_at, idle_expires_at,
                absolute_expires_at, id = $2 as current
         from web_sessions
         where user_id = $1 and revoked_at is null and absolute_expires_at > now()
         order by last_seen_at desc, id desc
         limit 100",
    )
    .bind(user_id)
    .bind(current_session_id)
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(sessions))
}

#[utoipa::path(delete, path = "/api/v1/auth/sessions/{session_id}", tag = "identity",
    params(("session_id" = Uuid, Path)),
    responses((status = 204, description = "Web session revoked"))
)]
pub async fn revoke_web_session(
    State(state): State<AppState>,
    principal: PrincipalContext,
    Path(session_id): Path<Uuid>,
) -> Result<(HeaderMap, StatusCode), ApiError> {
    let user_id = principal.user_id.ok_or(ApiError::Forbidden)?;
    let revoked = sqlx::query_scalar::<_, bool>("select zeus_private.revoke_user_session($1, $2)")
        .bind(session_id)
        .bind(user_id)
        .fetch_one(&state.database)
        .await?;
    if !revoked {
        return Err(ApiError::NotFound);
    }
    let headers = if principal.session_id == Some(session_id) {
        expired_auth_cookie_headers(&state)?
    } else {
        HeaderMap::new()
    };
    Ok((headers, StatusCode::NO_CONTENT))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ChangePasswordRequest {
    #[serde(default)]
    #[schema(write_only, value_type = Option<String>)]
    pub current_password: Option<String>,
    #[schema(write_only, value_type = String, min_length = 15, max_length = 128)]
    pub new_password: String,
}

#[utoipa::path(put, path = "/api/v1/users/me/password", tag = "identity",
    request_body = ChangePasswordRequest,
    responses((status = 204, description = "Password changed and session rotated"))
)]
pub async fn change_password(
    State(state): State<AppState>,
    principal: PrincipalContext,
    Json(request): Json<ChangePasswordRequest>,
) -> Result<(HeaderMap, StatusCode), ApiError> {
    require_recent_authentication(&principal)?;
    let user_id = principal.user_id.ok_or(ApiError::Forbidden)?;
    let session_id = principal.session_id.ok_or(ApiError::Forbidden)?;
    let email = principal.email.as_deref().ok_or(ApiError::Forbidden)?;
    let row =
        sqlx::query_as::<_, NativeLoginRow>("select * from zeus_private.lookup_native_login($1)")
            .bind(email)
            .fetch_optional(&state.database)
            .await?;
    let current_hash = if let Some(row) = row {
        let current_password = request.current_password.ok_or(ApiError::Unauthorized)?;
        let current_hash = row.password_hash.clone();
        let verified = state
            .password_executor
            .verify(SecretString::from(current_password), row.password_hash)
            .await
            .map_err(map_password_error)?;
        if !verified.valid {
            return Err(ApiError::Unauthorized);
        }
        Some(current_hash)
    } else {
        if !principal
            .auth_methods
            .iter()
            .any(|method| method.starts_with("federated:"))
        {
            return Err(ApiError::Unauthorized);
        }
        None
    };
    let password_hash = state
        .password_executor
        .hash(SecretString::from(request.new_password))
        .await
        .map_err(map_password_error)?;
    let session_token = random_token(32).map_err(|_| ApiError::Internal)?;
    let csrf_token = random_token(32).map_err(|_| ApiError::Internal)?;
    let mut transaction = begin_user(&state.database, user_id).await?;
    let updated: bool = if let Some(current_hash) = current_hash {
        sqlx::query_scalar("select zeus_private.update_password_hash_after_login($1, $2, $3)")
            .bind(user_id)
            .bind(current_hash)
            .bind(password_hash)
            .fetch_one(&mut *transaction)
            .await?
    } else {
        sqlx::query_scalar("select zeus_private.set_initial_native_password($1, $2, $3)")
            .bind(user_id)
            .bind(session_id)
            .bind(password_hash)
            .fetch_one(&mut *transaction)
            .await?
    };
    if !updated {
        return Err(ApiError::Conflict(
            "password credential changed concurrently".to_owned(),
        ));
    }
    sqlx::query(
        "update web_sessions set revoked_at = coalesce(revoked_at, now())
         where user_id = $1 and id <> $2 and revoked_at is null",
    )
    .bind(user_id)
    .bind(session_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "update web_sessions
         set token_hash = $3, csrf_token_hash = $4,
             token_rotated_at = now(), last_seen_at = now()
         where user_id = $1 and id = $2 and revoked_at is null",
    )
    .bind(user_id)
    .bind(session_id)
    .bind(sha256(session_token.expose_secret().as_bytes()))
    .bind(sha256(csrf_token.expose_secret().as_bytes()))
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok((
        auth_cookie_headers(&state, &session_token, &csrf_token)?,
        StatusCode::NO_CONTENT,
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TotpSetupRequest {
    #[schema(write_only, value_type = Option<String>)]
    pub code: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TotpSetupResponse {
    pub confirmed: bool,
    #[schema(write_only, value_type = Option<String>)]
    pub secret: Option<String>,
    #[schema(write_only, value_type = Option<String>)]
    pub provisioning_uri: Option<String>,
    #[schema(write_only, value_type = Vec<String>)]
    pub recovery_codes: Vec<String>,
}

#[utoipa::path(post, path = "/api/v1/users/me/totp", tag = "identity",
    request_body = TotpSetupRequest,
    responses((status = 200, description = "TOTP enrollment state", body = TotpSetupResponse))
)]
pub async fn configure_totp(
    State(state): State<AppState>,
    principal: PrincipalContext,
    Json(request): Json<TotpSetupRequest>,
) -> Result<(HeaderMap, Json<TotpSetupResponse>), ApiError> {
    require_recent_authentication(&principal)?;
    if principal.email_verified_at.is_none() {
        return Err(ApiError::EmailVerificationRequired);
    }
    let user_id = principal.user_id.ok_or(ApiError::Forbidden)?;
    let session_id = principal.session_id.ok_or(ApiError::Forbidden)?;
    if let Some(code) = request.code {
        let credential = load_totp_credential(&state, user_id).await?;
        if credential.confirmed_at.is_some() {
            return Err(ApiError::Conflict("TOTP is already enabled".to_owned()));
        }
        let secret = open_totp_secret(&state, user_id, credential)?;
        let counter = Totp::new(secret)
            .map_err(|_| ApiError::Internal)?
            .verify_at(&code, unix_timestamp())
            .map_err(|_| ApiError::Unauthorized)?;
        let recovery_codes = generate_recovery_codes().map_err(|_| ApiError::Internal)?;
        let digests = recovery_codes
            .iter()
            .map(|value| value.digest().as_bytes().to_vec())
            .collect::<Vec<_>>();
        let confirmed: bool =
            sqlx::query_scalar("select zeus_private.confirm_totp_credential($1, $2, $3)")
                .bind(user_id)
                .bind(i64::try_from(counter).map_err(|_| ApiError::Internal)?)
                .bind(digests)
                .fetch_one(&state.database)
                .await?;
        if !confirmed {
            return Err(ApiError::Conflict(
                "TOTP enrollment is no longer pending".to_owned(),
            ));
        }
        let headers = rotate_authenticated_session(
            &state,
            session_id,
            user_id,
            Some(OffsetDateTime::now_utc()),
            "totp",
        )
        .await?;
        return Ok((
            headers,
            Json(TotpSetupResponse {
                confirmed: true,
                secret: None,
                provisioning_uri: None,
                recovery_codes: recovery_codes
                    .iter()
                    .map(|value| value.as_str().to_owned())
                    .collect(),
            }),
        ));
    }

    let mut secret = [0_u8; 20];
    getrandom::fill(&mut secret).map_err(|_| ApiError::Internal)?;
    let aad = totp_aad(user_id);
    let sealed = state
        .envelope
        .seal(&secret, aad.as_bytes())
        .map_err(|_| ApiError::Internal)?;
    let stored: bool = sqlx::query_scalar("select zeus_private.store_pending_totp($1, $2, $3, $4)")
        .bind(user_id)
        .bind(sealed.ciphertext)
        .bind(sealed.nonce)
        .bind(sealed.key_id)
        .fetch_one(&state.database)
        .await?;
    if !stored {
        return Err(ApiError::Forbidden);
    }
    let encoded = base32_no_padding(&secret);
    let email = principal.email.as_deref().unwrap_or("user");
    let label = percent_encode(&format!("Zeus:{email}"));
    let provisioning_uri = format!(
        "otpauth://totp/{label}?secret={encoded}&issuer=Zeus&algorithm=SHA1&digits=6&period=30"
    );
    Ok((
        HeaderMap::new(),
        Json(TotpSetupResponse {
            confirmed: false,
            secret: Some(encoded),
            provisioning_uri: Some(provisioning_uri),
            recovery_codes: Vec::new(),
        }),
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DisableTotpRequest {
    #[schema(write_only, value_type = String)]
    pub password: String,
    #[schema(write_only, value_type = String)]
    pub code: String,
}

#[utoipa::path(delete, path = "/api/v1/users/me/totp", tag = "identity",
    request_body = DisableTotpRequest,
    responses((status = 204, description = "TOTP disabled and session rotated"))
)]
pub async fn disable_totp(
    State(state): State<AppState>,
    principal: PrincipalContext,
    Json(request): Json<DisableTotpRequest>,
) -> Result<(HeaderMap, StatusCode), ApiError> {
    require_recent_authentication(&principal)?;
    if principal.platform_roles.contains("platform_admin") {
        return Err(ApiError::Conflict(
            "platform administrators must keep TOTP enabled".to_owned(),
        ));
    }
    let user_id = principal.user_id.ok_or(ApiError::Forbidden)?;
    let session_id = principal.session_id.ok_or(ApiError::Forbidden)?;
    verify_current_password(&state, &principal, request.password).await?;
    verify_second_factor(&state, user_id, &request.code).await?;
    let disabled: bool = sqlx::query_scalar("select zeus_private.disable_totp($1)")
        .bind(user_id)
        .fetch_one(&state.database)
        .await?;
    if !disabled {
        return Err(ApiError::NotFound);
    }
    let session_token = random_token(32).map_err(|_| ApiError::Internal)?;
    let csrf_token = random_token(32).map_err(|_| ApiError::Internal)?;
    let mut transaction = begin_user(&state.database, user_id).await?;
    sqlx::query(
        "update web_sessions
         set token_hash = $3, csrf_token_hash = $4,
             auth_methods = array_remove(array_remove(auth_methods, 'totp'), 'recovery_code'),
             mfa_satisfied_at = null, token_rotated_at = now(), last_seen_at = now()
         where user_id = $1 and id = $2 and revoked_at is null",
    )
    .bind(user_id)
    .bind(session_id)
    .bind(sha256(session_token.expose_secret().as_bytes()))
    .bind(sha256(csrf_token.expose_secret().as_bytes()))
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok((
        auth_cookie_headers(&state, &session_token, &csrf_token)?,
        StatusCode::NO_CONTENT,
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SelectIdentityContextRequest {
    pub organization_id: Option<Uuid>,
    pub workspace_id: Option<Uuid>,
}

#[utoipa::path(post, path = "/api/v1/auth/context", tag = "identity",
    request_body = SelectIdentityContextRequest,
    responses((status = 204, description = "Session tenant context selected"))
)]
pub async fn select_identity_context(
    State(state): State<AppState>,
    principal: PrincipalContext,
    Json(request): Json<SelectIdentityContextRequest>,
) -> Result<(HeaderMap, StatusCode), ApiError> {
    if request.workspace_id.is_some() && request.organization_id.is_none() {
        return Err(ApiError::Validation(
            "workspace_id requires organization_id".to_owned(),
        ));
    }
    if principal.email_verified_at.is_none() {
        return Err(ApiError::EmailVerificationRequired);
    }
    let user_id = principal.user_id.ok_or(ApiError::Forbidden)?;
    let session_id = principal.session_id.ok_or(ApiError::Forbidden)?;
    if let Some(organization_id) = request.organization_id
        && organization_requires_mfa(&state, user_id, organization_id).await?
        && principal.mfa_satisfied_at.is_none()
    {
        return Err(ApiError::MfaRequired);
    }
    if request.organization_id.is_some() {
        let mut selected_principal = principal.clone();
        selected_principal.organization_id = request.organization_id;
        selected_principal.workspace_id = request.workspace_id;
        if let Some(provider_id) = required_federated_provider(&state, &selected_principal).await?
            && !principal
                .auth_methods
                .contains(&format!("federated:{provider_id}"))
        {
            return Err(ApiError::FederatedAuthenticationRequired);
        }
    }
    let session_token = random_token(32).map_err(|_| ApiError::Internal)?;
    let csrf_token = random_token(32).map_err(|_| ApiError::Internal)?;
    let selected: bool = sqlx::query_scalar(
        "select zeus_private.rotate_user_session_context($1, $2, $3, $4, $5, $6)",
    )
    .bind(session_id)
    .bind(user_id)
    .bind(request.organization_id)
    .bind(request.workspace_id)
    .bind(sha256(session_token.expose_secret().as_bytes()))
    .bind(sha256(csrf_token.expose_secret().as_bytes()))
    .fetch_one(&state.database)
    .await?;
    if !selected {
        return Err(ApiError::Forbidden);
    }
    Ok((
        auth_cookie_headers(&state, &session_token, &csrf_token)?,
        StatusCode::NO_CONTENT,
    ))
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct UserOrganizationResponse {
    pub organization_id: Uuid,
    pub organization_slug: String,
    pub organization_name: String,
    pub organization_status: String,
    pub organization_role: String,
    pub workspaces: serde_json::Value,
    pub identity_providers: serde_json::Value,
}

#[utoipa::path(
    get,
    path = "/api/v1/users/me/organizations",
    tag = "identity",
    responses((status = 200, description = "Organizations available to the current user", body = [UserOrganizationResponse]))
)]
pub async fn list_user_organizations(
    State(state): State<AppState>,
    principal: PrincipalContext,
) -> Result<Json<Vec<UserOrganizationResponse>>, ApiError> {
    let user_id = principal.user_id.ok_or(ApiError::Forbidden)?;
    let session_id = principal.session_id.ok_or(ApiError::Forbidden)?;
    let organizations = sqlx::query_as::<_, UserOrganizationResponse>(
        "select * from zeus_private.list_user_organizations($1, $2)",
    )
    .bind(user_id)
    .bind(session_id)
    .fetch_all(&state.database)
    .await?;
    Ok(Json(organizations))
}

#[utoipa::path(
    post,
    path = "/api/v1/invitations/{token}/accept",
    tag = "identity",
    params(("token" = String, Path, description = "One-time invitation token")),
    responses((status = 204, description = "Invitation accepted and tenant context selected"))
)]
pub async fn accept_invitation(
    State(state): State<AppState>,
    principal: PrincipalContext,
    Path(token): Path<String>,
) -> Result<(HeaderMap, StatusCode), ApiError> {
    if token.len() < 43 || token.len() > 256 {
        return Err(ApiError::Unauthorized);
    }
    let user_id = principal.user_id.ok_or(ApiError::Forbidden)?;
    let session_id = principal.session_id.ok_or(ApiError::Forbidden)?;
    let accepted = sqlx::query_as::<_, (Uuid, Option<Uuid>)>(
        "select organization_id, workspace_id
         from zeus_private.accept_organization_invitation($1, $2, $3)",
    )
    .bind(user_id)
    .bind(session_id)
    .bind(sha256(token.as_bytes()))
    .fetch_one(&state.database)
    .await?;
    let session_token = random_token(32).map_err(|_| ApiError::Internal)?;
    let csrf_token = random_token(32).map_err(|_| ApiError::Internal)?;
    let selected: bool = sqlx::query_scalar(
        "select zeus_private.rotate_user_session_context($1, $2, $3, $4, $5, $6)",
    )
    .bind(session_id)
    .bind(user_id)
    .bind(Some(accepted.0))
    .bind(accepted.1)
    .bind(sha256(session_token.expose_secret().as_bytes()))
    .bind(sha256(csrf_token.expose_secret().as_bytes()))
    .fetch_one(&state.database)
    .await?;
    if !selected {
        return Err(ApiError::Forbidden);
    }
    Ok((
        auth_cookie_headers(&state, &session_token, &csrf_token)?,
        StatusCode::NO_CONTENT,
    ))
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct FederatedIdentityResponse {
    pub identity_id: Uuid,
    pub provider_id: Uuid,
    pub organization_id: Uuid,
    pub organization_name: String,
    pub provider_slug: String,
    pub issuer: String,
    pub subject: String,
    #[serde(with = "time::serde::rfc3339")]
    pub linked_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_login_at: OffsetDateTime,
}

#[utoipa::path(
    get,
    path = "/api/v1/users/me/federated-identities",
    tag = "identity",
    responses((status = 200, description = "Federated identities linked to the current user", body = [FederatedIdentityResponse]))
)]
pub async fn list_federated_identities(
    State(state): State<AppState>,
    principal: PrincipalContext,
) -> Result<Json<Vec<FederatedIdentityResponse>>, ApiError> {
    let user_id = principal.user_id.ok_or(ApiError::Forbidden)?;
    let session_id = principal.session_id.ok_or(ApiError::Forbidden)?;
    let identities = sqlx::query_as::<_, FederatedIdentityResponse>(
        "select * from zeus_private.list_user_federated_identities($1, $2)",
    )
    .bind(user_id)
    .bind(session_id)
    .fetch_all(&state.database)
    .await?;
    Ok(Json(identities))
}

#[utoipa::path(
    delete,
    path = "/api/v1/users/me/federated-identities/{identity_id}",
    tag = "identity",
    params(("identity_id" = Uuid, Path)),
    responses((status = 204, description = "Federated identity unlinked"))
)]
pub async fn unlink_federated_identity(
    State(state): State<AppState>,
    principal: PrincipalContext,
    Path(identity_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    require_recent_authentication(&principal)?;
    let user_id = principal.user_id.ok_or(ApiError::Forbidden)?;
    let session_id = principal.session_id.ok_or(ApiError::Forbidden)?;
    let removed: bool =
        sqlx::query_scalar("select zeus_private.unlink_federated_identity($1, $2, $3)")
            .bind(user_id)
            .bind(session_id)
            .bind(identity_id)
            .fetch_one(&state.database)
            .await?;
    if !removed {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/auth/register", post(register))
        .route("/api/v1/auth/login", post(native_login))
        .route("/api/v1/auth/logout", post(native_logout))
        .route(
            "/api/v1/auth/email-verifications",
            post(request_email_verification),
        )
        .route(
            "/api/v1/auth/email-verifications/confirm",
            post(confirm_email_verification),
        )
        .route("/api/v1/auth/password-resets", post(request_password_reset))
        .route(
            "/api/v1/auth/password-resets/confirm",
            post(confirm_password_reset),
        )
        .route("/api/v1/auth/mfa/verify", post(verify_mfa))
        .route("/api/v1/auth/context", post(select_identity_context))
        .route("/api/v1/auth/sessions", get(list_web_sessions))
        .route(
            "/api/v1/auth/sessions/{session_id}",
            delete(revoke_web_session),
        )
        .route("/api/v1/users/me/password", put(change_password))
        .route(
            "/api/v1/users/me/organizations",
            get(list_user_organizations),
        )
        .route(
            "/api/v1/invitations/{token}/accept",
            post(accept_invitation),
        )
        .route(
            "/api/v1/users/me/federated-identities",
            get(list_federated_identities),
        )
        .route(
            "/api/v1/users/me/federated-identities/{identity_id}",
            delete(unlink_federated_identity),
        )
        .route(
            "/api/v1/users/me/totp",
            post(configure_totp).delete(disable_totp),
        )
}

#[derive(Debug, FromRow)]
struct TotpCredentialRow {
    encrypted_secret: Vec<u8>,
    secret_nonce: Vec<u8>,
    key_id: String,
    last_used_counter: Option<i64>,
    confirmed_at: Option<OffsetDateTime>,
}

async fn load_totp_credential(
    state: &AppState,
    user_id: Uuid,
) -> Result<TotpCredentialRow, ApiError> {
    sqlx::query_as::<_, TotpCredentialRow>("select * from zeus_private.load_totp_credential($1)")
        .bind(user_id)
        .fetch_optional(&state.database)
        .await?
        .ok_or_else(|| ApiError::Conflict("TOTP setup is required".to_owned()))
}

fn open_totp_secret(
    state: &AppState,
    user_id: Uuid,
    credential: TotpCredentialRow,
) -> Result<Vec<u8>, ApiError> {
    state
        .envelope
        .open(
            &SealedSecret {
                ciphertext: credential.encrypted_secret,
                nonce: credential.secret_nonce,
                key_id: credential.key_id,
            },
            totp_aad(user_id).as_bytes(),
        )
        .map_err(|_| ApiError::Internal)
}

async fn verify_second_factor(
    state: &AppState,
    user_id: Uuid,
    code: &str,
) -> Result<&'static str, ApiError> {
    if code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit()) {
        let credential = load_totp_credential(state, user_id).await?;
        if credential.confirmed_at.is_none() {
            return Err(ApiError::Conflict("TOTP setup is required".to_owned()));
        }
        let last_counter = credential
            .last_used_counter
            .map(u64::try_from)
            .transpose()
            .map_err(|_| ApiError::Internal)?;
        let secret = open_totp_secret(state, user_id, credential)?;
        let counter = Totp::new(secret)
            .map_err(|_| ApiError::Internal)?
            .verify_once(code, unix_timestamp(), last_counter)
            .map_err(|_| ApiError::Unauthorized)?;
        let consumed: bool = sqlx::query_scalar("select zeus_private.consume_totp_counter($1, $2)")
            .bind(user_id)
            .bind(i64::try_from(counter).map_err(|_| ApiError::Internal)?)
            .fetch_one(&state.database)
            .await?;
        if !consumed {
            return Err(ApiError::Unauthorized);
        }
        return Ok("totp");
    }
    let digest = recovery_code_digest(code).map_err(|_| ApiError::Unauthorized)?;
    let consumed: bool = sqlx::query_scalar("select zeus_private.consume_recovery_code($1, $2)")
        .bind(user_id)
        .bind(digest.as_bytes().to_vec())
        .fetch_one(&state.database)
        .await?;
    if consumed {
        Ok("recovery_code")
    } else {
        Err(ApiError::Unauthorized)
    }
}

async fn verify_current_password(
    state: &AppState,
    principal: &PrincipalContext,
    password: String,
) -> Result<(), ApiError> {
    let email = principal.email.as_deref().ok_or(ApiError::Forbidden)?;
    let row =
        sqlx::query_as::<_, NativeLoginRow>("select * from zeus_private.lookup_native_login($1)")
            .bind(email)
            .fetch_optional(&state.database)
            .await?
            .ok_or(ApiError::Unauthorized)?;
    let verified = state
        .password_executor
        .verify(SecretString::from(password), row.password_hash)
        .await
        .map_err(map_password_error)?;
    if verified.valid {
        Ok(())
    } else {
        Err(ApiError::Unauthorized)
    }
}

async fn rotate_authenticated_session(
    state: &AppState,
    session_id: Uuid,
    user_id: Uuid,
    mfa_satisfied_at: Option<OffsetDateTime>,
    method: &str,
) -> Result<HeaderMap, ApiError> {
    let session_token = random_token(32).map_err(|_| ApiError::Internal)?;
    let csrf_token = random_token(32).map_err(|_| ApiError::Internal)?;
    let rotated: bool =
        sqlx::query_scalar("select zeus_private.rotate_user_session_token($1, $2, $3, $4, $5, $6)")
            .bind(session_id)
            .bind(user_id)
            .bind(sha256(session_token.expose_secret().as_bytes()))
            .bind(sha256(csrf_token.expose_secret().as_bytes()))
            .bind(mfa_satisfied_at)
            .bind(method)
            .fetch_one(&state.database)
            .await?;
    if !rotated {
        return Err(ApiError::Unauthorized);
    }
    auth_cookie_headers(state, &session_token, &csrf_token)
}

pub(crate) fn require_recent_authentication(principal: &PrincipalContext) -> Result<(), ApiError> {
    let most_recent = [principal.authenticated_at, principal.mfa_satisfied_at]
        .into_iter()
        .flatten()
        .max();
    if most_recent.is_some_and(|value| {
        OffsetDateTime::now_utc() - value <= time::Duration::seconds(RECENT_AUTHENTICATION_SECONDS)
    }) {
        Ok(())
    } else {
        Err(ApiError::ReauthenticationRequired)
    }
}

async fn organization_requires_mfa(
    state: &AppState,
    user_id: Uuid,
    organization_id: Uuid,
) -> Result<bool, ApiError> {
    let mut transaction = crate::database::begin_tenant(
        &state.database,
        crate::database::TenantScope::organization(Some(user_id), organization_id),
    )
    .await?;
    let required = sqlx::query_scalar::<_, bool>(
        "select coalesce((
           select mfa_required from organization_identity_policies
           where organization_id = $1
         ), false)",
    )
    .bind(organization_id)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(required)
}

pub(crate) async fn queue_email_verification(
    state: &AppState,
    user_id: Uuid,
    email: &str,
) -> Result<(), ApiError> {
    let mut connection = state.database.acquire().await?;
    queue_email_verification_on(state, &mut connection, user_id, email).await
}

pub(crate) async fn queue_email_verification_on(
    state: &AppState,
    connection: &mut PgConnection,
    user_id: Uuid,
    email: &str,
) -> Result<(), ApiError> {
    let token = random_token(32).map_err(|_| ApiError::Internal)?;
    sqlx::query_scalar::<_, Uuid>(
        "select zeus_private.create_email_verification_token($1, $2, $3)",
    )
    .bind(user_id)
    .bind(sha256(token.expose_secret().as_bytes()))
    .bind(
        OffsetDateTime::now_utc() + time::Duration::hours(EMAIL_VERIFICATION_TTL_HOURS)
            - time::Duration::minutes(1),
    )
    .fetch_one(&mut *connection)
    .await?;
    let link = identity_link(state, "/verify-email", token.expose_secret())?;
    queue_identity_email_on(
        state,
        connection,
        "email_verification",
        email,
        "Verify your Zeus email",
        &format!("Open this link to verify your Zeus email address:\n\n{link}\n"),
    )
    .await
}

async fn queue_password_reset(
    state: &AppState,
    user_id: Uuid,
    email: &str,
) -> Result<(), ApiError> {
    let token = random_token(32).map_err(|_| ApiError::Internal)?;
    sqlx::query_scalar::<_, Uuid>("select zeus_private.create_password_reset_token($1, $2, $3)")
        .bind(user_id)
        .bind(sha256(token.expose_secret().as_bytes()))
        .bind(OffsetDateTime::now_utc() + time::Duration::minutes(PASSWORD_RESET_TTL_MINUTES))
        .fetch_one(&state.database)
        .await?;
    let link = identity_link(state, "/reset-password", token.expose_secret())?;
    queue_identity_email(
        state,
        "password_reset",
        email,
        "Reset your Zeus password",
        &format!("Open this link to reset your Zeus password:\n\n{link}\n"),
    )
    .await
}

async fn queue_identity_email(
    state: &AppState,
    message_kind: &str,
    recipient: &str,
    subject: &str,
    body: &str,
) -> Result<(), ApiError> {
    let mut connection = state.database.acquire().await?;
    queue_identity_email_on(
        state,
        &mut connection,
        message_kind,
        recipient,
        subject,
        body,
    )
    .await
}

pub(crate) async fn queue_identity_email_on(
    state: &AppState,
    connection: &mut PgConnection,
    message_kind: &str,
    recipient: &str,
    subject: &str,
    body: &str,
) -> Result<(), ApiError> {
    let aad_prefix = format!("identity-email/{message_kind}/{recipient}");
    let sealed_subject = state
        .envelope
        .seal(
            subject.as_bytes(),
            format!("{aad_prefix}/subject").as_bytes(),
        )
        .map_err(|_| ApiError::Internal)?;
    let sealed_body = state
        .envelope
        .seal(body.as_bytes(), format!("{aad_prefix}/body").as_bytes())
        .map_err(|_| ApiError::Internal)?;
    if sealed_subject.key_id != sealed_body.key_id {
        return Err(ApiError::Internal);
    }
    sqlx::query_scalar::<_, Uuid>(
        "select zeus_private.queue_identity_email($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(message_kind)
    .bind(recipient)
    .bind(sealed_subject.ciphertext)
    .bind(sealed_subject.nonce)
    .bind(sealed_body.ciphertext)
    .bind(sealed_body.nonce)
    .bind(sealed_subject.key_id)
    .bind(OffsetDateTime::now_utc())
    .fetch_one(&mut *connection)
    .await?;
    Ok(())
}

pub(crate) async fn queue_invitation_email_on(
    state: &AppState,
    connection: &mut PgConnection,
    email: &str,
    invitation_token: &str,
    organization_name: &str,
) -> Result<(), ApiError> {
    let mut url = state
        .public_url
        .join("register")
        .map_err(|_| ApiError::Internal)?;
    url.query_pairs_mut()
        .append_pair("invitation_token", invitation_token)
        .append_pair("email", email);
    queue_identity_email_on(
        state,
        connection,
        "organization_invitation",
        email,
        &format!("Join {organization_name} in Zeus"),
        &format!(
            "Open this link to join {organization_name} in Zeus:\n\n{}\n",
            url.as_str()
        ),
    )
    .await
}

fn identity_link(state: &AppState, path: &str, token: &str) -> Result<String, ApiError> {
    let mut url = state
        .public_url
        .join(path.trim_start_matches('/'))
        .map_err(|_| ApiError::Internal)?;
    url.query_pairs_mut().append_pair("token", token);
    Ok(url.into())
}

async fn enforce_email_request_limits(
    state: &AppState,
    kind: &str,
    email: &str,
    address: ClientAddress,
) -> Result<(), ApiError> {
    let email_kind = format!("{kind}_email");
    let ip_kind = format!("{kind}_ip");
    let email_key = throttle_key(state, &email_kind, email);
    let ip_key = address_throttle_key(state, &ip_kind, address);
    ensure_not_throttled(state, &email_kind, &email_key).await?;
    ensure_not_throttled(state, &ip_kind, &ip_key).await?;
    let email_retry = record_throttle(state, &email_kind, &email_key, 3600, 4, 3600).await?;
    let ip_retry = record_throttle(state, &ip_kind, &ip_key, 3600, 21, 3600).await?;
    let retry = email_retry.max(ip_retry);
    if retry > 0 {
        return Err(ApiError::RateLimited(u64::try_from(retry).unwrap_or(3600)));
    }
    Ok(())
}

async fn record_password_failure(
    state: &AppState,
    account_key: &[u8],
    ip_key: &[u8],
) -> Result<(), ApiError> {
    record_throttle(state, "password_account", account_key, 900, 10, 900).await?;
    record_throttle(state, "password_ip", ip_key, 600, 30, 600).await?;
    Ok(())
}

async fn consume_dummy_password_work(state: &AppState) -> Result<(), ApiError> {
    state
        .password_executor
        .hash(SecretString::from("zeus unknown account timing work value"))
        .await
        .map(|_| ())
        .map_err(map_password_error)
}

fn throttle_key(state: &AppState, domain: &str, value: &str) -> Vec<u8> {
    privacy_digest(&state.identity_hash_key, domain, value)
}

fn address_throttle_key(state: &AppState, domain: &str, address: ClientAddress) -> Vec<u8> {
    let value = address
        .0
        .map_or_else(|| "unavailable".to_owned(), |ip| ip.to_string());
    throttle_key(state, domain, &value)
}

async fn ensure_not_throttled(state: &AppState, kind: &str, key: &[u8]) -> Result<(), ApiError> {
    let retry = sqlx::query_scalar::<_, Option<i32>>(
        "select zeus_private.identity_throttle_retry_after($1, $2)",
    )
    .bind(kind)
    .bind(key)
    .fetch_one(&state.database)
    .await?
    .unwrap_or(0);
    if retry > 0 {
        return Err(ApiError::RateLimited(u64::try_from(retry).unwrap_or(1)));
    }
    Ok(())
}

async fn record_throttle(
    state: &AppState,
    kind: &str,
    key: &[u8],
    window_seconds: i32,
    attempts: i32,
    block_seconds: i32,
) -> Result<i32, ApiError> {
    Ok(sqlx::query_scalar(
        "select zeus_private.record_identity_throttle_failure($1, $2, $3, $4, $5)",
    )
    .bind(kind)
    .bind(key)
    .bind(window_seconds)
    .bind(attempts)
    .bind(block_seconds)
    .fetch_one(&state.database)
    .await?)
}

async fn clear_throttle(state: &AppState, kind: &str, key: &[u8]) -> Result<(), ApiError> {
    sqlx::query("select zeus_private.clear_identity_throttle($1, $2)")
        .bind(kind)
        .bind(key)
        .execute(&state.database)
        .await?;
    Ok(())
}

fn auth_cookie_headers(
    state: &AppState,
    session_token: &SecretString,
    csrf_token: &SecretString,
) -> Result<HeaderMap, ApiError> {
    let mut headers = HeaderMap::new();
    headers.append(
        header::SET_COOKIE,
        session_cookie(
            state,
            session_token.expose_secret(),
            state.session_absolute_ttl.as_secs(),
        )
        .parse()
        .map_err(|_| ApiError::Internal)?,
    );
    headers.append(
        header::SET_COOKIE,
        csrf_cookie(
            state,
            csrf_token.expose_secret(),
            state.session_absolute_ttl.as_secs(),
        )
        .parse()
        .map_err(|_| ApiError::Internal)?,
    );
    Ok(headers)
}

fn expired_auth_cookie_headers(state: &AppState) -> Result<HeaderMap, ApiError> {
    let mut headers = HeaderMap::new();
    headers.append(
        header::SET_COOKIE,
        expired_session_cookie(state)
            .parse()
            .map_err(|_| ApiError::Internal)?,
    );
    headers.append(
        header::SET_COOKIE,
        expired_csrf_cookie(state)
            .parse()
            .map_err(|_| ApiError::Internal)?,
    );
    Ok(headers)
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

fn validate_display_name(value: &str) -> Result<(), ApiError> {
    if value.trim().is_empty() || value.chars().count() > 120 {
        return Err(ApiError::Validation(
            "display_name must contain between 1 and 120 characters".to_owned(),
        ));
    }
    Ok(())
}

fn validate_opaque_token(value: &str) -> Result<(), ApiError> {
    if value.len() != 43
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ApiError::BadRequest("token is malformed".to_owned()));
    }
    Ok(())
}

fn has_database_code(error: &sqlx::Error, expected: &str) -> bool {
    error
        .as_database_error()
        .is_some_and(|database_error| database_error.code().as_deref() == Some(expected))
}

fn ttl_seconds(duration: std::time::Duration) -> i32 {
    i32::try_from(duration.as_secs()).unwrap_or(i32::MAX)
}

fn totp_aad(user_id: Uuid) -> String {
    format!("identity/totp/{user_id}")
}

fn unix_timestamp() -> u64 {
    u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).unwrap_or_default()
}

fn percent_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn base32_no_padding(input: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut output = String::with_capacity((input.len() * 8).div_ceil(5));
    let mut buffer = 0_u16;
    let mut bits = 0_u8;
    for &byte in input {
        buffer = (buffer << 8) | u16::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1f) as usize;
            output.push(char::from(ALPHABET[index]));
        }
        if bits == 0 {
            buffer = 0;
        } else {
            buffer &= (1_u16 << bits) - 1;
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        output.push(char::from(ALPHABET[index]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{base32_no_padding, percent_encode, validate_display_name, validate_opaque_token};

    #[test]
    fn totp_transport_helpers_match_rfc4648_shape() {
        assert_eq!(base32_no_padding(b"foo"), "MZXW6");
        assert_eq!(
            percent_encode("Zeus:user@example.test"),
            "Zeus%3Auser%40example.test"
        );
    }

    #[test]
    fn public_identity_inputs_are_bounded() {
        assert!(validate_display_name("Team member").is_ok());
        assert!(validate_display_name(" ").is_err());
        assert!(validate_opaque_token(&"a".repeat(43)).is_ok());
        assert!(validate_opaque_token("short").is_err());
    }
}
