use axum::{Json, response::IntoResponse};
use http::StatusCode;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

tokio::task_local! {
    pub(crate) static REQUEST_ID: Uuid;
}

fn current_request_id() -> Uuid {
    REQUEST_ID
        .try_with(ToOwned::to_owned)
        .unwrap_or_else(|_| Uuid::now_v7())
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("database is unavailable")]
    DatabaseUnavailable,
    #[error("the requested resource was not found")]
    NotFound,
    #[error("the request is malformed: {0}")]
    BadRequest(String),
    #[error("request validation failed: {0}")]
    Validation(String),
    #[error("authentication is required")]
    Unauthorized,
    #[error("access is denied")]
    Forbidden,
    #[error("email verification is required")]
    EmailVerificationRequired,
    #[error("multi-factor authentication is required")]
    MfaRequired,
    #[error("recent authentication is required")]
    ReauthenticationRequired,
    #[error("the request conflicts with current resource state: {0}")]
    Conflict(String),
    #[error("If-Match is required for this operation")]
    PreconditionRequired,
    #[error("the supplied revision no longer matches the resource")]
    PreconditionFailed,
    #[error("the idempotency key was already used with a different request")]
    IdempotencyConflict,
    #[error("the identity provider could not complete authentication")]
    IdentityProvider,
    #[error("too many authentication attempts")]
    RateLimited(u64),
    #[error("an internal operation failed")]
    Internal,
    #[error("the requested feature is not available yet")]
    NotImplemented,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProblemDetails {
    #[schema(example = "https://zeus.example.com/problems/validation_failed")]
    pub r#type: String,
    pub title: String,
    pub status: u16,
    pub code: String,
    pub detail: String,
    pub request_id: Uuid,
}

impl IntoResponse for ApiError {
    #[allow(clippy::too_many_lines)]
    fn into_response(self) -> axum::response::Response {
        let (status, code, title, retry_after) = match self {
            Self::DatabaseUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                "Database unavailable",
                None,
            ),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", "Not found", None),
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request", "Bad request", None),
            Self::Validation(_) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "validation_failed",
                "Validation failed",
                None,
            ),
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Authentication required",
                None,
            ),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden", "Access denied", None),
            Self::EmailVerificationRequired => (
                StatusCode::FORBIDDEN,
                "email_verification_required",
                "Email verification required",
                None,
            ),
            Self::MfaRequired => (
                StatusCode::FORBIDDEN,
                "mfa_required",
                "Multi-factor authentication required",
                None,
            ),
            Self::ReauthenticationRequired => (
                StatusCode::FORBIDDEN,
                "reauthentication_required",
                "Recent authentication required",
                None,
            ),
            Self::Conflict(_) => (StatusCode::CONFLICT, "conflict", "Conflict", None),
            Self::PreconditionRequired => (
                StatusCode::PRECONDITION_REQUIRED,
                "precondition_required",
                "Precondition required",
                None,
            ),
            Self::PreconditionFailed => (
                StatusCode::PRECONDITION_FAILED,
                "precondition_failed",
                "Precondition failed",
                None,
            ),
            Self::IdempotencyConflict => (
                StatusCode::CONFLICT,
                "idempotency_conflict",
                "Idempotency conflict",
                None,
            ),
            Self::IdentityProvider => (
                StatusCode::BAD_GATEWAY,
                "identity_provider_error",
                "Identity provider error",
                None,
            ),
            Self::RateLimited(seconds) => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "Too many requests",
                Some(seconds),
            ),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Internal error",
                None,
            ),
            Self::NotImplemented => (
                StatusCode::NOT_IMPLEMENTED,
                "feature_not_available",
                "Feature not available",
                None,
            ),
        };
        let body = ProblemDetails {
            r#type: format!("https://zeus.example.com/problems/{code}"),
            title: title.to_owned(),
            status: status.as_u16(),
            code: code.to_owned(),
            detail: self.to_string(),
            request_id: current_request_id(),
        };
        let mut response = (
            status,
            [(http::header::CONTENT_TYPE, "application/problem+json")],
            Json(body),
        )
            .into_response();
        if let Some(seconds) = retry_after
            && let Ok(value) = http::HeaderValue::from_str(&seconds.to_string())
        {
            response
                .headers_mut()
                .insert(http::header::RETRY_AFTER, value);
        }
        response
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        if matches!(error, sqlx::Error::RowNotFound) {
            return Self::NotFound;
        }
        if let Some(database_error) = error.as_database_error() {
            return match database_error.code().as_deref() {
                Some("23505") => Self::Conflict("resource already exists".to_owned()),
                Some("23503") => Self::Validation("referenced resource does not exist".to_owned()),
                Some("23514" | "22023") => {
                    Self::Validation("database constraint rejected the request".to_owned())
                }
                Some("42501") => Self::Forbidden,
                _ => Self::Internal,
            };
        }
        Self::Internal
    }
}
