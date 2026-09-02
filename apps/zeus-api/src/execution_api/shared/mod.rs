pub(super) mod types;

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::Value;

use crate::{
    auth::{AuthContext, PrincipalKind},
    error::ApiError,
};

pub(super) fn actor_kind(auth: &AuthContext) -> &'static str {
    match auth.principal_kind {
        PrincipalKind::User => "user",
        PrincipalKind::ServiceAccount => "service_account",
    }
}

pub(super) fn json_response(status: u16, body: Value) -> Result<Response, ApiError> {
    let status = StatusCode::from_u16(status).map_err(|_| ApiError::Internal)?;
    Ok((status, Json(body)).into_response())
}
