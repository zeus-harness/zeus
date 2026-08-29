use axum::http::HeaderMap;
use serde::Serialize;
use serde_json::Value;
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    auth::{AuthContext, PrincipalKind},
    crypto::sha256,
    error::ApiError,
};

#[derive(Clone, Debug)]
pub struct IdempotencyReservation {
    pub id: Uuid,
    request_hash: Vec<u8>,
}

#[derive(Clone, Debug)]
pub enum IdempotencyDecision {
    New(IdempotencyReservation),
    Replay { status: u16, body: Value },
}

#[derive(Debug, FromRow)]
struct ReservationRow {
    id: Uuid,
    status: String,
    request_hash: Vec<u8>,
    response_status: Option<i32>,
    response_body: Option<Value>,
    replayed: bool,
}

/// Reserves a required `Idempotency-Key` inside the caller's tenant transaction.
///
/// # Errors
///
/// Returns a stable conflict for key reuse with another payload or a request still in progress.
pub async fn begin<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    auth: &AuthContext,
    workspace_id: Uuid,
    method: &str,
    path: &str,
    headers: &HeaderMap,
    request: &T,
) -> Result<IdempotencyDecision, ApiError> {
    let key = required_key(headers)?;
    let request_bytes = serde_json::to_vec(request).map_err(|_| ApiError::Internal)?;
    let request_hash = sha256(&request_bytes);
    let actor_kind = match auth.principal_kind {
        PrincipalKind::User => "user",
        PrincipalKind::ServiceAccount => "service_account",
    };
    let row = sqlx::query_as::<_, ReservationRow>(
        "select * from zeus_private.begin_http_idempotency(
            $1, $2, $3, $4, $5, $6, $7, $8, 86400
         )",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(actor_kind)
    .bind(auth.principal_id)
    .bind(method)
    .bind(path)
    .bind(key)
    .bind(&request_hash)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_begin_error)?;

    if row.request_hash != request_hash {
        return Err(ApiError::IdempotencyConflict);
    }

    if !row.replayed {
        return Ok(IdempotencyDecision::New(IdempotencyReservation {
            id: row.id,
            request_hash,
        }));
    }
    match row.status.as_str() {
        "completed" | "failed" => {
            let status = row
                .response_status
                .and_then(|status| u16::try_from(status).ok())
                .ok_or(ApiError::Internal)?;
            Ok(IdempotencyDecision::Replay {
                status,
                body: row.response_body.unwrap_or(Value::Null),
            })
        }
        "in_progress" => Err(ApiError::Conflict(
            "an equivalent request is still in progress".to_owned(),
        )),
        _ => Err(ApiError::Internal),
    }
}

/// Stores the exact JSON response for future idempotent replay.
///
/// # Errors
///
/// Returns an internal error when the reservation was lost or changed.
pub async fn complete<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    reservation: &IdempotencyReservation,
    status: u16,
    body: &T,
) -> Result<(), ApiError> {
    let body = serde_json::to_value(body).map_err(|_| ApiError::Internal)?;
    let completed: bool = sqlx::query_scalar(
        "select zeus_private.complete_http_idempotency($1, $2, 'completed', $3, $4)",
    )
    .bind(reservation.id)
    .bind(&reservation.request_hash)
    .bind(i32::from(status))
    .bind(body)
    .fetch_one(&mut **transaction)
    .await?;
    if !completed {
        return Err(ApiError::Internal);
    }
    Ok(())
}

fn required_key(headers: &HeaderMap) -> Result<&str, ApiError> {
    let value = headers
        .get("idempotency-key")
        .ok_or_else(|| ApiError::BadRequest("Idempotency-Key is required".to_owned()))?
        .to_str()
        .map_err(|_| ApiError::BadRequest("Idempotency-Key is malformed".to_owned()))?;
    if value.trim() != value || value.is_empty() || value.len() > 255 {
        return Err(ApiError::BadRequest(
            "Idempotency-Key must contain 1-255 visible characters".to_owned(),
        ));
    }
    Ok(value)
}

fn map_begin_error(error: sqlx::Error) -> ApiError {
    if error
        .as_database_error()
        .is_some_and(|database_error| database_error.code().as_deref() == Some("22023"))
    {
        ApiError::IdempotencyConflict
    } else {
        error.into()
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};

    use super::required_key;

    #[test]
    fn idempotency_key_is_required_and_bounded() {
        assert!(required_key(&HeaderMap::new()).is_err());
        let mut headers = HeaderMap::new();
        headers.insert("idempotency-key", HeaderValue::from_static("request-1"));
        assert_eq!(required_key(&headers).unwrap(), "request-1");
    }
}
