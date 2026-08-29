use axum::http::{HeaderMap, HeaderValue, header};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::ApiError;

pub const DEFAULT_PAGE_SIZE: u16 = 50;
pub const MAX_PAGE_SIZE: u16 = 100;

#[derive(Clone, Debug, Default, Deserialize)]
pub struct PageQuery {
    pub cursor: Option<String>,
    pub limit: Option<u16>,
}

impl PageQuery {
    /// Returns a bounded list limit.
    ///
    /// # Errors
    ///
    /// Returns a validation error when the caller requests zero or more than 100 rows.
    pub fn limit(&self) -> Result<i64, ApiError> {
        let limit = self.limit.unwrap_or(DEFAULT_PAGE_SIZE);
        if !(1..=MAX_PAGE_SIZE).contains(&limit) {
            return Err(ApiError::Validation(format!(
                "limit must be between 1 and {MAX_PAGE_SIZE}"
            )));
        }
        Ok(i64::from(limit))
    }

    /// Decodes the opaque keyset cursor.
    ///
    /// # Errors
    ///
    /// Returns a bad-request error for malformed or unsupported cursors.
    pub fn decoded_cursor(&self) -> Result<Option<ListCursor>, ApiError> {
        self.cursor.as_deref().map(ListCursor::decode).transpose()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListCursor {
    version: u8,
    created_at: OffsetDateTime,
    id: Uuid,
}

impl ListCursor {
    #[must_use]
    pub const fn new(created_at: OffsetDateTime, id: Uuid) -> Self {
        Self {
            version: 1,
            created_at,
            id,
        }
    }

    #[must_use]
    pub const fn created_at(self) -> OffsetDateTime {
        self.created_at
    }

    #[must_use]
    pub const fn id(self) -> Uuid {
        self.id
    }

    /// Encodes a cursor that clients must treat as opaque.
    ///
    /// # Errors
    ///
    /// Returns an internal error only when the fixed cursor shape cannot be serialized.
    pub fn encode(self) -> Result<String, ApiError> {
        let bytes = serde_json::to_vec(&self).map_err(|_| ApiError::Internal)?;
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    fn decode(value: &str) -> Result<Self, ApiError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| ApiError::BadRequest("cursor is malformed".to_owned()))?;
        let cursor: Self = serde_json::from_slice(&bytes)
            .map_err(|_| ApiError::BadRequest("cursor is malformed".to_owned()))?;
        if cursor.version != 1 {
            return Err(ApiError::BadRequest(
                "cursor version is unsupported".to_owned(),
            ));
        }
        Ok(cursor)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

/// Parses a required strong `ETag` of the form `"revision-N"`.
///
/// # Errors
///
/// Returns `428` when the header is missing and `400` when it is malformed.
pub fn required_revision(headers: &HeaderMap) -> Result<i64, ApiError> {
    let value = headers
        .get(header::IF_MATCH)
        .ok_or(ApiError::PreconditionRequired)?
        .to_str()
        .map_err(|_| ApiError::BadRequest("If-Match is malformed".to_owned()))?;
    parse_revision_etag(value)
}

/// Builds the response `ETag` for one mutable resource revision.
///
/// # Errors
///
/// Returns an internal error if a generated header value is invalid.
pub fn revision_etag(revision: i64) -> Result<HeaderValue, ApiError> {
    HeaderValue::from_str(&format!("\"revision-{revision}\"")).map_err(|_| ApiError::Internal)
}

fn parse_revision_etag(value: &str) -> Result<i64, ApiError> {
    let inner = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .and_then(|value| value.strip_prefix("revision-"))
        .ok_or_else(|| ApiError::BadRequest("If-Match is malformed".to_owned()))?;
    let revision = inner
        .parse::<i64>()
        .map_err(|_| ApiError::BadRequest("If-Match is malformed".to_owned()))?;
    if revision <= 0 {
        return Err(ApiError::BadRequest("If-Match is malformed".to_owned()));
    }
    Ok(revision)
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, header};
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::{ListCursor, required_revision};

    #[test]
    fn opaque_cursor_round_trips_keyset_values() {
        let cursor = ListCursor::new(OffsetDateTime::now_utc(), Uuid::now_v7());
        let encoded = cursor.encode().expect("cursor encodes");
        assert_eq!(
            ListCursor::decode(&encoded).expect("cursor decodes"),
            cursor
        );
    }

    #[test]
    fn if_match_requires_the_exact_revision_shape() {
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_MATCH, HeaderValue::from_static("\"revision-7\""));
        assert_eq!(required_revision(&headers).unwrap(), 7);
        headers.insert(
            header::IF_MATCH,
            HeaderValue::from_static("W/\"revision-7\""),
        );
        assert!(required_revision(&headers).is_err());
    }
}
