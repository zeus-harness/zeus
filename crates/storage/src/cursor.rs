use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::StorageError;

const CURSOR_VERSION: u8 = 1;
const CURSOR_MAX_BYTES: usize = 64 * 1024;

const SESSION_LIST_KIND: &str = "session_list";
const SESSION_RUN_IDS_KIND: &str = "session_run_ids";
const SESSION_TURNS_KIND: &str = "session_turns";
const SESSION_EVENTS_KIND: &str = "session_events";
const RUN_EVENTS_KIND: &str = "run_events";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorEnvelope {
    v: u8,
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    first: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    second: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    position: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TextKeyCursor {
    pub first: String,
    pub second: String,
}

pub(crate) fn encode_session_list(
    actor_user_id: &str,
    first: &str,
    second: &str,
) -> Result<String, StorageError> {
    encode_scoped_text_key(SESSION_LIST_KIND, actor_user_id, first, second)
}

pub(crate) fn decode_session_list(
    value: &str,
    actor_user_id: &str,
) -> Result<TextKeyCursor, StorageError> {
    decode_text_key(value, SESSION_LIST_KIND, Some(actor_user_id))
}

pub(crate) fn encode_session_run_ids(
    session_id: &str,
    first: &str,
    second: &str,
) -> Result<String, StorageError> {
    encode_scoped_text_key(SESSION_RUN_IDS_KIND, session_id, first, second)
}

pub(crate) fn decode_session_run_ids(
    value: &str,
    session_id: &str,
) -> Result<TextKeyCursor, StorageError> {
    decode_text_key(value, SESSION_RUN_IDS_KIND, Some(session_id))
}

pub(crate) fn encode_session_turns(
    session_id: &str,
    position: u64,
) -> Result<String, StorageError> {
    encode_scoped_position(SESSION_TURNS_KIND, session_id, position)
}

pub(crate) fn decode_session_turns(value: &str, session_id: &str) -> Result<u64, StorageError> {
    decode_position(value, SESSION_TURNS_KIND, session_id)
}

pub(crate) fn encode_session_events(
    session_id: &str,
    position: u64,
) -> Result<String, StorageError> {
    encode_scoped_position(SESSION_EVENTS_KIND, session_id, position)
}

pub(crate) fn decode_session_events(value: &str, session_id: &str) -> Result<u64, StorageError> {
    decode_position(value, SESSION_EVENTS_KIND, session_id)
}

pub(crate) fn encode_run_events(run_id: &str, position: u64) -> Result<String, StorageError> {
    encode_scoped_position(RUN_EVENTS_KIND, run_id, position)
}

pub(crate) fn decode_run_events(value: &str, run_id: &str) -> Result<u64, StorageError> {
    decode_position(value, RUN_EVENTS_KIND, run_id)
}

fn encode_scoped_text_key(
    kind: &str,
    resource_id: &str,
    first: &str,
    second: &str,
) -> Result<String, StorageError> {
    encode(CursorEnvelope {
        v: CURSOR_VERSION,
        kind: kind.into(),
        scope: Some(scope_digest(resource_id)),
        first: Some(first.into()),
        second: Some(second.into()),
        position: None,
    })
}

fn encode_scoped_position(
    kind: &str,
    resource_id: &str,
    position: u64,
) -> Result<String, StorageError> {
    encode(CursorEnvelope {
        v: CURSOR_VERSION,
        kind: kind.into(),
        scope: Some(scope_digest(resource_id)),
        first: None,
        second: None,
        position: Some(position),
    })
}

fn decode_text_key(
    value: &str,
    expected_kind: &str,
    resource_id: Option<&str>,
) -> Result<TextKeyCursor, StorageError> {
    let envelope = decode(value)?;
    require_envelope(&envelope, expected_kind, resource_id)?;
    if envelope.position.is_some() {
        return Err(StorageError::InvalidPageCursor);
    }
    let first = envelope.first.ok_or(StorageError::InvalidPageCursor)?;
    let second = envelope.second.ok_or(StorageError::InvalidPageCursor)?;
    require_canonical_text(&first)?;
    require_canonical_text(&second)?;
    Ok(TextKeyCursor { first, second })
}

fn decode_position(
    value: &str,
    expected_kind: &str,
    resource_id: &str,
) -> Result<u64, StorageError> {
    let envelope = decode(value)?;
    require_envelope(&envelope, expected_kind, Some(resource_id))?;
    if envelope.first.is_some() || envelope.second.is_some() {
        return Err(StorageError::InvalidPageCursor);
    }
    let position = envelope.position.ok_or(StorageError::InvalidPageCursor)?;
    if position == 0 || position > i64::MAX as u64 {
        return Err(StorageError::InvalidPageCursor);
    }
    Ok(position)
}

fn require_envelope(
    envelope: &CursorEnvelope,
    expected_kind: &str,
    resource_id: Option<&str>,
) -> Result<(), StorageError> {
    if envelope.v != CURSOR_VERSION || envelope.kind != expected_kind {
        return Err(StorageError::InvalidPageCursor);
    }
    let expected_scope = resource_id.map(scope_digest);
    if envelope.scope != expected_scope {
        return Err(StorageError::InvalidPageCursor);
    }
    Ok(())
}

fn require_canonical_text(value: &str) -> Result<(), StorageError> {
    if value.is_empty() || value.trim() != value {
        Err(StorageError::InvalidPageCursor)
    } else {
        Ok(())
    }
}

fn encode(envelope: CursorEnvelope) -> Result<String, StorageError> {
    let json = serde_json::to_vec(&envelope).map_err(|_| StorageError::InvalidPageCursor)?;
    let encoded = URL_SAFE_NO_PAD.encode(json);
    if encoded.len() > CURSOR_MAX_BYTES {
        return Err(StorageError::InvalidPageCursor);
    }
    Ok(encoded)
}

fn decode(value: &str) -> Result<CursorEnvelope, StorageError> {
    if value.is_empty() || value.len() > CURSOR_MAX_BYTES {
        return Err(StorageError::InvalidPageCursor);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| StorageError::InvalidPageCursor)?;
    let envelope: CursorEnvelope =
        serde_json::from_slice(&decoded).map_err(|_| StorageError::InvalidPageCursor)?;
    let canonical = encode(CursorEnvelope {
        v: envelope.v,
        kind: envelope.kind.clone(),
        scope: envelope.scope.clone(),
        first: envelope.first.clone(),
        second: envelope.second.clone(),
        position: envelope.position,
    })?;
    if canonical != value {
        return Err(StorageError::InvalidPageCursor);
    }
    Ok(envelope)
}

fn scope_digest(resource_id: &str) -> String {
    let digest = Sha256::digest(resource_id.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursors_are_canonical_scoped_and_preserve_oversized_ids() {
        let oversized = "s".repeat(protocol::RESOURCE_ID_MAX_BYTES + 1);
        let cursor =
            encode_session_run_ids(&oversized, "2026-01-01T00:00:00Z", &oversized).unwrap();
        assert_eq!(
            decode_session_run_ids(&cursor, &oversized).unwrap(),
            TextKeyCursor {
                first: "2026-01-01T00:00:00Z".into(),
                second: oversized.clone(),
            }
        );
        assert!(decode_session_run_ids(&cursor, "different").is_err());
        assert!(decode_session_run_ids(&(cursor + "="), &oversized).is_err());

        let list_cursor =
            encode_session_list("actor-a", "2026-01-01T00:00:00Z", "session").unwrap();
        assert!(decode_session_list(&list_cursor, "actor-b").is_err());
        assert!(decode_session_list(&(list_cursor + "="), "actor-a").is_err());
    }

    #[test]
    fn cursor_kind_and_position_are_not_interchangeable() {
        let cursor = encode_session_turns("session", 9).unwrap();
        assert_eq!(decode_session_turns(&cursor, "session").unwrap(), 9);
        assert!(decode_session_events(&cursor, "session").is_err());
        assert!(decode_session_list(&cursor, "actor-a").is_err());
    }
}
