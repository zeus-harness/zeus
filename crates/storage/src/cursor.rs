use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::StorageError;

const CURSOR_VERSION: u8 = 2;
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
    account_id: &str,
    actor_user_id: &str,
    first: &str,
    second: &str,
) -> Result<String, StorageError> {
    encode_scoped_text_key(
        SESSION_LIST_KIND,
        account_id,
        actor_user_id,
        "collection",
        first,
        second,
    )
}

pub(crate) fn decode_session_list(
    value: &str,
    account_id: &str,
    actor_user_id: &str,
) -> Result<TextKeyCursor, StorageError> {
    decode_text_key(
        value,
        SESSION_LIST_KIND,
        account_id,
        actor_user_id,
        "collection",
    )
}

pub(crate) fn encode_session_run_ids(
    account_id: &str,
    actor_user_id: &str,
    session_id: &str,
    first: &str,
    second: &str,
) -> Result<String, StorageError> {
    encode_scoped_text_key(
        SESSION_RUN_IDS_KIND,
        account_id,
        actor_user_id,
        session_id,
        first,
        second,
    )
}

pub(crate) fn decode_session_run_ids(
    value: &str,
    account_id: &str,
    actor_user_id: &str,
    session_id: &str,
) -> Result<TextKeyCursor, StorageError> {
    decode_text_key(
        value,
        SESSION_RUN_IDS_KIND,
        account_id,
        actor_user_id,
        session_id,
    )
}

pub(crate) fn encode_session_turns(
    account_id: &str,
    actor_user_id: &str,
    session_id: &str,
    position: u64,
) -> Result<String, StorageError> {
    encode_scoped_position(
        SESSION_TURNS_KIND,
        account_id,
        actor_user_id,
        session_id,
        position,
    )
}

pub(crate) fn decode_session_turns(
    value: &str,
    account_id: &str,
    actor_user_id: &str,
    session_id: &str,
) -> Result<u64, StorageError> {
    decode_position(
        value,
        SESSION_TURNS_KIND,
        account_id,
        actor_user_id,
        session_id,
    )
}

pub(crate) fn encode_session_events(
    account_id: &str,
    actor_user_id: &str,
    session_id: &str,
    position: u64,
) -> Result<String, StorageError> {
    encode_scoped_position(
        SESSION_EVENTS_KIND,
        account_id,
        actor_user_id,
        session_id,
        position,
    )
}

pub(crate) fn decode_session_events(
    value: &str,
    account_id: &str,
    actor_user_id: &str,
    session_id: &str,
) -> Result<u64, StorageError> {
    decode_position(
        value,
        SESSION_EVENTS_KIND,
        account_id,
        actor_user_id,
        session_id,
    )
}

pub(crate) fn encode_run_events(
    account_id: &str,
    actor_user_id: &str,
    run_id: &str,
    position: u64,
) -> Result<String, StorageError> {
    encode_scoped_position(RUN_EVENTS_KIND, account_id, actor_user_id, run_id, position)
}

pub(crate) fn decode_run_events(
    value: &str,
    account_id: &str,
    actor_user_id: &str,
    run_id: &str,
) -> Result<u64, StorageError> {
    decode_position(value, RUN_EVENTS_KIND, account_id, actor_user_id, run_id)
}

fn encode_scoped_text_key(
    kind: &str,
    account_id: &str,
    actor_user_id: &str,
    parent_scope: &str,
    first: &str,
    second: &str,
) -> Result<String, StorageError> {
    encode(CursorEnvelope {
        v: CURSOR_VERSION,
        kind: kind.into(),
        scope: Some(scope_digest(kind, account_id, actor_user_id, parent_scope)),
        first: Some(first.into()),
        second: Some(second.into()),
        position: None,
    })
}

fn encode_scoped_position(
    kind: &str,
    account_id: &str,
    actor_user_id: &str,
    parent_scope: &str,
    position: u64,
) -> Result<String, StorageError> {
    encode(CursorEnvelope {
        v: CURSOR_VERSION,
        kind: kind.into(),
        scope: Some(scope_digest(kind, account_id, actor_user_id, parent_scope)),
        first: None,
        second: None,
        position: Some(position),
    })
}

fn decode_text_key(
    value: &str,
    expected_kind: &str,
    account_id: &str,
    actor_user_id: &str,
    parent_scope: &str,
) -> Result<TextKeyCursor, StorageError> {
    let envelope = decode(value)?;
    require_envelope(
        &envelope,
        expected_kind,
        account_id,
        actor_user_id,
        parent_scope,
    )?;
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
    account_id: &str,
    actor_user_id: &str,
    parent_scope: &str,
) -> Result<u64, StorageError> {
    let envelope = decode(value)?;
    require_envelope(
        &envelope,
        expected_kind,
        account_id,
        actor_user_id,
        parent_scope,
    )?;
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
    account_id: &str,
    actor_user_id: &str,
    parent_scope: &str,
) -> Result<(), StorageError> {
    if envelope.v != CURSOR_VERSION || envelope.kind != expected_kind {
        return Err(StorageError::InvalidPageCursor);
    }
    let expected_scope = Some(scope_digest(
        expected_kind,
        account_id,
        actor_user_id,
        parent_scope,
    ));
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

fn scope_digest(kind: &str, account_id: &str, actor_user_id: &str, parent_scope: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"zeus.cursor.v2\0");
    for component in [account_id, actor_user_id, kind, parent_scope] {
        hasher.update((component.len() as u64).to_be_bytes());
        hasher.update(component.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_scope_digest_uses_account_actor_kind_parent_order() {
        assert_eq!(
            scope_digest("run_events", "acc-a", "actor-a", "run-a"),
            "c87ca7bcba7e57c6511c1394e5dc239c0690495044651acd7c4456c3364d6023"
        );
    }

    #[test]
    fn v2_cursors_are_canonical_scoped_and_preserve_oversized_ids() {
        let oversized = "s".repeat(protocol::RESOURCE_ID_MAX_BYTES + 1);
        let cursor = encode_session_run_ids(
            "acc-a",
            "actor-a",
            &oversized,
            "2026-01-01T00:00:00Z",
            &oversized,
        )
        .unwrap();
        assert_eq!(
            decode_session_run_ids(&cursor, "acc-a", "actor-a", &oversized).unwrap(),
            TextKeyCursor {
                first: "2026-01-01T00:00:00Z".into(),
                second: oversized.clone(),
            }
        );
        assert!(decode_session_run_ids(&cursor, "acc-a", "actor-a", "different-session").is_err());
        assert!(decode_session_run_ids(&(cursor + "="), "acc-a", "actor-a", &oversized).is_err());

        let list_cursor =
            encode_session_list("acc-a", "actor-a", "2026-01-01T00:00:00Z", "session").unwrap();
        assert!(decode_session_list(&list_cursor, "acc-a", "actor-b").is_err());
        assert!(decode_session_list(&list_cursor, "acc-b", "actor-a").is_err());
        assert!(decode_session_list(&(list_cursor + "="), "acc-a", "actor-a").is_err());
    }

    #[test]
    fn cursor_kind_account_actor_and_parent_are_not_interchangeable() {
        let cursor = encode_session_turns("acc-a", "actor-a", "session-a", 9).unwrap();
        assert_eq!(
            decode_session_turns(&cursor, "acc-a", "actor-a", "session-a").unwrap(),
            9
        );
        assert!(decode_session_events(&cursor, "acc-a", "actor-a", "session-a").is_err());
        assert!(decode_session_turns(&cursor, "acc-b", "actor-a", "session-a").is_err());
        assert!(decode_session_turns(&cursor, "acc-a", "actor-b", "session-a").is_err());
        assert!(decode_session_turns(&cursor, "acc-a", "actor-a", "session-b").is_err());
        assert!(decode_session_list(&cursor, "acc-a", "actor-a").is_err());
    }

    #[test]
    fn same_actor_cursor_survives_auth_session_rotation_and_revision_change() {
        let cursor = encode_run_events("acc-a", "actor-a", "run-a", 11).unwrap();

        // Authentication-session identity and membership revision are
        // deliberately absent from the v2 scope tuple. A refreshed login for
        // the same account actor can resume the same resource cursor.
        assert_eq!(
            decode_run_events(&cursor, "acc-a", "actor-a", "run-a").unwrap(),
            11
        );
    }

    #[test]
    fn one_actor_cannot_reuse_a_cursor_for_a_new_parent_session_or_run() {
        let session_cursor = encode_session_events("acc-a", "actor-a", "session-old", 7).unwrap();
        assert!(decode_session_events(&session_cursor, "acc-a", "actor-a", "session-new").is_err());

        let run_cursor = encode_run_events("acc-a", "actor-a", "run-old", 11).unwrap();
        assert!(decode_run_events(&run_cursor, "acc-a", "actor-a", "run-new").is_err());
        assert!(decode_run_events(&run_cursor, "acc-a", "actor-b", "run-old").is_err());
    }

    #[test]
    fn legacy_v1_cursors_fail_closed() {
        let legacy_scope = Sha256::digest(b"session-a")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let legacy = encode(CursorEnvelope {
            v: 1,
            kind: SESSION_TURNS_KIND.into(),
            scope: Some(legacy_scope),
            first: None,
            second: None,
            position: Some(9),
        })
        .unwrap();

        assert!(decode_session_turns(&legacy, "acc-a", "actor-a", "session-a").is_err());
    }
}
