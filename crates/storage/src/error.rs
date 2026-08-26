use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("blocking storage task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("persistent SQLite database `{0}` is already owned by another Zeus instance")]
    DatabaseLocked(String),
    #[error("run `{0}` was not found")]
    RunNotFound(String),
    #[error("session `{0}` was not found")]
    SessionNotFound(String),
    #[error("session turn `{0}` was not found")]
    SessionTurnNotFound(String),
    #[error("session `{0}` already exists")]
    SessionAlreadyExists(String),
    #[error("run `{run_id}` already belongs to session `{session_id}`")]
    RunAlreadyAttached { run_id: String, session_id: String },
    #[error("the idempotency key is empty")]
    EmptyIdempotencyKey,
    #[error("the idempotency key was already used with different command input")]
    IdempotencyConflict,
    #[error("the durable projection changed concurrently")]
    ConcurrentModification,
    #[error("dispatch job `{0}` was not found")]
    DispatchJobNotFound(String),
    #[error("invalid dispatch state transition: {0}")]
    InvalidDispatchTransition(String),
    #[error("invalid session state transition: {0}")]
    InvalidSessionTransition(String),
    #[error("unsupported schema version {found}; this binary supports up to {supported}")]
    UnsupportedSchemaVersion { found: i64, supported: i64 },
    #[error("unsupported event kind `{0}`")]
    UnsupportedEventKind(String),
    #[error("unsupported payload version {version} for event kind `{event_kind}`")]
    UnsupportedPayloadVersion { event_kind: String, version: i64 },
    #[error("stored data is inconsistent: {0}")]
    CorruptData(String),
    #[error("runtime identity mismatch: expected {expected}; stored database is bound to {found}")]
    RuntimeIdentityMismatch { expected: String, found: String },
    #[error("a protocol integer cannot be represented by SQLite: {0}")]
    IntegerOutOfRange(&'static str),
    #[cfg(test)]
    #[error("injected storage transaction failure")]
    InjectedFailure,
}
