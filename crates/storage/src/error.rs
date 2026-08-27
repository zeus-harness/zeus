use thiserror::Error;

use crate::{SqliteOperationLimitsError, SqlitePhysicalLimitsError, StorageLimitsError};

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SQLite error: {0}")]
    Sqlite(rusqlite::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("blocking storage task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("invalid storage limits: {0}")]
    InvalidLimits(#[from] StorageLimitsError),
    #[error("invalid SQLite physical limits: {0}")]
    InvalidPhysicalLimits(#[from] SqlitePhysicalLimitsError),
    #[error("invalid SQLite operation limits: {0}")]
    InvalidOperationLimits(#[from] SqliteOperationLimitsError),
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
    #[error("the local owner account is already configured")]
    AccountAlreadyConfigured,
    #[error("the bootstrap credential is invalid, expired, or already used")]
    InvalidBootstrapToken,
    #[error("user `{0}` was not found")]
    UserNotFound(String),
    #[error("user `{0}` is disabled")]
    UserDisabled(String),
    #[error("the authentication session was not found or has expired")]
    AuthSessionNotFound,
    #[error("the current account membership lacks the required capability")]
    PermissionDenied,
    #[error("account member `{0}` was not found")]
    MemberNotFound(String),
    #[error("account member `{0}` already exists")]
    MemberAlreadyExists(String),
    #[error("the account membership revision changed concurrently")]
    MembershipRevisionConflict,
    #[error("an account must retain at least one active owner")]
    LastAccountOwner,
    #[error("the member setup credential is invalid or already used")]
    InvalidMemberSetupToken,
    #[error("the member setup credential has expired")]
    MemberSetupExpired,
    #[error("member setup is already complete")]
    MemberSetupAlreadyCompleted,
    #[error("the account security audit has exhausted its bounded local capacity")]
    AuditStorageExhausted,
    #[error("account audit detail compaction is blocked by legal hold")]
    AuditLegalHold,
    #[error("account audit detail compaction requires an archive checkpoint")]
    AuditArchiveRequired,
    #[error("the account audit policy changed concurrently")]
    AuditPolicyConflict,
    #[error("the account audit archive checkpoint changed concurrently or is invalid")]
    AuditCheckpointConflict,
    #[error(
        "account audit policy for `{account_id}` retains {detail_rows} detail rows, above the configured limit {configured_limit}"
    )]
    AccountAuditPolicyExceedsConfiguredLimit {
        account_id: String,
        detail_rows: i64,
        configured_limit: i64,
    },
    #[error("the durable storage quota is exhausted")]
    StorageQuotaExceeded,
    #[error("SQLite physical storage cannot safely accept this operation")]
    PhysicalStorageExhausted,
    #[error("SQLite operation capacity is exhausted")]
    OperationCapacityExceeded,
    #[error("the durable reply queue is at capacity")]
    ReplyQueueCapacityExceeded,
    #[error("the durable dispatch queue is at capacity")]
    DispatchQueueCapacityExceeded,
    #[error("the authentication session store is at capacity")]
    AuthSessionCapacityExceeded,
    #[error("the durable finalization reservation is missing or inconsistent")]
    FinalizationReservationUnavailable,
    #[error("invalid account data: {0}")]
    InvalidAccountData(String),
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
    #[error("reply job `{0}` was not found")]
    ReplyJobNotFound(String),
    #[error("invalid dispatch state transition: {0}")]
    InvalidDispatchTransition(String),
    #[error("invalid reply state transition: {0}")]
    InvalidReplyTransition(String),
    #[error("invalid session state transition: {0}")]
    InvalidSessionTransition(String),
    #[error("invalid API resource envelope: {0}")]
    InvalidResourceEnvelope(String),
    #[error("event page limit {limit} is invalid; expected 1..={max}")]
    InvalidEventPageLimit { limit: usize, max: usize },
    #[error("read page limit {limit} is invalid; expected 1..={max}")]
    InvalidPageLimit { limit: usize, max: usize },
    #[error("read page cursor is invalid")]
    InvalidPageCursor,
    #[error("read page cursor is ahead of the durable collection head {head}")]
    PageCursorBeyondHead { head: u64 },
    #[error("event cursor {after} cannot be represented by SQLite")]
    EventCursorOutOfRange { after: u64 },
    #[error("event cursor {after} is ahead of durable ledger head {head_sequence}")]
    EventCursorBeyondHead { after: u64, head_sequence: u64 },
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

impl From<rusqlite::Error> for StorageError {
    fn from(error: rusqlite::Error) -> Self {
        if error.sqlite_error_code() == Some(rusqlite::ErrorCode::DiskFull) {
            Self::PhysicalStorageExhausted
        } else {
            Self::Sqlite(error)
        }
    }
}
