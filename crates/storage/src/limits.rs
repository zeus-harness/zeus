//! Validated logical capacity limits for the Alpha SQLite store.
//!
//! These limits bound durable row counts, active work, event slots, and the
//! logical UTF-8 byte length of serialized event payloads. Slot and payload-byte
//! limits apply to the durable ledger plus every outstanding finalization
//! reservation, so callers cannot consume the terminal-event capacity needed by
//! work that is already in flight.
//!
//! Logical event-payload bytes do not represent SQLite database-file, WAL,
//! index, page-overhead, or free-disk usage.

use thiserror::Error;

pub const DEFAULT_SESSIONS_PER_ACTOR: usize = 1_000;
pub const DEFAULT_SESSIONS_PER_ACCOUNT: usize = 10_000;
pub const DEFAULT_SESSIONS_GLOBAL: usize = 10_000;
pub const DEFAULT_OPEN_TURNS_PER_ACTOR: usize = 32;
pub const DEFAULT_OPEN_TURNS_PER_ACCOUNT: usize = 64;
pub const DEFAULT_OPEN_TURNS_GLOBAL: usize = 64;
pub const DEFAULT_ACTIVE_REPLY_JOBS_PER_ACTOR: usize = 32;
pub const DEFAULT_ACTIVE_REPLY_JOBS_PER_ACCOUNT: usize = 64;
pub const DEFAULT_ACTIVE_REPLY_JOBS_GLOBAL: usize = 64;
pub const DEFAULT_ACTIVE_DISPATCH_JOBS_PER_ACTOR: usize = 16;
pub const DEFAULT_ACTIVE_DISPATCH_JOBS_PER_ACCOUNT: usize = 32;
pub const DEFAULT_ACTIVE_DISPATCH_JOBS_GLOBAL: usize = 32;
pub const DEFAULT_AUTH_SESSIONS_PER_USER: usize = 32;
pub const DEFAULT_AUTH_SESSIONS_GLOBAL: usize = 256;
pub const DEFAULT_SESSION_EVENT_SLOTS_PER_SESSION: usize = 10_000;
pub const DEFAULT_RUN_EVENT_SLOTS_PER_RUN: usize = 50_000;
pub const DEFAULT_SESSION_EVENT_PAYLOAD_BYTES_PER_SESSION: usize = 64 * 1024 * 1024;
pub const DEFAULT_RUN_EVENT_PAYLOAD_BYTES_PER_RUN: usize = 256 * 1024 * 1024;
pub const DEFAULT_EVENT_PAYLOAD_BYTES_GLOBAL: usize = 1024 * 1024 * 1024;
pub const DEFAULT_BOOTSTRAP_AUDIT_ROWS: usize = 1_024;

pub const HARD_MAX_SESSIONS_PER_ACTOR: usize = 10_000;
pub const HARD_MAX_SESSIONS_PER_ACCOUNT: usize = 100_000;
pub const HARD_MAX_SESSIONS_GLOBAL: usize = 100_000;
pub const HARD_MAX_OPEN_TURNS_PER_ACTOR: usize = 128;
pub const HARD_MAX_OPEN_TURNS_PER_ACCOUNT: usize = 512;
pub const HARD_MAX_OPEN_TURNS_GLOBAL: usize = 512;
pub const HARD_MAX_ACTIVE_REPLY_JOBS_PER_ACTOR: usize = 128;
pub const HARD_MAX_ACTIVE_REPLY_JOBS_PER_ACCOUNT: usize = 512;
pub const HARD_MAX_ACTIVE_REPLY_JOBS_GLOBAL: usize = 512;
pub const HARD_MAX_ACTIVE_DISPATCH_JOBS_PER_ACTOR: usize = 64;
pub const HARD_MAX_ACTIVE_DISPATCH_JOBS_PER_ACCOUNT: usize = 256;
pub const HARD_MAX_ACTIVE_DISPATCH_JOBS_GLOBAL: usize = 256;
pub const HARD_MAX_AUTH_SESSIONS_PER_USER: usize = 128;
pub const HARD_MAX_AUTH_SESSIONS_GLOBAL: usize = 4_096;
pub const HARD_MAX_SESSION_EVENT_SLOTS_PER_SESSION: usize = 100_000;
pub const HARD_MAX_RUN_EVENT_SLOTS_PER_RUN: usize = 500_000;
pub const HARD_MAX_SESSION_EVENT_PAYLOAD_BYTES_PER_SESSION: usize = 256 * 1024 * 1024;
pub const HARD_MAX_RUN_EVENT_PAYLOAD_BYTES_PER_RUN: usize = 1024 * 1024 * 1024;
pub const HARD_MAX_EVENT_PAYLOAD_BYTES_GLOBAL: usize = 2 * 1024 * 1024 * 1024;
pub const HARD_MAX_BOOTSTRAP_AUDIT_ROWS: usize = 65_536;

/// Logical capacity limits enforced by the SQLite storage transaction layer.
///
/// Actor limits prevent one member from monopolizing an account; account
/// limits bound aggregate tenant usage; global limits protect the SQLite
/// process. Each narrower tier must fit within the next broader tier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageLimits {
    pub sessions_per_actor: usize,
    pub sessions_per_account: usize,
    pub sessions_global: usize,
    pub open_turns_per_actor: usize,
    pub open_turns_per_account: usize,
    pub open_turns_global: usize,
    pub active_reply_jobs_per_actor: usize,
    pub active_reply_jobs_per_account: usize,
    pub active_reply_jobs_global: usize,
    pub active_dispatch_jobs_per_actor: usize,
    pub active_dispatch_jobs_per_account: usize,
    pub active_dispatch_jobs_global: usize,
    pub auth_sessions_per_user: usize,
    pub auth_sessions_global: usize,
    /// Maximum durable Session event head plus outstanding reserved slots.
    pub session_event_slots_per_session: usize,
    /// Maximum durable Run event head plus outstanding reserved slots.
    pub run_event_slots_per_run: usize,
    /// Maximum serialized Session event payload bytes plus outstanding reserves.
    pub session_event_payload_bytes_per_session: usize,
    /// Maximum serialized Run event payload bytes plus outstanding reserves.
    pub run_event_payload_bytes_per_run: usize,
    /// Maximum serialized Session and Run event payload bytes plus all reserves.
    pub event_payload_bytes_global: usize,
    pub bootstrap_audit_rows: usize,
}

impl StorageLimits {
    /// The supported Alpha defaults.
    pub const ALPHA_DEFAULT: Self = Self {
        sessions_per_actor: DEFAULT_SESSIONS_PER_ACTOR,
        sessions_per_account: DEFAULT_SESSIONS_PER_ACCOUNT,
        sessions_global: DEFAULT_SESSIONS_GLOBAL,
        open_turns_per_actor: DEFAULT_OPEN_TURNS_PER_ACTOR,
        open_turns_per_account: DEFAULT_OPEN_TURNS_PER_ACCOUNT,
        open_turns_global: DEFAULT_OPEN_TURNS_GLOBAL,
        active_reply_jobs_per_actor: DEFAULT_ACTIVE_REPLY_JOBS_PER_ACTOR,
        active_reply_jobs_per_account: DEFAULT_ACTIVE_REPLY_JOBS_PER_ACCOUNT,
        active_reply_jobs_global: DEFAULT_ACTIVE_REPLY_JOBS_GLOBAL,
        active_dispatch_jobs_per_actor: DEFAULT_ACTIVE_DISPATCH_JOBS_PER_ACTOR,
        active_dispatch_jobs_per_account: DEFAULT_ACTIVE_DISPATCH_JOBS_PER_ACCOUNT,
        active_dispatch_jobs_global: DEFAULT_ACTIVE_DISPATCH_JOBS_GLOBAL,
        auth_sessions_per_user: DEFAULT_AUTH_SESSIONS_PER_USER,
        auth_sessions_global: DEFAULT_AUTH_SESSIONS_GLOBAL,
        session_event_slots_per_session: DEFAULT_SESSION_EVENT_SLOTS_PER_SESSION,
        run_event_slots_per_run: DEFAULT_RUN_EVENT_SLOTS_PER_RUN,
        session_event_payload_bytes_per_session: DEFAULT_SESSION_EVENT_PAYLOAD_BYTES_PER_SESSION,
        run_event_payload_bytes_per_run: DEFAULT_RUN_EVENT_PAYLOAD_BYTES_PER_RUN,
        event_payload_bytes_global: DEFAULT_EVENT_PAYLOAD_BYTES_GLOBAL,
        bootstrap_audit_rows: DEFAULT_BOOTSTRAP_AUDIT_ROWS,
    };

    /// Absolute ceilings accepted by this binary.
    ///
    /// This value is useful to configuration adapters that want to expose the
    /// supported range without duplicating storage policy.
    pub const HARD_CEILINGS: Self = Self {
        sessions_per_actor: HARD_MAX_SESSIONS_PER_ACTOR,
        sessions_per_account: HARD_MAX_SESSIONS_PER_ACCOUNT,
        sessions_global: HARD_MAX_SESSIONS_GLOBAL,
        open_turns_per_actor: HARD_MAX_OPEN_TURNS_PER_ACTOR,
        open_turns_per_account: HARD_MAX_OPEN_TURNS_PER_ACCOUNT,
        open_turns_global: HARD_MAX_OPEN_TURNS_GLOBAL,
        active_reply_jobs_per_actor: HARD_MAX_ACTIVE_REPLY_JOBS_PER_ACTOR,
        active_reply_jobs_per_account: HARD_MAX_ACTIVE_REPLY_JOBS_PER_ACCOUNT,
        active_reply_jobs_global: HARD_MAX_ACTIVE_REPLY_JOBS_GLOBAL,
        active_dispatch_jobs_per_actor: HARD_MAX_ACTIVE_DISPATCH_JOBS_PER_ACTOR,
        active_dispatch_jobs_per_account: HARD_MAX_ACTIVE_DISPATCH_JOBS_PER_ACCOUNT,
        active_dispatch_jobs_global: HARD_MAX_ACTIVE_DISPATCH_JOBS_GLOBAL,
        auth_sessions_per_user: HARD_MAX_AUTH_SESSIONS_PER_USER,
        auth_sessions_global: HARD_MAX_AUTH_SESSIONS_GLOBAL,
        session_event_slots_per_session: HARD_MAX_SESSION_EVENT_SLOTS_PER_SESSION,
        run_event_slots_per_run: HARD_MAX_RUN_EVENT_SLOTS_PER_RUN,
        session_event_payload_bytes_per_session: HARD_MAX_SESSION_EVENT_PAYLOAD_BYTES_PER_SESSION,
        run_event_payload_bytes_per_run: HARD_MAX_RUN_EVENT_PAYLOAD_BYTES_PER_RUN,
        event_payload_bytes_global: HARD_MAX_EVENT_PAYLOAD_BYTES_GLOBAL,
        bootstrap_audit_rows: HARD_MAX_BOOTSTRAP_AUDIT_ROWS,
    };

    /// Validates every limit before a database is opened or mutated.
    pub fn validate(&self) -> Result<(), StorageLimitsError> {
        for (field, value, hard_ceiling) in [
            (
                "sessions_per_actor",
                self.sessions_per_actor,
                HARD_MAX_SESSIONS_PER_ACTOR,
            ),
            (
                "sessions_per_account",
                self.sessions_per_account,
                HARD_MAX_SESSIONS_PER_ACCOUNT,
            ),
            (
                "sessions_global",
                self.sessions_global,
                HARD_MAX_SESSIONS_GLOBAL,
            ),
            (
                "open_turns_per_actor",
                self.open_turns_per_actor,
                HARD_MAX_OPEN_TURNS_PER_ACTOR,
            ),
            (
                "open_turns_per_account",
                self.open_turns_per_account,
                HARD_MAX_OPEN_TURNS_PER_ACCOUNT,
            ),
            (
                "open_turns_global",
                self.open_turns_global,
                HARD_MAX_OPEN_TURNS_GLOBAL,
            ),
            (
                "active_reply_jobs_per_actor",
                self.active_reply_jobs_per_actor,
                HARD_MAX_ACTIVE_REPLY_JOBS_PER_ACTOR,
            ),
            (
                "active_reply_jobs_per_account",
                self.active_reply_jobs_per_account,
                HARD_MAX_ACTIVE_REPLY_JOBS_PER_ACCOUNT,
            ),
            (
                "active_reply_jobs_global",
                self.active_reply_jobs_global,
                HARD_MAX_ACTIVE_REPLY_JOBS_GLOBAL,
            ),
            (
                "active_dispatch_jobs_per_actor",
                self.active_dispatch_jobs_per_actor,
                HARD_MAX_ACTIVE_DISPATCH_JOBS_PER_ACTOR,
            ),
            (
                "active_dispatch_jobs_per_account",
                self.active_dispatch_jobs_per_account,
                HARD_MAX_ACTIVE_DISPATCH_JOBS_PER_ACCOUNT,
            ),
            (
                "active_dispatch_jobs_global",
                self.active_dispatch_jobs_global,
                HARD_MAX_ACTIVE_DISPATCH_JOBS_GLOBAL,
            ),
            (
                "auth_sessions_per_user",
                self.auth_sessions_per_user,
                HARD_MAX_AUTH_SESSIONS_PER_USER,
            ),
            (
                "auth_sessions_global",
                self.auth_sessions_global,
                HARD_MAX_AUTH_SESSIONS_GLOBAL,
            ),
            (
                "session_event_slots_per_session",
                self.session_event_slots_per_session,
                HARD_MAX_SESSION_EVENT_SLOTS_PER_SESSION,
            ),
            (
                "run_event_slots_per_run",
                self.run_event_slots_per_run,
                HARD_MAX_RUN_EVENT_SLOTS_PER_RUN,
            ),
            (
                "session_event_payload_bytes_per_session",
                self.session_event_payload_bytes_per_session,
                HARD_MAX_SESSION_EVENT_PAYLOAD_BYTES_PER_SESSION,
            ),
            (
                "run_event_payload_bytes_per_run",
                self.run_event_payload_bytes_per_run,
                HARD_MAX_RUN_EVENT_PAYLOAD_BYTES_PER_RUN,
            ),
            (
                "event_payload_bytes_global",
                self.event_payload_bytes_global,
                HARD_MAX_EVENT_PAYLOAD_BYTES_GLOBAL,
            ),
            (
                "bootstrap_audit_rows",
                self.bootstrap_audit_rows,
                HARD_MAX_BOOTSTRAP_AUDIT_ROWS,
            ),
        ] {
            validate_field(field, value, hard_ceiling)?;
        }

        validate_scope_pair(
            "sessions_per_actor",
            self.sessions_per_actor,
            "sessions_per_account",
            self.sessions_per_account,
        )?;
        validate_scope_pair(
            "sessions_per_account",
            self.sessions_per_account,
            "sessions_global",
            self.sessions_global,
        )?;
        validate_scope_pair(
            "open_turns_per_actor",
            self.open_turns_per_actor,
            "open_turns_per_account",
            self.open_turns_per_account,
        )?;
        validate_scope_pair(
            "open_turns_per_account",
            self.open_turns_per_account,
            "open_turns_global",
            self.open_turns_global,
        )?;
        validate_scope_pair(
            "active_reply_jobs_per_actor",
            self.active_reply_jobs_per_actor,
            "active_reply_jobs_per_account",
            self.active_reply_jobs_per_account,
        )?;
        validate_scope_pair(
            "active_reply_jobs_per_account",
            self.active_reply_jobs_per_account,
            "active_reply_jobs_global",
            self.active_reply_jobs_global,
        )?;
        validate_scope_pair(
            "active_dispatch_jobs_per_actor",
            self.active_dispatch_jobs_per_actor,
            "active_dispatch_jobs_per_account",
            self.active_dispatch_jobs_per_account,
        )?;
        validate_scope_pair(
            "active_dispatch_jobs_per_account",
            self.active_dispatch_jobs_per_account,
            "active_dispatch_jobs_global",
            self.active_dispatch_jobs_global,
        )?;
        validate_scope_pair(
            "auth_sessions_per_user",
            self.auth_sessions_per_user,
            "auth_sessions_global",
            self.auth_sessions_global,
        )?;
        validate_scope_pair(
            "session_event_payload_bytes_per_session",
            self.session_event_payload_bytes_per_session,
            "event_payload_bytes_global",
            self.event_payload_bytes_global,
        )?;
        validate_scope_pair(
            "run_event_payload_bytes_per_run",
            self.run_event_payload_bytes_per_run,
            "event_payload_bytes_global",
            self.event_payload_bytes_global,
        )?;

        Ok(())
    }

    /// Validates and returns the owned limits, convenient for configuration
    /// parsing before passing them into storage.
    pub fn validated(self) -> Result<Self, StorageLimitsError> {
        self.validate()?;
        Ok(self)
    }
}

impl Default for StorageLimits {
    fn default() -> Self {
        Self::ALPHA_DEFAULT
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum StorageLimitsError {
    #[error("storage limit `{field}` must be greater than zero")]
    Zero { field: &'static str },
    #[error(
        "storage limit `{field}` is {value}, exceeding the supported hard ceiling {hard_ceiling}"
    )]
    ExceedsHardCeiling {
        field: &'static str,
        value: usize,
        hard_ceiling: usize,
    },
    #[error(
        "scoped storage limit `{scope_field}` ({scope_value}) exceeds `{global_field}` ({global_value})"
    )]
    ScopeExceedsGlobal {
        scope_field: &'static str,
        scope_value: usize,
        global_field: &'static str,
        global_value: usize,
    },
}

fn validate_field(
    field: &'static str,
    value: usize,
    hard_ceiling: usize,
) -> Result<(), StorageLimitsError> {
    if value == 0 {
        return Err(StorageLimitsError::Zero { field });
    }
    if value > hard_ceiling {
        return Err(StorageLimitsError::ExceedsHardCeiling {
            field,
            value,
            hard_ceiling,
        });
    }
    Ok(())
}

fn validate_scope_pair(
    scope_field: &'static str,
    scope_value: usize,
    global_field: &'static str,
    global_value: usize,
) -> Result<(), StorageLimitsError> {
    if scope_value > global_value {
        return Err(StorageLimitsError::ScopeExceedsGlobal {
            scope_field,
            scope_value,
            global_field,
            global_value,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    type LimitMutation = (&'static str, fn(&mut StorageLimits));
    type CeilingMutation = (&'static str, usize, fn(&mut StorageLimits));
    type ScopePairMutation = (&'static str, &'static str, fn(&mut StorageLimits));

    #[test]
    fn alpha_defaults_are_valid_and_within_hard_ceilings() {
        let defaults = StorageLimits::default();

        assert_eq!(defaults, StorageLimits::ALPHA_DEFAULT);
        assert!(defaults.validate().is_ok());

        for (value, hard_ceiling) in [
            (
                defaults.sessions_per_actor,
                StorageLimits::HARD_CEILINGS.sessions_per_actor,
            ),
            (
                defaults.sessions_per_account,
                StorageLimits::HARD_CEILINGS.sessions_per_account,
            ),
            (
                defaults.sessions_global,
                StorageLimits::HARD_CEILINGS.sessions_global,
            ),
            (
                defaults.open_turns_per_actor,
                StorageLimits::HARD_CEILINGS.open_turns_per_actor,
            ),
            (
                defaults.open_turns_per_account,
                StorageLimits::HARD_CEILINGS.open_turns_per_account,
            ),
            (
                defaults.open_turns_global,
                StorageLimits::HARD_CEILINGS.open_turns_global,
            ),
            (
                defaults.active_reply_jobs_per_actor,
                StorageLimits::HARD_CEILINGS.active_reply_jobs_per_actor,
            ),
            (
                defaults.active_reply_jobs_per_account,
                StorageLimits::HARD_CEILINGS.active_reply_jobs_per_account,
            ),
            (
                defaults.active_reply_jobs_global,
                StorageLimits::HARD_CEILINGS.active_reply_jobs_global,
            ),
            (
                defaults.active_dispatch_jobs_per_actor,
                StorageLimits::HARD_CEILINGS.active_dispatch_jobs_per_actor,
            ),
            (
                defaults.active_dispatch_jobs_per_account,
                StorageLimits::HARD_CEILINGS.active_dispatch_jobs_per_account,
            ),
            (
                defaults.active_dispatch_jobs_global,
                StorageLimits::HARD_CEILINGS.active_dispatch_jobs_global,
            ),
            (
                defaults.auth_sessions_per_user,
                StorageLimits::HARD_CEILINGS.auth_sessions_per_user,
            ),
            (
                defaults.auth_sessions_global,
                StorageLimits::HARD_CEILINGS.auth_sessions_global,
            ),
            (
                defaults.session_event_slots_per_session,
                StorageLimits::HARD_CEILINGS.session_event_slots_per_session,
            ),
            (
                defaults.run_event_slots_per_run,
                StorageLimits::HARD_CEILINGS.run_event_slots_per_run,
            ),
            (
                defaults.session_event_payload_bytes_per_session,
                StorageLimits::HARD_CEILINGS.session_event_payload_bytes_per_session,
            ),
            (
                defaults.run_event_payload_bytes_per_run,
                StorageLimits::HARD_CEILINGS.run_event_payload_bytes_per_run,
            ),
            (
                defaults.event_payload_bytes_global,
                StorageLimits::HARD_CEILINGS.event_payload_bytes_global,
            ),
            (
                defaults.bootstrap_audit_rows,
                StorageLimits::HARD_CEILINGS.bootstrap_audit_rows,
            ),
        ] {
            assert!(value > 0);
            assert!(value <= hard_ceiling);
        }
    }

    #[test]
    fn event_payload_byte_defaults_and_hard_ceilings_are_exact() {
        let defaults = StorageLimits::default();
        let hard_ceilings = StorageLimits::HARD_CEILINGS;

        assert_eq!(defaults.session_event_payload_bytes_per_session, 64 << 20);
        assert_eq!(defaults.run_event_payload_bytes_per_run, 256 << 20);
        assert_eq!(defaults.event_payload_bytes_global, 1 << 30);
        assert_eq!(
            hard_ceilings.session_event_payload_bytes_per_session,
            256 << 20
        );
        assert_eq!(hard_ceilings.run_event_payload_bytes_per_run, 1 << 30);
        assert_eq!(hard_ceilings.event_payload_bytes_global, 2 << 30);
    }

    #[test]
    fn every_zero_field_is_rejected_with_its_name() {
        let mutations: [LimitMutation; 20] = [
            ("sessions_per_actor", |limits| limits.sessions_per_actor = 0),
            ("sessions_per_account", |limits| {
                limits.sessions_per_account = 0
            }),
            ("sessions_global", |limits| limits.sessions_global = 0),
            ("open_turns_per_actor", |limits| {
                limits.open_turns_per_actor = 0
            }),
            ("open_turns_per_account", |limits| {
                limits.open_turns_per_account = 0
            }),
            ("open_turns_global", |limits| limits.open_turns_global = 0),
            ("active_reply_jobs_per_actor", |limits| {
                limits.active_reply_jobs_per_actor = 0
            }),
            ("active_reply_jobs_per_account", |limits| {
                limits.active_reply_jobs_per_account = 0
            }),
            ("active_reply_jobs_global", |limits| {
                limits.active_reply_jobs_global = 0
            }),
            ("active_dispatch_jobs_per_actor", |limits| {
                limits.active_dispatch_jobs_per_actor = 0
            }),
            ("active_dispatch_jobs_per_account", |limits| {
                limits.active_dispatch_jobs_per_account = 0
            }),
            ("active_dispatch_jobs_global", |limits| {
                limits.active_dispatch_jobs_global = 0
            }),
            ("auth_sessions_per_user", |limits| {
                limits.auth_sessions_per_user = 0
            }),
            ("auth_sessions_global", |limits| {
                limits.auth_sessions_global = 0
            }),
            ("session_event_slots_per_session", |limits| {
                limits.session_event_slots_per_session = 0
            }),
            ("run_event_slots_per_run", |limits| {
                limits.run_event_slots_per_run = 0
            }),
            ("session_event_payload_bytes_per_session", |limits| {
                limits.session_event_payload_bytes_per_session = 0
            }),
            ("run_event_payload_bytes_per_run", |limits| {
                limits.run_event_payload_bytes_per_run = 0
            }),
            ("event_payload_bytes_global", |limits| {
                limits.event_payload_bytes_global = 0
            }),
            ("bootstrap_audit_rows", |limits| {
                limits.bootstrap_audit_rows = 0
            }),
        ];

        for (expected_field, mutate) in mutations {
            let mut limits = StorageLimits::default();
            mutate(&mut limits);
            assert_eq!(
                limits.validate(),
                Err(StorageLimitsError::Zero {
                    field: expected_field,
                })
            );
        }
    }

    #[test]
    fn every_value_above_its_hard_ceiling_is_rejected() {
        let mutations: [CeilingMutation; 20] = [
            (
                "sessions_per_actor",
                HARD_MAX_SESSIONS_PER_ACTOR,
                |limits| limits.sessions_per_actor = HARD_MAX_SESSIONS_PER_ACTOR + 1,
            ),
            (
                "sessions_per_account",
                HARD_MAX_SESSIONS_PER_ACCOUNT,
                |limits| limits.sessions_per_account = HARD_MAX_SESSIONS_PER_ACCOUNT + 1,
            ),
            ("sessions_global", HARD_MAX_SESSIONS_GLOBAL, |limits| {
                limits.sessions_global = HARD_MAX_SESSIONS_GLOBAL + 1
            }),
            (
                "open_turns_per_actor",
                HARD_MAX_OPEN_TURNS_PER_ACTOR,
                |limits| limits.open_turns_per_actor = HARD_MAX_OPEN_TURNS_PER_ACTOR + 1,
            ),
            (
                "open_turns_per_account",
                HARD_MAX_OPEN_TURNS_PER_ACCOUNT,
                |limits| limits.open_turns_per_account = HARD_MAX_OPEN_TURNS_PER_ACCOUNT + 1,
            ),
            ("open_turns_global", HARD_MAX_OPEN_TURNS_GLOBAL, |limits| {
                limits.open_turns_global = HARD_MAX_OPEN_TURNS_GLOBAL + 1
            }),
            (
                "active_reply_jobs_per_actor",
                HARD_MAX_ACTIVE_REPLY_JOBS_PER_ACTOR,
                |limits| {
                    limits.active_reply_jobs_per_actor = HARD_MAX_ACTIVE_REPLY_JOBS_PER_ACTOR + 1
                },
            ),
            (
                "active_reply_jobs_per_account",
                HARD_MAX_ACTIVE_REPLY_JOBS_PER_ACCOUNT,
                |limits| {
                    limits.active_reply_jobs_per_account =
                        HARD_MAX_ACTIVE_REPLY_JOBS_PER_ACCOUNT + 1
                },
            ),
            (
                "active_reply_jobs_global",
                HARD_MAX_ACTIVE_REPLY_JOBS_GLOBAL,
                |limits| limits.active_reply_jobs_global = HARD_MAX_ACTIVE_REPLY_JOBS_GLOBAL + 1,
            ),
            (
                "active_dispatch_jobs_per_actor",
                HARD_MAX_ACTIVE_DISPATCH_JOBS_PER_ACTOR,
                |limits| {
                    limits.active_dispatch_jobs_per_actor =
                        HARD_MAX_ACTIVE_DISPATCH_JOBS_PER_ACTOR + 1
                },
            ),
            (
                "active_dispatch_jobs_per_account",
                HARD_MAX_ACTIVE_DISPATCH_JOBS_PER_ACCOUNT,
                |limits| {
                    limits.active_dispatch_jobs_per_account =
                        HARD_MAX_ACTIVE_DISPATCH_JOBS_PER_ACCOUNT + 1
                },
            ),
            (
                "active_dispatch_jobs_global",
                HARD_MAX_ACTIVE_DISPATCH_JOBS_GLOBAL,
                |limits| {
                    limits.active_dispatch_jobs_global = HARD_MAX_ACTIVE_DISPATCH_JOBS_GLOBAL + 1
                },
            ),
            (
                "auth_sessions_per_user",
                HARD_MAX_AUTH_SESSIONS_PER_USER,
                |limits| limits.auth_sessions_per_user = HARD_MAX_AUTH_SESSIONS_PER_USER + 1,
            ),
            (
                "auth_sessions_global",
                HARD_MAX_AUTH_SESSIONS_GLOBAL,
                |limits| limits.auth_sessions_global = HARD_MAX_AUTH_SESSIONS_GLOBAL + 1,
            ),
            (
                "session_event_slots_per_session",
                HARD_MAX_SESSION_EVENT_SLOTS_PER_SESSION,
                |limits| {
                    limits.session_event_slots_per_session =
                        HARD_MAX_SESSION_EVENT_SLOTS_PER_SESSION + 1
                },
            ),
            (
                "run_event_slots_per_run",
                HARD_MAX_RUN_EVENT_SLOTS_PER_RUN,
                |limits| limits.run_event_slots_per_run = HARD_MAX_RUN_EVENT_SLOTS_PER_RUN + 1,
            ),
            (
                "session_event_payload_bytes_per_session",
                HARD_MAX_SESSION_EVENT_PAYLOAD_BYTES_PER_SESSION,
                |limits| {
                    limits.session_event_payload_bytes_per_session =
                        HARD_MAX_SESSION_EVENT_PAYLOAD_BYTES_PER_SESSION + 1
                },
            ),
            (
                "run_event_payload_bytes_per_run",
                HARD_MAX_RUN_EVENT_PAYLOAD_BYTES_PER_RUN,
                |limits| {
                    limits.run_event_payload_bytes_per_run =
                        HARD_MAX_RUN_EVENT_PAYLOAD_BYTES_PER_RUN + 1
                },
            ),
            (
                "event_payload_bytes_global",
                HARD_MAX_EVENT_PAYLOAD_BYTES_GLOBAL,
                |limits| {
                    limits.event_payload_bytes_global = HARD_MAX_EVENT_PAYLOAD_BYTES_GLOBAL + 1
                },
            ),
            (
                "bootstrap_audit_rows",
                HARD_MAX_BOOTSTRAP_AUDIT_ROWS,
                |limits| limits.bootstrap_audit_rows = HARD_MAX_BOOTSTRAP_AUDIT_ROWS + 1,
            ),
        ];

        for (expected_field, hard_ceiling, mutate) in mutations {
            let mut limits = StorageLimits::default();
            mutate(&mut limits);
            assert_eq!(
                limits.validate(),
                Err(StorageLimitsError::ExceedsHardCeiling {
                    field: expected_field,
                    value: hard_ceiling + 1,
                    hard_ceiling,
                })
            );
        }
    }

    #[test]
    fn actor_account_and_global_limit_order_is_enforced() {
        let cases: [ScopePairMutation; 11] = [
            ("sessions_per_actor", "sessions_per_account", |limits| {
                limits.sessions_per_actor = 2;
                limits.sessions_per_account = 1;
            }),
            ("sessions_per_account", "sessions_global", |limits| {
                limits.sessions_per_actor = 1;
                limits.sessions_per_account = 2;
                limits.sessions_global = 1;
            }),
            ("open_turns_per_actor", "open_turns_per_account", |limits| {
                limits.open_turns_per_actor = 2;
                limits.open_turns_per_account = 1;
            }),
            ("open_turns_per_account", "open_turns_global", |limits| {
                limits.open_turns_per_actor = 1;
                limits.open_turns_per_account = 2;
                limits.open_turns_global = 1;
            }),
            (
                "active_reply_jobs_per_actor",
                "active_reply_jobs_per_account",
                |limits| {
                    limits.active_reply_jobs_per_actor = 2;
                    limits.active_reply_jobs_per_account = 1;
                },
            ),
            (
                "active_reply_jobs_per_account",
                "active_reply_jobs_global",
                |limits| {
                    limits.active_reply_jobs_per_actor = 1;
                    limits.active_reply_jobs_per_account = 2;
                    limits.active_reply_jobs_global = 1;
                },
            ),
            (
                "active_dispatch_jobs_per_actor",
                "active_dispatch_jobs_per_account",
                |limits| {
                    limits.active_dispatch_jobs_per_actor = 2;
                    limits.active_dispatch_jobs_per_account = 1;
                },
            ),
            (
                "active_dispatch_jobs_per_account",
                "active_dispatch_jobs_global",
                |limits| {
                    limits.active_dispatch_jobs_per_actor = 1;
                    limits.active_dispatch_jobs_per_account = 2;
                    limits.active_dispatch_jobs_global = 1;
                },
            ),
            ("auth_sessions_per_user", "auth_sessions_global", |limits| {
                limits.auth_sessions_per_user = 2;
                limits.auth_sessions_global = 1;
            }),
            (
                "session_event_payload_bytes_per_session",
                "event_payload_bytes_global",
                |limits| {
                    limits.session_event_payload_bytes_per_session = 2;
                    limits.event_payload_bytes_global = 1;
                },
            ),
            (
                "run_event_payload_bytes_per_run",
                "event_payload_bytes_global",
                |limits| {
                    limits.session_event_payload_bytes_per_session = 1;
                    limits.run_event_payload_bytes_per_run = 2;
                    limits.event_payload_bytes_global = 1;
                },
            ),
        ];

        for (scope_field, global_field, mutate) in cases {
            let mut limits = StorageLimits::default();
            mutate(&mut limits);
            assert_eq!(
                limits.validate(),
                Err(StorageLimitsError::ScopeExceedsGlobal {
                    scope_field,
                    scope_value: 2,
                    global_field,
                    global_value: 1,
                })
            );
        }
    }

    #[test]
    fn validated_preserves_a_valid_configuration() {
        let limits = StorageLimits {
            sessions_per_actor: 7,
            sessions_per_account: 9,
            sessions_global: 11,
            ..StorageLimits::default()
        };

        assert_eq!(limits.clone().validated(), Ok(limits));
    }
}
