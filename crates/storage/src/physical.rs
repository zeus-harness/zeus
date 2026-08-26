//! Validated physical-capacity policy for the Alpha SQLite store.
//!
//! These limits configure application-level admission checks and SQLite
//! PRAGMA policy for the main database and its write-ahead log. They preserve
//! operating headroom, but they are not a filesystem quota or an absolute
//! guarantee that disk space remains available: other processes can consume
//! the same filesystem after Zeus checks it, and an active WAL can temporarily
//! exceed its checkpoint target.

use thiserror::Error;

pub const DEFAULT_MAX_MAIN_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub const DEFAULT_WAL_TARGET_BYTES: u64 = 16 * 1024 * 1024;
pub const DEFAULT_MIN_FREE_BYTES: u64 = 256 * 1024 * 1024;
pub const DEFAULT_ADMISSION_RESERVE_BYTES: u64 = 512 * 1024 * 1024;

pub const HARD_MAX_MAIN_BYTES: u64 = 32 * 1024 * 1024 * 1024;
pub const HARD_MAX_WAL_TARGET_BYTES: u64 = 256 * 1024 * 1024;
pub const HARD_MAX_MIN_FREE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const HARD_MAX_ADMISSION_RESERVE_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Physical SQLite limits accepted by application admission and PRAGMA setup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqlitePhysicalLimits {
    /// Maximum configured size of the main SQLite database file.
    pub max_main_bytes: u64,
    /// Target at which SQLite should checkpoint and later trim the WAL.
    pub wal_target_bytes: u64,
    /// Filesystem bytes Zeus keeps free for already accepted work and recovery.
    pub min_free_bytes: u64,
    /// Main-file and filesystem headroom withheld from ordinary admission.
    pub admission_reserve_bytes: u64,
}

impl SqlitePhysicalLimits {
    /// The supported Alpha defaults.
    pub const ALPHA_DEFAULT: Self = Self {
        max_main_bytes: DEFAULT_MAX_MAIN_BYTES,
        wal_target_bytes: DEFAULT_WAL_TARGET_BYTES,
        min_free_bytes: DEFAULT_MIN_FREE_BYTES,
        admission_reserve_bytes: DEFAULT_ADMISSION_RESERVE_BYTES,
    };

    /// Absolute ceilings accepted by this binary.
    pub const HARD_CEILINGS: Self = Self {
        max_main_bytes: HARD_MAX_MAIN_BYTES,
        wal_target_bytes: HARD_MAX_WAL_TARGET_BYTES,
        min_free_bytes: HARD_MAX_MIN_FREE_BYTES,
        admission_reserve_bytes: HARD_MAX_ADMISSION_RESERVE_BYTES,
    };

    /// Validates every value and the headroom ordering before it is used.
    pub fn validate(&self) -> Result<(), SqlitePhysicalLimitsError> {
        for (field, value, hard_ceiling) in [
            ("max_main_bytes", self.max_main_bytes, HARD_MAX_MAIN_BYTES),
            (
                "wal_target_bytes",
                self.wal_target_bytes,
                HARD_MAX_WAL_TARGET_BYTES,
            ),
            (
                "min_free_bytes",
                self.min_free_bytes,
                HARD_MAX_MIN_FREE_BYTES,
            ),
            (
                "admission_reserve_bytes",
                self.admission_reserve_bytes,
                HARD_MAX_ADMISSION_RESERVE_BYTES,
            ),
        ] {
            validate_field(field, value, hard_ceiling)?;
        }

        if self.wal_target_bytes >= self.admission_reserve_bytes {
            return Err(SqlitePhysicalLimitsError::InvalidOrdering {
                lower_field: "wal_target_bytes",
                lower_value: self.wal_target_bytes,
                upper_field: "admission_reserve_bytes",
                upper_value: self.admission_reserve_bytes,
            });
        }
        if self.admission_reserve_bytes >= self.max_main_bytes {
            return Err(SqlitePhysicalLimitsError::InvalidOrdering {
                lower_field: "admission_reserve_bytes",
                lower_value: self.admission_reserve_bytes,
                upper_field: "max_main_bytes",
                upper_value: self.max_main_bytes,
            });
        }
        validate_headroom_sum(self.min_free_bytes, self.admission_reserve_bytes)?;

        Ok(())
    }

    /// Validates and returns the owned policy for configuration adapters.
    pub fn validated(self) -> Result<Self, SqlitePhysicalLimitsError> {
        self.validate()?;
        Ok(self)
    }
}

impl Default for SqlitePhysicalLimits {
    fn default() -> Self {
        Self::ALPHA_DEFAULT
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SqlitePhysicalLimitsError {
    #[error("SQLite physical limit `{field}` must be greater than zero")]
    Zero { field: &'static str },
    #[error(
        "SQLite physical limit `{field}` is {value}, exceeding the supported hard ceiling {hard_ceiling}"
    )]
    ExceedsHardCeiling {
        field: &'static str,
        value: u64,
        hard_ceiling: u64,
    },
    #[error(
        "SQLite physical limit `{lower_field}` ({lower_value}) must be less than `{upper_field}` ({upper_value})"
    )]
    InvalidOrdering {
        lower_field: &'static str,
        lower_value: u64,
        upper_field: &'static str,
        upper_value: u64,
    },
    #[error(
        "SQLite physical headroom overflows u64: min_free_bytes={min_free_bytes}, admission_reserve_bytes={admission_reserve_bytes}"
    )]
    HeadroomOverflow {
        min_free_bytes: u64,
        admission_reserve_bytes: u64,
    },
}

fn validate_field(
    field: &'static str,
    value: u64,
    hard_ceiling: u64,
) -> Result<(), SqlitePhysicalLimitsError> {
    if value == 0 {
        return Err(SqlitePhysicalLimitsError::Zero { field });
    }
    if value > hard_ceiling {
        return Err(SqlitePhysicalLimitsError::ExceedsHardCeiling {
            field,
            value,
            hard_ceiling,
        });
    }
    Ok(())
}

fn validate_headroom_sum(
    min_free_bytes: u64,
    admission_reserve_bytes: u64,
) -> Result<(), SqlitePhysicalLimitsError> {
    min_free_bytes.checked_add(admission_reserve_bytes).ok_or(
        SqlitePhysicalLimitsError::HeadroomOverflow {
            min_free_bytes,
            admission_reserve_bytes,
        },
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    type LimitMutation = (&'static str, fn(&mut SqlitePhysicalLimits));
    type CeilingMutation = (&'static str, u64, fn(&mut SqlitePhysicalLimits));

    #[test]
    fn alpha_defaults_are_valid_and_match_the_public_constants() {
        let defaults = SqlitePhysicalLimits::default();

        assert_eq!(defaults, SqlitePhysicalLimits::ALPHA_DEFAULT);
        assert_eq!(defaults.max_main_bytes, 4 * 1024 * 1024 * 1024);
        assert_eq!(defaults.wal_target_bytes, 16 * 1024 * 1024);
        assert_eq!(defaults.min_free_bytes, 256 * 1024 * 1024);
        assert_eq!(defaults.admission_reserve_bytes, 512 * 1024 * 1024);
        assert!(defaults.validate().is_ok());
        assert_eq!(defaults.clone().validated(), Ok(defaults));
    }

    #[test]
    fn hard_ceilings_are_valid_and_match_the_public_constants() {
        let hard_ceilings = SqlitePhysicalLimits::HARD_CEILINGS;

        assert_eq!(hard_ceilings.max_main_bytes, HARD_MAX_MAIN_BYTES);
        assert_eq!(hard_ceilings.wal_target_bytes, HARD_MAX_WAL_TARGET_BYTES);
        assert_eq!(hard_ceilings.min_free_bytes, HARD_MAX_MIN_FREE_BYTES);
        assert_eq!(
            hard_ceilings.admission_reserve_bytes,
            HARD_MAX_ADMISSION_RESERVE_BYTES
        );
        assert!(hard_ceilings.validate().is_ok());
    }

    #[test]
    fn every_field_rejects_zero() {
        let mutations: [LimitMutation; 4] = [
            ("max_main_bytes", |limits| limits.max_main_bytes = 0),
            ("wal_target_bytes", |limits| limits.wal_target_bytes = 0),
            ("min_free_bytes", |limits| limits.min_free_bytes = 0),
            ("admission_reserve_bytes", |limits| {
                limits.admission_reserve_bytes = 0;
            }),
        ];

        for (field, mutate) in mutations {
            let mut limits = SqlitePhysicalLimits::default();
            mutate(&mut limits);
            assert_eq!(
                limits.validate(),
                Err(SqlitePhysicalLimitsError::Zero { field })
            );
        }
    }

    #[test]
    fn every_field_rejects_values_above_its_hard_ceiling() {
        let mutations: [CeilingMutation; 4] = [
            ("max_main_bytes", HARD_MAX_MAIN_BYTES, |limits| {
                limits.max_main_bytes = HARD_MAX_MAIN_BYTES + 1;
            }),
            ("wal_target_bytes", HARD_MAX_WAL_TARGET_BYTES, |limits| {
                limits.wal_target_bytes = HARD_MAX_WAL_TARGET_BYTES + 1
            }),
            ("min_free_bytes", HARD_MAX_MIN_FREE_BYTES, |limits| {
                limits.min_free_bytes = HARD_MAX_MIN_FREE_BYTES + 1;
            }),
            (
                "admission_reserve_bytes",
                HARD_MAX_ADMISSION_RESERVE_BYTES,
                |limits| {
                    limits.admission_reserve_bytes = HARD_MAX_ADMISSION_RESERVE_BYTES + 1;
                },
            ),
        ];

        for (field, hard_ceiling, mutate) in mutations {
            let mut limits = SqlitePhysicalLimits::default();
            mutate(&mut limits);
            assert_eq!(
                limits.validate(),
                Err(SqlitePhysicalLimitsError::ExceedsHardCeiling {
                    field,
                    value: hard_ceiling + 1,
                    hard_ceiling,
                })
            );
        }
    }

    #[test]
    fn wal_target_must_be_strictly_below_admission_reserve() {
        let admission_reserve_bytes = 128 * 1024 * 1024;
        for wal_target_bytes in [admission_reserve_bytes, admission_reserve_bytes + 1] {
            let limits = SqlitePhysicalLimits {
                wal_target_bytes,
                admission_reserve_bytes,
                ..SqlitePhysicalLimits::default()
            };

            assert_eq!(
                limits.validate(),
                Err(SqlitePhysicalLimitsError::InvalidOrdering {
                    lower_field: "wal_target_bytes",
                    lower_value: wal_target_bytes,
                    upper_field: "admission_reserve_bytes",
                    upper_value: admission_reserve_bytes,
                })
            );
        }
    }

    #[test]
    fn admission_reserve_must_be_strictly_below_main_limit() {
        for admission_reserve_bytes in [DEFAULT_MAX_MAIN_BYTES, DEFAULT_MAX_MAIN_BYTES + 1] {
            let limits = SqlitePhysicalLimits {
                admission_reserve_bytes,
                ..SqlitePhysicalLimits::default()
            };

            assert_eq!(
                limits.validate(),
                Err(SqlitePhysicalLimitsError::InvalidOrdering {
                    lower_field: "admission_reserve_bytes",
                    lower_value: admission_reserve_bytes,
                    upper_field: "max_main_bytes",
                    upper_value: DEFAULT_MAX_MAIN_BYTES,
                })
            );
        }
    }

    #[test]
    fn hard_ceiling_validation_precedes_headroom_arithmetic() {
        let limits = SqlitePhysicalLimits {
            max_main_bytes: HARD_MAX_MAIN_BYTES,
            wal_target_bytes: 1,
            min_free_bytes: u64::MAX,
            admission_reserve_bytes: 2,
        };

        assert_eq!(
            limits.validate(),
            Err(SqlitePhysicalLimitsError::ExceedsHardCeiling {
                field: "min_free_bytes",
                value: u64::MAX,
                hard_ceiling: HARD_MAX_MIN_FREE_BYTES,
            })
        );
    }

    #[test]
    fn headroom_sum_rejects_overflow() {
        assert_eq!(
            validate_headroom_sum(u64::MAX, 1),
            Err(SqlitePhysicalLimitsError::HeadroomOverflow {
                min_free_bytes: u64::MAX,
                admission_reserve_bytes: 1,
            })
        );
    }
}
