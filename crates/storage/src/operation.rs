//! Bounded admission for blocking SQLite operations.
//!
//! General work cannot consume the reserved durable-progress lane. Its
//! admission semaphore is deliberately acquired with `try_acquire`, bounding
//! both running operations and callers waiting for the total-operation gate.
//! Durable-progress work may use every total slot, but still has a bounded
//! acquisition time.

use std::{sync::Arc, time::Duration};

use thiserror::Error;
use tokio::{
    sync::{Notify, OwnedSemaphorePermit, Semaphore, TryAcquireError},
    time::{Instant, timeout_at},
};

use crate::StorageError;

pub const DEFAULT_MAX_CONCURRENT_OPERATIONS: usize = 8;
pub const DEFAULT_RESERVED_PROGRESS_OPERATIONS: usize = 1;
pub const DEFAULT_ACQUIRE_TIMEOUT_MS: u64 = 1_000;

pub const HARD_MAX_CONCURRENT_OPERATIONS: usize = 32;
pub const HARD_MAX_RESERVED_PROGRESS_OPERATIONS: usize = 8;
pub const HARD_MAX_ACQUIRE_TIMEOUT_MS: u64 = 5_000;

/// Concurrency limits for SQLite connection and transaction work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqliteOperationLimits {
    /// Maximum file or in-memory SQLite operations admitted at once.
    pub max_concurrent_operations: usize,
    /// Slots withheld from ordinary work so accepted jobs can make progress.
    pub reserved_progress_operations: usize,
    /// Maximum time spent waiting for an already-admitted operation slot.
    pub acquire_timeout_ms: u64,
}

impl SqliteOperationLimits {
    pub const ALPHA_DEFAULT: Self = Self {
        max_concurrent_operations: DEFAULT_MAX_CONCURRENT_OPERATIONS,
        reserved_progress_operations: DEFAULT_RESERVED_PROGRESS_OPERATIONS,
        acquire_timeout_ms: DEFAULT_ACQUIRE_TIMEOUT_MS,
    };

    pub const HARD_CEILINGS: Self = Self {
        max_concurrent_operations: HARD_MAX_CONCURRENT_OPERATIONS,
        reserved_progress_operations: HARD_MAX_RESERVED_PROGRESS_OPERATIONS,
        acquire_timeout_ms: HARD_MAX_ACQUIRE_TIMEOUT_MS,
    };

    pub fn validate(&self) -> Result<(), SqliteOperationLimitsError> {
        validate_usize_field(
            "max_concurrent_operations",
            self.max_concurrent_operations,
            HARD_MAX_CONCURRENT_OPERATIONS,
        )?;
        validate_usize_field(
            "reserved_progress_operations",
            self.reserved_progress_operations,
            HARD_MAX_RESERVED_PROGRESS_OPERATIONS,
        )?;
        validate_u64_field(
            "acquire_timeout_ms",
            self.acquire_timeout_ms,
            HARD_MAX_ACQUIRE_TIMEOUT_MS,
        )?;

        if self.reserved_progress_operations >= self.max_concurrent_operations {
            return Err(SqliteOperationLimitsError::InvalidReservation {
                reserved_progress_operations: self.reserved_progress_operations,
                max_concurrent_operations: self.max_concurrent_operations,
            });
        }

        Ok(())
    }

    pub fn validated(self) -> Result<Self, SqliteOperationLimitsError> {
        self.validate()?;
        Ok(self)
    }
}

impl Default for SqliteOperationLimits {
    fn default() -> Self {
        Self::ALPHA_DEFAULT
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SqliteOperationLimitsError {
    #[error("SQLite operation limit `{field}` must be greater than zero")]
    Zero { field: &'static str },
    #[error(
        "SQLite operation limit `{field}` is {value}, exceeding the supported hard ceiling {hard_ceiling}"
    )]
    ExceedsHardCeiling {
        field: &'static str,
        value: u64,
        hard_ceiling: u64,
    },
    #[error(
        "reserved_progress_operations ({reserved_progress_operations}) must be less than max_concurrent_operations ({max_concurrent_operations})"
    )]
    InvalidReservation {
        reserved_progress_operations: usize,
        max_concurrent_operations: usize,
    },
}

fn validate_usize_field(
    field: &'static str,
    value: usize,
    hard_ceiling: usize,
) -> Result<(), SqliteOperationLimitsError> {
    if value == 0 {
        return Err(SqliteOperationLimitsError::Zero { field });
    }
    if value > hard_ceiling {
        return Err(SqliteOperationLimitsError::ExceedsHardCeiling {
            field,
            value: value as u64,
            hard_ceiling: hard_ceiling as u64,
        });
    }
    Ok(())
}

fn validate_u64_field(
    field: &'static str,
    value: u64,
    hard_ceiling: u64,
) -> Result<(), SqliteOperationLimitsError> {
    if value == 0 {
        return Err(SqliteOperationLimitsError::Zero { field });
    }
    if value > hard_ceiling {
        return Err(SqliteOperationLimitsError::ExceedsHardCeiling {
            field,
            value,
            hard_ceiling,
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OperationClass {
    General,
    DurableProgress,
}

pub(crate) struct OperationPermits {
    _general: Option<OwnedSemaphorePermit>,
    _total: OwnedSemaphorePermit,
    _memory: Option<MemoryPermit>,
}

struct MemoryPermit {
    permit: Option<OwnedSemaphorePermit>,
    available: Arc<Notify>,
}

impl Drop for MemoryPermit {
    fn drop(&mut self) {
        drop(self.permit.take());
        self.available.notify_waiters();
    }
}

pub(crate) struct OperationLimiter {
    total: Arc<Semaphore>,
    general: Arc<Semaphore>,
    memory: Arc<Semaphore>,
    memory_available: Arc<Notify>,
    progress_memory_waiters: std::sync::atomic::AtomicUsize,
    acquire_timeout: Duration,
    #[cfg(test)]
    blocking_tasks_active: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    memory_waiters: std::sync::atomic::AtomicUsize,
}

impl OperationLimiter {
    pub(crate) fn new(limits: &SqliteOperationLimits) -> Self {
        Self {
            total: Arc::new(Semaphore::new(limits.max_concurrent_operations)),
            general: Arc::new(Semaphore::new(
                limits.max_concurrent_operations - limits.reserved_progress_operations,
            )),
            // An in-memory SQLite store owns exactly one Connection. Acquiring
            // this gate asynchronously keeps mutex waiters out of Tokio's
            // blocking pool.
            memory: Arc::new(Semaphore::new(1)),
            memory_available: Arc::new(Notify::new()),
            progress_memory_waiters: std::sync::atomic::AtomicUsize::new(0),
            acquire_timeout: Duration::from_millis(limits.acquire_timeout_ms),
            #[cfg(test)]
            blocking_tasks_active: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            memory_waiters: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub(crate) async fn acquire(
        &self,
        class: OperationClass,
        is_memory: bool,
    ) -> Result<OperationPermits, StorageError> {
        let deadline = Instant::now() + self.acquire_timeout;
        let general = match class {
            OperationClass::General => Some(
                Arc::clone(&self.general)
                    .try_acquire_owned()
                    .map_err(map_try_acquire_error)?,
            ),
            OperationClass::DurableProgress => None,
        };

        let total = acquire_before(&self.total, deadline).await?;
        let memory = if is_memory {
            Some(self.acquire_memory(class, deadline).await?)
        } else {
            None
        };

        Ok(OperationPermits {
            _general: general,
            _total: total,
            _memory: memory,
        })
    }

    async fn acquire_memory(
        &self,
        class: OperationClass,
        deadline: Instant,
    ) -> Result<MemoryPermit, StorageError> {
        if class == OperationClass::General
            && self
                .progress_memory_waiters
                .load(std::sync::atomic::Ordering::Acquire)
                > 0
        {
            return self.acquire_general_memory(deadline).await;
        }
        match Arc::clone(&self.memory).try_acquire_owned() {
            Ok(permit) => Ok(self.memory_permit(permit)),
            Err(TryAcquireError::Closed) => Err(StorageError::OperationCapacityExceeded),
            Err(TryAcquireError::NoPermits) if class == OperationClass::DurableProgress => {
                let _progress_waiter =
                    ProgressWaiterGuard::new(&self.progress_memory_waiters, &self.memory_available);
                #[cfg(test)]
                let _waiter = CounterGuard::new(&self.memory_waiters);
                let permit = acquire_before(&self.memory, deadline).await?;
                Ok(self.memory_permit(permit))
            }
            Err(TryAcquireError::NoPermits) => self.acquire_general_memory(deadline).await,
        }
    }

    async fn acquire_general_memory(
        &self,
        deadline: Instant,
    ) -> Result<MemoryPermit, StorageError> {
        // General waiters stay outside the FIFO semaphore queue. This
        // preserves normal in-memory concurrency while ensuring a later
        // durable-progress waiter receives the next permit.
        #[cfg(test)]
        let _waiter = CounterGuard::new(&self.memory_waiters);
        loop {
            let notified = self.memory_available.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self
                .progress_memory_waiters
                .load(std::sync::atomic::Ordering::Acquire)
                == 0
            {
                match Arc::clone(&self.memory).try_acquire_owned() {
                    Ok(permit) => return Ok(self.memory_permit(permit)),
                    Err(TryAcquireError::Closed) => {
                        return Err(StorageError::OperationCapacityExceeded);
                    }
                    Err(TryAcquireError::NoPermits) => {}
                }
            }
            if timeout_at(deadline, notified).await.is_err() {
                return Err(StorageError::OperationCapacityExceeded);
            }
        }
    }

    fn memory_permit(&self, permit: OwnedSemaphorePermit) -> MemoryPermit {
        MemoryPermit {
            permit: Some(permit),
            available: Arc::clone(&self.memory_available),
        }
    }

    #[cfg(test)]
    pub(crate) fn blocking_task_guard(&self) -> CounterGuard<'_> {
        CounterGuard::new(&self.blocking_tasks_active)
    }

    #[cfg(test)]
    pub(crate) fn test_snapshot(&self) -> (usize, usize) {
        use std::sync::atomic::Ordering;

        (
            self.blocking_tasks_active.load(Ordering::SeqCst),
            self.memory_waiters.load(Ordering::SeqCst),
        )
    }
}

async fn acquire_before(
    semaphore: &Arc<Semaphore>,
    deadline: Instant,
) -> Result<OwnedSemaphorePermit, StorageError> {
    match timeout_at(deadline, Arc::clone(semaphore).acquire_owned()).await {
        Ok(Ok(permit)) => Ok(permit),
        Ok(Err(_)) | Err(_) => Err(StorageError::OperationCapacityExceeded),
    }
}

fn map_try_acquire_error(_error: TryAcquireError) -> StorageError {
    StorageError::OperationCapacityExceeded
}

#[cfg(test)]
pub(crate) struct CounterGuard<'a> {
    counter: &'a std::sync::atomic::AtomicUsize,
}

struct ProgressWaiterGuard<'a> {
    counter: &'a std::sync::atomic::AtomicUsize,
    available: &'a Notify,
}

impl<'a> ProgressWaiterGuard<'a> {
    fn new(counter: &'a std::sync::atomic::AtomicUsize, available: &'a Notify) -> Self {
        use std::sync::atomic::Ordering;

        counter.fetch_add(1, Ordering::SeqCst);
        Self { counter, available }
    }
}

impl Drop for ProgressWaiterGuard<'_> {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;

        if self.counter.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.available.notify_waiters();
        }
    }
}

#[cfg(test)]
impl<'a> CounterGuard<'a> {
    fn new(counter: &'a std::sync::atomic::AtomicUsize) -> Self {
        use std::sync::atomic::Ordering;

        counter.fetch_add(1, Ordering::SeqCst);
        Self { counter }
    }
}

#[cfg(test)]
impl Drop for CounterGuard<'_> {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;

        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type LimitMutation = (&'static str, fn(&mut SqliteOperationLimits));
    type CeilingMutation = (&'static str, u64, fn(&mut SqliteOperationLimits));

    #[test]
    fn alpha_defaults_are_valid_and_match_public_constants() {
        let defaults = SqliteOperationLimits::default();

        assert_eq!(defaults, SqliteOperationLimits::ALPHA_DEFAULT);
        assert_eq!(defaults.max_concurrent_operations, 8);
        assert_eq!(defaults.reserved_progress_operations, 1);
        assert_eq!(defaults.acquire_timeout_ms, 1_000);
        assert!(defaults.validate().is_ok());
        assert_eq!(defaults.clone().validated(), Ok(defaults));
    }

    #[test]
    fn hard_ceilings_are_valid_and_match_public_constants() {
        let ceilings = SqliteOperationLimits::HARD_CEILINGS;

        assert_eq!(
            ceilings.max_concurrent_operations,
            HARD_MAX_CONCURRENT_OPERATIONS
        );
        assert_eq!(
            ceilings.reserved_progress_operations,
            HARD_MAX_RESERVED_PROGRESS_OPERATIONS
        );
        assert_eq!(ceilings.acquire_timeout_ms, HARD_MAX_ACQUIRE_TIMEOUT_MS);
        assert!(ceilings.validate().is_ok());
    }

    #[test]
    fn every_field_rejects_zero() {
        let mutations: [LimitMutation; 3] = [
            ("max_concurrent_operations", |limits| {
                limits.max_concurrent_operations = 0;
            }),
            ("reserved_progress_operations", |limits| {
                limits.reserved_progress_operations = 0;
            }),
            ("acquire_timeout_ms", |limits| {
                limits.acquire_timeout_ms = 0;
            }),
        ];

        for (field, mutate) in mutations {
            let mut limits = SqliteOperationLimits::default();
            mutate(&mut limits);
            assert_eq!(
                limits.validate(),
                Err(SqliteOperationLimitsError::Zero { field })
            );
        }
    }

    #[test]
    fn every_field_rejects_values_above_its_hard_ceiling() {
        let mutations: [CeilingMutation; 3] = [
            (
                "max_concurrent_operations",
                HARD_MAX_CONCURRENT_OPERATIONS as u64,
                |limits| {
                    limits.max_concurrent_operations = HARD_MAX_CONCURRENT_OPERATIONS + 1;
                },
            ),
            (
                "reserved_progress_operations",
                HARD_MAX_RESERVED_PROGRESS_OPERATIONS as u64,
                |limits| {
                    limits.reserved_progress_operations = HARD_MAX_RESERVED_PROGRESS_OPERATIONS + 1;
                },
            ),
            (
                "acquire_timeout_ms",
                HARD_MAX_ACQUIRE_TIMEOUT_MS,
                |limits| limits.acquire_timeout_ms = HARD_MAX_ACQUIRE_TIMEOUT_MS + 1,
            ),
        ];

        for (field, hard_ceiling, mutate) in mutations {
            let mut limits = SqliteOperationLimits::default();
            mutate(&mut limits);
            assert_eq!(
                limits.validate(),
                Err(SqliteOperationLimitsError::ExceedsHardCeiling {
                    field,
                    value: hard_ceiling + 1,
                    hard_ceiling,
                })
            );
        }
    }

    #[test]
    fn progress_reservation_must_be_strictly_below_total() {
        for (max_concurrent_operations, reserved_progress_operations) in [(8, 8), (7, 8)] {
            let limits = SqliteOperationLimits {
                max_concurrent_operations,
                reserved_progress_operations,
                ..SqliteOperationLimits::default()
            };

            assert_eq!(
                limits.validate(),
                Err(SqliteOperationLimitsError::InvalidReservation {
                    reserved_progress_operations,
                    max_concurrent_operations,
                })
            );
        }
    }

    async fn wait_for_memory_waiters(limiter: &OperationLimiter, expected: usize) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while limiter.test_snapshot().1 != expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("memory waiter count did not converge");
    }

    #[tokio::test]
    async fn memory_progress_overtakes_an_existing_general_waiter() {
        let limiter = Arc::new(OperationLimiter::new(&SqliteOperationLimits {
            max_concurrent_operations: 3,
            reserved_progress_operations: 1,
            acquire_timeout_ms: 1_000,
        }));
        let owner = limiter
            .acquire(OperationClass::General, true)
            .await
            .unwrap();
        let general_limiter = Arc::clone(&limiter);
        let general =
            tokio::spawn(
                async move { general_limiter.acquire(OperationClass::General, true).await },
            );
        wait_for_memory_waiters(&limiter, 1).await;

        let progress_limiter = Arc::clone(&limiter);
        let progress = tokio::spawn(async move {
            progress_limiter
                .acquire(OperationClass::DurableProgress, true)
                .await
        });
        wait_for_memory_waiters(&limiter, 2).await;

        drop(owner);
        let progress_permits = progress.await.unwrap().unwrap();
        assert!(!general.is_finished());
        drop(progress_permits);
        let general_permits = general.await.unwrap().unwrap();
        drop(general_permits);
        assert_eq!(limiter.total.available_permits(), 3);
        assert_eq!(limiter.general.available_permits(), 2);
        assert_eq!(limiter.memory.available_permits(), 1);
    }

    #[tokio::test]
    async fn cancelling_a_memory_waiter_releases_partial_permits() {
        let limiter = Arc::new(OperationLimiter::new(&SqliteOperationLimits {
            max_concurrent_operations: 2,
            reserved_progress_operations: 1,
            acquire_timeout_ms: 1_000,
        }));
        let owner = limiter
            .acquire(OperationClass::General, true)
            .await
            .unwrap();
        let waiting_limiter = Arc::clone(&limiter);
        let waiter = tokio::spawn(async move {
            waiting_limiter
                .acquire(OperationClass::DurableProgress, true)
                .await
        });
        wait_for_memory_waiters(&limiter, 1).await;
        assert_eq!(limiter.total.available_permits(), 0);

        waiter.abort();
        assert!(matches!(waiter.await, Err(error) if error.is_cancelled()));
        wait_for_memory_waiters(&limiter, 0).await;
        assert_eq!(limiter.total.available_permits(), 1);

        drop(owner);
        assert_eq!(limiter.total.available_permits(), 2);
        assert_eq!(limiter.general.available_permits(), 1);
        assert_eq!(limiter.memory.available_permits(), 1);
    }

    #[tokio::test]
    async fn cancelling_the_last_progress_waiter_wakes_general_memory_work() {
        let limiter = Arc::new(OperationLimiter::new(&SqliteOperationLimits {
            max_concurrent_operations: 2,
            reserved_progress_operations: 1,
            acquire_timeout_ms: 1_000,
        }));
        let progress_waiter =
            ProgressWaiterGuard::new(&limiter.progress_memory_waiters, &limiter.memory_available);
        let general_limiter = Arc::clone(&limiter);
        let general =
            tokio::spawn(
                async move { general_limiter.acquire(OperationClass::General, true).await },
            );
        wait_for_memory_waiters(&limiter, 1).await;
        assert_eq!(limiter.memory.available_permits(), 1);
        assert!(!general.is_finished());

        drop(progress_waiter);
        let permits = tokio::time::timeout(Duration::from_millis(100), general)
            .await
            .expect("general waiter was not notified after progress cancellation")
            .unwrap()
            .unwrap();
        drop(permits);
        assert_eq!(limiter.total.available_permits(), 2);
        assert_eq!(limiter.general.available_permits(), 1);
        assert_eq!(limiter.memory.available_permits(), 1);
    }

    #[tokio::test]
    async fn total_and_memory_waits_share_one_deadline() {
        let limiter = Arc::new(OperationLimiter::new(&SqliteOperationLimits {
            max_concurrent_operations: 2,
            reserved_progress_operations: 1,
            acquire_timeout_ms: 100,
        }));
        let memory_owner = limiter
            .acquire(OperationClass::General, true)
            .await
            .unwrap();
        let total_owner = limiter
            .acquire(OperationClass::DurableProgress, false)
            .await
            .unwrap();
        let waiting_limiter = Arc::clone(&limiter);
        let waiter = tokio::spawn(async move {
            waiting_limiter
                .acquire(OperationClass::DurableProgress, true)
                .await
        });

        tokio::time::sleep(Duration::from_millis(70)).await;
        drop(total_owner);
        let result = tokio::time::timeout(Duration::from_millis(80), waiter)
            .await
            .expect("the memory gate reused a fresh timeout budget")
            .unwrap();
        assert!(matches!(
            result,
            Err(StorageError::OperationCapacityExceeded)
        ));
        assert_eq!(limiter.total.available_permits(), 1);

        drop(memory_owner);
        assert_eq!(limiter.total.available_permits(), 2);
        assert_eq!(limiter.general.available_permits(), 1);
        assert_eq!(limiter.memory.available_permits(), 1);
    }
}
