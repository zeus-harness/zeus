//! Bounded asynchronous execution for password hashing.

use std::{fmt, future::Future, sync::Arc};

use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use tokio::sync::Semaphore;

use crate::password::{
    NormalizedPassword, PasswordError, PasswordPolicy, PasswordVerification,
    hash_normalized_password, normalize_password, verify_normalized_password,
};

/// The maximum number of Argon2 operations that may run at once.
pub const MAX_CONCURRENT_HASHES: usize = 4;

const DUMMY_WORK_INPUT: &str = "zeus unknown account timing work value";

/// Stable failures returned by the bounded password-hash executor.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PasswordExecutorError {
    /// All active and waiting slots are occupied.
    #[error("password hash queue is full")]
    QueueFull,
    /// The configured queue size cannot be represented with the four active slots.
    #[error("password hash queue capacity is invalid")]
    InvalidQueueCapacity,
    /// The requested active concurrency is outside the supported one-to-four range.
    #[error("password hash concurrency is invalid")]
    InvalidConcurrency,
    /// Password normalization or policy validation failed.
    #[error("password input is invalid")]
    Password(#[source] PasswordError),
    /// The Tokio blocking task could not be joined.
    #[error("password hashing task failed")]
    TaskFailed,
    /// The executor's internal semaphore was closed unexpectedly.
    #[error("password hash executor is closed")]
    ExecutorClosed,
}

impl PasswordExecutorError {
    /// Returns the stable, transport-independent error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::QueueFull => "password_hash_queue_full",
            Self::InvalidQueueCapacity => "invalid_password_hash_queue_capacity",
            Self::InvalidConcurrency => "invalid_password_hash_concurrency",
            Self::Password(error) => error.code(),
            Self::TaskFailed => "password_hash_task_failed",
            Self::ExecutorClosed => "password_hash_executor_closed",
        }
    }
}

/// A password hasher with four active slots and a bounded waiting queue.
///
/// A call reserves one of `4 + queue_capacity` slots before it waits for an
/// active slot. The Argon2 operation itself always runs in
/// [`tokio::task::spawn_blocking`], so Tokio worker threads do not perform the
/// CPU- and memory-intensive hash directly.
#[derive(Clone)]
pub struct PasswordHashExecutor {
    active: Arc<Semaphore>,
    capacity: Arc<Semaphore>,
    queue_capacity: usize,
    max_concurrency: usize,
    policy: PasswordPolicy,
}

impl PasswordHashExecutor {
    /// Creates an executor with bounded active and waiting capacities.
    ///
    /// `max_concurrency` must be between one and four. `max_waiters` is the
    /// number of additional requests that may wait for an active slot; a zero
    /// value is valid and rejects the next request immediately.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordExecutorError::InvalidConcurrency`] for a value
    /// outside one through four, or [`PasswordExecutorError::InvalidQueueCapacity`]
    /// on arithmetic overflow.
    pub fn new(
        max_concurrency: usize,
        max_waiters: usize,
        policy: PasswordPolicy,
    ) -> Result<Self, PasswordExecutorError> {
        if !(1..=MAX_CONCURRENT_HASHES).contains(&max_concurrency) {
            return Err(PasswordExecutorError::InvalidConcurrency);
        }
        let total_capacity = max_concurrency
            .checked_add(max_waiters)
            .ok_or(PasswordExecutorError::InvalidQueueCapacity)?;
        if total_capacity > Semaphore::MAX_PERMITS {
            return Err(PasswordExecutorError::InvalidQueueCapacity);
        }
        Ok(Self {
            active: Arc::new(Semaphore::new(max_concurrency)),
            capacity: Arc::new(Semaphore::new(total_capacity)),
            queue_capacity: max_waiters,
            max_concurrency,
            policy,
        })
    }

    /// Creates a four-worker executor using the supplied password policy.
    ///
    /// # Errors
    ///
    /// Returns a stable configuration error when `max_waiters` overflows the
    /// total slot count.
    pub fn with_policy(
        max_waiters: usize,
        policy: PasswordPolicy,
    ) -> Result<Self, PasswordExecutorError> {
        Self::new(MAX_CONCURRENT_HASHES, max_waiters, policy)
    }

    /// Creates a four-worker executor without a weak-password list.
    ///
    /// # Errors
    ///
    /// Returns a stable configuration error on slot-count overflow.
    pub fn with_queue_capacity(max_waiters: usize) -> Result<Self, PasswordExecutorError> {
        Self::new(
            MAX_CONCURRENT_HASHES,
            max_waiters,
            PasswordPolicy::default(),
        )
    }

    /// Returns the configured number of waiting slots.
    #[must_use]
    pub const fn queue_capacity(&self) -> usize {
        self.queue_capacity
    }

    /// Returns the configured maximum number of active Argon2 operations.
    #[must_use]
    pub const fn max_concurrency(&self) -> usize {
        self.max_concurrency
    }

    /// Reserves a bounded slot and returns a future for the hash operation.
    ///
    /// Reservation is synchronous, so a caller can reject a full queue before
    /// spawning or awaiting a task. Dropping the returned future releases its
    /// reservation. The password is normalized before a slot is reserved.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordExecutorError::QueueFull`] when all active and waiting
    /// slots are occupied, or a password validation error for invalid input.
    pub fn try_hash_password(
        &self,
        password: &str,
    ) -> Result<
        impl Future<Output = Result<String, PasswordExecutorError>> + Send + 'static,
        PasswordExecutorError,
    > {
        let normalized = self
            .policy
            .validate(password)
            .map_err(PasswordExecutorError::Password)?;
        let capacity_permit = Arc::clone(&self.capacity)
            .try_acquire_owned()
            .map_err(|_| PasswordExecutorError::QueueFull)?;
        let active = Arc::clone(&self.active);
        Ok(async move {
            let _capacity_permit = capacity_permit;
            let _active_permit = active
                .acquire_owned()
                .await
                .map_err(|_| PasswordExecutorError::ExecutorClosed)?;
            spawn_hash(normalized).await
        })
    }

    /// Hashes a secret password using the bounded executor.
    ///
    /// The input is consumed so callers can keep password exposure explicit.
    /// Argon2 runs only inside `spawn_blocking`.
    ///
    /// # Errors
    ///
    /// Returns a stable validation, queue, executor, or task error.
    pub async fn hash(&self, password: SecretString) -> Result<String, PasswordExecutorError> {
        let normalized = self
            .policy
            .validate(password.expose_secret())
            .map_err(PasswordExecutorError::Password)?;
        let (_capacity_permit, _active_permit) = self.acquire().await?;
        spawn_hash(normalized).await
    }

    /// Verifies a secret password against a stored PHC string.
    ///
    /// Verification is also bounded because Argon2 verification is a hashing
    /// operation. The stored PHC string contains no plaintext password.
    ///
    /// # Errors
    ///
    /// Returns a stable validation, invalid-hash, queue, executor, or task error.
    pub async fn verify(
        &self,
        password: SecretString,
        encoded_hash: String,
    ) -> Result<PasswordVerification, PasswordExecutorError> {
        let normalized = normalize_password(password.expose_secret())
            .map_err(PasswordExecutorError::Password)?;
        let (_capacity_permit, _active_permit) = self.acquire().await?;
        tokio::task::spawn_blocking(move || verify_normalized_password(&normalized, &encoded_hash))
            .await
            .map_err(|_| PasswordExecutorError::TaskFailed)?
            .map_err(PasswordExecutorError::Password)
    }

    /// Consumes one bounded Argon2 operation for an unknown account.
    ///
    /// The fixed input bypasses the deployment weak-password set so changes to
    /// that set cannot make unknown-account requests observably cheaper.
    ///
    /// # Errors
    ///
    /// Returns a stable queue, executor, randomness, hashing, or task error.
    pub async fn consume_dummy_work(&self) -> Result<(), PasswordExecutorError> {
        let normalized =
            normalize_password(DUMMY_WORK_INPUT).map_err(PasswordExecutorError::Password)?;
        let (_capacity_permit, _active_permit) = self.acquire().await?;
        spawn_hash(normalized).await.map(drop)
    }

    async fn acquire(
        &self,
    ) -> Result<
        (
            tokio::sync::OwnedSemaphorePermit,
            tokio::sync::OwnedSemaphorePermit,
        ),
        PasswordExecutorError,
    > {
        let capacity_permit = Arc::clone(&self.capacity)
            .try_acquire_owned()
            .map_err(|_| PasswordExecutorError::QueueFull)?;
        let active_permit = Arc::clone(&self.active)
            .acquire_owned()
            .await
            .map_err(|_| PasswordExecutorError::ExecutorClosed)?;
        Ok((capacity_permit, active_permit))
    }

    /// Hashes a password while respecting the active and waiting limits.
    ///
    /// # Errors
    ///
    /// Returns a stable validation, queue, executor, or task error.
    pub async fn hash_password(&self, password: &str) -> Result<String, PasswordExecutorError> {
        self.try_hash_password(password)?.await
    }
}

impl fmt::Debug for PasswordHashExecutor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PasswordHashExecutor")
            .field("max_concurrent_hashes", &MAX_CONCURRENT_HASHES)
            .field("max_concurrency", &self.max_concurrency)
            .field("queue_capacity", &self.queue_capacity)
            .finish_non_exhaustive()
    }
}

async fn spawn_hash(password: NormalizedPassword) -> Result<String, PasswordExecutorError> {
    tokio::task::spawn_blocking(move || hash_normalized_password(&password))
        .await
        .map_err(|_| PasswordExecutorError::TaskFailed)?
        .map_err(PasswordExecutorError::Password)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use secrecy::SecretString;

    use super::{
        DUMMY_WORK_INPUT, MAX_CONCURRENT_HASHES, PasswordExecutorError, PasswordHashExecutor,
    };
    use crate::{PasswordPolicy, WeakPasswordSet};

    const PASSWORD: &str = "correct horse battery staple";

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn queue_reservation_is_bounded_and_reports_full() {
        let executor =
            PasswordHashExecutor::new(4, 1, PasswordPolicy::default()).expect("executor");
        let mut pending = Vec::new();
        for _ in 0..=MAX_CONCURRENT_HASHES {
            pending.push(executor.try_hash_password(PASSWORD).expect("slot"));
        }

        assert!(matches!(
            executor.try_hash_password(PASSWORD),
            Err(PasswordExecutorError::QueueFull)
        ));
        drop(pending);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn hashing_is_available_through_spawn_blocking_path() {
        let executor = Arc::new(
            crate::PasswordExecutor::new(4, 0, PasswordPolicy::default()).expect("executor"),
        );
        let first = {
            let executor = Arc::clone(&executor);
            tokio::spawn(async move { executor.hash(SecretString::from(PASSWORD)).await })
        };
        let encoded = first.await.expect("join").expect("hash");
        assert!(encoded.starts_with("$argon2id$v=19$m=65536,t=3,p=4$"));

        let verified = executor
            .verify(SecretString::from(PASSWORD), encoded)
            .await
            .expect("verify");
        assert!(verified.valid);
        assert!(!verified.needs_rehash);
    }

    #[tokio::test]
    async fn dummy_work_is_not_blocked_by_the_deployment_weak_password_set() {
        let executor = PasswordHashExecutor::new(
            1,
            0,
            PasswordPolicy::with_weak_passwords(WeakPasswordSet::new([DUMMY_WORK_INPUT])),
        )
        .expect("executor");

        executor.consume_dummy_work().await.expect("dummy work");
    }

    #[test]
    fn concurrency_is_capped_at_four() {
        assert!(matches!(
            PasswordHashExecutor::new(0, 0, PasswordPolicy::default()),
            Err(PasswordExecutorError::InvalidConcurrency)
        ));
        assert!(matches!(
            PasswordHashExecutor::new(5, 0, PasswordPolicy::default()),
            Err(PasswordExecutorError::InvalidConcurrency)
        ));
        assert!(matches!(
            PasswordHashExecutor::new(4, usize::MAX, PasswordPolicy::default()),
            Err(PasswordExecutorError::InvalidQueueCapacity)
        ));
    }
}
