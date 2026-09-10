use serde::{Deserialize, Serialize};

use crate::{CapabilityPolicy, IdempotencyMode};

/// The kind of operation for which a retry is being considered.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryOperation {
    ModelRequest,
    CapabilityCall,
}

/// Failure classes whose retryability is known by the domain layer.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryFailure {
    Transient,
    RateLimited,
    ServerError,
    ToolNotStarted,
    OutcomeUnknown,
    InvalidResponse,
    PolicyDenied,
    Canceled,
}

impl RetryFailure {
    #[must_use]
    pub const fn is_automatically_retryable(self, operation: RetryOperation) -> bool {
        match operation {
            RetryOperation::ModelRequest => {
                matches!(
                    self,
                    Self::Transient | Self::RateLimited | Self::ServerError
                )
            }
            RetryOperation::CapabilityCall => matches!(
                self,
                Self::Transient | Self::RateLimited | Self::ServerError | Self::ToolNotStarted
            ),
        }
    }
}

/// Inputs to the common retry policy function.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RetryRequest {
    pub operation: RetryOperation,
    pub idempotency_mode: Option<IdempotencyMode>,
    pub idempotency_key_present: bool,
    pub retry_count: u8,
    pub max_retries: u8,
    pub failure: RetryFailure,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RetryDecision {
    Retry { retry_number: u8 },
    DoNotRetry { reason: RetryReason },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryReason {
    AttemptsExhausted,
    CapabilityNotIdempotent,
    MissingIdempotencyKey,
    FailureNotRetryable,
    OutcomeUnknown,
}

/// Applies the pure retry decision used by both model and Capability paths.
#[must_use]
pub fn decide_retry(request: RetryRequest) -> RetryDecision {
    if request.retry_count >= request.max_retries {
        return RetryDecision::DoNotRetry {
            reason: RetryReason::AttemptsExhausted,
        };
    }

    if request.failure == RetryFailure::OutcomeUnknown {
        return RetryDecision::DoNotRetry {
            reason: RetryReason::OutcomeUnknown,
        };
    }

    if !request
        .failure
        .is_automatically_retryable(request.operation)
    {
        return RetryDecision::DoNotRetry {
            reason: RetryReason::FailureNotRetryable,
        };
    }

    if request.operation == RetryOperation::CapabilityCall {
        let mode = request
            .idempotency_mode
            .unwrap_or(IdempotencyMode::Unavailable);
        if !mode.allows_automatic_retry() {
            return RetryDecision::DoNotRetry {
                reason: RetryReason::CapabilityNotIdempotent,
            };
        }
        if !request.idempotency_key_present {
            return RetryDecision::DoNotRetry {
                reason: RetryReason::MissingIdempotencyKey,
            };
        }
    }

    RetryDecision::Retry {
        retry_number: request.retry_count + 1,
    }
}

/// Decides whether a Capability call may be retried automatically.
#[must_use]
pub fn decide_capability_retry(
    policy: &CapabilityPolicy,
    idempotency_key_present: bool,
    retry_count: u8,
    max_retries: u8,
    failure: RetryFailure,
) -> RetryDecision {
    decide_retry(RetryRequest {
        operation: RetryOperation::CapabilityCall,
        idempotency_mode: Some(policy.idempotency_mode),
        idempotency_key_present,
        retry_count,
        max_retries,
        failure,
    })
}

/// Decides whether a transient model request failure may be retried.
#[must_use]
pub fn decide_model_retry(
    retry_count: u8,
    max_retries: u8,
    failure: RetryFailure,
) -> RetryDecision {
    decide_retry(RetryRequest {
        operation: RetryOperation::ModelRequest,
        idempotency_mode: None,
        idempotency_key_present: false,
        retry_count,
        max_retries,
        failure,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        RetryDecision, RetryFailure, RetryReason, decide_capability_retry, decide_model_retry,
    };
    use crate::{CapabilityPolicy, IdempotencyMode, RiskLevel};

    fn policy(idempotency_mode: IdempotencyMode) -> CapabilityPolicy {
        CapabilityPolicy {
            idempotency_mode,
            risk_level: RiskLevel::Low,
            approval_required: false,
            timeout_seconds: 30,
        }
    }

    #[test]
    fn non_idempotent_capability_is_never_automatically_retried() {
        assert_eq!(
            decide_capability_retry(
                &policy(IdempotencyMode::Unavailable),
                true,
                0,
                2,
                RetryFailure::Transient,
            ),
            RetryDecision::DoNotRetry {
                reason: RetryReason::CapabilityNotIdempotent,
            }
        );
    }

    #[test]
    fn idempotent_capability_with_key_can_retry_until_budget() {
        assert_eq!(
            decide_capability_retry(
                &policy(IdempotencyMode::Supported),
                true,
                1,
                2,
                RetryFailure::ToolNotStarted,
            ),
            RetryDecision::Retry { retry_number: 2 }
        );
        assert_eq!(
            decide_model_retry(2, 2, RetryFailure::Transient),
            RetryDecision::DoNotRetry {
                reason: RetryReason::AttemptsExhausted,
            }
        );
    }
}
