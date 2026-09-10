use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Raw provider usage for one model request.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub cost_micros: u64,
}

impl TokenUsage {
    #[must_use]
    pub const fn new(prompt_tokens: u64, completion_tokens: u64) -> Self {
        Self {
            prompt_tokens,
            completion_tokens,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            cost_micros: 0,
        }
    }

    #[must_use]
    pub const fn accounted_tokens(self) -> u64 {
        self.prompt_tokens.saturating_add(self.completion_tokens)
    }

    #[must_use]
    pub fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            prompt_tokens: self.prompt_tokens.checked_add(other.prompt_tokens)?,
            completion_tokens: self
                .completion_tokens
                .checked_add(other.completion_tokens)?,
            cache_read_tokens: self
                .cache_read_tokens
                .checked_add(other.cache_read_tokens)?,
            cache_write_tokens: self
                .cache_write_tokens
                .checked_add(other.cache_write_tokens)?,
            cost_micros: self.cost_micros.checked_add(other.cost_micros)?,
        })
    }
}

/// One append-only ledger entry.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UsageEntry {
    ordinal: u64,
    usage: TokenUsage,
}

impl UsageEntry {
    #[must_use]
    pub const fn ordinal(self) -> u64 {
        self.ordinal
    }

    #[must_use]
    pub const fn usage(self) -> TokenUsage {
        self.usage
    }
}

/// Accumulates provider usage while enforcing an optional prompt plus
/// completion token budget.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct UsageLedger {
    token_budget: Option<u64>,
    total: TokenUsage,
    entries: Vec<UsageEntry>,
}

impl UsageLedger {
    #[must_use]
    pub const fn new(token_budget: Option<u64>) -> Self {
        Self {
            token_budget,
            total: TokenUsage {
                prompt_tokens: 0,
                completion_tokens: 0,
                cache_read_tokens: 0,
                cache_write_tokens: 0,
                cost_micros: 0,
            },
            entries: Vec::new(),
        }
    }

    /// Appends usage if the resulting ledger remains within its token budget.
    /// The ledger is unchanged when this returns an error.
    ///
    /// # Errors
    ///
    /// Returns [`UsageLedgerError::TokenBudgetExceeded`] when prompt plus
    /// completion tokens exceed the configured budget, or
    /// [`UsageLedgerError::CounterOverflow`] if a counter cannot be summed.
    pub fn record(&mut self, usage: TokenUsage) -> Result<(), UsageLedgerError> {
        let used = self
            .total
            .prompt_tokens
            .checked_add(self.total.completion_tokens)
            .ok_or(UsageLedgerError::CounterOverflow)?;
        let requested = usage
            .prompt_tokens
            .checked_add(usage.completion_tokens)
            .ok_or(UsageLedgerError::CounterOverflow)?;
        let next_total = self
            .total
            .checked_add(usage)
            .ok_or(UsageLedgerError::CounterOverflow)?;
        let next_used = used
            .checked_add(requested)
            .ok_or(UsageLedgerError::CounterOverflow)?;

        if let Some(budget) = self.token_budget
            && next_used > budget
        {
            return Err(UsageLedgerError::TokenBudgetExceeded {
                budget,
                used,
                requested,
            });
        }

        let ordinal =
            u64::try_from(self.entries.len()).map_err(|_| UsageLedgerError::CounterOverflow)?;
        self.total = next_total;
        self.entries.push(UsageEntry { ordinal, usage });
        Ok(())
    }

    #[must_use]
    pub const fn token_budget(&self) -> Option<u64> {
        self.token_budget
    }

    #[must_use]
    pub const fn total(&self) -> TokenUsage {
        self.total
    }

    #[must_use]
    pub fn remaining_tokens(&self) -> Option<u64> {
        self.token_budget
            .map(|budget| budget.saturating_sub(self.total.accounted_tokens()))
    }

    #[must_use]
    pub fn entries(&self) -> &[UsageEntry] {
        &self.entries
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum UsageLedgerError {
    #[error("token budget exceeded: budget={budget}, used={used}, requested={requested}")]
    TokenBudgetExceeded {
        budget: u64,
        used: u64,
        requested: u64,
    },
    #[error("usage counter overflow")]
    CounterOverflow,
}

#[cfg(test)]
mod tests {
    use super::{TokenUsage, UsageLedger, UsageLedgerError};

    #[test]
    fn records_are_accumulated_by_category() {
        let mut ledger = UsageLedger::new(Some(20));
        let mut first = TokenUsage::new(5, 3);
        first.cache_read_tokens = 2;
        first.cost_micros = 7;
        ledger.record(first).expect("first usage fits");
        ledger
            .record(TokenUsage::new(4, 2))
            .expect("second usage fits");

        assert_eq!(ledger.total().prompt_tokens, 9);
        assert_eq!(ledger.total().completion_tokens, 5);
        assert_eq!(ledger.total().cache_read_tokens, 2);
        assert_eq!(ledger.total().cost_micros, 7);
        assert_eq!(ledger.entries().len(), 2);
        assert_eq!(ledger.entries()[1].ordinal(), 1);
        assert_eq!(ledger.remaining_tokens(), Some(6));
    }

    #[test]
    fn token_budget_overflow_does_not_append_usage() {
        let mut ledger = UsageLedger::new(Some(10));
        ledger
            .record(TokenUsage::new(7, 2))
            .expect("initial usage fits");

        let error = ledger
            .record(TokenUsage::new(1, 2))
            .expect_err("the second usage exceeds the budget");

        assert_eq!(
            error,
            UsageLedgerError::TokenBudgetExceeded {
                budget: 10,
                used: 9,
                requested: 3,
            }
        );
        assert_eq!(ledger.total().accounted_tokens(), 9);
        assert_eq!(ledger.entries().len(), 1);
    }
}
