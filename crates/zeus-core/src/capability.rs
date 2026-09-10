use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdempotencyMode {
    Required,
    Supported,
    Unavailable,
}

impl IdempotencyMode {
    #[must_use]
    pub const fn allows_automatic_retry(self) -> bool {
        matches!(self, Self::Required | Self::Supported)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CapabilityPolicy {
    pub idempotency_mode: IdempotencyMode,
    pub risk_level: RiskLevel,
    pub approval_required: bool,
    pub timeout_seconds: u32,
}

impl CapabilityPolicy {
    #[must_use]
    pub const fn requires_approval(&self) -> bool {
        self.approval_required || matches!(self.risk_level, RiskLevel::High)
    }
}
