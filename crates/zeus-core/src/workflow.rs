use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{AgentVersionId, CapabilityId, RunLimits};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct WorkflowVersionSpec {
    pub agent_version_id: AgentVersionId,
    pub model_profile_id: uuid::Uuid,
    pub input_schema: Value,
    pub output_schema: Value,
    pub allowed_capabilities: Vec<CapabilityId>,
    pub approval_policy: ApprovalPolicy,
    pub experience_policy: ExperiencePolicy,
    pub limits: RunLimits,
    pub retry_policy: RetryPolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ApprovalPolicy {
    pub require_high_risk: bool,
    pub fail_on_denial: bool,
}

impl Default for ApprovalPolicy {
    fn default() -> Self {
        Self {
            require_high_risk: true,
            fail_on_denial: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExperiencePolicy {
    pub include_workspace: bool,
    pub include_organization: bool,
    pub max_entries: u16,
}

impl Default for ExperiencePolicy {
    fn default() -> Self {
        Self {
            include_workspace: true,
            include_organization: true,
            max_entries: 8,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RetryPolicy {
    pub model_network_attempts: u8,
    pub capability_attempts: u8,
}
