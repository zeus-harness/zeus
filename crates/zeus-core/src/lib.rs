//! IO-free domain model for Zeus.

mod capability;
mod event;
mod id;
mod message;
mod retry;
mod role;
mod run;
mod session;
mod tool;
mod usage;
mod work_item;
mod workflow;

pub use capability::{CapabilityPolicy, IdempotencyMode, RiskLevel};
pub use event::{
    ActorKind, ActorRef, EventEnvelope, SessionEvent, SessionEventKind, ToolPairError,
    synthesize_canceled_tool_results, validate_tool_pairs,
};
pub use id::{
    AgentVersionId, CapabilityId, EventId, OrganizationId, RunId, SessionId, WorkItemId,
    WorkflowVersionId, WorkspaceId,
};
pub use message::{CANCELED_TOOL_RESULT_CODE, ModelMessage, ModelRole, ToolCall, ToolResult};
pub use retry::{
    RetryDecision, RetryFailure, RetryOperation, RetryReason, RetryRequest,
    decide_capability_retry, decide_model_retry, decide_retry,
};
pub use role::{OrganizationRole, Permission, WorkspaceRole};
pub use run::{RunLimits, RunState, RunTransition, TransitionError};
pub use session::{SessionContext, SessionContextBuilder, SessionContextError};
pub use tool::{ToolPipeline, ToolPipelineError, ToolPipelinePhase};
pub use usage::{TokenUsage, UsageEntry, UsageLedger, UsageLedgerError};
pub use work_item::{WorkItemState, WorkItemStateParseError, WorkItemTransitionError};
pub use workflow::{ApprovalPolicy, ExperiencePolicy, RetryPolicy, WorkflowVersionSpec};
