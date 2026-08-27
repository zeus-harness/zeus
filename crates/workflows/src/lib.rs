//! Pure, durable state transitions for one sequential Zeus agent turn.
//!
//! This crate performs no I/O. Callers persist the returned [`Transition`]
//! before acting on its optional [`ExternalCall`]. That ordering is the core
//! safety contract: a model or tool is never invoked until its `started` state
//! is durable, and an unknown result can only move the turn to
//! [`AgentStatus::NeedsAttention`].

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Persisted schema version for [`State`].
pub const STATE_SCHEMA_VERSION: u16 = 1;

const KIBIBYTE: u64 = 1024;

/// Hard resource limits copied into each durable agent turn.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Maximum model invocations admitted for one turn.
    pub max_model_steps: u32,
    /// Maximum model-proposed tool calls admitted for one turn.
    pub max_tool_calls: u32,
    /// Maximum simultaneously pending approvals.
    pub max_pending_approvals: u32,
    /// Maximum serialized bytes in one model-visible tool result.
    pub max_tool_result_bytes: u64,
    /// Maximum cumulative serialized tool-result bytes for one turn.
    pub max_turn_tool_result_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_model_steps: 8,
            max_tool_calls: 4,
            max_pending_approvals: 1,
            max_tool_result_bytes: 64 * KIBIBYTE,
            max_turn_tool_result_bytes: 128 * KIBIBYTE,
        }
    }
}

impl Limits {
    fn validate(&self) -> Result<(), Error> {
        if self.max_model_steps == 0 {
            return Err(Error::InvalidLimits {
                field: LimitField::ModelSteps,
            });
        }
        if self.max_tool_calls == 0 {
            return Err(Error::InvalidLimits {
                field: LimitField::ToolCalls,
            });
        }
        if self.max_pending_approvals == 0 {
            return Err(Error::InvalidLimits {
                field: LimitField::PendingApprovals,
            });
        }
        if self.max_tool_result_bytes == 0
            || self.max_tool_result_bytes > self.max_turn_tool_result_bytes
        {
            return Err(Error::InvalidLimits {
                field: LimitField::ToolResultBytes,
            });
        }
        Ok(())
    }
}

/// Durable phase of one agent turn.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    ModelQueued,
    ModelStarted,
    WaitingApproval,
    ToolQueued,
    ToolStarted,
    ContinuationQueued,
    Completed,
    Failed,
    NeedsAttention,
}

/// Stable terminal cause retained with failed or uncertain turns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalReason {
    ModelFailed,
    AuthorizationRevoked,
    ContinuationUnavailable,
    ModelOutcomeUnknown,
    ToolOutcomeUnknown,
    ModelStepLimitReached,
    ToolCallLimitReached,
    PendingApprovalLimitReached,
    ToolResultBytesLimitReached,
}

/// Policy disposition for exactly one model-proposed tool call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProposalDisposition {
    Allow,
    RequireApproval,
    Deny {
        /// Bytes in the structured policy-denied result for the next model step.
        result_bytes: u64,
    },
}

/// Known executor terminal class. Unknown outcomes use a separate command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCompletionKind {
    Succeeded,
    Failed,
    Cancelled,
    NotDispatched,
}

/// Structured result class emitted for durable model context.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KnownToolResultKind {
    Succeeded,
    Failed,
    Cancelled,
    NotDispatched,
    PolicyDenied,
    ApprovalRejected,
}

/// Bounded structured tool result admitted to the next model step.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnownToolResult {
    pub kind: KnownToolResultKind,
    pub serialized_bytes: u64,
}

/// One input to the reducer. Commands describe durable facts, not I/O work.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    /// Admit the next model invocation and durably mark it started.
    StartModel,
    /// Record a non-empty final assistant text.
    ModelFinal { content_bytes: u64 },
    /// Record exactly one tool proposal from the currently started model step.
    ModelToolProposal { disposition: ProposalDisposition },
    /// Record a known model failure for which retry is not part of this turn.
    ModelFailed,
    /// Record that a started model invocation has no trustworthy result.
    ModelOutcomeUnknown,
    /// Current Session authority disappeared after work was queued but before
    /// any external model/tool operation was invoked.
    AuthorizationRevoked,
    /// The immutable deployment manifest is missing or no longer matches the
    /// executable runtime. Callers may use this only before invoking the
    /// external operation authorized by the current durable phase.
    DeploymentUnavailable,
    /// The immutable knowledge corpus, selection snapshot, or Agent binding is
    /// missing or no longer verifies. Callers may use this only before the
    /// current external model/tool operation is invoked.
    KnowledgeUnavailable,
    /// Record an allow-once approval and queue the already-bound tool call.
    ApprovalApproved,
    /// Record a rejection as a structured non-dispatch result.
    ApprovalRejected { result_bytes: u64 },
    /// Admit the queued tool invocation and durably mark it started.
    StartTool,
    /// Record a known tool result and queue model continuation.
    ToolResultKnown {
        kind: ToolCompletionKind,
        result_bytes: u64,
    },
    /// A known result was committed, but no bounded provider continuation can
    /// represent it. The external outcome remains known and is never retried.
    ContinuationUnavailable,
    /// Record that a started tool invocation has no trustworthy result.
    ToolOutcomeUnknown,
}

impl Command {
    fn kind(&self) -> CommandKind {
        match self {
            Self::StartModel => CommandKind::StartModel,
            Self::ModelFinal { .. } => CommandKind::ModelFinal,
            Self::ModelToolProposal { .. } => CommandKind::ModelToolProposal,
            Self::ModelFailed => CommandKind::ModelFailed,
            Self::ModelOutcomeUnknown => CommandKind::ModelOutcomeUnknown,
            Self::AuthorizationRevoked => CommandKind::AuthorizationRevoked,
            Self::DeploymentUnavailable => CommandKind::DeploymentUnavailable,
            Self::KnowledgeUnavailable => CommandKind::KnowledgeUnavailable,
            Self::ApprovalApproved => CommandKind::ApprovalApproved,
            Self::ApprovalRejected { .. } => CommandKind::ApprovalRejected,
            Self::StartTool => CommandKind::StartTool,
            Self::ToolResultKnown { .. } => CommandKind::ToolResultKnown,
            Self::ContinuationUnavailable => CommandKind::ContinuationUnavailable,
            Self::ToolOutcomeUnknown => CommandKind::ToolOutcomeUnknown,
        }
    }
}

/// External operation authorized only after the transition has been persisted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExternalCall {
    Model { step: u32 },
    Tool { call: u32 },
}

/// Complete output of one pure state reduction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transition {
    from: AgentStatus,
    state: State,
    external_call: Option<ExternalCall>,
    emitted_result: Option<KnownToolResult>,
}

impl Transition {
    pub const fn from(&self) -> AgentStatus {
        self.from
    }

    pub const fn state(&self) -> &State {
        &self.state
    }

    pub const fn external_call(&self) -> Option<&ExternalCall> {
        self.external_call.as_ref()
    }

    pub const fn emitted_result(&self) -> Option<&KnownToolResult> {
        self.emitted_result.as_ref()
    }

    pub fn into_state(self) -> State {
        self.state
    }
}

/// Durable counters and phase for one sequential agent turn.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    schema_version: u16,
    limits: Limits,
    status: AgentStatus,
    model_steps: u32,
    tool_calls: u32,
    pending_approvals: u32,
    tool_result_bytes: u64,
    terminal_reason: Option<TerminalReason>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Limits::default()).expect("default agent-loop limits are valid")
    }
}

impl State {
    /// Construct a fresh turn with immutable per-turn limits.
    pub fn new(limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        Ok(Self {
            schema_version: STATE_SCHEMA_VERSION,
            limits,
            status: AgentStatus::ModelQueued,
            model_steps: 0,
            tool_calls: 0,
            pending_approvals: 0,
            tool_result_bytes: 0,
            terminal_reason: None,
        })
    }

    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub const fn limits(&self) -> &Limits {
        &self.limits
    }

    pub const fn status(&self) -> AgentStatus {
        self.status
    }

    pub const fn model_steps(&self) -> u32 {
        self.model_steps
    }

    pub const fn tool_calls(&self) -> u32 {
        self.tool_calls
    }

    pub const fn pending_approvals(&self) -> u32 {
        self.pending_approvals
    }

    pub const fn tool_result_bytes(&self) -> u64 {
        self.tool_result_bytes
    }

    pub const fn terminal_reason(&self) -> Option<TerminalReason> {
        self.terminal_reason
    }

    /// Validate a deserialized state before reducer use.
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema_version != STATE_SCHEMA_VERSION {
            return Err(Error::UnsupportedStateSchemaVersion {
                version: self.schema_version,
            });
        }
        self.limits.validate()?;
        if self.model_steps > self.limits.max_model_steps
            || self.tool_calls > self.limits.max_tool_calls
            || self.pending_approvals > self.limits.max_pending_approvals
            || self.tool_result_bytes > self.limits.max_turn_tool_result_bytes
        {
            return Err(Error::InvalidState {
                invariant: StateInvariant::CounterAboveLimit,
            });
        }
        if self.tool_calls == 0 && self.tool_result_bytes != 0 {
            return Err(Error::InvalidState {
                invariant: StateInvariant::ResultWithoutToolCall,
            });
        }

        match (self.status, self.terminal_reason) {
            (
                AgentStatus::Failed,
                Some(
                    TerminalReason::ModelFailed
                    | TerminalReason::AuthorizationRevoked
                    | TerminalReason::ContinuationUnavailable
                    | TerminalReason::ModelStepLimitReached
                    | TerminalReason::ToolCallLimitReached
                    | TerminalReason::PendingApprovalLimitReached
                    | TerminalReason::ToolResultBytesLimitReached,
                ),
            )
            | (
                AgentStatus::NeedsAttention,
                Some(TerminalReason::ModelOutcomeUnknown | TerminalReason::ToolOutcomeUnknown),
            )
            | (
                AgentStatus::ModelQueued
                | AgentStatus::ModelStarted
                | AgentStatus::WaitingApproval
                | AgentStatus::ToolQueued
                | AgentStatus::ToolStarted
                | AgentStatus::ContinuationQueued
                | AgentStatus::Completed,
                None,
            ) => {}
            _ => {
                return Err(Error::InvalidState {
                    invariant: StateInvariant::TerminalReasonMismatch,
                });
            }
        }

        if self.status == AgentStatus::ModelQueued
            && (self.model_steps != 0
                || self.tool_calls != 0
                || self.pending_approvals != 0
                || self.tool_result_bytes != 0)
        {
            return Err(Error::InvalidState {
                invariant: StateInvariant::PhaseCounterMismatch,
            });
        }
        if self.status != AgentStatus::ModelQueued
            && self.model_steps == 0
            && !matches!(
                (self.status, self.terminal_reason),
                (
                    AgentStatus::Failed,
                    Some(TerminalReason::AuthorizationRevoked)
                )
            )
        {
            return Err(Error::InvalidState {
                invariant: StateInvariant::PhaseCounterMismatch,
            });
        }
        if matches!(
            self.status,
            AgentStatus::WaitingApproval | AgentStatus::ToolQueued | AgentStatus::ToolStarted
        ) && self.tool_calls == 0
        {
            return Err(Error::InvalidState {
                invariant: StateInvariant::PhaseCounterMismatch,
            });
        }
        if self.status == AgentStatus::WaitingApproval {
            if self.pending_approvals != 1 {
                return Err(Error::InvalidState {
                    invariant: StateInvariant::PendingApprovalMismatch,
                });
            }
        } else if self.pending_approvals != 0 {
            return Err(Error::InvalidState {
                invariant: StateInvariant::PendingApprovalMismatch,
            });
        }
        Ok(())
    }
}

/// Apply one command without performing I/O or mutating the input state.
pub fn reduce(state: &State, command: Command) -> Result<Transition, Error> {
    state.validate()?;
    let command_kind = command.kind();
    match command {
        Command::StartModel => start_model(state, command_kind),
        Command::ModelFinal { content_bytes } => {
            require_status(state, AgentStatus::ModelStarted, command_kind)?;
            if content_bytes == 0 {
                return Err(Error::EmptyFinalText);
            }
            next_transition(state, AgentStatus::Completed, None, None, None, None)
        }
        Command::ModelToolProposal { disposition } => {
            model_tool_proposal(state, command_kind, disposition)
        }
        Command::ModelFailed => {
            require_status(state, AgentStatus::ModelStarted, command_kind)?;
            next_transition(
                state,
                AgentStatus::Failed,
                Some(TerminalReason::ModelFailed),
                None,
                None,
                None,
            )
        }
        Command::ModelOutcomeUnknown => {
            require_status(state, AgentStatus::ModelStarted, command_kind)?;
            next_transition(
                state,
                AgentStatus::NeedsAttention,
                Some(TerminalReason::ModelOutcomeUnknown),
                None,
                None,
                None,
            )
        }
        Command::AuthorizationRevoked => {
            require_one_of(
                state,
                &[
                    AgentStatus::ModelQueued,
                    AgentStatus::ModelStarted,
                    AgentStatus::ToolQueued,
                    AgentStatus::ToolStarted,
                ],
                command_kind,
            )?;
            next_transition(
                state,
                AgentStatus::Failed,
                Some(TerminalReason::AuthorizationRevoked),
                None,
                None,
                None,
            )
        }
        Command::DeploymentUnavailable => {
            require_one_of(
                state,
                &[
                    AgentStatus::ModelQueued,
                    AgentStatus::ModelStarted,
                    AgentStatus::WaitingApproval,
                    AgentStatus::ToolQueued,
                    AgentStatus::ToolStarted,
                    AgentStatus::ContinuationQueued,
                ],
                command_kind,
            )?;
            next_transition(
                state,
                AgentStatus::Failed,
                // A deployment manifest is durable execution authority. Reuse
                // the existing authorization terminal class so upgraded v17
                // databases and fresh databases persist the same state shape;
                // callers retain the precise `deployment_unavailable` code in
                // the terminal error envelope.
                Some(TerminalReason::AuthorizationRevoked),
                Some(0),
                None,
                None,
            )
        }
        Command::KnowledgeUnavailable => {
            require_one_of(
                state,
                &[
                    AgentStatus::ModelQueued,
                    AgentStatus::ModelStarted,
                    AgentStatus::WaitingApproval,
                    AgentStatus::ToolQueued,
                    AgentStatus::ToolStarted,
                    AgentStatus::ContinuationQueued,
                ],
                command_kind,
            )?;
            next_transition(
                state,
                AgentStatus::Failed,
                // The durable error envelope retains the precise
                // knowledge_unavailable code. Reusing the established
                // pre-release authorization terminal class preserves the
                // existing workflow-state schema for upgraded databases.
                Some(TerminalReason::AuthorizationRevoked),
                Some(0),
                None,
                None,
            )
        }
        Command::ApprovalApproved => {
            require_status(state, AgentStatus::WaitingApproval, command_kind)?;
            next_transition(state, AgentStatus::ToolQueued, None, Some(0), None, None)
        }
        Command::ApprovalRejected { result_bytes } => {
            require_status(state, AgentStatus::WaitingApproval, command_kind)?;
            known_result_transition(
                state,
                KnownToolResultKind::ApprovalRejected,
                result_bytes,
                Some(0),
            )
        }
        Command::StartTool => {
            require_status(state, AgentStatus::ToolQueued, command_kind)?;
            next_transition(
                state,
                AgentStatus::ToolStarted,
                None,
                None,
                Some(ExternalCall::Tool {
                    call: state.tool_calls,
                }),
                None,
            )
        }
        Command::ToolResultKnown { kind, result_bytes } => {
            require_status(state, AgentStatus::ToolStarted, command_kind)?;
            known_result_transition(state, completion_result_kind(kind), result_bytes, None)
        }
        Command::ContinuationUnavailable => {
            require_status(state, AgentStatus::ContinuationQueued, command_kind)?;
            next_transition(
                state,
                AgentStatus::Failed,
                Some(TerminalReason::ContinuationUnavailable),
                None,
                None,
                None,
            )
        }
        Command::ToolOutcomeUnknown => {
            require_status(state, AgentStatus::ToolStarted, command_kind)?;
            next_transition(
                state,
                AgentStatus::NeedsAttention,
                Some(TerminalReason::ToolOutcomeUnknown),
                None,
                None,
                None,
            )
        }
    }
}

fn start_model(state: &State, command: CommandKind) -> Result<Transition, Error> {
    require_one_of(
        state,
        &[AgentStatus::ModelQueued, AgentStatus::ContinuationQueued],
        command,
    )?;
    let next_step = state
        .model_steps
        .checked_add(1)
        .ok_or(Error::CounterOverflow {
            counter: Counter::ModelSteps,
        })?;
    if next_step > state.limits.max_model_steps {
        return next_transition(
            state,
            AgentStatus::Failed,
            Some(TerminalReason::ModelStepLimitReached),
            None,
            None,
            None,
        );
    }
    next_transition(
        state,
        AgentStatus::ModelStarted,
        None,
        None,
        Some(ExternalCall::Model { step: next_step }),
        Some(next_step),
    )
}

fn model_tool_proposal(
    state: &State,
    command: CommandKind,
    disposition: ProposalDisposition,
) -> Result<Transition, Error> {
    require_status(state, AgentStatus::ModelStarted, command)?;
    let next_call = state
        .tool_calls
        .checked_add(1)
        .ok_or(Error::CounterOverflow {
            counter: Counter::ToolCalls,
        })?;
    if next_call > state.limits.max_tool_calls {
        return next_transition(
            state,
            AgentStatus::Failed,
            Some(TerminalReason::ToolCallLimitReached),
            None,
            None,
            None,
        );
    }

    match disposition {
        ProposalDisposition::Allow => {
            next_transition_with_tool_call(state, next_call, AgentStatus::ToolQueued, None)
        }
        ProposalDisposition::RequireApproval => {
            let pending = state
                .pending_approvals
                .checked_add(1)
                .ok_or(Error::CounterOverflow {
                    counter: Counter::PendingApprovals,
                })?;
            if pending > state.limits.max_pending_approvals {
                return next_transition(
                    state,
                    AgentStatus::Failed,
                    Some(TerminalReason::PendingApprovalLimitReached),
                    None,
                    None,
                    None,
                );
            }
            next_transition_with_tool_call(
                state,
                next_call,
                AgentStatus::WaitingApproval,
                Some(pending),
            )
        }
        ProposalDisposition::Deny { result_bytes } => {
            let mut proposed = state.clone();
            proposed.tool_calls = next_call;
            known_result_transition(
                &proposed,
                KnownToolResultKind::PolicyDenied,
                result_bytes,
                None,
            )
            .map(|mut transition| {
                transition.from = state.status;
                transition
            })
        }
    }
}

fn completion_result_kind(kind: ToolCompletionKind) -> KnownToolResultKind {
    match kind {
        ToolCompletionKind::Succeeded => KnownToolResultKind::Succeeded,
        ToolCompletionKind::Failed => KnownToolResultKind::Failed,
        ToolCompletionKind::Cancelled => KnownToolResultKind::Cancelled,
        ToolCompletionKind::NotDispatched => KnownToolResultKind::NotDispatched,
    }
}

fn known_result_transition(
    state: &State,
    kind: KnownToolResultKind,
    result_bytes: u64,
    pending_approvals: Option<u32>,
) -> Result<Transition, Error> {
    if result_bytes == 0 {
        return Err(Error::EmptyToolResult);
    }
    let cumulative =
        state
            .tool_result_bytes
            .checked_add(result_bytes)
            .ok_or(Error::CounterOverflow {
                counter: Counter::ToolResultBytes,
            })?;
    if result_bytes > state.limits.max_tool_result_bytes
        || cumulative > state.limits.max_turn_tool_result_bytes
    {
        return next_transition(
            state,
            AgentStatus::Failed,
            Some(TerminalReason::ToolResultBytesLimitReached),
            pending_approvals,
            None,
            None,
        );
    }
    next_transition_with_result(
        state,
        pending_approvals,
        cumulative,
        KnownToolResult {
            kind,
            serialized_bytes: result_bytes,
        },
    )
}

fn next_transition_with_tool_call(
    state: &State,
    tool_calls: u32,
    status: AgentStatus,
    pending_approvals: Option<u32>,
) -> Result<Transition, Error> {
    let mut next = state.clone();
    next.status = status;
    next.tool_calls = tool_calls;
    if let Some(pending) = pending_approvals {
        next.pending_approvals = pending;
    }
    next.terminal_reason = None;
    finish_transition(state.status, next, None, None)
}

fn next_transition_with_result(
    state: &State,
    pending_approvals: Option<u32>,
    cumulative: u64,
    result: KnownToolResult,
) -> Result<Transition, Error> {
    let mut next = state.clone();
    next.status = AgentStatus::ContinuationQueued;
    next.tool_result_bytes = cumulative;
    if let Some(pending) = pending_approvals {
        next.pending_approvals = pending;
    }
    next.terminal_reason = None;
    finish_transition(state.status, next, None, Some(result))
}

fn next_transition(
    state: &State,
    status: AgentStatus,
    terminal_reason: Option<TerminalReason>,
    pending_approvals: Option<u32>,
    external_call: Option<ExternalCall>,
    model_steps: Option<u32>,
) -> Result<Transition, Error> {
    let mut next = state.clone();
    next.status = status;
    next.terminal_reason = terminal_reason;
    if let Some(pending) = pending_approvals {
        next.pending_approvals = pending;
    }
    if let Some(model_steps) = model_steps {
        next.model_steps = model_steps;
    }
    finish_transition(state.status, next, external_call, None)
}

fn finish_transition(
    from: AgentStatus,
    state: State,
    external_call: Option<ExternalCall>,
    emitted_result: Option<KnownToolResult>,
) -> Result<Transition, Error> {
    state.validate()?;
    Ok(Transition {
        from,
        state,
        external_call,
        emitted_result,
    })
}

fn require_status(state: &State, expected: AgentStatus, command: CommandKind) -> Result<(), Error> {
    require_one_of(state, &[expected], command)
}

fn require_one_of(
    state: &State,
    expected: &[AgentStatus],
    command: CommandKind,
) -> Result<(), Error> {
    if expected.contains(&state.status) {
        Ok(())
    } else {
        Err(Error::InvalidTransition {
            status: state.status,
            command,
        })
    }
}

/// Stable command identity used in reducer diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandKind {
    StartModel,
    ModelFinal,
    ModelToolProposal,
    ModelFailed,
    ModelOutcomeUnknown,
    AuthorizationRevoked,
    DeploymentUnavailable,
    KnowledgeUnavailable,
    ApprovalApproved,
    ApprovalRejected,
    StartTool,
    ToolResultKnown,
    ContinuationUnavailable,
    ToolOutcomeUnknown,
}

/// Counter whose checked arithmetic overflowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Counter {
    ModelSteps,
    ToolCalls,
    PendingApprovals,
    ToolResultBytes,
}

/// Invalid limit field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitField {
    ModelSteps,
    ToolCalls,
    PendingApprovals,
    ToolResultBytes,
}

/// Persisted-state invariant rejected before command evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateInvariant {
    CounterAboveLimit,
    ResultWithoutToolCall,
    TerminalReasonMismatch,
    PhaseCounterMismatch,
    PendingApprovalMismatch,
}

/// Controlled reducer failures. The input state remains unchanged on error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Error)]
#[serde(tag = "error", rename_all = "snake_case", deny_unknown_fields)]
pub enum Error {
    #[error("invalid agent-loop limit: {field:?}")]
    InvalidLimits { field: LimitField },
    #[error("unsupported agent-loop state schema version {version}")]
    UnsupportedStateSchemaVersion { version: u16 },
    #[error("invalid persisted agent-loop state: {invariant:?}")]
    InvalidState { invariant: StateInvariant },
    #[error("command {command:?} is invalid from {status:?}")]
    InvalidTransition {
        status: AgentStatus,
        command: CommandKind,
    },
    #[error("counter overflow: {counter:?}")]
    CounterOverflow { counter: Counter },
    #[error("final model text must be non-empty")]
    EmptyFinalText,
    #[error("a structured tool result must contain at least one serialized byte")]
    EmptyToolResult,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn apply(state: State, command: Command) -> Transition {
        reduce(&state, command).unwrap()
    }

    fn start_model(state: State) -> Transition {
        apply(state, Command::StartModel)
    }

    fn started_model() -> State {
        start_model(State::default()).into_state()
    }

    fn queued_tool() -> State {
        apply(
            started_model(),
            Command::ModelToolProposal {
                disposition: ProposalDisposition::Allow,
            },
        )
        .into_state()
    }

    fn waiting_approval() -> State {
        apply(
            started_model(),
            Command::ModelToolProposal {
                disposition: ProposalDisposition::RequireApproval,
            },
        )
        .into_state()
    }

    fn started_tool() -> State {
        apply(queued_tool(), Command::StartTool).into_state()
    }

    #[test]
    fn default_limits_and_initial_state_are_fixed() {
        let state = State::default();
        assert_eq!(state.schema_version(), STATE_SCHEMA_VERSION);
        assert_eq!(
            state.limits(),
            &Limits {
                max_model_steps: 8,
                max_tool_calls: 4,
                max_pending_approvals: 1,
                max_tool_result_bytes: 64 * 1024,
                max_turn_tool_result_bytes: 128 * 1024,
            }
        );
        assert_eq!(state.status(), AgentStatus::ModelQueued);
        assert_eq!(state.model_steps(), 0);
        assert_eq!(state.tool_calls(), 0);
        assert_eq!(state.pending_approvals(), 0);
        assert_eq!(state.tool_result_bytes(), 0);
        assert_eq!(state.terminal_reason(), None);
    }

    #[test]
    fn only_start_commands_authorize_external_calls() {
        let model = start_model(State::default());
        assert_eq!(model.from(), AgentStatus::ModelQueued);
        assert_eq!(model.state().status(), AgentStatus::ModelStarted);
        assert_eq!(
            model.external_call(),
            Some(&ExternalCall::Model { step: 1 })
        );

        let proposal = apply(
            model.into_state(),
            Command::ModelToolProposal {
                disposition: ProposalDisposition::Allow,
            },
        );
        assert_eq!(proposal.external_call(), None);
        let tool = apply(proposal.into_state(), Command::StartTool);
        assert_eq!(tool.state().status(), AgentStatus::ToolStarted);
        assert_eq!(tool.external_call(), Some(&ExternalCall::Tool { call: 1 }));
    }

    #[test]
    fn final_text_is_the_only_successful_completion() {
        let completed = apply(started_model(), Command::ModelFinal { content_bytes: 12 });
        assert_eq!(completed.state().status(), AgentStatus::Completed);
        assert_eq!(completed.external_call(), None);
        assert_eq!(completed.emitted_result(), None);

        assert_eq!(
            reduce(&State::default(), Command::ModelFinal { content_bytes: 12 }).unwrap_err(),
            Error::InvalidTransition {
                status: AgentStatus::ModelQueued,
                command: CommandKind::ModelFinal,
            }
        );
        assert_eq!(
            reduce(&started_model(), Command::ModelFinal { content_bytes: 0 }).unwrap_err(),
            Error::EmptyFinalText
        );
    }

    #[test]
    fn proposal_dispositions_follow_the_transition_table() {
        struct Case {
            disposition: ProposalDisposition,
            status: AgentStatus,
            pending: u32,
            result: Option<KnownToolResult>,
        }
        let cases = [
            Case {
                disposition: ProposalDisposition::Allow,
                status: AgentStatus::ToolQueued,
                pending: 0,
                result: None,
            },
            Case {
                disposition: ProposalDisposition::RequireApproval,
                status: AgentStatus::WaitingApproval,
                pending: 1,
                result: None,
            },
            Case {
                disposition: ProposalDisposition::Deny { result_bytes: 17 },
                status: AgentStatus::ContinuationQueued,
                pending: 0,
                result: Some(KnownToolResult {
                    kind: KnownToolResultKind::PolicyDenied,
                    serialized_bytes: 17,
                }),
            },
        ];

        for case in cases {
            let transition = apply(
                started_model(),
                Command::ModelToolProposal {
                    disposition: case.disposition,
                },
            );
            assert_eq!(transition.state().status(), case.status);
            assert_eq!(transition.state().tool_calls(), 1);
            assert_eq!(transition.state().pending_approvals(), case.pending);
            assert_eq!(transition.emitted_result(), case.result.as_ref());
            assert_eq!(transition.external_call(), None);
        }
    }

    #[test]
    fn at_most_one_tool_proposal_is_admitted_per_model_step() {
        let state = queued_tool();
        assert_eq!(
            reduce(
                &state,
                Command::ModelToolProposal {
                    disposition: ProposalDisposition::Allow,
                }
            )
            .unwrap_err(),
            Error::InvalidTransition {
                status: AgentStatus::ToolQueued,
                command: CommandKind::ModelToolProposal,
            }
        );
    }

    #[test]
    fn approval_decisions_follow_the_transition_table() {
        let approved = apply(waiting_approval(), Command::ApprovalApproved);
        assert_eq!(approved.state().status(), AgentStatus::ToolQueued);
        assert_eq!(approved.state().pending_approvals(), 0);
        assert_eq!(approved.emitted_result(), None);

        let rejected = apply(
            waiting_approval(),
            Command::ApprovalRejected { result_bytes: 23 },
        );
        assert_eq!(rejected.state().status(), AgentStatus::ContinuationQueued);
        assert_eq!(rejected.state().pending_approvals(), 0);
        assert_eq!(
            rejected.emitted_result(),
            Some(&KnownToolResult {
                kind: KnownToolResultKind::ApprovalRejected,
                serialized_bytes: 23,
            })
        );
    }

    #[test]
    fn every_known_tool_result_queues_continuation_and_counts_bytes() {
        let cases = [
            (
                ToolCompletionKind::Succeeded,
                KnownToolResultKind::Succeeded,
            ),
            (ToolCompletionKind::Failed, KnownToolResultKind::Failed),
            (
                ToolCompletionKind::Cancelled,
                KnownToolResultKind::Cancelled,
            ),
            (
                ToolCompletionKind::NotDispatched,
                KnownToolResultKind::NotDispatched,
            ),
        ];

        for (completion, result_kind) in cases {
            let transition = apply(
                started_tool(),
                Command::ToolResultKnown {
                    kind: completion,
                    result_bytes: 31,
                },
            );
            assert_eq!(transition.state().status(), AgentStatus::ContinuationQueued);
            assert_eq!(transition.state().tool_result_bytes(), 31);
            assert_eq!(
                transition.emitted_result(),
                Some(&KnownToolResult {
                    kind: result_kind,
                    serialized_bytes: 31,
                })
            );
        }
    }

    #[test]
    fn started_unknown_outcomes_are_terminal_and_not_retryable() {
        struct Case {
            state: State,
            command: Command,
            reason: TerminalReason,
            retry: Command,
        }
        let cases = [
            Case {
                state: started_model(),
                command: Command::ModelOutcomeUnknown,
                reason: TerminalReason::ModelOutcomeUnknown,
                retry: Command::StartModel,
            },
            Case {
                state: started_tool(),
                command: Command::ToolOutcomeUnknown,
                reason: TerminalReason::ToolOutcomeUnknown,
                retry: Command::StartTool,
            },
        ];

        for case in cases {
            let uncertain = apply(case.state, case.command);
            assert_eq!(uncertain.state().status(), AgentStatus::NeedsAttention);
            assert_eq!(uncertain.state().terminal_reason(), Some(case.reason));
            assert_eq!(uncertain.external_call(), None);
            assert!(matches!(
                reduce(uncertain.state(), case.retry),
                Err(Error::InvalidTransition {
                    status: AgentStatus::NeedsAttention,
                    ..
                })
            ));
        }
    }

    #[test]
    fn revoked_authority_fails_before_any_new_external_call() {
        for state in [
            State::default(),
            started_model(),
            queued_tool(),
            started_tool(),
        ] {
            let revoked = apply(state, Command::AuthorizationRevoked);
            assert_eq!(revoked.state().status(), AgentStatus::Failed);
            assert_eq!(
                revoked.state().terminal_reason(),
                Some(TerminalReason::AuthorizationRevoked)
            );
            assert_eq!(revoked.external_call(), None);
        }
    }

    #[test]
    fn unavailable_deployment_fails_every_admitted_phase_before_external_io() {
        let continuation = apply(
            started_tool(),
            Command::ToolResultKnown {
                kind: ToolCompletionKind::Succeeded,
                result_bytes: 17,
            },
        )
        .into_state();
        for state in [
            started_model(),
            waiting_approval(),
            queued_tool(),
            started_tool(),
            continuation,
        ] {
            let model_steps = state.model_steps();
            let tool_calls = state.tool_calls();
            let result_bytes = state.tool_result_bytes();
            let rejected = apply(state, Command::DeploymentUnavailable);
            assert_eq!(rejected.state().status(), AgentStatus::Failed);
            assert_eq!(
                rejected.state().terminal_reason(),
                Some(TerminalReason::AuthorizationRevoked)
            );
            assert_eq!(rejected.state().model_steps(), model_steps);
            assert_eq!(rejected.state().tool_calls(), tool_calls);
            assert_eq!(rejected.state().tool_result_bytes(), result_bytes);
            assert_eq!(rejected.state().pending_approvals(), 0);
            assert_eq!(rejected.external_call(), None);
            assert_eq!(rejected.emitted_result(), None);
        }

        let queued = apply(State::default(), Command::DeploymentUnavailable);
        assert_eq!(queued.state().status(), AgentStatus::Failed);
        assert_eq!(queued.external_call(), None);
    }

    #[test]
    fn unavailable_knowledge_fails_every_admitted_phase_before_external_io() {
        let continuation = apply(
            started_tool(),
            Command::ToolResultKnown {
                kind: ToolCompletionKind::Succeeded,
                result_bytes: 17,
            },
        )
        .into_state();
        for state in [
            State::default(),
            started_model(),
            waiting_approval(),
            queued_tool(),
            started_tool(),
            continuation,
        ] {
            let model_steps = state.model_steps();
            let tool_calls = state.tool_calls();
            let result_bytes = state.tool_result_bytes();
            let rejected = apply(state, Command::KnowledgeUnavailable);
            assert_eq!(rejected.state().status(), AgentStatus::Failed);
            assert_eq!(
                rejected.state().terminal_reason(),
                Some(TerminalReason::AuthorizationRevoked)
            );
            assert_eq!(rejected.state().model_steps(), model_steps);
            assert_eq!(rejected.state().tool_calls(), tool_calls);
            assert_eq!(rejected.state().tool_result_bytes(), result_bytes);
            assert_eq!(rejected.state().pending_approvals(), 0);
            assert_eq!(rejected.external_call(), None);
            assert_eq!(rejected.emitted_result(), None);
        }
    }

    #[test]
    fn ninth_model_call_is_rejected_before_external_io() {
        let limits = Limits {
            max_model_steps: 8,
            max_tool_calls: 8,
            ..Limits::default()
        };
        let mut state = State::new(limits).unwrap();
        for _ in 0..8 {
            state = start_model(state).into_state();
            state = apply(
                state,
                Command::ModelToolProposal {
                    disposition: ProposalDisposition::Deny { result_bytes: 1 },
                },
            )
            .into_state();
        }
        assert_eq!(state.model_steps(), 8);

        let rejected = start_model(state);
        assert_eq!(rejected.state().status(), AgentStatus::Failed);
        assert_eq!(rejected.state().model_steps(), 8);
        assert_eq!(
            rejected.state().terminal_reason(),
            Some(TerminalReason::ModelStepLimitReached)
        );
        assert_eq!(rejected.external_call(), None);
    }

    #[test]
    fn fifth_tool_proposal_is_rejected_before_tool_io() {
        let mut state = State::default();
        for _ in 0..4 {
            state = start_model(state).into_state();
            state = apply(
                state,
                Command::ModelToolProposal {
                    disposition: ProposalDisposition::Deny { result_bytes: 1 },
                },
            )
            .into_state();
        }
        state = start_model(state).into_state();
        let rejected = apply(
            state,
            Command::ModelToolProposal {
                disposition: ProposalDisposition::Allow,
            },
        );
        assert_eq!(rejected.state().status(), AgentStatus::Failed);
        assert_eq!(rejected.state().tool_calls(), 4);
        assert_eq!(
            rejected.state().terminal_reason(),
            Some(TerminalReason::ToolCallLimitReached)
        );
        assert_eq!(rejected.external_call(), None);
    }

    #[test]
    fn tool_result_byte_limits_are_exact_and_fail_closed() {
        let limits = Limits {
            max_tool_result_bytes: 5,
            max_turn_tool_result_bytes: 8,
            ..Limits::default()
        };
        let initial = State::new(limits).unwrap();
        let first_started = apply(
            apply(
                start_model(initial).into_state(),
                Command::ModelToolProposal {
                    disposition: ProposalDisposition::Allow,
                },
            )
            .into_state(),
            Command::StartTool,
        )
        .into_state();
        let first = apply(
            first_started,
            Command::ToolResultKnown {
                kind: ToolCompletionKind::Succeeded,
                result_bytes: 5,
            },
        );
        assert_eq!(first.state().tool_result_bytes(), 5);

        let second_started = apply(
            apply(
                start_model(first.into_state()).into_state(),
                Command::ModelToolProposal {
                    disposition: ProposalDisposition::Allow,
                },
            )
            .into_state(),
            Command::StartTool,
        )
        .into_state();
        let exact = apply(
            second_started.clone(),
            Command::ToolResultKnown {
                kind: ToolCompletionKind::Succeeded,
                result_bytes: 3,
            },
        );
        assert_eq!(exact.state().status(), AgentStatus::ContinuationQueued);
        assert_eq!(exact.state().tool_result_bytes(), 8);

        let exceeded = apply(
            second_started,
            Command::ToolResultKnown {
                kind: ToolCompletionKind::Succeeded,
                result_bytes: 4,
            },
        );
        assert_eq!(exceeded.state().status(), AgentStatus::Failed);
        assert_eq!(
            exceeded.state().terminal_reason(),
            Some(TerminalReason::ToolResultBytesLimitReached)
        );
        assert_eq!(exceeded.external_call(), None);
        assert_eq!(exceeded.emitted_result(), None);
    }

    #[test]
    fn unavailable_continuation_terminalizes_known_results_without_making_them_unknown() {
        let tool_result = apply(
            started_tool(),
            Command::ToolResultKnown {
                kind: ToolCompletionKind::Succeeded,
                result_bytes: 17,
            },
        )
        .into_state();
        let policy_denied = apply(
            started_model(),
            Command::ModelToolProposal {
                disposition: ProposalDisposition::Deny { result_bytes: 19 },
            },
        )
        .into_state();
        let approval_rejected = apply(
            waiting_approval(),
            Command::ApprovalRejected { result_bytes: 23 },
        )
        .into_state();

        for known in [tool_result, policy_denied, approval_rejected] {
            assert_eq!(known.status(), AgentStatus::ContinuationQueued);
            let expected_model_steps = known.model_steps();
            let expected_tool_calls = known.tool_calls();
            let expected_result_bytes = known.tool_result_bytes();
            let terminal = apply(known, Command::ContinuationUnavailable);
            assert_eq!(terminal.state().status(), AgentStatus::Failed);
            assert_eq!(
                terminal.state().terminal_reason(),
                Some(TerminalReason::ContinuationUnavailable)
            );
            assert_eq!(terminal.state().model_steps(), expected_model_steps);
            assert_eq!(terminal.state().tool_calls(), expected_tool_calls);
            assert_eq!(terminal.state().tool_result_bytes(), expected_result_bytes);
            assert_eq!(terminal.external_call(), None);
        }
    }

    #[test]
    fn invalid_limits_and_empty_results_are_rejected() {
        let invalid_limits = [
            Limits {
                max_model_steps: 0,
                ..Limits::default()
            },
            Limits {
                max_tool_calls: 0,
                ..Limits::default()
            },
            Limits {
                max_pending_approvals: 0,
                ..Limits::default()
            },
            Limits {
                max_tool_result_bytes: 129,
                max_turn_tool_result_bytes: 128,
                ..Limits::default()
            },
        ];
        for limits in invalid_limits {
            assert!(matches!(
                State::new(limits),
                Err(Error::InvalidLimits { .. })
            ));
        }

        assert_eq!(
            reduce(
                &started_tool(),
                Command::ToolResultKnown {
                    kind: ToolCompletionKind::Succeeded,
                    result_bytes: 0,
                }
            )
            .unwrap_err(),
            Error::EmptyToolResult
        );
        assert_eq!(
            reduce(
                &waiting_approval(),
                Command::ApprovalRejected { result_bytes: 0 }
            )
            .unwrap_err(),
            Error::EmptyToolResult
        );
    }

    #[test]
    fn checked_counter_arithmetic_rejects_overflow() {
        let mut model = State::default();
        model.limits.max_model_steps = u32::MAX;
        model.limits.max_tool_calls = u32::MAX;
        model.status = AgentStatus::ContinuationQueued;
        model.model_steps = u32::MAX;
        model.tool_calls = 1;
        assert_eq!(
            reduce(&model, Command::StartModel).unwrap_err(),
            Error::CounterOverflow {
                counter: Counter::ModelSteps,
            }
        );

        let mut tool = started_model();
        tool.limits.max_tool_calls = u32::MAX;
        tool.tool_calls = u32::MAX;
        assert_eq!(
            reduce(
                &tool,
                Command::ModelToolProposal {
                    disposition: ProposalDisposition::Allow,
                }
            )
            .unwrap_err(),
            Error::CounterOverflow {
                counter: Counter::ToolCalls,
            }
        );

        let mut bytes = started_tool();
        bytes.limits.max_tool_result_bytes = u64::MAX;
        bytes.limits.max_turn_tool_result_bytes = u64::MAX;
        bytes.tool_result_bytes = u64::MAX;
        assert_eq!(
            reduce(
                &bytes,
                Command::ToolResultKnown {
                    kind: ToolCompletionKind::Succeeded,
                    result_bytes: 1,
                }
            )
            .unwrap_err(),
            Error::CounterOverflow {
                counter: Counter::ToolResultBytes,
            }
        );
    }

    #[test]
    fn invalid_persisted_state_is_rejected_before_command_evaluation() {
        let mut value = serde_json::to_value(waiting_approval()).unwrap();
        value["pending_approvals"] = json!(0);
        let state: State = serde_json::from_value(value).unwrap();
        assert_eq!(
            reduce(&state, Command::ApprovalApproved).unwrap_err(),
            Error::InvalidState {
                invariant: StateInvariant::PendingApprovalMismatch,
            }
        );
    }

    #[test]
    fn persisted_types_round_trip_and_reject_unknown_fields() {
        let state = waiting_approval();
        let encoded = serde_json::to_value(&state).unwrap();
        assert_eq!(
            serde_json::from_value::<State>(encoded.clone()).unwrap(),
            state
        );
        let mut unknown_state = encoded;
        unknown_state["unexpected"] = Value::Bool(true);
        assert!(serde_json::from_value::<State>(unknown_state).is_err());

        let command = Command::ModelToolProposal {
            disposition: ProposalDisposition::Deny { result_bytes: 7 },
        };
        let command_json = serde_json::to_value(&command).unwrap();
        assert_eq!(
            serde_json::from_value::<Command>(command_json.clone()).unwrap(),
            command
        );
        let mut unknown_command = command_json;
        unknown_command["unexpected"] = Value::Bool(true);
        assert!(serde_json::from_value::<Command>(unknown_command).is_err());

        let transition = apply(waiting_approval(), Command::ApprovalApproved);
        let transition_json = serde_json::to_value(&transition).unwrap();
        assert_eq!(
            serde_json::from_value::<Transition>(transition_json).unwrap(),
            transition
        );
    }

    #[test]
    fn known_model_failure_is_terminal_without_external_work() {
        let failed = apply(started_model(), Command::ModelFailed);
        assert_eq!(failed.state().status(), AgentStatus::Failed);
        assert_eq!(
            failed.state().terminal_reason(),
            Some(TerminalReason::ModelFailed)
        );
        assert_eq!(failed.external_call(), None);
    }
}
