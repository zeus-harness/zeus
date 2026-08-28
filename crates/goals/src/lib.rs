//! Durable same-Session completion Goals and their model-facing tool contracts.
//!
//! Goal mutations are prepared here as bounded canonical values. SQLite owns
//! the compare-and-set authority and commits each snapshot atomically with the
//! successful Agent tool result that exposed it to the model.

use std::collections::BTreeMap;

use protocol::{AgentGoalBlocker, AgentGoalPhase, SandboxProfile, ToolEffect};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tools::{
    ExecutionFuture, ExecutionRequest, ExecutorError, ObjectSchema, ParameterSpec, ParameterType,
    RegistryError, ToolDescriptor, ToolExecutor, ToolRegistry,
};

pub const GET_GOAL_TOOL_NAME: &str = "get_goal";
pub const CREATE_GOAL_TOOL_NAME: &str = "create_goal";
pub const UPDATE_GOAL_TOOL_NAME: &str = "update_goal";
pub const GOAL_TOOL_VERSION: &str = "1-session-cas";
pub const GOAL_OBJECTIVE_MAX_BYTES: usize = 1024;
pub const GOAL_BLOCKER_MAX_BYTES: usize = 1024;
pub const GOAL_ARGUMENTS_MAX_BYTES: usize = 4096;
pub const DEFAULT_MAX_GOAL_ROUNDS: u64 = 256;
pub const MAX_GOAL_ROUNDS: u64 = 4096;

const GET_DESCRIPTION: &str = "Read the current durable completion goal for this Session. The result is null when no goal exists. Use the exact id and revision before updating a goal.";
const CREATE_DESCRIPTION: &str = "Create one durable same-Session completion goal for a substantial multi-step objective. A Session may have only one unfinished goal; a completed goal may be replaced. max_rounds defaults to 256 and bounds future autonomous continuation.";
const UPDATE_DESCRIPTION: &str = "Update the exact current goal using goal_id and expected_revision. edit changes the objective and/or round cap; pause, resume, complete, and blocked are lifecycle transitions. blocked requires a concrete blocker message.";

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum GoalError {
    #[error("goal arguments are not a strict bounded object")]
    InvalidArguments,
    #[error("goal objective is empty, non-canonical, contains control characters, or is too large")]
    InvalidObjective,
    #[error("goal identifier is invalid")]
    InvalidGoalId,
    #[error("goal revision is outside the durable integer range")]
    InvalidRevision,
    #[error("goal round limit must be between 1 and {MAX_GOAL_ROUNDS}")]
    InvalidRoundLimit,
    #[error("goal blocker is empty, non-canonical, contains control characters, or is too large")]
    InvalidBlocker,
    #[error("an unfinished goal already exists")]
    GoalAlreadyActive,
    #[error("the current goal does not match the requested goal")]
    GoalMismatch,
    #[error("the goal revision is stale")]
    RevisionConflict,
    #[error("the requested goal transition is invalid")]
    InvalidTransition,
    #[error("goal result does not match its canonical mutation")]
    InvalidResult,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalSnapshot {
    pub id: String,
    pub revision: u64,
    pub objective: String,
    pub phase: AgentGoalPhase,
    pub rounds_started: u64,
    pub max_rounds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocker: Option<AgentGoalBlocker>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalToolResult {
    pub goal: Option<GoalSnapshot>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateGoalArguments {
    objective: String,
    #[serde(default)]
    max_rounds: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalUpdateAction {
    Edit,
    Pause,
    Resume,
    Complete,
    Blocked,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateGoalArguments {
    goal_id: String,
    expected_revision: u64,
    action: GoalUpdateAction,
    #[serde(default)]
    objective: Option<String>,
    #[serde(default)]
    max_rounds: Option<u64>,
    #[serde(default)]
    blocked_reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreparedGoalMutation {
    Create {
        snapshot: GoalSnapshot,
    },
    Update {
        previous: GoalSnapshot,
        snapshot: GoalSnapshot,
        action: GoalUpdateAction,
    },
}

impl PreparedGoalMutation {
    pub fn snapshot(&self) -> &GoalSnapshot {
        match self {
            Self::Create { snapshot } | Self::Update { snapshot, .. } => snapshot,
        }
    }

    pub fn previous(&self) -> Option<&GoalSnapshot> {
        match self {
            Self::Create { .. } => None,
            Self::Update { previous, .. } => Some(previous),
        }
    }

    pub fn result(&self) -> GoalToolResult {
        GoalToolResult {
            goal: Some(self.snapshot().clone()),
        }
    }
}

pub fn prepare_create_goal(
    arguments: &Value,
    current: Option<&GoalSnapshot>,
    call_id: &str,
) -> Result<PreparedGoalMutation, GoalError> {
    let raw: CreateGoalArguments =
        serde_json::from_value(arguments.clone()).map_err(|_| GoalError::InvalidArguments)?;
    if current.is_some_and(|goal| goal.phase != AgentGoalPhase::Completed) {
        return Err(GoalError::GoalAlreadyActive);
    }
    let objective = canonical_text(&raw.objective, GOAL_OBJECTIVE_MAX_BYTES)
        .ok_or(GoalError::InvalidObjective)?;
    let max_rounds = validate_round_limit(raw.max_rounds.unwrap_or(DEFAULT_MAX_GOAL_ROUNDS))?;
    Ok(PreparedGoalMutation::Create {
        snapshot: GoalSnapshot {
            id: stable_goal_id(call_id)?,
            revision: 1,
            objective,
            phase: AgentGoalPhase::Active,
            rounds_started: 0,
            max_rounds,
            blocker: None,
        },
    })
}

pub fn prepare_update_goal(
    arguments: &Value,
    current: Option<&GoalSnapshot>,
) -> Result<PreparedGoalMutation, GoalError> {
    let raw: UpdateGoalArguments =
        serde_json::from_value(arguments.clone()).map_err(|_| GoalError::InvalidArguments)?;
    let previous = current.cloned().ok_or(GoalError::GoalMismatch)?;
    if raw.goal_id.is_empty()
        || raw.goal_id.trim() != raw.goal_id
        || raw.goal_id.chars().any(char::is_control)
    {
        return Err(GoalError::InvalidGoalId);
    }
    if raw.expected_revision == 0 || raw.expected_revision > i64::MAX as u64 {
        return Err(GoalError::InvalidRevision);
    }
    if raw.goal_id != previous.id {
        return Err(GoalError::GoalMismatch);
    }
    if raw.expected_revision != previous.revision {
        return Err(GoalError::RevisionConflict);
    }
    let revision = previous
        .revision
        .checked_add(1)
        .filter(|revision| *revision <= i64::MAX as u64)
        .ok_or(GoalError::InvalidRevision)?;
    let mut snapshot = previous.clone();
    snapshot.revision = revision;
    match raw.action {
        GoalUpdateAction::Edit => {
            if previous.phase == AgentGoalPhase::Completed || raw.blocked_reason.is_some() {
                return Err(GoalError::InvalidTransition);
            }
            if raw.objective.is_none() && raw.max_rounds.is_none() {
                return Err(GoalError::InvalidTransition);
            }
            if let Some(objective) = raw.objective {
                snapshot.objective = canonical_text(&objective, GOAL_OBJECTIVE_MAX_BYTES)
                    .ok_or(GoalError::InvalidObjective)?;
            }
            if let Some(max_rounds) = raw.max_rounds {
                snapshot.max_rounds = validate_round_limit(max_rounds)?;
                if snapshot.rounds_started > snapshot.max_rounds {
                    return Err(GoalError::InvalidRoundLimit);
                }
            }
        }
        GoalUpdateAction::Pause => {
            require_empty_replacements(&raw)?;
            if previous.phase != AgentGoalPhase::Active {
                return Err(GoalError::InvalidTransition);
            }
            snapshot.phase = AgentGoalPhase::Paused;
        }
        GoalUpdateAction::Resume => {
            require_empty_replacements(&raw)?;
            if !matches!(
                previous.phase,
                AgentGoalPhase::Paused | AgentGoalPhase::Blocked
            ) || previous.rounds_started >= previous.max_rounds
            {
                return Err(GoalError::InvalidTransition);
            }
            snapshot.phase = AgentGoalPhase::Active;
            snapshot.blocker = None;
        }
        GoalUpdateAction::Complete => {
            require_empty_replacements(&raw)?;
            if previous.phase != AgentGoalPhase::Active {
                return Err(GoalError::InvalidTransition);
            }
            snapshot.phase = AgentGoalPhase::Completed;
            snapshot.blocker = None;
        }
        GoalUpdateAction::Blocked => {
            if raw.objective.is_some() || raw.max_rounds.is_some() {
                return Err(GoalError::InvalidTransition);
            }
            if previous.phase != AgentGoalPhase::Active {
                return Err(GoalError::InvalidTransition);
            }
            let message = raw
                .blocked_reason
                .as_deref()
                .and_then(|value| canonical_text(value, GOAL_BLOCKER_MAX_BYTES))
                .ok_or(GoalError::InvalidBlocker)?;
            snapshot.phase = AgentGoalPhase::Blocked;
            snapshot.blocker = Some(AgentGoalBlocker {
                code: "model_reported".into(),
                message,
            });
        }
    }
    Ok(PreparedGoalMutation::Update {
        previous,
        snapshot,
        action: raw.action,
    })
}

pub fn decode_goal_tool_result(value: &Value) -> Result<GoalToolResult, GoalError> {
    let result: GoalToolResult =
        serde_json::from_value(value.clone()).map_err(|_| GoalError::InvalidResult)?;
    if let Some(goal) = &result.goal {
        validate_snapshot(goal).map_err(|_| GoalError::InvalidResult)?;
    }
    Ok(result)
}

pub fn validate_snapshot(goal: &GoalSnapshot) -> Result<(), GoalError> {
    if goal.id.is_empty()
        || goal.id.len() > 80
        || goal.id.trim() != goal.id
        || goal.id.chars().any(char::is_control)
    {
        return Err(GoalError::InvalidGoalId);
    }
    if goal.revision == 0 || goal.revision > i64::MAX as u64 {
        return Err(GoalError::InvalidRevision);
    }
    if canonical_text(&goal.objective, GOAL_OBJECTIVE_MAX_BYTES).as_deref()
        != Some(goal.objective.as_str())
    {
        return Err(GoalError::InvalidObjective);
    }
    validate_round_limit(goal.max_rounds)?;
    if goal.rounds_started > goal.max_rounds {
        return Err(GoalError::InvalidRoundLimit);
    }
    match (&goal.phase, &goal.blocker) {
        (AgentGoalPhase::Blocked, Some(blocker))
            if blocker.code == "model_reported"
                && canonical_text(&blocker.message, GOAL_BLOCKER_MAX_BYTES).as_deref()
                    == Some(blocker.message.as_str()) => {}
        (AgentGoalPhase::Blocked, _) => return Err(GoalError::InvalidBlocker),
        (_, None) => {}
        (_, Some(_)) => return Err(GoalError::InvalidTransition),
    }
    Ok(())
}

fn require_empty_replacements(raw: &UpdateGoalArguments) -> Result<(), GoalError> {
    if raw.objective.is_some() || raw.max_rounds.is_some() || raw.blocked_reason.is_some() {
        return Err(GoalError::InvalidTransition);
    }
    Ok(())
}

fn validate_round_limit(value: u64) -> Result<u64, GoalError> {
    (value > 0 && value <= MAX_GOAL_ROUNDS)
        .then_some(value)
        .ok_or(GoalError::InvalidRoundLimit)
}

fn canonical_text(value: &str, max_bytes: usize) -> Option<String> {
    let canonical = value.trim();
    (!canonical.is_empty()
        && canonical.len() <= max_bytes
        && !canonical.chars().any(char::is_control))
    .then(|| canonical.to_owned())
}

pub fn stable_goal_id(call_id: &str) -> Result<String, GoalError> {
    if call_id.is_empty() || call_id.trim() != call_id || call_id.chars().any(char::is_control) {
        return Err(GoalError::InvalidGoalId);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"zeus-session-goal-id-v1\0");
    hasher.update((call_id.len() as u64).to_be_bytes());
    hasher.update(call_id.as_bytes());
    let digest = hasher.finalize();
    let mut encoded = String::from("goal-");
    for byte in &digest[..16] {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(encoded)
}

pub fn goal_tool_descriptors() -> [ToolDescriptor; 3] {
    [
        get_goal_descriptor(),
        create_goal_descriptor(),
        update_goal_descriptor(),
    ]
}

pub fn get_goal_descriptor() -> ToolDescriptor {
    descriptor(
        GET_GOAL_TOOL_NAME,
        GET_DESCRIPTION,
        ToolEffect::ReadOnly,
        ObjectSchema::empty(),
    )
}

pub fn create_goal_descriptor() -> ToolDescriptor {
    descriptor(
        CREATE_GOAL_TOOL_NAME,
        CREATE_DESCRIPTION,
        ToolEffect::LocalWrite,
        ObjectSchema {
            max_serialized_bytes: GOAL_ARGUMENTS_MAX_BYTES,
            properties: BTreeMap::from([
                (
                    "objective".into(),
                    ParameterSpec::required_string(GOAL_OBJECTIVE_MAX_BYTES),
                ),
                ("max_rounds".into(), optional_integer()),
            ]),
        },
    )
}

pub fn update_goal_descriptor() -> ToolDescriptor {
    descriptor(
        UPDATE_GOAL_TOOL_NAME,
        UPDATE_DESCRIPTION,
        ToolEffect::LocalWrite,
        ObjectSchema {
            max_serialized_bytes: GOAL_ARGUMENTS_MAX_BYTES,
            properties: BTreeMap::from([
                ("goal_id".into(), ParameterSpec::required_string(80)),
                ("expected_revision".into(), required_integer()),
                (
                    "action".into(),
                    ParameterSpec {
                        parameter_type: ParameterType::StringEnum {
                            values: vec![
                                "edit".into(),
                                "pause".into(),
                                "resume".into(),
                                "complete".into(),
                                "blocked".into(),
                            ],
                        },
                        required: true,
                        min_length: None,
                        max_length: None,
                    },
                ),
                (
                    "objective".into(),
                    optional_string(GOAL_OBJECTIVE_MAX_BYTES),
                ),
                ("max_rounds".into(), optional_integer()),
                (
                    "blocked_reason".into(),
                    optional_string(GOAL_BLOCKER_MAX_BYTES),
                ),
            ]),
        },
    )
}

fn descriptor(
    name: &str,
    description: &str,
    effect: ToolEffect,
    input_schema: ObjectSchema,
) -> ToolDescriptor {
    ToolDescriptor {
        name: name.into(),
        version: GOAL_TOOL_VERSION.into(),
        description: description.into(),
        effect,
        sandbox_profile: SandboxProfile::ReadOnly,
        input_schema,
    }
}

fn required_integer() -> ParameterSpec {
    ParameterSpec {
        parameter_type: ParameterType::Integer,
        required: true,
        min_length: None,
        max_length: None,
    }
}

fn optional_integer() -> ParameterSpec {
    ParameterSpec {
        required: false,
        ..required_integer()
    }
}

fn optional_string(max_length: usize) -> ParameterSpec {
    ParameterSpec {
        parameter_type: ParameterType::String,
        required: false,
        min_length: Some(1),
        max_length: Some(max_length),
    }
}

pub fn register_goal_tools(registry: &mut ToolRegistry) -> Result<(), RegistryError> {
    for descriptor in goal_tool_descriptors() {
        registry.register(descriptor, RuntimeGoalExecutor)?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct RuntimeGoalExecutor;

impl ToolExecutor for RuntimeGoalExecutor {
    fn execute(&self, _request: ExecutionRequest) -> ExecutionFuture<'_> {
        Box::pin(async {
            Err(ExecutorError::Failed {
                code: "goal_runtime_required".into(),
                message: "Goal tools require the Zeus durable Session runtime".into(),
                retryable: false,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_lifecycle_updates_are_canonical_and_compare_and_set() {
        let created = prepare_create_goal(
            &serde_json::json!({"objective":"  ship durable goals  "}),
            None,
            "call-create-goal",
        )
        .unwrap();
        assert_eq!(created.snapshot().objective, "ship durable goals");
        assert_eq!(created.snapshot().revision, 1);
        assert_eq!(created.snapshot().max_rounds, DEFAULT_MAX_GOAL_ROUNDS);
        let paused = prepare_update_goal(
            &serde_json::json!({
                "goal_id": created.snapshot().id,
                "expected_revision": 1,
                "action": "pause"
            }),
            Some(created.snapshot()),
        )
        .unwrap();
        assert_eq!(paused.snapshot().phase, AgentGoalPhase::Paused);
        assert_eq!(paused.snapshot().revision, 2);
        assert!(
            prepare_update_goal(
                &serde_json::json!({
                    "goal_id": created.snapshot().id,
                    "expected_revision": 1,
                    "action": "complete"
                }),
                Some(paused.snapshot()),
            )
            .is_err()
        );
    }

    #[test]
    fn transitions_reject_ambiguous_fields_and_invalid_blockers() {
        let created = prepare_create_goal(
            &serde_json::json!({"objective":"finish core"}),
            None,
            "call-create",
        )
        .unwrap();
        for invalid in [
            serde_json::json!({"goal_id":created.snapshot().id,"expected_revision":1,"action":"pause","objective":"x"}),
            serde_json::json!({"goal_id":created.snapshot().id,"expected_revision":1,"action":"blocked"}),
            serde_json::json!({"goal_id":created.snapshot().id,"expected_revision":1,"action":"edit"}),
        ] {
            assert!(prepare_update_goal(&invalid, Some(created.snapshot())).is_err());
        }
        assert!(
            decode_goal_tool_result(&serde_json::json!({"goal": null, "unexpected": true}))
                .is_err()
        );
    }

    #[test]
    fn descriptors_are_closed_bounded_and_locked() {
        let [get, create, update] = goal_tool_descriptors();
        assert_eq!(
            get.input_schema.provider_json_schema().unwrap()["required"],
            serde_json::json!([])
        );
        assert_eq!(create.name, CREATE_GOAL_TOOL_NAME);
        assert_eq!(
            update.input_schema.provider_json_schema().unwrap()["properties"]["action"]["enum"],
            serde_json::json!(["edit", "pause", "resume", "complete", "blocked"])
        );
        assert_eq!(
            stable_goal_id("call-create-goal").unwrap(),
            "goal-a7f605d38bada74a129d4870b33a0810"
        );
    }
}
