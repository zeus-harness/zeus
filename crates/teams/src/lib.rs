//! Durable shared task DAGs for one root Session and its spawned descendants.
//!
//! This crate owns bounded parsing, compare-and-set transitions, dependency
//! validation, derived readiness, and model-facing tool contracts. SQLite is
//! the mutation authority and commits a successful task snapshot atomically
//! with the exact Agent tool result that exposed it to the model.

use std::collections::{BTreeMap, BTreeSet};

use protocol::{SandboxProfile, ToolEffect};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tools::{
    ExecutionFuture, ExecutionRequest, ExecutorError, ObjectSchema, ParameterSpec, ParameterType,
    RegistryError, TOOL_OUTPUT_MAX_SERIALIZED_BYTES, ToolDescriptor, ToolExecutor, ToolRegistry,
};

pub const TEAM_TASK_CREATE_TOOL_NAME: &str = "team_task_create";
pub const TEAM_TASK_GET_TOOL_NAME: &str = "team_task_get";
pub const TEAM_TASK_LIST_TOOL_NAME: &str = "team_task_list";
pub const TEAM_TASK_UPDATE_TOOL_NAME: &str = "team_task_update";
pub const TEAM_TASK_TOOL_VERSION: &str = "1-session-dag";
pub const TEAM_TASK_MAX_TASKS: usize = 256;
pub const TEAM_TASK_MAX_SNAPSHOTS: usize = 4096;
pub const TEAM_TASK_SUBJECT_MAX_BYTES: usize = 200;
pub const TEAM_TASK_DESCRIPTION_MAX_BYTES: usize = 16 * 1024;
pub const TEAM_TASK_MAX_DEPENDENCIES: usize = 32;
pub const TEAM_TASK_MAX_WRITE_SCOPES: usize = 32;
pub const TEAM_TASK_WRITE_SCOPE_MAX_BYTES: usize = 256;
pub const TEAM_TASK_ARGUMENTS_MAX_BYTES: usize = 16 * 1024;
pub const TEAM_TASK_LIST_DEFAULT_LIMIT: usize = 16;
pub const TEAM_TASK_LIST_MAX_LIMIT: usize = 32;
pub const TEAM_TASK_MAX_MEMBERS: usize = 1 + 8 + 64 + 512;

const CREATE_DESCRIPTION: &str = "Create one unowned pending task on the durable task board shared by this root Session and its spawned descendants. Dependencies must name existing non-deleted tasks and remain acyclic; write_scopes are advisory workspace-relative prefixes, not locks.";
const GET_DESCRIPTION: &str = "Read one exact durable shared task, including a deleted tombstone. The result includes its current CAS revision, owner Session, blockers, readiness, and advisory write-scope overlap warnings.";
const LIST_DESCRIPTION: &str = "List a bounded page of non-deleted durable shared tasks in creation order. Optional status, owner_session_id (or unowned), and ready filters are exact. Continue with next_after_task_id when present.";
const UPDATE_DESCRIPTION: &str = "Compare-and-set one durable shared task. Any Team member may claim a ready unowned task. The owner or root Lead may edit, release, complete, reopen, set dependencies, or delete; only the root Lead may reassign. Every successful mutation increments revision.";

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum TeamTaskError {
    #[error("team task arguments are not a strict bounded object")]
    InvalidArguments,
    #[error("the caller is not a member of this durable Session Team")]
    CallerNotMember,
    #[error("team task identifier is invalid")]
    InvalidTaskId,
    #[error("team task revision is outside the durable integer range")]
    InvalidRevision,
    #[error("team task subject is empty, non-canonical, control-bearing, or too large")]
    InvalidSubject,
    #[error("team task description is empty, non-canonical, control-bearing, or too large")]
    InvalidDescription,
    #[error("team task dependency list is invalid")]
    InvalidDependencies,
    #[error("team task write scope is not a canonical workspace-relative prefix")]
    InvalidWriteScope,
    #[error("the durable Team task limit is exhausted")]
    CapacityExceeded,
    #[error("the requested team task does not exist")]
    NotFound,
    #[error("the requested team task has been deleted")]
    Deleted,
    #[error("the team task revision is stale")]
    RevisionConflict,
    #[error("the requested team task transition is invalid")]
    InvalidTransition,
    #[error("the team task is blocked by incomplete dependencies")]
    Blocked,
    #[error("the team task is owned by another Session")]
    AlreadyClaimed,
    #[error("the task mutation requires its owner or the root Lead")]
    OwnerOrLeadRequired,
    #[error("only the root Lead may reassign a task")]
    LeadRequired,
    #[error("the requested assignee is not an active Team member")]
    InvalidAssignee,
    #[error("the team task dependency graph contains a cycle")]
    DependencyCycle,
    #[error("the team task still has a non-deleted dependent")]
    HasDependents,
    #[error("the team task result is not canonical")]
    InvalidResult,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamTaskStatus {
    Pending,
    InProgress,
    Completed,
    Deleted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamTaskSnapshot {
    pub id: String,
    pub revision: u64,
    pub subject: String,
    pub description: String,
    pub status: TeamTaskStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_session_id: Option<String>,
    pub blocked_by: Vec<String>,
    pub write_scopes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeamMember {
    pub session_id: String,
    pub assignable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeamTaskBoard {
    pub root_session_id: String,
    pub members: Vec<TeamMember>,
    pub tasks: Vec<TeamTaskSnapshot>,
}

impl TeamTaskBoard {
    pub fn validate(&self) -> Result<(), TeamTaskError> {
        validate_session_id(&self.root_session_id)?;
        if self.members.is_empty() || self.members.len() > TEAM_TASK_MAX_MEMBERS {
            return Err(TeamTaskError::CallerNotMember);
        }
        let members = self
            .members
            .iter()
            .map(|member| {
                validate_session_id(&member.session_id)?;
                Ok(member.session_id.as_str())
            })
            .collect::<Result<BTreeSet<_>, TeamTaskError>>()?;
        if members.len() != self.members.len() || !members.contains(self.root_session_id.as_str()) {
            return Err(TeamTaskError::CallerNotMember);
        }
        if self.tasks.len() > TEAM_TASK_MAX_TASKS {
            return Err(TeamTaskError::CapacityExceeded);
        }
        let mut ids = BTreeSet::new();
        for task in &self.tasks {
            validate_snapshot(task)?;
            if !ids.insert(task.id.as_str()) {
                return Err(TeamTaskError::InvalidTaskId);
            }
            if task
                .owner_session_id
                .as_deref()
                .is_some_and(|owner| !members.contains(owner))
            {
                return Err(TeamTaskError::InvalidAssignee);
            }
        }
        validate_graph(&self.tasks)
    }

    pub fn contains_member(&self, session_id: &str) -> bool {
        self.members
            .iter()
            .any(|member| member.session_id == session_id)
    }

    pub fn is_assignable_member(&self, session_id: &str) -> bool {
        self.members
            .iter()
            .any(|member| member.session_id == session_id && member.assignable)
    }

    pub fn current(&self, task_id: &str) -> Option<&TeamTaskSnapshot> {
        self.tasks.iter().find(|task| task.id == task_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamTaskView {
    pub id: String,
    pub revision: u64,
    pub subject: String,
    pub description: String,
    pub status: TeamTaskStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_session_id: Option<String>,
    pub blocked_by: Vec<String>,
    pub write_scopes: Vec<String>,
    pub ready: bool,
    pub write_scope_warnings: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamTaskSummary {
    pub id: String,
    pub revision: u64,
    pub subject: String,
    pub status: TeamTaskStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_session_id: Option<String>,
    pub blocked_by: Vec<String>,
    pub ready: bool,
    pub write_scope_warnings: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamTaskToolResult {
    pub task: TeamTaskView,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamTaskListResult {
    pub tasks: Vec<TeamTaskSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_after_task_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedTeamTaskMutation {
    previous: Option<TeamTaskSnapshot>,
    snapshot: TeamTaskSnapshot,
}

impl PreparedTeamTaskMutation {
    pub fn previous(&self) -> Option<&TeamTaskSnapshot> {
        self.previous.as_ref()
    }

    pub const fn snapshot(&self) -> &TeamTaskSnapshot {
        &self.snapshot
    }

    pub fn result(&self, board: &TeamTaskBoard) -> Result<TeamTaskToolResult, TeamTaskError> {
        let result = TeamTaskToolResult {
            task: task_view(board, &self.snapshot)?,
        };
        validate_output(&result)?;
        Ok(result)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateArguments {
    subject: String,
    description: String,
    #[serde(default)]
    blocked_by: Vec<String>,
    #[serde(default)]
    write_scopes: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamTaskAction {
    Claim,
    Release,
    Edit,
    SetDependencies,
    Complete,
    Reopen,
    Reassign,
    Delete,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateArguments {
    task_id: String,
    expected_revision: u64,
    action: TeamTaskAction,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    blocked_by: Option<Vec<String>>,
    #[serde(default)]
    write_scopes: Option<Vec<String>>,
    #[serde(default)]
    owner_session_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetArguments {
    task_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListArguments {
    #[serde(default)]
    after_task_id: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    status: Option<TeamTaskStatus>,
    #[serde(default)]
    owner_session_id: Option<String>,
    #[serde(default)]
    ready: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeamTaskListRequest {
    after_number: u64,
    limit: usize,
    status: Option<TeamTaskStatus>,
    owner_session_id: Option<String>,
    ready: Option<bool>,
}

pub fn prepare_create(
    arguments: &Value,
    board: &TeamTaskBoard,
    caller_session_id: &str,
) -> Result<PreparedTeamTaskMutation, TeamTaskError> {
    board.validate()?;
    require_member(board, caller_session_id)?;
    let raw: CreateArguments =
        serde_json::from_value(arguments.clone()).map_err(|_| TeamTaskError::InvalidArguments)?;
    if board.tasks.len() >= TEAM_TASK_MAX_TASKS {
        return Err(TeamTaskError::CapacityExceeded);
    }
    let next = board
        .tasks
        .iter()
        .map(|task| parse_task_id(&task.id))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .filter(|value| *value <= TEAM_TASK_MAX_TASKS as u64)
        .ok_or(TeamTaskError::CapacityExceeded)?;
    let snapshot = TeamTaskSnapshot {
        id: format!("task-{next}"),
        revision: 1,
        subject: canonical_text(&raw.subject, TEAM_TASK_SUBJECT_MAX_BYTES)
            .ok_or(TeamTaskError::InvalidSubject)?,
        description: canonical_text(&raw.description, TEAM_TASK_DESCRIPTION_MAX_BYTES)
            .ok_or(TeamTaskError::InvalidDescription)?,
        status: TeamTaskStatus::Pending,
        owner_session_id: None,
        blocked_by: canonical_dependencies(&raw.blocked_by, None, board)?,
        write_scopes: canonical_write_scopes(&raw.write_scopes)?,
    };
    let candidate = board_with_candidate(board, &snapshot);
    candidate.validate()?;
    Ok(PreparedTeamTaskMutation {
        previous: None,
        snapshot,
    })
}

pub fn prepare_update(
    arguments: &Value,
    board: &TeamTaskBoard,
    caller_session_id: &str,
) -> Result<PreparedTeamTaskMutation, TeamTaskError> {
    board.validate()?;
    require_member(board, caller_session_id)?;
    let raw: UpdateArguments =
        serde_json::from_value(arguments.clone()).map_err(|_| TeamTaskError::InvalidArguments)?;
    parse_task_id(&raw.task_id)?;
    if raw.expected_revision == 0 || raw.expected_revision > i64::MAX as u64 {
        return Err(TeamTaskError::InvalidRevision);
    }
    let previous = board
        .current(&raw.task_id)
        .cloned()
        .ok_or(TeamTaskError::NotFound)?;
    if previous.status == TeamTaskStatus::Deleted {
        return Err(TeamTaskError::Deleted);
    }
    if raw.expected_revision != previous.revision {
        return Err(TeamTaskError::RevisionConflict);
    }
    let revision = previous
        .revision
        .checked_add(1)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or(TeamTaskError::InvalidRevision)?;
    let lead = caller_session_id == board.root_session_id;
    let owner = previous.owner_session_id.as_deref() == Some(caller_session_id);
    let require_owner_or_lead = || {
        (lead || owner)
            .then_some(())
            .ok_or(TeamTaskError::OwnerOrLeadRequired)
    };
    let no_extras = || {
        (raw.subject.is_none()
            && raw.description.is_none()
            && raw.blocked_by.is_none()
            && raw.write_scopes.is_none()
            && raw.owner_session_id.is_none())
        .then_some(())
        .ok_or(TeamTaskError::InvalidArguments)
    };
    let mut next = previous.clone();
    match raw.action {
        TeamTaskAction::Claim => {
            no_extras()?;
            if previous.status != TeamTaskStatus::Pending || !task_ready(board, &previous) {
                return Err(TeamTaskError::Blocked);
            }
            if previous.owner_session_id.is_some() {
                return Err(TeamTaskError::AlreadyClaimed);
            }
            next.status = TeamTaskStatus::InProgress;
            next.owner_session_id = Some(caller_session_id.to_owned());
        }
        TeamTaskAction::Release => {
            no_extras()?;
            require_owner_or_lead()?;
            if previous.status != TeamTaskStatus::InProgress {
                return Err(TeamTaskError::InvalidTransition);
            }
            next.status = TeamTaskStatus::Pending;
            next.owner_session_id = None;
        }
        TeamTaskAction::Edit => {
            require_owner_or_lead()?;
            if raw.blocked_by.is_some() || raw.owner_session_id.is_some() {
                return Err(TeamTaskError::InvalidArguments);
            }
            if raw.subject.is_none() && raw.description.is_none() && raw.write_scopes.is_none() {
                return Err(TeamTaskError::InvalidArguments);
            }
            if let Some(subject) = raw.subject.as_deref() {
                next.subject = canonical_text(subject, TEAM_TASK_SUBJECT_MAX_BYTES)
                    .ok_or(TeamTaskError::InvalidSubject)?;
            }
            if let Some(description) = raw.description.as_deref() {
                next.description = canonical_text(description, TEAM_TASK_DESCRIPTION_MAX_BYTES)
                    .ok_or(TeamTaskError::InvalidDescription)?;
            }
            if let Some(scopes) = raw.write_scopes.as_deref() {
                next.write_scopes = canonical_write_scopes(scopes)?;
            }
        }
        TeamTaskAction::SetDependencies => {
            require_owner_or_lead()?;
            if !matches!(
                previous.status,
                TeamTaskStatus::Pending | TeamTaskStatus::InProgress
            ) {
                return Err(TeamTaskError::InvalidTransition);
            }
            if raw.subject.is_some()
                || raw.description.is_some()
                || raw.write_scopes.is_some()
                || raw.owner_session_id.is_some()
            {
                return Err(TeamTaskError::InvalidArguments);
            }
            next.blocked_by = canonical_dependencies(
                raw.blocked_by
                    .as_deref()
                    .ok_or(TeamTaskError::InvalidArguments)?,
                Some(&previous.id),
                board,
            )?;
        }
        TeamTaskAction::Complete => {
            no_extras()?;
            require_owner_or_lead()?;
            if previous.status != TeamTaskStatus::InProgress {
                return Err(TeamTaskError::InvalidTransition);
            }
            if !dependencies_completed(board, &previous) {
                return Err(TeamTaskError::Blocked);
            }
            next.status = TeamTaskStatus::Completed;
        }
        TeamTaskAction::Reopen => {
            no_extras()?;
            require_owner_or_lead()?;
            if previous.status != TeamTaskStatus::Completed {
                return Err(TeamTaskError::InvalidTransition);
            }
            next.status = TeamTaskStatus::Pending;
            next.owner_session_id = None;
        }
        TeamTaskAction::Reassign => {
            if !lead {
                return Err(TeamTaskError::LeadRequired);
            }
            if raw.subject.is_some()
                || raw.description.is_some()
                || raw.blocked_by.is_some()
                || raw.write_scopes.is_some()
            {
                return Err(TeamTaskError::InvalidArguments);
            }
            if !matches!(
                previous.status,
                TeamTaskStatus::Pending | TeamTaskStatus::InProgress
            ) {
                return Err(TeamTaskError::InvalidTransition);
            }
            let assignee = raw
                .owner_session_id
                .as_deref()
                .ok_or(TeamTaskError::InvalidArguments)?;
            if assignee == "unowned" {
                next.status = TeamTaskStatus::Pending;
                next.owner_session_id = None;
            } else {
                validate_session_id(assignee).map_err(|_| TeamTaskError::InvalidAssignee)?;
                if !board.is_assignable_member(assignee) {
                    return Err(TeamTaskError::InvalidAssignee);
                }
                if !dependencies_completed(board, &previous) {
                    return Err(TeamTaskError::Blocked);
                }
                next.status = TeamTaskStatus::InProgress;
                next.owner_session_id = Some(assignee.to_owned());
            }
        }
        TeamTaskAction::Delete => {
            no_extras()?;
            require_owner_or_lead()?;
            if board.tasks.iter().any(|task| {
                task.id != previous.id
                    && task.status != TeamTaskStatus::Deleted
                    && task.blocked_by.contains(&previous.id)
            }) {
                return Err(TeamTaskError::HasDependents);
            }
            next.status = TeamTaskStatus::Deleted;
            next.owner_session_id = None;
        }
    }
    next.revision = revision;
    let candidate = board_with_candidate(board, &next);
    candidate.validate()?;
    Ok(PreparedTeamTaskMutation {
        previous: Some(previous),
        snapshot: next,
    })
}

pub fn prepare_get(arguments: &Value) -> Result<String, TeamTaskError> {
    let raw: GetArguments =
        serde_json::from_value(arguments.clone()).map_err(|_| TeamTaskError::InvalidArguments)?;
    parse_task_id(&raw.task_id)?;
    Ok(raw.task_id)
}

pub fn team_task_number(task_id: &str) -> Result<u64, TeamTaskError> {
    parse_task_id(task_id)
}

pub const fn error_code(error: &TeamTaskError) -> &'static str {
    match error {
        TeamTaskError::InvalidArguments => "invalid_arguments",
        TeamTaskError::CallerNotMember => "caller_not_member",
        TeamTaskError::InvalidTaskId => "invalid_task_id",
        TeamTaskError::InvalidRevision => "invalid_revision",
        TeamTaskError::InvalidSubject => "invalid_subject",
        TeamTaskError::InvalidDescription => "invalid_description",
        TeamTaskError::InvalidDependencies => "invalid_dependencies",
        TeamTaskError::InvalidWriteScope => "invalid_write_scope",
        TeamTaskError::CapacityExceeded => "team_task_capacity_exceeded",
        TeamTaskError::NotFound => "team_task_not_found",
        TeamTaskError::Deleted => "team_task_deleted",
        TeamTaskError::RevisionConflict => "team_task_revision_conflict",
        TeamTaskError::InvalidTransition => "invalid_team_task_transition",
        TeamTaskError::Blocked => "team_task_blocked",
        TeamTaskError::AlreadyClaimed => "team_task_already_claimed",
        TeamTaskError::OwnerOrLeadRequired => "team_task_owner_or_lead_required",
        TeamTaskError::LeadRequired => "team_task_lead_required",
        TeamTaskError::InvalidAssignee => "invalid_team_task_assignee",
        TeamTaskError::DependencyCycle => "team_task_dependency_cycle",
        TeamTaskError::HasDependents => "team_task_has_dependents",
        TeamTaskError::InvalidResult => "invalid_team_task_result",
    }
}

pub fn prepare_list(arguments: &Value) -> Result<TeamTaskListRequest, TeamTaskError> {
    let raw: ListArguments =
        serde_json::from_value(arguments.clone()).map_err(|_| TeamTaskError::InvalidArguments)?;
    let after_number = raw
        .after_task_id
        .as_deref()
        .map(parse_task_id)
        .transpose()?
        .unwrap_or(0);
    let limit = raw.limit.unwrap_or(TEAM_TASK_LIST_DEFAULT_LIMIT);
    if limit == 0 || limit > TEAM_TASK_LIST_MAX_LIMIT {
        return Err(TeamTaskError::InvalidArguments);
    }
    if raw
        .owner_session_id
        .as_deref()
        .is_some_and(|owner| owner != "unowned" && validate_session_id(owner).is_err())
    {
        return Err(TeamTaskError::InvalidAssignee);
    }
    Ok(TeamTaskListRequest {
        after_number,
        limit,
        status: raw.status,
        owner_session_id: raw.owner_session_id,
        ready: raw.ready,
    })
}

pub fn get_task(
    board: &TeamTaskBoard,
    caller_session_id: &str,
    task_id: &str,
) -> Result<TeamTaskToolResult, TeamTaskError> {
    board.validate()?;
    require_member(board, caller_session_id)?;
    parse_task_id(task_id)?;
    let task = board.current(task_id).ok_or(TeamTaskError::NotFound)?;
    let result = TeamTaskToolResult {
        task: task_view(board, task)?,
    };
    validate_output(&result)?;
    Ok(result)
}

pub fn list_tasks(
    board: &TeamTaskBoard,
    caller_session_id: &str,
    request: &TeamTaskListRequest,
) -> Result<TeamTaskListResult, TeamTaskError> {
    board.validate()?;
    require_member(board, caller_session_id)?;
    let mut matching = board
        .tasks
        .iter()
        .filter(|task| task.status != TeamTaskStatus::Deleted)
        .filter(|task| parse_task_id(&task.id).is_ok_and(|id| id > request.after_number))
        .filter(|task| request.status.is_none_or(|status| task.status == status))
        .filter(|task| {
            request.owner_session_id.as_deref().is_none_or(|owner| {
                if owner == "unowned" {
                    task.owner_session_id.is_none()
                } else {
                    task.owner_session_id.as_deref() == Some(owner)
                }
            })
        })
        .filter(|task| {
            request
                .ready
                .is_none_or(|ready| task_ready(board, task) == ready)
        })
        .collect::<Vec<_>>();
    matching.sort_by_key(|task| parse_task_id(&task.id).unwrap_or(u64::MAX));
    let has_more = matching.len() > request.limit;
    matching.truncate(request.limit);
    let tasks = matching
        .iter()
        .map(|task| task_summary(board, task))
        .collect::<Result<Vec<_>, _>>()?;
    let next_after_task_id = has_more
        .then(|| tasks.last().map(|task| task.id.clone()))
        .flatten();
    let result = TeamTaskListResult {
        tasks,
        next_after_task_id,
    };
    validate_output(&result)?;
    Ok(result)
}

pub fn decode_tool_result(value: &Value) -> Result<TeamTaskToolResult, TeamTaskError> {
    let result: TeamTaskToolResult =
        serde_json::from_value(value.clone()).map_err(|_| TeamTaskError::InvalidResult)?;
    validate_view(&result.task)?;
    validate_output(&result)?;
    Ok(result)
}

pub fn validate_snapshot(task: &TeamTaskSnapshot) -> Result<(), TeamTaskError> {
    parse_task_id(&task.id)?;
    if task.revision == 0 || task.revision > i64::MAX as u64 {
        return Err(TeamTaskError::InvalidRevision);
    }
    if canonical_text(&task.subject, TEAM_TASK_SUBJECT_MAX_BYTES).as_deref()
        != Some(task.subject.as_str())
    {
        return Err(TeamTaskError::InvalidSubject);
    }
    if canonical_text(&task.description, TEAM_TASK_DESCRIPTION_MAX_BYTES).as_deref()
        != Some(task.description.as_str())
    {
        return Err(TeamTaskError::InvalidDescription);
    }
    if task.blocked_by != canonical_dependency_values(&task.blocked_by, Some(&task.id))? {
        return Err(TeamTaskError::InvalidDependencies);
    }
    if task.write_scopes != canonical_write_scopes(&task.write_scopes)? {
        return Err(TeamTaskError::InvalidWriteScope);
    }
    if task
        .owner_session_id
        .as_deref()
        .is_some_and(|owner| validate_session_id(owner).is_err())
    {
        return Err(TeamTaskError::InvalidAssignee);
    }
    match task.status {
        TeamTaskStatus::Pending | TeamTaskStatus::Deleted if task.owner_session_id.is_some() => {
            Err(TeamTaskError::InvalidTransition)
        }
        TeamTaskStatus::InProgress if task.owner_session_id.is_none() => {
            Err(TeamTaskError::InvalidTransition)
        }
        _ => Ok(()),
    }
}

pub fn team_task_descriptors() -> [ToolDescriptor; 4] {
    [
        create_descriptor(),
        get_descriptor(),
        list_descriptor(),
        update_descriptor(),
    ]
}

pub fn register_team_task_tools(registry: &mut ToolRegistry) -> Result<(), RegistryError> {
    for descriptor in team_task_descriptors() {
        registry.register(descriptor, RuntimeTeamTaskExecutor)?;
    }
    Ok(())
}

fn create_descriptor() -> ToolDescriptor {
    descriptor(
        TEAM_TASK_CREATE_TOOL_NAME,
        CREATE_DESCRIPTION,
        ToolEffect::LocalWrite,
        ObjectSchema {
            max_serialized_bytes: TEAM_TASK_ARGUMENTS_MAX_BYTES,
            properties: BTreeMap::from([
                (
                    "subject".into(),
                    ParameterSpec::required_string(TEAM_TASK_SUBJECT_MAX_BYTES),
                ),
                (
                    "description".into(),
                    ParameterSpec::required_string(TEAM_TASK_DESCRIPTION_MAX_BYTES),
                ),
                ("blocked_by".into(), optional_array()),
                ("write_scopes".into(), optional_array()),
            ]),
        },
    )
}

fn get_descriptor() -> ToolDescriptor {
    descriptor(
        TEAM_TASK_GET_TOOL_NAME,
        GET_DESCRIPTION,
        ToolEffect::ReadOnly,
        ObjectSchema {
            max_serialized_bytes: 256,
            properties: BTreeMap::from([("task_id".into(), ParameterSpec::required_string(32))]),
        },
    )
}

fn list_descriptor() -> ToolDescriptor {
    descriptor(
        TEAM_TASK_LIST_TOOL_NAME,
        LIST_DESCRIPTION,
        ToolEffect::ReadOnly,
        ObjectSchema {
            max_serialized_bytes: 1024,
            properties: BTreeMap::from([
                ("after_task_id".into(), optional_string(32)),
                ("limit".into(), optional_integer()),
                (
                    "status".into(),
                    ParameterSpec {
                        parameter_type: ParameterType::StringEnum {
                            values: vec![
                                "pending".into(),
                                "in_progress".into(),
                                "completed".into(),
                            ],
                        },
                        required: false,
                        min_length: None,
                        max_length: None,
                    },
                ),
                ("owner_session_id".into(), optional_string(128)),
                ("ready".into(), optional_boolean()),
            ]),
        },
    )
}

fn update_descriptor() -> ToolDescriptor {
    descriptor(
        TEAM_TASK_UPDATE_TOOL_NAME,
        UPDATE_DESCRIPTION,
        ToolEffect::LocalWrite,
        ObjectSchema {
            max_serialized_bytes: TEAM_TASK_ARGUMENTS_MAX_BYTES,
            properties: BTreeMap::from([
                ("task_id".into(), ParameterSpec::required_string(32)),
                ("expected_revision".into(), required_integer()),
                (
                    "action".into(),
                    ParameterSpec {
                        parameter_type: ParameterType::StringEnum {
                            values: vec![
                                "claim".into(),
                                "release".into(),
                                "edit".into(),
                                "set_dependencies".into(),
                                "complete".into(),
                                "reopen".into(),
                                "reassign".into(),
                                "delete".into(),
                            ],
                        },
                        required: true,
                        min_length: None,
                        max_length: None,
                    },
                ),
                (
                    "subject".into(),
                    optional_string(TEAM_TASK_SUBJECT_MAX_BYTES),
                ),
                (
                    "description".into(),
                    optional_string(TEAM_TASK_DESCRIPTION_MAX_BYTES),
                ),
                ("blocked_by".into(), optional_array()),
                ("write_scopes".into(), optional_array()),
                ("owner_session_id".into(), optional_string(128)),
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
        version: TEAM_TASK_TOOL_VERSION.into(),
        description: description.into(),
        effect,
        sandbox_profile: SandboxProfile::ReadOnly,
        input_schema,
    }
}

#[derive(Clone, Copy)]
struct RuntimeTeamTaskExecutor;

impl ToolExecutor for RuntimeTeamTaskExecutor {
    fn execute(&self, _request: ExecutionRequest) -> ExecutionFuture<'_> {
        Box::pin(async {
            Err(ExecutorError::Failed {
                code: "team_task_runtime_required".into(),
                message: "Team task tools require the Zeus durable Session runtime".into(),
                retryable: false,
            })
        })
    }
}

fn require_member(board: &TeamTaskBoard, caller_session_id: &str) -> Result<(), TeamTaskError> {
    validate_session_id(caller_session_id)?;
    board
        .contains_member(caller_session_id)
        .then_some(())
        .ok_or(TeamTaskError::CallerNotMember)
}

fn canonical_text(value: &str, max_bytes: usize) -> Option<String> {
    let canonical = value.trim();
    (!canonical.is_empty()
        && canonical.len() <= max_bytes
        && !canonical.chars().any(char::is_control))
    .then(|| canonical.to_owned())
}

fn validate_session_id(value: &str) -> Result<(), TeamTaskError> {
    (!value.is_empty()
        && value.len() <= 128
        && value.trim() == value
        && !value.chars().any(char::is_control))
    .then_some(())
    .ok_or(TeamTaskError::CallerNotMember)
}

fn parse_task_id(value: &str) -> Result<u64, TeamTaskError> {
    let number = value
        .strip_prefix("task-")
        .filter(|value| !value.is_empty() && !value.starts_with('0'))
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0 && *value <= TEAM_TASK_MAX_TASKS as u64)
        .ok_or(TeamTaskError::InvalidTaskId)?;
    (format!("task-{number}") == value)
        .then_some(number)
        .ok_or(TeamTaskError::InvalidTaskId)
}

fn canonical_dependencies(
    values: &[String],
    self_id: Option<&str>,
    board: &TeamTaskBoard,
) -> Result<Vec<String>, TeamTaskError> {
    let canonical = canonical_dependency_values(values, self_id)?;
    for dependency in &canonical {
        let task = board.current(dependency).ok_or(TeamTaskError::NotFound)?;
        if task.status == TeamTaskStatus::Deleted {
            return Err(TeamTaskError::NotFound);
        }
    }
    Ok(canonical)
}

fn canonical_dependency_values(
    values: &[String],
    self_id: Option<&str>,
) -> Result<Vec<String>, TeamTaskError> {
    if values.len() > TEAM_TASK_MAX_DEPENDENCIES {
        return Err(TeamTaskError::InvalidDependencies);
    }
    let mut seen = BTreeSet::new();
    let mut canonical = Vec::with_capacity(values.len());
    for value in values {
        parse_task_id(value)?;
        if self_id == Some(value.as_str()) {
            return Err(TeamTaskError::DependencyCycle);
        }
        if !seen.insert(value.as_str()) {
            return Err(TeamTaskError::InvalidDependencies);
        }
        canonical.push(value.clone());
    }
    Ok(canonical)
}

fn canonical_write_scopes(values: &[String]) -> Result<Vec<String>, TeamTaskError> {
    if values.len() > TEAM_TASK_MAX_WRITE_SCOPES {
        return Err(TeamTaskError::InvalidWriteScope);
    }
    let mut scopes = BTreeSet::new();
    for value in values {
        if value.is_empty()
            || value.len() > TEAM_TASK_WRITE_SCOPE_MAX_BYTES
            || value.trim() != value
            || value.starts_with('/')
            || value.ends_with('/')
            || value.contains('\\')
            || value.chars().any(char::is_control)
            || value
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(TeamTaskError::InvalidWriteScope);
        }
        scopes.insert(value.clone());
    }
    Ok(scopes.into_iter().collect())
}

fn board_with_candidate(board: &TeamTaskBoard, candidate: &TeamTaskSnapshot) -> TeamTaskBoard {
    let mut tasks = board
        .tasks
        .iter()
        .filter(|task| task.id != candidate.id)
        .cloned()
        .collect::<Vec<_>>();
    tasks.push(candidate.clone());
    tasks.sort_by_key(|task| parse_task_id(&task.id).unwrap_or(u64::MAX));
    TeamTaskBoard {
        root_session_id: board.root_session_id.clone(),
        members: board.members.clone(),
        tasks,
    }
}

fn validate_graph(tasks: &[TeamTaskSnapshot]) -> Result<(), TeamTaskError> {
    let by_id = tasks
        .iter()
        .map(|task| (task.id.as_str(), task))
        .collect::<BTreeMap<_, _>>();
    for task in tasks {
        for dependency in &task.blocked_by {
            if by_id
                .get(dependency.as_str())
                .is_none_or(|dependency| dependency.status == TeamTaskStatus::Deleted)
            {
                return Err(TeamTaskError::InvalidDependencies);
            }
        }
    }
    fn visit<'a>(
        id: &'a str,
        by_id: &BTreeMap<&'a str, &'a TeamTaskSnapshot>,
        visiting: &mut BTreeSet<&'a str>,
        complete: &mut BTreeSet<&'a str>,
    ) -> Result<(), TeamTaskError> {
        if complete.contains(id) {
            return Ok(());
        }
        if !visiting.insert(id) {
            return Err(TeamTaskError::DependencyCycle);
        }
        if let Some(task) = by_id.get(id) {
            for dependency in &task.blocked_by {
                visit(dependency, by_id, visiting, complete)?;
            }
        }
        visiting.remove(id);
        complete.insert(id);
        Ok(())
    }
    let mut complete = BTreeSet::new();
    for id in by_id.keys().copied() {
        visit(id, &by_id, &mut BTreeSet::new(), &mut complete)?;
    }
    Ok(())
}

fn task_ready(board: &TeamTaskBoard, task: &TeamTaskSnapshot) -> bool {
    task.status == TeamTaskStatus::Pending && dependencies_completed(board, task)
}

fn dependencies_completed(board: &TeamTaskBoard, task: &TeamTaskSnapshot) -> bool {
    task.blocked_by.iter().all(|dependency| {
        board
            .current(dependency)
            .is_some_and(|task| task.status == TeamTaskStatus::Completed)
    })
}

fn scopes_overlap(left: &str, right: &str) -> bool {
    left == right
        || left
            .strip_prefix(right)
            .is_some_and(|suffix| suffix.starts_with('/'))
        || right
            .strip_prefix(left)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn task_warnings(board: &TeamTaskBoard, task: &TeamTaskSnapshot) -> Vec<String> {
    board
        .tasks
        .iter()
        .filter(|other| other.id != task.id && other.status == TeamTaskStatus::InProgress)
        .filter(|other| {
            task.write_scopes.iter().any(|left| {
                other
                    .write_scopes
                    .iter()
                    .any(|right| scopes_overlap(left, right))
            })
        })
        .map(|other| format!("write scopes overlap with {}", other.id))
        .collect()
}

fn task_view(
    board: &TeamTaskBoard,
    task: &TeamTaskSnapshot,
) -> Result<TeamTaskView, TeamTaskError> {
    validate_snapshot(task)?;
    Ok(TeamTaskView {
        id: task.id.clone(),
        revision: task.revision,
        subject: task.subject.clone(),
        description: task.description.clone(),
        status: task.status,
        owner_session_id: task.owner_session_id.clone(),
        blocked_by: task.blocked_by.clone(),
        write_scopes: task.write_scopes.clone(),
        ready: task_ready(board, task),
        write_scope_warnings: task_warnings(board, task),
    })
}

fn task_summary(
    board: &TeamTaskBoard,
    task: &TeamTaskSnapshot,
) -> Result<TeamTaskSummary, TeamTaskError> {
    validate_snapshot(task)?;
    Ok(TeamTaskSummary {
        id: task.id.clone(),
        revision: task.revision,
        subject: task.subject.clone(),
        status: task.status,
        owner_session_id: task.owner_session_id.clone(),
        blocked_by: task.blocked_by.clone(),
        ready: task_ready(board, task),
        write_scope_warnings: task_warnings(board, task),
    })
}

fn validate_view(view: &TeamTaskView) -> Result<(), TeamTaskError> {
    validate_snapshot(&TeamTaskSnapshot {
        id: view.id.clone(),
        revision: view.revision,
        subject: view.subject.clone(),
        description: view.description.clone(),
        status: view.status,
        owner_session_id: view.owner_session_id.clone(),
        blocked_by: view.blocked_by.clone(),
        write_scopes: view.write_scopes.clone(),
    })
}

fn validate_output<T: Serialize>(value: &T) -> Result<(), TeamTaskError> {
    let encoded = serde_json::to_vec(value).map_err(|_| TeamTaskError::InvalidResult)?;
    (encoded.len() <= TOOL_OUTPUT_MAX_SERIALIZED_BYTES)
        .then_some(())
        .ok_or(TeamTaskError::InvalidResult)
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

fn optional_array() -> ParameterSpec {
    ParameterSpec {
        parameter_type: ParameterType::Array,
        required: false,
        min_length: None,
        max_length: None,
    }
}

fn optional_boolean() -> ParameterSpec {
    ParameterSpec {
        parameter_type: ParameterType::Boolean,
        required: false,
        min_length: None,
        max_length: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn board() -> TeamTaskBoard {
        TeamTaskBoard {
            root_session_id: "root".into(),
            members: vec![
                TeamMember {
                    session_id: "root".into(),
                    assignable: true,
                },
                TeamMember {
                    session_id: "child-a".into(),
                    assignable: true,
                },
                TeamMember {
                    session_id: "child-b".into(),
                    assignable: true,
                },
            ],
            tasks: Vec::new(),
        }
    }

    #[test]
    fn task_dag_is_cas_bound_owned_and_ready_only_after_blockers_complete() {
        let mut state = board();
        let first = prepare_create(
            &serde_json::json!({
                "subject": "foundation",
                "description": "Build the durable foundation",
                "write_scopes": ["crates/storage"]
            }),
            &state,
            "root",
        )
        .unwrap();
        state.tasks.push(first.snapshot().clone());
        let second = prepare_create(
            &serde_json::json!({
                "subject": "runtime",
                "description": "Connect the runtime",
                "blocked_by": ["task-1"],
                "write_scopes": ["crates/runtime"]
            }),
            &state,
            "child-a",
        )
        .unwrap();
        state.tasks.push(second.snapshot().clone());
        assert!(!get_task(&state, "child-a", "task-2").unwrap().task.ready);
        assert!(matches!(
            prepare_update(
                &serde_json::json!({
                    "task_id": "task-2", "expected_revision": 1, "action": "claim"
                }),
                &state,
                "child-a"
            ),
            Err(TeamTaskError::Blocked)
        ));
        let claimed = prepare_update(
            &serde_json::json!({
                "task_id": "task-1", "expected_revision": 1, "action": "claim"
            }),
            &state,
            "child-a",
        )
        .unwrap();
        state.tasks[0] = claimed.snapshot().clone();
        let completed = prepare_update(
            &serde_json::json!({
                "task_id": "task-1", "expected_revision": 2, "action": "complete"
            }),
            &state,
            "child-a",
        )
        .unwrap();
        state.tasks[0] = completed.snapshot().clone();
        assert!(get_task(&state, "child-b", "task-2").unwrap().task.ready);
        assert!(matches!(
            prepare_update(
                &serde_json::json!({
                    "task_id": "task-1", "expected_revision": 2, "action": "reopen"
                }),
                &state,
                "root"
            ),
            Err(TeamTaskError::RevisionConflict)
        ));
    }

    #[test]
    fn dependencies_cycles_deletes_and_lead_reassignment_fail_closed() {
        let mut state = board();
        for subject in ["one", "two"] {
            let prepared = prepare_create(
                &serde_json::json!({"subject": subject, "description": "work"}),
                &state,
                "root",
            )
            .unwrap();
            state.tasks.push(prepared.snapshot().clone());
        }
        let second = prepare_update(
            &serde_json::json!({
                "task_id": "task-2", "expected_revision": 1,
                "action": "set_dependencies", "blocked_by": ["task-1"]
            }),
            &state,
            "root",
        )
        .unwrap();
        state.tasks[1] = second.snapshot().clone();
        assert!(matches!(
            prepare_update(
                &serde_json::json!({
                    "task_id": "task-1", "expected_revision": 1,
                    "action": "set_dependencies", "blocked_by": ["task-2"]
                }),
                &state,
                "root"
            ),
            Err(TeamTaskError::DependencyCycle)
        ));
        assert!(matches!(
            prepare_update(
                &serde_json::json!({
                    "task_id": "task-1", "expected_revision": 1, "action": "delete"
                }),
                &state,
                "root"
            ),
            Err(TeamTaskError::HasDependents)
        ));
        assert!(matches!(
            prepare_update(
                &serde_json::json!({
                    "task_id": "task-1", "expected_revision": 1,
                    "action": "reassign", "owner_session_id": "child-b"
                }),
                &state,
                "child-a"
            ),
            Err(TeamTaskError::LeadRequired)
        ));
        assert!(matches!(
            prepare_update(
                &serde_json::json!({
                    "task_id": "task-1", "expected_revision": 1,
                    "action": "reassign", "owner_session_id": "invalid\nsession"
                }),
                &state,
                "root"
            ),
            Err(TeamTaskError::InvalidAssignee)
        ));
        let claimed = prepare_update(
            &serde_json::json!({
                "task_id": "task-1", "expected_revision": 1, "action": "claim"
            }),
            &state,
            "child-a",
        )
        .unwrap();
        state.tasks[0] = claimed.snapshot().clone();
        let reassigned = prepare_update(
            &serde_json::json!({
                "task_id": "task-1", "expected_revision": 2,
                "action": "reassign", "owner_session_id": "child-b"
            }),
            &state,
            "root",
        )
        .unwrap();
        assert_eq!(
            reassigned.snapshot().owner_session_id.as_deref(),
            Some("child-b")
        );
    }

    #[test]
    fn list_is_bounded_filtered_and_write_scope_overlap_is_advisory() {
        let mut state = board();
        for index in 0..18 {
            let prepared = prepare_create(
                &serde_json::json!({
                    "subject": format!("task {index}"),
                    "description": "work",
                    "write_scopes": [if index < 2 { "crates/storage" } else { "docs" }]
                }),
                &state,
                "root",
            )
            .unwrap();
            state.tasks.push(prepared.snapshot().clone());
        }
        let claimed = prepare_update(
            &serde_json::json!({
                "task_id": "task-1", "expected_revision": 1, "action": "claim"
            }),
            &state,
            "child-a",
        )
        .unwrap();
        state.tasks[0] = claimed.snapshot().clone();
        assert_eq!(
            get_task(&state, "root", "task-2")
                .unwrap()
                .task
                .write_scope_warnings,
            vec!["write scopes overlap with task-1"]
        );
        let first = list_tasks(
            &state,
            "root",
            &prepare_list(&serde_json::json!({})).unwrap(),
        )
        .unwrap();
        assert_eq!(first.tasks.len(), TEAM_TASK_LIST_DEFAULT_LIMIT);
        assert_eq!(first.next_after_task_id.as_deref(), Some("task-16"));
        let second = list_tasks(
            &state,
            "child-b",
            &prepare_list(&serde_json::json!({
                "after_task_id": "task-16", "limit": 16
            }))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(second.tasks.len(), 2);
        assert!(second.next_after_task_id.is_none());
    }

    #[test]
    fn descriptors_are_closed_bounded_and_runtime_owned() {
        let descriptors = team_task_descriptors();
        assert_eq!(descriptors.len(), 4);
        assert_eq!(descriptors[0].name, TEAM_TASK_CREATE_TOOL_NAME);
        assert_eq!(descriptors[3].name, TEAM_TASK_UPDATE_TOOL_NAME);
        for descriptor in &descriptors {
            assert_eq!(descriptor.version, TEAM_TASK_TOOL_VERSION);
            descriptor.input_schema.provider_json_schema().unwrap();
        }
        assert_eq!(descriptors[0].effect, ToolEffect::LocalWrite);
        assert_eq!(descriptors[1].effect, ToolEffect::ReadOnly);
    }

    #[test]
    fn canonical_paths_ids_and_payloads_reject_ambiguous_values() {
        let state = board();
        for invalid in [
            serde_json::json!({"subject":"x", "description":"work", "write_scopes":["/tmp"]}),
            serde_json::json!({"subject":"x", "description":"work", "write_scopes":["a/../b"]}),
            serde_json::json!({"subject":"x\ny", "description":"work"}),
            serde_json::json!({"subject":"x", "description":"work", "blocked_by":["task-01"]}),
        ] {
            assert!(prepare_create(&invalid, &state, "root").is_err());
        }
        assert!(prepare_get(&serde_json::json!({"task_id":"task-0"})).is_err());
    }
}
