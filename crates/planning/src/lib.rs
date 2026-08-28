//! Agent-owned durable planning snapshots and the model-facing `todo_write` tool.
//!
//! The executor performs only bounded canonicalization. SQLite commits the
//! resulting whole-list replacement atomically with the exact Agent tool
//! completion, so model-visible success cannot outrun durable state.

use std::collections::BTreeMap;

use protocol::{AgentTodoItem, AgentTodoStatus, SandboxProfile, ToolEffect};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tools::{
    ExecutionFuture, ExecutionRequest, ExecutorError, ObjectSchema, ParameterSpec, ParameterType,
    RegistryError, ToolDescriptor, ToolExecutor, ToolOutput, ToolRegistry,
};

pub const TODO_WRITE_TOOL_NAME: &str = "todo_write";
pub const TODO_WRITE_TOOL_VERSION: &str = "1-single-active";
pub const TODO_MAX_ITEMS: usize = 24;
pub const TODO_CONTENT_MAX_BYTES: usize = 256;
pub const TODO_ARGUMENTS_MAX_BYTES: usize = 12 * 1024;
pub const TODO_DIGEST_PREFIX: &str = "sha256:";

const TODO_DESCRIPTION: &str = "Replace the complete structured task list for this Agent turn using the current expected_revision. Send every item on each call; there are no partial edits. Use pending, in_progress, or completed, keep at most one item in_progress, and use revision 0 for the first write. The result returns the next revision for a later replacement.";

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum TodoError {
    #[error("todo_write arguments are not a strict bounded object")]
    InvalidArguments,
    #[error("expected_revision is outside the durable integer range")]
    InvalidRevision,
    #[error("todo list exceeds the {TODO_MAX_ITEMS}-item limit")]
    TooManyItems,
    #[error(
        "todo content must be a non-empty control-free line of at most {TODO_CONTENT_MAX_BYTES} UTF-8 bytes"
    )]
    InvalidContent,
    #[error("todo content is duplicated after canonical trimming")]
    DuplicateContent,
    #[error("at most one todo may be in_progress")]
    ParallelInProgress,
    #[error("todo revision overflow")]
    RevisionOverflow,
    #[error("todo_write result does not match its canonical snapshot")]
    InvalidResult,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTodoWriteArguments {
    expected_revision: u64,
    todos: Vec<AgentTodoItem>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedTodoWrite {
    expected_revision: u64,
    revision: u64,
    digest: String,
    todos: Vec<AgentTodoItem>,
    counts: TodoCounts,
}

impl PreparedTodoWrite {
    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn todos(&self) -> &[AgentTodoItem] {
        &self.todos
    }

    pub const fn counts(&self) -> &TodoCounts {
        &self.counts
    }

    pub fn result(&self) -> TodoWriteResult {
        TodoWriteResult {
            revision: self.revision,
            digest: self.digest.clone(),
            todos: self.todos.clone(),
            counts: self.counts.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TodoCounts {
    pub pending: u32,
    pub in_progress: u32,
    pub completed: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TodoWriteResult {
    pub revision: u64,
    pub digest: String,
    pub todos: Vec<AgentTodoItem>,
    pub counts: TodoCounts,
}

pub fn prepare_todo_write(arguments: &Value) -> Result<PreparedTodoWrite, TodoError> {
    let raw: RawTodoWriteArguments =
        serde_json::from_value(arguments.clone()).map_err(|_| TodoError::InvalidArguments)?;
    if raw.expected_revision > i64::MAX as u64 {
        return Err(TodoError::InvalidRevision);
    }
    if raw.todos.len() > TODO_MAX_ITEMS {
        return Err(TodoError::TooManyItems);
    }

    let mut todos = Vec::with_capacity(raw.todos.len());
    let mut seen = std::collections::BTreeSet::new();
    let mut pending = 0u32;
    let mut in_progress = 0u32;
    let mut completed = 0u32;
    for mut todo in raw.todos {
        let content = todo.content.trim();
        if content.is_empty()
            || content.len() > TODO_CONTENT_MAX_BYTES
            || content.chars().any(char::is_control)
        {
            return Err(TodoError::InvalidContent);
        }
        if !seen.insert(content.to_owned()) {
            return Err(TodoError::DuplicateContent);
        }
        todo.content = content.to_owned();
        match todo.status {
            AgentTodoStatus::Pending => pending = pending.saturating_add(1),
            AgentTodoStatus::InProgress => in_progress = in_progress.saturating_add(1),
            AgentTodoStatus::Completed => completed = completed.saturating_add(1),
        }
        todos.push(todo);
    }
    if in_progress > 1 {
        return Err(TodoError::ParallelInProgress);
    }
    let revision = raw
        .expected_revision
        .checked_add(1)
        .filter(|revision| *revision <= i64::MAX as u64)
        .ok_or(TodoError::RevisionOverflow)?;
    let digest = todo_digest(&todos)?;
    Ok(PreparedTodoWrite {
        expected_revision: raw.expected_revision,
        revision,
        digest,
        todos,
        counts: TodoCounts {
            pending,
            in_progress,
            completed,
        },
    })
}

pub fn decode_todo_write_result(value: &Value) -> Result<TodoWriteResult, TodoError> {
    let result: TodoWriteResult =
        serde_json::from_value(value.clone()).map_err(|_| TodoError::InvalidResult)?;
    let prepared = prepare_todo_write(&serde_json::json!({
        "expected_revision": result.revision.checked_sub(1).ok_or(TodoError::InvalidResult)?,
        "todos": result.todos,
    }))?;
    if result != prepared.result() {
        return Err(TodoError::InvalidResult);
    }
    Ok(result)
}

pub fn todo_digest(todos: &[AgentTodoItem]) -> Result<String, TodoError> {
    let mut hasher = Sha256::new();
    hasher.update(b"zeus-agent-todo-v1\0");
    hasher.update(
        u64::try_from(todos.len())
            .map_err(|_| TodoError::TooManyItems)?
            .to_be_bytes(),
    );
    for todo in todos {
        hash_field(&mut hasher, todo.content.as_bytes());
        hash_field(
            &mut hasher,
            match todo.status {
                AgentTodoStatus::Pending => b"pending",
                AgentTodoStatus::InProgress => b"in_progress",
                AgentTodoStatus::Completed => b"completed",
            },
        );
    }
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(TODO_DIGEST_PREFIX.len() + digest.len() * 2);
    encoded.push_str(TODO_DIGEST_PREFIX);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(encoded)
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

pub fn todo_write_descriptor() -> ToolDescriptor {
    let item_properties = BTreeMap::from([
        (
            "content".into(),
            ParameterSpec::required_string(TODO_CONTENT_MAX_BYTES),
        ),
        (
            "status".into(),
            ParameterSpec {
                parameter_type: ParameterType::StringEnum {
                    values: vec!["pending".into(), "in_progress".into(), "completed".into()],
                },
                required: true,
                min_length: None,
                max_length: None,
            },
        ),
    ]);
    ToolDescriptor {
        name: TODO_WRITE_TOOL_NAME.into(),
        version: TODO_WRITE_TOOL_VERSION.into(),
        description: TODO_DESCRIPTION.into(),
        effect: ToolEffect::LocalWrite,
        sandbox_profile: SandboxProfile::ReadOnly,
        input_schema: ObjectSchema {
            max_serialized_bytes: TODO_ARGUMENTS_MAX_BYTES,
            properties: BTreeMap::from([
                (
                    "expected_revision".into(),
                    ParameterSpec {
                        parameter_type: ParameterType::Integer,
                        required: true,
                        min_length: None,
                        max_length: None,
                    },
                ),
                (
                    "todos".into(),
                    ParameterSpec {
                        parameter_type: ParameterType::ArrayOfObjects {
                            min_items: 0,
                            max_items: TODO_MAX_ITEMS,
                            properties: item_properties,
                        },
                        required: true,
                        min_length: None,
                        max_length: None,
                    },
                ),
            ]),
        },
    }
}

pub fn register_todo_tool(registry: &mut ToolRegistry) -> Result<(), RegistryError> {
    registry.register(todo_write_descriptor(), TodoWriteExecutor)
}

#[derive(Clone, Copy)]
struct TodoWriteExecutor;

impl ToolExecutor for TodoWriteExecutor {
    fn execute(&self, request: ExecutionRequest) -> ExecutionFuture<'_> {
        Box::pin(async move {
            if request.scope.is_none() {
                return Err(todo_failure(
                    "todo_scope_required",
                    "todo_write requires a server-owned Agent execution scope",
                ));
            }
            let prepared = prepare_todo_write(&request.call.arguments).map_err(|error| {
                todo_failure(todo_error_code(&error), "The todo snapshot is invalid")
            })?;
            Ok(ToolOutput {
                value: serde_json::to_value(prepared.result()).map_err(|_| {
                    todo_failure(
                        "todo_result_encoding_failed",
                        "The todo result could not be encoded",
                    )
                })?,
                replayed: false,
                provider_request_id: None,
            })
        })
    }
}

fn todo_error_code(error: &TodoError) -> &'static str {
    match error {
        TodoError::InvalidArguments => "todo_invalid_arguments",
        TodoError::InvalidRevision | TodoError::RevisionOverflow => "todo_invalid_revision",
        TodoError::TooManyItems => "todo_too_many_items",
        TodoError::InvalidContent => "todo_invalid_content",
        TodoError::DuplicateContent => "todo_duplicate_content",
        TodoError::ParallelInProgress => "todo_parallel_in_progress",
        TodoError::InvalidResult => "todo_invalid_result",
    }
}

fn todo_failure(code: &str, message: &str) -> ExecutorError {
    ExecutorError::Failed {
        code: code.into(),
        message: message.into(),
        retryable: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::{ToolCall, ToolExecutorStatus};
    use tools::{ExecutionScope, arguments_digest};

    fn valid_arguments() -> Value {
        serde_json::json!({
            "expected_revision": 0,
            "todos": [
                {"content": "  inspect state  ", "status": "in_progress"},
                {"content": "apply fix", "status": "pending"}
            ]
        })
    }

    #[test]
    fn whole_list_is_canonical_bounded_unique_and_single_active() {
        let prepared = prepare_todo_write(&valid_arguments()).unwrap();
        assert_eq!(prepared.expected_revision(), 0);
        assert_eq!(prepared.revision(), 1);
        assert_eq!(prepared.todos()[0].content, "inspect state");
        assert_eq!(prepared.counts().pending, 1);
        assert_eq!(prepared.counts().in_progress, 1);
        assert_eq!(prepared.digest().len(), TODO_DIGEST_PREFIX.len() + 64);
        assert_eq!(
            decode_todo_write_result(&serde_json::to_value(prepared.result()).unwrap()).unwrap(),
            prepared.result()
        );

        for invalid in [
            serde_json::json!({"expected_revision": 0, "todos": [{"content":" ","status":"pending"}]}),
            serde_json::json!({"expected_revision": 0, "todos": [{"content":"same","status":"pending"},{"content":" same ","status":"completed"}]}),
            serde_json::json!({"expected_revision": 0, "todos": [{"content":"a","status":"in_progress"},{"content":"b","status":"in_progress"}]}),
            serde_json::json!({"expected_revision": 0, "todos": [{"content":"line\nbreak","status":"pending"}]}),
        ] {
            assert!(prepare_todo_write(&invalid).is_err());
        }
    }

    #[test]
    fn descriptor_exposes_exact_nested_schema_and_revision_contract() {
        let descriptor = todo_write_descriptor();
        assert_eq!(descriptor.name, TODO_WRITE_TOOL_NAME);
        assert_eq!(descriptor.version, TODO_WRITE_TOOL_VERSION);
        assert_eq!(descriptor.effect, ToolEffect::LocalWrite);
        let schema = descriptor.input_schema.provider_json_schema().unwrap();
        assert_eq!(schema["properties"]["todos"]["maxItems"], TODO_MAX_ITEMS);
        assert_eq!(
            schema["properties"]["todos"]["items"]["properties"]["status"]["enum"],
            serde_json::json!(["pending", "in_progress", "completed"])
        );
        assert_eq!(
            schema["required"],
            serde_json::json!(["expected_revision", "todos"])
        );
    }

    fn call(descriptor: &ToolDescriptor, arguments: Value) -> ToolCall {
        ToolCall {
            call_id: "call-todo-write".into(),
            tool: descriptor.name.clone(),
            tool_version: descriptor.version.clone(),
            arguments_digest: arguments_digest(&arguments),
            arguments,
            effect: descriptor.effect.clone(),
            sandbox_profile: descriptor.sandbox_profile.clone(),
            executor_status: ToolExecutorStatus::Available,
        }
    }

    #[tokio::test]
    async fn executor_requires_agent_scope_and_returns_the_exact_snapshot() {
        let descriptor = todo_write_descriptor();
        let mut registry = ToolRegistry::new();
        register_todo_tool(&mut registry).unwrap();
        let arguments = valid_arguments();
        let unscoped = registry
            .dispatch(call(&descriptor, arguments.clone()), "production")
            .await
            .unwrap_err();
        assert!(matches!(
            unscoped,
            RegistryError::Executor(ExecutorError::Failed { code, .. })
                if code == "todo_scope_required"
        ));

        let output = registry
            .dispatch_scoped(
                call(&descriptor, arguments),
                "production",
                ExecutionScope::new("acc", "actor", "session", "turn", "agent").unwrap(),
            )
            .await
            .unwrap();
        let result = decode_todo_write_result(&output.value).unwrap();
        assert_eq!(result.revision, 1);
        assert_eq!(result.todos[0].content, "inspect state");
    }

    #[test]
    fn digest_is_domain_separated_order_sensitive_and_locked() {
        let first = prepare_todo_write(&serde_json::json!({
            "expected_revision": 0,
            "todos": [{"content":"a","status":"pending"},{"content":"b","status":"completed"}]
        }))
        .unwrap();
        let reversed = prepare_todo_write(&serde_json::json!({
            "expected_revision": 0,
            "todos": [{"content":"b","status":"completed"},{"content":"a","status":"pending"}]
        }))
        .unwrap();
        assert_ne!(first.digest(), reversed.digest());
        assert_eq!(
            first.digest(),
            "sha256:a7d770322b0bad4d0bc0b972fdb51f850865ae47a1b11d63e5b9a583c236766e"
        );
    }
}
