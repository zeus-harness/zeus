//! Narrow, explicitly configured tool connectors.
//!
//! The Alpha ships a local marker executor plus capability-rooted workspace
//! discovery, literal text search, and file reading. They are registered only
//! for `local-development`; no connector has a host-command or remote-provider
//! fallback.

use std::{
    collections::{BTreeMap, VecDeque},
    fs::{self, File, OpenOptions as StdOpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions as CapOpenOptions},
};
use protocol::{SandboxProfile, ToolCall, ToolEffect};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use tools::{
    ExecutionFuture, ExecutionRequest, ExecutorError, ObjectSchema, ParameterSpec, ParameterType,
    RegistryError, ToolDescriptor, ToolExecutor, ToolOutput, ToolRegistry,
};

pub const LOCAL_DEV_ENVIRONMENT: &str = "local-development";
/// Provider-visible function name. DeepSeek/OpenAI-compatible function names
/// permit only ASCII letters, digits, underscores, and dashes.
pub const DEV_MARKER_TOOL_NAME: &str = "dev_marker_write";
pub const DEV_MARKER_TOOL_VERSION: &str = "1";
pub const MAX_MARKER_BYTES: usize = 128;
pub const WORKSPACE_READ_FILE_TOOL_NAME: &str = "workspace_read_file";
pub const WORKSPACE_READ_FILE_TOOL_VERSION: &str = "1";
pub const WORKSPACE_LIST_DIRECTORY_TOOL_NAME: &str = "workspace_list_directory";
pub const WORKSPACE_LIST_DIRECTORY_TOOL_VERSION: &str = "1";
pub const WORKSPACE_SEARCH_TEXT_TOOL_NAME: &str = "workspace_search_text";
pub const WORKSPACE_SEARCH_TEXT_TOOL_VERSION: &str = "1";
pub const WORKSPACE_REPLACE_TEXT_TOOL_NAME: &str = "workspace_replace_text";
pub const WORKSPACE_REPLACE_TEXT_TOOL_VERSION: &str = "1";
pub const WORKSPACE_CREATE_FILE_TOOL_NAME: &str = "workspace_create_file";
pub const WORKSPACE_CREATE_FILE_TOOL_VERSION: &str = "1";
pub const MAX_WORKSPACE_PATH_BYTES: usize = 512;
pub const MAX_WORKSPACE_FILE_BYTES: usize = 8 * 1024;
pub const MAX_WORKSPACE_DIRECTORY_ENTRIES: usize = 64;
pub const MAX_WORKSPACE_SEARCH_QUERY_BYTES: usize = 256;
pub const MAX_WORKSPACE_SEARCH_MATCHES: usize = 32;
pub const MAX_WORKSPACE_SEARCH_FILES: usize = 256;
pub const MAX_WORKSPACE_SEARCH_DIRECTORIES: usize = 64;
pub const MAX_WORKSPACE_SEARCH_TOTAL_BYTES: usize = 1024 * 1024;
pub const MAX_WORKSPACE_SEARCH_FILE_BYTES: usize = 64 * 1024;
pub const MAX_WORKSPACE_SEARCH_DEPTH: usize = 12;
pub const MAX_WORKSPACE_SEARCH_PREVIEW_BYTES: usize = 256;
pub const MAX_WORKSPACE_EDIT_TEXT_BYTES: usize = 4 * 1024;
pub const MAX_WORKSPACE_EDIT_FILE_BYTES: usize = 64 * 1024;
pub const MAX_WORKSPACE_CREATE_CONTENT_BYTES: usize = 12 * 1024;
pub const MAX_WORKSPACE_MUTATION_RECEIPTS: usize = 1024;

const WORKSPACE_SEARCH_IGNORED_DIRECTORIES: [&str; 6] = [
    ".git",
    ".svelte-kit",
    ".zeus",
    "node_modules",
    "target",
    "dist",
];

static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ConnectorConfigError {
    #[error("development connectors cannot be registered in environment `{0}`")]
    EnvironmentDenied(String),
    #[error("marker root must be a directory: {0}")]
    InvalidRoot(String),
    #[error("failed to prepare marker root: {0}")]
    RootIo(String),
    #[error("workspace root must be a directory: {0}")]
    InvalidWorkspaceRoot(String),
    #[error("failed to open workspace root: {0}")]
    WorkspaceRootIo(String),
    #[error(transparent)]
    Registry(#[from] RegistryError),
}

/// Registers the complete local-development connector set.
///
/// The environment check happens before the directory is touched. Callers must
/// invoke this only from explicit local-development configuration.
pub fn register_local_dev_connectors(
    registry: &mut ToolRegistry,
    environment: &str,
    marker_root: impl AsRef<Path>,
) -> Result<PathBuf, ConnectorConfigError> {
    if environment != LOCAL_DEV_ENVIRONMENT {
        return Err(ConnectorConfigError::EnvironmentDenied(
            environment.to_owned(),
        ));
    }

    let executor = DevMarkerWriteExecutor::new(marker_root.as_ref())?;
    let canonical_root = executor.root.clone();
    registry.register(dev_marker_descriptor(), executor)?;
    Ok(canonical_root)
}

/// Register the bounded workspace connectors for local development.
///
/// The ambient path is resolved once at startup and converted into a rooted
/// capability. Model-selected paths are always relative to that capability.
pub fn register_local_workspace_connectors(
    registry: &mut ToolRegistry,
    environment: &str,
    workspace_root: impl AsRef<Path>,
) -> Result<PathBuf, ConnectorConfigError> {
    if environment != LOCAL_DEV_ENVIRONMENT {
        return Err(ConnectorConfigError::EnvironmentDenied(
            environment.to_owned(),
        ));
    }

    let executor = WorkspaceReadFileExecutor::new(workspace_root.as_ref())?;
    let canonical_root = executor.canonical_root.clone();
    let list_executor = WorkspaceListDirectoryExecutor {
        roots: Arc::clone(&executor.roots),
    };
    let search_executor = WorkspaceSearchTextExecutor {
        roots: Arc::clone(&executor.roots),
    };
    let replace_executor = WorkspaceReplaceTextExecutor {
        roots: Arc::clone(&executor.roots),
    };
    let create_executor = WorkspaceCreateFileExecutor {
        roots: Arc::clone(&executor.roots),
    };
    registry.register(workspace_read_file_descriptor(), executor)?;
    registry.register(workspace_list_directory_descriptor(), list_executor)?;
    registry.register(workspace_search_text_descriptor(), search_executor)?;
    registry.register(workspace_replace_text_descriptor(), replace_executor)?;
    registry.register(workspace_create_file_descriptor(), create_executor)?;
    Ok(canonical_root)
}

pub fn dev_marker_descriptor() -> ToolDescriptor {
    ToolDescriptor {
        name: DEV_MARKER_TOOL_NAME.into(),
        version: DEV_MARKER_TOOL_VERSION.into(),
        description: "Write one bounded marker below the configured local development root".into(),
        effect: ToolEffect::LocalWrite,
        sandbox_profile: SandboxProfile::WorkspaceWrite,
        input_schema: ObjectSchema {
            max_serialized_bytes: 160,
            properties: BTreeMap::from([(
                "marker".into(),
                ParameterSpec::required_string(MAX_MARKER_BYTES),
            )]),
        },
    }
}

pub fn workspace_read_file_descriptor() -> ToolDescriptor {
    ToolDescriptor {
        name: WORKSPACE_READ_FILE_TOOL_NAME.into(),
        version: WORKSPACE_READ_FILE_TOOL_VERSION.into(),
        description: format!(
            "Read one UTF-8 regular file relative to the configured workspace root (maximum {MAX_WORKSPACE_FILE_BYTES} bytes)"
        ),
        effect: ToolEffect::ReadOnly,
        sandbox_profile: SandboxProfile::ReadOnly,
        input_schema: ObjectSchema {
            max_serialized_bytes: 4 * 1024,
            properties: BTreeMap::from([(
                "path".into(),
                ParameterSpec::required_string(MAX_WORKSPACE_PATH_BYTES),
            )]),
        },
    }
}

pub fn workspace_list_directory_descriptor() -> ToolDescriptor {
    ToolDescriptor {
        name: WORKSPACE_LIST_DIRECTORY_TOOL_NAME.into(),
        version: WORKSPACE_LIST_DIRECTORY_TOOL_VERSION.into(),
        description: format!(
            "List one directory relative to the configured workspace root (maximum {MAX_WORKSPACE_DIRECTORY_ENTRIES} entries; use . for the root)"
        ),
        effect: ToolEffect::ReadOnly,
        sandbox_profile: SandboxProfile::ReadOnly,
        input_schema: ObjectSchema {
            max_serialized_bytes: 4 * 1024,
            properties: BTreeMap::from([(
                "path".into(),
                ParameterSpec::required_string(MAX_WORKSPACE_PATH_BYTES),
            )]),
        },
    }
}

pub fn workspace_search_text_descriptor() -> ToolDescriptor {
    ToolDescriptor {
        name: WORKSPACE_SEARCH_TEXT_TOOL_NAME.into(),
        version: WORKSPACE_SEARCH_TEXT_TOOL_VERSION.into(),
        description: format!(
            "Search UTF-8 workspace files for literal text below one relative directory (maximum {MAX_WORKSPACE_SEARCH_MATCHES} matches; use . for the root)"
        ),
        effect: ToolEffect::ReadOnly,
        sandbox_profile: SandboxProfile::ReadOnly,
        input_schema: ObjectSchema {
            max_serialized_bytes: 4 * 1024,
            properties: BTreeMap::from([
                (
                    "path".into(),
                    ParameterSpec::required_string(MAX_WORKSPACE_PATH_BYTES),
                ),
                (
                    "query".into(),
                    ParameterSpec::required_string(MAX_WORKSPACE_SEARCH_QUERY_BYTES),
                ),
            ]),
        },
    }
}

pub fn workspace_replace_text_descriptor() -> ToolDescriptor {
    ToolDescriptor {
        name: WORKSPACE_REPLACE_TEXT_TOOL_NAME.into(),
        version: WORKSPACE_REPLACE_TEXT_TOOL_VERSION.into(),
        description: format!(
            "Replace one unique exact text occurrence in an existing UTF-8 workspace file (maximum {MAX_WORKSPACE_EDIT_FILE_BYTES} file bytes)"
        ),
        effect: ToolEffect::LocalWrite,
        sandbox_profile: SandboxProfile::WorkspaceWrite,
        input_schema: ObjectSchema {
            max_serialized_bytes: 12 * 1024,
            properties: BTreeMap::from([
                (
                    "new_text".into(),
                    ParameterSpec {
                        parameter_type: ParameterType::String,
                        required: true,
                        min_length: Some(0),
                        max_length: Some(MAX_WORKSPACE_EDIT_TEXT_BYTES),
                    },
                ),
                (
                    "old_text".into(),
                    ParameterSpec::required_string(MAX_WORKSPACE_EDIT_TEXT_BYTES),
                ),
                (
                    "path".into(),
                    ParameterSpec::required_string(MAX_WORKSPACE_PATH_BYTES),
                ),
            ]),
        },
    }
}

pub fn workspace_create_file_descriptor() -> ToolDescriptor {
    ToolDescriptor {
        name: WORKSPACE_CREATE_FILE_TOOL_NAME.into(),
        version: WORKSPACE_CREATE_FILE_TOOL_VERSION.into(),
        description: format!(
            "Create one new UTF-8 file below an existing workspace directory without overwriting any path (maximum {MAX_WORKSPACE_CREATE_CONTENT_BYTES} content bytes)"
        ),
        effect: ToolEffect::LocalWrite,
        sandbox_profile: SandboxProfile::WorkspaceWrite,
        input_schema: ObjectSchema {
            max_serialized_bytes: 16 * 1024,
            properties: BTreeMap::from([
                (
                    "content".into(),
                    ParameterSpec {
                        parameter_type: ParameterType::String,
                        required: true,
                        min_length: Some(0),
                        max_length: Some(MAX_WORKSPACE_CREATE_CONTENT_BYTES),
                    },
                ),
                (
                    "path".into(),
                    ParameterSpec::required_string(MAX_WORKSPACE_PATH_BYTES),
                ),
            ]),
        },
    }
}

struct WorkspaceRoots {
    confined: Dir,
    inspection: Dir,
    mutation_state: Mutex<WorkspaceMutationState>,
}

#[derive(Default)]
struct WorkspaceMutationState {
    receipts: BTreeMap<String, WorkspaceMutationReceipt>,
    receipt_order: VecDeque<String>,
}

#[derive(Clone)]
struct WorkspaceMutationReceipt {
    tool: String,
    arguments_digest: String,
    output: ToolOutput,
}

#[derive(Clone)]
struct WorkspaceReadFileExecutor {
    canonical_root: PathBuf,
    roots: Arc<WorkspaceRoots>,
}

impl WorkspaceReadFileExecutor {
    fn new(root: &Path) -> Result<Self, ConnectorConfigError> {
        let canonical_root = fs::canonicalize(root)
            .map_err(|error| ConnectorConfigError::WorkspaceRootIo(error.to_string()))?;
        let metadata = fs::metadata(&canonical_root)
            .map_err(|error| ConnectorConfigError::WorkspaceRootIo(error.to_string()))?;
        if !metadata.is_dir() {
            return Err(ConnectorConfigError::InvalidWorkspaceRoot(
                canonical_root.display().to_string(),
            ));
        }
        let confined = Dir::open_ambient_dir(&canonical_root, ambient_authority())
            .map_err(|error| ConnectorConfigError::WorkspaceRootIo(error.to_string()))?;
        let inspection = Dir::open_ambient_dir(&canonical_root, ambient_authority())
            .map_err(|error| ConnectorConfigError::WorkspaceRootIo(error.to_string()))?;
        Ok(Self {
            canonical_root,
            roots: Arc::new(WorkspaceRoots {
                confined,
                inspection,
                mutation_state: Mutex::new(WorkspaceMutationState::default()),
            }),
        })
    }
}

impl ToolExecutor for WorkspaceReadFileExecutor {
    fn execute(&self, request: ExecutionRequest) -> ExecutionFuture<'_> {
        let roots = Arc::clone(&self.roots);
        Box::pin(async move {
            if request.environment != LOCAL_DEV_ENVIRONMENT {
                return Err(workspace_failure(
                    "environment_denied",
                    "Workspace reads are restricted to local-development",
                    false,
                ));
            }
            let arguments: WorkspaceReadArguments =
                serde_json::from_value(request.call.arguments.clone()).map_err(|_| {
                    workspace_failure(
                        "invalid_arguments",
                        "Workspace read arguments are invalid",
                        false,
                    )
                })?;
            let path = validate_workspace_path(&arguments.path)?;
            tokio::task::spawn_blocking(move || {
                read_workspace_file(&roots, &path, &arguments.path, &request.call.call_id)
            })
            .await
            .map_err(|_| {
                workspace_failure(
                    "workspace_reader_join_failed",
                    "The workspace reader stopped unexpectedly",
                    false,
                )
            })?
        })
    }
}

#[derive(Clone)]
struct WorkspaceListDirectoryExecutor {
    roots: Arc<WorkspaceRoots>,
}

impl ToolExecutor for WorkspaceListDirectoryExecutor {
    fn execute(&self, request: ExecutionRequest) -> ExecutionFuture<'_> {
        let roots = Arc::clone(&self.roots);
        Box::pin(async move {
            if request.environment != LOCAL_DEV_ENVIRONMENT {
                return Err(workspace_failure(
                    "environment_denied",
                    "Workspace listing is restricted to local-development",
                    false,
                ));
            }
            let arguments: WorkspaceReadArguments =
                serde_json::from_value(request.call.arguments.clone()).map_err(|_| {
                    workspace_failure(
                        "invalid_arguments",
                        "Workspace directory arguments are invalid",
                        false,
                    )
                })?;
            let path = validate_workspace_directory_path(&arguments.path)?;
            tokio::task::spawn_blocking(move || {
                list_workspace_directory(&roots, &path, &arguments.path, &request.call.call_id)
            })
            .await
            .map_err(|_| {
                workspace_failure(
                    "workspace_lister_join_failed",
                    "The workspace directory lister stopped unexpectedly",
                    false,
                )
            })?
        })
    }
}

#[derive(Clone)]
struct WorkspaceSearchTextExecutor {
    roots: Arc<WorkspaceRoots>,
}

impl ToolExecutor for WorkspaceSearchTextExecutor {
    fn execute(&self, request: ExecutionRequest) -> ExecutionFuture<'_> {
        let roots = Arc::clone(&self.roots);
        Box::pin(async move {
            if request.environment != LOCAL_DEV_ENVIRONMENT {
                return Err(workspace_failure(
                    "environment_denied",
                    "Workspace search is restricted to local-development",
                    false,
                ));
            }
            let arguments: WorkspaceSearchTextArguments =
                serde_json::from_value(request.call.arguments.clone()).map_err(|_| {
                    workspace_failure(
                        "invalid_arguments",
                        "Workspace search arguments are invalid",
                        false,
                    )
                })?;
            let path = validate_workspace_directory_path(&arguments.path)?;
            validate_workspace_search_query(&arguments.query)?;
            tokio::task::spawn_blocking(move || {
                search_workspace_text(
                    &roots,
                    &path,
                    &arguments.path,
                    &arguments.query,
                    &request.call.call_id,
                )
            })
            .await
            .map_err(|_| {
                workspace_failure(
                    "workspace_search_join_failed",
                    "The workspace search stopped unexpectedly",
                    false,
                )
            })?
        })
    }
}

#[derive(Clone)]
struct WorkspaceReplaceTextExecutor {
    roots: Arc<WorkspaceRoots>,
}

impl ToolExecutor for WorkspaceReplaceTextExecutor {
    fn execute(&self, request: ExecutionRequest) -> ExecutionFuture<'_> {
        let roots = Arc::clone(&self.roots);
        Box::pin(async move {
            if request.environment != LOCAL_DEV_ENVIRONMENT {
                return Err(workspace_failure(
                    "environment_denied",
                    "Workspace edits are restricted to local-development",
                    false,
                ));
            }
            let arguments: WorkspaceReplaceTextArguments =
                serde_json::from_value(request.call.arguments.clone()).map_err(|_| {
                    workspace_failure(
                        "invalid_arguments",
                        "Workspace edit arguments are invalid",
                        false,
                    )
                })?;
            let path = validate_workspace_path(&arguments.path)?;
            validate_workspace_edit_text(&arguments.old_text, false)?;
            validate_workspace_edit_text(&arguments.new_text, true)?;
            if arguments.old_text == arguments.new_text {
                return Err(workspace_failure(
                    "workspace_edit_no_change",
                    "Workspace edit old_text and new_text must differ",
                    false,
                ));
            }
            tokio::task::spawn_blocking(move || {
                replace_workspace_text(&roots, &path, &arguments, &request.call)
            })
            .await
            .map_err(|_| {
                workspace_failure(
                    "workspace_editor_join_failed",
                    "The workspace editor stopped unexpectedly",
                    false,
                )
            })?
        })
    }
}

#[derive(Clone)]
struct WorkspaceCreateFileExecutor {
    roots: Arc<WorkspaceRoots>,
}

impl ToolExecutor for WorkspaceCreateFileExecutor {
    fn execute(&self, request: ExecutionRequest) -> ExecutionFuture<'_> {
        let roots = Arc::clone(&self.roots);
        Box::pin(async move {
            if request.environment != LOCAL_DEV_ENVIRONMENT {
                return Err(workspace_failure(
                    "environment_denied",
                    "Workspace file creation is restricted to local-development",
                    false,
                ));
            }
            let arguments: WorkspaceCreateFileArguments =
                serde_json::from_value(request.call.arguments.clone()).map_err(|_| {
                    workspace_failure(
                        "invalid_arguments",
                        "Workspace file creation arguments are invalid",
                        false,
                    )
                })?;
            let path = validate_workspace_path(&arguments.path)?;
            if arguments.content.len() > MAX_WORKSPACE_CREATE_CONTENT_BYTES {
                return Err(workspace_failure(
                    "workspace_create_content_too_large",
                    "Workspace file content exceeds the 12288-byte limit",
                    false,
                ));
            }
            tokio::task::spawn_blocking(move || {
                create_workspace_file(&roots, &path, &arguments, &request.call)
            })
            .await
            .map_err(|_| {
                workspace_failure(
                    "workspace_creator_join_failed",
                    "The workspace file creator stopped unexpectedly",
                    false,
                )
            })?
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceReadArguments {
    path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceSearchTextArguments {
    path: String,
    query: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceReplaceTextArguments {
    path: String,
    old_text: String,
    new_text: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceCreateFileArguments {
    path: String,
    content: String,
}

fn validate_workspace_path(path: &str) -> Result<PathBuf, ExecutorError> {
    if path.is_empty()
        || path.len() > MAX_WORKSPACE_PATH_BYTES
        || path.trim() != path
        || path.contains('\\')
        || path.chars().any(char::is_control)
    {
        return Err(invalid_workspace_path());
    }
    let mut parts = Vec::new();
    for component in Path::new(path).components() {
        match component {
            Component::Normal(part) => {
                let part = part.to_str().ok_or_else(invalid_workspace_path)?;
                if is_workspace_internal_entry(part) {
                    return Err(invalid_workspace_path());
                }
                parts.push(part);
            }
            _ => return Err(invalid_workspace_path()),
        }
    }
    if parts.is_empty() || parts.join("/") != path {
        return Err(invalid_workspace_path());
    }
    Ok(parts.iter().collect())
}

fn is_workspace_internal_entry(name: &str) -> bool {
    name.starts_with(".zeus-tool-")
}

fn validate_workspace_directory_path(path: &str) -> Result<PathBuf, ExecutorError> {
    if path == "." {
        return Ok(PathBuf::from(path));
    }
    validate_workspace_path(path)
}

fn validate_workspace_search_query(query: &str) -> Result<(), ExecutorError> {
    if query.is_empty()
        || query.len() > MAX_WORKSPACE_SEARCH_QUERY_BYTES
        || query.chars().all(char::is_whitespace)
        || query.chars().any(char::is_control)
    {
        return Err(workspace_failure(
            "invalid_workspace_search_query",
            "Workspace search query must be non-blank single-line UTF-8 text within 256 bytes",
            false,
        ));
    }
    Ok(())
}

fn validate_workspace_edit_text(text: &str, allow_empty: bool) -> Result<(), ExecutorError> {
    if (!allow_empty && text.is_empty()) || text.len() > MAX_WORKSPACE_EDIT_TEXT_BYTES {
        return Err(workspace_failure(
            "invalid_workspace_edit_text",
            "Workspace edit text exceeds its UTF-8 byte limit or old_text is empty",
            false,
        ));
    }
    Ok(())
}

fn invalid_workspace_path() -> ExecutorError {
    workspace_failure(
        "invalid_workspace_path",
        "Workspace path must be a canonical relative UTF-8 path without traversal",
        false,
    )
}

fn read_workspace_file(
    roots: &WorkspaceRoots,
    path: &Path,
    display_path: &str,
    call_id: &str,
) -> Result<ToolOutput, ExecutorError> {
    reject_workspace_symlinks(&roots.inspection, path)?;
    let mut file = roots.confined.open(path).map_err(workspace_read_error)?;
    let metadata = file.metadata().map_err(workspace_read_error)?;
    if !metadata.is_file() {
        return Err(workspace_failure(
            "workspace_not_regular_file",
            "The requested workspace path is not a regular file",
            false,
        ));
    }
    if metadata.len() > MAX_WORKSPACE_FILE_BYTES as u64 {
        return Err(workspace_file_too_large());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take((MAX_WORKSPACE_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(workspace_read_error)?;
    if bytes.len() > MAX_WORKSPACE_FILE_BYTES {
        return Err(workspace_file_too_large());
    }
    let content = String::from_utf8(bytes).map_err(|_| {
        workspace_failure(
            "workspace_file_not_utf8",
            "The requested workspace file is not valid UTF-8 text",
            false,
        )
    })?;
    Ok(ToolOutput {
        value: json!({
            "path": display_path,
            "content": content,
            "bytes": content.len(),
        }),
        replayed: false,
        provider_request_id: Some(call_id.to_owned()),
    })
}

fn list_workspace_directory(
    roots: &WorkspaceRoots,
    path: &Path,
    display_path: &str,
    call_id: &str,
) -> Result<ToolOutput, ExecutorError> {
    if path != Path::new(".") {
        reject_workspace_symlinks(&roots.inspection, path)?;
    }
    let directory = roots
        .confined
        .read_dir(path)
        .map_err(workspace_directory_error)?;
    let mut entries = Vec::new();
    for entry in directory {
        let entry = entry.map_err(workspace_directory_error)?;
        let name = entry.file_name().into_string().map_err(|_| {
            workspace_failure(
                "workspace_entry_not_utf8",
                "The requested workspace directory contains a non-UTF-8 entry",
                false,
            )
        })?;
        if name.is_empty()
            || name.len() > MAX_WORKSPACE_PATH_BYTES
            || name.chars().any(char::is_control)
        {
            return Err(workspace_failure(
                "workspace_entry_invalid",
                "The requested workspace directory contains an invalid entry name",
                false,
            ));
        }
        if is_workspace_internal_entry(&name) {
            continue;
        }
        if entries.len() == MAX_WORKSPACE_DIRECTORY_ENTRIES {
            return Err(workspace_failure(
                "workspace_directory_too_large",
                "The requested workspace directory exceeds the 64-entry limit",
                false,
            ));
        }
        let file_type = entry.file_type().map_err(workspace_directory_error)?;
        let kind = if file_type.is_file() {
            "file"
        } else if file_type.is_dir() {
            "directory"
        } else if file_type.is_symlink() {
            "symlink"
        } else {
            "other"
        };
        entries.push(json!({ "name": name, "kind": kind }));
    }
    entries.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
    Ok(ToolOutput {
        value: json!({
            "path": display_path,
            "entries": entries,
        }),
        replayed: false,
        provider_request_id: Some(call_id.to_owned()),
    })
}

#[derive(Debug)]
struct WorkspaceSearchEntry {
    name: String,
    kind: WorkspaceSearchEntryKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WorkspaceSearchEntryKind {
    File,
    Directory,
    Symlink,
    Other,
}

fn search_workspace_text(
    roots: &WorkspaceRoots,
    path: &Path,
    display_path: &str,
    query: &str,
    call_id: &str,
) -> Result<ToolOutput, ExecutorError> {
    if path != Path::new(".") {
        reject_workspace_symlinks(&roots.inspection, path)?;
    }

    let mut pending = VecDeque::from([(path.to_path_buf(), 0_usize)]);
    let mut matches = Vec::new();
    let mut scanned_directories = 0_usize;
    let mut scanned_files = 0_usize;
    let mut scanned_bytes = 0_usize;
    let mut skipped_entries = 0_usize;
    let mut truncated = false;

    'search: while let Some((directory_path, depth)) = pending.pop_front() {
        if scanned_directories == MAX_WORKSPACE_SEARCH_DIRECTORIES {
            truncated = true;
            break;
        }
        if directory_path != Path::new(".") {
            reject_workspace_symlinks(&roots.inspection, &directory_path)?;
        }
        scanned_directories += 1;
        let directory = roots
            .confined
            .read_dir(&directory_path)
            .map_err(workspace_directory_error)?;
        let mut entries = Vec::new();
        for entry in directory {
            let entry = entry.map_err(workspace_directory_error)?;
            let name = entry.file_name().into_string().map_err(|_| {
                workspace_failure(
                    "workspace_entry_not_utf8",
                    "The searched workspace contains a non-UTF-8 entry",
                    false,
                )
            })?;
            if name.is_empty()
                || name.len() > MAX_WORKSPACE_PATH_BYTES
                || name.chars().any(char::is_control)
            {
                return Err(workspace_failure(
                    "workspace_entry_invalid",
                    "The searched workspace contains an invalid entry name",
                    false,
                ));
            }
            if is_workspace_internal_entry(&name) {
                continue;
            }
            if entries.len() == MAX_WORKSPACE_DIRECTORY_ENTRIES {
                return Err(workspace_failure(
                    "workspace_search_directory_too_large",
                    "A searched workspace directory exceeds the 64-entry limit",
                    false,
                ));
            }
            let file_type = entry.file_type().map_err(workspace_directory_error)?;
            let kind = if file_type.is_file() {
                WorkspaceSearchEntryKind::File
            } else if file_type.is_dir() {
                WorkspaceSearchEntryKind::Directory
            } else if file_type.is_symlink() {
                WorkspaceSearchEntryKind::Symlink
            } else {
                WorkspaceSearchEntryKind::Other
            };
            entries.push(WorkspaceSearchEntry { name, kind });
        }
        entries.sort_by(|left, right| left.name.cmp(&right.name));

        for entry in entries {
            let entry_path = join_workspace_path(&directory_path, &entry.name);
            let entry_display_path = workspace_display_path(&entry_path)?;
            if entry_display_path.len() > MAX_WORKSPACE_PATH_BYTES {
                skipped_entries += 1;
                truncated = true;
                continue;
            }
            match entry.kind {
                WorkspaceSearchEntryKind::Directory => {
                    if WORKSPACE_SEARCH_IGNORED_DIRECTORIES.contains(&entry.name.as_str()) {
                        skipped_entries += 1;
                    } else if depth == MAX_WORKSPACE_SEARCH_DEPTH {
                        skipped_entries += 1;
                        truncated = true;
                    } else {
                        pending.push_back((entry_path, depth + 1));
                    }
                }
                WorkspaceSearchEntryKind::File => {
                    if scanned_files == MAX_WORKSPACE_SEARCH_FILES {
                        truncated = true;
                        break 'search;
                    }
                    scanned_files += 1;
                    reject_workspace_symlinks(&roots.inspection, &entry_path)?;
                    let mut file = roots
                        .confined
                        .open(&entry_path)
                        .map_err(workspace_read_error)?;
                    let metadata = file.metadata().map_err(workspace_read_error)?;
                    if !metadata.is_file()
                        || metadata.len() > MAX_WORKSPACE_SEARCH_FILE_BYTES as u64
                    {
                        skipped_entries += 1;
                        continue;
                    }
                    let declared_bytes = usize::try_from(metadata.len()).map_err(|_| {
                        workspace_failure(
                            "workspace_search_size_overflow",
                            "A searched workspace file has an unsupported size",
                            false,
                        )
                    })?;
                    if scanned_bytes
                        .checked_add(declared_bytes)
                        .is_none_or(|total| total > MAX_WORKSPACE_SEARCH_TOTAL_BYTES)
                    {
                        truncated = true;
                        break 'search;
                    }
                    let mut bytes = Vec::with_capacity(declared_bytes);
                    Read::by_ref(&mut file)
                        .take((MAX_WORKSPACE_SEARCH_FILE_BYTES + 1) as u64)
                        .read_to_end(&mut bytes)
                        .map_err(workspace_read_error)?;
                    if bytes.len() > MAX_WORKSPACE_SEARCH_FILE_BYTES {
                        skipped_entries += 1;
                        continue;
                    }
                    if scanned_bytes
                        .checked_add(bytes.len())
                        .is_none_or(|total| total > MAX_WORKSPACE_SEARCH_TOTAL_BYTES)
                    {
                        truncated = true;
                        break 'search;
                    }
                    scanned_bytes += bytes.len();
                    let Ok(content) = String::from_utf8(bytes) else {
                        skipped_entries += 1;
                        continue;
                    };
                    for (line_index, line) in content.lines().enumerate() {
                        if !line.contains(query) {
                            continue;
                        }
                        if matches.len() == MAX_WORKSPACE_SEARCH_MATCHES {
                            truncated = true;
                            break 'search;
                        }
                        matches.push(json!({
                            "path": entry_display_path,
                            "line": line_index + 1,
                            "text": workspace_search_preview(line, query),
                        }));
                    }
                }
                WorkspaceSearchEntryKind::Symlink | WorkspaceSearchEntryKind::Other => {
                    skipped_entries += 1;
                }
            }
        }
    }

    Ok(ToolOutput {
        value: json!({
            "path": display_path,
            "query": query,
            "matches": matches,
            "truncated": truncated,
            "scanned_directories": scanned_directories,
            "scanned_files": scanned_files,
            "scanned_bytes": scanned_bytes,
            "skipped_entries": skipped_entries,
        }),
        replayed: false,
        provider_request_id: Some(call_id.to_owned()),
    })
}

fn join_workspace_path(directory: &Path, name: &str) -> PathBuf {
    if directory == Path::new(".") {
        PathBuf::from(name)
    } else {
        directory.join(name)
    }
}

fn workspace_display_path(path: &Path) -> Result<String, ExecutorError> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(component) => components.push(
                component
                    .to_str()
                    .ok_or_else(invalid_workspace_path)?
                    .to_owned(),
            ),
            _ => return Err(invalid_workspace_path()),
        }
    }
    if components.is_empty() {
        Ok(".".into())
    } else {
        Ok(components.join("/"))
    }
}

fn workspace_search_preview(line: &str, query: &str) -> String {
    fn sanitize(text: &str) -> String {
        text.chars()
            .map(|character| {
                if character.is_control() {
                    ' '
                } else {
                    character
                }
            })
            .collect()
    }

    if line.len() <= MAX_WORKSPACE_SEARCH_PREVIEW_BYTES {
        return sanitize(line);
    }
    if query.len() > MAX_WORKSPACE_SEARCH_PREVIEW_BYTES - 6 {
        return sanitize(query);
    }

    let match_start = line.find(query).unwrap_or(0);
    let match_end = match_start + query.len();
    let context_bytes = MAX_WORKSPACE_SEARCH_PREVIEW_BYTES - query.len() - 6;
    let mut start = match_start.saturating_sub(context_bytes / 2);
    while !line.is_char_boundary(start) {
        start += 1;
    }
    let mut end = match_end
        .saturating_add(context_bytes - (match_start - start))
        .min(line.len());
    while !line.is_char_boundary(end) {
        end -= 1;
    }

    let mut preview = String::with_capacity(MAX_WORKSPACE_SEARCH_PREVIEW_BYTES);
    if start > 0 {
        preview.push_str("...");
    }
    preview.push_str(&sanitize(&line[start..end]));
    if end < line.len() {
        preview.push_str("...");
    }
    preview
}

fn create_workspace_file(
    roots: &WorkspaceRoots,
    path: &Path,
    arguments: &WorkspaceCreateFileArguments,
    call: &ToolCall,
) -> Result<ToolOutput, ExecutorError> {
    let mut mutation_state = roots.mutation_state.lock().map_err(|_| {
        workspace_failure(
            "workspace_mutation_state_poisoned",
            "The workspace mutation state is unavailable",
            false,
        )
    })?;
    if let Some(receipt) = mutation_state.receipts.get(&call.call_id) {
        if receipt.tool != call.tool || receipt.arguments_digest != call.arguments_digest {
            return Err(workspace_failure(
                "workspace_create_idempotency_conflict",
                "The workspace create call id is already bound to a different tool or arguments",
                false,
            ));
        }
        let mut output = receipt.output.clone();
        output.replayed = true;
        return Ok(output);
    }

    let parent_path = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if parent_path != Path::new(".") {
        reject_workspace_create_parent_symlinks(&roots.inspection, parent_path)?;
    }
    let file_name = path.file_name().ok_or_else(invalid_workspace_path)?;
    let parent = roots
        .confined
        .open_dir(parent_path)
        .map_err(workspace_create_parent_error)?;
    match parent.symlink_metadata(file_name) {
        Ok(_) => {
            return Err(workspace_failure(
                "workspace_create_target_exists",
                "Workspace file creation never overwrites an existing path",
                false,
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(workspace_create_io(error)),
    }

    let temp_sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp_name = format!(
        ".zeus-tool-create-{}-{}-{temp_sequence}.tmp",
        call.call_id,
        std::process::id()
    );
    let publish_result = (|| -> Result<(), ExecutorError> {
        let mut options = CapOpenOptions::new();
        options.write(true).create_new(true);
        let mut temp = parent
            .open_with(&temp_name, &options)
            .map_err(workspace_create_io)?;
        temp.write_all(arguments.content.as_bytes())
            .map_err(workspace_create_io)?;
        temp.sync_all().map_err(workspace_create_io)?;
        parent
            .hard_link(&temp_name, &parent, file_name)
            .map_err(workspace_create_publish_error)?;
        let _ = parent.remove_file(&temp_name);
        sync_cap_directory(&parent).map_err(workspace_create_io)
    })();
    if let Err(error) = publish_result {
        let _ = parent.remove_file(&temp_name);
        return Err(error);
    }

    let output = ToolOutput {
        value: json!({
            "path": arguments.path,
            "bytes": arguments.content.len(),
            "created": true,
        }),
        replayed: false,
        provider_request_id: Some(call.call_id.clone()),
    };
    remember_workspace_mutation_receipt(
        &mut mutation_state,
        call.call_id.clone(),
        WorkspaceMutationReceipt {
            tool: call.tool.clone(),
            arguments_digest: call.arguments_digest.clone(),
            output: output.clone(),
        },
    );
    Ok(output)
}

fn workspace_create_parent_error(error: io::Error) -> ExecutorError {
    match error.kind() {
        io::ErrorKind::NotFound => workspace_failure(
            "workspace_create_parent_not_found",
            "Workspace file creation requires an existing parent directory",
            false,
        ),
        io::ErrorKind::PermissionDenied => workspace_failure(
            "workspace_create_parent_denied",
            "The workspace file parent directory is not writable",
            false,
        ),
        io::ErrorKind::NotADirectory => workspace_failure(
            "workspace_create_parent_not_directory",
            "Workspace file creation requires every parent path to be a directory",
            false,
        ),
        _ => workspace_failure(
            "workspace_create_parent_failed",
            "The workspace file parent directory could not be opened",
            true,
        ),
    }
}

fn workspace_create_io(error: io::Error) -> ExecutorError {
    match error.kind() {
        io::ErrorKind::PermissionDenied => workspace_failure(
            "workspace_create_denied",
            "The workspace file could not be created in its parent directory",
            false,
        ),
        io::ErrorKind::AlreadyExists => workspace_failure(
            "workspace_create_temp_conflict",
            "The workspace create temporary file already exists",
            true,
        ),
        _ => workspace_failure(
            "workspace_create_failed",
            "The workspace file could not be prepared atomically",
            true,
        ),
    }
}

fn workspace_create_publish_error(error: io::Error) -> ExecutorError {
    if error.kind() == io::ErrorKind::AlreadyExists {
        workspace_failure(
            "workspace_create_target_exists",
            "Workspace file creation never overwrites an existing path",
            false,
        )
    } else {
        workspace_create_io(error)
    }
}

fn replace_workspace_text(
    roots: &WorkspaceRoots,
    path: &Path,
    arguments: &WorkspaceReplaceTextArguments,
    call: &ToolCall,
) -> Result<ToolOutput, ExecutorError> {
    let mut mutation_state = roots.mutation_state.lock().map_err(|_| {
        workspace_failure(
            "workspace_mutation_state_poisoned",
            "The workspace mutation state is unavailable",
            false,
        )
    })?;
    if let Some(receipt) = mutation_state.receipts.get(&call.call_id) {
        if receipt.tool != call.tool || receipt.arguments_digest != call.arguments_digest {
            return Err(workspace_failure(
                "workspace_edit_idempotency_conflict",
                "The workspace edit call id is already bound to a different tool or arguments",
                false,
            ));
        }
        let mut output = receipt.output.clone();
        output.replayed = true;
        return Ok(output);
    }

    reject_workspace_symlinks(&roots.inspection, path)?;
    let parent_path = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(invalid_workspace_path)?;
    let parent = roots
        .confined
        .open_dir(parent_path)
        .map_err(workspace_directory_error)?;
    let (original_bytes, permissions) = read_workspace_edit_file(&parent, file_name)?;
    let original = String::from_utf8(original_bytes.clone()).map_err(|_| {
        workspace_failure(
            "workspace_edit_file_not_utf8",
            "The workspace edit target is not valid UTF-8 text",
            false,
        )
    })?;
    let mut occurrences = original.match_indices(&arguments.old_text);
    let Some((match_offset, _)) = occurrences.next() else {
        return Err(workspace_failure(
            "workspace_edit_text_not_found",
            "Workspace edit old_text was not found",
            false,
        ));
    };
    if occurrences.next().is_some() {
        return Err(workspace_failure(
            "workspace_edit_text_not_unique",
            "Workspace edit old_text must occur exactly once",
            false,
        ));
    }
    let updated_len = original
        .len()
        .checked_sub(arguments.old_text.len())
        .and_then(|length| length.checked_add(arguments.new_text.len()))
        .ok_or_else(workspace_edit_file_too_large)?;
    if updated_len > MAX_WORKSPACE_EDIT_FILE_BYTES {
        return Err(workspace_edit_file_too_large());
    }
    let mut updated = String::with_capacity(updated_len);
    updated.push_str(&original[..match_offset]);
    updated.push_str(&arguments.new_text);
    updated.push_str(&original[match_offset + arguments.old_text.len()..]);

    let temp_sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp_name = format!(
        ".zeus-tool-replace-{}-{}-{temp_sequence}.tmp",
        call.call_id,
        std::process::id()
    );
    let write_result = (|| -> Result<(), ExecutorError> {
        let mut options = CapOpenOptions::new();
        options.write(true).create_new(true);
        let mut temp = parent
            .open_with(&temp_name, &options)
            .map_err(workspace_edit_io)?;
        temp.write_all(updated.as_bytes())
            .map_err(workspace_edit_io)?;
        temp.set_permissions(permissions)
            .map_err(workspace_edit_io)?;
        temp.sync_all().map_err(workspace_edit_io)?;

        let (current_bytes, _) = read_workspace_edit_file(&parent, file_name)?;
        if current_bytes != original_bytes {
            return Err(workspace_failure(
                "workspace_edit_conflict",
                "The workspace edit target changed before atomic replacement",
                false,
            ));
        }
        parent
            .rename(&temp_name, &parent, file_name)
            .map_err(workspace_edit_io)?;
        sync_cap_directory(&parent).map_err(workspace_edit_io)
    })();
    if let Err(error) = write_result {
        let _ = parent.remove_file(&temp_name);
        return Err(error);
    }

    let output = ToolOutput {
        value: json!({
            "path": arguments.path,
            "replacements": 1,
            "bytes_before": original.len(),
            "bytes_after": updated.len(),
        }),
        replayed: false,
        provider_request_id: Some(call.call_id.clone()),
    };
    remember_workspace_mutation_receipt(
        &mut mutation_state,
        call.call_id.clone(),
        WorkspaceMutationReceipt {
            tool: call.tool.clone(),
            arguments_digest: call.arguments_digest.clone(),
            output: output.clone(),
        },
    );
    Ok(output)
}

fn remember_workspace_mutation_receipt(
    mutation_state: &mut WorkspaceMutationState,
    call_id: String,
    receipt: WorkspaceMutationReceipt,
) {
    if mutation_state.receipts.len() == MAX_WORKSPACE_MUTATION_RECEIPTS
        && let Some(expired_call_id) = mutation_state.receipt_order.pop_front()
    {
        mutation_state.receipts.remove(&expired_call_id);
    }
    mutation_state.receipt_order.push_back(call_id.clone());
    mutation_state.receipts.insert(call_id, receipt);
}

fn read_workspace_edit_file(
    parent: &Dir,
    file_name: &std::ffi::OsStr,
) -> Result<(Vec<u8>, cap_std::fs::Permissions), ExecutorError> {
    let target_metadata = parent
        .symlink_metadata(file_name)
        .map_err(workspace_read_error)?;
    if target_metadata.file_type().is_symlink() {
        return Err(workspace_failure(
            "workspace_symlink_denied",
            "Workspace edits do not follow symbolic links",
            false,
        ));
    }
    let mut file = parent.open(file_name).map_err(workspace_read_error)?;
    let metadata = file.metadata().map_err(workspace_read_error)?;
    if !metadata.is_file() {
        return Err(workspace_failure(
            "workspace_edit_not_regular_file",
            "The workspace edit target is not a regular file",
            false,
        ));
    }
    if metadata.len() > MAX_WORKSPACE_EDIT_FILE_BYTES as u64 {
        return Err(workspace_edit_file_too_large());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take((MAX_WORKSPACE_EDIT_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(workspace_read_error)?;
    if bytes.len() > MAX_WORKSPACE_EDIT_FILE_BYTES {
        return Err(workspace_edit_file_too_large());
    }
    Ok((bytes, metadata.permissions()))
}

fn workspace_edit_file_too_large() -> ExecutorError {
    workspace_failure(
        "workspace_edit_file_too_large",
        "The workspace edit target or result exceeds the 65536-byte limit",
        false,
    )
}

fn workspace_edit_io(error: io::Error) -> ExecutorError {
    match error.kind() {
        io::ErrorKind::NotFound => workspace_failure(
            "workspace_edit_target_not_found",
            "The workspace edit target was not found",
            false,
        ),
        io::ErrorKind::PermissionDenied => workspace_failure(
            "workspace_edit_denied",
            "The workspace edit target is not writable",
            false,
        ),
        io::ErrorKind::AlreadyExists => workspace_failure(
            "workspace_edit_temp_conflict",
            "The workspace edit temporary file already exists",
            true,
        ),
        _ => workspace_failure(
            "workspace_edit_failed",
            "The workspace edit could not be committed atomically",
            true,
        ),
    }
}

#[cfg(unix)]
fn sync_cap_directory(directory: &Dir) -> io::Result<()> {
    Dir::reopen_dir(directory).and_then(|directory| directory.into_std_file().sync_all())
}

#[cfg(not(unix))]
fn sync_cap_directory(_directory: &Dir) -> io::Result<()> {
    Ok(())
}

fn reject_workspace_symlinks(root: &Dir, path: &Path) -> Result<(), ExecutorError> {
    let mut prefix = PathBuf::new();
    for component in path.components() {
        let Component::Normal(component) = component else {
            return Err(invalid_workspace_path());
        };
        prefix.push(component);
        let metadata = root
            .symlink_metadata(&prefix)
            .map_err(workspace_read_error)?;
        if metadata.file_type().is_symlink() {
            return Err(workspace_failure(
                "workspace_symlink_denied",
                "Workspace reads do not follow symbolic links",
                false,
            ));
        }
    }
    Ok(())
}

fn reject_workspace_create_parent_symlinks(root: &Dir, path: &Path) -> Result<(), ExecutorError> {
    let mut prefix = PathBuf::new();
    for component in path.components() {
        let Component::Normal(component) = component else {
            return Err(invalid_workspace_path());
        };
        prefix.push(component);
        let metadata = root
            .symlink_metadata(&prefix)
            .map_err(workspace_create_parent_error)?;
        if metadata.file_type().is_symlink() {
            return Err(workspace_failure(
                "workspace_symlink_denied",
                "Workspace tools do not follow symbolic links",
                false,
            ));
        }
        if !metadata.is_dir() {
            return Err(workspace_failure(
                "workspace_create_parent_not_directory",
                "Workspace file creation requires every parent path to be a directory",
                false,
            ));
        }
    }
    Ok(())
}

fn workspace_file_too_large() -> ExecutorError {
    workspace_failure(
        "workspace_file_too_large",
        "The requested workspace file exceeds the 8192-byte limit",
        false,
    )
}

fn workspace_read_error(error: io::Error) -> ExecutorError {
    match error.kind() {
        io::ErrorKind::NotFound => workspace_failure(
            "workspace_file_not_found",
            "The requested workspace file was not found",
            false,
        ),
        io::ErrorKind::PermissionDenied => workspace_failure(
            "workspace_file_denied",
            "The requested workspace file is not readable",
            false,
        ),
        _ => workspace_failure(
            "workspace_read_failed",
            "The workspace file could not be read",
            true,
        ),
    }
}

fn workspace_directory_error(error: io::Error) -> ExecutorError {
    match error.kind() {
        io::ErrorKind::NotFound => workspace_failure(
            "workspace_directory_not_found",
            "The requested workspace directory was not found",
            false,
        ),
        io::ErrorKind::PermissionDenied => workspace_failure(
            "workspace_directory_denied",
            "The requested workspace directory is not readable",
            false,
        ),
        _ => workspace_failure(
            "workspace_directory_failed",
            "The workspace directory could not be listed",
            true,
        ),
    }
}

fn workspace_failure(code: &'static str, message: &'static str, retryable: bool) -> ExecutorError {
    ExecutorError::Failed {
        code: code.into(),
        message: message.into(),
        retryable,
    }
}

#[derive(Debug)]
struct DevMarkerWriteExecutor {
    root: PathBuf,
}

impl DevMarkerWriteExecutor {
    fn new(root: &Path) -> Result<Self, ConnectorConfigError> {
        fs::create_dir_all(root)
            .map_err(|error| ConnectorConfigError::RootIo(error.to_string()))?;
        let root = fs::canonicalize(root)
            .map_err(|error| ConnectorConfigError::RootIo(error.to_string()))?;
        let metadata =
            fs::metadata(&root).map_err(|error| ConnectorConfigError::RootIo(error.to_string()))?;
        if !metadata.is_dir() {
            return Err(ConnectorConfigError::InvalidRoot(
                root.display().to_string(),
            ));
        }
        Ok(Self { root })
    }
}

impl ToolExecutor for DevMarkerWriteExecutor {
    fn execute(&self, request: ExecutionRequest) -> ExecutionFuture<'_> {
        let root = self.root.clone();
        Box::pin(async move {
            if request.environment != LOCAL_DEV_ENVIRONMENT {
                return Err(ExecutorError::Failed {
                    code: "environment_denied".into(),
                    message: "development marker writes are restricted to local-development".into(),
                    retryable: false,
                });
            }
            let arguments: MarkerArguments = serde_json::from_value(request.call.arguments.clone())
                .map_err(|error| ExecutorError::Failed {
                    code: "invalid_arguments".into(),
                    message: error.to_string(),
                    retryable: false,
                })?;
            validate_marker(&arguments.marker)?;

            tokio::task::spawn_blocking(move || write_marker(&root, request, arguments))
                .await
                .map_err(|error| ExecutorError::Failed {
                    code: "executor_join_failure".into(),
                    message: error.to_string(),
                    retryable: false,
                })?
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MarkerArguments {
    marker: String,
}

#[derive(Serialize)]
struct MarkerDocument<'a> {
    call_id: &'a str,
    provider_idempotency_key: &'a str,
    marker: &'a str,
}

fn validate_marker(marker: &str) -> Result<(), ExecutorError> {
    if marker.is_empty()
        || marker.len() > MAX_MARKER_BYTES
        || marker.trim() != marker
        || !marker.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || byte == b' '
                || byte == b'.'
                || byte == b','
                || byte == b':'
                || byte == b'_'
                || byte == b'-'
        })
    {
        return Err(ExecutorError::Failed {
            code: "invalid_marker".into(),
            message: format!(
                "marker must contain 1..={MAX_MARKER_BYTES} ASCII letters, digits, spaces, or .,:_-"
            ),
            retryable: false,
        });
    }
    Ok(())
}

fn write_marker(
    root: &Path,
    request: ExecutionRequest,
    arguments: MarkerArguments,
) -> Result<ToolOutput, ExecutorError> {
    let file_name = format!("marker-{}.json", request.call.call_id);
    let target = root.join(&file_name);
    debug_assert_eq!(target.parent(), Some(root));

    let mut bytes = serde_json::to_vec(&MarkerDocument {
        call_id: &request.call.call_id,
        provider_idempotency_key: &request.provider_idempotency_key,
        marker: &arguments.marker,
    })
    .map_err(|error| marker_failure("marker_serialize_failed", error, false))?;
    bytes.push(b'\n');

    if target.try_exists().map_err(marker_io)? {
        return existing_result(&target, &file_name, &bytes, &request.call.call_id);
    }

    let temp_sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp_name = format!(
        ".marker-{}-{}-{temp_sequence}.tmp",
        request.call.call_id,
        std::process::id()
    );
    let temp = root.join(temp_name);
    let publish_result = (|| -> io::Result<()> {
        let mut file = StdOpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::hard_link(&temp, &target)?;
        Ok(())
    })();
    let _ = fs::remove_file(&temp);

    match publish_result {
        Ok(()) => {
            sync_directory(root)?;
            Ok(marker_output(
                file_name,
                bytes.len(),
                false,
                &request.call.call_id,
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            existing_result(&target, &file_name, &bytes, &request.call.call_id)
        }
        Err(error) => Err(marker_io(error)),
    }
}

fn existing_result(
    target: &Path,
    file_name: &str,
    expected: &[u8],
    call_id: &str,
) -> Result<ToolOutput, ExecutorError> {
    let metadata = fs::symlink_metadata(target).map_err(marker_io)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ExecutorError::Failed {
            code: "unsafe_existing_marker".into(),
            message: "existing marker target is not a regular file".into(),
            retryable: false,
        });
    }
    let existing = fs::read(target).map_err(marker_io)?;
    if existing != expected {
        return Err(ExecutorError::Failed {
            code: "idempotency_conflict".into(),
            message: "the call id already exists with different marker content".into(),
            retryable: false,
        });
    }
    Ok(marker_output(
        file_name.to_owned(),
        expected.len(),
        true,
        call_id,
    ))
}

fn marker_output(file_name: String, bytes: usize, replayed: bool, call_id: &str) -> ToolOutput {
    ToolOutput {
        value: json!({
            "file_name": file_name,
            "bytes": bytes,
        }),
        replayed,
        provider_request_id: Some(call_id.to_owned()),
    }
}

fn marker_io(error: io::Error) -> ExecutorError {
    marker_failure("marker_io_failed", error, true)
}

fn marker_failure(
    code: &'static str,
    error: impl std::fmt::Display,
    retryable: bool,
) -> ExecutorError {
    ExecutorError::Failed {
        code: code.into(),
        message: error.to_string(),
        retryable,
    }
}

#[cfg(unix)]
fn sync_directory(root: &Path) -> Result<(), ExecutorError> {
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(marker_io)
}

#[cfg(not(unix))]
fn sync_directory(_root: &Path) -> Result<(), ExecutorError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use protocol::{ToolCall, ToolExecutorStatus};
    use serde_json::json;
    use tools::{RegistryError, arguments_digest, stable_call_id};

    use super::*;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "zeus-connectors-test-{}-{nonce}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn call(marker: &str) -> ToolCall {
        let arguments = json!({"marker": marker});
        ToolCall {
            call_id: stable_call_id("run-1", 1, 1, DEV_MARKER_TOOL_NAME).unwrap(),
            tool: DEV_MARKER_TOOL_NAME.into(),
            tool_version: DEV_MARKER_TOOL_VERSION.into(),
            arguments_digest: arguments_digest(&arguments),
            arguments,
            effect: ToolEffect::LocalWrite,
            sandbox_profile: SandboxProfile::WorkspaceWrite,
            executor_status: ToolExecutorStatus::Available,
        }
    }

    fn workspace_call(path: &str) -> ToolCall {
        let arguments = json!({"path": path});
        ToolCall {
            call_id: stable_call_id("run-1", 1, 1, WORKSPACE_READ_FILE_TOOL_NAME).unwrap(),
            tool: WORKSPACE_READ_FILE_TOOL_NAME.into(),
            tool_version: WORKSPACE_READ_FILE_TOOL_VERSION.into(),
            arguments_digest: arguments_digest(&arguments),
            arguments,
            effect: ToolEffect::ReadOnly,
            sandbox_profile: SandboxProfile::ReadOnly,
            executor_status: ToolExecutorStatus::Available,
        }
    }

    fn workspace_list_call(path: &str) -> ToolCall {
        let arguments = json!({"path": path});
        ToolCall {
            call_id: stable_call_id("run-1", 1, 1, WORKSPACE_LIST_DIRECTORY_TOOL_NAME).unwrap(),
            tool: WORKSPACE_LIST_DIRECTORY_TOOL_NAME.into(),
            tool_version: WORKSPACE_LIST_DIRECTORY_TOOL_VERSION.into(),
            arguments_digest: arguments_digest(&arguments),
            arguments,
            effect: ToolEffect::ReadOnly,
            sandbox_profile: SandboxProfile::ReadOnly,
            executor_status: ToolExecutorStatus::Available,
        }
    }

    fn workspace_search_call(path: &str, query: &str) -> ToolCall {
        let arguments = json!({"path": path, "query": query});
        ToolCall {
            call_id: stable_call_id("run-1", 1, 1, WORKSPACE_SEARCH_TEXT_TOOL_NAME).unwrap(),
            tool: WORKSPACE_SEARCH_TEXT_TOOL_NAME.into(),
            tool_version: WORKSPACE_SEARCH_TEXT_TOOL_VERSION.into(),
            arguments_digest: arguments_digest(&arguments),
            arguments,
            effect: ToolEffect::ReadOnly,
            sandbox_profile: SandboxProfile::ReadOnly,
            executor_status: ToolExecutorStatus::Available,
        }
    }

    fn workspace_replace_call(step: u32, path: &str, old_text: &str, new_text: &str) -> ToolCall {
        let arguments = json!({
            "path": path,
            "old_text": old_text,
            "new_text": new_text,
        });
        ToolCall {
            call_id: stable_call_id("run-1", 1, step, WORKSPACE_REPLACE_TEXT_TOOL_NAME).unwrap(),
            tool: WORKSPACE_REPLACE_TEXT_TOOL_NAME.into(),
            tool_version: WORKSPACE_REPLACE_TEXT_TOOL_VERSION.into(),
            arguments_digest: arguments_digest(&arguments),
            arguments,
            effect: ToolEffect::LocalWrite,
            sandbox_profile: SandboxProfile::WorkspaceWrite,
            executor_status: ToolExecutorStatus::Available,
        }
    }

    fn workspace_create_call(step: u32, path: &str, content: &str) -> ToolCall {
        let arguments = json!({
            "path": path,
            "content": content,
        });
        ToolCall {
            call_id: stable_call_id("run-1", 1, step, WORKSPACE_CREATE_FILE_TOOL_NAME).unwrap(),
            tool: WORKSPACE_CREATE_FILE_TOOL_NAME.into(),
            tool_version: WORKSPACE_CREATE_FILE_TOOL_VERSION.into(),
            arguments_digest: arguments_digest(&arguments),
            arguments,
            effect: ToolEffect::LocalWrite,
            sandbox_profile: SandboxProfile::WorkspaceWrite,
            executor_status: ToolExecutorStatus::Available,
        }
    }

    #[test]
    fn workspace_search_preview_keeps_a_late_utf8_match_within_the_byte_limit() {
        let line = format!("{}目标needle{}", "前".repeat(120), "后".repeat(120));
        let preview = workspace_search_preview(&line, "目标needle");

        assert!(preview.len() <= MAX_WORKSPACE_SEARCH_PREVIEW_BYTES);
        assert!(preview.contains("目标needle"));
        assert!(preview.starts_with("..."));
        assert!(preview.ends_with("..."));
    }

    #[test]
    fn workspace_mutation_receipts_evict_in_insertion_order_at_the_hard_limit() {
        let mut state = WorkspaceMutationState::default();
        for index in 0..=MAX_WORKSPACE_MUTATION_RECEIPTS {
            remember_workspace_mutation_receipt(
                &mut state,
                format!("call-{index}"),
                WorkspaceMutationReceipt {
                    tool: WORKSPACE_REPLACE_TEXT_TOOL_NAME.into(),
                    arguments_digest: format!("digest-{index}"),
                    output: ToolOutput {
                        value: json!({"index": index}),
                        replayed: false,
                        provider_request_id: None,
                    },
                },
            );
        }

        assert_eq!(state.receipts.len(), MAX_WORKSPACE_MUTATION_RECEIPTS);
        assert_eq!(state.receipt_order.len(), MAX_WORKSPACE_MUTATION_RECEIPTS);
        assert!(!state.receipts.contains_key("call-0"));
        assert_eq!(state.receipt_order.front().unwrap(), "call-1");
        assert!(
            state
                .receipts
                .contains_key(&format!("call-{MAX_WORKSPACE_MUTATION_RECEIPTS}"))
        );
    }

    #[test]
    fn non_local_registration_fails_before_touching_the_root() {
        let temp = TestDirectory::new();
        let marker_root = temp.0.join("must-not-exist");
        let mut registry = ToolRegistry::new();

        let error =
            register_local_dev_connectors(&mut registry, "production", &marker_root).unwrap_err();

        assert_eq!(
            error,
            ConnectorConfigError::EnvironmentDenied("production".into())
        );
        assert!(!marker_root.exists());
        assert!(registry.descriptor(DEV_MARKER_TOOL_NAME).is_none());
    }

    #[test]
    fn non_local_workspace_registration_fails_before_opening_the_root() {
        let temp = TestDirectory::new();
        let missing_root = temp.0.join("must-not-exist");
        let mut registry = ToolRegistry::new();

        let error = register_local_workspace_connectors(&mut registry, "production", &missing_root)
            .unwrap_err();

        assert_eq!(
            error,
            ConnectorConfigError::EnvironmentDenied("production".into())
        );
        assert!(registry.descriptor(WORKSPACE_READ_FILE_TOOL_NAME).is_none());
        assert!(
            registry
                .descriptor(WORKSPACE_REPLACE_TEXT_TOOL_NAME)
                .is_none()
        );
        assert!(
            registry
                .descriptor(WORKSPACE_CREATE_FILE_TOOL_NAME)
                .is_none()
        );
    }

    #[tokio::test]
    async fn workspace_read_is_rooted_bounded_and_utf8_only() {
        let temp = TestDirectory::new();
        fs::create_dir(temp.0.join("src")).unwrap();
        fs::write(temp.0.join("src/lib.rs"), "pub fn zeus() {}\n").unwrap();
        fs::write(
            temp.0.join("too-large.txt"),
            vec![b'a'; MAX_WORKSPACE_FILE_BYTES + 1],
        )
        .unwrap();
        fs::write(temp.0.join("binary.dat"), [0xff, 0xfe]).unwrap();
        let mut registry = ToolRegistry::new();
        let canonical_root =
            register_local_workspace_connectors(&mut registry, LOCAL_DEV_ENVIRONMENT, &temp.0)
                .unwrap();
        assert_eq!(canonical_root, fs::canonicalize(&temp.0).unwrap());

        let output = registry
            .dispatch(workspace_call("src/lib.rs"), LOCAL_DEV_ENVIRONMENT)
            .await
            .unwrap();
        assert_eq!(output.value["path"], "src/lib.rs");
        assert_eq!(output.value["content"], "pub fn zeus() {}\n");
        assert_eq!(output.value["bytes"], 17);
        assert!(!output.replayed);

        for (path, expected_code) in [
            ("too-large.txt", "workspace_file_too_large"),
            ("binary.dat", "workspace_file_not_utf8"),
            ("missing.txt", "workspace_file_not_found"),
        ] {
            let error = registry
                .dispatch(workspace_call(path), LOCAL_DEV_ENVIRONMENT)
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                RegistryError::Executor(ExecutorError::Failed { ref code, .. })
                    if code == expected_code
            ));
        }
    }

    #[tokio::test]
    async fn workspace_read_rejects_noncanonical_and_escaping_paths() {
        let temp = TestDirectory::new();
        fs::write(temp.0.join("safe.txt"), "safe").unwrap();
        let mut registry = ToolRegistry::new();
        register_local_workspace_connectors(&mut registry, LOCAL_DEV_ENVIRONMENT, &temp.0).unwrap();

        for path in [
            "../outside.txt",
            "/etc/passwd",
            "./safe.txt",
            "safe//file.txt",
            "safe.txt/",
            "safe\\file.txt",
            ".zeus-tool-hidden.tmp",
        ] {
            let error = registry
                .dispatch(workspace_call(path), LOCAL_DEV_ENVIRONMENT)
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                RegistryError::Executor(ExecutorError::Failed { ref code, .. })
                    if code == "invalid_workspace_path"
            ));
        }
    }

    #[tokio::test]
    async fn workspace_listing_is_sorted_bounded_and_never_follows_entries() {
        let temp = TestDirectory::new();
        fs::create_dir(temp.0.join("src")).unwrap();
        fs::write(temp.0.join("z.txt"), "z").unwrap();
        fs::write(temp.0.join("a.txt"), "a").unwrap();
        fs::write(temp.0.join(".zeus-tool-hidden.tmp"), "hidden").unwrap();
        fs::create_dir(temp.0.join("too-many")).unwrap();
        for index in 0..=MAX_WORKSPACE_DIRECTORY_ENTRIES {
            fs::write(
                temp.0.join("too-many").join(format!("entry-{index:03}")),
                [],
            )
            .unwrap();
        }
        let mut registry = ToolRegistry::new();
        register_local_workspace_connectors(&mut registry, LOCAL_DEV_ENVIRONMENT, &temp.0).unwrap();

        let output = registry
            .dispatch(workspace_list_call("."), LOCAL_DEV_ENVIRONMENT)
            .await
            .unwrap();
        assert_eq!(output.value["path"], ".");
        assert_eq!(
            output.value["entries"],
            serde_json::json!([
                { "name": "a.txt", "kind": "file" },
                { "name": "src", "kind": "directory" },
                { "name": "too-many", "kind": "directory" },
                { "name": "z.txt", "kind": "file" },
            ])
        );

        let error = registry
            .dispatch(workspace_list_call("too-many"), LOCAL_DEV_ENVIRONMENT)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            RegistryError::Executor(ExecutorError::Failed { ref code, .. })
                if code == "workspace_directory_too_large"
        ));
        let search_error = registry
            .dispatch(
                workspace_search_call("too-many", "entry"),
                LOCAL_DEV_ENVIRONMENT,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            search_error,
            RegistryError::Executor(ExecutorError::Failed { ref code, .. })
                if code == "workspace_search_directory_too_large"
        ));

        let traversal = registry
            .dispatch(workspace_list_call("../outside"), LOCAL_DEV_ENVIRONMENT)
            .await
            .unwrap_err();
        assert!(matches!(
            traversal,
            RegistryError::Executor(ExecutorError::Failed { ref code, .. })
                if code == "invalid_workspace_path"
        ));
    }

    #[tokio::test]
    async fn workspace_search_is_literal_deterministic_and_bounded() {
        let temp = TestDirectory::new();
        fs::create_dir_all(temp.0.join("src/nested")).unwrap();
        fs::create_dir(temp.0.join("target")).unwrap();
        fs::create_dir(temp.0.join("many")).unwrap();
        fs::write(temp.0.join("src/a.rs"), "alpha\nneedle first\nlast\n").unwrap();
        fs::write(temp.0.join("src/nested/b.rs"), "needle second\n").unwrap();
        fs::write(temp.0.join("target/ignored.rs"), "needle ignored\n").unwrap();
        fs::write(
            temp.0.join("large.txt"),
            vec![b'n'; MAX_WORKSPACE_SEARCH_FILE_BYTES + 1],
        )
        .unwrap();
        let many = (0..=MAX_WORKSPACE_SEARCH_MATCHES)
            .map(|index| format!("needle {index}\n"))
            .collect::<String>();
        fs::write(temp.0.join("many/hits.rs"), many).unwrap();
        let mut registry = ToolRegistry::new();
        register_local_workspace_connectors(&mut registry, LOCAL_DEV_ENVIRONMENT, &temp.0).unwrap();

        let output = registry
            .dispatch(
                workspace_search_call("src", "needle"),
                LOCAL_DEV_ENVIRONMENT,
            )
            .await
            .unwrap();
        assert_eq!(output.value["path"], "src");
        assert_eq!(output.value["query"], "needle");
        assert_eq!(
            output.value["matches"],
            serde_json::json!([
                { "path": "src/a.rs", "line": 2, "text": "needle first" },
                { "path": "src/nested/b.rs", "line": 1, "text": "needle second" },
            ])
        );
        assert_eq!(output.value["truncated"], false);
        assert_eq!(output.value["scanned_directories"], 2);
        assert_eq!(output.value["scanned_files"], 2);
        assert_eq!(output.value["scanned_bytes"], 38);
        assert_eq!(output.value["skipped_entries"], 0);

        let ignored = registry
            .dispatch(
                workspace_search_call(".", "needle ignored"),
                LOCAL_DEV_ENVIRONMENT,
            )
            .await
            .unwrap();
        assert!(ignored.value["matches"].as_array().unwrap().is_empty());
        assert!(ignored.value["skipped_entries"].as_u64().unwrap() >= 2);

        let bounded = registry
            .dispatch(
                workspace_search_call("many", "needle"),
                LOCAL_DEV_ENVIRONMENT,
            )
            .await
            .unwrap();
        assert_eq!(
            bounded.value["matches"].as_array().unwrap().len(),
            MAX_WORKSPACE_SEARCH_MATCHES
        );
        assert_eq!(bounded.value["truncated"], true);

        for (path, query, expected_code) in [
            ("../outside", "needle", "invalid_workspace_path"),
            ("src", " \t", "invalid_workspace_search_query"),
        ] {
            let error = registry
                .dispatch(workspace_search_call(path, query), LOCAL_DEV_ENVIRONMENT)
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                RegistryError::Executor(ExecutorError::Failed { ref code, .. })
                    if code == expected_code
            ));
        }
    }

    #[tokio::test]
    async fn workspace_replace_is_atomic_unique_and_idempotent() {
        let temp = TestDirectory::new();
        fs::create_dir(temp.0.join("src")).unwrap();
        fs::write(temp.0.join("src/lib.rs"), "alpha target omega\n").unwrap();
        fs::write(temp.0.join("ambiguous.txt"), "same same\n").unwrap();
        fs::write(temp.0.join("delete.txt"), "prefix remove suffix\n").unwrap();
        fs::write(
            temp.0.join("too-large.txt"),
            vec![b'a'; MAX_WORKSPACE_EDIT_FILE_BYTES + 1],
        )
        .unwrap();
        let mut registry = ToolRegistry::new();
        register_local_workspace_connectors(&mut registry, LOCAL_DEV_ENVIRONMENT, &temp.0).unwrap();

        let call = workspace_replace_call(1, "src/lib.rs", "target", "replacement");
        let first = registry
            .dispatch(call.clone(), LOCAL_DEV_ENVIRONMENT)
            .await
            .unwrap();
        assert_eq!(
            first.value,
            serde_json::json!({
                "path": "src/lib.rs",
                "replacements": 1,
                "bytes_before": 19,
                "bytes_after": 24,
            })
        );
        assert!(!first.replayed);
        assert_eq!(
            fs::read_to_string(temp.0.join("src/lib.rs")).unwrap(),
            "alpha replacement omega\n"
        );

        let replay = registry
            .dispatch(call, LOCAL_DEV_ENVIRONMENT)
            .await
            .unwrap();
        assert_eq!(replay.value, first.value);
        assert!(replay.replayed);

        let conflict = registry
            .dispatch(
                workspace_replace_call(1, "src/lib.rs", "replacement", "other"),
                LOCAL_DEV_ENVIRONMENT,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            conflict,
            RegistryError::Executor(ExecutorError::Failed { ref code, .. })
                if code == "workspace_edit_idempotency_conflict"
        ));

        for (step, path, old_text, new_text, expected_code) in [
            (
                2,
                "ambiguous.txt",
                "same",
                "different",
                "workspace_edit_text_not_unique",
            ),
            (
                3,
                "src/lib.rs",
                "missing",
                "different",
                "workspace_edit_text_not_found",
            ),
            (
                4,
                "src/lib.rs",
                "replacement",
                "replacement",
                "workspace_edit_no_change",
            ),
            (
                5,
                "too-large.txt",
                "a",
                "b",
                "workspace_edit_file_too_large",
            ),
            (
                6,
                "../outside.txt",
                "outside",
                "inside",
                "invalid_workspace_path",
            ),
        ] {
            let error = registry
                .dispatch(
                    workspace_replace_call(step, path, old_text, new_text),
                    LOCAL_DEV_ENVIRONMENT,
                )
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                RegistryError::Executor(ExecutorError::Failed { ref code, .. })
                    if code == expected_code
            ));
        }
        assert_eq!(
            fs::read_to_string(temp.0.join("ambiguous.txt")).unwrap(),
            "same same\n"
        );

        let deleted = registry
            .dispatch(
                workspace_replace_call(7, "delete.txt", "remove", ""),
                LOCAL_DEV_ENVIRONMENT,
            )
            .await
            .unwrap();
        assert_eq!(deleted.value["replacements"], 1);
        assert_eq!(
            fs::read_to_string(temp.0.join("delete.txt")).unwrap(),
            "prefix  suffix\n"
        );
        assert!(fs::read_dir(temp.0.join("src")).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".zeus-tool-")
        }));
    }

    #[tokio::test]
    async fn workspace_create_is_atomic_create_new_and_idempotent() {
        let temp = TestDirectory::new();
        fs::create_dir(temp.0.join("src")).unwrap();
        fs::write(temp.0.join("existing.txt"), "preserve me\n").unwrap();
        let mut registry = ToolRegistry::new();
        register_local_workspace_connectors(&mut registry, LOCAL_DEV_ENVIRONMENT, &temp.0).unwrap();

        let call = workspace_create_call(20, "src/generated.rs", "pub fn generated() {}\n");
        let first = registry
            .dispatch(call.clone(), LOCAL_DEV_ENVIRONMENT)
            .await
            .unwrap();
        assert_eq!(
            first.value,
            serde_json::json!({
                "path": "src/generated.rs",
                "bytes": 22,
                "created": true,
            })
        );
        assert!(!first.replayed);
        assert_eq!(
            fs::read_to_string(temp.0.join("src/generated.rs")).unwrap(),
            "pub fn generated() {}\n"
        );

        let replay = registry
            .dispatch(call, LOCAL_DEV_ENVIRONMENT)
            .await
            .unwrap();
        assert_eq!(replay.value, first.value);
        assert!(replay.replayed);

        let idempotency_conflict = registry
            .dispatch(
                workspace_create_call(20, "src/generated.rs", "different\n"),
                LOCAL_DEV_ENVIRONMENT,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            idempotency_conflict,
            RegistryError::Executor(ExecutorError::Failed { ref code, .. })
                if code == "workspace_create_idempotency_conflict"
        ));

        let existing = registry
            .dispatch(
                workspace_create_call(21, "existing.txt", "overwrite\n"),
                LOCAL_DEV_ENVIRONMENT,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            existing,
            RegistryError::Executor(ExecutorError::Failed { ref code, .. })
                if code == "workspace_create_target_exists"
        ));
        assert_eq!(
            fs::read_to_string(temp.0.join("existing.txt")).unwrap(),
            "preserve me\n"
        );

        let missing_parent = registry
            .dispatch(
                workspace_create_call(22, "missing/file.txt", "content\n"),
                LOCAL_DEV_ENVIRONMENT,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(
                missing_parent,
                RegistryError::Executor(ExecutorError::Failed { ref code, .. })
                    if code == "workspace_create_parent_not_found"
            ),
            "unexpected missing-parent error: {missing_parent:?}"
        );

        let oversized = registry
            .dispatch(
                workspace_create_call(23, "oversized.txt", &"界".repeat(4097)),
                LOCAL_DEV_ENVIRONMENT,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            oversized,
            RegistryError::Executor(ExecutorError::Failed { ref code, .. })
                if code == "workspace_create_content_too_large"
        ));
        assert!(!temp.0.join("oversized.txt").exists());

        assert!(fs::read_dir(temp.0.join("src")).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".zeus-tool-")
        }));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn workspace_read_never_follows_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = TestDirectory::new();
        let outside = temp.0.parent().unwrap().join(format!(
            "zeus-connectors-outside-{}-{}",
            std::process::id(),
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&outside, "outside secret").unwrap();
        fs::create_dir(temp.0.join("nested")).unwrap();
        symlink(&outside, temp.0.join("linked-file")).unwrap();
        symlink(temp.0.parent().unwrap(), temp.0.join("nested/linked-dir")).unwrap();
        let mut registry = ToolRegistry::new();
        register_local_workspace_connectors(&mut registry, LOCAL_DEV_ENVIRONMENT, &temp.0).unwrap();

        let listing = registry
            .dispatch(workspace_list_call("."), LOCAL_DEV_ENVIRONMENT)
            .await
            .unwrap();
        assert!(
            listing.value["entries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["name"] == "linked-file" && entry["kind"] == "symlink")
        );
        let search = registry
            .dispatch(
                workspace_search_call(".", "outside secret"),
                LOCAL_DEV_ENVIRONMENT,
            )
            .await
            .unwrap();
        assert!(search.value["matches"].as_array().unwrap().is_empty());
        let edit = registry
            .dispatch(
                workspace_replace_call(8, "linked-file", "outside", "inside"),
                LOCAL_DEV_ENVIRONMENT,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            edit,
            RegistryError::Executor(ExecutorError::Failed { ref code, .. })
                if code == "workspace_symlink_denied"
        ));
        assert_eq!(fs::read_to_string(&outside).unwrap(), "outside secret");

        let create = registry
            .dispatch(
                workspace_create_call(24, "nested/linked-dir/created.txt", "inside\n"),
                LOCAL_DEV_ENVIRONMENT,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            create,
            RegistryError::Executor(ExecutorError::Failed { ref code, .. })
                if code == "workspace_symlink_denied"
        ));
        assert!(!temp.0.parent().unwrap().join("created.txt").exists());

        for path in ["linked-file", "nested/linked-dir/outside.txt"] {
            let error = registry
                .dispatch(workspace_call(path), LOCAL_DEV_ENVIRONMENT)
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                RegistryError::Executor(ExecutorError::Failed { ref code, .. })
                    if code == "workspace_symlink_denied"
            ));
        }
        fs::remove_file(outside).unwrap();
    }

    #[tokio::test]
    async fn marker_write_is_atomic_bounded_and_idempotent() {
        let temp = TestDirectory::new();
        let marker_root = temp.0.join("markers");
        let mut registry = ToolRegistry::new();
        let canonical_root =
            register_local_dev_connectors(&mut registry, LOCAL_DEV_ENVIRONMENT, &marker_root)
                .unwrap();
        let call = call("alpha verified");

        let first = registry
            .dispatch(call.clone(), LOCAL_DEV_ENVIRONMENT)
            .await
            .unwrap();
        let replay = registry
            .dispatch(call, LOCAL_DEV_ENVIRONMENT)
            .await
            .unwrap();

        assert!(!first.replayed);
        assert!(replay.replayed);
        let file_name = first.value["file_name"].as_str().unwrap();
        assert!(!file_name.contains("alpha verified"));
        let files = fs::read_dir(&canonical_root)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(files.len(), 1);
        let contents = fs::read_to_string(canonical_root.join(file_name)).unwrap();
        assert!(contents.contains("alpha verified"));
    }

    #[tokio::test]
    async fn caller_cannot_select_a_path_or_escape_with_marker_text() {
        let temp = TestDirectory::new();
        let marker_root = temp.0.join("markers");
        let mut registry = ToolRegistry::new();
        register_local_dev_connectors(&mut registry, LOCAL_DEV_ENVIRONMENT, &marker_root).unwrap();

        let mut path_argument = call("safe");
        path_argument.arguments = json!({"marker": "safe", "path": "../../escaped"});
        path_argument.arguments_digest = arguments_digest(&path_argument.arguments);
        assert!(matches!(
            registry
                .dispatch(path_argument, LOCAL_DEV_ENVIRONMENT)
                .await,
            Err(RegistryError::InvalidArguments(_))
        ));

        let traversal = call("../../escaped");
        assert!(matches!(
            registry.dispatch(traversal, LOCAL_DEV_ENVIRONMENT).await,
            Err(RegistryError::Executor(ExecutorError::Failed { ref code, .. }))
                if code == "invalid_marker"
        ));
        assert_eq!(fs::read_dir(&marker_root).unwrap().count(), 0);
        assert!(!temp.0.join("escaped").exists());
    }

    #[tokio::test]
    async fn reused_call_id_with_different_content_is_a_conflict() {
        let temp = TestDirectory::new();
        let marker_root = temp.0.join("markers");
        let mut registry = ToolRegistry::new();
        register_local_dev_connectors(&mut registry, LOCAL_DEV_ENVIRONMENT, &marker_root).unwrap();

        registry
            .dispatch(call("first"), LOCAL_DEV_ENVIRONMENT)
            .await
            .unwrap();
        let error = registry
            .dispatch(call("second"), LOCAL_DEV_ENVIRONMENT)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            RegistryError::Executor(ExecutorError::Failed { ref code, .. })
                if code == "idempotency_conflict"
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_existing_symlink_is_never_followed() {
        use std::os::unix::fs::symlink;

        let temp = TestDirectory::new();
        let marker_root = temp.0.join("markers");
        let outside = temp.0.join("outside.txt");
        fs::write(&outside, "do not change").unwrap();
        let mut registry = ToolRegistry::new();
        let root =
            register_local_dev_connectors(&mut registry, LOCAL_DEV_ENVIRONMENT, &marker_root)
                .unwrap();
        let call = call("safe");
        symlink(&outside, root.join(format!("marker-{}.json", call.call_id))).unwrap();

        let error = registry
            .dispatch(call, LOCAL_DEV_ENVIRONMENT)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            RegistryError::Executor(ExecutorError::Failed { ref code, .. })
                if code == "unsafe_existing_marker"
        ));
        assert_eq!(fs::read_to_string(outside).unwrap(), "do not change");
    }
}
