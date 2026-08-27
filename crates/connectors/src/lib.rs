//! Narrow, explicitly configured tool connectors.
//!
//! The Alpha ships one real executor, `dev_marker_write`. It is registered only
//! for `local-development`, accepts no caller-provided path, and atomically publishes a
//! deterministic file below one fixed root. There is no host-command or remote
//! provider fallback.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use cap_std::{ambient_authority, fs::Dir};
use protocol::{SandboxProfile, ToolEffect};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use tools::{
    ExecutionFuture, ExecutionRequest, ExecutorError, ObjectSchema, ParameterSpec, RegistryError,
    ToolDescriptor, ToolExecutor, ToolOutput, ToolRegistry,
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
pub const MAX_WORKSPACE_PATH_BYTES: usize = 512;
pub const MAX_WORKSPACE_FILE_BYTES: usize = 8 * 1024;
pub const MAX_WORKSPACE_DIRECTORY_ENTRIES: usize = 64;

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

/// Register the bounded read-only workspace connector for local development.
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
    registry.register(workspace_read_file_descriptor(), executor)?;
    registry.register(workspace_list_directory_descriptor(), list_executor)?;
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

struct WorkspaceRoots {
    confined: Dir,
    inspection: Dir,
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceReadArguments {
    path: String,
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

fn validate_workspace_directory_path(path: &str) -> Result<PathBuf, ExecutorError> {
    if path == "." {
        return Ok(PathBuf::from(path));
    }
    validate_workspace_path(path)
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
        if entries.len() == MAX_WORKSPACE_DIRECTORY_ENTRIES {
            return Err(workspace_failure(
                "workspace_directory_too_large",
                "The requested workspace directory exceeds the 64-entry limit",
                false,
            ));
        }
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
        let mut file = OpenOptions::new()
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
