//! Narrow, explicitly configured tool connectors.
//!
//! The Alpha ships one real executor, `dev_marker_write`. It is registered only
//! for `local-development`, accepts no caller-provided path, and atomically publishes a
//! deterministic file below one fixed root. There is no host-command or remote
//! provider fallback.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

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

static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ConnectorConfigError {
    #[error("development connectors cannot be registered in environment `{0}`")]
    EnvironmentDenied(String),
    #[error("marker root must be a directory: {0}")]
    InvalidRoot(String),
    #[error("failed to prepare marker root: {0}")]
    RootIo(String),
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
