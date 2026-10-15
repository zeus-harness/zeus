//! Managed Git storage. This is not a shell executor or a sandbox boundary.
//! Only deployment operators import sources; runtime paths are derived from IDs.
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{io::AsyncReadExt, process::Command};
use uuid::Uuid;

#[cfg(test)]
mod tests;

const MAX_BYTES: u64 = 32 * 1024 * 1024;
const MAX_FILES: usize = 4096;
const MAX_OUTPUT: u64 = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum CodeError {
    #[error("code_storage_io_error")]
    Io,
    #[error("code_git_operation_failed")]
    Git,
    #[error("code_operation_timeout")]
    Timeout,
    #[error("code_storage_limit_exceeded")]
    Limit,
    #[error("code_repository_unavailable")]
    Unavailable,
    #[error("invalid_code_repository_input")]
    Invalid,
}
impl From<std::io::Error> for CodeError {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryBinding {
    pub repository_id: Uuid,
    pub commit: String,
}
impl RepositoryBinding {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        valid_commit(&self.commit) && !self.repository_id.is_nil()
    }
}
#[must_use]
pub fn valid_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Copy)]
pub struct CodeScope {
    pub organization_id: Uuid,
    pub workspace_id: Uuid,
    pub run_id: Uuid,
    pub fence: i64,
}

pub struct CodeStorage {
    root: PathBuf,
}

#[allow(clippy::missing_errors_doc)]
impl CodeStorage {
    pub async fn new(root: &Path) -> Result<Self, CodeError> {
        if !root.is_absolute() {
            return Err(CodeError::Invalid);
        }
        tokio::fs::create_dir_all(root).await?;
        let metadata = tokio::fs::symlink_metadata(root).await?;
        if metadata.file_type().is_symlink() {
            return Err(CodeError::Invalid);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).await?;
        }
        Ok(Self {
            root: tokio::fs::canonicalize(root).await?,
        })
    }
    fn repository(&self, scope: CodeScope, repository: Uuid) -> PathBuf {
        self.root
            .join(scope.organization_id.to_string())
            .join(scope.workspace_id.to_string())
            .join("repositories")
            .join(repository.to_string())
    }
    #[must_use]
    pub fn directory(&self, scope: CodeScope) -> PathBuf {
        self.root
            .join(scope.organization_id.to_string())
            .join(scope.workspace_id.to_string())
            .join("runs")
            .join(scope.run_id.to_string())
            .join(scope.fence.to_string())
    }
    /// Imports an operator-authorized local repository or credential-free HTTPS URL.
    /// Never call with a model-supplied URL or path. No recursive submodule fetch.
    pub async fn import(
        &self,
        scope: CodeScope,
        repository: Uuid,
        source: &str,
    ) -> Result<(), CodeError> {
        if let Ok(url) = url::Url::parse(source) {
            if url.scheme() != "https"
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(CodeError::Invalid);
            }
        } else if !Path::new(source).is_absolute() {
            return Err(CodeError::Invalid);
        }
        let destination = self.repository(scope, repository);
        if tokio::fs::try_exists(&destination).await? {
            return Err(CodeError::Invalid);
        }
        let parent = destination.parent().ok_or(CodeError::Invalid)?;
        tokio::fs::create_dir_all(parent).await?;
        let staging = parent.join(format!("import-{}", Uuid::now_v7()));
        let result = git(
            parent,
            &[
                "clone",
                "--bare",
                "--no-local",
                "--",
                source,
                path_text(&staging)?,
            ],
            true,
        )
        .await;
        if result.is_err() {
            let _ = tokio::fs::remove_dir_all(&staging).await;
        }
        result?;
        // The operator-selected transport is no longer needed during execution.
        git(&staging, &["remote", "remove", "origin"], false).await?;
        tokio::fs::rename(staging, destination).await?;
        Ok(())
    }
    pub async fn prepare(
        &self,
        scope: CodeScope,
        binding: &RepositoryBinding,
        checkpoint: Option<&str>,
    ) -> Result<PathBuf, CodeError> {
        if scope.fence <= 0 || !binding.is_valid() {
            return Err(CodeError::Invalid);
        }
        let commit = checkpoint.unwrap_or(&binding.commit);
        if !valid_commit(commit) {
            return Err(CodeError::Invalid);
        }
        let repository = self.repository(scope, binding.repository_id);
        if !tokio::fs::try_exists(&repository).await? {
            return Err(CodeError::Unavailable);
        }
        validate_tree(&repository, commit).await?;
        let destination = self.directory(scope);
        // Never reset a live attempt: it may contain changes not yet checkpointed.
        if tokio::fs::try_exists(&destination).await? {
            return Err(CodeError::Invalid);
        }
        tokio::fs::create_dir_all(destination.parent().ok_or(CodeError::Invalid)?).await?;
        git(
            &repository,
            &[
                "worktree",
                "add",
                "--detach",
                path_text(&destination)?,
                commit,
            ],
            false,
        )
        .await?;
        Ok(destination)
    }
    pub async fn checkpoint(
        &self,
        scope: CodeScope,
        binding: &RepositoryBinding,
        id: Uuid,
    ) -> Result<String, CodeError> {
        let directory = self.directory(scope);
        validate_directory(&directory).await?;
        validate_git_pointer(&directory, &self.repository(scope, binding.repository_id)).await?;
        git(&directory, &["add", "--all", "--", "."], false).await?;
        let tree = git(&directory, &["write-tree"], false).await?;
        let parent = git(&directory, &["rev-parse", "--verify", "HEAD"], false).await?;
        let commit = git(
            &directory,
            &[
                "commit-tree",
                tree.trim(),
                "-p",
                parent.trim(),
                "-m",
                "Zeus code checkpoint",
            ],
            false,
        )
        .await?;
        let commit = commit.trim().to_owned();
        if !valid_commit(&commit) {
            return Err(CodeError::Git);
        }
        // A checkpoint must satisfy the same restore limits as an imported tree.
        validate_tree(&directory, &commit).await?;
        git(
            &self.repository(scope, binding.repository_id),
            &[
                "update-ref",
                &format!("refs/zeus/checkpoints/{}/{}", scope.run_id, id),
                &commit,
            ],
            false,
        )
        .await?;
        Ok(commit)
    }
    pub async fn release(
        &self,
        scope: CodeScope,
        binding: &RepositoryBinding,
    ) -> Result<(), CodeError> {
        let directory = self.directory(scope);
        if !tokio::fs::try_exists(&directory).await? {
            return Ok(());
        }
        git(
            &self.repository(scope, binding.repository_id),
            &["worktree", "remove", "--force", path_text(&directory)?],
            false,
        )
        .await?;
        Ok(())
    }
}
fn path_text(path: &Path) -> Result<&str, CodeError> {
    path.to_str().ok_or(CodeError::Invalid)
}

async fn git(directory: &Path, args: &[&str], transport: bool) -> Result<String, CodeError> {
    let mut command = Command::new("/usr/bin/git");
    command
        .current_dir(directory)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/nonexistent")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env(
            "GIT_ALLOW_PROTOCOL",
            if transport { "https:file" } else { "" },
        )
        .env("LC_ALL", "C")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "credential.helper=",
            "-c",
            "http.followRedirects=false",
            "-c",
            "commit.gpgSign=false",
            "-c",
            "user.name=Zeus",
            "-c",
            "user.email=checkpoint@zeus.invalid",
        ])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    if !Path::new("/bin/kill").is_file() {
        return Err(CodeError::Unavailable);
    }
    let mut child = command.spawn()?;
    let mut process_group = GitProcessGroup(child.id());
    let output = child.stdout.take().ok_or(CodeError::Git)?;
    let operation = async {
        let mut bytes = Vec::new();
        output.take(MAX_OUTPUT + 1).read_to_end(&mut bytes).await?;
        if bytes.len() as u64 > MAX_OUTPUT {
            return Err(CodeError::Limit);
        }
        let status = child.wait().await?;
        process_group.0 = None;
        if !status.success() {
            return Err(CodeError::Git);
        }
        String::from_utf8(bytes).map_err(|_| CodeError::Invalid)
    };
    tokio::time::timeout(Duration::from_mins(2), operation)
        .await
        .map_err(|_| CodeError::Timeout)?
}
async fn validate_tree(repository: &Path, commit: &str) -> Result<(), CodeError> {
    let output = git(repository, &["ls-tree", "-r", "-l", "-z", commit], false).await?;
    let mut bytes = 0_u64;
    for (index, entry) in output
        .split('\0')
        .filter(|entry| !entry.is_empty())
        .enumerate()
    {
        let (metadata, name) = entry.split_once('\t').ok_or(CodeError::Invalid)?;
        let fields: Vec<_> = metadata.split_whitespace().collect();
        if fields.len() != 4
            || !matches!(fields[0], "100644" | "100755")
            || fields[1] != "blob"
            || Path::new(name)
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
            || name
                .split('/')
                .any(|part| part.eq_ignore_ascii_case(".git"))
        {
            return Err(CodeError::Invalid);
        }
        bytes = bytes
            .checked_add(fields[3].parse::<u64>().map_err(|_| CodeError::Invalid)?)
            .ok_or(CodeError::Limit)?;
        if index >= MAX_FILES || bytes > MAX_BYTES {
            return Err(CodeError::Limit);
        }
    }
    Ok(())
}
async fn validate_directory(root: &Path) -> Result<(), CodeError> {
    if !tokio::fs::symlink_metadata(root)
        .await?
        .file_type()
        .is_dir()
    {
        return Err(CodeError::Invalid);
    }
    let mut pending = vec![root.to_path_buf()];
    let mut count = 0_usize;
    let mut bytes = 0_u64;
    while let Some(directory) = pending.pop() {
        let mut entries = tokio::fs::read_dir(&directory).await?;
        while let Some(entry) = entries.next_entry().await? {
            if directory == root && entry.file_name() == ".git" {
                continue;
            }
            let metadata = tokio::fs::symlink_metadata(entry.path()).await?;
            count += 1;
            if count > MAX_FILES {
                return Err(CodeError::Limit);
            }
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                bytes = bytes.saturating_add(metadata.len());
            } else {
                return Err(CodeError::Invalid);
            }
            if bytes > MAX_BYTES {
                return Err(CodeError::Limit);
            }
        }
    }
    Ok(())
}

// Cancel the whole Git process group before dropping the parent handle. No shell
// is involved, and the only argument is a kernel-assigned PID.
struct GitProcessGroup(Option<u32>);
impl Drop for GitProcessGroup {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            let _ = std::process::Command::new("/bin/kill")
                .args(["-KILL", "--", &format!("-{pid}")])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

async fn validate_git_pointer(directory: &Path, repository: &Path) -> Result<(), CodeError> {
    let pointer = directory.join(".git");
    let metadata = tokio::fs::symlink_metadata(&pointer).await?;
    if !metadata.is_file() || metadata.len() > 4096 {
        return Err(CodeError::Invalid);
    }
    let content = tokio::fs::read_to_string(&pointer).await?;
    let target = content
        .trim()
        .strip_prefix("gitdir: ")
        .ok_or(CodeError::Invalid)?;
    let git_directory = tokio::fs::canonicalize(directory.join(target)).await?;
    let repository = tokio::fs::canonicalize(repository).await?;
    if git_directory.parent() != Some(repository.join("worktrees").as_path()) {
        return Err(CodeError::Invalid);
    }
    let common = tokio::fs::read_to_string(git_directory.join("commondir")).await?;
    let backlink = tokio::fs::read_to_string(git_directory.join("gitdir")).await?;
    if tokio::fs::canonicalize(git_directory.join(common.trim())).await? != repository
        || tokio::fs::canonicalize(backlink.trim()).await?
            != tokio::fs::canonicalize(pointer).await?
    {
        return Err(CodeError::Invalid);
    }
    Ok(())
}
