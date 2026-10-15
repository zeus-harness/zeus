//! Authenticated client for the separate Linux sandbox adapter. No local shell fallback.
use base64::{Engine, engine::general_purpose::STANDARD};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::{
    path::{Component, Path},
    time::Duration,
};
use uuid::Uuid;

const MAX_BYTES: usize = 32 * 1024 * 1024;
const MAX_FILES: usize = 4096;
const MAX_JSON: usize = 48 * 1024 * 1024;

#[must_use]
pub fn valid_environment(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hash| {
        hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
#[derive(Debug, thiserror::Error)]
#[error("sandbox_operation_failed")]
pub struct SandboxError;
impl From<std::io::Error> for SandboxError {
    fn from(_: std::io::Error) -> Self {
        Self
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeFile {
    path: String,
    data: String,
    executable: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxOutput {
    pub status: String,
    pub exit_code: i32,
    pub output: String,
    pub files: Vec<CodeFile>,
}
#[derive(Clone)]
pub struct SandboxClient {
    client: reqwest::Client,
    base: url::Url,
    token: SecretString,
}
#[allow(clippy::missing_errors_doc)]
impl SandboxClient {
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let (Ok(endpoint), Ok(token)) = (
            std::env::var("ZEUS_SANDBOX_URL"),
            std::env::var("ZEUS_SANDBOX_TOKEN"),
        ) else {
            anyhow::ensure!(
                std::env::var_os("ZEUS_SANDBOX_URL").is_none()
                    && std::env::var_os("ZEUS_SANDBOX_TOKEN").is_none(),
                "incomplete sandbox configuration"
            );
            return Ok(None);
        };
        Self::new(&endpoint, SecretString::from(token)).map(Some)
    }
    pub fn new(endpoint: &str, token: SecretString) -> anyhow::Result<Self> {
        let base =
            url::Url::parse(endpoint).map_err(|_| anyhow::anyhow!("invalid sandbox endpoint"))?;
        anyhow::ensure!(
            matches!(base.scheme(), "http" | "https")
                && base.host_str().is_some()
                && base.username().is_empty()
                && base.password().is_none()
                && base.query().is_none()
                && base.fragment().is_none()
                && base.path() == "/"
                && token.expose_secret().len() >= 32,
            "invalid sandbox configuration"
        );
        Ok(Self {
            base,
            token,
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(330))
                .build()?,
        })
    }
    fn request(&self, suffix: &str) -> reqwest::RequestBuilder {
        self.client
            .post(self.base.join(suffix).expect("internal static path"))
            .bearer_auth(self.token.expose_secret())
    }
    pub async fn execute(
        &self,
        id: Uuid,
        environment: &str,
        script: &str,
        timeout: u32,
        files: Vec<CodeFile>,
    ) -> Result<SandboxOutput, SandboxError> {
        if !valid_environment(environment)
            || script.is_empty()
            || script.len() > 16384
            || script.contains('\0')
            || !(1..=300).contains(&timeout)
        {
            return Err(SandboxError);
        }
        let _guard = CancelJob {
            client: self.clone(),
            id,
        };
        let request = self
            .request("execute")
            .json(&serde_json::json!({"job_id":id, "environment":environment,
            "script":script, "timeout_seconds":timeout,"files":files}))
            .send();
        tokio::pin!(request);
        let mut heartbeat = tokio::time::interval(Duration::from_secs(2));
        let mut response = loop {
            tokio::select! {
                result = &mut request => break result.map_err(|_| SandboxError)?.error_for_status().map_err(|_| SandboxError)?,
                _ = heartbeat.tick() => {
                    self.request(&format!("jobs/{id}/renew")).timeout(Duration::from_secs(2)).send().await.map_err(|_| SandboxError)?.error_for_status().map_err(|_| SandboxError)?;
                }
            }
        };
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| SandboxError)? {
            if bytes.len().saturating_add(chunk.len()) > MAX_JSON {
                return Err(SandboxError);
            }
            bytes.extend_from_slice(&chunk);
        }
        let output: SandboxOutput = serde_json::from_slice(&bytes).map_err(|_| SandboxError)?;
        if output.output.len() > 4 * 65536 || output.status != "completed" {
            return Err(SandboxError);
        }
        validate_files(&output.files)?;
        Ok(output)
    }
}
struct CancelJob {
    client: SandboxClient,
    id: Uuid,
}
impl Drop for CancelJob {
    fn drop(&mut self) {
        let client = self.client.clone();
        let id = self.id;
        tokio::spawn(async move {
            let _ = client
                .request(&format!("jobs/{id}/cancel"))
                .timeout(Duration::from_secs(2))
                .send()
                .await;
        });
    }
}
fn valid_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.contains(['\\', '\0'])
        && value.split('/').all(|part| {
            !part.is_empty() && part != "." && part != ".." && !part.eq_ignore_ascii_case(".git")
        })
        && Path::new(value)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}
fn validate_files(files: &[CodeFile]) -> Result<(), SandboxError> {
    let mut size = 0_usize;
    let mut names = std::collections::HashSet::new();
    if files.len() > MAX_FILES {
        return Err(SandboxError);
    }
    for file in files {
        if !valid_path(&file.path) || !names.insert(&file.path) {
            return Err(SandboxError);
        }
        size = size.saturating_add(STANDARD.decode(&file.data).map_err(|_| SandboxError)?.len());
        if size > MAX_BYTES {
            return Err(SandboxError);
        }
    }
    Ok(())
}
#[allow(clippy::missing_errors_doc)]
pub async fn export_files(root: &Path) -> Result<Vec<CodeFile>, SandboxError> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    let mut count = 0;
    let mut bytes = 0;
    if !tokio::fs::symlink_metadata(root).await?.is_dir() {
        return Err(SandboxError);
    }
    while let Some(directory) = pending.pop() {
        let mut entries = tokio::fs::read_dir(&directory).await?;
        while let Some(entry) = entries.next_entry().await? {
            if directory == root && entry.file_name() == ".git" {
                continue;
            }
            let path = entry.path();
            let metadata = tokio::fs::symlink_metadata(&path).await?;
            let relative = path
                .strip_prefix(root)
                .map_err(|_| SandboxError)?
                .to_str()
                .ok_or(SandboxError)?
                .to_owned();
            count += 1;
            if count > MAX_FILES || !valid_path(&relative) {
                return Err(SandboxError);
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                bytes += metadata.len();
                if bytes > MAX_BYTES as u64 {
                    return Err(SandboxError);
                }
                #[cfg(unix)]
                let executable = {
                    use std::os::unix::fs::PermissionsExt;
                    metadata.permissions().mode() & 0o111 != 0
                };
                #[cfg(not(unix))]
                let executable = false;
                files.push(CodeFile {
                    path: relative,
                    data: STANDARD.encode(tokio::fs::read(path).await?),
                    executable,
                });
            } else {
                return Err(SandboxError);
            }
        }
    }
    Ok(files)
}
#[allow(clippy::missing_errors_doc)]
pub async fn import_files(root: &Path, files: &[CodeFile]) -> Result<(), SandboxError> {
    validate_files(files)?;
    // Build a separate tree before touching the managed worktree. Never import .git.
    let staging = root.with_file_name(format!("result-{}", Uuid::now_v7()));
    tokio::fs::create_dir(&staging).await?;
    let result = async {
        for file in files {
            let path = staging.join(&file.path);
            tokio::fs::create_dir_all(path.parent().ok_or(SandboxError)?).await?;
            tokio::fs::write(
                &path,
                STANDARD.decode(&file.data).map_err(|_| SandboxError)?,
            )
            .await?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                tokio::fs::set_permissions(
                    path,
                    std::fs::Permissions::from_mode(if file.executable { 0o700 } else { 0o600 }),
                )
                .await?;
            }
        }
        // Only this fenced attempt owns root; all imported files are ordinary files.
        let mut entries = tokio::fs::read_dir(root).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_name() == ".git" {
                continue;
            }
            if entry.file_type().await?.is_dir() {
                tokio::fs::remove_dir_all(entry.path()).await?;
            } else {
                tokio::fs::remove_file(entry.path()).await?;
            }
        }
        let mut entries = tokio::fs::read_dir(&staging).await?;
        while let Some(entry) = entries.next_entry().await? {
            tokio::fs::rename(entry.path(), root.join(entry.file_name())).await?;
        }
        Ok(())
    }
    .await;
    let _ = tokio::fs::remove_dir_all(staging).await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_traversal_metadata_and_mutable_images() {
        for path in [
            "../escape",
            "/etc/passwd",
            ".git/config",
            "a/.GIT/b",
            "a//b",
            "a/./b",
            "a\\b",
        ] {
            assert!(!valid_path(path));
        }
        assert!(valid_path("src/main.rs"));
        assert!(!valid_environment("alpine:latest"));
        assert!(valid_environment(&format!("sha256:{}", "a".repeat(64))));
    }
    #[tokio::test]
    async fn transfer_preserves_git_metadata_and_binary_files() {
        let root = std::env::temp_dir().join(format!("zeus-sandbox-transfer-{}", Uuid::now_v7()));
        tokio::fs::create_dir(&root).await.unwrap();
        tokio::fs::write(root.join(".git"), "private")
            .await
            .unwrap();
        tokio::fs::write(root.join("old.txt"), "old").await.unwrap();
        let files = vec![CodeFile {
            path: "src/new.bin".into(),
            data: STANDARD.encode([0, 255, 10]),
            executable: true,
        }];
        import_files(&root, &files).await.unwrap();
        assert_eq!(
            tokio::fs::read_to_string(root.join(".git")).await.unwrap(),
            "private"
        );
        assert!(!root.join("old.txt").exists());
        let exported = export_files(&root).await.unwrap();
        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0].data, files[0].data);
        tokio::fs::remove_dir_all(root).await.unwrap();
    }
}
