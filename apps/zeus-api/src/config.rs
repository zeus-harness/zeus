use std::{
    env, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use anyhow::{Context, bail};
use secrecy::SecretString;
use url::Url;

#[derive(Clone, Debug)]
#[allow(clippy::struct_excessive_bools)] // These are independent deployment policy switches.
pub struct AppConfig {
    pub bind_address: SocketAddr,
    pub database_url: String,
    pub runtime_database_url: String,
    pub public_url: Url,
    pub http_database_connections: u32,
    pub runtime_database_connections: u32,
    pub run_concurrency: usize,
    pub supervisor_enabled: bool,
    pub lease_duration: Duration,
    pub poll_interval: Duration,
    pub node_id: String,
    pub session_ttl: Duration,
    pub oidc_state_ttl: Duration,
    pub cookie_secure: bool,
    pub allow_private_oidc_issuers: bool,
    pub allow_private_model_endpoints: bool,
    pub envelope_key_id: String,
    pub envelope_key: Option<SecretString>,
}

impl AppConfig {
    /// Loads process configuration from environment variables.
    ///
    /// # Errors
    ///
    /// Returns an error when a required value is missing, a value cannot be
    /// parsed, or a configured limit is outside the accepted range.
    pub fn from_env() -> anyhow::Result<Self> {
        let database_url = required("DATABASE_URL")?;
        let runtime_database_url =
            env::var("RUNTIME_DATABASE_URL").unwrap_or_else(|_| database_url.clone());
        let bind_address = parse("ZEUS_BIND_ADDRESS", "0.0.0.0:8080")?;
        let public_url = parse_url("ZEUS_PUBLIC_URL", "http://127.0.0.1:8080")?;
        let http_database_connections = parse("ZEUS_HTTP_DB_CONNECTIONS", "10")?;
        let runtime_database_connections = parse("ZEUS_RUNTIME_DB_CONNECTIONS", "5")?;
        let run_concurrency = parse(
            "ZEUS_RUN_CONCURRENCY",
            if cfg!(debug_assertions) { "4" } else { "32" },
        )?;
        let supervisor_enabled = parse("ZEUS_SUPERVISOR_ENABLED", "false")?;
        let lease_seconds: u64 = parse("ZEUS_RUN_LEASE_SECONDS", "60")?;
        let poll_milliseconds: u64 = parse("ZEUS_RUN_POLL_MILLISECONDS", "1000")?;
        let node_id = env::var("ZEUS_NODE_ID")
            .unwrap_or_else(|_| format!("zeus-api-{}", uuid::Uuid::now_v7()));
        let session_ttl_seconds: u64 = parse("ZEUS_SESSION_TTL_SECONDS", "43200")?;
        let oidc_state_ttl_seconds: u64 = parse("ZEUS_OIDC_STATE_TTL_SECONDS", "600")?;
        let cookie_secure = parse(
            "ZEUS_COOKIE_SECURE",
            if public_url.scheme() == "https" {
                "true"
            } else {
                "false"
            },
        )?;
        let allow_private_oidc_issuers = parse("ZEUS_ALLOW_PRIVATE_OIDC_ISSUERS", "false")?;
        let allow_private_model_endpoints = parse("ZEUS_ALLOW_PRIVATE_MODEL_ENDPOINTS", "false")?;
        let envelope_key_id =
            env::var("ZEUS_ENVELOPE_KEY_ID").unwrap_or_else(|_| "local-v1".to_owned());
        let envelope_key = load_envelope_key()?;

        if run_concurrency == 0 {
            bail!("ZEUS_RUN_CONCURRENCY must be greater than zero");
        }
        if lease_seconds < 10 {
            bail!("ZEUS_RUN_LEASE_SECONDS must be at least 10");
        }
        if session_ttl_seconds < 300 {
            bail!("ZEUS_SESSION_TTL_SECONDS must be at least 300");
        }
        if !(60..=1800).contains(&oidc_state_ttl_seconds) {
            bail!("ZEUS_OIDC_STATE_TTL_SECONDS must be between 60 and 1800");
        }

        Ok(Self {
            bind_address,
            database_url,
            runtime_database_url,
            public_url,
            http_database_connections,
            runtime_database_connections,
            run_concurrency,
            supervisor_enabled,
            lease_duration: Duration::from_secs(lease_seconds),
            poll_interval: Duration::from_millis(poll_milliseconds),
            node_id,
            session_ttl: Duration::from_secs(session_ttl_seconds),
            oidc_state_ttl: Duration::from_secs(oidc_state_ttl_seconds),
            cookie_secure,
            allow_private_oidc_issuers,
            allow_private_model_endpoints,
            envelope_key_id,
            envelope_key,
        })
    }
}

fn load_envelope_key() -> anyhow::Result<Option<SecretString>> {
    let direct = env::var("ZEUS_ENVELOPE_KEY")
        .or_else(|_| env::var("ZEUS_LOCAL_MASTER_KEY"))
        .ok();
    let file = env::var("ZEUS_ENVELOPE_KEY_FILE").ok().map(PathBuf::from);
    load_envelope_key_from(direct, file.as_deref())
}

fn load_envelope_key_from(
    direct: Option<String>,
    file: Option<&Path>,
) -> anyhow::Result<Option<SecretString>> {
    if direct.is_some() && file.is_some() {
        bail!("configure either ZEUS_ENVELOPE_KEY_FILE or an inline envelope key, not both");
    }
    if let Some(path) = file {
        return load_envelope_key_file(path).map(Some);
    }
    Ok(direct.map(SecretString::from))
}

fn load_envelope_key_file(path: &Path) -> anyhow::Result<SecretString> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| "ZEUS_ENVELOPE_KEY_FILE cannot be read")?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        bail!("ZEUS_ENVELOPE_KEY_FILE must reference a regular file");
    }
    if metadata.len() == 0 || metadata.len() > 4_096 {
        bail!("ZEUS_ENVELOPE_KEY_FILE has an invalid size");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("ZEUS_ENVELOPE_KEY_FILE must not be accessible by group or other users");
        }
    }
    let encoded = fs::read_to_string(path)
        .with_context(|| "ZEUS_ENVELOPE_KEY_FILE cannot be read as text")?;
    let encoded = encoded.trim();
    if encoded.is_empty() {
        bail!("ZEUS_ENVELOPE_KEY_FILE is empty");
    }
    Ok(SecretString::from(encoded.to_owned()))
}

fn required(name: &str) -> anyhow::Result<String> {
    env::var(name).with_context(|| format!("required environment variable {name} is not set"))
}

fn parse<T>(name: &str, default: &str) -> anyhow::Result<T>
where
    T: FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    env::var(name)
        .unwrap_or_else(|_| default.to_owned())
        .parse::<T>()
        .with_context(|| format!("environment variable {name} is invalid"))
}

fn parse_url(name: &str, default: &str) -> anyhow::Result<Url> {
    let value = env::var(name).unwrap_or_else(|_| default.to_owned());
    Url::parse(&value).with_context(|| format!("environment variable {name} is not a valid URL"))
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use secrecy::ExposeSecret;
    use uuid::Uuid;

    use super::{load_envelope_key_file, load_envelope_key_from};

    fn test_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("zeus-config-{name}-{}", Uuid::now_v7()))
    }

    #[test]
    fn envelope_key_source_is_exclusive() {
        let error =
            load_envelope_key_from(Some("00".repeat(32)), Some(std::path::Path::new("ignored")))
                .expect_err("two key sources must be rejected");
        assert!(error.to_string().contains("either"));
        assert!(
            load_envelope_key_from(None, None)
                .expect("an absent key is valid for migration commands")
                .is_none()
        );
    }

    #[test]
    fn protected_regular_envelope_key_file_loads() {
        let path = test_path("valid");
        fs::write(&path, format!("{}\n", "ab".repeat(32))).expect("test key writes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("test permissions set");
        }
        let key = load_envelope_key_file(&path).expect("protected key loads");
        assert_eq!(key.expose_secret(), &"ab".repeat(32));
        fs::remove_file(path).expect("test key removes");
    }

    #[cfg(unix)]
    #[test]
    fn wide_permissions_and_symlinks_are_rejected() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let target = test_path("target");
        let link = test_path("link");
        fs::write(&target, "ab".repeat(32)).expect("test key writes");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644))
            .expect("test permissions set");
        assert!(load_envelope_key_file(&target).is_err());
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
            .expect("test permissions set");
        symlink(&target, &link).expect("test symlink creates");
        assert!(load_envelope_key_file(&link).is_err());
        fs::remove_file(link).expect("test link removes");
        fs::remove_file(target).expect("test key removes");
    }

    #[test]
    fn empty_oversized_and_missing_key_files_are_rejected() {
        let empty = test_path("empty");
        let oversized = test_path("oversized");
        let missing = test_path("missing");
        fs::write(&empty, "").expect("empty test file writes");
        fs::write(&oversized, vec![b'a'; 4_097]).expect("oversized test file writes");
        assert!(load_envelope_key_file(&empty).is_err());
        assert!(load_envelope_key_file(&oversized).is_err());
        assert!(load_envelope_key_file(&missing).is_err());
        fs::remove_file(empty).expect("empty test file removes");
        fs::remove_file(oversized).expect("oversized test file removes");
    }
}
