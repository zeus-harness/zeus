use std::{future::IntoFuture, io, net::SocketAddr, sync::Arc, time::Duration};

#[cfg(unix)]
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::{Component, Path, PathBuf},
};
#[cfg(unix)]
use zeroize::Zeroizing;

use llm::{
    LocalFallbackProvider, OpenAiCompatibleProvider, ReplyProvider, ResolvedSecret, SecretRef,
    SecretResolveError, SecretResolveFuture, SecretResolver,
};
use runtime::{DemoStore, SqliteOperationLimits, SqlitePhysicalLimits, StorageLimits};
use tenancy::BootstrapToken;
use tokio::sync::oneshot;
use zeus_api::IngressPolicy;

const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const BOOTSTRAP_TOKEN_TTL: chrono::Duration = chrono::Duration::minutes(15);
#[cfg(unix)]
const SECRET_FILE_MAX_BYTES: usize = 16 * 1024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_path =
        std::env::var("ZEUS_DATABASE_PATH").unwrap_or_else(|_| ".zeus/zeus.db".into());
    let profile =
        std::env::var("ZEUS_DEMO_PROFILE").unwrap_or_else(|_| "production-guarded".into());
    let storage_limits = configured_storage_limits()?;
    let physical_limits = configured_sqlite_physical_limits()?;
    let operation_limits = configured_sqlite_operation_limits()?;
    let ingress = configured_ingress_policy()?;
    let ingress_mode = ingress.mode_name();
    let public_origin = ingress.public_origin().unwrap_or("direct peer").to_owned();
    let reply_provider = configured_reply_provider().await?;
    let reply_provider_id = reply_provider.metadata().provider_id.clone();
    let store = match profile.as_str() {
        "production-guarded" => {
            DemoStore::open_with_limits_and_physical_and_operations(
                &database_path,
                storage_limits.clone(),
                physical_limits.clone(),
                operation_limits.clone(),
            )
            .await?
        }
        "local-development" => {
            let marker_root = std::env::var("ZEUS_LOCAL_MARKER_ROOT")
                .unwrap_or_else(|_| ".zeus/local-markers".into());
            match optional_environment("ZEUS_LOCAL_WORKSPACE_ROOT")? {
                Some(workspace_root) => {
                    DemoStore::open_local_with_workspace_and_limits_and_physical_and_operations(
                        &database_path,
                        marker_root,
                        workspace_root,
                        storage_limits,
                        physical_limits,
                        operation_limits,
                    )
                    .await?
                }
                None => {
                    DemoStore::open_local_with_limits_and_physical_and_operations(
                        &database_path,
                        marker_root,
                        storage_limits,
                        physical_limits,
                        operation_limits,
                    )
                    .await?
                }
            }
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "unsupported ZEUS_DEMO_PROFILE {other}; expected production-guarded or local-development"
                ),
            )
            .into());
        }
    };
    let address = std::env::var("ZEUS_LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8081".into())
        .parse::<SocketAddr>()?;
    if !store.has_users().await? {
        let bootstrap = BootstrapToken::generate()?;
        let expires_at = (chrono::Utc::now() + BOOTSTRAP_TOKEN_TTL)
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        store
            .replace_bootstrap_token(&bootstrap.digest().to_persistence(), &expires_at)
            .await?;
        eprintln!(
            "Zeus owner setup token (expires {expires_at}): {}",
            bootstrap.expose_secret()
        );
    }
    let listener = tokio::net::TcpListener::bind(address).await?;
    let app =
        zeus_api::authenticated_app_with_provider_and_ingress(store, ingress, reply_provider)?;

    println!(
        "zeus-api listening on http://{address} with profile {profile}, ingress {ingress_mode} ({public_origin}), reply provider {reply_provider_id}, and SQLite at {database_path}"
    );
    serve_with_bounded_shutdown(listener, app).await?;
    Ok(())
}

fn configured_storage_limits() -> Result<StorageLimits, io::Error> {
    let defaults = StorageLimits::default();
    let sessions_global =
        environment_capacity("ZEUS_MAX_SESSIONS_GLOBAL", defaults.sessions_global)?;
    let open_turns_global =
        environment_capacity("ZEUS_MAX_OPEN_TURNS_GLOBAL", defaults.open_turns_global)?;
    let active_reply_jobs_global = environment_capacity(
        "ZEUS_MAX_ACTIVE_REPLY_JOBS_GLOBAL",
        defaults.active_reply_jobs_global,
    )?;
    let active_dispatch_jobs_global = environment_capacity(
        "ZEUS_MAX_ACTIVE_DISPATCH_JOBS_GLOBAL",
        defaults.active_dispatch_jobs_global,
    )?;
    StorageLimits {
        sessions_per_actor: environment_capacity_with_legacy_alias(
            "ZEUS_MAX_SESSIONS_PER_ACTOR",
            "ZEUS_MAX_SESSIONS_PER_SCOPE",
            defaults.sessions_per_actor,
        )?,
        sessions_per_account: environment_capacity(
            "ZEUS_MAX_SESSIONS_PER_ACCOUNT",
            sessions_global,
        )?,
        sessions_global,
        open_turns_per_actor: environment_capacity_with_legacy_alias(
            "ZEUS_MAX_OPEN_TURNS_PER_ACTOR",
            "ZEUS_MAX_OPEN_TURNS_PER_SCOPE",
            defaults.open_turns_per_actor,
        )?,
        open_turns_per_account: environment_capacity(
            "ZEUS_MAX_OPEN_TURNS_PER_ACCOUNT",
            open_turns_global,
        )?,
        open_turns_global,
        active_reply_jobs_per_actor: environment_capacity_with_legacy_alias(
            "ZEUS_MAX_ACTIVE_REPLY_JOBS_PER_ACTOR",
            "ZEUS_MAX_ACTIVE_REPLY_JOBS_PER_SCOPE",
            defaults.active_reply_jobs_per_actor,
        )?,
        active_reply_jobs_per_account: environment_capacity(
            "ZEUS_MAX_ACTIVE_REPLY_JOBS_PER_ACCOUNT",
            active_reply_jobs_global,
        )?,
        active_reply_jobs_global,
        active_dispatch_jobs_per_actor: environment_capacity_with_legacy_alias(
            "ZEUS_MAX_ACTIVE_DISPATCH_JOBS_PER_ACTOR",
            "ZEUS_MAX_ACTIVE_DISPATCH_JOBS_PER_SCOPE",
            defaults.active_dispatch_jobs_per_actor,
        )?,
        active_dispatch_jobs_per_account: environment_capacity(
            "ZEUS_MAX_ACTIVE_DISPATCH_JOBS_PER_ACCOUNT",
            active_dispatch_jobs_global,
        )?,
        active_dispatch_jobs_global,
        auth_sessions_per_user: environment_capacity(
            "ZEUS_MAX_AUTH_SESSIONS_PER_USER",
            defaults.auth_sessions_per_user,
        )?,
        auth_sessions_global: environment_capacity(
            "ZEUS_MAX_AUTH_SESSIONS_GLOBAL",
            defaults.auth_sessions_global,
        )?,
        session_event_slots_per_session: environment_capacity(
            "ZEUS_MAX_SESSION_EVENT_SLOTS_PER_SESSION",
            defaults.session_event_slots_per_session,
        )?,
        run_event_slots_per_run: environment_capacity(
            "ZEUS_MAX_RUN_EVENT_SLOTS_PER_RUN",
            defaults.run_event_slots_per_run,
        )?,
        session_event_payload_bytes_per_session: environment_capacity(
            "ZEUS_MAX_SESSION_EVENT_PAYLOAD_BYTES_PER_SESSION",
            defaults.session_event_payload_bytes_per_session,
        )?,
        run_event_payload_bytes_per_run: environment_capacity(
            "ZEUS_MAX_RUN_EVENT_PAYLOAD_BYTES_PER_RUN",
            defaults.run_event_payload_bytes_per_run,
        )?,
        event_payload_bytes_global: environment_capacity(
            "ZEUS_MAX_EVENT_PAYLOAD_BYTES_GLOBAL",
            defaults.event_payload_bytes_global,
        )?,
        bootstrap_audit_rows: environment_capacity(
            "ZEUS_MAX_BOOTSTRAP_AUDIT_ROWS",
            defaults.bootstrap_audit_rows,
        )?,
        account_audit_detail_rows: environment_capacity(
            "ZEUS_MAX_ACCOUNT_AUDIT_DETAIL_ROWS",
            defaults.account_audit_detail_rows,
        )?,
        account_audit_rows_per_account: environment_capacity(
            "ZEUS_MAX_ACCOUNT_AUDIT_ROWS_PER_ACCOUNT",
            defaults.account_audit_rows_per_account,
        )?,
        account_audit_rows_global: environment_capacity(
            "ZEUS_MAX_ACCOUNT_AUDIT_ROWS_GLOBAL",
            defaults.account_audit_rows_global,
        )?,
        account_audit_progress_rows_per_account: environment_capacity(
            "ZEUS_RESERVED_ACCOUNT_AUDIT_PROGRESS_ROWS_PER_ACCOUNT",
            defaults.account_audit_progress_rows_per_account,
        )?,
        account_audit_progress_rows_global: environment_capacity(
            "ZEUS_RESERVED_ACCOUNT_AUDIT_PROGRESS_ROWS_GLOBAL",
            defaults.account_audit_progress_rows_global,
        )?,
        account_audit_compaction_batch: environment_capacity(
            "ZEUS_ACCOUNT_AUDIT_COMPACTION_BATCH",
            defaults.account_audit_compaction_batch,
        )?,
    }
    .validated()
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

fn environment_capacity(name: &str, default: usize) -> Result<usize, io::Error> {
    parse_environment_capacity(name, std::env::var(name), default)
}

fn environment_capacity_with_legacy_alias(
    name: &str,
    legacy_name: &str,
    default: usize,
) -> Result<usize, io::Error> {
    parse_environment_capacity_with_legacy_alias(
        name,
        std::env::var(name),
        legacy_name,
        std::env::var(legacy_name),
        default,
    )
}

fn configured_sqlite_physical_limits() -> Result<SqlitePhysicalLimits, io::Error> {
    let defaults = SqlitePhysicalLimits::default();
    SqlitePhysicalLimits {
        max_main_bytes: environment_u64("ZEUS_SQLITE_MAX_MAIN_BYTES", defaults.max_main_bytes)?,
        wal_target_bytes: environment_u64(
            "ZEUS_SQLITE_WAL_TARGET_BYTES",
            defaults.wal_target_bytes,
        )?,
        min_free_bytes: environment_u64("ZEUS_SQLITE_MIN_FREE_BYTES", defaults.min_free_bytes)?,
        admission_reserve_bytes: environment_u64(
            "ZEUS_SQLITE_ADMISSION_RESERVE_BYTES",
            defaults.admission_reserve_bytes,
        )?,
    }
    .validated()
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

fn configured_sqlite_operation_limits() -> Result<SqliteOperationLimits, io::Error> {
    let defaults = SqliteOperationLimits::default();
    SqliteOperationLimits {
        max_concurrent_operations: environment_capacity(
            "ZEUS_SQLITE_MAX_CONCURRENT_OPERATIONS",
            defaults.max_concurrent_operations,
        )?,
        reserved_progress_operations: environment_capacity(
            "ZEUS_SQLITE_RESERVED_PROGRESS_OPERATIONS",
            defaults.reserved_progress_operations,
        )?,
        acquire_timeout_ms: environment_u64(
            "ZEUS_SQLITE_OPERATION_ACQUIRE_TIMEOUT_MS",
            defaults.acquire_timeout_ms,
        )?,
    }
    .validated()
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

fn environment_u64(name: &str, default: u64) -> Result<u64, io::Error> {
    parse_environment_u64(name, std::env::var(name), default)
}

fn parse_environment_u64(
    name: &str,
    value: Result<String, std::env::VarError>,
    default: u64,
) -> Result<u64, io::Error> {
    match value {
        Ok(value) if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => {
            value.parse::<u64>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("{name} is too large"))
            })
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be an unsigned decimal integer without whitespace"),
        )),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be valid UTF-8"),
        )),
    }
}

fn parse_environment_capacity(
    name: &str,
    value: Result<String, std::env::VarError>,
    default: usize,
) -> Result<usize, io::Error> {
    match value {
        Ok(value) if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => {
            value.parse::<usize>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("{name} is too large"))
            })
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be an unsigned decimal integer without whitespace"),
        )),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be valid UTF-8"),
        )),
    }
}

fn parse_environment_capacity_with_legacy_alias(
    name: &str,
    value: Result<String, std::env::VarError>,
    legacy_name: &str,
    legacy_value: Result<String, std::env::VarError>,
    default: usize,
) -> Result<usize, io::Error> {
    match (&value, &legacy_value) {
        (Err(std::env::VarError::NotPresent), Err(std::env::VarError::NotPresent)) => Ok(default),
        (Err(std::env::VarError::NotPresent), _) => {
            parse_environment_capacity(legacy_name, legacy_value, default)
        }
        (_, Err(std::env::VarError::NotPresent)) => {
            parse_environment_capacity(name, value, default)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} and its legacy alias {legacy_name} cannot both be set"),
        )),
    }
}

async fn configured_reply_provider() -> Result<Arc<dyn ReplyProvider>, io::Error> {
    let settings = parse_reply_provider_settings(
        optional_environment("ZEUS_LLM_ENDPOINT")?,
        optional_environment("ZEUS_LLM_MODEL")?,
        optional_environment("ZEUS_LLM_API_KEY")?,
        optional_environment("ZEUS_LLM_API_KEY_REF")?,
    )?;
    match settings {
        ReplyProviderSettings::LocalFallback => Ok(Arc::new(LocalFallbackProvider::new())),
        ReplyProviderSettings::Inline {
            endpoint,
            model,
            api_key,
        } => Ok(Arc::new(
            OpenAiCompatibleProvider::new(endpoint, model, api_key)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
        )),
        ReplyProviderSettings::SecretRef {
            endpoint,
            model,
            secret_ref,
        } => {
            let resolver = configured_secret_resolver(secret_ref.clone())?;
            let provider = OpenAiCompatibleProvider::with_secret_resolver(
                endpoint, model, secret_ref, resolver,
            )
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            provider
                .validate_secret_source()
                .await
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            Ok(Arc::new(provider))
        }
    }
}

fn configured_secret_resolver(reference: SecretRef) -> Result<Arc<dyn SecretResolver>, io::Error> {
    if reference.as_str().starts_with("env:") {
        return Ok(Arc::new(EnvironmentSecretResolver::new(reference)?));
    }
    if reference.as_str().starts_with("file:") {
        #[cfg(unix)]
        {
            return Ok(Arc::new(FileSecretResolver::new(reference)?));
        }
        #[cfg(not(unix))]
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "file SecretRef requires a Unix no-follow file boundary",
            ));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "ZEUS_LLM_API_KEY_REF must use env:VARIABLE or file:/absolute/path syntax",
    ))
}

enum ReplyProviderSettings {
    LocalFallback,
    Inline {
        endpoint: String,
        model: String,
        api_key: String,
    },
    SecretRef {
        endpoint: String,
        model: String,
        secret_ref: SecretRef,
    },
}

fn parse_reply_provider_settings(
    endpoint: Option<String>,
    model: Option<String>,
    api_key: Option<String>,
    api_key_ref: Option<String>,
) -> Result<ReplyProviderSettings, io::Error> {
    match (endpoint, model, api_key, api_key_ref) {
        (None, None, None, None) => Ok(ReplyProviderSettings::LocalFallback),
        (Some(endpoint), Some(model), Some(api_key), None) => Ok(ReplyProviderSettings::Inline {
            endpoint,
            model,
            api_key,
        }),
        (Some(endpoint), Some(model), None, Some(secret_ref)) => {
            let secret_ref = SecretRef::parse(secret_ref)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            Ok(ReplyProviderSettings::SecretRef {
                endpoint,
                model,
                secret_ref,
            })
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ZEUS_LLM_ENDPOINT and ZEUS_LLM_MODEL require exactly one of ZEUS_LLM_API_KEY or ZEUS_LLM_API_KEY_REF",
        )),
    }
}

struct EnvironmentSecretResolver {
    reference: SecretRef,
    variable: String,
}

impl EnvironmentSecretResolver {
    fn new(reference: SecretRef) -> Result<Self, io::Error> {
        let variable = reference.as_str().strip_prefix("env:").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "ZEUS_LLM_API_KEY_REF must use env:VARIABLE syntax",
            )
        })?;
        let mut bytes = variable.bytes();
        if !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
            || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ZEUS_LLM_API_KEY_REF environment variable name is invalid",
            ));
        }
        let variable = variable.to_owned();
        Ok(Self {
            reference,
            variable,
        })
    }
}

impl SecretResolver for EnvironmentSecretResolver {
    fn resolve<'a>(&'a self, reference: &'a SecretRef) -> SecretResolveFuture<'a> {
        let result = if reference != &self.reference {
            Err(SecretResolveError::Unavailable)
        } else {
            std::env::var(&self.variable)
                .map(ResolvedSecret::new)
                .map_err(|_| SecretResolveError::Unavailable)
        };
        Box::pin(async move { result })
    }
}

#[cfg(unix)]
struct FileSecretResolver {
    reference: SecretRef,
    path: PathBuf,
}

#[cfg(unix)]
impl FileSecretResolver {
    fn new(reference: SecretRef) -> Result<Self, io::Error> {
        let raw_path = reference
            .as_str()
            .strip_prefix("file:")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid file SecretRef"))?;
        let path = PathBuf::from(raw_path);
        let mut components = path.components();
        let invalid_segment = raw_path
            .split('/')
            .skip(1)
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."));
        if !matches!(components.next(), Some(Component::RootDir))
            || components
                .clone()
                .any(|component| !matches!(component, Component::Normal(_)))
            || components.next().is_none()
            || invalid_segment
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "file SecretRef must use a normalized absolute path without traversal",
            ));
        }
        Ok(Self { reference, path })
    }
}

#[cfg(unix)]
impl SecretResolver for FileSecretResolver {
    fn resolve<'a>(&'a self, reference: &'a SecretRef) -> SecretResolveFuture<'a> {
        let authorized = reference == &self.reference;
        let path = self.path.clone();
        Box::pin(async move {
            if !authorized {
                return Err(SecretResolveError::Unavailable);
            }
            tokio::task::spawn_blocking(move || read_secret_file(&path))
                .await
                .unwrap_or(Err(SecretResolveError::Unavailable))
        })
    }
}

#[cfg(unix)]
fn read_secret_file(path: &Path) -> Result<ResolvedSecret, SecretResolveError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| SecretResolveError::Unavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| SecretResolveError::Unavailable)?;
    if !metadata.is_file() || metadata.len() > SECRET_FILE_MAX_BYTES as u64 {
        return Err(SecretResolveError::Unavailable);
    }

    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(metadata.len()).unwrap_or(SECRET_FILE_MAX_BYTES),
    ));
    file.take(SECRET_FILE_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SecretResolveError::Unavailable)?;
    if bytes.len() > SECRET_FILE_MAX_BYTES {
        return Err(SecretResolveError::Unavailable);
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    let value = String::from_utf8(std::mem::take(&mut *bytes))
        .map_err(|_| SecretResolveError::Unavailable)?;
    Ok(ResolvedSecret::new(value))
}

fn optional_environment(name: &str) -> Result<Option<String>, io::Error> {
    match std::env::var(name) {
        Ok(value) if value.trim().is_empty() => Ok(None),
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be valid UTF-8"),
        )),
    }
}

async fn serve_with_bounded_shutdown(
    listener: tokio::net::TcpListener,
    app: axum::Router,
) -> io::Result<()> {
    let (shutdown_started_tx, shutdown_started_rx) = oneshot::channel();
    let shutdown = async move {
        shutdown_signal().await;
        let _ = shutdown_started_tx.send(());
    };
    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .into_future();
    tokio::pin!(server);

    tokio::select! {
        result = &mut server => result,
        started = shutdown_started_rx => {
            if started.is_err() {
                return Err(io::Error::other(
                    "shutdown signal task ended before reporting a signal",
                ));
            }
            match tokio::time::timeout(GRACEFUL_SHUTDOWN_TIMEOUT, &mut server).await {
                Ok(result) => result,
                Err(_) => {
                    eprintln!(
                        "zeus-api graceful shutdown exceeded {} seconds; forcing remaining connections closed",
                        GRACEFUL_SHUTDOWN_TIMEOUT.as_secs()
                    );
                    // Dropping the server future returns control to `main`.
                    // The Tokio runtime then cancels its connection tasks,
                    // dropping every Router/DemoStore clone and SQLite lock.
                    Ok(())
                }
            }
        }
    }
}

fn parse_environment_flag(
    name: &str,
    value: Result<String, std::env::VarError>,
    default: bool,
) -> Result<bool, io::Error> {
    let value = match value {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name} must be valid UTF-8"),
            ));
        }
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be a boolean flag"),
        )),
    }
}

fn configured_ingress_policy() -> Result<IngressPolicy, io::Error> {
    parse_ingress_policy(
        std::env::var("ZEUS_PUBLIC_ORIGIN"),
        std::env::var("ZEUS_TRUSTED_PROXY_CIDRS"),
        std::env::var("ZEUS_COOKIE_SECURE"),
    )
}

fn parse_ingress_policy(
    public_origin: Result<String, std::env::VarError>,
    trusted_proxies: Result<String, std::env::VarError>,
    cookie_secure: Result<String, std::env::VarError>,
) -> Result<IngressPolicy, io::Error> {
    let public_origin = exact_optional_environment("ZEUS_PUBLIC_ORIGIN", public_origin)?;
    let trusted_proxies = exact_optional_environment("ZEUS_TRUSTED_PROXY_CIDRS", trusted_proxies)?;
    match (public_origin, trusted_proxies) {
        (None, None) => Ok(IngressPolicy::direct(parse_environment_flag(
            "ZEUS_COOKIE_SECURE",
            cookie_secure,
            false,
        )?)),
        (Some(public_origin), Some(trusted_proxies)) => {
            if !parse_environment_flag("ZEUS_COOKIE_SECURE", cookie_secure, true)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ZEUS_COOKIE_SECURE cannot be disabled when trusted ingress is configured",
                ));
            }
            IngressPolicy::trusted_proxy_csv(public_origin, &trusted_proxies)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ZEUS_PUBLIC_ORIGIN and ZEUS_TRUSTED_PROXY_CIDRS must be set together",
        )),
    }
}

fn exact_optional_environment(
    name: &str,
    value: Result<String, std::env::VarError>,
) -> Result<Option<String>, io::Error> {
    match value {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be valid UTF-8"),
        )),
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EnvironmentSecretResolver, ReplyProviderSettings, parse_environment_capacity,
        parse_environment_capacity_with_legacy_alias, parse_environment_flag,
        parse_environment_u64, parse_ingress_policy, parse_reply_provider_settings,
    };
    #[cfg(unix)]
    use super::{FileSecretResolver, SECRET_FILE_MAX_BYTES};
    use llm::{SecretRef, SecretResolveError, SecretResolver};
    use std::{env::VarError, io};

    #[test]
    fn capacity_environment_uses_the_default_only_when_unset() {
        assert_eq!(
            parse_environment_capacity("ZEUS_TEST_LIMIT", Err(VarError::NotPresent), 17).unwrap(),
            17
        );
        assert_eq!(
            parse_environment_capacity("ZEUS_TEST_LIMIT", Ok("23".into()), 17).unwrap(),
            23
        );
    }

    #[test]
    fn trusted_ingress_environment_is_paired_and_forces_secure_cookies() {
        let direct = parse_ingress_policy(
            Err(VarError::NotPresent),
            Err(VarError::NotPresent),
            Err(VarError::NotPresent),
        )
        .unwrap();
        assert_eq!(direct.mode_name(), "direct");
        assert!(!direct.cookie_secure());

        let trusted = parse_ingress_policy(
            Ok("https://zeus.example.com".into()),
            Ok("127.0.0.1/32".into()),
            Err(VarError::NotPresent),
        )
        .unwrap();
        assert_eq!(trusted.mode_name(), "trusted-proxy");
        assert!(trusted.cookie_secure());

        assert!(
            parse_ingress_policy(
                Ok("https://zeus.example.com".into()),
                Err(VarError::NotPresent),
                Err(VarError::NotPresent),
            )
            .is_err()
        );
        assert!(
            parse_ingress_policy(
                Ok("https://zeus.example.com".into()),
                Ok("127.0.0.1/32".into()),
                Ok("false".into()),
            )
            .is_err()
        );
        assert!(
            parse_ingress_policy(
                Err(VarError::NotPresent),
                Ok("127.0.0.1/32".into()),
                Err(VarError::NotPresent),
            )
            .is_err()
        );
        assert!(
            parse_ingress_policy(
                Ok(String::new()),
                Ok(String::new()),
                Err(VarError::NotPresent),
            )
            .is_err()
        );
        assert!(
            parse_ingress_policy(
                Err(VarError::NotUnicode("invalid".into())),
                Ok("127.0.0.1/32".into()),
                Err(VarError::NotPresent),
            )
            .is_err()
        );
    }

    #[test]
    fn boolean_environment_rejects_non_utf8_and_ambiguous_values() {
        assert!(parse_environment_flag("FLAG", Ok(" yes ".into()), false).unwrap());
        assert!(!parse_environment_flag("FLAG", Ok("OFF".into()), true).unwrap());
        assert!(parse_environment_flag("FLAG", Ok("maybe".into()), false).is_err());
        assert!(
            parse_environment_flag("FLAG", Err(VarError::NotUnicode("invalid".into())), false,)
                .is_err()
        );
    }

    #[test]
    fn reply_provider_settings_require_one_complete_credential_source() {
        assert!(matches!(
            parse_reply_provider_settings(None, None, None, None).unwrap(),
            ReplyProviderSettings::LocalFallback
        ));
        assert!(matches!(
            parse_reply_provider_settings(
                Some("https://provider.example/v1/chat/completions".into()),
                Some("model-a".into()),
                Some("inline-key".into()),
                None,
            )
            .unwrap(),
            ReplyProviderSettings::Inline { .. }
        ));
        let referenced = parse_reply_provider_settings(
            Some("https://provider.example/v1/chat/completions".into()),
            Some("model-a".into()),
            None,
            Some("env:ZEUS_RUNTIME_KEY".into()),
        )
        .unwrap();
        assert!(matches!(
            referenced,
            ReplyProviderSettings::SecretRef { ref secret_ref, .. }
                if secret_ref.as_str() == "env:ZEUS_RUNTIME_KEY"
        ));

        for settings in [
            (Some("endpoint".into()), None, None, None),
            (
                Some("endpoint".into()),
                Some("model".into()),
                Some("key".into()),
                Some("env:KEY".into()),
            ),
            (
                Some("endpoint".into()),
                Some("model".into()),
                None,
                Some("invalid ref".into()),
            ),
        ] {
            assert!(
                parse_reply_provider_settings(settings.0, settings.1, settings.2, settings.3)
                    .is_err()
            );
        }
    }

    #[test]
    fn environment_secret_resolver_accepts_only_exact_environment_references() {
        let valid = SecretRef::parse("env:ZEUS_RUNTIME_KEY_2").unwrap();
        let resolver = EnvironmentSecretResolver::new(valid.clone()).unwrap();
        assert_eq!(resolver.reference, valid);
        assert_eq!(resolver.variable, "ZEUS_RUNTIME_KEY_2");

        for invalid in ["vault:key", "env:", "env:2KEY", "env:KEY-NAME"] {
            let reference = SecretRef::parse(invalid).unwrap();
            assert!(EnvironmentSecretResolver::new(reference).is_err());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn file_secret_resolver_rotates_bounded_regular_files_without_following_symlinks() {
        use std::{
            fs,
            os::unix::fs::symlink,
            time::{SystemTime, UNIX_EPOCH},
        };

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("zeus-secret-ref-{}-{nonce}", std::process::id()));
        let link = path.with_extension("link");
        fs::write(&path, b"first-api-key\n").unwrap();
        let reference = SecretRef::parse(format!("file:{}", path.display())).unwrap();
        let resolver = FileSecretResolver::new(reference.clone()).unwrap();

        let first = resolver.resolve(&reference).await.unwrap();
        assert_eq!(first.expose_secret(), "first-api-key");
        drop(first);
        fs::write(&path, b"rotated-api-key\r\n").unwrap();
        let rotated = resolver.resolve(&reference).await.unwrap();
        assert_eq!(rotated.expose_secret(), "rotated-api-key");
        drop(rotated);

        symlink(&path, &link).unwrap();
        let link_ref = SecretRef::parse(format!("file:{}", link.display())).unwrap();
        let link_resolver = FileSecretResolver::new(link_ref.clone()).unwrap();
        assert_eq!(
            link_resolver.resolve(&link_ref).await.unwrap_err(),
            SecretResolveError::Unavailable
        );

        fs::write(&path, vec![b'x'; SECRET_FILE_MAX_BYTES + 1]).unwrap();
        assert_eq!(
            resolver.resolve(&reference).await.unwrap_err(),
            SecretResolveError::Unavailable
        );
        let _ = fs::remove_file(&link);
        let _ = fs::remove_file(&path);

        for invalid in [
            "file:relative",
            "file:/",
            "file:/tmp/../key",
            "file:/tmp/./key",
            "file:/tmp//key",
        ] {
            assert!(
                FileSecretResolver::new(SecretRef::parse(invalid).unwrap()).is_err(),
                "{invalid} must fail closed"
            );
        }
    }

    #[test]
    fn capacity_environment_rejects_empty_whitespace_signed_and_non_ascii_values() {
        for value in ["", " 1", "1 ", "+1", "-1", "1_000", "１２"] {
            let error =
                parse_environment_capacity("ZEUS_TEST_LIMIT", Ok(value.into()), 17).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn capacity_environment_rejects_overflow_and_non_utf8_values() {
        let overflow = format!("{}0", usize::MAX);
        assert_eq!(
            parse_environment_capacity("ZEUS_TEST_LIMIT", Ok(overflow), 17)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            parse_environment_capacity(
                "ZEUS_TEST_LIMIT",
                Err(VarError::NotUnicode("invalid".into())),
                17,
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn capacity_environment_accepts_one_legacy_alias_and_rejects_ambiguous_configuration() {
        assert_eq!(
            parse_environment_capacity_with_legacy_alias(
                "ZEUS_TEST_PER_ACTOR",
                Err(VarError::NotPresent),
                "ZEUS_TEST_PER_SCOPE",
                Ok("23".into()),
                17,
            )
            .unwrap(),
            23
        );
        assert_eq!(
            parse_environment_capacity_with_legacy_alias(
                "ZEUS_TEST_PER_ACTOR",
                Ok("19".into()),
                "ZEUS_TEST_PER_SCOPE",
                Err(VarError::NotPresent),
                17,
            )
            .unwrap(),
            19
        );
        assert_eq!(
            parse_environment_capacity_with_legacy_alias(
                "ZEUS_TEST_PER_ACTOR",
                Err(VarError::NotPresent),
                "ZEUS_TEST_PER_SCOPE",
                Err(VarError::NotPresent),
                17,
            )
            .unwrap(),
            17
        );
        let error = parse_environment_capacity_with_legacy_alias(
            "ZEUS_TEST_PER_ACTOR",
            Ok("19".into()),
            "ZEUS_TEST_PER_SCOPE",
            Ok("19".into()),
            17,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("cannot both be set"));
    }

    #[test]
    fn account_capacity_defaults_to_the_configured_global_value() {
        let global = parse_environment_capacity("ZEUS_TEST_GLOBAL", Ok("73".into()), 41).unwrap();
        assert_eq!(
            parse_environment_capacity("ZEUS_TEST_PER_ACCOUNT", Err(VarError::NotPresent), global,)
                .unwrap(),
            73
        );
        assert_eq!(
            parse_environment_capacity("ZEUS_TEST_PER_ACCOUNT", Ok("29".into()), global).unwrap(),
            29
        );
    }

    #[test]
    fn physical_byte_environment_uses_strict_unsigned_u64_values() {
        assert_eq!(
            parse_environment_u64("ZEUS_TEST_BYTES", Err(VarError::NotPresent), 19).unwrap(),
            19
        );
        assert_eq!(
            parse_environment_u64("ZEUS_TEST_BYTES", Ok(u64::MAX.to_string()), 19).unwrap(),
            u64::MAX
        );
        for value in ["", " 1", "1 ", "+1", "-1", "1_000", "１２"] {
            assert_eq!(
                parse_environment_u64("ZEUS_TEST_BYTES", Ok(value.into()), 19)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert_eq!(
            parse_environment_u64("ZEUS_TEST_BYTES", Ok(format!("{}0", u64::MAX)), 19,)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
