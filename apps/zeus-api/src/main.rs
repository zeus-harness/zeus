use std::{future::IntoFuture, io, net::SocketAddr, sync::Arc, time::Duration};

use llm::{LocalFallbackProvider, OpenAiCompatibleProvider, ReplyProvider};
use runtime::{DemoStore, SqliteOperationLimits, SqlitePhysicalLimits, StorageLimits};
use tenancy::BootstrapToken;
use tokio::sync::oneshot;

const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const BOOTSTRAP_TOKEN_TTL: chrono::Duration = chrono::Duration::minutes(15);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_path =
        std::env::var("ZEUS_DATABASE_PATH").unwrap_or_else(|_| ".zeus/zeus.db".into());
    let profile =
        std::env::var("ZEUS_DEMO_PROFILE").unwrap_or_else(|_| "production-guarded".into());
    let storage_limits = configured_storage_limits()?;
    let physical_limits = configured_sqlite_physical_limits()?;
    let operation_limits = configured_sqlite_operation_limits()?;
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
            DemoStore::open_local_with_limits_and_physical_and_operations(
                &database_path,
                marker_root,
                storage_limits,
                physical_limits,
                operation_limits,
            )
            .await?
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
    let cookie_secure = environment_flag("ZEUS_COOKIE_SECURE", false)?;
    let reply_provider = configured_reply_provider()?;
    let reply_provider_id = reply_provider.metadata().provider_id.clone();
    let listener = tokio::net::TcpListener::bind(address).await?;
    let app = zeus_api::authenticated_app_with_provider(store, cookie_secure, reply_provider)?;

    println!(
        "zeus-api listening on http://{address} with profile {profile}, reply provider {reply_provider_id}, and SQLite at {database_path}"
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

fn configured_reply_provider() -> Result<Arc<dyn ReplyProvider>, io::Error> {
    let endpoint = optional_environment("ZEUS_LLM_ENDPOINT")?;
    let model = optional_environment("ZEUS_LLM_MODEL")?;
    let api_key = optional_environment("ZEUS_LLM_API_KEY")?;
    match (endpoint, model, api_key) {
        (None, None, None) => Ok(Arc::new(LocalFallbackProvider::new())),
        (Some(endpoint), Some(model), Some(api_key)) => Ok(Arc::new(
            OpenAiCompatibleProvider::new(endpoint, model, api_key)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
        )),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ZEUS_LLM_ENDPOINT, ZEUS_LLM_MODEL, and ZEUS_LLM_API_KEY must be set together",
        )),
    }
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

fn environment_flag(name: &str, default: bool) -> Result<bool, io::Error> {
    let Ok(value) = std::env::var(name) else {
        return Ok(default);
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
        parse_environment_capacity, parse_environment_capacity_with_legacy_alias,
        parse_environment_u64,
    };
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
