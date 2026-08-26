use std::{future::IntoFuture, io, net::SocketAddr, sync::Arc, time::Duration};

use llm::{LocalFallbackProvider, OpenAiCompatibleProvider, ReplyProvider};
use runtime::DemoStore;
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
    let store = match profile.as_str() {
        "production-guarded" => DemoStore::open(&database_path).await?,
        "local-development" => {
            let marker_root = std::env::var("ZEUS_LOCAL_MARKER_ROOT")
                .unwrap_or_else(|_| ".zeus/local-markers".into());
            DemoStore::open_local(&database_path, marker_root).await?
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
