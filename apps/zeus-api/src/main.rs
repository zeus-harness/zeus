use std::{future::IntoFuture, io, net::SocketAddr, time::Duration};

use runtime::DemoStore;
use tokio::sync::oneshot;

const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

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
    let listener = tokio::net::TcpListener::bind(address).await?;

    println!(
        "zeus-api listening on http://{address} with profile {profile} and SQLite at {database_path}"
    );
    serve_with_bounded_shutdown(listener, store).await?;
    Ok(())
}

async fn serve_with_bounded_shutdown(
    listener: tokio::net::TcpListener,
    store: DemoStore,
) -> io::Result<()> {
    let (shutdown_started_tx, shutdown_started_rx) = oneshot::channel();
    let shutdown = async move {
        shutdown_signal().await;
        let _ = shutdown_started_tx.send(());
    };
    let server = axum::serve(listener, zeus_api::app(store))
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
