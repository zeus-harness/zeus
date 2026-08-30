use std::{io::Write as _, sync::Arc};

use clap::{Parser, Subcommand};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use zeus_api::{
    RUNTIME_DATABASE_ROLE, build_state,
    config::AppConfig,
    connect_pool, connect_pool_as_role, http,
    identity_maintenance::{IdentityMaintenance, run_oidc_protocol_maintenance},
    migrate,
    runtime::DurableRunExecutor,
    supervisor::ExecutionSupervisor,
    telemetry,
};

#[derive(Debug, Parser)]
#[command(
    name = "zeus-api",
    version,
    about = "Zeus enterprise Harness Agent API"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve,
    Db {
        #[command(subcommand)]
        command: DatabaseCommand,
    },
    Openapi,
}

#[derive(Debug, Subcommand)]
enum DatabaseCommand {
    Migrate,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let telemetry = telemetry::init()?;
    let result = match Cli::parse().command {
        Command::Serve => serve().await,
        Command::Db {
            command: DatabaseCommand::Migrate,
        } => migrate_command().await,
        Command::Openapi => {
            use utoipa::OpenApi;
            let yaml = http::ApiDoc::openapi().to_yaml()?;
            std::io::stdout().write_all(yaml.as_bytes())?;
            Ok(())
        }
    };
    if let Err(error) = telemetry.shutdown() {
        warn!(%error, "telemetry shutdown failed");
    }
    result
}

async fn serve() -> anyhow::Result<()> {
    let config = AppConfig::from_env()?;
    let state = build_state(&config).await?;
    let shutdown = CancellationToken::new();

    let supervisor_task = if config.supervisor_enabled {
        let runtime_pool = connect_pool_as_role(
            &config.runtime_database_url,
            config.runtime_database_connections,
            RUNTIME_DATABASE_ROLE,
        )
        .await?;
        let executor = DurableRunExecutor::new(
            runtime_pool.clone(),
            config.node_id.clone(),
            Arc::clone(&state.envelope),
        );
        let supervisor = ExecutionSupervisor::new(
            runtime_pool,
            Arc::new(executor),
            config.node_id.clone(),
            config.lease_duration,
            config.poll_interval,
            config.run_concurrency,
            shutdown.child_token(),
            Arc::clone(&state.metrics),
        );
        Some(tokio::spawn(supervisor.run()))
    } else {
        warn!("execution supervisor is disabled");
        None
    };

    let identity_maintenance_task = if config.identity_maintenance_enabled {
        let smtp_url = config
            .smtp_url
            .as_ref()
            .expect("validated identity maintenance SMTP URL");
        let mail_from = config
            .mail_from
            .as_deref()
            .expect("validated identity maintenance sender");
        let maintenance = IdentityMaintenance::new(
            state.database.clone(),
            Arc::clone(&state.envelope),
            smtp_url,
            mail_from,
            config.node_id.clone(),
            config.identity_email_poll_interval,
            config.identity_email_lease_duration,
            shutdown.child_token(),
        )?;
        Some(tokio::spawn(maintenance.run()))
    } else {
        warn!("identity maintenance is disabled; queued email will remain pending");
        None
    };
    let oidc_maintenance_task = tokio::spawn(run_oidc_protocol_maintenance(
        state.database.clone(),
        Arc::clone(&state.envelope),
        Arc::clone(&state.metrics),
        shutdown.child_token(),
    ));

    let listener = tokio::net::TcpListener::bind(config.bind_address).await?;
    info!(address = %config.bind_address, "zeus api listening");
    axum::serve(
        listener,
        http::router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal(shutdown))
    .await?;

    if let Some(task) = supervisor_task {
        task.await?;
    }
    if let Some(task) = identity_maintenance_task {
        task.await?;
    }
    oidc_maintenance_task.await?;
    Ok(())
}

async fn migrate_command() -> anyhow::Result<()> {
    let config = AppConfig::from_env()?;
    let pool = connect_pool(&config.database_url, 1).await?;
    migrate(&pool).await?;
    info!("database migrations applied");
    Ok(())
}

async fn shutdown_signal(shutdown: CancellationToken) {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            warn!(%error, "failed to install ctrl-c handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => warn!(%error, "failed to install terminate handler"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    shutdown.cancel();
}
