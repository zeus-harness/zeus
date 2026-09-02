pub mod collaboration;
pub mod control_plane;
pub mod execution;
pub mod execution_api;
pub mod http;
pub mod identity;
pub mod platform;

pub use collaboration::{experiences, work_items};
pub use control_plane::{agents, integrations, organization, platform_tenants};
pub use execution::{model, runtime, supervisor};
pub use identity::{
    auth, federated_identity, maintenance as identity_maintenance, native_auth, native_identity,
    oidc, oidc_provider, organization_identity,
};
pub use platform::{api_support, config, crypto, database, error, idempotency, telemetry};

use std::{str::FromStr, sync::Arc, time::Duration};

use secrecy::SecretString;
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use url::Url;
use zeus_identity::{PasswordExecutor, PasswordPolicy};

use crate::{
    config::AppConfig,
    crypto::{EnvelopeCipher, LocalEnvelopeCipher},
    supervisor::SupervisorMetrics,
};

pub struct PlatformServices {
    pub database: PgPool,
    pub envelope: Arc<dyn EnvelopeCipher>,
    pub metrics: Arc<SupervisorMetrics>,
    pub version: &'static str,
}

#[allow(clippy::struct_excessive_bools)] // Deployment and protocol switches are independent.
pub struct IdentityRuntimeConfig {
    pub public_url: Url,
    pub session_idle_ttl: Duration,
    pub session_absolute_ttl: Duration,
    pub oidc_state_ttl: Duration,
    pub cookie_secure: bool,
    pub allow_private_oidc_issuers: bool,
    pub bootstrap_token: Option<SecretString>,
    pub identity_hash_key: SecretString,
    pub trust_proxy_headers: bool,
    pub password_executor: PasswordExecutor,
}

pub struct ExternalClients {
    pub http: reqwest::Client,
}

pub struct ExecutionRuntimeConfig {
    pub allow_private_model_endpoints: bool,
}

#[derive(Clone)]
pub struct AppState {
    pub platform: Arc<PlatformServices>,
    pub identity: Arc<IdentityRuntimeConfig>,
    pub external: Arc<ExternalClients>,
    pub execution: Arc<ExecutionRuntimeConfig>,
}

pub const HTTP_DATABASE_ROLE: &str = "zeus_http";
pub const RUNTIME_DATABASE_ROLE: &str = "zeus_runtime";

/// Opens a `PostgreSQL` pool with the service's bounded defaults.
///
/// # Errors
///
/// Returns an error when `SQLx` cannot connect to `PostgreSQL`.
pub async fn connect_pool(database_url: &str, max_connections: u32) -> anyhow::Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(max_connections)
        .min_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .idle_timeout(std::time::Duration::from_mins(5))
        .connect(database_url)
        .await
        .map_err(Into::into)
}

/// Opens a bounded pool whose `PostgreSQL` startup role is fixed for the whole connection.
///
/// The login user in `database_url` must be allowed to assume `role`. Keeping the
/// role in the startup packet prevents a request from running before RLS is active.
///
/// # Errors
///
/// Returns an error when the role name is unsafe or `SQLx` cannot connect.
pub async fn connect_pool_as_role(
    database_url: &str,
    max_connections: u32,
    role: &str,
) -> anyhow::Result<PgPool> {
    if role.is_empty()
        || !role
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        anyhow::bail!("database role contains unsupported characters");
    }
    let options =
        PgConnectOptions::from_str(database_url)?.options([("role", role), ("row_security", "on")]);
    PgPoolOptions::new()
        .max_connections(max_connections)
        .min_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .idle_timeout(std::time::Duration::from_mins(5))
        .connect_with(options)
        .await
        .map_err(Into::into)
}

/// Applies every pending forward `SQLx` migration.
///
/// # Errors
///
/// Returns an error when a migration cannot be read or applied.
pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::migrate!("../../db/migrations").run(pool).await?;
    Ok(())
}

/// Creates shared HTTP application state.
///
/// # Errors
///
/// Returns an error when the HTTP database pool cannot be opened.
pub async fn build_state(config: &AppConfig) -> anyhow::Result<AppState> {
    let database = connect_pool_as_role(
        &config.database_url,
        config.http_database_connections,
        HTTP_DATABASE_ROLE,
    )
    .await?;
    let envelope_key = config.envelope_key.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "ZEUS_ENVELOPE_KEY_FILE, ZEUS_ENVELOPE_KEY, or ZEUS_LOCAL_MASTER_KEY is required"
        )
    })?;
    let envelope = LocalEnvelopeCipher::from_encoded(config.envelope_key_id.clone(), envelope_key)?;
    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .user_agent(concat!("zeus-api/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let password_policy = config
        .weak_passwords
        .clone()
        .map_or_else(PasswordPolicy::default, PasswordPolicy::with_weak_passwords);
    let password_executor = PasswordExecutor::new(4, 32, password_policy)?;
    let identity_hash_key = config
        .identity_hash_key
        .clone()
        .ok_or_else(|| anyhow::anyhow!("ZEUS_IDENTITY_HASH_KEY or an envelope key is required"))?;
    Ok(AppState {
        platform: Arc::new(PlatformServices {
            database,
            envelope: Arc::new(envelope),
            metrics: Arc::new(SupervisorMetrics::default()),
            version: env!("CARGO_PKG_VERSION"),
        }),
        identity: Arc::new(IdentityRuntimeConfig {
            public_url: config.public_url.clone(),
            session_idle_ttl: config.session_idle_ttl,
            session_absolute_ttl: config.session_absolute_ttl,
            oidc_state_ttl: config.oidc_state_ttl,
            cookie_secure: config.cookie_secure,
            allow_private_oidc_issuers: config.allow_private_oidc_issuers,
            bootstrap_token: config.bootstrap_token.clone(),
            identity_hash_key,
            trust_proxy_headers: config.trust_proxy_headers,
            password_executor,
        }),
        external: Arc::new(ExternalClients { http: http_client }),
        execution: Arc::new(ExecutionRuntimeConfig {
            allow_private_model_endpoints: config.allow_private_model_endpoints,
        }),
    })
}
