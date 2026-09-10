use axum::{Json, extract::State};
use utoipa::OpenApi;

use crate::{
    AppState,
    error::{ApiError, ProblemDetails},
};

use super::openapi::{ApiDoc, FeatureStatus, HealthResponse, MetaResponse};

#[utoipa::path(get, path = "/health/live", tag = "operations", responses(
    (status = 200, description = "Process is alive", body = HealthResponse)
))]
pub(super) async fn live() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

#[utoipa::path(get, path = "/health/ready", tag = "operations", responses(
    (status = 200, description = "Database is ready", body = HealthResponse),
    (status = 503, description = "Database is unavailable", body = ProblemDetails, content_type = "application/problem+json")
))]
pub(super) async fn ready(State(state): State<AppState>) -> Result<Json<HealthResponse>, ApiError> {
    sqlx::query_scalar::<_, i32>("select 1")
        .fetch_one(&state.platform.database)
        .await
        .map_err(|_| ApiError::DatabaseUnavailable)?;
    Ok(Json(HealthResponse { status: "ready" }))
}

#[utoipa::path(get, path = "/api/v1/meta", tag = "platform", responses(
    (status = 200, description = "Zeus API metadata", body = MetaResponse)
))]
pub(super) async fn meta(State(state): State<AppState>) -> Json<MetaResponse> {
    Json(MetaResponse {
        product: "Zeus",
        version: state.platform.version,
        api_version: "v1",
        queue_backend: "postgresql",
        worker_process: false,
        features: vec![
            FeatureStatus {
                name: "schema",
                status: "implemented",
            },
            FeatureStatus {
                name: "execution_supervisor",
                status: "implemented",
            },
            FeatureStatus {
                name: "oidc",
                status: "implemented",
            },
            FeatureStatus {
                name: "control_plane",
                status: "implemented",
            },
        ],
    })
}

pub(super) async fn openapi() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}

pub(super) async fn metrics(State(state): State<AppState>) -> String {
    format!(
        concat!(
            "# HELP zeus_runs_claimed_total Runs claimed by this process.\n",
            "# TYPE zeus_runs_claimed_total counter\n",
            "zeus_runs_claimed_total {}\n",
            "# HELP zeus_runs_finished_total Runs finished by this process.\n",
            "# TYPE zeus_runs_finished_total counter\n",
            "zeus_runs_finished_total {}\n",
            "# HELP zeus_runs_failed_total Runs failed by this process.\n",
            "# TYPE zeus_runs_failed_total counter\n",
            "zeus_runs_failed_total {}\n",
            "# HELP zeus_active_runs Runs currently executing in this process.\n",
            "# TYPE zeus_active_runs gauge\n",
            "zeus_active_runs {}\n",
            "# HELP zeus_queue_depth Runs ready to be claimed.\n",
            "# TYPE zeus_queue_depth gauge\n",
            "zeus_queue_depth {}\n",
            "# HELP zeus_http_requests_total HTTP requests completed by this process.\n",
            "# TYPE zeus_http_requests_total counter\n",
            "zeus_http_requests_total {}\n",
            "# HELP zeus_http_inflight_requests HTTP requests currently handled by this process.\n",
            "# TYPE zeus_http_inflight_requests gauge\n",
            "zeus_http_inflight_requests {}\n",
            "# HELP zeus_identity_password_failures_total Native password login failures observed by this process.\n",
            "# TYPE zeus_identity_password_failures_total counter\n",
            "zeus_identity_password_failures_total {}\n",
            "# HELP zeus_identity_mfa_failures_total MFA verification failures observed by this process.\n",
            "# TYPE zeus_identity_mfa_failures_total counter\n",
            "zeus_identity_mfa_failures_total {}\n",
            "# HELP zeus_identity_throttled_total Identity requests rejected by a bounded queue or persistent throttle.\n",
            "# TYPE zeus_identity_throttled_total counter\n",
            "zeus_identity_throttled_total {}\n",
            "# HELP zeus_identity_email_backlog Identity emails waiting or currently leased.\n",
            "# TYPE zeus_identity_email_backlog gauge\n",
            "zeus_identity_email_backlog {}\n",
            "# HELP zeus_identity_email_oldest_pending_age_seconds Age of the oldest pending identity email.\n",
            "# TYPE zeus_identity_email_oldest_pending_age_seconds gauge\n",
            "zeus_identity_email_oldest_pending_age_seconds {}\n",
            "# HELP zeus_identity_operational_metrics_up Whether the last PostgreSQL identity observation succeeded.\n",
            "# TYPE zeus_identity_operational_metrics_up gauge\n",
            "zeus_identity_operational_metrics_up {}\n",
            "# HELP zeus_federated_provider_errors_total Upstream federated OIDC protocol errors observed by this process.\n",
            "# TYPE zeus_federated_provider_errors_total counter\n",
            "zeus_federated_provider_errors_total {}\n",
            "# HELP zeus_oidc_refresh_replay_total Replayed Zeus refresh tokens observed by this process.\n",
            "# TYPE zeus_oidc_refresh_replay_total counter\n",
            "zeus_oidc_refresh_replay_total {}\n",
            "# HELP zeus_oidc_signing_key_present Whether a current signing key exists.\n",
            "# TYPE zeus_oidc_signing_key_present gauge\n",
            "zeus_oidc_signing_key_present {}\n",
            "# HELP zeus_oidc_signing_key_age_seconds Age of the current Zeus OIDC signing key.\n",
            "# TYPE zeus_oidc_signing_key_age_seconds gauge\n",
            "zeus_oidc_signing_key_age_seconds {}\n"
        ),
        state.platform.metrics.claimed(),
        state.platform.metrics.finished(),
        state.platform.metrics.failed(),
        state.platform.metrics.active(),
        state.platform.metrics.queue_depth(),
        state.platform.metrics.http_requests(),
        state.platform.metrics.http_inflight(),
        state.platform.metrics.identity_password_failures(),
        state.platform.metrics.identity_mfa_failures(),
        state.platform.metrics.identity_throttled(),
        state.platform.metrics.identity_email_backlog(),
        state
            .platform
            .metrics
            .identity_email_oldest_pending_age_seconds(),
        state.platform.metrics.identity_operational_metrics_up(),
        state.platform.metrics.federated_provider_errors(),
        state.platform.metrics.oidc_refresh_replays(),
        state.platform.metrics.oidc_signing_key_present(),
        state.platform.metrics.oidc_signing_key_age_seconds(),
    )
}
