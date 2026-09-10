use std::sync::Arc;

use axum::{
    Router,
    extract::{DefaultBodyLimit, Request, State},
    middleware::{self, Next},
    response::Response as AxumResponse,
    routing::get,
};
use http::{HeaderMap, HeaderName, HeaderValue};
use tower_http::{
    catch_panic::CatchPanicLayer,
    compression::CompressionLayer,
    trace::{DefaultOnResponse, TraceLayer},
};
use tracing::Level;
use uuid::Uuid;

use crate::error::REQUEST_ID;
use crate::{
    AppState, auth, collaboration, control_plane, execution, identity,
    supervisor::SupervisorMetrics,
};

use super::operations::{live, meta, metrics, openapi, ready};

pub fn router(state: AppState) -> Router {
    let request_metrics = Arc::clone(&state.platform.metrics);
    let browser_security_state = state.clone();
    Router::new()
        .merge(identity::routes())
        .merge(control_plane::routes())
        .merge(collaboration::routes())
        .merge(execution::routes())
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/metrics", get(metrics))
        .route("/api/v1/meta", get(meta))
        .route("/api/v1/openapi.json", get(openapi))
        .with_state(state)
        .layer(middleware::from_fn_with_state(
            browser_security_state,
            auth::enforce_browser_write_security,
        ))
        .layer(middleware::from_fn_with_state(
            request_metrics,
            track_http_request,
        ))
        .layer(DefaultBodyLimit::max(8 * 1024 * 1024))
        .layer(CompressionLayer::new())
        .layer(CatchPanicLayer::new())
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request| {
                    let request_id = request
                        .headers()
                        .get("x-request-id")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("missing");
                    tracing::span!(
                        Level::INFO,
                        "http.request",
                        method = %request.method(),
                        path = request.uri().path(),
                        request_id = %request_id,
                    )
                })
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .layer(middleware::from_fn(request_context))
}

async fn request_context(mut request: Request, next: Next) -> AxumResponse {
    let request_id = request_id_from_headers(request.headers()).unwrap_or_else(Uuid::now_v7);
    let header_value = HeaderValue::from_str(&request_id.to_string())
        .expect("a UUID is always a valid header value");
    request.headers_mut().insert(
        HeaderName::from_static("x-request-id"),
        header_value.clone(),
    );
    let mut response = REQUEST_ID
        .scope(request_id, async move { next.run(request).await })
        .await;
    response
        .headers_mut()
        .insert(HeaderName::from_static("x-request-id"), header_value);
    response
}

pub(super) fn request_id_from_headers(headers: &HeaderMap) -> Option<Uuid> {
    let request_id = headers
        .get("x-request-id")?
        .to_str()
        .ok()
        .and_then(|value| Uuid::parse_str(value).ok())?;
    (request_id.get_version_num() == 7).then_some(request_id)
}

async fn track_http_request(
    State(metrics): State<Arc<SupervisorMetrics>>,
    request: Request,
    next: Next,
) -> AxumResponse {
    if !should_track_http_path(request.uri().path()) {
        return next.run(request).await;
    }
    let _request = metrics.begin_http_request();
    next.run(request).await
}

pub(super) fn should_track_http_path(path: &str) -> bool {
    !matches!(path, "/health/live" | "/health/ready" | "/metrics")
}
