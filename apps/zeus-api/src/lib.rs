//! HTTP composition for the durable Zeus Alpha slice.

use std::{convert::Infallible, time::Duration};

use axum::{
    Json, Router,
    extract::{
        Path, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, StatusCode, header},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use protocol::{
    CreateSessionRequest, CreateSessionResponse, FlushSessionRequest, FlushSessionResponse,
    HealthResponse, ProblemDetails, ResumeSessionRequest, ResumeSessionResponse, ReviewRequest,
    ReviewResponse, RunDetail, SessionDetail, SessionEvent, SessionSummary, StartTurnRequest,
    StartTurnResponse,
};
use runtime::{DemoStore, PublishedEvent, StoreError};
use serde::Deserialize;
use tokio::{
    sync::broadcast,
    time::{Instant, MissedTickBehavior},
};

const DURABLE_LEDGER_POLL_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Clone)]
struct ApiState {
    store: DemoStore,
    durable_ledger_poll_interval: Duration,
    broadcast_hints_enabled: bool,
}

#[derive(Debug, Default, Deserialize)]
struct EventsQuery {
    after: Option<u64>,
}

pub fn app(store: DemoStore) -> Router {
    app_with_event_feed_options(store, DURABLE_LEDGER_POLL_INTERVAL, true)
}

fn app_with_event_feed_options(
    store: DemoStore,
    durable_ledger_poll_interval: Duration,
    broadcast_hints_enabled: bool,
) -> Router {
    assert!(
        !durable_ledger_poll_interval.is_zero(),
        "the durable ledger poll interval must be positive"
    );
    Router::new()
        .route("/health/live", get(liveness))
        .route("/health/ready", get(readiness))
        .route("/api/v1/overview", get(overview))
        .route("/api/v1/sessions", get(list_sessions).post(create_session))
        .route("/api/v1/sessions/{id}", get(session_detail))
        .route("/api/v1/sessions/{id}/resume", post(resume_session))
        .route("/api/v1/sessions/{id}/turns", post(start_turn))
        .route(
            "/api/v1/sessions/{id}/turns/{turn_id}/flush",
            post(flush_turn),
        )
        .route("/api/v1/sessions/{id}/events", get(session_events))
        .route("/api/v1/runs/{id}", get(run_detail))
        .route(
            "/api/v1/runs/{id}/approvals/{approval_id}/decision",
            post(review_decision),
        )
        .route("/api/v1/runs/{id}/events", get(run_events))
        .fallback(not_found)
        .with_state(ApiState {
            store,
            durable_ledger_poll_interval,
            broadcast_hints_enabled,
        })
}

async fn liveness() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn readiness(State(state): State<ApiState>) -> Result<Json<HealthResponse>, ApiError> {
    state.store.readiness().await?;
    Ok(Json(HealthResponse { status: "ready" }))
}

async fn overview(
    State(state): State<ApiState>,
) -> Result<Json<protocol::OverviewResponse>, ApiError> {
    Ok(Json(state.store.overview().await?))
}

async fn list_sessions(
    State(state): State<ApiState>,
) -> Result<Json<Vec<SessionSummary>>, ApiError> {
    Ok(Json(state.store.list_sessions().await?))
}

async fn create_session(
    State(state): State<ApiState>,
    headers: HeaderMap,
    payload: Result<Json<CreateSessionRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<CreateSessionResponse>), ApiError> {
    let idempotency_key = required_idempotency_key(&headers)?;
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    Ok((
        StatusCode::CREATED,
        Json(
            state
                .store
                .create_session(request, &idempotency_key)
                .await?,
        ),
    ))
}

async fn session_detail(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<SessionDetail>, ApiError> {
    Ok(Json(state.store.get_session(&id).await?))
}

async fn resume_session(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<ResumeSessionRequest>, JsonRejection>,
) -> Result<Json<ResumeSessionResponse>, ApiError> {
    let idempotency_key = required_idempotency_key(&headers)?;
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    Ok(Json(
        state
            .store
            .resume_session(&id, request, &idempotency_key)
            .await?,
    ))
}

async fn start_turn(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<StartTurnRequest>, JsonRejection>,
) -> Result<Json<StartTurnResponse>, ApiError> {
    let idempotency_key = required_idempotency_key(&headers)?;
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    Ok(Json(
        state
            .store
            .start_turn(&id, request, &idempotency_key)
            .await?,
    ))
}

async fn flush_turn(
    State(state): State<ApiState>,
    Path((id, turn_id)): Path<(String, String)>,
    headers: HeaderMap,
    payload: Result<Json<FlushSessionRequest>, JsonRejection>,
) -> Result<Json<FlushSessionResponse>, ApiError> {
    let idempotency_key = required_idempotency_key(&headers)?;
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    if turn_id != request.turn_id {
        return Err(ApiError::bad_request(
            "turn_id_mismatch",
            "The turn ID in the path must match the request body",
        ));
    }
    Ok(Json(
        state
            .store
            .flush_turn(&id, request, &idempotency_key)
            .await?,
    ))
}

async fn run_detail(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<RunDetail>, ApiError> {
    Ok(Json(state.store.run_detail(&id).await?))
}

async fn review_decision(
    State(state): State<ApiState>,
    Path((id, approval_id)): Path<(String, String)>,
    headers: HeaderMap,
    payload: Result<Json<ReviewRequest>, JsonRejection>,
) -> Result<Json<ReviewResponse>, ApiError> {
    let header_key = required_idempotency_key(&headers)?;
    let Json(request) = payload.map_err(ApiError::invalid_json)?;

    if let Some(body_key) = &request.idempotency_key
        && &header_key != body_key
    {
        return Err(ApiError::bad_request(
            "idempotency_key_mismatch",
            "Idempotency-Key header and request body must match",
        ));
    }

    Ok(Json(
        state
            .store
            .review(&id, &approval_id, request, &header_key)
            .await?,
    ))
}

fn required_idempotency_key(headers: &HeaderMap) -> Result<String, ApiError> {
    let value = headers.get("idempotency-key").ok_or_else(|| {
        ApiError::bad_request(
            "missing_idempotency_key",
            "Idempotency-Key header is required for POST requests",
        )
    })?;
    let key = value.to_str().map_err(|_| {
        ApiError::bad_request(
            "invalid_idempotency_key",
            "Idempotency-Key must be valid UTF-8",
        )
    })?;
    let key = key.trim();
    if key.is_empty() {
        return Err(ApiError::bad_request(
            "invalid_idempotency_key",
            "Idempotency-Key cannot be empty",
        ));
    }
    Ok(key.to_owned())
}

async fn session_events(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    query: Result<Query<EventsQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(ApiError::invalid_query)?;
    let after = event_cursor(&headers, query)?;
    let mut feed = state.store.session_event_feed(&id, after).await?;
    let store = state.store.clone();
    let durable_ledger_poll_interval = state.durable_ledger_poll_interval;
    let broadcast_hints_enabled = state.broadcast_hints_enabled;
    let session_id = id;

    let stream = async_stream::stream! {
        let mut cursor = after;
        for event in feed.replay {
            cursor = cursor.max(event.sequence);
            yield Ok::<Event, Infallible>(session_sse_event(&event));
        }

        yield Ok(Event::default().comment("stream-open"));

        let mut durable_poll = tokio::time::interval_at(
            Instant::now() + durable_ledger_poll_interval,
            durable_ledger_poll_interval,
        );
        durable_poll.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                received = feed.receiver.recv(), if broadcast_hints_enabled => match received {
                    Ok(published) => {
                        if published.session_id == session_id && published.event.sequence > cursor {
                            // A post-commit broadcast is only a wake hint: two
                            // commits can publish out of order. Always advance
                            // from the ordered durable ledger so a later hint
                            // cannot make an earlier event permanently vanish.
                            match store.session_events_after(&session_id, cursor).await {
                                Ok(events) => {
                                    for event in events {
                                        if event.sequence > cursor {
                                            cursor = event.sequence;
                                            yield Ok(session_sse_event(&event));
                                        }
                                    }
                                }
                                Err(error) => {
                                    eprintln!(
                                        "zeus SSE durable replay failed for a session: {error:?}"
                                    );
                                    break;
                                }
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        match store.session_events_after(&session_id, cursor).await {
                            Ok(events) => {
                                for event in events {
                                    if event.sequence > cursor {
                                        cursor = event.sequence;
                                        yield Ok(session_sse_event(&event));
                                    }
                                }
                            }
                            Err(error) => {
                                eprintln!(
                                    "zeus SSE durable replay failed for a session: {error:?}"
                                );
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                },
                _ = durable_poll.tick() => {
                    match store.session_events_after(&session_id, cursor).await {
                        Ok(events) => {
                            for event in events {
                                if event.sequence > cursor {
                                    cursor = event.sequence;
                                    yield Ok(session_sse_event(&event));
                                }
                            }
                        }
                        Err(error) => {
                            eprintln!("zeus SSE durable poll failed for a session: {error:?}");
                            break;
                        }
                    }
                }
            }
        }
    };

    Ok(Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keep-alive"),
        )
        .into_response())
}

async fn run_events(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    query: Result<Query<EventsQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(ApiError::invalid_query)?;
    let after = event_cursor(&headers, query)?;
    let mut feed = state.store.event_feed(&id, after).await?;
    let store = state.store.clone();
    let durable_ledger_poll_interval = state.durable_ledger_poll_interval;
    let broadcast_hints_enabled = state.broadcast_hints_enabled;
    let run_id = id;

    let stream = async_stream::stream! {
        let mut cursor = after;
        for event in feed.replay {
            cursor = cursor.max(event.sequence);
            yield Ok::<Event, Infallible>(sse_event(&event));
        }

        // Flush a harmless SSE comment even when the client is already at the
        // ledger head. Some development proxies buffer response headers until
        // the first body chunk, which otherwise leaves the UI looking as if it
        // is reconnecting until the first keep-alive interval.
        yield Ok(Event::default().comment("stream-open"));

        // Broadcast is a same-process latency hint only. Poll the durable
        // ledger at a bounded interval so commits without a local hint are
        // still observed. Delay missed ticks to avoid catch-up bursts.
        let mut durable_poll = tokio::time::interval_at(
            Instant::now() + durable_ledger_poll_interval,
            durable_ledger_poll_interval,
        );
        durable_poll.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                received = feed.receiver.recv(), if broadcast_hints_enabled => match received {
                    Ok(published) => {
                        // Broadcast is only a wake hint. Separate commits can
                        // publish out of order, so advancing directly to the
                        // hinted sequence could permanently skip an earlier
                        // durable event.
                        match run_events_for_hint(&store, &run_id, cursor, &published).await {
                            Ok(events) => {
                                for event in events {
                                    if event.sequence > cursor {
                                        cursor = event.sequence;
                                        yield Ok(sse_event(&event));
                                    }
                                }
                            }
                            Err(error) => {
                                eprintln!(
                                    "zeus SSE durable replay failed for run {run_id}: {error:?}"
                                );
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // Recover a slow client from the append-only ledger
                        // instead of silently skipping events.
                        match store.events_after(&run_id, cursor).await {
                            Ok(events) => {
                                for event in events {
                                    if event.sequence > cursor {
                                        cursor = event.sequence;
                                        yield Ok(sse_event(&event));
                                    }
                                }
                            }
                            Err(error) => {
                                eprintln!(
                                    "zeus SSE durable replay failed for run {run_id}: {error:?}"
                                );
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                },
                _ = durable_poll.tick() => {
                    match store.events_after(&run_id, cursor).await {
                        Ok(events) => {
                            for event in events {
                                if event.sequence > cursor {
                                    cursor = event.sequence;
                                    yield Ok(sse_event(&event));
                                }
                            }
                        }
                        Err(error) => {
                            eprintln!(
                                "zeus SSE durable poll failed for run {run_id}: {error:?}"
                            );
                            break;
                        }
                    }
                }
            }
        }
    };

    Ok(Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keep-alive"),
        )
        .into_response())
}

async fn run_events_for_hint(
    store: &DemoStore,
    run_id: &str,
    cursor: u64,
    published: &PublishedEvent,
) -> Result<Vec<protocol::RunEvent>, StoreError> {
    if published.run_id != run_id || published.event.sequence <= cursor {
        return Ok(Vec::new());
    }
    store.events_after(run_id, cursor).await
}

fn sse_event(event: &protocol::RunEvent) -> Event {
    Event::default()
        .event("run.event")
        .id(event.sequence.to_string())
        .data(serde_json::to_string(event).expect("RunEvent must serialize"))
}

fn session_sse_event(event: &SessionEvent) -> Event {
    Event::default()
        .event("session.event")
        .id(event.sequence.to_string())
        .data(serde_json::to_string(event).expect("SessionEvent must serialize"))
}

fn event_cursor(headers: &HeaderMap, query: EventsQuery) -> Result<u64, ApiError> {
    let header_cursor = headers
        .get("last-event-id")
        .map(|value| {
            value
                .to_str()
                .map_err(|_| ())
                .and_then(|value| value.parse::<u64>().map_err(|_| ()))
                .map_err(|_| {
                    ApiError::bad_request(
                        "invalid_event_cursor",
                        "Last-Event-ID must be an unsigned integer sequence",
                    )
                })
        })
        .transpose()?;
    // EventSource keeps the original query string when reconnecting but sends
    // its newer cursor in Last-Event-ID. Prefer that header so reconnects do
    // not repeatedly replay from the page's initial sequence.
    Ok(header_cursor.or(query.after).unwrap_or(0))
}

async fn not_found() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        "route_not_found",
        "Route not found",
        "The requested API route does not exist",
    )
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    problem: Box<ProblemDetails>,
}

impl ApiError {
    fn new(
        status: StatusCode,
        code: impl Into<String>,
        title: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            status,
            problem: Box::new(ProblemDetails::new(status.as_u16(), code, title, detail)),
        }
    }

    fn bad_request(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, "Invalid request", detail)
    }

    fn invalid_json(rejection: JsonRejection) -> Self {
        Self::bad_request("invalid_json", rejection.body_text())
    }

    fn invalid_query(rejection: QueryRejection) -> Self {
        Self::bad_request("invalid_query", rejection.body_text())
    }

    fn internal_runtime_error(error: &StoreError) -> Self {
        eprintln!("zeus request failed an internal runtime invariant: {error:?}");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "runtime_unavailable",
            "Runtime is unavailable",
            "The runtime could not process the request safely",
        )
    }

    fn unavailable(error: &StoreError) -> Self {
        eprintln!("zeus request failed because the runtime is unavailable: {error:?}");
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "runtime_unavailable",
            "Runtime is unavailable",
            "The runtime is temporarily unavailable",
        )
    }
}

impl From<StoreError> for ApiError {
    fn from(error: StoreError) -> Self {
        match &error {
            StoreError::RunNotFound(id) => Self::new(
                StatusCode::NOT_FOUND,
                "run_not_found",
                "Run not found",
                format!("Run `{id}` does not exist"),
            ),
            StoreError::SessionNotFound(id) => Self::new(
                StatusCode::NOT_FOUND,
                "session_not_found",
                "Session not found",
                format!("Session `{id}` does not exist"),
            ),
            StoreError::SessionTurnNotFound(id) => Self::new(
                StatusCode::NOT_FOUND,
                "session_turn_not_found",
                "Session turn not found",
                format!("Session turn `{id}` does not exist"),
            ),
            StoreError::SessionAlreadyExists(id) => Self::new(
                StatusCode::CONFLICT,
                "session_already_exists",
                "Session already exists",
                format!("Session `{id}` already exists"),
            ),
            StoreError::RunAlreadyAttached { run_id, session_id } => Self::new(
                StatusCode::CONFLICT,
                "run_already_attached",
                "Run already attached",
                format!("Run `{run_id}` already belongs to session `{session_id}`"),
            ),
            StoreError::InvalidSessionRequest(reason) => {
                Self::bad_request("invalid_session_request", reason.clone())
            }
            StoreError::EmptyIdempotencyKey => {
                Self::bad_request("invalid_idempotency_key", "Idempotency-Key cannot be empty")
            }
            StoreError::IdempotencyConflict => Self::new(
                StatusCode::CONFLICT,
                "idempotency_conflict",
                "Idempotency conflict",
                "The Idempotency-Key was already used with different command input",
            ),
            StoreError::InvalidSessionTransition(_) => Self::new(
                StatusCode::CONFLICT,
                "invalid_session_transition",
                "Session command conflicts with current state",
                "The session state does not allow this command",
            ),
            StoreError::ApprovalNotPending {
                run_id,
                approval_id,
            } => Self::new(
                StatusCode::CONFLICT,
                "approval_not_pending",
                "Approval is not pending",
                format!("Approval {approval_id} is not pending for run {run_id}"),
            ),
            StoreError::PolicyDenied(reason) => Self::new(
                StatusCode::FORBIDDEN,
                "policy_denied",
                "Policy denied the call",
                reason.clone(),
            ),
            StoreError::PolicyChanged(reason) => Self::new(
                StatusCode::CONFLICT,
                "policy_changed",
                "Approval is stale",
                reason.clone(),
            ),
            StoreError::ToolCallNotFound
            | StoreError::ExecutionInvariant(_)
            | StoreError::Kernel(_)
            | StoreError::SequenceOverflow => Self::internal_runtime_error(&error),
            StoreError::ConcurrentModification => Self::new(
                StatusCode::CONFLICT,
                "concurrent_modification",
                "Concurrent modification",
                "The resource changed while the command was being committed; retry the request",
            ),
            StoreError::PolicyBuild(_)
            | StoreError::ConnectorConfig(_)
            | StoreError::Registry(_)
            | StoreError::Storage(_) => Self::unavailable(&error),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            [(header::CONTENT_TYPE, "application/problem+json")],
            Json(*self.problem),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, header},
    };
    use http_body_util::BodyExt;
    use protocol::{
        CreateSessionResponse, DEMO_RUN_ID, FlushSessionResponse, OverviewResponse, ReviewDecision,
        ReviewRequest, ReviewResponse, SessionDetail, SessionStatus, SessionSummary,
        StartTurnResponse,
    };
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn health_and_overview_are_available() {
        let app = test_app().await;

        let health = app
            .clone()
            .oneshot(Request::get("/health/ready").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::get("/api/v1/overview")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let overview: OverviewResponse = response_json(response).await;
        assert_eq!(overview.run.id, DEMO_RUN_ID);
        assert_eq!(overview.run.sequence, 8);
        assert_eq!(overview.recent_events.len(), 8);
    }

    #[tokio::test]
    async fn review_endpoint_is_idempotent() {
        let app = test_app().await;
        let request = || {
            Request::post(format!(
                "/api/v1/runs/{DEMO_RUN_ID}/approvals/APR-901/decision"
            ))
            .header(header::CONTENT_TYPE, "application/json")
            .header("idempotency-key", "api-review-1")
            .body(Body::from(r#"{"decision":"approve","note":"ship it"}"#))
            .unwrap()
        };

        let first = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let first: ReviewResponse = response_json(first).await;
        let second = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(second.status(), StatusCode::OK);
        let second: ReviewResponse = response_json(second).await;

        assert!(!first.replayed);
        assert!(second.replayed);
        assert_eq!(first.event.sequence, 9);
        assert_eq!(first.event, second.event);

        let detail = app
            .oneshot(
                Request::get(format!("/api/v1/runs/{DEMO_RUN_ID}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let detail: RunDetail = response_json(detail).await;
        assert!(detail.events.len() >= 9);
        assert_eq!(
            detail
                .events
                .iter()
                .filter(|event| matches!(
                    event.data,
                    Some(protocol::RunEventData::ApprovalDecided { .. })
                ))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn session_create_list_and_get_are_idempotent() {
        let app = test_app().await;
        let request = || {
            Request::post("/api/v1/sessions")
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "api-create-session-1")
                .body(Body::from(
                    r#"{"id":"session-api","title":"API conversation"}"#,
                ))
                .unwrap()
        };

        let first = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(first.status(), StatusCode::CREATED);
        let first: CreateSessionResponse = response_json(first).await;
        assert!(!first.replayed);
        assert_eq!(first.session.sequence, 1);

        let second = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(second.status(), StatusCode::CREATED);
        let second: CreateSessionResponse = response_json(second).await;
        assert!(second.replayed);
        assert_eq!(second.event, first.event);

        let sessions = app
            .clone()
            .oneshot(
                Request::get("/api/v1/sessions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(sessions.status(), StatusCode::OK);
        let sessions: Vec<SessionSummary> = response_json(sessions).await;
        assert!(sessions.iter().any(|session| session.id == "session-api"));

        let detail = app
            .oneshot(
                Request::get("/api/v1/sessions/session-api")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(detail.status(), StatusCode::OK);
        let detail: SessionDetail = response_json(detail).await;
        assert_eq!(detail.session, first.session);
        assert_eq!(detail.events, vec![first.event]);
    }

    #[tokio::test]
    async fn session_create_rejects_missing_and_conflicting_idempotency_keys() {
        let app = test_app().await;
        let missing = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"id":"session-missing-key","title":"Missing key"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
        let problem: ProblemDetails = response_json(missing).await;
        assert_eq!(problem.code, "missing_idempotency_key");

        let first = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "api-create-conflict")
                    .body(Body::from(
                        r#"{"id":"session-conflict","title":"Original"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::CREATED);

        let conflict = app
            .oneshot(
                Request::post("/api/v1/sessions")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "api-create-conflict")
                    .body(Body::from(
                        r#"{"id":"session-conflict","title":"Different"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        let problem: ProblemDetails = response_json(conflict).await;
        assert_eq!(problem.code, "idempotency_conflict");
    }

    #[tokio::test]
    async fn session_errors_use_400_404_and_409_problem_details() {
        let app = test_app().await;

        let missing = app
            .clone()
            .oneshot(
                Request::get("/api/v1/sessions/not-real")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        let problem: ProblemDetails = response_json(missing).await;
        assert_eq!(problem.code, "session_not_found");

        let invalid = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "api-create-invalid")
                    .body(Body::from(r#"{"id":" session-invalid","title":"Invalid"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
        let problem: ProblemDetails = response_json(invalid).await;
        assert_eq!(problem.code, "invalid_session_request");

        create_test_session(&app, "session-state").await;
        let duplicate = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "api-create-session-state-again")
                    .body(Body::from(r#"{"id":"session-state","title":"Duplicate"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(duplicate.status(), StatusCode::CONFLICT);
        let problem: ProblemDetails = response_json(duplicate).await;
        assert_eq!(problem.code, "session_already_exists");

        let started = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-state/turns")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "api-start-session-state")
                    .body(Body::from(
                        r#"{"turn_id":"turn-state","user_message":"Keep running","expected_sequence":1}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::OK);

        let invalid_transition = app
            .oneshot(
                Request::post("/api/v1/sessions/session-state/resume")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "api-resume-running-session")
                    .body(Body::from(r#"{"expected_sequence":2}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid_transition.status(), StatusCode::CONFLICT);
        let problem: ProblemDetails = response_json(invalid_transition).await;
        assert_eq!(problem.code, "invalid_session_transition");
        assert_eq!(
            problem.detail,
            "The session state does not allow this command"
        );
    }

    #[tokio::test]
    async fn start_and_flush_routes_are_idempotent_and_validate_the_path_turn() {
        let app = test_app().await;
        create_test_session(&app, "session-turns").await;

        let start_request = || {
            Request::post("/api/v1/sessions/session-turns/turns")
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "api-start-turn-1")
                .body(Body::from(
                    r#"{"turn_id":"turn-1","user_message":"Investigate","expected_sequence":1}"#,
                ))
                .unwrap()
        };
        let started = app.clone().oneshot(start_request()).await.unwrap();
        assert_eq!(started.status(), StatusCode::OK);
        let started: StartTurnResponse = response_json(started).await;
        assert!(!started.replayed);
        assert_eq!(started.session.status, SessionStatus::Running);
        assert_eq!(started.session.sequence, 2);

        let replayed = app.clone().oneshot(start_request()).await.unwrap();
        assert_eq!(replayed.status(), StatusCode::OK);
        let replayed: StartTurnResponse = response_json(replayed).await;
        assert!(replayed.replayed);
        assert_eq!(replayed.event, started.event);

        let mismatch = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-turns/turns/not-turn-1/flush")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "api-flush-mismatch")
                    .body(Body::from(
                        r#"{"turn_id":"turn-1","assistant_message":"Done","expected_sequence":2}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mismatch.status(), StatusCode::BAD_REQUEST);
        let problem: ProblemDetails = response_json(mismatch).await;
        assert_eq!(problem.code, "turn_id_mismatch");

        let unchanged = app
            .clone()
            .oneshot(
                Request::get("/api/v1/sessions/session-turns")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let unchanged: SessionDetail = response_json(unchanged).await;
        assert_eq!(unchanged.session.status, SessionStatus::Running);
        assert_eq!(unchanged.session.sequence, 2);

        let flush_request = || {
            Request::post("/api/v1/sessions/session-turns/turns/turn-1/flush")
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "api-flush-turn-1")
                .body(Body::from(
                    r#"{"turn_id":"turn-1","assistant_message":"Done","expected_sequence":2}"#,
                ))
                .unwrap()
        };
        let flushed = app.clone().oneshot(flush_request()).await.unwrap();
        assert_eq!(flushed.status(), StatusCode::OK);
        let flushed: FlushSessionResponse = response_json(flushed).await;
        assert!(!flushed.replayed);
        assert_eq!(flushed.session.status, SessionStatus::Ready);
        assert_eq!(flushed.ack.turn_id, "turn-1");
        assert_eq!(flushed.ack.durability_sequence, 4);

        let replayed = app.oneshot(flush_request()).await.unwrap();
        assert_eq!(replayed.status(), StatusCode::OK);
        let replayed: FlushSessionResponse = response_json(replayed).await;
        assert!(replayed.replayed);
        assert_eq!(replayed.ack, flushed.ack);
        assert_eq!(replayed.events, flushed.events);
    }

    #[tokio::test]
    async fn session_sse_replays_events_after_the_cursor() {
        let app = test_app().await;
        create_test_session(&app, "session-events").await;
        let started = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-events/turns")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "api-start-events")
                    .body(Body::from(
                        r#"{"turn_id":"turn-events","user_message":"Stream me","expected_sequence":1}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::get("/api/v1/sessions/session-events/events?after=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers()[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/event-stream")
        );
        let frame = tokio::time::timeout(Duration::from_secs(1), response.into_body().frame())
            .await
            .expect("session SSE replay should be immediate")
            .expect("session SSE stream should produce a frame")
            .expect("session SSE frame should be valid");
        let payload = String::from_utf8(frame.into_data().unwrap().to_vec()).unwrap();
        assert!(payload.contains("event: session.event"));
        assert!(payload.contains("id: 2"));
        assert!(!payload.contains("id: 1"));
    }

    #[tokio::test]
    async fn sse_replays_only_events_after_the_cursor() {
        let response = test_app()
            .await
            .oneshot(
                Request::get(format!("/api/v1/runs/{DEMO_RUN_ID}/events?after=4"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers()[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/event-stream")
        );
        let frame = tokio::time::timeout(Duration::from_secs(1), response.into_body().frame())
            .await
            .expect("SSE replay should be immediate")
            .expect("SSE stream should produce a frame")
            .expect("SSE frame should be valid");
        let payload = String::from_utf8(frame.into_data().unwrap().to_vec()).unwrap();
        assert!(payload.contains("id: 5"));
        assert!(!payload.contains("id: 4"));
    }

    #[tokio::test]
    async fn sse_reconnect_prefers_last_event_id_over_initial_query() {
        let response = test_app()
            .await
            .oneshot(
                Request::get(format!("/api/v1/runs/{DEMO_RUN_ID}/events?after=1"))
                    .header("last-event-id", "4")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let frame = tokio::time::timeout(Duration::from_secs(1), response.into_body().frame())
            .await
            .expect("SSE replay should be immediate")
            .expect("SSE stream should produce a frame")
            .expect("SSE frame should be valid");
        let payload = String::from_utf8(frame.into_data().unwrap().to_vec()).unwrap();
        assert!(payload.contains("id: 5"));
        assert!(!payload.contains("id: 2"));
    }

    #[tokio::test]
    async fn sse_polls_the_ledger_without_local_broadcast_hints() {
        let store = DemoStore::seeded().await.unwrap();
        let response = app_with_event_feed_options(store.clone(), Duration::from_millis(10), false)
            .oneshot(
                Request::get(format!("/api/v1/runs/{DEMO_RUN_ID}/events?after=8"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Start polling before the commit. Broadcast hints are disabled for
        // this test route, so only the durable sequence cursor can advance the
        // stream.
        let mut body = response.into_body();
        let opened = tokio::time::timeout(Duration::from_secs(1), body.frame())
            .await
            .expect("SSE should flush its opening comment immediately")
            .expect("SSE stream should produce an opening frame")
            .expect("SSE opening frame should be valid");
        let opened = String::from_utf8(opened.into_data().unwrap().to_vec()).unwrap();
        assert!(opened.contains(": stream-open"));

        let next_frame = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(2), body.frame())
                .await
                .expect("SSE durable polling should observe the commit")
                .expect("SSE stream should produce a frame")
                .expect("SSE frame should be valid")
        });
        tokio::time::sleep(Duration::from_millis(30)).await;

        let reviewed = store
            .review(
                DEMO_RUN_ID,
                "APR-901",
                ReviewRequest {
                    decision: ReviewDecision::Reject,
                    note: Some("durable poll review".into()),
                    idempotency_key: None,
                },
                "durable-poll-review-1",
            )
            .await
            .unwrap();
        assert_eq!(reviewed.event.sequence, 9);

        let frame = next_frame.await.unwrap();
        let payload = String::from_utf8(frame.into_data().unwrap().to_vec()).unwrap();
        assert!(payload.contains("id: 9"));
        assert!(payload.contains("approval_decided"));
        assert!(!payload.contains("id: 8"));
    }

    #[tokio::test]
    async fn run_broadcast_hint_reconciles_every_durable_event_before_it() {
        let store = DemoStore::seeded().await.unwrap();
        let reviewed = store
            .review(
                DEMO_RUN_ID,
                "APR-901",
                ReviewRequest {
                    decision: ReviewDecision::Approve,
                    note: Some("exercise ordered hint reconciliation".into()),
                    idempotency_key: None,
                },
                "ordered-run-hint-review-1",
            )
            .await
            .unwrap();
        assert_eq!(reviewed.event.sequence, 9);

        let detail = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let detail = store.run_detail(DEMO_RUN_ID).await.unwrap();
                if detail.run.sequence >= 11 {
                    break detail;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the guarded demo dispatcher should settle durably");
        let hinted = detail.events.last().cloned().unwrap();
        assert_eq!(hinted.sequence, 11);

        let replay = run_events_for_hint(
            &store,
            DEMO_RUN_ID,
            8,
            &PublishedEvent {
                run_id: DEMO_RUN_ID.into(),
                event: hinted,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            replay
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![9, 10, 11]
        );
    }

    #[tokio::test]
    async fn internal_execution_invariants_return_a_generic_500_problem() {
        let errors = [
            StoreError::ToolCallNotFound,
            StoreError::ExecutionInvariant("private persisted binding detail".into()),
            StoreError::Kernel(kernel::KernelError::InvalidToolCall),
            StoreError::SequenceOverflow,
        ];

        for error in errors {
            let response = ApiError::from(error).into_response();
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            let problem: ProblemDetails = response_json(response).await;
            assert_eq!(problem.code, "runtime_unavailable");
            assert_eq!(problem.title, "Runtime is unavailable");
            assert_eq!(
                problem.detail,
                "The runtime could not process the request safely"
            );
            assert!(!problem.detail.contains("binding"));
            assert!(!problem.detail.contains("tool call"));
        }
    }

    #[tokio::test]
    async fn unknown_runs_use_problem_details() {
        let response = test_app()
            .await
            .oneshot(
                Request::get("/api/v1/runs/not-real")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/problem+json"
        );
        let problem: ProblemDetails = response_json(response).await;
        assert_eq!(problem.code, "run_not_found");
    }

    #[tokio::test]
    async fn review_requires_an_idempotency_header() {
        let response = test_app()
            .await
            .oneshot(
                Request::post(format!(
                    "/api/v1/runs/{DEMO_RUN_ID}/approvals/APR-901/decision"
                ))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"decision":"approve"}"#))
                .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let problem: ProblemDetails = response_json(response).await;
        assert_eq!(problem.code, "missing_idempotency_key");
    }

    async fn test_app() -> Router {
        app(DemoStore::seeded().await.unwrap())
    }

    async fn create_test_session(app: &Router, session_id: &str) -> CreateSessionResponse {
        let response = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", format!("create-{session_id}"))
                    .body(Body::from(
                        serde_json::json!({
                            "id": session_id,
                            "title": "API test session",
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        response_json(response).await
    }

    async fn response_json<T: serde::de::DeserializeOwned>(response: Response) -> T {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }
}
