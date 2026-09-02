use std::{convert::Infallible, time::Duration};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::sse::{Event, KeepAlive, Sse},
    routing::get,
};
use futures_util::stream;
use sqlx::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;
use zeus_core::Permission;

use crate::{AppState, auth::AuthContext, database::begin_tenant, error::ApiError};

use super::{
    run,
    shared::types::{
        ApprovalResponse, ChildRunResponse, EventQuery, RunEventResponse, RunTraceResponse,
        RunUsageResponse, RunUsageSummaryResponse, SessionEventResponse,
        TraceExperienceInjectionResponse, TraceRunLinkResponse, TraceToolCallResponse,
    },
};

#[derive(Debug, FromRow)]
struct TraceExperienceInjectionRow {
    id: Uuid,
    experience_entry_id: Uuid,
    experience_version: i32,
    rank: f32,
    query_sha256: Vec<u8>,
    injected_at: OffsetDateTime,
}

pub async fn list_session_events(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, session_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<EventQuery>,
) -> Result<Json<Vec<SessionEventResponse>>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let limit = event_limit(query.limit)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let events = sqlx::query_as::<_, SessionEventResponse>(
        "select id, session_id, run_id, sequence, schema_version, event_type,
                actor_kind, actor_id, payload, occurred_at
         from session_events
         where session_id = $1 and organization_id = $2 and workspace_id = $3 and sequence > $4
         order by sequence limit $5",
    )
    .bind(session_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(query.after.max(0))
    .bind(limit)
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(events))
}

#[allow(clippy::too_many_lines)] // A trace is one read snapshot across the Run's durable facts.
pub async fn get_run_trace(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, run_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<RunTraceResponse>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let run = run::load_run(&mut transaction, auth.organization_id, workspace_id, run_id).await?;
    let run_events = sqlx::query_as::<_, RunEventResponse>(
        "select id, run_id, session_event_id, sequence, schema_version,
                event_type, payload, occurred_at
         from run_events
         where run_id = $1 and organization_id = $2 and workspace_id = $3
         order by sequence limit 5000",
    )
    .bind(run_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .fetch_all(&mut *transaction)
    .await?;
    let session_events = sqlx::query_as::<_, SessionEventResponse>(
        "select id, session_id, run_id, sequence, schema_version, event_type,
                actor_kind, actor_id, payload, occurred_at
         from session_events
         where run_id = $1 and organization_id = $2 and workspace_id = $3
         order by sequence limit 5000",
    )
    .bind(run_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .fetch_all(&mut *transaction)
    .await?;
    let tool_calls = sqlx::query_as::<_, TraceToolCallResponse>(
        "select id, capability_id, call_key, status, input, result, error_code, child_run_id,
                started_at, finished_at, created_at
         from tool_calls
         where run_id = $1 and organization_id = $2 and workspace_id = $3
         order by created_at, id limit 1000",
    )
    .bind(run_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .fetch_all(&mut *transaction)
    .await?;
    let approvals = sqlx::query_as::<_, ApprovalResponse>(
        "select id, run_id, tool_call_id, status, requested_at, expires_at,
                decided_at, decided_by, reason
         from approvals
         where run_id = $1 and organization_id = $2 and workspace_id = $3
         order by requested_at, id limit 1000",
    )
    .bind(run_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .fetch_all(&mut *transaction)
    .await?;
    let usage_entries = sqlx::query_as::<_, RunUsageResponse>(
        "select id, run_id, provider_request_id, prompt_tokens,
                completion_tokens, cache_tokens, occurred_at
         from zeus_private.read_run_usage($1)",
    )
    .bind(run_id)
    .fetch_all(&mut *transaction)
    .await?;
    let linked_runs = sqlx::query_as::<_, TraceRunLinkResponse>(
        "select l.relation, linked.id as run_id, linked.status, linked.output,
                linked.error_code, l.created_at
         from run_links l
         join runs linked on linked.id = case
           when l.parent_run_id = $1 then l.child_run_id else l.parent_run_id
         end
         where (l.parent_run_id = $1 or l.child_run_id = $1)
           and l.organization_id = $2 and l.workspace_id = $3
           and linked.organization_id = $2 and linked.workspace_id = $3
         order by l.created_at, linked.id limit 1000",
    )
    .bind(run_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .fetch_all(&mut *transaction)
    .await?;
    let experience_injections = sqlx::query_as::<_, TraceExperienceInjectionRow>(
        "select id, experience_entry_id, experience_version, rank,
                query_sha256, injected_at
         from run_experience_injections
         where run_id = $1 and organization_id = $2 and workspace_id = $3
         order by injected_at, id limit 1000",
    )
    .bind(run_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .fetch_all(&mut *transaction)
    .await?
    .into_iter()
    .map(|item| TraceExperienceInjectionResponse {
        id: item.id,
        experience_entry_id: item.experience_entry_id,
        experience_version: item.experience_version,
        rank: item.rank,
        query_sha256: hex::encode(item.query_sha256),
        injected_at: item.injected_at,
    })
    .collect();
    transaction.commit().await?;
    let usage = usage_summary(usage_entries);
    Ok(Json(RunTraceResponse {
        run,
        run_events,
        session_events,
        tool_calls,
        approvals,
        usage,
        linked_runs,
        experience_injections,
    }))
}

pub async fn list_child_runs(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, run_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Vec<ChildRunResponse>>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    run::load_run(&mut transaction, auth.organization_id, workspace_id, run_id).await?;
    let children = sqlx::query_as::<_, ChildRunResponse>(
        "select child.id, child.workflow_version_id, child.session_id, child.status,
                child.depth, child.token_budget_override as token_budget,
                child.max_runtime_seconds_override as max_runtime_seconds,
                child.output, child.error_code, child.error_detail,
                child.created_at, child.finished_at
         from run_links link
         join runs child on child.id = link.child_run_id
         where link.parent_run_id = $1 and link.relation = 'child'
           and link.organization_id = $2 and link.workspace_id = $3
           and child.organization_id = $2 and child.workspace_id = $3
         order by link.created_at, child.id limit 1000",
    )
    .bind(run_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(children))
}

pub async fn list_run_events(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, run_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<EventQuery>,
) -> Result<Json<Vec<RunEventResponse>>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let limit = event_limit(query.limit)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let events = sqlx::query_as::<_, RunEventResponse>(
        "select id, run_id, session_event_id, sequence, schema_version,
                event_type, payload, occurred_at
         from run_events
         where run_id = $1 and organization_id = $2 and workspace_id = $3 and sequence > $4
         order by sequence limit $5",
    )
    .bind(run_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(query.after.max(0))
    .bind(limit)
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(events))
}

pub async fn stream_run_events(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, run_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let after = last_event_sequence(&headers)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    run::load_run(&mut transaction, auth.organization_id, workspace_id, run_id).await?;
    transaction.commit().await?;

    let stream_state = RunEventStreamState {
        state,
        auth,
        workspace_id,
        run_id,
        sequence: after,
        stopped: false,
    };
    let events = stream::unfold(stream_state, |mut stream_state| async move {
        if stream_state.stopped {
            return None;
        }
        loop {
            match next_run_event(&stream_state).await {
                Ok(Some(event)) => {
                    stream_state.sequence = event.sequence;
                    let data = serde_json::to_string(&event).unwrap_or_else(|_| "{}".to_owned());
                    let sse = Event::default()
                        .id(event.sequence.to_string())
                        .event(event.event_type.clone())
                        .data(data);
                    return Some((Ok(sse), stream_state));
                }
                Ok(None) => tokio::time::sleep(Duration::from_secs(1)).await,
                Err(_) => {
                    stream_state.stopped = true;
                    let sse = Event::default()
                        .event("stream_error")
                        .data("{\"code\":\"event_stream_unavailable\"}");
                    return Some((Ok(sse), stream_state));
                }
            }
        }
    });
    Ok(Sse::new(events).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}

struct RunEventStreamState {
    state: AppState,
    auth: AuthContext,
    workspace_id: Uuid,
    run_id: Uuid,
    sequence: i64,
    stopped: bool,
}

async fn next_run_event(
    stream: &RunEventStreamState,
) -> Result<Option<RunEventResponse>, ApiError> {
    let mut transaction = begin_tenant(
        &stream.state.platform.database,
        stream.auth.tenant_scope(Some(stream.workspace_id)),
    )
    .await?;
    let event = sqlx::query_as::<_, RunEventResponse>(
        "select id, run_id, session_event_id, sequence, schema_version,
                event_type, payload, occurred_at
         from run_events
         where run_id = $1 and organization_id = $2 and workspace_id = $3 and sequence > $4
         order by sequence limit 1",
    )
    .bind(stream.run_id)
    .bind(stream.auth.organization_id)
    .bind(stream.workspace_id)
    .bind(stream.sequence)
    .fetch_optional(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(event)
}

pub async fn get_run_usage(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, run_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<RunUsageSummaryResponse>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let entries = sqlx::query_as::<_, RunUsageResponse>(
        "select id, run_id, provider_request_id, prompt_tokens,
                completion_tokens, cache_tokens, occurred_at
         from zeus_private.read_run_usage($1)",
    )
    .bind(run_id)
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(usage_summary(entries)))
}

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/workspaces/{workspace_id}/sessions/{session_id}/events",
            get(list_session_events),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/runs/{run_id}/trace",
            get(get_run_trace),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/runs/{run_id}/children",
            get(list_child_runs),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/runs/{run_id}/events",
            get(list_run_events),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/runs/{run_id}/events/stream",
            get(stream_run_events),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/runs/{run_id}/usage",
            get(get_run_usage),
        )
}

pub(super) fn event_limit(value: Option<u16>) -> Result<i64, ApiError> {
    let value = value.unwrap_or(100);
    if !(1..=500).contains(&value) {
        return Err(ApiError::Validation(
            "event limit must be between 1 and 500".to_owned(),
        ));
    }
    Ok(i64::from(value))
}

pub(super) fn last_event_sequence(headers: &HeaderMap) -> Result<i64, ApiError> {
    headers
        .get("last-event-id")
        .map(|value| {
            value
                .to_str()
                .map_err(|_| ApiError::BadRequest("Last-Event-ID is malformed".to_owned()))?
                .parse::<i64>()
                .map_err(|_| ApiError::BadRequest("Last-Event-ID is malformed".to_owned()))
        })
        .transpose()
        .map(|value| value.unwrap_or(0).max(0))
}

fn usage_summary(entries: Vec<RunUsageResponse>) -> RunUsageSummaryResponse {
    let prompt_tokens = entries.iter().map(|entry| entry.prompt_tokens).sum();
    let completion_tokens = entries.iter().map(|entry| entry.completion_tokens).sum();
    let cache_tokens = entries.iter().map(|entry| entry.cache_tokens).sum();
    RunUsageSummaryResponse {
        prompt_tokens,
        completion_tokens,
        cache_tokens,
        entries,
    }
}
