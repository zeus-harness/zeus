#![allow(clippy::missing_errors_doc)] // HTTP failures use the shared Problem Details contract.

use std::{convert::Infallible, time::Duration};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use futures_util::stream;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::FromRow;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;
use zeus_core::Permission;

use crate::{
    AppState,
    api_support::{ListCursor, PageQuery},
    auth::{AuthContext, PrincipalKind, insert_audit},
    database::begin_tenant,
    error::ApiError,
    idempotency::{self, IdempotencyDecision},
};

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct SessionResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub workspace_id: Uuid,
    pub work_item_id: Option<Uuid>,
    pub title: String,
    pub status: String,
    pub created_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub closed_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SessionPageResponse {
    pub items: Vec<SessionResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateSessionRequest {
    pub work_item_id: Option<Uuid>,
    #[serde(default)]
    pub title: String,
}

pub async fn list_sessions(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<SessionPageResponse>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let limit = page.limit()?;
    let cursor = page.decoded_cursor()?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let mut items = sqlx::query_as::<_, SessionResponse>(
        "select id, organization_id, workspace_id, work_item_id, title, status,
                created_by, created_at, updated_at, closed_at
         from sessions
         where organization_id = $1 and workspace_id = $2
           and ($3::timestamptz is null or (created_at, id) < ($3, $4))
         order by created_at desc, id desc limit $5",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(cursor.map(ListCursor::created_at))
    .bind(cursor.map(ListCursor::id))
    .bind(limit + 1)
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    let has_more = i64::try_from(items.len()).unwrap_or(i64::MAX) > limit;
    if has_more {
        items.pop();
    }
    let next_cursor = if has_more {
        items
            .last()
            .map(|item| ListCursor::new(item.created_at, item.id).encode())
            .transpose()?
    } else {
        None
    };
    Ok(Json(SessionPageResponse { items, next_cursor }))
}

pub async fn create_session(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    Json(request): Json<CreateSessionRequest>,
) -> Result<(StatusCode, Json<SessionResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::OperateRun)?;
    if request.title.len() > 500 {
        return Err(ApiError::Validation("title is too long".to_owned()));
    }
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    if let Some(work_item_id) = request.work_item_id {
        let belongs: bool = sqlx::query_scalar(
            "select exists(select 1 from work_items where id = $1 and organization_id = $2 and workspace_id = $3)",
        )
        .bind(work_item_id)
        .bind(auth.organization_id)
        .bind(workspace_id)
        .fetch_one(&mut *transaction)
        .await?;
        if !belongs {
            return Err(ApiError::Validation(
                "work_item_id is outside the workspace".to_owned(),
            ));
        }
    }
    let session = sqlx::query_as::<_, SessionResponse>(
        "insert into sessions (
            organization_id, workspace_id, work_item_id, title, created_by
         ) values ($1, $2, $3, $4, $5)
         returning id, organization_id, workspace_id, work_item_id, title, status,
                   created_by, created_at, updated_at, closed_at",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(request.work_item_id)
    .bind(request.title)
    .bind(auth.user_id)
    .fetch_one(&mut *transaction)
    .await?;
    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace_id),
        "session.created",
        "session",
        session.id,
    )
    .await?;
    transaction.commit().await?;
    Ok((StatusCode::CREATED, Json(session)))
}

pub async fn get_session(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, session_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<SessionResponse>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let session = sqlx::query_as::<_, SessionResponse>(
        "select id, organization_id, workspace_id, work_item_id, title, status,
                created_by, created_at, updated_at, closed_at
         from sessions where id = $1 and organization_id = $2 and workspace_id = $3",
    )
    .bind(session_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(session))
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct SubmitMessageRequest {
    #[serde(default = "user_message_kind")]
    pub kind: String,
    pub content: String,
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct AppendedEventResponse {
    pub event_id: Uuid,
    pub event_sequence: i64,
}

pub async fn submit_message(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, session_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<SubmitMessageRequest>,
) -> Result<(StatusCode, Json<AppendedEventResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::OperateRun)?;
    if request.content.trim().is_empty() || request.content.len() > 200_000 {
        return Err(ApiError::Validation(
            "content must contain between 1 and 200000 characters".to_owned(),
        ));
    }
    if !matches!(
        request.kind.as_str(),
        "user_message" | "steering" | "follow_up"
    ) {
        return Err(ApiError::Validation("unknown message kind".to_owned()));
    }
    let event_type = match request.kind.as_str() {
        "user_message" => "user_message",
        "steering" => "steering_message",
        "follow_up" => "follow_up_message",
        _ => unreachable!(),
    };
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let event = sqlx::query_as::<_, AppendedEventResponse>(
        "select * from zeus_private.append_session_event($1, $2, $3, $4, $5)",
    )
    .bind(session_id)
    .bind(event_type)
    .bind(actor_kind(&auth))
    .bind(auth.principal_id)
    .bind(json!({ "content": request.content }))
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok((StatusCode::CREATED, Json(event)))
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct SessionEventResponse {
    pub id: Uuid,
    pub session_id: Uuid,
    pub run_id: Option<Uuid>,
    pub sequence: i64,
    pub schema_version: i16,
    pub event_type: String,
    pub actor_kind: String,
    pub actor_id: Option<Uuid>,
    pub payload: Value,
    pub occurred_at: OffsetDateTime,
}

#[derive(Debug, Default, Deserialize)]
pub struct EventQuery {
    #[serde(default)]
    pub after: i64,
    pub limit: Option<u16>,
}

pub async fn list_session_events(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, session_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<EventQuery>,
) -> Result<Json<Vec<SessionEventResponse>>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let limit = event_limit(query.limit)?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
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

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct CreateRunRequest {
    pub workflow_version_id: Uuid,
    pub session_id: Uuid,
    pub work_item_id: Option<Uuid>,
    #[serde(default = "empty_object")]
    pub input: Value,
    pub message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, FromRow)]
pub struct RunResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub workspace_id: Uuid,
    pub workflow_version_id: Uuid,
    pub work_item_id: Option<Uuid>,
    pub session_id: Uuid,
    pub parent_run_id: Option<Uuid>,
    pub retry_of_run_id: Option<Uuid>,
    pub status: String,
    pub input: Value,
    pub output: Option<Value>,
    pub error_code: Option<String>,
    pub error_detail: Option<String>,
    pub attempt_count: i32,
    pub cancel_requested_at: Option<OffsetDateTime>,
    pub started_at: Option<OffsetDateTime>,
    pub finished_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RunPageResponse {
    pub items: Vec<RunResponse>,
    pub next_cursor: Option<String>,
}

#[utoipa::path(post, path = "/api/v1/workspaces/{workspace_id}/runs", tag = "execution",
    params(("workspace_id" = Uuid, Path), ("Idempotency-Key" = String, Header)),
    request_body = CreateRunRequest,
    responses((status = 201, description = "Queued Run", body = RunResponse), (status = 409, description = "Idempotency conflict"))
)]
#[allow(clippy::too_many_lines)] // Keeps the idempotent queue insert in one transaction boundary.
pub async fn create_run(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<CreateRunRequest>,
) -> Result<Response, ApiError> {
    auth.require_workspace(workspace_id, Permission::OperateRun)?;
    if !request.input.is_object() {
        return Err(ApiError::Validation(
            "input must be a JSON object".to_owned(),
        ));
    }
    if request
        .message
        .as_ref()
        .is_some_and(|value| value.trim().is_empty() || value.len() > 200_000)
    {
        return Err(ApiError::Validation(
            "message is empty or too long".to_owned(),
        ));
    }
    let path = format!("/api/v1/workspaces/{workspace_id}/runs");
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let reservation = match idempotency::begin(
        &mut transaction,
        &auth,
        workspace_id,
        "POST",
        &path,
        &headers,
        &request,
    )
    .await?
    {
        IdempotencyDecision::Replay { status, body } => {
            transaction.commit().await?;
            return json_response(status, body);
        }
        IdempotencyDecision::New(reservation) => reservation,
    };
    let dependency = sqlx::query_as::<_, (Uuid, Option<Uuid>)>(
        "select s.id, s.work_item_id
         from sessions s
         join workflow_versions w on w.id = $1
         where s.id = $2
           and s.organization_id = $3 and s.workspace_id = $4
           and w.organization_id = $3 and w.workspace_id = $4",
    )
    .bind(request.workflow_version_id)
    .bind(request.session_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| {
        ApiError::Validation("session or workflow version is outside the workspace".to_owned())
    })?;
    if request.work_item_id.is_some() && request.work_item_id != dependency.1 {
        return Err(ApiError::Validation(
            "work_item_id does not match the session".to_owned(),
        ));
    }
    let idempotency_key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::BadRequest("Idempotency-Key is required".to_owned()))?;
    let run = sqlx::query_as::<_, RunResponse>(
        "insert into runs (
            organization_id, workspace_id, workflow_version_id, work_item_id,
            session_id, input, idempotency_key, created_by
         ) values ($1, $2, $3, $4, $5, $6, $7, $8)
         returning id, organization_id, workspace_id, workflow_version_id, work_item_id,
                   session_id, parent_run_id, retry_of_run_id, status, input, output,
                   error_code, error_detail, attempt_count, cancel_requested_at,
                   started_at, finished_at, created_at, updated_at",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(request.workflow_version_id)
    .bind(request.work_item_id)
    .bind(request.session_id)
    .bind(&request.input)
    .bind(idempotency_key)
    .bind(auth.user_id)
    .fetch_one(&mut *transaction)
    .await?;
    let content = request.message.unwrap_or_else(|| {
        serde_json::to_string(&request.input).unwrap_or_else(|_| "{}".to_owned())
    });
    let session_event = sqlx::query_as::<_, AppendedEventResponse>(
        "select * from zeus_private.append_session_event($1, 'user_message', $2, $3, $4, $5)",
    )
    .bind(request.session_id)
    .bind(actor_kind(&auth))
    .bind(auth.principal_id)
    .bind(json!({ "content": content, "source": "run" }))
    .bind(run.id)
    .fetch_one(&mut *transaction)
    .await?;
    sqlx::query("select * from zeus_private.append_run_event($1, 'run_queued', $2, $3)")
        .bind(run.id)
        .bind(json!({ "attempt_count": 0 }))
        .bind(session_event.event_id)
        .execute(&mut *transaction)
        .await?;
    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace_id),
        "run.created",
        "run",
        run.id,
    )
    .await?;
    idempotency::complete(&mut transaction, &reservation, 201, &run).await?;
    transaction.commit().await?;
    Ok((StatusCode::CREATED, Json(run)).into_response())
}

pub async fn list_runs(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<RunPageResponse>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let limit = page.limit()?;
    let cursor = page.decoded_cursor()?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let mut items = sqlx::query_as::<_, RunResponse>(
        "select id, organization_id, workspace_id, workflow_version_id, work_item_id,
                session_id, parent_run_id, retry_of_run_id, status, input, output,
                error_code, error_detail, attempt_count, cancel_requested_at,
                started_at, finished_at, created_at, updated_at
         from runs
         where organization_id = $1 and workspace_id = $2
           and ($3::timestamptz is null or (created_at, id) < ($3, $4))
         order by created_at desc, id desc limit $5",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(cursor.map(ListCursor::created_at))
    .bind(cursor.map(ListCursor::id))
    .bind(limit + 1)
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    let has_more = i64::try_from(items.len()).unwrap_or(i64::MAX) > limit;
    if has_more {
        items.pop();
    }
    let next_cursor = if has_more {
        items
            .last()
            .map(|item| ListCursor::new(item.created_at, item.id).encode())
            .transpose()?
    } else {
        None
    };
    Ok(Json(RunPageResponse { items, next_cursor }))
}

pub async fn get_run(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, run_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<RunResponse>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let run = load_run(&mut transaction, auth.organization_id, workspace_id, run_id).await?;
    transaction.commit().await?;
    Ok(Json(run))
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct TraceToolCallResponse {
    pub id: Uuid,
    pub capability_id: Uuid,
    pub call_key: String,
    pub status: String,
    pub input: Value,
    pub result: Option<Value>,
    pub error_code: Option<String>,
    pub child_run_id: Option<Uuid>,
    pub started_at: Option<OffsetDateTime>,
    pub finished_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct TraceRunLinkResponse {
    pub relation: String,
    pub run_id: Uuid,
    pub status: String,
    pub output: Option<Value>,
    pub error_code: Option<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct ChildRunResponse {
    pub id: Uuid,
    pub workflow_version_id: Uuid,
    pub session_id: Uuid,
    pub status: String,
    pub depth: i16,
    pub token_budget: i64,
    pub max_runtime_seconds: i32,
    pub output: Option<Value>,
    pub error_code: Option<String>,
    pub error_detail: Option<String>,
    pub created_at: OffsetDateTime,
    pub finished_at: Option<OffsetDateTime>,
}

pub async fn list_child_runs(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, run_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Vec<ChildRunResponse>>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    load_run(&mut transaction, auth.organization_id, workspace_id, run_id).await?;
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

#[derive(Debug, Serialize, ToSchema)]
pub struct TraceExperienceInjectionResponse {
    pub id: Uuid,
    pub experience_entry_id: Uuid,
    pub experience_version: i32,
    pub rank: f32,
    pub query_sha256: String,
    pub injected_at: OffsetDateTime,
}

#[derive(Debug, FromRow)]
struct TraceExperienceInjectionRow {
    id: Uuid,
    experience_entry_id: Uuid,
    experience_version: i32,
    rank: f32,
    query_sha256: Vec<u8>,
    injected_at: OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RunTraceResponse {
    pub run: RunResponse,
    pub run_events: Vec<RunEventResponse>,
    pub session_events: Vec<SessionEventResponse>,
    pub tool_calls: Vec<TraceToolCallResponse>,
    pub approvals: Vec<ApprovalResponse>,
    pub usage: RunUsageSummaryResponse,
    pub linked_runs: Vec<TraceRunLinkResponse>,
    pub experience_injections: Vec<TraceExperienceInjectionResponse>,
}

#[allow(clippy::too_many_lines)] // A trace is one read snapshot across the Run's durable facts.
pub async fn get_run_trace(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, run_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<RunTraceResponse>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let run = load_run(&mut transaction, auth.organization_id, workspace_id, run_id).await?;
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

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct CancelRunRequest {
    pub reason: Option<String>,
}

pub async fn cancel_run(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, run_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<CancelRunRequest>,
) -> Result<StatusCode, ApiError> {
    auth.require_workspace(workspace_id, Permission::OperateRun)?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let canceled: bool =
        sqlx::query_scalar("select zeus_private.request_run_cancel($1, $2, $3, $4)")
            .bind(run_id)
            .bind(actor_kind(&auth))
            .bind(auth.principal_id)
            .bind(request.reason.as_deref())
            .fetch_one(&mut *transaction)
            .await?;
    if !canceled {
        return Err(ApiError::Conflict(
            "run cannot be canceled in its current state".to_owned(),
        ));
    }
    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace_id),
        "run.cancel_requested",
        "run",
        run_id,
    )
    .await?;
    transaction.commit().await?;
    Ok(StatusCode::ACCEPTED)
}

#[derive(Debug, Default, Deserialize, Serialize, ToSchema)]
pub struct RetryRunRequest {}

pub async fn retry_run(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, run_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<RetryRunRequest>,
) -> Result<Response, ApiError> {
    auth.require_workspace(workspace_id, Permission::OperateRun)?;
    let path = format!("/api/v1/workspaces/{workspace_id}/runs/{run_id}/retry");
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let reservation = match idempotency::begin(
        &mut transaction,
        &auth,
        workspace_id,
        "POST",
        &path,
        &headers,
        &request,
    )
    .await?
    {
        IdempotencyDecision::Replay { status, body } => {
            transaction.commit().await?;
            return json_response(status, body);
        }
        IdempotencyDecision::New(reservation) => reservation,
    };
    let original = sqlx::query_as::<_, RunResponse>(
        "select id, organization_id, workspace_id, workflow_version_id, work_item_id,
                session_id, parent_run_id, retry_of_run_id, status, input, output,
                error_code, error_detail, attempt_count, cancel_requested_at,
                started_at, finished_at, created_at, updated_at
         from runs where id = $1 and organization_id = $2 and workspace_id = $3 for update",
    )
    .bind(run_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .fetch_one(&mut *transaction)
    .await?;
    if !matches!(original.status.as_str(), "failed" | "canceled") {
        return Err(ApiError::Conflict(
            "only failed or canceled runs can be retried manually".to_owned(),
        ));
    }
    let idempotency_key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::BadRequest("Idempotency-Key is required".to_owned()))?;
    let retry = sqlx::query_as::<_, RunResponse>(
        "insert into runs (
            organization_id, workspace_id, workflow_version_id, work_item_id,
            session_id, retry_of_run_id, input, idempotency_key, created_by
         ) values ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         returning id, organization_id, workspace_id, workflow_version_id, work_item_id,
                   session_id, parent_run_id, retry_of_run_id, status, input, output,
                   error_code, error_detail, attempt_count, cancel_requested_at,
                   started_at, finished_at, created_at, updated_at",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(original.workflow_version_id)
    .bind(original.work_item_id)
    .bind(original.session_id)
    .bind(original.id)
    .bind(original.input)
    .bind(idempotency_key)
    .bind(auth.user_id)
    .fetch_one(&mut *transaction)
    .await?;
    sqlx::query(
        "insert into run_links (organization_id, workspace_id, parent_run_id, child_run_id, relation)
         values ($1, $2, $3, $4, 'retry')",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(original.id)
    .bind(retry.id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query("select * from zeus_private.append_run_event($1, 'run_queued', $2)")
        .bind(retry.id)
        .bind(json!({ "retry_of_run_id": original.id }))
        .execute(&mut *transaction)
        .await?;
    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace_id),
        "run.retried",
        "run",
        retry.id,
    )
    .await?;
    idempotency::complete(&mut transaction, &reservation, 201, &retry).await?;
    transaction.commit().await?;
    Ok((StatusCode::CREATED, Json(retry)).into_response())
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct RunEventResponse {
    pub id: Uuid,
    pub run_id: Uuid,
    pub session_event_id: Option<Uuid>,
    pub sequence: i64,
    pub schema_version: i16,
    pub event_type: String,
    pub payload: Value,
    pub occurred_at: OffsetDateTime,
}

pub async fn list_run_events(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, run_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<EventQuery>,
) -> Result<Json<Vec<RunEventResponse>>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let limit = event_limit(query.limit)?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
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
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    load_run(&mut transaction, auth.organization_id, workspace_id, run_id).await?;
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
        &stream.state.database,
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

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct RunUsageResponse {
    pub id: Uuid,
    pub run_id: Uuid,
    pub provider_request_id: String,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub cache_tokens: i64,
    pub occurred_at: OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RunUsageSummaryResponse {
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub cache_tokens: i64,
    pub entries: Vec<RunUsageResponse>,
}

pub async fn get_run_usage(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, run_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<RunUsageSummaryResponse>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
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

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct ApprovalResponse {
    pub id: Uuid,
    pub run_id: Uuid,
    pub tool_call_id: Uuid,
    pub status: String,
    pub requested_at: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
    pub decided_at: Option<OffsetDateTime>,
    pub decided_by: Option<Uuid>,
    pub reason: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ApprovalQuery {
    pub status: Option<String>,
}

pub async fn list_approvals(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    Query(query): Query<ApprovalQuery>,
) -> Result<Json<Vec<ApprovalResponse>>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ApproveTool)?;
    let status = query.status.as_deref().unwrap_or("pending");
    if !matches!(
        status,
        "all" | "pending" | "approved" | "rejected" | "expired" | "canceled"
    ) {
        return Err(ApiError::Validation(
            "approval status is invalid".to_owned(),
        ));
    }
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let approvals = sqlx::query_as::<_, ApprovalResponse>(
        "select id, run_id, tool_call_id, status, requested_at, expires_at,
                decided_at, decided_by, reason
         from approvals
         where organization_id = $1 and workspace_id = $2
           and ($3 = 'all' or status = $3)
         order by requested_at, id limit 200",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(status)
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(approvals))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DecideApprovalRequest {
    pub reason: Option<String>,
}

pub async fn approve(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, approval_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<DecideApprovalRequest>,
) -> Result<StatusCode, ApiError> {
    decide_approval(state, auth, workspace_id, approval_id, true, request.reason).await
}

pub async fn reject(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, approval_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<DecideApprovalRequest>,
) -> Result<StatusCode, ApiError> {
    decide_approval(
        state,
        auth,
        workspace_id,
        approval_id,
        false,
        request.reason,
    )
    .await
}

#[allow(clippy::too_many_lines)] // One transaction owns the approval and paired session event.
async fn decide_approval(
    state: AppState,
    auth: AuthContext,
    workspace_id: Uuid,
    approval_id: Uuid,
    approved: bool,
    reason: Option<String>,
) -> Result<StatusCode, ApiError> {
    auth.require_workspace(workspace_id, Permission::ApproveTool)?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let row = sqlx::query_as::<_, (Uuid, Uuid, Uuid, String)>(
        "select a.run_id, a.tool_call_id, r.session_id, t.call_key
         from approvals a
         join runs r on r.id = a.run_id
         join tool_calls t on t.id = a.tool_call_id
         where a.id = $1 and a.organization_id = $2 and a.workspace_id = $3
           and a.status = 'pending'
         for update of a, r",
    )
    .bind(approval_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(ApiError::Conflict(
        "approval is no longer pending".to_owned(),
    ))?;
    let status = if approved { "approved" } else { "rejected" };
    sqlx::query(
        "update approvals set status = $1, decided_at = now(), decided_by = $2, reason = $3
         where id = $4",
    )
    .bind(status)
    .bind(auth.user_id)
    .bind(reason)
    .bind(approval_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query("update tool_calls set status = $1, finished_at = case when $1 = 'denied' then now() else finished_at end where id = $2")
        .bind(if approved { "ready" } else { "denied" })
        .bind(row.1)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "update runs set status = 'queued', available_at = now(), updated_at = now()
         where id = $1 and status = 'waiting_approval'",
    )
    .bind(row.0)
    .execute(&mut *transaction)
    .await?;
    let session_event = sqlx::query_as::<_, AppendedEventResponse>(
        "select * from zeus_private.append_session_event($1, 'approval_result', $2, $3, $4, $5)",
    )
    .bind(row.2)
    .bind(actor_kind(&auth))
    .bind(auth.principal_id)
    .bind(json!({ "approval_id": approval_id, "approved": approved }))
    .bind(row.0)
    .fetch_one(&mut *transaction)
    .await?;
    sqlx::query("select * from zeus_private.append_run_event($1, 'approval_resolved', $2, $3)")
        .bind(row.0)
        .bind(json!({ "approval_id": approval_id, "approved": approved }))
        .bind(session_event.event_id)
        .execute(&mut *transaction)
        .await?;
    if !approved {
        let tool_result = sqlx::query_as::<_, AppendedEventResponse>(
            "select * from zeus_private.append_session_event(
                $1, 'tool_result', 'system', null, $2, $3
             )",
        )
        .bind(row.2)
        .bind(json!({
            "call_id": row.3,
            "result": { "code": "approval_rejected" },
            "synthetic": true,
            "tool_call_id": row.1,
        }))
        .bind(row.0)
        .fetch_one(&mut *transaction)
        .await?;
        sqlx::query("select * from zeus_private.append_run_event($1, 'tool.result', $2, $3)")
            .bind(row.0)
            .bind(json!({
                "tool_call_id": row.1,
                "call_id": row.3,
                "status": "denied",
                "synthetic": true,
            }))
            .bind(tool_result.event_id)
            .execute(&mut *transaction)
            .await?;
    }
    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace_id),
        if approved {
            "approval.approved"
        } else {
            "approval.rejected"
        },
        "approval",
        approval_id,
    )
    .await?;
    transaction.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/workspaces/{workspace_id}/sessions",
            get(list_sessions).post(create_session),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/sessions/{session_id}",
            get(get_session),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/sessions/{session_id}/messages",
            post(submit_message),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/sessions/{session_id}/events",
            get(list_session_events),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/runs",
            get(list_runs).post(create_run),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/runs/{run_id}",
            get(get_run),
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
            "/api/v1/workspaces/{workspace_id}/runs/{run_id}/cancel",
            post(cancel_run),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/runs/{run_id}/retry",
            post(retry_run),
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
        .route(
            "/api/v1/workspaces/{workspace_id}/approvals",
            get(list_approvals),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/approvals/{approval_id}/approve",
            post(approve),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/approvals/{approval_id}/reject",
            post(reject),
        )
}

async fn load_run(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: Uuid,
    workspace_id: Uuid,
    run_id: Uuid,
) -> Result<RunResponse, ApiError> {
    sqlx::query_as::<_, RunResponse>(
        "select id, organization_id, workspace_id, workflow_version_id, work_item_id,
                session_id, parent_run_id, retry_of_run_id, status, input, output,
                error_code, error_detail, attempt_count, cancel_requested_at,
                started_at, finished_at, created_at, updated_at
         from runs where id = $1 and organization_id = $2 and workspace_id = $3",
    )
    .bind(run_id)
    .bind(organization_id)
    .bind(workspace_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(Into::into)
}

fn actor_kind(auth: &AuthContext) -> &'static str {
    match auth.principal_kind {
        PrincipalKind::User => "user",
        PrincipalKind::ServiceAccount => "service_account",
    }
}

fn event_limit(value: Option<u16>) -> Result<i64, ApiError> {
    let value = value.unwrap_or(100);
    if !(1..=500).contains(&value) {
        return Err(ApiError::Validation(
            "event limit must be between 1 and 500".to_owned(),
        ));
    }
    Ok(i64::from(value))
}

fn last_event_sequence(headers: &HeaderMap) -> Result<i64, ApiError> {
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

fn json_response(status: u16, body: Value) -> Result<Response, ApiError> {
    let status = StatusCode::from_u16(status).map_err(|_| ApiError::Internal)?;
    Ok((status, Json(body)).into_response())
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

fn empty_object() -> Value {
    json!({})
}

fn user_message_kind() -> String {
    "user_message".to_owned()
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};

    use super::{event_limit, last_event_sequence};

    #[test]
    fn event_limits_are_bounded() {
        assert_eq!(event_limit(None).unwrap(), 100);
        assert!(event_limit(Some(0)).is_err());
        assert!(event_limit(Some(501)).is_err());
    }

    #[test]
    fn last_event_id_uses_the_event_sequence() {
        let mut headers = HeaderMap::new();
        headers.insert("last-event-id", HeaderValue::from_static("42"));
        assert_eq!(last_event_sequence(&headers).unwrap(), 42);
    }
}
