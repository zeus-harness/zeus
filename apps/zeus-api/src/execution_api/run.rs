use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;
use zeus_core::Permission;

use crate::{
    AppState,
    api_support::{ListCursor, PageQuery},
    auth::{AuthContext, insert_audit},
    database::begin_tenant,
    error::ApiError,
    idempotency::{self, IdempotencyDecision},
};

use super::{
    session,
    shared::{
        actor_kind, json_response,
        types::{
            CancelRunRequest, CreateRunRequest, RetryRunRequest, RunPageResponse, RunQuery,
            RunResponse, StartWorkItemRunRequest, WorkItemRunStartResponse,
        },
    },
};

struct NewRun<'a> {
    workflow_version_id: Uuid,
    session_id: Uuid,
    work_item_id: Option<Uuid>,
    input: &'a Value,
    message: Option<&'a str>,
    idempotency_key: &'a str,
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
    validate_run_input(&request.input, request.message.as_deref())?;
    let path = format!("/api/v1/workspaces/{workspace_id}/runs");
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
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
    let run = insert_run(
        &mut transaction,
        &auth,
        workspace_id,
        NewRun {
            workflow_version_id: request.workflow_version_id,
            session_id: request.session_id,
            work_item_id: request.work_item_id,
            input: &request.input,
            message: request.message.as_deref(),
            idempotency_key,
        },
    )
    .await?;
    idempotency::complete(&mut transaction, &reservation, 201, &run).await?;
    transaction.commit().await?;
    Ok((StatusCode::CREATED, Json(run)).into_response())
}

#[utoipa::path(post, path = "/api/v1/workspaces/{workspace_id}/work-items/{work_item_id}/runs", tag = "execution",
    params(("workspace_id" = Uuid, Path), ("work_item_id" = Uuid, Path), ("Idempotency-Key" = String, Header)),
    request_body = StartWorkItemRunRequest,
    responses((status = 201, description = "Linked session and queued Run", body = WorkItemRunStartResponse), (status = 409, description = "Workflow state or idempotency conflict"))
)]
pub async fn start_work_item_run(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, work_item_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<StartWorkItemRunRequest>,
) -> Result<Response, ApiError> {
    auth.require_workspace(workspace_id, Permission::OperateRun)?;
    validate_run_input(&request.input, request.message.as_deref())?;
    let path = format!("/api/v1/workspaces/{workspace_id}/work-items/{work_item_id}/runs");
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
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
    let dependency = sqlx::query_as::<_, (String, Option<Uuid>)>(
        "select wi.title, w.active_version_id
         from work_items wi
         cross join workflows w
         where wi.id = $1 and w.id = $2
           and wi.organization_id = $3 and wi.workspace_id = $4
           and w.organization_id = $3 and w.workspace_id = $4
           and w.archived_at is null",
    )
    .bind(work_item_id)
    .bind(request.workflow_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| {
        ApiError::Validation("work item or workflow is outside the workspace".to_owned())
    })?;
    let workflow_version_id = dependency
        .1
        .ok_or_else(|| ApiError::Conflict("workflow has no active version".to_owned()))?;
    let session = session::insert_session(
        &mut transaction,
        &auth,
        workspace_id,
        Some(work_item_id),
        &dependency.0,
    )
    .await?;
    let idempotency_key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::BadRequest("Idempotency-Key is required".to_owned()))?;
    let run = insert_run(
        &mut transaction,
        &auth,
        workspace_id,
        NewRun {
            workflow_version_id,
            session_id: session.id,
            work_item_id: Some(work_item_id),
            input: &request.input,
            message: request.message.as_deref(),
            idempotency_key,
        },
    )
    .await?;
    let response = WorkItemRunStartResponse { session, run };
    idempotency::complete(&mut transaction, &reservation, 201, &response).await?;
    transaction.commit().await?;
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

#[utoipa::path(get, path = "/api/v1/workspaces/{workspace_id}/runs", tag = "execution",
    params(
        ("workspace_id" = Uuid, Path),
        ("cursor" = Option<String>, Query, description = "Opaque pagination cursor"),
        ("limit" = Option<u16>, Query, description = "Page size from 1 to 100"),
        ("work_item_id" = Option<Uuid>, Query, description = "Only Runs linked to this WorkItem"),
        ("status" = Option<String>, Query, description = "Only Runs in this state")
    ),
    responses((status = 200, description = "Workspace Runs", body = RunPageResponse))
)]
pub async fn list_runs(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    Query(query): Query<RunQuery>,
) -> Result<Json<RunPageResponse>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    validate_run_status_filter(query.status.as_deref())?;
    let page = PageQuery {
        cursor: query.cursor,
        limit: query.limit,
    };
    let limit = page.limit()?;
    let cursor = page.decoded_cursor()?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let mut items = sqlx::query_as::<_, RunResponse>(
        "select id, organization_id, workspace_id, workflow_version_id, work_item_id,
                session_id, parent_run_id, retry_of_run_id, status, input, output,
                error_code, error_detail, attempt_count, cancel_requested_at,
                started_at, finished_at, created_at, updated_at
         from runs
         where organization_id = $1 and workspace_id = $2
           and ($3::uuid is null or work_item_id = $3)
           and ($4::text is null or status = $4)
           and ($5::timestamptz is null or (created_at, id) < ($5, $6))
         order by created_at desc, id desc limit $7",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(query.work_item_id)
    .bind(query.status)
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
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let run = load_run(&mut transaction, auth.organization_id, workspace_id, run_id).await?;
    transaction.commit().await?;
    Ok(Json(run))
}

pub async fn cancel_run(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, run_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<CancelRunRequest>,
) -> Result<StatusCode, ApiError> {
    auth.require_workspace(workspace_id, Permission::OperateRun)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
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

pub async fn retry_run(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, run_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<RetryRunRequest>,
) -> Result<Response, ApiError> {
    auth.require_workspace(workspace_id, Permission::OperateRun)?;
    let path = format!("/api/v1/workspaces/{workspace_id}/runs/{run_id}/retry");
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
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

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/workspaces/{workspace_id}/runs",
            get(list_runs).post(create_run),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/work-items/{work_item_id}/runs",
            post(start_work_item_run),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/runs/{run_id}",
            get(get_run),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/runs/{run_id}/cancel",
            post(cancel_run),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/runs/{run_id}/retry",
            post(retry_run),
        )
}

async fn insert_run(
    transaction: &mut Transaction<'_, Postgres>,
    auth: &AuthContext,
    workspace_id: Uuid,
    request: NewRun<'_>,
) -> Result<RunResponse, ApiError> {
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
    .bind(request.input)
    .bind(request.idempotency_key)
    .bind(auth.user_id)
    .fetch_one(&mut **transaction)
    .await?;
    let content = request.message.map_or_else(
        || serde_json::to_string(request.input).unwrap_or_else(|_| "{}".to_owned()),
        ToOwned::to_owned,
    );
    let session_event = sqlx::query_as::<_, super::shared::types::AppendedEventResponse>(
        "select * from zeus_private.append_session_event($1, 'user_message', $2, $3, $4, $5)",
    )
    .bind(request.session_id)
    .bind(actor_kind(auth))
    .bind(auth.principal_id)
    .bind(json!({ "content": content, "source": "run" }))
    .bind(run.id)
    .fetch_one(&mut **transaction)
    .await?;
    sqlx::query("select * from zeus_private.append_run_event($1, 'run_queued', $2, $3)")
        .bind(run.id)
        .bind(json!({ "attempt_count": 0 }))
        .bind(session_event.event_id)
        .execute(&mut **transaction)
        .await?;
    insert_audit(
        transaction,
        auth,
        Some(workspace_id),
        "run.created",
        "run",
        run.id,
    )
    .await?;
    Ok(run)
}

pub(super) fn validate_run_input(input: &Value, message: Option<&str>) -> Result<(), ApiError> {
    if !input.is_object() {
        return Err(ApiError::Validation(
            "input must be a JSON object".to_owned(),
        ));
    }
    if message.is_some_and(|value| value.trim().is_empty() || value.len() > 200_000) {
        return Err(ApiError::Validation(
            "message is empty or too long".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_run_status_filter(status: Option<&str>) -> Result<(), ApiError> {
    if status.is_some_and(|value| {
        !matches!(
            value,
            "queued"
                | "running"
                | "waiting_approval"
                | "waiting_child"
                | "succeeded"
                | "failed"
                | "canceled"
        )
    }) {
        return Err(ApiError::Validation("run status is invalid".to_owned()));
    }
    Ok(())
}

pub(super) async fn load_run(
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

#[cfg(test)]
mod tests {
    use axum::extract::Query;
    use http::Uri;

    use super::RunQuery;

    #[test]
    fn run_query_accepts_filters_and_pagination() {
        let work_item_id = uuid::Uuid::now_v7();
        let uri: Uri =
            format!("/runs?work_item_id={work_item_id}&status=waiting_approval&limit=10")
                .parse()
                .expect("query URI parses");
        let Query(query) = Query::<RunQuery>::try_from_uri(&uri).expect("query parses");

        assert_eq!(query.work_item_id, Some(work_item_id));
        assert_eq!(query.status.as_deref(), Some("waiting_approval"));
        assert_eq!(query.limit, Some(10));
        assert!(query.cursor.is_none());
    }
}
