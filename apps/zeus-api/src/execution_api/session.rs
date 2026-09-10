use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use serde_json::json;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;
use zeus_core::Permission;

use crate::{
    AppState,
    api_support::{ListCursor, PageQuery},
    auth::{AuthContext, insert_audit},
    database::begin_tenant,
    error::ApiError,
};

use super::shared::{
    actor_kind,
    types::{
        AppendedEventResponse, CreateSessionRequest, SessionPageResponse, SessionResponse,
        SubmitMessageRequest,
    },
};

pub async fn list_sessions(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<SessionPageResponse>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let limit = page.limit()?;
    let cursor = page.decoded_cursor()?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
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
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
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
    let session = insert_session(
        &mut transaction,
        &auth,
        workspace_id,
        request.work_item_id,
        &request.title,
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
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
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
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
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

pub(super) fn routes() -> Router<AppState> {
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
}

pub(super) async fn insert_session(
    transaction: &mut Transaction<'_, Postgres>,
    auth: &AuthContext,
    workspace_id: Uuid,
    work_item_id: Option<Uuid>,
    title: &str,
) -> Result<SessionResponse, ApiError> {
    let session = sqlx::query_as::<_, SessionResponse>(
        "insert into sessions (
            organization_id, workspace_id, work_item_id, title, created_by
         ) values ($1, $2, $3, $4, $5)
         returning id, organization_id, workspace_id, work_item_id, title, status,
                   created_by, created_at, updated_at, closed_at",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(work_item_id)
    .bind(title)
    .bind(auth.user_id)
    .fetch_one(&mut **transaction)
    .await?;
    insert_audit(
        transaction,
        auth,
        Some(workspace_id),
        "session.created",
        "session",
        session.id,
    )
    .await?;
    Ok(session)
}
