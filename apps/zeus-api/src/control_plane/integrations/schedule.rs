use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    AppState,
    api_support::{ListCursor, PageQuery, required_revision},
    auth::{AuthContext, insert_audit},
    database::begin_tenant,
    error::ApiError,
};

use super::{
    default_enabled, default_timezone, empty_object, ensure_active_workflow, etag_headers,
    load_schedule, require_object, validate_cron_expression, validate_name,
    validate_schedule_request, validate_timezone,
};
use zeus_core::Permission;

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct ScheduleResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub workspace_id: Uuid,
    pub workflow_id: Uuid,
    pub name: String,
    pub cron_expression: String,
    pub timezone: String,
    pub input: Value,
    pub enabled: bool,
    pub next_run_at: Option<OffsetDateTime>,
    pub revision: i64,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SchedulePageResponse {
    pub items: Vec<ScheduleResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateScheduleRequest {
    pub workflow_id: Uuid,
    pub name: String,
    pub cron_expression: String,
    #[serde(default = "default_timezone")]
    pub timezone: String,
    #[serde(default = "empty_object")]
    pub input: Value,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub next_run_at: Option<OffsetDateTime>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateScheduleRequest {
    pub workflow_id: Option<Uuid>,
    pub name: Option<String>,
    pub cron_expression: Option<String>,
    pub timezone: Option<String>,
    pub input: Option<Value>,
    pub enabled: Option<bool>,
    pub next_run_at: Option<Option<OffsetDateTime>>,
}

pub async fn list_schedules(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<SchedulePageResponse>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let limit = page.limit()?;
    let cursor = page.decoded_cursor()?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let mut items = sqlx::query_as::<_, ScheduleResponse>(
        "select id, organization_id, workspace_id, workflow_id, name,
                cron_expression, timezone, input, enabled, next_run_at,
                revision, created_at, updated_at
         from schedules
         where organization_id = $1 and workspace_id = $2
           and ($3::timestamptz is null or (created_at, id) < ($3, $4))
         order by created_at desc, id desc
         limit $5",
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
    Ok(Json(SchedulePageResponse { items, next_cursor }))
}

pub async fn create_schedule(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    Json(request): Json<CreateScheduleRequest>,
) -> Result<(StatusCode, HeaderMap, Json<ScheduleResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::ManageWorkspace)?;
    validate_schedule_request(
        &request.name,
        &request.cron_expression,
        &request.timezone,
        &request.input,
    )?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    ensure_active_workflow(
        &mut transaction,
        auth.organization_id,
        workspace_id,
        request.workflow_id,
    )
    .await?;
    let schedule = sqlx::query_as::<_, ScheduleResponse>(
        "insert into schedules (
            organization_id, workspace_id, workflow_id, name,
            cron_expression, timezone, input, enabled, next_run_at
         ) values ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         returning id, organization_id, workspace_id, workflow_id, name,
                   cron_expression, timezone, input, enabled, next_run_at,
                   revision, created_at, updated_at",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(request.workflow_id)
    .bind(request.name.trim())
    .bind(request.cron_expression.trim())
    .bind(request.timezone.trim())
    .bind(request.input)
    .bind(request.enabled)
    .bind(request.next_run_at)
    .fetch_one(&mut *transaction)
    .await?;
    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace_id),
        "schedule.created",
        "schedule",
        schedule.id,
    )
    .await?;
    transaction.commit().await?;
    Ok((
        StatusCode::CREATED,
        etag_headers(schedule.revision)?,
        Json(schedule),
    ))
}

pub async fn get_schedule(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, schedule_id)): Path<(Uuid, Uuid)>,
) -> Result<(HeaderMap, Json<ScheduleResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let schedule = load_schedule(
        &mut transaction,
        auth.organization_id,
        workspace_id,
        schedule_id,
    )
    .await?;
    transaction.commit().await?;
    Ok((etag_headers(schedule.revision)?, Json(schedule)))
}

pub async fn update_schedule(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, schedule_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<UpdateScheduleRequest>,
) -> Result<(HeaderMap, Json<ScheduleResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::ManageWorkspace)?;
    let revision = required_revision(&headers)?;
    if let Some(name) = request.name.as_deref() {
        validate_name(name, "name", 160)?;
    }
    if let Some(cron_expression) = request.cron_expression.as_deref() {
        validate_cron_expression(cron_expression)?;
    }
    if let Some(timezone) = request.timezone.as_deref() {
        validate_timezone(timezone)?;
    }
    if let Some(input) = request.input.as_ref() {
        require_object(input, "input")?;
    }
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    if let Some(workflow_id) = request.workflow_id {
        ensure_active_workflow(
            &mut transaction,
            auth.organization_id,
            workspace_id,
            workflow_id,
        )
        .await?;
    }
    let schedule = sqlx::query_as::<_, ScheduleResponse>(
        "update schedules
         set workflow_id = coalesce($1, workflow_id),
             name = coalesce($2, name),
             cron_expression = coalesce($3, cron_expression),
             timezone = coalesce($4, timezone),
             input = coalesce($5, input),
             enabled = coalesce($6, enabled),
             next_run_at = case when $7 then $8 else next_run_at end,
             revision = revision + 1,
             updated_at = now()
         where id = $9 and organization_id = $10 and workspace_id = $11 and revision = $12
         returning id, organization_id, workspace_id, workflow_id, name,
                   cron_expression, timezone, input, enabled, next_run_at,
                   revision, created_at, updated_at",
    )
    .bind(request.workflow_id)
    .bind(request.name.map(|value| value.trim().to_owned()))
    .bind(request.cron_expression.map(|value| value.trim().to_owned()))
    .bind(request.timezone.map(|value| value.trim().to_owned()))
    .bind(request.input)
    .bind(request.enabled)
    .bind(request.next_run_at.is_some())
    .bind(request.next_run_at.flatten())
    .bind(schedule_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(revision)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(ApiError::PreconditionFailed)?;
    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace_id),
        "schedule.updated",
        "schedule",
        schedule_id,
    )
    .await?;
    transaction.commit().await?;
    Ok((etag_headers(schedule.revision)?, Json(schedule)))
}

pub async fn enable_schedule(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, schedule_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<ScheduleResponse>), ApiError> {
    set_schedule_enabled(state, auth, workspace_id, schedule_id, headers, true).await
}

pub async fn disable_schedule(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, schedule_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<ScheduleResponse>), ApiError> {
    set_schedule_enabled(state, auth, workspace_id, schedule_id, headers, false).await
}

async fn set_schedule_enabled(
    state: AppState,
    auth: AuthContext,
    workspace_id: Uuid,
    schedule_id: Uuid,
    headers: HeaderMap,
    enabled: bool,
) -> Result<(HeaderMap, Json<ScheduleResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::ManageWorkspace)?;
    let revision = required_revision(&headers)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let schedule = sqlx::query_as::<_, ScheduleResponse>(
        "update schedules
         set enabled = $1, revision = revision + 1, updated_at = now()
         where id = $2 and organization_id = $3 and workspace_id = $4 and revision = $5
         returning id, organization_id, workspace_id, workflow_id, name,
                   cron_expression, timezone, input, enabled, next_run_at,
                   revision, created_at, updated_at",
    )
    .bind(enabled)
    .bind(schedule_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(revision)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(ApiError::PreconditionFailed)?;
    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace_id),
        if enabled {
            "schedule.enabled"
        } else {
            "schedule.disabled"
        },
        "schedule",
        schedule_id,
    )
    .await?;
    transaction.commit().await?;
    Ok((etag_headers(schedule.revision)?, Json(schedule)))
}
