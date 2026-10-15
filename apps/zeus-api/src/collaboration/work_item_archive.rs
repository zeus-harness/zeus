//! Human closure of a persistent goal, independent of tool approval or Run success.
#![allow(clippy::missing_errors_doc)]

use crate::{
    AppState,
    api_support::required_revision,
    auth::{AuthContext, insert_audit},
    database::begin_tenant,
    error::ApiError,
    idempotency::{self, IdempotencyDecision},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{FromRow, Postgres, Transaction};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;
use zeus_core::{Permission, WorkItemState, WorkspaceRole};

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct WorkItemArchiveResponse {
    pub id: Uuid,
    pub work_item_id: Uuid,
    pub run_id: Uuid,
    pub review_id: Uuid,
    pub workflow_version_id: Uuid,
    pub work_item_revision: i64,
    pub resolution_summary: String,
    pub archived_by: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct ArchiveWorkItemRequest {
    pub review_id: Uuid,
    pub resolution_summary: String,
}

const ARCHIVE_COLUMNS: &str = "id,work_item_id,run_id,review_id,workflow_version_id,work_item_revision,resolution_summary,archived_by,created_at";

pub async fn get_archive(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace, item)): Path<(Uuid, Uuid)>,
) -> Result<Json<WorkItemArchiveResponse>, ApiError> {
    auth.require_workspace(workspace, Permission::ReadWorkspace)?;
    let mut tx = begin_tenant(&state.platform.database, auth.tenant_scope(Some(workspace))).await?;
    let exists: bool = sqlx::query_scalar("select exists(select 1 from work_items where id=$1 and organization_id=$2 and workspace_id=$3)")
        .bind(item).bind(auth.organization_id).bind(workspace).fetch_one(&mut *tx).await?;
    if !exists {
        return Err(ApiError::NotFound);
    }
    let archive = sqlx::query_as(&format!("select {ARCHIVE_COLUMNS} from work_item_archives where work_item_id=$1 and organization_id=$2 and workspace_id=$3"))
        .bind(item).bind(auth.organization_id).bind(workspace).fetch_optional(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(archive.ok_or(ApiError::NotFound)?))
}

#[allow(clippy::too_many_lines)] // Goal lock, acceptance evidence, archival and audit commit together.
pub async fn archive(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace, item)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<ArchiveWorkItemRequest>,
) -> Result<Response, ApiError> {
    auth.require_workspace(workspace, Permission::OperateRun)?;
    if auth.workspace_role != Some(WorkspaceRole::Owner) || auth.tenant_access_grant_id.is_some() {
        return Err(ApiError::Forbidden);
    }
    let actor = auth.user_id.ok_or(ApiError::Forbidden)?;
    let revision = required_revision(&headers)?;
    if request.resolution_summary.trim().is_empty()
        || request.resolution_summary.chars().count() > 4000
    {
        return Err(ApiError::Validation(
            "resolution summary must contain 1 to 4000 characters".into(),
        ));
    }
    let mut tx = begin_tenant(&state.platform.database, auth.tenant_scope(Some(workspace))).await?;
    let path = format!("/api/v1/workspaces/{workspace}/work-items/{item}/archive");
    // Include If-Match in the payload identity. Lost responses can safely replay after completion.
    let reservation = match idempotency::begin(
        &mut tx,
        &auth,
        workspace,
        "POST",
        &path,
        &headers,
        &(revision, &request),
    )
    .await?
    {
        IdempotencyDecision::Replay { status, body } => {
            tx.commit().await?;
            return Ok((
                StatusCode::from_u16(status).map_err(|_| ApiError::Internal)?,
                Json(body),
            )
                .into_response());
        }
        IdempotencyDecision::New(value) => value,
    };
    let (status, current_revision, archived_at): (String, i64, Option<OffsetDateTime>) = sqlx::query_as("select status,revision,archived_at from work_items where id=$1 and organization_id=$2 and workspace_id=$3 for update")
        .bind(item).bind(auth.organization_id).bind(workspace).fetch_one(&mut *tx).await?;
    if current_revision != revision {
        return Err(ApiError::PreconditionFailed);
    }
    if archived_at.is_some() {
        return Err(ApiError::Conflict("work item is already archived".into()));
    }
    WorkItemState::try_from(status.as_str())
        .map_err(|_| ApiError::Internal)?
        .transition(WorkItemState::Completed)
        .map_err(|_| {
            ApiError::Conflict("work item cannot be completed from its current state".into())
        })?;
    // Recheck the real current Owner inside the write transaction; support/service identities cannot close goals.
    let owner: bool = sqlx::query_scalar("select exists(select 1 from workspace_memberships wm join organization_memberships om on om.organization_id=wm.organization_id and om.user_id=wm.user_id join users u on u.id=wm.user_id where wm.organization_id=$1 and wm.workspace_id=$2 and wm.user_id=$3 and wm.role='owner' and wm.status='active' and om.status='active' and u.status='active')")
        .bind(auth.organization_id).bind(workspace).bind(actor).fetch_one(&mut *tx).await?;
    if !owner {
        return Err(ApiError::Forbidden);
    }
    let (run_id, version, output) = accepted_latest_result(
        &mut tx,
        auth.organization_id,
        workspace,
        item,
        request.review_id,
        revision,
    )
    .await?;
    let record: WorkItemArchiveResponse = sqlx::query_as(&format!("insert into work_item_archives(organization_id,workspace_id,work_item_id,run_id,review_id,workflow_version_id,work_item_revision,resolution_summary,archived_by) values($1,$2,$3,$4,$5,$6,$7,$8,$9) returning {ARCHIVE_COLUMNS}"))
        .bind(auth.organization_id).bind(workspace).bind(item).bind(run_id).bind(request.review_id).bind(version).bind(revision).bind(request.resolution_summary.trim()).bind(actor)
        .fetch_one(&mut *tx).await?;
    sqlx::query("update work_items set status='completed',output=$4,completed_at=coalesce(completed_at,clock_timestamp()),archived_at=clock_timestamp(),revision=revision+1,updated_at=clock_timestamp() where id=$1 and organization_id=$2 and workspace_id=$3")
        .bind(item).bind(auth.organization_id).bind(workspace).bind(output).execute(&mut *tx).await?;
    insert_audit(
        &mut tx,
        &auth,
        Some(workspace),
        "work_item.archived",
        "work_item_archive",
        record.id,
    )
    .await?;
    idempotency::complete(&mut tx, &reservation, 201, &record).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(record)).into_response())
}

async fn accepted_latest_result(
    tx: &mut Transaction<'_, Postgres>,
    org: Uuid,
    workspace: Uuid,
    item: Uuid,
    review: Uuid,
    revision: i64,
) -> Result<(Uuid, Uuid, Value), ApiError> {
    let result = sqlx::query_as("select r.id,r.workflow_version_id,r.output
      from work_item_reviews v join runs r on r.id=v.run_id join sessions s on s.id=r.session_id
      where v.id=$4 and v.organization_id=$1 and v.workspace_id=$2 and v.work_item_id=$3
        and v.decision='accepted' and v.work_item_revision=$5-1
        and exists(select 1 from workspace_memberships where organization_id=$1 and workspace_id=$2
          and user_id=v.reviewed_by and role='owner' and status='active')
        and r.organization_id=$1 and r.workspace_id=$2 and r.work_item_id=$3
        and s.organization_id=$1 and s.workspace_id=$2 and s.work_item_id=$3
        and r.status='succeeded' and r.output is not null and r.output<>'null'::jsonb
        and r.id=(select id from runs where organization_id=$1 and workspace_id=$2 and work_item_id=$3 and parent_run_id is null order by created_at desc,id desc limit 1)
        and v.id=(select id from work_item_reviews where organization_id=$1 and workspace_id=$2 and work_item_id=$3 order by created_at desc,id desc limit 1)
        and not exists(select 1 from runs where organization_id=$1 and workspace_id=$2 and work_item_id=$3 and status not in ('succeeded','failed','canceled'))")
        .bind(org).bind(workspace).bind(item).bind(review).bind(revision).fetch_optional(&mut **tx).await?;
    result.ok_or_else(|| ApiError::Conflict("archive requires the latest successful attempt, current accepted review and no unfinished runs".into()))
}

pub fn routes() -> Router<AppState> {
    Router::new().route(
        "/api/v1/workspaces/{workspace_id}/work-items/{work_item_id}/archive",
        get(get_archive).post(archive),
    )
}
