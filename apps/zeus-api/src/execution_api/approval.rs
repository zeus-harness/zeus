use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use serde_json::json;
use uuid::Uuid;
use zeus_core::Permission;

use crate::{
    AppState,
    auth::{AuthContext, insert_audit},
    database::begin_tenant,
    error::ApiError,
};

use super::shared::{
    actor_kind,
    types::{AppendedEventResponse, ApprovalQuery, ApprovalResponse, DecideApprovalRequest},
};

#[utoipa::path(get, path = "/api/v1/workspaces/{workspace_id}/approvals", tag = "approvals",
    params(
        ("workspace_id" = Uuid, Path),
        ("status" = Option<String>, Query, description = "Approval state; defaults to pending"),
        ("work_item_id" = Option<Uuid>, Query, description = "Only approvals linked to this WorkItem")
    ),
    responses((status = 200, description = "Workspace approvals", body = [ApprovalResponse]))
)]
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
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let approvals = sqlx::query_as::<_, ApprovalResponse>(
        "select a.id, a.run_id, a.tool_call_id, a.status, a.requested_at, a.expires_at,
                a.decided_at, a.decided_by, a.reason
         from approvals a
         join runs r on r.id = a.run_id
           and r.organization_id = a.organization_id and r.workspace_id = a.workspace_id
         where a.organization_id = $1 and a.workspace_id = $2
           and ($3 = 'all' or a.status = $3)
           and ($4::uuid is null or r.work_item_id = $4)
         order by a.requested_at, a.id limit 200",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(status)
    .bind(query.work_item_id)
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(approvals))
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
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
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

pub(super) fn routes() -> Router<AppState> {
    Router::new()
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
