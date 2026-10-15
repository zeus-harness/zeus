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
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
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
    let mut approvals = sqlx::query_as::<_, ApprovalResponse>(
        "select a.id, a.run_id, a.tool_call_id, a.status, a.requested_at, a.expires_at,
                a.decided_at, a.decided_by, a.reason, a.kind, a.requested_by, a.authorized_until, a.revoked_at
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
    set_decision_permissions(&auth, &mut approvals);
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
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    // All approval/expiry/finish paths lock the Run before its approval rows.
    let eligible: Option<Uuid> = sqlx::query_scalar(
        "select r.id from runs r join approvals a on a.run_id = r.id
         where a.id = $1 and r.organization_id = $2 and r.workspace_id = $3
           and r.status in ('queued', 'running', 'waiting_approval') and r.cancel_requested_at is null
           and (r.deadline_at is null or r.deadline_at > clock_timestamp())
           and (r.wait_expires_at is null or r.wait_expires_at > clock_timestamp())
         for update of r",
    )
    .bind(approval_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .fetch_optional(&mut *transaction)
    .await?;
    if eligible.is_none() {
        return Err(ApiError::Conflict(
            "run is no longer awaiting this decision".to_owned(),
        ));
    }
    let row = sqlx::query_as::<_, (Uuid, Uuid, Uuid, String, String, Option<Uuid>)>(
        "select a.run_id, a.tool_call_id, r.session_id, t.call_key, a.kind, a.requested_by
         from approvals a
         join runs r on r.id = a.run_id
         join tool_calls t on t.id = a.tool_call_id
         where a.id = $1 and a.organization_id = $2 and a.workspace_id = $3
           and a.status = 'pending' and (a.expires_at is null or a.expires_at > clock_timestamp())
           and (r.deadline_at is null or r.deadline_at > clock_timestamp())
           and (r.wait_expires_at is null or r.wait_expires_at > clock_timestamp())
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
    if !decision_allowed(&auth, &row.4, row.5) {
        return Err(ApiError::Forbidden);
    }
    if approved && row.4 == "execution" {
        let access_valid: bool = sqlx::query_scalar("select not exists(select 1 from approvals where tool_call_id=$1 and kind='resource_access' and (status <> 'approved' or revoked_at is not null or authorized_until <= now()))")
            .bind(row.1).fetch_one(&mut *transaction).await?;
        if !access_valid {
            return Err(ApiError::Conflict(
                "resource authorization is no longer valid".to_owned(),
            ));
        }
    }
    if row.4 == "resource_access" && reason.as_ref().is_none_or(|value| value.trim().is_empty()) {
        return Err(ApiError::Validation(
            "resource authorization requires a reason".to_owned(),
        ));
    }
    let status = if approved { "approved" } else { "rejected" };
    sqlx::query(
        "update approvals set status = $1, decided_at = now(), decided_by = $2, reason = $3
          , authorized_until = case when kind = 'resource_access' and $1 = 'approved'
             then least(expires_at, now() + interval '1 hour') else authorized_until end
         where id = $4",
    )
    .bind(status)
    .bind(auth.user_id)
    .bind(reason)
    .bind(approval_id)
    .execute(&mut *transaction)
    .await?;
    let awaiting_execution = approved && row.4 == "resource_access";
    if awaiting_execution {
        sqlx::query("insert into approvals(organization_id,workspace_id,run_id,tool_call_id,kind,requested_by,input_snapshot,capability_revision,binding_revision,expires_at)
            select organization_id,workspace_id,run_id,tool_call_id,'execution',requested_by,input_snapshot,capability_revision,binding_revision,least(expires_at,authorized_until)
            from approvals where id=$1")
            .bind(approval_id).execute(&mut *transaction).await?;
    }
    sqlx::query("update tool_calls set status = $1, finished_at = case when $1 = 'denied' then now() else finished_at end where id = $2")
        .bind(if awaiting_execution { "pending_approval" } else if approved { "ready" } else { "denied" })
        .bind(row.1)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "update runs set status = 'queued', available_at = now(), updated_at = now()
         where id = $1 and status = 'waiting_approval' and not $2",
    )
    .bind(row.0)
    .bind(awaiting_execution)
    .execute(&mut *transaction)
    .await?;
    let session_event = sqlx::query_as::<_, AppendedEventResponse>(
        "select * from zeus_private.append_session_event($1, 'approval_result', $2, $3, $4, $5)",
    )
    .bind(row.2)
    .bind(actor_kind(&auth))
    .bind(auth.principal_id)
    .bind(json!({ "approval_id": approval_id, "approved": approved, "kind": row.4, "awaiting_execution_confirmation": awaiting_execution }))
    .bind(row.0)
    .fetch_one(&mut *transaction)
    .await?;
    sqlx::query("select * from zeus_private.append_run_event($1, 'approval_resolved', $2, $3)")
        .bind(row.0)
        .bind(json!({ "approval_id": approval_id, "approved": approved, "kind": row.4, "awaiting_execution_confirmation": awaiting_execution }))
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

fn decision_allowed(auth: &AuthContext, kind: &str, requester: Option<Uuid>) -> bool {
    zeus_core::can_decide_approval(
        kind,
        auth.user_id,
        requester,
        auth.workspace_role,
        auth.tenant_access_grant_id.is_some(),
    )
}

pub(super) fn set_decision_permissions(auth: &AuthContext, approvals: &mut [ApprovalResponse]) {
    for approval in approvals {
        approval.can_decide = decision_allowed(auth, &approval.kind, approval.requested_by);
    }
}

#[utoipa::path(post, path = "/api/v1/workspaces/{workspace_id}/approvals/{approval_id}/revoke", operation_id = "revoke_resource_authorization", tag = "approvals",
    params(("workspace_id" = Uuid, Path), ("approval_id" = Uuid, Path)),
    request_body = DecideApprovalRequest,
    responses((status = 204, description = "Resource authorization revoked before execution"))) ]
pub async fn revoke(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, approval_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<DecideApprovalRequest>,
) -> Result<StatusCode, ApiError> {
    auth.require_workspace(workspace_id, Permission::ManageWorkspace)?;
    if !decision_allowed(&auth, "resource_access", None) {
        return Err(ApiError::Forbidden);
    }
    if request
        .reason
        .as_ref()
        .is_none_or(|value| value.trim().is_empty())
    {
        return Err(ApiError::Validation(
            "revocation requires a reason".to_owned(),
        ));
    }
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    // Serialize with claim/start/decision. Revocation cannot undo an already started operation.
    sqlx::query(
        "select r.id from runs r join approvals a on a.run_id=r.id where a.id=$1 for update of r",
    )
    .bind(approval_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let affected = sqlx::query("update approvals a set revoked_at=now(), revoked_by=$2
        where a.id=$1 and a.kind='resource_access' and a.status='approved' and a.revoked_at is null
        and exists(select 1 from tool_calls t where t.id=a.tool_call_id and t.status in ('pending_approval','ready'))")
        .bind(approval_id).bind(auth.user_id).execute(&mut *transaction).await?.rows_affected();
    if affected != 1 {
        return Err(ApiError::Conflict(
            "authorization unavailable or operation already started".to_owned(),
        ));
    }
    let call: (Uuid, Uuid, Uuid, String) = sqlx::query_as("select a.run_id,a.tool_call_id,r.session_id,t.call_key from approvals a join runs r on r.id=a.run_id join tool_calls t on t.id=a.tool_call_id where a.id=$1")
        .bind(approval_id).fetch_one(&mut *transaction).await?;
    sqlx::query("update approvals set status='canceled', decided_at=now(), reason='resource_authorization_revoked' where tool_call_id=$1 and status='pending'")
        .bind(call.1).execute(&mut *transaction).await?;
    sqlx::query("update tool_calls set status='denied', finished_at=now(), error_code='resource_authorization_revoked' where id=$1")
        .bind(call.1).execute(&mut *transaction).await?;
    let event = sqlx::query_as::<_, AppendedEventResponse>("select * from zeus_private.append_session_event($1,'tool_result','system',null,$2,$3)")
        .bind(call.2).bind(json!({"call_id":call.3,"tool_call_id":call.1,"synthetic":true,"result":{"code":"resource_authorization_revoked"}})).bind(call.0)
        .fetch_one(&mut *transaction).await?;
    sqlx::query("select * from zeus_private.append_run_event($1,'tool.result',$2,$3)")
        .bind(call.0).bind(json!({"tool_call_id":call.1,"status":"denied","synthetic":true,"error_code":"resource_authorization_revoked"})).bind(event.event_id)
        .execute(&mut *transaction).await?;
    sqlx::query("update runs set status='queued',available_at=now(),updated_at=now() where id=$1 and status='waiting_approval'")
        .bind(call.0).execute(&mut *transaction).await?;
    sqlx::query("insert into audit_events(organization_id,workspace_id,actor_kind,actor_id,action,target_type,target_id,metadata)
        values($1,$2,'user',$3,'approval.authorization_revoked','approval',$4,jsonb_build_object('reason',$5::text))")
        .bind(auth.organization_id).bind(workspace_id).bind(auth.user_id).bind(approval_id).bind(request.reason)
        .execute(&mut *transaction).await?;
    transaction.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/workspaces/{workspace_id}/approvals/{approval_id}/revoke",
            post(revoke),
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
