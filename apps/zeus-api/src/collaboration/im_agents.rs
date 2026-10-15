//! Explicit, human-authorized Agent invocations in organization conversations.
#![allow(clippy::missing_errors_doc)]
use super::im::{ImId, db_error, tenant};
use crate::{AppState, auth::AuthContext, database::begin_tenant, error::ApiError};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Postgres, Transaction};
use utoipa::ToSchema;
use uuid::Uuid;
use zeus_core::Permission;

#[derive(Serialize, ToSchema, FromRow)]
pub struct ImAgentMember {
    pub id: Uuid,
    pub display_name: String,
    pub workspace_id: Uuid,
    pub workflow_version_id: Uuid,
    pub joined_sequence: i64,
}
#[derive(Serialize, ToSchema, FromRow)]
pub struct ImAgentCall {
    pub run_id: Uuid,
    pub agent_member_id: Uuid,
    pub source_message_id: Uuid,
    pub workspace_id: Uuid,
    pub status: String,
    pub work_item_id: Option<Uuid>,
}
#[derive(Serialize, ToSchema)]
pub struct ImAgentInvocation {
    pub id: Uuid,
    pub work_item_id: Option<Uuid>,
}
#[derive(Deserialize, ToSchema)]
pub struct ImAddAgent {
    pub workflow_version_id: Uuid,
}
#[derive(Deserialize, ToSchema)]
pub struct ImInvokeAgent {
    pub agent_member_id: Uuid,
    pub source_message_id: Uuid,
    /// Create a persistent business goal, independent of this execution attempt.
    #[serde(default)]
    pub create_work_item: bool,
}

pub(super) async fn members(
    tx: &mut Transaction<'_, Postgres>,
    conv: Uuid,
) -> Result<Vec<ImAgentMember>, ApiError> {
    Ok(sqlx::query_as("select id,display_name,workspace_id,workflow_version_id,joined_sequence from im_agent_members where conversation_id=$1 and left_at is null order by joined_at,id")
        .bind(conv).fetch_all(&mut **tx).await?)
}

pub async fn add(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace, conv)): Path<(Uuid, Uuid)>,
    Json(input): Json<ImAddAgent>,
) -> Result<Json<ImId>, ApiError> {
    auth.require_workspace(workspace, Permission::OperateRun)?;
    if auth.user_id.is_none() || auth.tenant_access_grant_id.is_some() {
        return Err(ApiError::Forbidden);
    }
    let mut tx = begin_tenant(&state.platform.database, auth.tenant_scope(Some(workspace))).await?;
    let id = sqlx::query_scalar("select zeus_private.im_add_agent($1,$2)")
        .bind(conv)
        .bind(input.workflow_version_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_error)?;
    tx.commit().await?;
    Ok(Json(ImId { id }))
}

pub async fn remove(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((org, conv, member)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<axum::http::StatusCode, ApiError> {
    let mut tx = tenant(&state, &auth, org).await?;
    sqlx::query("select zeus_private.im_remove_agent($1,$2)")
        .bind(conv)
        .bind(member)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    tx.commit().await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

pub async fn invoke(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace, conv)): Path<(Uuid, Uuid)>,
    headers: axum::http::HeaderMap,
    Json(input): Json<ImInvokeAgent>,
) -> Result<Json<ImAgentInvocation>, ApiError> {
    let request_key = format!("im:{}:{}", input.agent_member_id, input.source_message_id);
    if headers.get("idempotency-key").and_then(|v| v.to_str().ok()) != Some(request_key.as_str()) {
        return Err(ApiError::BadRequest(
            "Idempotency-Key must be im:<agent_member_id>:<source_message_id>".into(),
        ));
    }
    auth.require_workspace(workspace, Permission::OperateRun)?;
    if auth.user_id.is_none() || auth.tenant_access_grant_id.is_some() {
        return Err(ApiError::Forbidden);
    }
    let mut tx = begin_tenant(&state.platform.database, auth.tenant_scope(Some(workspace))).await?;
    // Same lock order as membership edits and result delivery. Retries cannot create a second Run.
    sqlx::query_scalar::<_, Uuid>("select zeus_private.im_lock_conversation($1)")
        .bind(conv)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_error)?;
    let version: Option<Uuid>=sqlx::query_scalar("select a.workflow_version_id from im_agent_members a join workflow_versions v on v.id=a.workflow_version_id join workflows w on w.id=v.workflow_id join agent_versions av on av.id=v.agent_version_id join agents ag on ag.id=av.agent_id where a.id=$1 and a.conversation_id=$2 and a.workspace_id=$3 and a.left_at is null and w.archived_at is null and ag.archived_at is null")
        .bind(input.agent_member_id).bind(conv).bind(workspace).fetch_optional(&mut *tx).await?;
    let version = version.ok_or(ApiError::Forbidden)?;
    let content: Option<String>=sqlx::query_scalar("select m.content from im_messages m join im_agent_members a on a.id=$1 where m.id=$2 and m.conversation_id=$3 and m.sender_id is not null and m.sequence>=a.joined_sequence")
        .bind(input.agent_member_id).bind(input.source_message_id).bind(conv).fetch_optional(&mut *tx).await?;
    let content = content.ok_or(ApiError::Forbidden)?;
    let prior: Option<(Uuid, Option<Uuid>)> = sqlx::query_as(
        "select l.run_id,r.work_item_id from im_agent_runs l join runs r on r.id=l.run_id
         where l.agent_member_id=$1 and l.source_message_id=$2",
    )
    .bind(input.agent_member_id)
    .bind(input.source_message_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((id, work_item_id)) = prior {
        if work_item_id.is_some() != input.create_work_item {
            return Err(ApiError::IdempotencyConflict);
        }
        tx.commit().await?;
        return Ok(Json(ImAgentInvocation { id, work_item_id }));
    }
    let work_item_id = if input.create_work_item {
        // Only server-loaded source content becomes the goal. No client-supplied title/body.
        let title: String = content
            .lines()
            .next()
            .unwrap_or("群聊任务")
            .chars()
            .take(120)
            .collect();
        let id = sqlx::query_scalar(
            "insert into work_items(organization_id,workspace_id,title,description,status,source_kind,
              external_reference,idempotency_key,created_by)
             values($1,$2,$3,$4,'in_progress','im_agent',$5,$6,$7) returning id",
        )
        .bind(auth.organization_id).bind(workspace).bind(title).bind(&content)
        .bind(format!("im:{conv}:{}", input.source_message_id)).bind(&request_key).bind(auth.user_id)
        .fetch_one(&mut *tx).await?;
        crate::auth::insert_audit(
            &mut tx,
            &auth,
            Some(workspace),
            "work_item.created_from_message",
            "work_item",
            id,
        )
        .await?;
        Some(id)
    } else {
        None
    };
    let message = format!(
        "这是群聊成员明确交给你的单条消息。只处理下述消息，不假设可以读取其他聊天历史。回复会分享给有权查看原消息的会话成员。创建工作项或流程时仅提出草稿。\n\n{content}"
    );
    let run = crate::execution_api::insert_conversation_run(
        &mut tx,
        &auth,
        workspace,
        version,
        &message,
        &request_key,
        work_item_id,
    )
    .await?;
    sqlx::query("select zeus_private.im_link_agent_run($1,$2,$3)")
        .bind(input.agent_member_id)
        .bind(input.source_message_id)
        .bind(run.id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    tx.commit().await?;
    Ok(Json(ImAgentInvocation {
        id: run.id,
        work_item_id,
    }))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/workspaces/{workspace_id}/im/conversations/{conversation_id}/agents",post(add))
        .route("/api/v1/workspaces/{workspace_id}/im/conversations/{conversation_id}/agent-calls",post(invoke))
        .route("/api/v1/organizations/{organization_id}/im/conversations/{conversation_id}/agents/{agent_member_id}",axum::routing::delete(remove))
}
