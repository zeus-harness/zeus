#![allow(clippy::missing_errors_doc)] // HTTP failures use the shared Problem Details contract.

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::FromRow;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;
use zeus_core::Permission;

use crate::{
    AppState,
    api_support::{ListCursor, PageQuery, required_revision, revision_etag},
    auth::{AuthContext, insert_audit},
    database::begin_tenant,
    error::ApiError,
};

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct AgentResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub workspace_id: Uuid,
    pub name: String,
    pub description: String,
    pub active_version_id: Option<Uuid>,
    pub revision: i64,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub archived_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AgentPageResponse {
    pub items: Vec<AgentResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateAgentRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateAgentRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub archived: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct AgentVersionResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub workspace_id: Uuid,
    pub agent_id: Uuid,
    pub version_number: i32,
    pub instructions: String,
    pub configuration: Value,
    pub created_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateAgentVersionRequest {
    pub instructions: String,
    #[serde(default = "empty_object")]
    pub configuration: Value,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ActivateVersionRequest {
    pub version_id: Uuid,
}

pub async fn list_agents(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<AgentPageResponse>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let limit = page.limit()?;
    let cursor = page.decoded_cursor()?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let mut items = sqlx::query_as::<_, AgentResponse>(
        "select id, organization_id, workspace_id, name, description, active_version_id,
                revision, created_at, updated_at, archived_at
         from agents
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
    Ok(Json(AgentPageResponse { items, next_cursor }))
}

pub async fn create_agent(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    Json(request): Json<CreateAgentRequest>,
) -> Result<(StatusCode, Json<AgentResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::BuildWorkflow)?;
    validate_name(&request.name)?;
    if request.description.len() > 8_000 {
        return Err(ApiError::Validation("description is too long".to_owned()));
    }
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let agent = sqlx::query_as::<_, AgentResponse>(
        "insert into agents (organization_id, workspace_id, name, description)
         values ($1, $2, $3, $4)
         returning id, organization_id, workspace_id, name, description, active_version_id,
                   revision, created_at, updated_at, archived_at",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(request.name.trim())
    .bind(request.description)
    .fetch_one(&mut *transaction)
    .await?;
    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace_id),
        "agent.created",
        "agent",
        agent.id,
    )
    .await?;
    transaction.commit().await?;
    Ok((StatusCode::CREATED, Json(agent)))
}

pub async fn get_agent(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, agent_id)): Path<(Uuid, Uuid)>,
) -> Result<(HeaderMap, Json<AgentResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let agent = load_agent(
        &mut transaction,
        auth.organization_id,
        workspace_id,
        agent_id,
    )
    .await?;
    transaction.commit().await?;
    let mut headers = HeaderMap::new();
    headers.insert(header::ETAG, revision_etag(agent.revision)?);
    Ok((headers, Json(agent)))
}

pub async fn update_agent(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, agent_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<UpdateAgentRequest>,
) -> Result<(HeaderMap, Json<AgentResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::BuildWorkflow)?;
    let revision = required_revision(&headers)?;
    if let Some(name) = request.name.as_deref() {
        validate_name(name)?;
    }
    if request
        .description
        .as_ref()
        .is_some_and(|value| value.len() > 8_000)
    {
        return Err(ApiError::Validation("description is too long".to_owned()));
    }
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let agent = sqlx::query_as::<_, AgentResponse>(
        "update agents
         set name = coalesce($1, name), description = coalesce($2, description),
             archived_at = case when $3 = true then coalesce(archived_at, now())
                                when $3 = false then null else archived_at end,
             revision = revision + 1, updated_at = now()
         where id = $4 and organization_id = $5 and workspace_id = $6 and revision = $7
         returning id, organization_id, workspace_id, name, description, active_version_id,
                   revision, created_at, updated_at, archived_at",
    )
    .bind(request.name.map(|value| value.trim().to_owned()))
    .bind(request.description)
    .bind(request.archived)
    .bind(agent_id)
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
        "agent.updated",
        "agent",
        agent_id,
    )
    .await?;
    transaction.commit().await?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(header::ETAG, revision_etag(agent.revision)?);
    Ok((response_headers, Json(agent)))
}

pub async fn list_agent_versions(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, agent_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Vec<AgentVersionResponse>>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let versions = sqlx::query_as::<_, AgentVersionResponse>(
        "select id, organization_id, workspace_id, agent_id, version_number,
                instructions, configuration, created_by, created_at
         from agent_versions
         where organization_id = $1 and workspace_id = $2 and agent_id = $3
         order by version_number desc limit 200",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(agent_id)
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(versions))
}

pub async fn create_agent_version(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, agent_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<CreateAgentVersionRequest>,
) -> Result<(StatusCode, Json<AgentVersionResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::BuildWorkflow)?;
    if request.instructions.trim().is_empty() || request.instructions.len() > 200_000 {
        return Err(ApiError::Validation(
            "instructions must contain between 1 and 200000 characters".to_owned(),
        ));
    }
    require_object(&request.configuration, "configuration")?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    sqlx::query(
        "select id from agents where id = $1 and organization_id = $2 and workspace_id = $3
         and archived_at is null for update",
    )
    .bind(agent_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .fetch_one(&mut *transaction)
    .await?;
    let version_number: i32 = sqlx::query_scalar(
        "select coalesce(max(version_number), 0) + 1 from agent_versions where agent_id = $1",
    )
    .bind(agent_id)
    .fetch_one(&mut *transaction)
    .await?;
    let version = sqlx::query_as::<_, AgentVersionResponse>(
        "insert into agent_versions (
            organization_id, workspace_id, agent_id, version_number,
            instructions, configuration, created_by
         ) values ($1, $2, $3, $4, $5, $6, $7)
         returning id, organization_id, workspace_id, agent_id, version_number,
                   instructions, configuration, created_by, created_at",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(agent_id)
    .bind(version_number)
    .bind(request.instructions)
    .bind(request.configuration)
    .bind(auth.user_id)
    .fetch_one(&mut *transaction)
    .await?;
    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace_id),
        "agent_version.created",
        "agent_version",
        version.id,
    )
    .await?;
    transaction.commit().await?;
    Ok((StatusCode::CREATED, Json(version)))
}

pub async fn get_agent_version(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, agent_id, version_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<Json<AgentVersionResponse>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let version = sqlx::query_as::<_, AgentVersionResponse>(
        "select id, organization_id, workspace_id, agent_id, version_number,
                instructions, configuration, created_by, created_at
         from agent_versions
         where id = $1 and agent_id = $2 and organization_id = $3 and workspace_id = $4",
    )
    .bind(version_id)
    .bind(agent_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(version))
}

pub async fn activate_agent_version(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, agent_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<ActivateVersionRequest>,
) -> Result<(HeaderMap, Json<AgentResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::BuildWorkflow)?;
    let revision = required_revision(&headers)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let agent = sqlx::query_as::<_, AgentResponse>(
        "update agents set active_version_id = $1, revision = revision + 1, updated_at = now()
         where id = $2 and organization_id = $3 and workspace_id = $4 and revision = $5
         returning id, organization_id, workspace_id, name, description, active_version_id,
                   revision, created_at, updated_at, archived_at",
    )
    .bind(request.version_id)
    .bind(agent_id)
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
        "agent_version.activated",
        "agent_version",
        request.version_id,
    )
    .await?;
    transaction.commit().await?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(header::ETAG, revision_etag(agent.revision)?);
    Ok((response_headers, Json(agent)))
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct WorkflowResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub workspace_id: Uuid,
    pub name: String,
    pub description: String,
    pub active_version_id: Option<Uuid>,
    pub revision: i64,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub archived_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WorkflowPageResponse {
    pub items: Vec<WorkflowResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateWorkflowRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateWorkflowRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub archived: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct WorkflowVersionResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub workspace_id: Uuid,
    pub workflow_id: Uuid,
    pub version_number: i32,
    pub agent_version_id: Uuid,
    pub model_profile_id: Uuid,
    pub input_schema: Value,
    pub output_schema: Value,
    pub capability_policy: Value,
    pub approval_policy: Value,
    pub experience_policy: Value,
    pub max_steps: i32,
    pub max_runtime_seconds: i32,
    pub token_budget: Option<i64>,
    pub retry_policy: Value,
    pub created_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateWorkflowVersionRequest {
    pub agent_version_id: Uuid,
    pub model_profile_id: Uuid,
    #[serde(default = "empty_object")]
    pub input_schema: Value,
    #[serde(default = "empty_object")]
    pub output_schema: Value,
    #[serde(default = "empty_object")]
    pub capability_policy: Value,
    #[serde(default = "default_approval_policy")]
    pub approval_policy: Value,
    #[serde(default = "default_experience_policy")]
    pub experience_policy: Value,
    #[serde(default = "default_max_steps")]
    pub max_steps: i32,
    #[serde(default = "default_max_runtime_seconds")]
    pub max_runtime_seconds: i32,
    pub token_budget: Option<i64>,
    #[serde(default = "default_retry_policy")]
    pub retry_policy: Value,
}

pub async fn list_workflows(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<WorkflowPageResponse>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let limit = page.limit()?;
    let cursor = page.decoded_cursor()?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let mut items = sqlx::query_as::<_, WorkflowResponse>(
        "select id, organization_id, workspace_id, name, description, active_version_id,
                revision, created_at, updated_at, archived_at
         from workflows
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
    Ok(Json(WorkflowPageResponse { items, next_cursor }))
}

pub async fn create_workflow(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    Json(request): Json<CreateWorkflowRequest>,
) -> Result<(StatusCode, Json<WorkflowResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::BuildWorkflow)?;
    validate_name(&request.name)?;
    if request.description.len() > 8_000 {
        return Err(ApiError::Validation("description is too long".to_owned()));
    }
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let workflow = sqlx::query_as::<_, WorkflowResponse>(
        "insert into workflows (organization_id, workspace_id, name, description)
         values ($1, $2, $3, $4)
         returning id, organization_id, workspace_id, name, description, active_version_id,
                   revision, created_at, updated_at, archived_at",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(request.name.trim())
    .bind(request.description)
    .fetch_one(&mut *transaction)
    .await?;
    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace_id),
        "workflow.created",
        "workflow",
        workflow.id,
    )
    .await?;
    transaction.commit().await?;
    Ok((StatusCode::CREATED, Json(workflow)))
}

pub async fn get_workflow(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, workflow_id)): Path<(Uuid, Uuid)>,
) -> Result<(HeaderMap, Json<WorkflowResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let workflow = load_workflow(
        &mut transaction,
        auth.organization_id,
        workspace_id,
        workflow_id,
    )
    .await?;
    transaction.commit().await?;
    let mut headers = HeaderMap::new();
    headers.insert(header::ETAG, revision_etag(workflow.revision)?);
    Ok((headers, Json(workflow)))
}

pub async fn update_workflow(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, workflow_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<UpdateWorkflowRequest>,
) -> Result<(HeaderMap, Json<WorkflowResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::BuildWorkflow)?;
    let revision = required_revision(&headers)?;
    if let Some(name) = request.name.as_deref() {
        validate_name(name)?;
    }
    if request
        .description
        .as_ref()
        .is_some_and(|value| value.len() > 8_000)
    {
        return Err(ApiError::Validation("description is too long".to_owned()));
    }
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let workflow = sqlx::query_as::<_, WorkflowResponse>(
        "update workflows
         set name = coalesce($1, name), description = coalesce($2, description),
             archived_at = case when $3 = true then coalesce(archived_at, now())
                                when $3 = false then null else archived_at end,
             revision = revision + 1, updated_at = now()
         where id = $4 and organization_id = $5 and workspace_id = $6 and revision = $7
         returning id, organization_id, workspace_id, name, description, active_version_id,
                   revision, created_at, updated_at, archived_at",
    )
    .bind(request.name.map(|value| value.trim().to_owned()))
    .bind(request.description)
    .bind(request.archived)
    .bind(workflow_id)
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
        "workflow.updated",
        "workflow",
        workflow_id,
    )
    .await?;
    transaction.commit().await?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(header::ETAG, revision_etag(workflow.revision)?);
    Ok((response_headers, Json(workflow)))
}

pub async fn list_workflow_versions(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, workflow_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Vec<WorkflowVersionResponse>>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let versions = sqlx::query_as::<_, WorkflowVersionResponse>(
        "select id, organization_id, workspace_id, workflow_id, version_number,
                agent_version_id, model_profile_id, input_schema, output_schema,
                capability_policy, approval_policy, experience_policy, max_steps,
                max_runtime_seconds, token_budget, retry_policy, created_by, created_at
         from workflow_versions
         where organization_id = $1 and workspace_id = $2 and workflow_id = $3
         order by version_number desc limit 200",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(workflow_id)
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(versions))
}

pub async fn create_workflow_version(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, workflow_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<CreateWorkflowVersionRequest>,
) -> Result<(StatusCode, Json<WorkflowVersionResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::BuildWorkflow)?;
    validate_workflow_version(&request)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    sqlx::query(
        "select id from workflows
         where id = $1 and organization_id = $2 and workspace_id = $3 and archived_at is null
         for update",
    )
    .bind(workflow_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .fetch_one(&mut *transaction)
    .await?;
    let dependencies_valid: bool = sqlx::query_scalar(
        "select exists(
           select 1 from agent_versions a, model_profiles m
           where a.id = $1 and m.id = $2
             and a.organization_id = $3 and a.workspace_id = $4
             and m.organization_id = $3 and m.workspace_id = $4 and m.archived_at is null
         )",
    )
    .bind(request.agent_version_id)
    .bind(request.model_profile_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .fetch_one(&mut *transaction)
    .await?;
    if !dependencies_valid {
        return Err(ApiError::Validation(
            "agent_version_id or model_profile_id is outside the workspace".to_owned(),
        ));
    }
    let version_number: i32 = sqlx::query_scalar(
        "select coalesce(max(version_number), 0) + 1 from workflow_versions where workflow_id = $1",
    )
    .bind(workflow_id)
    .fetch_one(&mut *transaction)
    .await?;
    let version = sqlx::query_as::<_, WorkflowVersionResponse>(
        "insert into workflow_versions (
            organization_id, workspace_id, workflow_id, version_number,
            agent_version_id, model_profile_id, input_schema, output_schema,
            capability_policy, approval_policy, experience_policy, max_steps,
            max_runtime_seconds, token_budget, retry_policy, created_by
         ) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
         returning id, organization_id, workspace_id, workflow_id, version_number,
                   agent_version_id, model_profile_id, input_schema, output_schema,
                   capability_policy, approval_policy, experience_policy, max_steps,
                   max_runtime_seconds, token_budget, retry_policy, created_by, created_at",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(workflow_id)
    .bind(version_number)
    .bind(request.agent_version_id)
    .bind(request.model_profile_id)
    .bind(request.input_schema)
    .bind(request.output_schema)
    .bind(request.capability_policy)
    .bind(request.approval_policy)
    .bind(request.experience_policy)
    .bind(request.max_steps)
    .bind(request.max_runtime_seconds)
    .bind(request.token_budget)
    .bind(request.retry_policy)
    .bind(auth.user_id)
    .fetch_one(&mut *transaction)
    .await?;
    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace_id),
        "workflow_version.created",
        "workflow_version",
        version.id,
    )
    .await?;
    transaction.commit().await?;
    Ok((StatusCode::CREATED, Json(version)))
}

pub async fn get_workflow_version(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, workflow_id, version_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<Json<WorkflowVersionResponse>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let version = sqlx::query_as::<_, WorkflowVersionResponse>(
        "select id, organization_id, workspace_id, workflow_id, version_number,
                agent_version_id, model_profile_id, input_schema, output_schema,
                capability_policy, approval_policy, experience_policy, max_steps,
                max_runtime_seconds, token_budget, retry_policy, created_by, created_at
         from workflow_versions
         where id = $1 and workflow_id = $2 and organization_id = $3 and workspace_id = $4",
    )
    .bind(version_id)
    .bind(workflow_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(version))
}

pub async fn activate_workflow_version(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, workflow_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<ActivateVersionRequest>,
) -> Result<(HeaderMap, Json<WorkflowResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::BuildWorkflow)?;
    let revision = required_revision(&headers)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let workflow = sqlx::query_as::<_, WorkflowResponse>(
        "update workflows set active_version_id = $1, revision = revision + 1, updated_at = now()
         where id = $2 and organization_id = $3 and workspace_id = $4 and revision = $5
         returning id, organization_id, workspace_id, name, description, active_version_id,
                   revision, created_at, updated_at, archived_at",
    )
    .bind(request.version_id)
    .bind(workflow_id)
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
        "workflow_version.activated",
        "workflow_version",
        request.version_id,
    )
    .await?;
    transaction.commit().await?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(header::ETAG, revision_etag(workflow.revision)?);
    Ok((response_headers, Json(workflow)))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/workspaces/{workspace_id}/agents",
            get(list_agents).post(create_agent),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/agents/{agent_id}",
            get(get_agent).patch(update_agent),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/agents/{agent_id}/versions",
            get(list_agent_versions).post(create_agent_version),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/agents/{agent_id}/versions/{version_id}",
            get(get_agent_version),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/agents/{agent_id}/active-version",
            post(activate_agent_version),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/workflows",
            get(list_workflows).post(create_workflow),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/workflows/{workflow_id}",
            get(get_workflow).patch(update_workflow),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/workflows/{workflow_id}/versions",
            get(list_workflow_versions).post(create_workflow_version),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/workflows/{workflow_id}/versions/{version_id}",
            get(get_workflow_version),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/workflows/{workflow_id}/active-version",
            post(activate_workflow_version),
        )
}

async fn load_agent(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: Uuid,
    workspace_id: Uuid,
    agent_id: Uuid,
) -> Result<AgentResponse, ApiError> {
    sqlx::query_as::<_, AgentResponse>(
        "select id, organization_id, workspace_id, name, description, active_version_id,
                revision, created_at, updated_at, archived_at
         from agents where id = $1 and organization_id = $2 and workspace_id = $3",
    )
    .bind(agent_id)
    .bind(organization_id)
    .bind(workspace_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(Into::into)
}

async fn load_workflow(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: Uuid,
    workspace_id: Uuid,
    workflow_id: Uuid,
) -> Result<WorkflowResponse, ApiError> {
    sqlx::query_as::<_, WorkflowResponse>(
        "select id, organization_id, workspace_id, name, description, active_version_id,
                revision, created_at, updated_at, archived_at
         from workflows where id = $1 and organization_id = $2 and workspace_id = $3",
    )
    .bind(workflow_id)
    .bind(organization_id)
    .bind(workspace_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(Into::into)
}

fn validate_workflow_version(request: &CreateWorkflowVersionRequest) -> Result<(), ApiError> {
    for (value, name) in [
        (&request.input_schema, "input_schema"),
        (&request.output_schema, "output_schema"),
        (&request.capability_policy, "capability_policy"),
        (&request.approval_policy, "approval_policy"),
        (&request.experience_policy, "experience_policy"),
        (&request.retry_policy, "retry_policy"),
    ] {
        require_object(value, name)?;
    }
    if !(1..=1_024).contains(&request.max_steps) {
        return Err(ApiError::Validation(
            "max_steps must be between 1 and 1024".to_owned(),
        ));
    }
    if !(1..=86_400).contains(&request.max_runtime_seconds) {
        return Err(ApiError::Validation(
            "max_runtime_seconds must be between 1 and 86400".to_owned(),
        ));
    }
    if request.token_budget.is_some_and(|budget| budget <= 0) {
        return Err(ApiError::Validation(
            "token_budget must be positive".to_owned(),
        ));
    }
    Ok(())
}

fn validate_name(value: &str) -> Result<(), ApiError> {
    if value.trim().is_empty() || value.len() > 160 {
        return Err(ApiError::Validation(
            "name must contain between 1 and 160 characters".to_owned(),
        ));
    }
    Ok(())
}

fn require_object(value: &Value, field: &str) -> Result<(), ApiError> {
    if value.is_object() {
        Ok(())
    } else {
        Err(ApiError::Validation(format!(
            "{field} must be a JSON object"
        )))
    }
}

fn empty_object() -> Value {
    json!({})
}

fn default_approval_policy() -> Value {
    json!({ "require_high_risk": true, "fail_on_denial": false })
}

fn default_experience_policy() -> Value {
    json!({ "include_workspace": true, "include_organization": true, "max_entries": 8 })
}

const fn default_max_steps() -> i32 {
    32
}

const fn default_max_runtime_seconds() -> i32 {
    900
}

fn default_retry_policy() -> Value {
    json!({ "model_network_attempts": 2, "capability_attempts": 0 })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{CreateWorkflowVersionRequest, validate_workflow_version};

    #[test]
    fn workflow_limits_are_rejected_before_database_work() {
        let request = CreateWorkflowVersionRequest {
            agent_version_id: uuid::Uuid::now_v7(),
            model_profile_id: uuid::Uuid::now_v7(),
            input_schema: json!({}),
            output_schema: json!({}),
            capability_policy: json!({}),
            approval_policy: json!({}),
            experience_policy: json!({}),
            max_steps: 0,
            max_runtime_seconds: 900,
            token_budget: None,
            retry_policy: json!({}),
        };
        assert!(validate_workflow_version(&request).is_err());
    }
}
