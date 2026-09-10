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
    database::{TenantScope, begin_tenant},
    error::ApiError,
};

use super::{
    default_enabled, empty_object, ensure_active_capability, ensure_active_connection,
    etag_headers, require_object, validate_capability_definition_request,
    validate_capability_definition_update, validate_timeout_seconds,
    validate_workspace_capability_request,
};
use zeus_core::Permission;

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct CapabilityDefinitionResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub registry_key: String,
    pub display_name: String,
    pub description: String,
    pub input_schema: Value,
    pub output_schema: Value,
    pub idempotency_mode: String,
    pub risk_level: String,
    pub executor_key: String,
    pub revision: i64,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub archived_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CapabilityDefinitionPageResponse {
    pub items: Vec<CapabilityDefinitionResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCapabilityDefinitionRequest {
    pub registry_key: String,
    pub display_name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "empty_object")]
    pub input_schema: Value,
    #[serde(default = "empty_object")]
    pub output_schema: Value,
    pub idempotency_mode: String,
    pub risk_level: String,
    pub executor_key: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateCapabilityDefinitionRequest {
    pub registry_key: Option<String>,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub input_schema: Option<Value>,
    pub output_schema: Option<Value>,
    pub idempotency_mode: Option<String>,
    pub risk_level: Option<String>,
    pub executor_key: Option<String>,
    pub archived: Option<bool>,
}

pub async fn list_capability_definitions(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(organization_id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<CapabilityDefinitionPageResponse>, ApiError> {
    auth.require_organization(organization_id, Permission::ReadWorkspace)?;
    let limit = page.limit()?;
    let cursor = page.decoded_cursor()?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let mut items = sqlx::query_as::<_, CapabilityDefinitionResponse>(
        "select id, organization_id, registry_key, display_name, description,
                input_schema, output_schema, idempotency_mode, risk_level,
                executor_key, revision, created_at, updated_at, archived_at
         from capability_definitions
         where organization_id = $1
           and ($2::timestamptz is null or (created_at, id) < ($2, $3))
         order by created_at desc, id desc
         limit $4",
    )
    .bind(organization_id)
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
    Ok(Json(CapabilityDefinitionPageResponse {
        items,
        next_cursor,
    }))
}

pub async fn create_capability_definition(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(organization_id): Path<Uuid>,
    Json(request): Json<CreateCapabilityDefinitionRequest>,
) -> Result<(StatusCode, HeaderMap, Json<CapabilityDefinitionResponse>), ApiError> {
    auth.require_organization(organization_id, Permission::ManageOrganization)?;
    validate_capability_definition_request(
        &request.registry_key,
        &request.display_name,
        &request.description,
        &request.input_schema,
        &request.output_schema,
        &request.idempotency_mode,
        &request.risk_level,
        &request.executor_key,
    )?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let capability = sqlx::query_as::<_, CapabilityDefinitionResponse>(
        "insert into capability_definitions (
            organization_id, registry_key, display_name, description,
            input_schema, output_schema, idempotency_mode, risk_level, executor_key
         ) values ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         returning id, organization_id, registry_key, display_name, description,
                   input_schema, output_schema, idempotency_mode, risk_level,
                   executor_key, revision, created_at, updated_at, archived_at",
    )
    .bind(organization_id)
    .bind(request.registry_key.trim())
    .bind(request.display_name.trim())
    .bind(request.description)
    .bind(request.input_schema)
    .bind(request.output_schema)
    .bind(request.idempotency_mode.trim())
    .bind(request.risk_level.trim())
    .bind(request.executor_key.trim())
    .fetch_one(&mut *transaction)
    .await?;
    insert_audit(
        &mut transaction,
        &auth,
        None,
        "capability_definition.created",
        "capability_definition",
        capability.id,
    )
    .await?;
    transaction.commit().await?;
    Ok((
        StatusCode::CREATED,
        etag_headers(capability.revision)?,
        Json(capability),
    ))
}

pub async fn get_capability_definition(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((organization_id, capability_id)): Path<(Uuid, Uuid)>,
) -> Result<(HeaderMap, Json<CapabilityDefinitionResponse>), ApiError> {
    auth.require_organization(organization_id, Permission::ReadWorkspace)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let capability = sqlx::query_as::<_, CapabilityDefinitionResponse>(
        "select id, organization_id, registry_key, display_name, description,
                input_schema, output_schema, idempotency_mode, risk_level,
                executor_key, revision, created_at, updated_at, archived_at
         from capability_definitions
         where id = $1 and organization_id = $2",
    )
    .bind(capability_id)
    .bind(organization_id)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok((etag_headers(capability.revision)?, Json(capability)))
}

pub async fn update_capability_definition(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((organization_id, capability_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<UpdateCapabilityDefinitionRequest>,
) -> Result<(HeaderMap, Json<CapabilityDefinitionResponse>), ApiError> {
    auth.require_organization(organization_id, Permission::ManageOrganization)?;
    let revision = required_revision(&headers)?;
    validate_capability_definition_update(&request)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let capability = sqlx::query_as::<_, CapabilityDefinitionResponse>(
        "update capability_definitions
         set registry_key = coalesce($1, registry_key),
             display_name = coalesce($2, display_name),
             description = coalesce($3, description),
             input_schema = coalesce($4, input_schema),
             output_schema = coalesce($5, output_schema),
             idempotency_mode = coalesce($6, idempotency_mode),
             risk_level = coalesce($7, risk_level),
             executor_key = coalesce($8, executor_key),
             archived_at = case when $9 = true then coalesce(archived_at, now())
                                when $9 = false then null else archived_at end,
             revision = revision + 1,
             updated_at = now()
         where id = $10 and organization_id = $11 and revision = $12
         returning id, organization_id, registry_key, display_name, description,
                   input_schema, output_schema, idempotency_mode, risk_level,
                   executor_key, revision, created_at, updated_at, archived_at",
    )
    .bind(request.registry_key.map(|value| value.trim().to_owned()))
    .bind(request.display_name.map(|value| value.trim().to_owned()))
    .bind(request.description)
    .bind(request.input_schema)
    .bind(request.output_schema)
    .bind(
        request
            .idempotency_mode
            .map(|value| value.trim().to_owned()),
    )
    .bind(request.risk_level.map(|value| value.trim().to_owned()))
    .bind(request.executor_key.map(|value| value.trim().to_owned()))
    .bind(request.archived)
    .bind(capability_id)
    .bind(organization_id)
    .bind(revision)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(ApiError::PreconditionFailed)?;
    insert_audit(
        &mut transaction,
        &auth,
        None,
        "capability_definition.updated",
        "capability_definition",
        capability_id,
    )
    .await?;
    transaction.commit().await?;
    Ok((etag_headers(capability.revision)?, Json(capability)))
}

pub async fn archive_capability_definition(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((organization_id, capability_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<CapabilityDefinitionResponse>), ApiError> {
    auth.require_organization(organization_id, Permission::ManageOrganization)?;
    let revision = required_revision(&headers)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let capability = sqlx::query_as::<_, CapabilityDefinitionResponse>(
        "update capability_definitions
         set archived_at = coalesce(archived_at, now()),
             revision = revision + 1,
             updated_at = now()
         where id = $1 and organization_id = $2 and revision = $3
         returning id, organization_id, registry_key, display_name, description,
                   input_schema, output_schema, idempotency_mode, risk_level,
                   executor_key, revision, created_at, updated_at, archived_at",
    )
    .bind(capability_id)
    .bind(organization_id)
    .bind(revision)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(ApiError::PreconditionFailed)?;
    insert_audit(
        &mut transaction,
        &auth,
        None,
        "capability_definition.archived",
        "capability_definition",
        capability_id,
    )
    .await?;
    transaction.commit().await?;
    Ok((etag_headers(capability.revision)?, Json(capability)))
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct WorkspaceCapabilityResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub workspace_id: Uuid,
    pub capability_id: Uuid,
    pub connection_id: Option<Uuid>,
    pub enabled: bool,
    pub approval_required: bool,
    pub timeout_seconds: i32,
    pub policy: Value,
    pub revision: i64,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WorkspaceCapabilityPageResponse {
    pub items: Vec<WorkspaceCapabilityResponse>,
    pub next_cursor: Option<String>,
}

fn default_timeout_seconds() -> i32 {
    60
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateWorkspaceCapabilityRequest {
    pub capability_id: Uuid,
    pub connection_id: Option<Uuid>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub approval_required: bool,
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: i32,
    #[serde(default = "empty_object")]
    pub policy: Value,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateWorkspaceCapabilityRequest {
    pub connection_id: Option<Option<Uuid>>,
    pub enabled: Option<bool>,
    pub approval_required: Option<bool>,
    pub timeout_seconds: Option<i32>,
    pub policy: Option<Value>,
}

pub async fn list_capabilities(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<WorkspaceCapabilityPageResponse>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let limit = page.limit()?;
    let cursor = page.decoded_cursor()?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let mut items = sqlx::query_as::<_, WorkspaceCapabilityResponse>(
        "select id, organization_id, workspace_id, capability_id, connection_id,
                enabled, approval_required, timeout_seconds, policy, revision,
                created_at, updated_at
         from workspace_capabilities
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
    Ok(Json(WorkspaceCapabilityPageResponse { items, next_cursor }))
}

pub async fn create_workspace_capability(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    Json(request): Json<CreateWorkspaceCapabilityRequest>,
) -> Result<(StatusCode, HeaderMap, Json<WorkspaceCapabilityResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::ManageWorkspace)?;
    validate_workspace_capability_request(request.timeout_seconds, &request.policy)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    ensure_active_capability(
        &mut transaction,
        auth.organization_id,
        request.capability_id,
    )
    .await?;
    if let Some(connection_id) = request.connection_id {
        ensure_active_connection(
            &mut transaction,
            auth.organization_id,
            workspace_id,
            connection_id,
        )
        .await?;
    }
    let capability = sqlx::query_as::<_, WorkspaceCapabilityResponse>(
        "insert into workspace_capabilities (
            organization_id, workspace_id, capability_id, connection_id,
            enabled, approval_required, timeout_seconds, policy
         ) values ($1, $2, $3, $4, $5, $6, $7, $8)
         returning id, organization_id, workspace_id, capability_id, connection_id,
                   enabled, approval_required, timeout_seconds, policy, revision,
                   created_at, updated_at",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(request.capability_id)
    .bind(request.connection_id)
    .bind(request.enabled)
    .bind(request.approval_required)
    .bind(request.timeout_seconds)
    .bind(request.policy)
    .fetch_one(&mut *transaction)
    .await?;
    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace_id),
        "workspace_capability.created",
        "workspace_capability",
        capability.id,
    )
    .await?;
    transaction.commit().await?;
    Ok((
        StatusCode::CREATED,
        etag_headers(capability.revision)?,
        Json(capability),
    ))
}

pub async fn get_workspace_capability(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, capability_id)): Path<(Uuid, Uuid)>,
) -> Result<(HeaderMap, Json<WorkspaceCapabilityResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let capability = sqlx::query_as::<_, WorkspaceCapabilityResponse>(
        "select id, organization_id, workspace_id, capability_id, connection_id,
                enabled, approval_required, timeout_seconds, policy, revision,
                created_at, updated_at
         from workspace_capabilities
         where (id = $1 or capability_id = $1)
           and organization_id = $2 and workspace_id = $3",
    )
    .bind(capability_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok((etag_headers(capability.revision)?, Json(capability)))
}

pub async fn update_workspace_capability(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, capability_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<UpdateWorkspaceCapabilityRequest>,
) -> Result<(HeaderMap, Json<WorkspaceCapabilityResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::ManageWorkspace)?;
    let revision = required_revision(&headers)?;
    if let Some(timeout_seconds) = request.timeout_seconds {
        validate_timeout_seconds(timeout_seconds)?;
    }
    if let Some(policy) = request.policy.as_ref() {
        require_object(policy, "policy")?;
    }
    if let Some(Some(connection_id)) = request.connection_id {
        let mut transaction = begin_tenant(
            &state.platform.database,
            auth.tenant_scope(Some(workspace_id)),
        )
        .await?;
        ensure_active_connection(
            &mut transaction,
            auth.organization_id,
            workspace_id,
            connection_id,
        )
        .await?;
        transaction.commit().await?;
    }
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let capability = sqlx::query_as::<_, WorkspaceCapabilityResponse>(
        "update workspace_capabilities
         set connection_id = case when $1 then $2 else connection_id end,
             enabled = coalesce($3, enabled),
             approval_required = coalesce($4, approval_required),
             timeout_seconds = coalesce($5, timeout_seconds),
             policy = coalesce($6, policy),
             revision = revision + 1,
             updated_at = now()
         where (id = $7 or capability_id = $7)
           and organization_id = $8 and workspace_id = $9 and revision = $10
         returning id, organization_id, workspace_id, capability_id, connection_id,
                   enabled, approval_required, timeout_seconds, policy, revision,
                   created_at, updated_at",
    )
    .bind(request.connection_id.is_some())
    .bind(request.connection_id.flatten())
    .bind(request.enabled)
    .bind(request.approval_required)
    .bind(request.timeout_seconds)
    .bind(request.policy)
    .bind(capability_id)
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
        "workspace_capability.updated",
        "workspace_capability",
        capability.id,
    )
    .await?;
    transaction.commit().await?;
    Ok((etag_headers(capability.revision)?, Json(capability)))
}

pub async fn enable_workspace_capability(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, capability_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<WorkspaceCapabilityResponse>), ApiError> {
    set_workspace_capability_enabled(state, auth, workspace_id, capability_id, headers, true).await
}

pub async fn disable_workspace_capability(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, capability_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<WorkspaceCapabilityResponse>), ApiError> {
    set_workspace_capability_enabled(state, auth, workspace_id, capability_id, headers, false).await
}

async fn set_workspace_capability_enabled(
    state: AppState,
    auth: AuthContext,
    workspace_id: Uuid,
    capability_id: Uuid,
    headers: HeaderMap,
    enabled: bool,
) -> Result<(HeaderMap, Json<WorkspaceCapabilityResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::ManageWorkspace)?;
    let revision = required_revision(&headers)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let capability = sqlx::query_as::<_, WorkspaceCapabilityResponse>(
        "update workspace_capabilities
         set enabled = $1, revision = revision + 1, updated_at = now()
         where (id = $2 or capability_id = $2)
           and organization_id = $3 and workspace_id = $4 and revision = $5
         returning id, organization_id, workspace_id, capability_id, connection_id,
                   enabled, approval_required, timeout_seconds, policy, revision,
                   created_at, updated_at",
    )
    .bind(enabled)
    .bind(capability_id)
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
            "workspace_capability.enabled"
        } else {
            "workspace_capability.disabled"
        },
        "workspace_capability",
        capability.id,
    )
    .await?;
    transaction.commit().await?;
    Ok((etag_headers(capability.revision)?, Json(capability)))
}
