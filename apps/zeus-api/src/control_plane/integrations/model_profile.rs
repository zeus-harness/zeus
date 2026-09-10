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
    empty_object, ensure_active_connection, etag_headers, normalize_model_base_url, require_object,
    validate_model_profile_request, validate_model_provider_kind, validate_name,
};
use zeus_core::Permission;

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct ModelProfileResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub workspace_id: Uuid,
    pub connection_id: Uuid,
    pub name: String,
    pub provider_kind: String,
    pub base_url: String,
    pub model: String,
    pub configuration: Value,
    pub revision: i64,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub archived_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ModelProfilePageResponse {
    pub items: Vec<ModelProfileResponse>,
    pub next_cursor: Option<String>,
}

fn default_model_provider_kind() -> String {
    "openai_compatible".to_owned()
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateModelProfileRequest {
    pub connection_id: Uuid,
    pub name: String,
    #[serde(default = "default_model_provider_kind")]
    pub provider_kind: String,
    pub base_url: String,
    pub model: String,
    #[serde(default = "empty_object")]
    pub configuration: Value,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateModelProfileRequest {
    pub connection_id: Option<Uuid>,
    pub name: Option<String>,
    pub provider_kind: Option<String>,
    pub base_url: Option<String>,
    pub model: Option<String>,
    pub configuration: Option<Value>,
    pub archived: Option<bool>,
}

pub async fn list_model_profiles(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<ModelProfilePageResponse>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let limit = page.limit()?;
    let cursor = page.decoded_cursor()?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let mut items = sqlx::query_as::<_, ModelProfileResponse>(
        "select id, organization_id, workspace_id, connection_id, name,
                provider_kind, base_url, model, configuration, revision,
                created_at, updated_at, archived_at
         from model_profiles
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
    Ok(Json(ModelProfilePageResponse { items, next_cursor }))
}

pub async fn create_model_profile(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    Json(request): Json<CreateModelProfileRequest>,
) -> Result<(StatusCode, HeaderMap, Json<ModelProfileResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::ManageWorkspace)?;
    validate_model_profile_request(
        &request.provider_kind,
        &request.name,
        &request.base_url,
        &request.model,
        &request.configuration,
        state.execution.allow_private_model_endpoints,
    )?;
    let base_url = normalize_model_base_url(
        &request.base_url,
        state.execution.allow_private_model_endpoints,
    )?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    ensure_active_connection(
        &mut transaction,
        auth.organization_id,
        workspace_id,
        request.connection_id,
    )
    .await?;
    let profile = sqlx::query_as::<_, ModelProfileResponse>(
        "insert into model_profiles (
            organization_id, workspace_id, connection_id, name,
            provider_kind, base_url, model, configuration
         ) values ($1, $2, $3, $4, $5, $6, $7, $8)
         returning id, organization_id, workspace_id, connection_id, name,
                   provider_kind, base_url, model, configuration, revision,
                   created_at, updated_at, archived_at",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(request.connection_id)
    .bind(request.name.trim())
    .bind(request.provider_kind.trim())
    .bind(base_url)
    .bind(request.model.trim())
    .bind(request.configuration)
    .fetch_one(&mut *transaction)
    .await?;
    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace_id),
        "model_profile.created",
        "model_profile",
        profile.id,
    )
    .await?;
    transaction.commit().await?;
    Ok((
        StatusCode::CREATED,
        etag_headers(profile.revision)?,
        Json(profile),
    ))
}

pub async fn get_model_profile(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, model_profile_id)): Path<(Uuid, Uuid)>,
) -> Result<(HeaderMap, Json<ModelProfileResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let profile = sqlx::query_as::<_, ModelProfileResponse>(
        "select id, organization_id, workspace_id, connection_id, name,
                provider_kind, base_url, model, configuration, revision,
                created_at, updated_at, archived_at
         from model_profiles
         where id = $1 and organization_id = $2 and workspace_id = $3",
    )
    .bind(model_profile_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok((etag_headers(profile.revision)?, Json(profile)))
}

pub async fn update_model_profile(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, model_profile_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<UpdateModelProfileRequest>,
) -> Result<(HeaderMap, Json<ModelProfileResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::ManageWorkspace)?;
    let revision = required_revision(&headers)?;
    if let Some(name) = request.name.as_deref() {
        validate_name(name, "name", 160)?;
    }
    if let Some(provider_kind) = request.provider_kind.as_deref() {
        validate_model_provider_kind(provider_kind)?;
    }
    if let Some(model) = request.model.as_deref() {
        validate_name(model, "model", 256)?;
    }
    if let Some(configuration) = request.configuration.as_ref() {
        require_object(configuration, "configuration")?;
    }
    let base_url = request
        .base_url
        .as_deref()
        .map(|value| normalize_model_base_url(value, state.execution.allow_private_model_endpoints))
        .transpose()?;

    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
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
    let profile = sqlx::query_as::<_, ModelProfileResponse>(
        "update model_profiles
         set connection_id = coalesce($1, connection_id),
             name = coalesce($2, name),
             provider_kind = coalesce($3, provider_kind),
             base_url = coalesce($4, base_url),
             model = coalesce($5, model),
             configuration = coalesce($6, configuration),
             archived_at = case when $7 = true then coalesce(archived_at, now())
                                when $7 = false then null else archived_at end,
             revision = revision + 1,
             updated_at = now()
         where id = $8 and organization_id = $9 and workspace_id = $10 and revision = $11
         returning id, organization_id, workspace_id, connection_id, name,
                   provider_kind, base_url, model, configuration, revision,
                   created_at, updated_at, archived_at",
    )
    .bind(request.connection_id)
    .bind(request.name.map(|value| value.trim().to_owned()))
    .bind(request.provider_kind.map(|value| value.trim().to_owned()))
    .bind(base_url)
    .bind(request.model.map(|value| value.trim().to_owned()))
    .bind(request.configuration)
    .bind(request.archived)
    .bind(model_profile_id)
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
        "model_profile.updated",
        "model_profile",
        model_profile_id,
    )
    .await?;
    transaction.commit().await?;
    Ok((etag_headers(profile.revision)?, Json(profile)))
}

pub async fn archive_model_profile(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, model_profile_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<ModelProfileResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::ManageWorkspace)?;
    let revision = required_revision(&headers)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let profile = sqlx::query_as::<_, ModelProfileResponse>(
        "update model_profiles
         set archived_at = coalesce(archived_at, now()),
             revision = revision + 1,
             updated_at = now()
         where id = $1 and organization_id = $2 and workspace_id = $3 and revision = $4
         returning id, organization_id, workspace_id, connection_id, name,
                   provider_kind, base_url, model, configuration, revision,
                   created_at, updated_at, archived_at",
    )
    .bind(model_profile_id)
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
        "model_profile.archived",
        "model_profile",
        model_profile_id,
    )
    .await?;
    transaction.commit().await?;
    Ok((etag_headers(profile.revision)?, Json(profile)))
}
