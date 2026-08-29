#![allow(clippy::missing_errors_doc)] // HTTP failures use the shared Problem Details contract.

use std::collections::BTreeMap;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{FromRow, Postgres, Transaction};
use time::OffsetDateTime;
use url::Url;
use utoipa::ToSchema;
use uuid::Uuid;
use zeus_core::Permission;

use crate::{
    AppState,
    api_support::{ListCursor, PageQuery, required_revision, revision_etag},
    auth::{AuthContext, insert_audit},
    crypto::{random_token, sha256},
    database::{TenantScope, begin_tenant},
    error::ApiError,
    idempotency::{self, IdempotencyDecision},
    oidc::validate_remote_url,
};

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct ConnectionResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub workspace_id: Uuid,
    pub name: String,
    pub provider_kind: String,
    pub configuration: Value,
    pub revision: i64,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub archived_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ConnectionPageResponse {
    pub items: Vec<ConnectionResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateConnectionRequest {
    pub name: String,
    pub provider_kind: String,
    #[serde(default = "empty_object")]
    pub configuration: Value,
    /// Secrets are write-only inputs. Their values are never echoed in a response.
    #[serde(default)]
    pub secrets: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateConnectionRequest {
    pub name: Option<String>,
    pub provider_kind: Option<String>,
    pub configuration: Option<Value>,
    pub archived: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct ConnectionSecretResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub workspace_id: Uuid,
    pub connection_id: Uuid,
    pub secret_name: String,
    pub created_at: OffsetDateTime,
    pub rotated_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ConnectionSecretPageResponse {
    pub items: Vec<ConnectionSecretResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateConnectionSecretRequest {
    pub secret_name: String,
    #[schema(value_type = String, write_only)]
    pub secret: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ConnectionSecretValueRequest {
    #[schema(value_type = String, write_only)]
    pub secret: String,
}

#[derive(Debug, FromRow)]
struct ConnectionRevisionRow {
    revision: i64,
}

pub async fn list_connections(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<ConnectionPageResponse>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let limit = page.limit()?;
    let cursor = page.decoded_cursor()?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let mut items = sqlx::query_as::<_, ConnectionResponse>(
        "select id, organization_id, workspace_id, name, provider_kind,
                configuration, revision, created_at, updated_at, archived_at
         from connections
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
    Ok(Json(ConnectionPageResponse { items, next_cursor }))
}

pub async fn create_connection(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    Json(request): Json<CreateConnectionRequest>,
) -> Result<(StatusCode, HeaderMap, Json<ConnectionResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::ManageWorkspace)?;
    validate_name(&request.name, "name", 160)?;
    validate_connection_provider_kind(&request.provider_kind)?;
    require_object(&request.configuration, "configuration")?;
    validate_connection_secrets(&request.secrets)?;

    let connection_id = Uuid::now_v7();
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let connection = sqlx::query_as::<_, ConnectionResponse>(
        "insert into connections (
            id, organization_id, workspace_id, name, provider_kind, configuration
         ) values ($1, $2, $3, $4, $5, $6)
         returning id, organization_id, workspace_id, name, provider_kind,
                   configuration, revision, created_at, updated_at, archived_at",
    )
    .bind(connection_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(request.name.trim())
    .bind(request.provider_kind.trim())
    .bind(&request.configuration)
    .fetch_one(&mut *transaction)
    .await?;

    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace_id),
        "connection.created",
        "connection",
        connection.id,
    )
    .await?;
    for (secret_name, secret) in &request.secrets {
        let sealed = seal_connection_secret(&state, connection.id, secret_name, secret)?;
        let secret_row = sqlx::query_as::<_, ConnectionSecretResponse>(
            "insert into connection_secrets (
                organization_id, workspace_id, connection_id, secret_name,
                ciphertext, nonce, key_id
             ) values ($1, $2, $3, $4, $5, $6, $7)
             returning id, organization_id, workspace_id, connection_id,
                       secret_name, created_at, rotated_at",
        )
        .bind(auth.organization_id)
        .bind(workspace_id)
        .bind(connection.id)
        .bind(secret_name)
        .bind(sealed.ciphertext)
        .bind(sealed.nonce)
        .bind(sealed.key_id)
        .fetch_one(&mut *transaction)
        .await?;
        insert_audit(
            &mut transaction,
            &auth,
            Some(workspace_id),
            "connection_secret.created",
            "connection_secret",
            secret_row.id,
        )
        .await?;
    }
    transaction.commit().await?;

    Ok((
        StatusCode::CREATED,
        etag_headers(connection.revision)?,
        Json(connection),
    ))
}

pub async fn get_connection(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, connection_id)): Path<(Uuid, Uuid)>,
) -> Result<(HeaderMap, Json<ConnectionResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let connection = sqlx::query_as::<_, ConnectionResponse>(
        "select id, organization_id, workspace_id, name, provider_kind,
                configuration, revision, created_at, updated_at, archived_at
         from connections
         where id = $1 and organization_id = $2 and workspace_id = $3",
    )
    .bind(connection_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok((etag_headers(connection.revision)?, Json(connection)))
}

pub async fn update_connection(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, connection_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<UpdateConnectionRequest>,
) -> Result<(HeaderMap, Json<ConnectionResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::ManageWorkspace)?;
    let revision = required_revision(&headers)?;
    if let Some(name) = request.name.as_deref() {
        validate_name(name, "name", 160)?;
    }
    if let Some(provider_kind) = request.provider_kind.as_deref() {
        validate_connection_provider_kind(provider_kind)?;
    }
    if let Some(configuration) = request.configuration.as_ref() {
        require_object(configuration, "configuration")?;
    }

    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let connection = sqlx::query_as::<_, ConnectionResponse>(
        "update connections
         set name = coalesce($1, name),
             provider_kind = coalesce($2, provider_kind),
             configuration = coalesce($3, configuration),
             archived_at = case when $4 = true then coalesce(archived_at, now())
                                when $4 = false then null else archived_at end,
             revision = revision + 1,
             updated_at = now()
         where id = $5 and organization_id = $6 and workspace_id = $7 and revision = $8
         returning id, organization_id, workspace_id, name, provider_kind,
                   configuration, revision, created_at, updated_at, archived_at",
    )
    .bind(request.name.map(|value| value.trim().to_owned()))
    .bind(request.provider_kind.map(|value| value.trim().to_owned()))
    .bind(request.configuration)
    .bind(request.archived)
    .bind(connection_id)
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
        "connection.updated",
        "connection",
        connection_id,
    )
    .await?;
    transaction.commit().await?;
    Ok((etag_headers(connection.revision)?, Json(connection)))
}

pub async fn archive_connection(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, connection_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<ConnectionResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::ManageWorkspace)?;
    let revision = required_revision(&headers)?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let connection = sqlx::query_as::<_, ConnectionResponse>(
        "update connections
         set archived_at = coalesce(archived_at, now()),
             revision = revision + 1,
             updated_at = now()
         where id = $1 and organization_id = $2 and workspace_id = $3 and revision = $4
         returning id, organization_id, workspace_id, name, provider_kind,
                   configuration, revision, created_at, updated_at, archived_at",
    )
    .bind(connection_id)
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
        "connection.archived",
        "connection",
        connection_id,
    )
    .await?;
    transaction.commit().await?;
    Ok((etag_headers(connection.revision)?, Json(connection)))
}

pub async fn list_connection_secrets(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, connection_id)): Path<(Uuid, Uuid)>,
    Query(page): Query<PageQuery>,
) -> Result<Json<ConnectionSecretPageResponse>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let limit = page.limit()?;
    let cursor = page.decoded_cursor()?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let mut items = sqlx::query_as::<_, ConnectionSecretResponse>(
        "select id, organization_id, workspace_id, connection_id, secret_name,
                created_at, rotated_at
         from connection_secrets
         where id is not null and connection_id = $1
           and organization_id = $2 and workspace_id = $3
           and ($4::timestamptz is null or (created_at, id) < ($4, $5))
         order by created_at desc, id desc
         limit $6",
    )
    .bind(connection_id)
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
    Ok(Json(ConnectionSecretPageResponse { items, next_cursor }))
}

pub async fn create_connection_secret(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, connection_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<CreateConnectionSecretRequest>,
) -> Result<(StatusCode, HeaderMap, Json<ConnectionSecretResponse>), ApiError> {
    create_connection_secret_value(
        state,
        auth,
        workspace_id,
        connection_id,
        request.secret_name,
        request.secret,
    )
    .await
}

async fn create_connection_secret_value(
    state: AppState,
    auth: AuthContext,
    workspace_id: Uuid,
    connection_id: Uuid,
    secret_name: String,
    secret: String,
) -> Result<(StatusCode, HeaderMap, Json<ConnectionSecretResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::ManageWorkspace)?;
    validate_secret_name(&secret_name)?;
    validate_secret_value(&secret)?;
    let sealed = seal_connection_secret(&state, connection_id, &secret_name, &secret)?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let _connection = sqlx::query_as::<_, ConnectionRevisionRow>(
        "select revision
         from connections
         where id = $1 and organization_id = $2 and workspace_id = $3
           and archived_at is null
         for update",
    )
    .bind(connection_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(ApiError::NotFound)?;
    let secret_row = sqlx::query_as::<_, ConnectionSecretResponse>(
        "insert into connection_secrets (
            organization_id, workspace_id, connection_id, secret_name,
            ciphertext, nonce, key_id
         ) values ($1, $2, $3, $4, $5, $6, $7)
         returning id, organization_id, workspace_id, connection_id,
                   secret_name, created_at, rotated_at",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(connection_id)
    .bind(&secret_name)
    .bind(sealed.ciphertext)
    .bind(sealed.nonce)
    .bind(sealed.key_id)
    .fetch_one(&mut *transaction)
    .await?;
    let new_revision: i64 = sqlx::query_scalar(
        "update connections
         set revision = revision + 1, updated_at = now()
         where id = $1 and organization_id = $2 and workspace_id = $3
         returning revision",
    )
    .bind(connection_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .fetch_one(&mut *transaction)
    .await?;
    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace_id),
        "connection_secret.created",
        "connection_secret",
        secret_row.id,
    )
    .await?;
    transaction.commit().await?;
    Ok((
        StatusCode::CREATED,
        etag_headers(new_revision)?,
        Json(secret_row),
    ))
}

pub async fn create_named_connection_secret(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, connection_id, secret_name)): Path<(Uuid, Uuid, String)>,
    Json(request): Json<ConnectionSecretValueRequest>,
) -> Result<(StatusCode, HeaderMap, Json<ConnectionSecretResponse>), ApiError> {
    create_connection_secret_value(
        state,
        auth,
        workspace_id,
        connection_id,
        secret_name,
        request.secret,
    )
    .await
}

pub async fn rotate_connection_secret(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, connection_id, secret_name)): Path<(Uuid, Uuid, String)>,
    headers: HeaderMap,
    Json(request): Json<ConnectionSecretValueRequest>,
) -> Result<(HeaderMap, Json<ConnectionSecretResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::ManageWorkspace)?;
    let expected_revision = required_revision(&headers)?;
    validate_secret_name(&secret_name)?;
    validate_secret_value(&request.secret)?;
    let sealed = seal_connection_secret(&state, connection_id, &secret_name, &request.secret)?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let connection = sqlx::query_as::<_, ConnectionRevisionRow>(
        "select revision
         from connections
         where id = $1 and organization_id = $2 and workspace_id = $3
           and archived_at is null
         for update",
    )
    .bind(connection_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(ApiError::NotFound)?;
    if connection.revision != expected_revision {
        return Err(ApiError::PreconditionFailed);
    }
    let secret_row = sqlx::query_as::<_, ConnectionSecretResponse>(
        "update connection_secrets
         set ciphertext = $1, nonce = $2, key_id = $3, rotated_at = now()
         where connection_id = $4 and organization_id = $5 and workspace_id = $6
           and secret_name = $7
         returning id, organization_id, workspace_id, connection_id,
                   secret_name, created_at, rotated_at",
    )
    .bind(sealed.ciphertext)
    .bind(sealed.nonce)
    .bind(sealed.key_id)
    .bind(connection_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(&secret_name)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(ApiError::NotFound)?;
    let new_revision: i64 = sqlx::query_scalar(
        "update connections
         set revision = revision + 1, updated_at = now()
         where id = $1 and organization_id = $2 and workspace_id = $3
           and revision = $4
         returning revision",
    )
    .bind(connection_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(expected_revision)
    .fetch_one(&mut *transaction)
    .await?;
    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace_id),
        "connection_secret.rotated",
        "connection_secret",
        secret_row.id,
    )
    .await?;
    transaction.commit().await?;
    Ok((etag_headers(new_revision)?, Json(secret_row)))
}

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
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
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
        state.allow_private_model_endpoints,
    )?;
    let base_url =
        normalize_model_base_url(&request.base_url, state.allow_private_model_endpoints)?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
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
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
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
        .map(|value| normalize_model_base_url(value, state.allow_private_model_endpoints))
        .transpose()?;

    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
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
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
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
        &state.database,
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
        &state.database,
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
        &state.database,
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
        &state.database,
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
        &state.database,
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

fn default_enabled() -> bool {
    true
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
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
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
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
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
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
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
        let mut transaction =
            begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
        ensure_active_connection(
            &mut transaction,
            auth.organization_id,
            workspace_id,
            connection_id,
        )
        .await?;
        transaction.commit().await?;
    }
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
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
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
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
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
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
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
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
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
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
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
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
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
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

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct WebhookEndpointResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub workspace_id: Uuid,
    pub workflow_id: Uuid,
    pub public_key: String,
    pub enabled: bool,
    pub revision: i64,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WebhookEndpointPageResponse {
    pub items: Vec<WebhookEndpointResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreatedWebhookEndpointResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub workspace_id: Uuid,
    pub workflow_id: Uuid,
    pub public_key: String,
    pub enabled: bool,
    pub revision: i64,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    /// Returned only in the create response; it cannot be read or rotated here.
    #[schema(value_type = String, write_only)]
    pub secret: String,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct CreateWebhookEndpointRequest {
    pub workflow_id: Uuid,
    pub public_key: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateWebhookEndpointRequest {
    pub workflow_id: Option<Uuid>,
    pub public_key: Option<String>,
    pub enabled: Option<bool>,
}

pub async fn list_webhook_endpoints(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<WebhookEndpointPageResponse>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let limit = page.limit()?;
    let cursor = page.decoded_cursor()?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let mut items = sqlx::query_as::<_, WebhookEndpointResponse>(
        "select id, organization_id, workspace_id, workflow_id, public_key,
                enabled, revision, created_at, updated_at
         from webhook_endpoints
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
    Ok(Json(WebhookEndpointPageResponse { items, next_cursor }))
}

pub async fn create_webhook_endpoint(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<CreateWebhookEndpointRequest>,
) -> Result<Response, ApiError> {
    auth.require_workspace(workspace_id, Permission::ManageWorkspace)?;
    let path = format!("/api/v1/workspaces/{workspace_id}/webhook-endpoints");
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
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
    let public_key = match request.public_key {
        Some(public_key) => {
            validate_public_key(&public_key)?;
            public_key.trim().to_owned()
        }
        None => random_token(18)
            .map_err(|_| ApiError::Internal)?
            .expose_secret()
            .to_owned(),
    };
    let (raw_secret, secret_hash) = {
        let raw_secret = random_token(32).map_err(|_| ApiError::Internal)?;
        let secret_hash = sha256(raw_secret.expose_secret().as_bytes());
        (raw_secret.expose_secret().to_owned(), secret_hash)
    };
    ensure_active_workflow(
        &mut transaction,
        auth.organization_id,
        workspace_id,
        request.workflow_id,
    )
    .await?;
    let endpoint = sqlx::query_as::<_, WebhookEndpointResponse>(
        "insert into webhook_endpoints (
            organization_id, workspace_id, workflow_id, public_key, secret_hash, enabled
         ) values ($1, $2, $3, $4, $5, $6)
         returning id, organization_id, workspace_id, workflow_id, public_key,
                   enabled, revision, created_at, updated_at",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(request.workflow_id)
    .bind(&public_key)
    .bind(secret_hash)
    .bind(request.enabled)
    .fetch_one(&mut *transaction)
    .await?;
    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace_id),
        "webhook_endpoint.created",
        "webhook_endpoint",
        endpoint.id,
    )
    .await?;
    idempotency::complete(&mut transaction, &reservation, 201, &endpoint).await?;
    transaction.commit().await?;
    let response = CreatedWebhookEndpointResponse {
        id: endpoint.id,
        organization_id: endpoint.organization_id,
        workspace_id: endpoint.workspace_id,
        workflow_id: endpoint.workflow_id,
        public_key: endpoint.public_key,
        enabled: endpoint.enabled,
        revision: endpoint.revision,
        created_at: endpoint.created_at,
        updated_at: endpoint.updated_at,
        secret: raw_secret,
    };
    let etag = revision_etag(response.revision)?;
    let mut http_response = (StatusCode::CREATED, Json(response)).into_response();
    http_response.headers_mut().insert(header::ETAG, etag);
    Ok(http_response)
}

pub async fn get_webhook_endpoint(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, endpoint_id)): Path<(Uuid, Uuid)>,
) -> Result<(HeaderMap, Json<WebhookEndpointResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let endpoint = load_webhook_endpoint(
        &mut transaction,
        auth.organization_id,
        workspace_id,
        endpoint_id,
    )
    .await?;
    transaction.commit().await?;
    Ok((etag_headers(endpoint.revision)?, Json(endpoint)))
}

pub async fn update_webhook_endpoint(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, endpoint_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<UpdateWebhookEndpointRequest>,
) -> Result<(HeaderMap, Json<WebhookEndpointResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::ManageWorkspace)?;
    let revision = required_revision(&headers)?;
    if let Some(public_key) = request.public_key.as_deref() {
        validate_public_key(public_key)?;
    }
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    if let Some(workflow_id) = request.workflow_id {
        ensure_active_workflow(
            &mut transaction,
            auth.organization_id,
            workspace_id,
            workflow_id,
        )
        .await?;
    }
    let endpoint = sqlx::query_as::<_, WebhookEndpointResponse>(
        "update webhook_endpoints
         set workflow_id = coalesce($1, workflow_id),
             public_key = coalesce($2, public_key),
             enabled = coalesce($3, enabled),
             revision = revision + 1,
             updated_at = now()
         where id = $4 and organization_id = $5 and workspace_id = $6 and revision = $7
         returning id, organization_id, workspace_id, workflow_id, public_key,
                   enabled, revision, created_at, updated_at",
    )
    .bind(request.workflow_id)
    .bind(request.public_key.map(|value| value.trim().to_owned()))
    .bind(request.enabled)
    .bind(endpoint_id)
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
        "webhook_endpoint.updated",
        "webhook_endpoint",
        endpoint_id,
    )
    .await?;
    transaction.commit().await?;
    Ok((etag_headers(endpoint.revision)?, Json(endpoint)))
}

pub async fn enable_webhook_endpoint(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, endpoint_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<WebhookEndpointResponse>), ApiError> {
    set_webhook_enabled(state, auth, workspace_id, endpoint_id, headers, true).await
}

pub async fn disable_webhook_endpoint(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, endpoint_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<WebhookEndpointResponse>), ApiError> {
    set_webhook_enabled(state, auth, workspace_id, endpoint_id, headers, false).await
}

async fn set_webhook_enabled(
    state: AppState,
    auth: AuthContext,
    workspace_id: Uuid,
    endpoint_id: Uuid,
    headers: HeaderMap,
    enabled: bool,
) -> Result<(HeaderMap, Json<WebhookEndpointResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::ManageWorkspace)?;
    let revision = required_revision(&headers)?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let endpoint = sqlx::query_as::<_, WebhookEndpointResponse>(
        "update webhook_endpoints
         set enabled = $1, revision = revision + 1, updated_at = now()
         where id = $2 and organization_id = $3 and workspace_id = $4 and revision = $5
         returning id, organization_id, workspace_id, workflow_id, public_key,
                   enabled, revision, created_at, updated_at",
    )
    .bind(enabled)
    .bind(endpoint_id)
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
            "webhook_endpoint.enabled"
        } else {
            "webhook_endpoint.disabled"
        },
        "webhook_endpoint",
        endpoint_id,
    )
    .await?;
    transaction.commit().await?;
    Ok((etag_headers(endpoint.revision)?, Json(endpoint)))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/workspaces/{workspace_id}/connections",
            get(list_connections).post(create_connection),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/connections/{connection_id}",
            get(get_connection).patch(update_connection),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/connections/{connection_id}/archive",
            post(archive_connection),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/connections/{connection_id}/secrets",
            get(list_connection_secrets).post(create_connection_secret),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/connections/{connection_id}/secrets/{secret_name}",
            post(create_named_connection_secret).put(rotate_connection_secret),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/model-profiles",
            get(list_model_profiles).post(create_model_profile),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/model-profiles/{model_profile_id}",
            get(get_model_profile).patch(update_model_profile),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/model-profiles/{model_profile_id}/archive",
            post(archive_model_profile),
        )
        .route(
            "/api/v1/organizations/{organization_id}/capability-definitions",
            get(list_capability_definitions).post(create_capability_definition),
        )
        .route(
            "/api/v1/organizations/{organization_id}/capability-definitions/{capability_id}",
            get(get_capability_definition).patch(update_capability_definition),
        )
        .route(
            "/api/v1/organizations/{organization_id}/capability-definitions/{capability_id}/archive",
            post(archive_capability_definition),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/capabilities",
            get(list_capabilities).post(create_workspace_capability),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/capabilities/{capability_id}",
            get(get_workspace_capability).patch(update_workspace_capability),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/capabilities/{capability_id}/enable",
            post(enable_workspace_capability),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/capabilities/{capability_id}/disable",
            post(disable_workspace_capability),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/schedules",
            get(list_schedules).post(create_schedule),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/schedules/{schedule_id}",
            get(get_schedule).patch(update_schedule),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/schedules/{schedule_id}/enable",
            post(enable_schedule),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/schedules/{schedule_id}/disable",
            post(disable_schedule),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/webhook-endpoints",
            get(list_webhook_endpoints).post(create_webhook_endpoint),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/webhook-endpoints/{endpoint_id}",
            get(get_webhook_endpoint).patch(update_webhook_endpoint),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/webhook-endpoints/{endpoint_id}/enable",
            post(enable_webhook_endpoint),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/webhook-endpoints/{endpoint_id}/disable",
            post(disable_webhook_endpoint),
        )
}

async fn ensure_active_connection(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    workspace_id: Uuid,
    connection_id: Uuid,
) -> Result<(), ApiError> {
    let exists: bool = sqlx::query_scalar(
        "select exists(
           select 1 from connections
           where id = $1 and organization_id = $2 and workspace_id = $3
             and archived_at is null
         )",
    )
    .bind(connection_id)
    .bind(organization_id)
    .bind(workspace_id)
    .fetch_one(&mut **transaction)
    .await?;
    if exists {
        Ok(())
    } else {
        Err(ApiError::Validation(
            "connection_id must reference an active connection in this workspace".to_owned(),
        ))
    }
}

async fn ensure_active_workflow(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    workspace_id: Uuid,
    workflow_id: Uuid,
) -> Result<(), ApiError> {
    let exists: bool = sqlx::query_scalar(
        "select exists(
           select 1 from workflows
           where id = $1 and organization_id = $2 and workspace_id = $3
             and archived_at is null
         )",
    )
    .bind(workflow_id)
    .bind(organization_id)
    .bind(workspace_id)
    .fetch_one(&mut **transaction)
    .await?;
    if exists {
        Ok(())
    } else {
        Err(ApiError::Validation(
            "workflow_id must reference an active workflow in this workspace".to_owned(),
        ))
    }
}

async fn ensure_active_capability(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    capability_id: Uuid,
) -> Result<(), ApiError> {
    let exists: bool = sqlx::query_scalar(
        "select exists(
           select 1 from capability_definitions
           where id = $1 and organization_id = $2 and archived_at is null
         )",
    )
    .bind(capability_id)
    .bind(organization_id)
    .fetch_one(&mut **transaction)
    .await?;
    if exists {
        Ok(())
    } else {
        Err(ApiError::Validation(
            "capability_id must reference an active organization capability".to_owned(),
        ))
    }
}

async fn load_schedule(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    workspace_id: Uuid,
    schedule_id: Uuid,
) -> Result<ScheduleResponse, ApiError> {
    sqlx::query_as::<_, ScheduleResponse>(
        "select id, organization_id, workspace_id, workflow_id, name,
                cron_expression, timezone, input, enabled, next_run_at,
                revision, created_at, updated_at
         from schedules
         where id = $1 and organization_id = $2 and workspace_id = $3",
    )
    .bind(schedule_id)
    .bind(organization_id)
    .bind(workspace_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(Into::into)
}

async fn load_webhook_endpoint(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    workspace_id: Uuid,
    endpoint_id: Uuid,
) -> Result<WebhookEndpointResponse, ApiError> {
    sqlx::query_as::<_, WebhookEndpointResponse>(
        "select id, organization_id, workspace_id, workflow_id, public_key,
                enabled, revision, created_at, updated_at
         from webhook_endpoints
         where id = $1 and organization_id = $2 and workspace_id = $3",
    )
    .bind(endpoint_id)
    .bind(organization_id)
    .bind(workspace_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(Into::into)
}

fn seal_connection_secret(
    state: &AppState,
    connection_id: Uuid,
    secret_name: &str,
    secret: &str,
) -> Result<crate::crypto::SealedSecret, ApiError> {
    let aad = connection_secret_aad(connection_id, secret_name);
    state
        .envelope
        .seal(secret.as_bytes(), aad.as_bytes())
        .map_err(|_| ApiError::Internal)
}

fn connection_secret_aad(connection_id: Uuid, secret_name: &str) -> String {
    format!("connection/{connection_id}/{secret_name}")
}

fn etag_headers(revision: i64) -> Result<HeaderMap, ApiError> {
    let mut headers = HeaderMap::new();
    headers.insert(header::ETAG, revision_etag(revision)?);
    Ok(headers)
}

fn json_response(status: u16, body: Value) -> Result<Response, ApiError> {
    let status = StatusCode::from_u16(status).map_err(|_| ApiError::Internal)?;
    Ok((status, Json(body)).into_response())
}

#[allow(clippy::too_many_arguments)] // Mirrors the fields of the capability definition request.
fn validate_capability_definition_request(
    registry_key: &str,
    display_name: &str,
    description: &str,
    input_schema: &Value,
    output_schema: &Value,
    idempotency_mode: &str,
    risk_level: &str,
    executor_key: &str,
) -> Result<(), ApiError> {
    validate_key(registry_key, "registry_key", 160)?;
    validate_name(display_name, "display_name", 160)?;
    validate_text(description, "description", 8_000, true)?;
    require_object(input_schema, "input_schema")?;
    require_object(output_schema, "output_schema")?;
    validate_json_schema(input_schema, "input_schema")?;
    validate_json_schema(output_schema, "output_schema")?;
    validate_idempotency_mode(idempotency_mode)?;
    validate_risk_level(risk_level)?;
    validate_key(executor_key, "executor_key", 160)
}

fn validate_capability_definition_update(
    request: &UpdateCapabilityDefinitionRequest,
) -> Result<(), ApiError> {
    if let Some(value) = request.registry_key.as_deref() {
        validate_key(value, "registry_key", 160)?;
    }
    if let Some(value) = request.display_name.as_deref() {
        validate_name(value, "display_name", 160)?;
    }
    if let Some(value) = request.description.as_deref() {
        validate_text(value, "description", 8_000, true)?;
    }
    if let Some(value) = request.input_schema.as_ref() {
        require_object(value, "input_schema")?;
        validate_json_schema(value, "input_schema")?;
    }
    if let Some(value) = request.output_schema.as_ref() {
        require_object(value, "output_schema")?;
        validate_json_schema(value, "output_schema")?;
    }
    if let Some(value) = request.idempotency_mode.as_deref() {
        validate_idempotency_mode(value)?;
    }
    if let Some(value) = request.risk_level.as_deref() {
        validate_risk_level(value)?;
    }
    if let Some(value) = request.executor_key.as_deref() {
        validate_key(value, "executor_key", 160)?;
    }
    Ok(())
}

fn validate_workspace_capability_request(
    timeout_seconds: i32,
    policy: &Value,
) -> Result<(), ApiError> {
    validate_timeout_seconds(timeout_seconds)?;
    require_object(policy, "policy")
}

fn validate_json_schema(schema: &Value, field: &str) -> Result<(), ApiError> {
    if !jsonschema::meta::is_valid(schema) {
        return Err(ApiError::Validation(format!(
            "{field} must be a valid JSON Schema"
        )));
    }
    if contains_external_schema_reference(schema) {
        return Err(ApiError::Validation(format!(
            "{field} cannot contain external $ref values"
        )));
    }
    Ok(())
}

fn contains_external_schema_reference(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            (key == "$ref"
                && value
                    .as_str()
                    .is_some_and(|reference| !reference.starts_with('#')))
                || contains_external_schema_reference(value)
        }),
        Value::Array(values) => values.iter().any(contains_external_schema_reference),
        _ => false,
    }
}

fn validate_model_profile_request(
    provider_kind: &str,
    name: &str,
    base_url: &str,
    model: &str,
    configuration: &Value,
    allow_private_model_endpoints: bool,
) -> Result<(), ApiError> {
    validate_model_provider_kind(provider_kind)?;
    validate_name(name, "name", 160)?;
    let _ = normalize_model_base_url(base_url, allow_private_model_endpoints)?;
    validate_name(model, "model", 256)?;
    require_object(configuration, "configuration")
}

fn validate_model_provider_kind(provider_kind: &str) -> Result<(), ApiError> {
    if provider_kind.trim() == "openai_compatible" {
        Ok(())
    } else {
        Err(ApiError::Validation(
            "provider_kind must be openai_compatible".to_owned(),
        ))
    }
}

fn normalize_model_base_url(value: &str, allow_private: bool) -> Result<String, ApiError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 2_048 || value.contains(['\r', '\n']) {
        return Err(ApiError::Validation(
            "base_url must contain between 1 and 2048 characters".to_owned(),
        ));
    }
    let parsed =
        Url::parse(value).map_err(|_| ApiError::Validation("base_url is invalid".to_owned()))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host().is_none() {
        return Err(ApiError::Validation(
            "base_url must be an HTTP(S) URL with a host".to_owned(),
        ));
    }
    validate_remote_url(&parsed, allow_private)
        .map_err(|_| ApiError::Validation("base_url is not allowed".to_owned()))?;
    Ok(parsed.as_str().trim_end_matches('/').to_owned())
}

fn validate_schedule_request(
    name: &str,
    cron_expression: &str,
    timezone: &str,
    input: &Value,
) -> Result<(), ApiError> {
    validate_name(name, "name", 160)?;
    validate_cron_expression(cron_expression)?;
    validate_timezone(timezone)?;
    require_object(input, "input")
}

fn validate_cron_expression(value: &str) -> Result<(), ApiError> {
    validate_text(value, "cron_expression", 256, false)
}

fn validate_timezone(value: &str) -> Result<(), ApiError> {
    if value.trim().is_empty()
        || value.len() > 128
        || value != value.trim()
        || value.contains(['\r', '\n'])
    {
        return Err(ApiError::Validation(
            "timezone must contain between 1 and 128 characters".to_owned(),
        ));
    }
    Ok(())
}

fn validate_connection_secrets(secrets: &BTreeMap<String, String>) -> Result<(), ApiError> {
    for (name, secret) in secrets {
        validate_secret_name(name)?;
        validate_secret_value(secret)?;
    }
    Ok(())
}

fn validate_secret_name(value: &str) -> Result<(), ApiError> {
    if value.is_empty()
        || value.len() > 128
        || value != value.trim()
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        })
    {
        return Err(ApiError::Validation(
            "secret_name must use 1-128 ASCII letters, digits, '.', '_' or '-'".to_owned(),
        ));
    }
    Ok(())
}

fn validate_secret_value(value: &str) -> Result<(), ApiError> {
    if value.is_empty() || value.len() > 16_384 {
        return Err(ApiError::Validation(
            "secret must contain between 1 and 16384 characters".to_owned(),
        ));
    }
    Ok(())
}

fn validate_public_key(value: &str) -> Result<(), ApiError> {
    if value.is_empty()
        || value.len() > 160
        || value != value.trim()
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        return Err(ApiError::Validation(
            "public_key must use 1-160 ASCII letters, digits, '_' or '-'".to_owned(),
        ));
    }
    Ok(())
}

fn validate_connection_provider_kind(value: &str) -> Result<(), ApiError> {
    validate_key(value, "provider_kind", 80)
}

fn validate_idempotency_mode(value: &str) -> Result<(), ApiError> {
    if matches!(value.trim(), "required" | "supported" | "unavailable") {
        Ok(())
    } else {
        Err(ApiError::Validation(
            "idempotency_mode must be required, supported, or unavailable".to_owned(),
        ))
    }
}

fn validate_risk_level(value: &str) -> Result<(), ApiError> {
    if matches!(value.trim(), "low" | "medium" | "high") {
        Ok(())
    } else {
        Err(ApiError::Validation(
            "risk_level must be low, medium, or high".to_owned(),
        ))
    }
}

fn validate_timeout_seconds(value: i32) -> Result<(), ApiError> {
    if (1..=3_600).contains(&value) {
        Ok(())
    } else {
        Err(ApiError::Validation(
            "timeout_seconds must be between 1 and 3600".to_owned(),
        ))
    }
}

fn validate_name(value: &str, field: &str, max_len: usize) -> Result<(), ApiError> {
    validate_text(value, field, max_len, false)
}

fn validate_key(value: &str, field: &str, max_len: usize) -> Result<(), ApiError> {
    if value.trim().is_empty()
        || value.len() > max_len
        || value != value.trim()
        || value.contains(['\r', '\n'])
    {
        return Err(ApiError::Validation(format!(
            "{field} must contain between 1 and {max_len} characters"
        )));
    }
    Ok(())
}

fn validate_text(
    value: &str,
    field: &str,
    max_len: usize,
    allow_empty: bool,
) -> Result<(), ApiError> {
    if value.len() > max_len
        || value.contains(['\r', '\n'])
        || (!allow_empty && value.trim().is_empty())
    {
        return Err(ApiError::Validation(format!(
            "{field} must contain between {} and {max_len} characters",
            i32::from(!allow_empty)
        )));
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

fn default_timezone() -> String {
    "UTC".to_owned()
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use url::Url;
    use uuid::Uuid;

    use super::{
        connection_secret_aad, normalize_model_base_url, validate_idempotency_mode,
        validate_json_schema, validate_model_provider_kind, validate_risk_level,
        validate_secret_name, validate_timeout_seconds,
    };

    #[test]
    fn connection_secret_aad_is_stable_and_namespaced() {
        let connection_id = Uuid::nil();
        assert_eq!(
            connection_secret_aad(connection_id, "api_key"),
            "connection/00000000-0000-0000-0000-000000000000/api_key"
        );
    }

    #[test]
    fn model_profile_validation_rejects_unsafe_or_unsupported_urls() {
        assert!(normalize_model_base_url("https://api.example.com/v1/", false).is_ok());
        assert!(normalize_model_base_url("http://127.0.0.1:8080/v1", false).is_err());
        assert!(normalize_model_base_url("http://127.0.0.1:8080/v1", true).is_ok());
        assert!(normalize_model_base_url("ftp://api.example.com/model", true).is_err());
        assert!(normalize_model_base_url("https://user:pass@api.example.com/v1", false).is_err());
    }

    #[test]
    fn control_plane_enum_and_timeout_validation_is_bounded() {
        assert!(validate_model_provider_kind("openai_compatible").is_ok());
        assert!(validate_model_provider_kind("anthropic").is_err());
        assert!(validate_idempotency_mode("required").is_ok());
        assert!(validate_idempotency_mode("best_effort").is_err());
        assert!(validate_risk_level("high").is_ok());
        assert!(validate_risk_level("critical").is_err());
        assert!(validate_timeout_seconds(1).is_ok());
        assert!(validate_timeout_seconds(3_601).is_err());
    }

    #[test]
    fn secret_names_are_safe_for_aad_namespacing() {
        assert!(validate_secret_name("api_key").is_ok());
        assert!(validate_secret_name("api/key").is_err());
        assert!(validate_secret_name(" api_key").is_err());
    }

    #[test]
    fn object_defaults_are_json_objects() {
        assert!(json!({}).is_object());
    }

    #[test]
    fn capability_schemas_are_valid_and_cannot_fetch_external_refs() {
        assert!(
            validate_json_schema(
                &json!({
                    "type": "object",
                    "$defs": { "id": { "type": "string" } },
                    "properties": { "id": { "$ref": "#/$defs/id" } }
                }),
                "input_schema"
            )
            .is_ok()
        );
        assert!(
            validate_json_schema(
                &json!({ "$ref": "https://schemas.example.test/tool.json" }),
                "input_schema"
            )
            .is_err()
        );
        assert!(validate_json_schema(&json!({ "type": "not-a-type" }), "input_schema").is_err());
    }

    #[test]
    fn url_parser_keeps_the_expected_scheme_and_host() {
        let url = Url::parse("https://api.example.com/v1").expect("valid URL");
        assert_eq!(url.scheme(), "https");
        assert!(url.host().is_some());
    }
}
