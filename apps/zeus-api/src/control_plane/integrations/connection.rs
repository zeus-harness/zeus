use std::collections::BTreeMap;

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
    empty_object, etag_headers, require_object, seal_connection_secret,
    validate_connection_provider_kind, validate_connection_secrets, validate_name,
    validate_secret_name, validate_secret_value,
};
use zeus_core::Permission;

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
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
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
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
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
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
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

    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
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
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
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
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
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
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
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
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
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
