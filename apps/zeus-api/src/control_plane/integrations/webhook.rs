use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    AppState,
    api_support::{ListCursor, PageQuery, required_revision, revision_etag},
    auth::{AuthContext, insert_audit},
    crypto::{random_token, sha256},
    database::begin_tenant,
    error::ApiError,
    idempotency::{self, IdempotencyDecision},
};

use super::{
    default_enabled, ensure_active_workflow, etag_headers, json_response, load_webhook_endpoint,
    validate_public_key,
};
use zeus_core::Permission;

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
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
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
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
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
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
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
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
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
