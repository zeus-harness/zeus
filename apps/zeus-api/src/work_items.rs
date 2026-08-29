#![allow(clippy::missing_errors_doc)] // HTTP failures use the shared Problem Details contract.

use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::FromRow;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;
use zeus_core::{Permission, WorkItemState};

use crate::{
    AppState,
    api_support::{ListCursor, PageQuery, required_revision, revision_etag},
    auth::{AuthContext, insert_audit},
    crypto::sha256,
    database::begin_tenant,
    error::ApiError,
    idempotency::{self, IdempotencyDecision},
};

const MAX_ATTACHMENT_BYTES: usize = 5 * 1024 * 1024;

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct WorkItemResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub workspace_id: Uuid,
    pub title: String,
    pub description: String,
    pub status: String,
    pub priority: String,
    pub assignee_user_id: Option<Uuid>,
    pub source_kind: Option<String>,
    pub external_reference: Option<String>,
    pub input: Value,
    pub output: Option<Value>,
    pub revision: i64,
    pub created_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub completed_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WorkItemPageResponse {
    pub items: Vec<WorkItemResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct WorkItemQuery {
    #[serde(flatten)]
    pub page: PageQuery,
    pub status: Option<String>,
    pub assignee_user_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct CreateWorkItemRequest {
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "normal_priority")]
    pub priority: String,
    pub assignee_user_id: Option<Uuid>,
    pub source_kind: Option<String>,
    pub external_reference: Option<String>,
    #[serde(default = "empty_object")]
    pub input: Value,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct UpdateWorkItemRequest {
    pub title: Option<String>,
    pub description: Option<String>,
    pub status: Option<String>,
    pub priority: Option<String>,
    pub assignee_user_id: Option<Uuid>,
    #[serde(default)]
    pub clear_assignee: bool,
    pub input: Option<Value>,
    pub output: Option<Value>,
}

pub async fn list_work_items(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    Query(query): Query<WorkItemQuery>,
) -> Result<Json<WorkItemPageResponse>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let limit = query.page.limit()?;
    let cursor = query.page.decoded_cursor()?;
    if let Some(status) = query.status.as_deref() {
        parse_state(status)?;
    }
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let mut items = sqlx::query_as::<_, WorkItemResponse>(
        "select id, organization_id, workspace_id, title, description, status, priority,
                assignee_user_id, source_kind, external_reference, input, output, revision,
                created_by, created_at, updated_at, completed_at
         from work_items
         where organization_id = $1 and workspace_id = $2
           and ($3::text is null or status = $3)
           and ($4::uuid is null or assignee_user_id = $4)
           and ($5::timestamptz is null or (created_at, id) < ($5, $6))
         order by created_at desc, id desc limit $7",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(query.status)
    .bind(query.assignee_user_id)
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
    Ok(Json(WorkItemPageResponse { items, next_cursor }))
}

#[allow(clippy::too_many_lines)] // Creation, idempotency, membership, and audit share one transaction.
pub async fn create_work_item(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    headers: HeaderMap,
    Json(mut request): Json<CreateWorkItemRequest>,
) -> Result<Response, ApiError> {
    auth.require_workspace(workspace_id, Permission::OperateRun)?;
    normalize_create_request(&mut request)?;
    let path = format!("/api/v1/workspaces/{workspace_id}/work-items");
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
    if let Some(assignee) = request.assignee_user_id {
        require_workspace_member(
            &mut transaction,
            auth.organization_id,
            workspace_id,
            assignee,
        )
        .await?;
    }
    let idempotency_key = required_idempotency_key(&headers)?;
    let item = sqlx::query_as::<_, WorkItemResponse>(
        "insert into work_items (
            organization_id, workspace_id, title, description, priority, assignee_user_id,
            source_kind, external_reference, input, idempotency_key, created_by
         ) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         returning id, organization_id, workspace_id, title, description, status, priority,
                   assignee_user_id, source_kind, external_reference, input, output, revision,
                   created_by, created_at, updated_at, completed_at",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(request.title)
    .bind(request.description)
    .bind(request.priority)
    .bind(request.assignee_user_id)
    .bind(request.source_kind)
    .bind(request.external_reference)
    .bind(request.input)
    .bind(idempotency_key)
    .bind(auth.user_id)
    .fetch_one(&mut *transaction)
    .await?;
    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace_id),
        "work_item.created",
        "work_item",
        item.id,
    )
    .await?;
    idempotency::complete(&mut transaction, &reservation, 201, &item).await?;
    transaction.commit().await?;
    let headers = etag_headers(item.revision)?;
    Ok((StatusCode::CREATED, headers, Json(item)).into_response())
}

pub async fn get_work_item(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, work_item_id)): Path<(Uuid, Uuid)>,
) -> Result<(HeaderMap, Json<WorkItemResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let item = load_work_item(
        &mut transaction,
        auth.organization_id,
        workspace_id,
        work_item_id,
        false,
    )
    .await?;
    transaction.commit().await?;
    Ok((etag_headers(item.revision)?, Json(item)))
}

#[allow(clippy::too_many_lines)] // Revision check and transition validation must share the row lock.
pub async fn update_work_item(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, work_item_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(mut request): Json<UpdateWorkItemRequest>,
) -> Result<(HeaderMap, Json<WorkItemResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::OperateRun)?;
    let revision = required_revision(&headers)?;
    normalize_update_request(&mut request)?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let current = load_work_item(
        &mut transaction,
        auth.organization_id,
        workspace_id,
        work_item_id,
        true,
    )
    .await?;
    if current.revision != revision {
        return Err(ApiError::PreconditionFailed);
    }
    if let Some(status) = request.status.as_deref() {
        parse_state(&current.status)?
            .transition(parse_state(status)?)
            .map_err(|_| {
                ApiError::Conflict("work item state transition is not allowed".to_owned())
            })?;
    }
    if let Some(assignee) = request.assignee_user_id {
        require_workspace_member(
            &mut transaction,
            auth.organization_id,
            workspace_id,
            assignee,
        )
        .await?;
    }
    let item = sqlx::query_as::<_, WorkItemResponse>(
        "update work_items
         set title = coalesce($1, title),
             description = coalesce($2, description),
             status = coalesce($3, status),
             priority = coalesce($4, priority),
             assignee_user_id = case when $5 then null else coalesce($6, assignee_user_id) end,
             input = coalesce($7, input),
             output = coalesce($8, output),
             completed_at = case
               when $3 = 'completed' then coalesce(completed_at, now())
               else completed_at
             end,
             revision = revision + 1,
             updated_at = now()
         where id = $9 and organization_id = $10 and workspace_id = $11 and revision = $12
         returning id, organization_id, workspace_id, title, description, status, priority,
                   assignee_user_id, source_kind, external_reference, input, output, revision,
                   created_by, created_at, updated_at, completed_at",
    )
    .bind(request.title)
    .bind(request.description)
    .bind(request.status)
    .bind(request.priority)
    .bind(request.clear_assignee)
    .bind(request.assignee_user_id)
    .bind(request.input)
    .bind(request.output)
    .bind(work_item_id)
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
        "work_item.updated",
        "work_item",
        item.id,
    )
    .await?;
    transaction.commit().await?;
    Ok((etag_headers(item.revision)?, Json(item)))
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct ExternalReferenceResponse {
    pub id: Uuid,
    pub work_item_id: Uuid,
    pub source_kind: String,
    pub external_reference: String,
    pub metadata: Value,
    pub created_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateExternalReferenceRequest {
    pub source_kind: String,
    pub external_reference: String,
    #[serde(default = "empty_object")]
    pub metadata: Value,
}

pub async fn list_external_references(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, work_item_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Vec<ExternalReferenceResponse>>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    ensure_work_item_exists(
        &mut transaction,
        auth.organization_id,
        workspace_id,
        work_item_id,
    )
    .await?;
    let references = sqlx::query_as::<_, ExternalReferenceResponse>(
        "select id, work_item_id, source_kind, external_reference, metadata, created_by, created_at
         from work_item_external_references
         where organization_id = $1 and workspace_id = $2 and work_item_id = $3
         order by created_at, id limit 500",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(work_item_id)
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(references))
}

pub async fn create_external_reference(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, work_item_id)): Path<(Uuid, Uuid)>,
    Json(mut request): Json<CreateExternalReferenceRequest>,
) -> Result<(StatusCode, Json<ExternalReferenceResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::OperateRun)?;
    request.source_kind = request.source_kind.trim().to_ascii_lowercase();
    request.external_reference = request.external_reference.trim().to_owned();
    validate_source_kind(&request.source_kind)?;
    if request.external_reference.is_empty() || request.external_reference.len() > 2_048 {
        return Err(ApiError::Validation(
            "external_reference must contain between 1 and 2048 characters".to_owned(),
        ));
    }
    require_object(&request.metadata, "metadata")?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    ensure_work_item_exists(
        &mut transaction,
        auth.organization_id,
        workspace_id,
        work_item_id,
    )
    .await?;
    let reference = sqlx::query_as::<_, ExternalReferenceResponse>(
        "insert into work_item_external_references (
            organization_id, workspace_id, work_item_id, source_kind,
            external_reference, metadata, created_by
         ) values ($1, $2, $3, $4, $5, $6, $7)
         returning id, work_item_id, source_kind, external_reference, metadata,
                   created_by, created_at",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(work_item_id)
    .bind(request.source_kind)
    .bind(request.external_reference)
    .bind(request.metadata)
    .bind(auth.user_id)
    .fetch_one(&mut *transaction)
    .await?;
    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace_id),
        "work_item.external_reference_added",
        "work_item",
        work_item_id,
    )
    .await?;
    transaction.commit().await?;
    Ok((StatusCode::CREATED, Json(reference)))
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct AttachmentResponse {
    pub id: Uuid,
    pub work_item_id: Option<Uuid>,
    pub file_name: String,
    pub content_type: String,
    pub sha256_hex: String,
    pub size_bytes: i32,
    pub created_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, FromRow)]
struct StoredAttachment {
    id: Uuid,
    work_item_id: Option<Uuid>,
    file_name: String,
    content_type: String,
    sha256: Vec<u8>,
    size_bytes: i32,
    created_by: Option<Uuid>,
    created_at: OffsetDateTime,
}

impl From<StoredAttachment> for AttachmentResponse {
    fn from(value: StoredAttachment) -> Self {
        Self {
            id: value.id,
            work_item_id: value.work_item_id,
            file_name: value.file_name,
            content_type: value.content_type,
            sha256_hex: hex::encode(value.sha256),
            size_bytes: value.size_bytes,
            created_by: value.created_by,
            created_at: value.created_at,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateAttachmentRequest {
    pub file_name: String,
    pub content_type: String,
    pub content_base64: String,
}

pub async fn list_attachments(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, work_item_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Vec<AttachmentResponse>>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    ensure_work_item_exists(
        &mut transaction,
        auth.organization_id,
        workspace_id,
        work_item_id,
    )
    .await?;
    let attachments = sqlx::query_as::<_, StoredAttachment>(
        "select id, work_item_id, file_name, content_type, sha256, size_bytes,
                created_by, created_at
         from attachments
         where organization_id = $1 and workspace_id = $2 and work_item_id = $3
         order by created_at, id limit 500",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(work_item_id)
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(
        attachments
            .into_iter()
            .map(AttachmentResponse::from)
            .collect(),
    ))
}

pub async fn create_attachment(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, work_item_id)): Path<(Uuid, Uuid)>,
    Json(mut request): Json<CreateAttachmentRequest>,
) -> Result<(StatusCode, Json<AttachmentResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::OperateRun)?;
    request.file_name = request.file_name.trim().to_owned();
    request.content_type = request.content_type.trim().to_ascii_lowercase();
    validate_attachment_metadata(&request.file_name, &request.content_type)?;
    let data = STANDARD
        .decode(request.content_base64.as_bytes())
        .map_err(|_| ApiError::Validation("content_base64 is malformed".to_owned()))?;
    if data.len() > MAX_ATTACHMENT_BYTES {
        return Err(ApiError::Validation(
            "attachment exceeds the 5 MiB limit".to_owned(),
        ));
    }
    let size_bytes = i32::try_from(data.len()).map_err(|_| ApiError::Internal)?;
    let digest = sha256(&data);
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    ensure_work_item_exists(
        &mut transaction,
        auth.organization_id,
        workspace_id,
        work_item_id,
    )
    .await?;
    let attachment = sqlx::query_as::<_, StoredAttachment>(
        "insert into attachments (
            organization_id, workspace_id, work_item_id, file_name, content_type,
            sha256, size_bytes, data, created_by
         ) values ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         returning id, work_item_id, file_name, content_type, sha256, size_bytes,
                   created_by, created_at",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(work_item_id)
    .bind(request.file_name)
    .bind(request.content_type)
    .bind(digest)
    .bind(size_bytes)
    .bind(data)
    .bind(auth.user_id)
    .fetch_one(&mut *transaction)
    .await?;
    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace_id),
        "work_item.attachment_added",
        "attachment",
        attachment.id,
    )
    .await?;
    transaction.commit().await?;
    Ok((StatusCode::CREATED, Json(attachment.into())))
}

#[derive(Debug, FromRow)]
struct AttachmentDownload {
    file_name: String,
    content_type: String,
    data: Vec<u8>,
}

pub async fn download_attachment(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, work_item_id, attachment_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<Response, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let attachment = sqlx::query_as::<_, AttachmentDownload>(
        "select file_name, content_type, data
         from attachments
         where id = $1 and organization_id = $2 and workspace_id = $3 and work_item_id = $4",
    )
    .bind(attachment_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(work_item_id)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;

    let mut response = Response::new(Body::from(attachment.data));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&attachment.content_type).map_err(|_| ApiError::Internal)?,
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!(
            "attachment; filename=\"{}\"",
            escape_file_name(&attachment.file_name)
        ))
        .map_err(|_| ApiError::Internal)?,
    );
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    Ok(response)
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/workspaces/{workspace_id}/work-items",
            get(list_work_items).post(create_work_item),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/work-items/{work_item_id}",
            get(get_work_item).patch(update_work_item),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/work-items/{work_item_id}/external-references",
            get(list_external_references).post(create_external_reference),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/work-items/{work_item_id}/attachments",
            get(list_attachments).post(create_attachment),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/work-items/{work_item_id}/attachments/{attachment_id}",
            get(download_attachment),
        )
}

fn normalize_create_request(request: &mut CreateWorkItemRequest) -> Result<(), ApiError> {
    request.title = request.title.trim().to_owned();
    validate_title(&request.title)?;
    validate_description(&request.description)?;
    validate_priority(&request.priority)?;
    require_object(&request.input, "input")?;
    request.source_kind = request
        .source_kind
        .take()
        .map(|value| value.trim().to_ascii_lowercase());
    request.external_reference = request
        .external_reference
        .take()
        .map(|value| value.trim().to_owned());
    match (
        request.source_kind.as_deref(),
        request.external_reference.as_deref(),
    ) {
        (Some(source), Some(reference)) => {
            validate_source_kind(source)?;
            if reference.is_empty() || reference.len() > 2_048 {
                return Err(ApiError::Validation(
                    "external_reference must contain between 1 and 2048 characters".to_owned(),
                ));
            }
        }
        (None, None) => {}
        _ => {
            return Err(ApiError::Validation(
                "source_kind and external_reference must be supplied together".to_owned(),
            ));
        }
    }
    Ok(())
}

fn normalize_update_request(request: &mut UpdateWorkItemRequest) -> Result<(), ApiError> {
    if request.clear_assignee && request.assignee_user_id.is_some() {
        return Err(ApiError::Validation(
            "clear_assignee and assignee_user_id cannot be used together".to_owned(),
        ));
    }
    if let Some(title) = request.title.as_mut() {
        *title = title.trim().to_owned();
        validate_title(title)?;
    }
    if let Some(description) = request.description.as_deref() {
        validate_description(description)?;
    }
    if let Some(status) = request.status.as_deref() {
        parse_state(status)?;
    }
    if let Some(priority) = request.priority.as_deref() {
        validate_priority(priority)?;
    }
    if let Some(input) = request.input.as_ref() {
        require_object(input, "input")?;
    }
    if let Some(output) = request.output.as_ref() {
        require_object(output, "output")?;
    }
    Ok(())
}

fn validate_title(value: &str) -> Result<(), ApiError> {
    if value.is_empty() || value.len() > 500 || value.contains(['\r', '\n']) {
        return Err(ApiError::Validation(
            "title must contain between 1 and 500 characters on one line".to_owned(),
        ));
    }
    Ok(())
}

fn validate_description(value: &str) -> Result<(), ApiError> {
    if value.len() > 50_000 {
        return Err(ApiError::Validation(
            "description exceeds 50000 characters".to_owned(),
        ));
    }
    Ok(())
}

fn validate_priority(value: &str) -> Result<(), ApiError> {
    if !matches!(value, "low" | "normal" | "high" | "urgent") {
        return Err(ApiError::Validation("priority is invalid".to_owned()));
    }
    Ok(())
}

fn parse_state(value: &str) -> Result<WorkItemState, ApiError> {
    WorkItemState::try_from(value).map_err(|_| ApiError::Validation("status is invalid".to_owned()))
}

fn validate_source_kind(value: &str) -> Result<(), ApiError> {
    if value.is_empty()
        || value.len() > 64
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
        || !value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return Err(ApiError::Validation("source_kind is invalid".to_owned()));
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

fn validate_attachment_metadata(file_name: &str, content_type: &str) -> Result<(), ApiError> {
    if file_name.is_empty()
        || file_name.len() > 255
        || file_name.contains(['\r', '\n'])
        || file_name.contains('/')
        || file_name.contains('\\')
    {
        return Err(ApiError::Validation("file_name is invalid".to_owned()));
    }
    if content_type.is_empty()
        || content_type.len() > 255
        || content_type.contains(['\r', '\n'])
        || !content_type.contains('/')
    {
        return Err(ApiError::Validation("content_type is invalid".to_owned()));
    }
    Ok(())
}

fn escape_file_name(value: &str) -> String {
    value.replace(['\\', '"'], "_")
}

async fn require_workspace_member(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: Uuid,
    workspace_id: Uuid,
    user_id: Uuid,
) -> Result<(), ApiError> {
    let exists: bool = sqlx::query_scalar(
        "select exists(
           select 1 from workspace_memberships
           where organization_id = $1 and workspace_id = $2 and user_id = $3 and status = 'active'
         )",
    )
    .bind(organization_id)
    .bind(workspace_id)
    .bind(user_id)
    .fetch_one(&mut **transaction)
    .await?;
    if exists {
        Ok(())
    } else {
        Err(ApiError::Validation(
            "assignee is not an active workspace member".to_owned(),
        ))
    }
}

async fn ensure_work_item_exists(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: Uuid,
    workspace_id: Uuid,
    work_item_id: Uuid,
) -> Result<(), ApiError> {
    let exists: bool = sqlx::query_scalar(
        "select exists(
           select 1 from work_items where id = $1 and organization_id = $2 and workspace_id = $3
         )",
    )
    .bind(work_item_id)
    .bind(organization_id)
    .bind(workspace_id)
    .fetch_one(&mut **transaction)
    .await?;
    if exists {
        Ok(())
    } else {
        Err(ApiError::NotFound)
    }
}

async fn load_work_item(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: Uuid,
    workspace_id: Uuid,
    work_item_id: Uuid,
    for_update: bool,
) -> Result<WorkItemResponse, ApiError> {
    let suffix = if for_update { " for update" } else { "" };
    let query = format!(
        "select id, organization_id, workspace_id, title, description, status, priority,
                assignee_user_id, source_kind, external_reference, input, output, revision,
                created_by, created_at, updated_at, completed_at
         from work_items where id = $1 and organization_id = $2 and workspace_id = $3{suffix}"
    );
    sqlx::query_as::<_, WorkItemResponse>(&query)
        .bind(work_item_id)
        .bind(organization_id)
        .bind(workspace_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(Into::into)
}

fn required_idempotency_key(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get("idempotency-key")
        .ok_or_else(|| ApiError::BadRequest("Idempotency-Key is required".to_owned()))?
        .to_str()
        .map_err(|_| ApiError::BadRequest("Idempotency-Key is malformed".to_owned()))
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

fn normal_priority() -> String {
    "normal".to_owned()
}

fn empty_object() -> Value {
    json!({})
}

#[cfg(test)]
mod tests {
    use super::{
        CreateWorkItemRequest, UpdateWorkItemRequest, normalize_create_request,
        normalize_update_request, validate_attachment_metadata,
    };
    use serde_json::json;

    #[test]
    fn work_item_input_and_external_reference_are_bounded() {
        let mut request = CreateWorkItemRequest {
            title: "  Investigate invoice  ".to_owned(),
            description: String::new(),
            priority: "high".to_owned(),
            assignee_user_id: None,
            source_kind: Some(" CRM ".to_owned()),
            external_reference: Some(" case-42 ".to_owned()),
            input: json!({}),
        };
        normalize_create_request(&mut request).expect("valid work item");
        assert_eq!(request.title, "Investigate invoice");
        assert_eq!(request.source_kind.as_deref(), Some("crm"));
        assert_eq!(request.external_reference.as_deref(), Some("case-42"));
    }

    #[test]
    fn assignment_cannot_be_set_and_cleared_together() {
        let mut request = UpdateWorkItemRequest {
            assignee_user_id: Some(uuid::Uuid::now_v7()),
            clear_assignee: true,
            ..UpdateWorkItemRequest::default()
        };
        assert!(normalize_update_request(&mut request).is_err());
    }

    #[test]
    fn attachment_metadata_rejects_header_and_path_injection() {
        assert!(validate_attachment_metadata("report.pdf", "application/pdf").is_ok());
        assert!(validate_attachment_metadata("../secret", "text/plain").is_err());
        assert!(validate_attachment_metadata("report\r\nX-Test: 1", "text/plain").is_err());
    }
}
