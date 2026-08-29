#![allow(clippy::missing_errors_doc)] // HTTP failures use the shared Problem Details contract.

use std::collections::HashSet;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;
use zeus_core::Permission;

use crate::{
    AppState,
    api_support::{ListCursor, PageQuery},
    auth::{AuthContext, insert_audit},
    database::begin_tenant,
    error::ApiError,
};

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct ExperienceEvidenceRef {
    pub event_kind: String,
    pub event_id: Uuid,
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct ExperienceCandidateResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub workspace_id: Uuid,
    pub source_run_id: Uuid,
    pub proposed_scope: String,
    pub title: String,
    pub content: String,
    pub tags: Vec<String>,
    pub evidence: Value,
    pub status: String,
    pub reviewed_by: Option<Uuid>,
    pub reviewed_at: Option<OffsetDateTime>,
    pub review_reason: Option<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ExperienceCandidatePageResponse {
    pub items: Vec<ExperienceCandidateResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CandidateQuery {
    #[serde(flatten)]
    pub page: PageQuery,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateExperienceCandidateRequest {
    pub source_run_id: Uuid,
    pub proposed_scope: String,
    pub title: String,
    pub content: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub evidence: Vec<ExperienceEvidenceRef>,
}

pub async fn list_candidates(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    Query(query): Query<CandidateQuery>,
) -> Result<Json<ExperienceCandidatePageResponse>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let limit = query.page.limit()?;
    let cursor = query.page.decoded_cursor()?;
    if let Some(status) = query.status.as_deref() {
        validate_candidate_status(status)?;
    }
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let mut items = sqlx::query_as::<_, ExperienceCandidateResponse>(
        "select id, organization_id, workspace_id, source_run_id, proposed_scope,
                title, content, tags, evidence, status, reviewed_by, reviewed_at,
                review_reason, created_at
         from experience_candidates
         where organization_id = $1 and workspace_id = $2
           and ($3::text is null or status = $3)
           and ($4::timestamptz is null or (created_at, id) < ($4, $5))
         order by created_at desc, id desc limit $6",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(query.status)
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
    Ok(Json(ExperienceCandidatePageResponse { items, next_cursor }))
}

#[allow(clippy::too_many_lines)] // Run and evidence ownership are checked before one candidate insert.
pub async fn create_candidate(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    Json(mut request): Json<CreateExperienceCandidateRequest>,
) -> Result<(StatusCode, Json<ExperienceCandidateResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::OperateRun)?;
    normalize_candidate_request(&mut request)?;
    let evidence_json = serde_json::to_value(&request.evidence).map_err(|_| ApiError::Internal)?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let run_succeeded: bool = sqlx::query_scalar(
        "select exists(
           select 1 from runs
           where id = $1 and organization_id = $2 and workspace_id = $3 and status = 'succeeded'
         )",
    )
    .bind(request.source_run_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .fetch_one(&mut *transaction)
    .await?;
    if !run_succeeded {
        return Err(ApiError::Conflict(
            "experience can only be proposed from a succeeded run".to_owned(),
        ));
    }
    validate_evidence(
        &mut transaction,
        auth.organization_id,
        workspace_id,
        request.source_run_id,
        &request.evidence,
    )
    .await?;
    let candidate = sqlx::query_as::<_, ExperienceCandidateResponse>(
        "insert into experience_candidates (
            organization_id, workspace_id, source_run_id, proposed_scope,
            title, content, tags, evidence
         ) values ($1, $2, $3, $4, $5, $6, $7, $8)
         returning id, organization_id, workspace_id, source_run_id, proposed_scope,
                   title, content, tags, evidence, status, reviewed_by, reviewed_at,
                   review_reason, created_at",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(request.source_run_id)
    .bind(request.proposed_scope)
    .bind(request.title)
    .bind(request.content)
    .bind(request.tags)
    .bind(evidence_json)
    .fetch_one(&mut *transaction)
    .await?;
    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace_id),
        "experience.candidate_created",
        "experience_candidate",
        candidate.id,
    )
    .await?;
    transaction.commit().await?;
    Ok((StatusCode::CREATED, Json(candidate)))
}

pub async fn get_candidate(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, candidate_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ExperienceCandidateResponse>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let candidate = load_candidate(
        &mut transaction,
        auth.organization_id,
        workspace_id,
        candidate_id,
        false,
    )
    .await?;
    transaction.commit().await?;
    Ok(Json(candidate))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ReviewExperienceCandidateRequest {
    pub decision: String,
    pub reason: Option<String>,
}

pub async fn review_candidate(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, candidate_id)): Path<(Uuid, Uuid)>,
    Json(mut request): Json<ReviewExperienceCandidateRequest>,
) -> Result<Json<ExperienceCandidateResponse>, ApiError> {
    auth.require_workspace(workspace_id, Permission::PublishWorkspaceExperience)?;
    let reviewer = auth.user_id.ok_or(ApiError::Forbidden)?;
    if !matches!(request.decision.as_str(), "approved" | "rejected") {
        return Err(ApiError::Validation(
            "decision must be approved or rejected".to_owned(),
        ));
    }
    if let Some(reason) = request.reason.as_mut() {
        *reason = reason.trim().to_owned();
        if reason.len() > 4_000 {
            return Err(ApiError::Validation(
                "review reason exceeds 4000 characters".to_owned(),
            ));
        }
    }
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let candidate = sqlx::query_as::<_, ExperienceCandidateResponse>(
        "update experience_candidates
         set status = $1, reviewed_by = $2, reviewed_at = now(), review_reason = $3
         where id = $4 and organization_id = $5 and workspace_id = $6 and status = 'pending'
         returning id, organization_id, workspace_id, source_run_id, proposed_scope,
                   title, content, tags, evidence, status, reviewed_by, reviewed_at,
                   review_reason, created_at",
    )
    .bind(&request.decision)
    .bind(reviewer)
    .bind(request.reason)
    .bind(candidate_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| ApiError::Conflict("candidate is no longer pending".to_owned()))?;
    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace_id),
        if request.decision == "approved" {
            "experience.candidate_approved"
        } else {
            "experience.candidate_rejected"
        },
        "experience_candidate",
        candidate.id,
    )
    .await?;
    transaction.commit().await?;
    Ok(Json(candidate))
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct ExperienceEntryResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub workspace_id: Option<Uuid>,
    pub candidate_id: Uuid,
    pub source_run_id: Uuid,
    pub scope: String,
    pub version_number: i32,
    pub title: String,
    pub content: String,
    pub tags: Vec<String>,
    pub evidence: Value,
    pub published_by: Uuid,
    pub published_at: OffsetDateTime,
    pub withdrawn_at: Option<OffsetDateTime>,
    pub withdrawal_reason: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ExperienceEntryPageResponse {
    pub items: Vec<ExperienceEntryResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ExperienceEntryQuery {
    #[serde(flatten)]
    pub page: PageQuery,
    pub scope: Option<String>,
    #[serde(default)]
    pub include_withdrawn: bool,
}

pub async fn publish_candidate(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, candidate_id)): Path<(Uuid, Uuid)>,
) -> Result<(StatusCode, Json<ExperienceEntryResponse>), ApiError> {
    let publisher = auth.user_id.ok_or(ApiError::Forbidden)?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let candidate = load_candidate(
        &mut transaction,
        auth.organization_id,
        workspace_id,
        candidate_id,
        true,
    )
    .await?;
    if candidate.status != "approved" {
        return Err(ApiError::Conflict(
            "only an approved candidate can be published".to_owned(),
        ));
    }
    match candidate.proposed_scope.as_str() {
        "workspace" => {
            auth.require_workspace(workspace_id, Permission::PublishWorkspaceExperience)?;
        }
        "organization" => {
            auth.require_organization(
                auth.organization_id,
                Permission::PublishOrganizationExperience,
            )?;
        }
        _ => return Err(ApiError::Internal),
    }
    let entry_id: Uuid = sqlx::query_scalar(
        "insert into experience_entries (
            organization_id, workspace_id, candidate_id, scope, version_number,
            title, content, tags, evidence, published_by
         ) values (
            $1, case when $2 = 'workspace' then $3 else null end, $4, $2, 1,
            $5, $6, $7, $8, $9
         ) returning id",
    )
    .bind(auth.organization_id)
    .bind(&candidate.proposed_scope)
    .bind(workspace_id)
    .bind(candidate.id)
    .bind(candidate.title)
    .bind(candidate.content)
    .bind(candidate.tags)
    .bind(candidate.evidence)
    .bind(publisher)
    .fetch_one(&mut *transaction)
    .await?;
    let entry = load_entry(
        &mut transaction,
        auth.organization_id,
        workspace_id,
        entry_id,
    )
    .await?;
    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace_id),
        if entry.scope == "organization" {
            "experience.organization_published"
        } else {
            "experience.workspace_published"
        },
        "experience_entry",
        entry.id,
    )
    .await?;
    transaction.commit().await?;
    Ok((StatusCode::CREATED, Json(entry)))
}

pub async fn list_entries(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    Query(query): Query<ExperienceEntryQuery>,
) -> Result<Json<ExperienceEntryPageResponse>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    validate_entry_scope(query.scope.as_deref())?;
    let limit = query.page.limit()?;
    let cursor = query.page.decoded_cursor()?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let mut items = sqlx::query_as::<_, ExperienceEntryResponse>(&entry_select_sql(
        "and ($3::text is null or e.scope = $3)
             and ($4 or w.experience_entry_id is null)
             and ($5::timestamptz is null or (e.published_at, e.id) < ($5, $6))
             order by e.published_at desc, e.id desc limit $7",
    ))
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(query.scope)
    .bind(query.include_withdrawn)
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
            .map(|item| ListCursor::new(item.published_at, item.id).encode())
            .transpose()?
    } else {
        None
    };
    Ok(Json(ExperienceEntryPageResponse { items, next_cursor }))
}

pub async fn get_entry(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, entry_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ExperienceEntryResponse>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let entry = load_entry(
        &mut transaction,
        auth.organization_id,
        workspace_id,
        entry_id,
    )
    .await?;
    transaction.commit().await?;
    Ok(Json(entry))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct WithdrawExperienceRequest {
    pub reason: String,
}

pub async fn withdraw_entry(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, entry_id)): Path<(Uuid, Uuid)>,
    Json(mut request): Json<WithdrawExperienceRequest>,
) -> Result<StatusCode, ApiError> {
    let actor = auth.user_id.ok_or(ApiError::Forbidden)?;
    request.reason = request.reason.trim().to_owned();
    if request.reason.is_empty() || request.reason.len() > 4_000 {
        return Err(ApiError::Validation(
            "reason must contain between 1 and 4000 characters".to_owned(),
        ));
    }
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let entry = load_entry(
        &mut transaction,
        auth.organization_id,
        workspace_id,
        entry_id,
    )
    .await?;
    if entry.withdrawn_at.is_some() {
        return Err(ApiError::Conflict(
            "experience is already withdrawn".to_owned(),
        ));
    }
    if entry.scope == "organization" {
        auth.require_organization(
            auth.organization_id,
            Permission::PublishOrganizationExperience,
        )?;
    } else {
        auth.require_workspace(workspace_id, Permission::PublishWorkspaceExperience)?;
    }
    sqlx::query(
        "insert into experience_entry_withdrawals (
            organization_id, workspace_id, experience_entry_id, reason, withdrawn_by
         ) values ($1, $2, $3, $4, $5)",
    )
    .bind(auth.organization_id)
    .bind(entry.workspace_id)
    .bind(entry.id)
    .bind(request.reason)
    .bind(actor)
    .execute(&mut *transaction)
    .await?;
    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace_id),
        "experience.withdrawn",
        "experience_entry",
        entry.id,
    )
    .await?;
    transaction.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct ExperienceSearchQuery {
    pub q: String,
    pub scope: Option<String>,
    pub tags: Option<String>,
    pub limit: Option<u16>,
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct ExperienceSearchResult {
    pub id: Uuid,
    pub scope: String,
    pub version_number: i32,
    pub title: String,
    pub content: String,
    pub tags: Vec<String>,
    pub rank: f32,
    pub published_at: OffsetDateTime,
}

pub async fn search_entries(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    Query(mut query): Query<ExperienceSearchQuery>,
) -> Result<Json<Vec<ExperienceSearchResult>>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    query.q = query.q.trim().to_owned();
    if query.q.is_empty() || query.q.len() > 500 {
        return Err(ApiError::Validation(
            "q must contain between 1 and 500 characters".to_owned(),
        ));
    }
    validate_entry_scope(query.scope.as_deref())?;
    let tags = normalize_search_tags(query.tags.as_deref())?;
    let limit = query.limit.unwrap_or(20);
    if !(1..=50).contains(&limit) {
        return Err(ApiError::Validation(
            "limit must be between 1 and 50".to_owned(),
        ));
    }
    let mut transaction =
        begin_tenant(&state.database, auth.tenant_scope(Some(workspace_id))).await?;
    let entries = sqlx::query_as::<_, ExperienceSearchResult>(
        "with query as (select plainto_tsquery('simple', $4) as value)
         select e.id, e.scope, e.version_number, e.title, e.content, e.tags,
                ts_rank(e.search_vector, query.value)::real as rank, e.published_at
         from experience_entries e
         cross join query
         left join experience_entry_withdrawals w on w.experience_entry_id = e.id
         where e.organization_id = $1
           and (e.workspace_id is null or e.workspace_id = $2)
           and ($3::text is null or e.scope = $3)
           and w.experience_entry_id is null
           and (e.search_vector @@ query.value or ($5::text[] <> '{}' and e.tags && $5))
         order by rank desc, e.published_at desc, e.id desc limit $6",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(query.scope)
    .bind(query.q)
    .bind(tags)
    .bind(i64::from(limit))
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(entries))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/workspaces/{workspace_id}/experience-candidates",
            get(list_candidates).post(create_candidate),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/experience-candidates/{candidate_id}",
            get(get_candidate),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/experience-candidates/{candidate_id}/review",
            post(review_candidate),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/experience-candidates/{candidate_id}/publish",
            post(publish_candidate),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/experience-entries",
            get(list_entries),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/experience-entries/search",
            get(search_entries),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/experience-entries/{entry_id}",
            get(get_entry),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/experience-entries/{entry_id}/withdraw",
            post(withdraw_entry),
        )
}

fn normalize_candidate_request(
    request: &mut CreateExperienceCandidateRequest,
) -> Result<(), ApiError> {
    request.title = request.title.trim().to_owned();
    request.content = request.content.trim().to_owned();
    if request.title.is_empty() || request.title.len() > 500 || request.title.contains(['\r', '\n'])
    {
        return Err(ApiError::Validation(
            "title must contain between 1 and 500 characters on one line".to_owned(),
        ));
    }
    if request.content.is_empty() || request.content.len() > 100_000 {
        return Err(ApiError::Validation(
            "content must contain between 1 and 100000 characters".to_owned(),
        ));
    }
    if !matches!(
        request.proposed_scope.as_str(),
        "workspace" | "organization"
    ) {
        return Err(ApiError::Validation("proposed_scope is invalid".to_owned()));
    }
    request.tags = normalize_tags(std::mem::take(&mut request.tags))?;
    if request.evidence.is_empty() || request.evidence.len() > 100 {
        return Err(ApiError::Validation(
            "evidence must contain between 1 and 100 references".to_owned(),
        ));
    }
    let mut seen = HashSet::new();
    for evidence in &request.evidence {
        if !matches!(evidence.event_kind.as_str(), "session_event" | "run_event") {
            return Err(ApiError::Validation(
                "evidence event_kind is invalid".to_owned(),
            ));
        }
        if !seen.insert((evidence.event_kind.as_str(), evidence.event_id)) {
            return Err(ApiError::Validation(
                "evidence references must be unique".to_owned(),
            ));
        }
    }
    Ok(())
}

fn normalize_tags(tags: Vec<String>) -> Result<Vec<String>, ApiError> {
    if tags.len() > 20 {
        return Err(ApiError::Validation(
            "at most 20 tags are allowed".to_owned(),
        ));
    }
    let mut tags = tags
        .into_iter()
        .map(|tag| tag.trim().to_lowercase())
        .filter(|tag| !tag.is_empty())
        .collect::<Vec<_>>();
    if tags.iter().any(|tag| tag.len() > 64) {
        return Err(ApiError::Validation(
            "tags are limited to 64 characters".to_owned(),
        ));
    }
    tags.sort();
    tags.dedup();
    Ok(tags)
}

fn normalize_search_tags(value: Option<&str>) -> Result<Vec<String>, ApiError> {
    value.map_or_else(
        || Ok(Vec::new()),
        |value| normalize_tags(value.split(',').map(ToOwned::to_owned).collect()),
    )
}

fn validate_candidate_status(status: &str) -> Result<(), ApiError> {
    if matches!(status, "pending" | "approved" | "rejected") {
        Ok(())
    } else {
        Err(ApiError::Validation(
            "candidate status is invalid".to_owned(),
        ))
    }
}

fn validate_entry_scope(scope: Option<&str>) -> Result<(), ApiError> {
    if scope.is_none_or(|value| matches!(value, "workspace" | "organization")) {
        Ok(())
    } else {
        Err(ApiError::Validation(
            "experience scope is invalid".to_owned(),
        ))
    }
}

async fn validate_evidence(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: Uuid,
    workspace_id: Uuid,
    run_id: Uuid,
    evidence: &[ExperienceEvidenceRef],
) -> Result<(), ApiError> {
    let session_ids = evidence
        .iter()
        .filter(|item| item.event_kind == "session_event")
        .map(|item| item.event_id)
        .collect::<Vec<_>>();
    let run_ids = evidence
        .iter()
        .filter(|item| item.event_kind == "run_event")
        .map(|item| item.event_id)
        .collect::<Vec<_>>();
    let session_count: i64 = sqlx::query_scalar(
        "select count(*)::bigint from session_events
         where organization_id = $1 and workspace_id = $2 and run_id = $3 and id = any($4)",
    )
    .bind(organization_id)
    .bind(workspace_id)
    .bind(run_id)
    .bind(&session_ids)
    .fetch_one(&mut **transaction)
    .await?;
    let run_count: i64 = sqlx::query_scalar(
        "select count(*)::bigint from run_events
         where organization_id = $1 and workspace_id = $2 and run_id = $3 and id = any($4)",
    )
    .bind(organization_id)
    .bind(workspace_id)
    .bind(run_id)
    .bind(&run_ids)
    .fetch_one(&mut **transaction)
    .await?;
    if usize::try_from(session_count).ok() != Some(session_ids.len())
        || usize::try_from(run_count).ok() != Some(run_ids.len())
    {
        return Err(ApiError::Validation(
            "evidence must reference events from the source run".to_owned(),
        ));
    }
    Ok(())
}

async fn load_candidate(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: Uuid,
    workspace_id: Uuid,
    candidate_id: Uuid,
    for_update: bool,
) -> Result<ExperienceCandidateResponse, ApiError> {
    let suffix = if for_update { " for update" } else { "" };
    let query = format!(
        "select id, organization_id, workspace_id, source_run_id, proposed_scope,
                title, content, tags, evidence, status, reviewed_by, reviewed_at,
                review_reason, created_at
         from experience_candidates
         where id = $1 and organization_id = $2 and workspace_id = $3{suffix}"
    );
    sqlx::query_as::<_, ExperienceCandidateResponse>(&query)
        .bind(candidate_id)
        .bind(organization_id)
        .bind(workspace_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(Into::into)
}

async fn load_entry(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: Uuid,
    workspace_id: Uuid,
    entry_id: Uuid,
) -> Result<ExperienceEntryResponse, ApiError> {
    sqlx::query_as::<_, ExperienceEntryResponse>(&entry_select_sql("and e.id = $3"))
        .bind(organization_id)
        .bind(workspace_id)
        .bind(entry_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(Into::into)
}

fn entry_select_sql(suffix: &str) -> String {
    format!(
        "select e.id, e.organization_id, e.workspace_id, e.candidate_id,
                c.source_run_id, e.scope, e.version_number, e.title, e.content,
                e.tags, e.evidence, e.published_by, e.published_at,
                w.withdrawn_at, w.reason as withdrawal_reason
         from experience_entries e
         join experience_candidates c on c.id = e.candidate_id
         left join experience_entry_withdrawals w on w.experience_entry_id = e.id
         where e.organization_id = $1
           and (e.workspace_id is null or e.workspace_id = $2)
           and c.organization_id = $1 {suffix}"
    )
}

#[cfg(test)]
mod tests {
    use super::{
        CreateExperienceCandidateRequest, ExperienceEvidenceRef, normalize_candidate_request,
        normalize_search_tags,
    };
    use uuid::Uuid;

    #[test]
    fn candidate_requires_unique_run_evidence() {
        let event_id = Uuid::now_v7();
        let mut request = CreateExperienceCandidateRequest {
            source_run_id: Uuid::now_v7(),
            proposed_scope: "workspace".to_owned(),
            title: "Useful result".to_owned(),
            content: "Call the billing API with the invoice id.".to_owned(),
            tags: vec![" Billing ".to_owned(), "billing".to_owned()],
            evidence: vec![
                ExperienceEvidenceRef {
                    event_kind: "run_event".to_owned(),
                    event_id,
                },
                ExperienceEvidenceRef {
                    event_kind: "run_event".to_owned(),
                    event_id,
                },
            ],
        };
        assert!(normalize_candidate_request(&mut request).is_err());
    }

    #[test]
    fn search_tags_are_normalized_and_bounded() {
        assert_eq!(
            normalize_search_tags(Some(" Billing,invoice,billing ")).unwrap(),
            vec!["billing".to_owned(), "invoice".to_owned()]
        );
    }
}
