#![allow(clippy::missing_errors_doc)] // HTTP failures use the shared Problem Details contract.

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    routing::{get, patch, post},
};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;
use zeus_core::{OrganizationRole, Permission};

use crate::{
    AppState,
    api_support::{ListCursor, PageQuery, required_revision, revision_etag},
    auth::{
        AuthContext, PrincipalContext, PrincipalKind, csrf_cookie, insert_audit, session_cookie,
    },
    crypto::{random_token, sha256},
    database::{TenantScope, begin_tenant},
    error::ApiError,
    oidc::validate_remote_url,
};

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct OrganizationResponse {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub status: String,
    pub revision: i64,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub archived_at: Option<OffsetDateTime>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateOrganizationRequest {
    pub slug: String,
    pub name: String,
    pub initial_workspace_slug: String,
    pub initial_workspace_name: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateOrganizationRequest {
    pub name: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, FromRow)]
struct CreatedOrganizationRow {
    organization_id: Uuid,
    workspace_id: Uuid,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreatedOrganizationResponse {
    pub organization_id: Uuid,
    pub workspace_id: Uuid,
}

#[utoipa::path(post, path = "/api/v1/organizations", tag = "organization",
    request_body = CreateOrganizationRequest,
    responses((status = 201, description = "Organization and initial workspace", body = CreatedOrganizationResponse))
)]
pub async fn create_organization(
    State(state): State<AppState>,
    auth: PrincipalContext,
    Json(request): Json<CreateOrganizationRequest>,
) -> Result<(StatusCode, HeaderMap, Json<CreatedOrganizationResponse>), ApiError> {
    if auth.principal_kind != PrincipalKind::User {
        return Err(ApiError::Forbidden);
    }
    if auth.email_verified_at.is_none() {
        return Err(ApiError::EmailVerificationRequired);
    }
    validate_slug(&request.slug)?;
    validate_slug(&request.initial_workspace_slug)?;
    validate_name(&request.name)?;
    validate_name(&request.initial_workspace_name)?;
    let user_id = auth.user_id.ok_or(ApiError::Forbidden)?;
    let session_id = auth.session_id.ok_or(ApiError::Forbidden)?;
    let mfa_enabled: bool = sqlx::query_scalar(
        "select exists (
           select 1 from zeus_private.load_totp_credential($1)
           where confirmed_at is not null
         )",
    )
    .bind(user_id)
    .fetch_one(&state.platform.database)
    .await?;
    if (mfa_enabled || auth.platform_roles.contains("platform_admin"))
        && auth.mfa_satisfied_at.is_none()
    {
        return Err(ApiError::MfaRequired);
    }
    let created = sqlx::query_as::<_, CreatedOrganizationRow>(
        "select * from zeus_private.create_organization_for_user($1, $2, $3, $4, $5)",
    )
    .bind(user_id)
    .bind(request.slug)
    .bind(request.name)
    .bind(request.initial_workspace_slug)
    .bind(request.initial_workspace_name)
    .fetch_one(&state.platform.database)
    .await?;
    let session_token = random_token(32).map_err(|_| ApiError::Internal)?;
    let csrf_token = random_token(32).map_err(|_| ApiError::Internal)?;
    let selected: bool = sqlx::query_scalar(
        "select zeus_private.rotate_user_session_context($1, $2, $3, $4, $5, $6)",
    )
    .bind(session_id)
    .bind(user_id)
    .bind(created.organization_id)
    .bind(created.workspace_id)
    .bind(sha256(session_token.expose_secret().as_bytes()))
    .bind(sha256(csrf_token.expose_secret().as_bytes()))
    .fetch_one(&state.platform.database)
    .await?;
    if !selected {
        return Err(ApiError::Internal);
    }
    let mut headers = HeaderMap::new();
    headers.append(
        header::SET_COOKIE,
        session_cookie(
            &state,
            session_token.expose_secret(),
            state.identity.session_absolute_ttl.as_secs(),
        )
        .parse()
        .map_err(|_| ApiError::Internal)?,
    );
    headers.append(
        header::SET_COOKIE,
        csrf_cookie(
            &state,
            csrf_token.expose_secret(),
            state.identity.session_absolute_ttl.as_secs(),
        )
        .parse()
        .map_err(|_| ApiError::Internal)?,
    );
    Ok((
        StatusCode::CREATED,
        headers,
        Json(CreatedOrganizationResponse {
            organization_id: created.organization_id,
            workspace_id: created.workspace_id,
        }),
    ))
}

#[utoipa::path(get, path = "/api/v1/organizations/{organization_id}", tag = "organization",
    params(("organization_id" = Uuid, Path)),
    responses((status = 200, description = "Organization", body = OrganizationResponse))
)]
pub async fn get_organization(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(organization_id): Path<Uuid>,
) -> Result<(HeaderMap, Json<OrganizationResponse>), ApiError> {
    auth.require_organization(organization_id, Permission::ReadWorkspace)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let organization = sqlx::query_as::<_, OrganizationResponse>(
        "select id, slug, name, status, revision, created_at, updated_at, archived_at
         from organizations where id = $1",
    )
    .bind(organization_id)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    let mut headers = HeaderMap::new();
    headers.insert(header::ETAG, revision_etag(organization.revision)?);
    Ok((headers, Json(organization)))
}

#[utoipa::path(patch, path = "/api/v1/organizations/{organization_id}", tag = "organization",
    params(("organization_id" = Uuid, Path), ("If-Match" = String, Header)),
    request_body = UpdateOrganizationRequest,
    responses((status = 200, description = "Updated organization", body = OrganizationResponse), (status = 412, description = "Revision mismatch"))
)]
pub async fn update_organization(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<UpdateOrganizationRequest>,
) -> Result<(HeaderMap, Json<OrganizationResponse>), ApiError> {
    auth.require_organization(organization_id, Permission::ManageOrganization)?;
    let revision = required_revision(&headers)?;
    if let Some(name) = request.name.as_deref() {
        validate_name(name)?;
    }
    if let Some(status) = request.status.as_deref()
        && !matches!(status, "active" | "suspended" | "archived")
    {
        return Err(ApiError::Validation(
            "unknown organization status".to_owned(),
        ));
    }
    let mut transaction = begin_tenant(
        &state.platform.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let updated = sqlx::query_as::<_, OrganizationResponse>(
        "update organizations
         set name = coalesce($1, name),
             status = coalesce($2, status),
             archived_at = case when $2 = 'archived' then coalesce(archived_at, now()) else archived_at end,
             revision = revision + 1,
             updated_at = now()
         where id = $3 and revision = $4
         returning id, slug, name, status, revision, created_at, updated_at, archived_at",
    )
    .bind(request.name)
    .bind(request.status)
    .bind(organization_id)
    .bind(revision)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(ApiError::PreconditionFailed)?;
    insert_audit(
        &mut transaction,
        &auth,
        None,
        "organization.updated",
        "organization",
        organization_id,
    )
    .await?;
    transaction.commit().await?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(header::ETAG, revision_etag(updated.revision)?);
    Ok((response_headers, Json(updated)))
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct WorkspaceResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub slug: String,
    pub name: String,
    pub status: String,
    pub revision: i64,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub archived_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WorkspacePageResponse {
    pub items: Vec<WorkspaceResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateWorkspaceRequest {
    pub slug: String,
    pub name: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateWorkspaceRequest {
    pub name: Option<String>,
    pub status: Option<String>,
}

#[utoipa::path(get, path = "/api/v1/organizations/{organization_id}/workspaces", tag = "organization",
    params(("organization_id" = Uuid, Path), ("cursor" = Option<String>, Query), ("limit" = Option<u16>, Query)),
    responses((status = 200, description = "Organization workspaces", body = WorkspacePageResponse))
)]
pub async fn list_workspaces(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(organization_id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<WorkspacePageResponse>, ApiError> {
    auth.require_organization(organization_id, Permission::ReadWorkspace)?;
    let limit = page.limit()?;
    let cursor = page.decoded_cursor()?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let mut items = sqlx::query_as::<_, WorkspaceResponse>(
        "select id, organization_id, slug, name, status, revision,
                created_at, updated_at, archived_at
         from workspaces
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
    Ok(Json(WorkspacePageResponse { items, next_cursor }))
}

#[utoipa::path(post, path = "/api/v1/organizations/{organization_id}/workspaces", tag = "organization",
    params(("organization_id" = Uuid, Path)), request_body = CreateWorkspaceRequest,
    responses((status = 201, description = "Workspace", body = WorkspaceResponse))
)]
pub async fn create_workspace(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(organization_id): Path<Uuid>,
    Json(request): Json<CreateWorkspaceRequest>,
) -> Result<(StatusCode, Json<WorkspaceResponse>), ApiError> {
    auth.require_organization(organization_id, Permission::ManageWorkspace)?;
    validate_slug(&request.slug)?;
    validate_name(&request.name)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let workspace = sqlx::query_as::<_, WorkspaceResponse>(
        "insert into workspaces (organization_id, slug, name)
         values ($1, $2, $3)
         returning id, organization_id, slug, name, status, revision,
                   created_at, updated_at, archived_at",
    )
    .bind(organization_id)
    .bind(request.slug)
    .bind(request.name)
    .fetch_one(&mut *transaction)
    .await?;
    if let Some(user_id) = auth.user_id {
        sqlx::query(
            "insert into workspace_memberships (organization_id, workspace_id, user_id, role)
             values ($1, $2, $3, 'admin') on conflict (workspace_id, user_id) do nothing",
        )
        .bind(organization_id)
        .bind(workspace.id)
        .bind(user_id)
        .execute(&mut *transaction)
        .await?;
    }
    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace.id),
        "workspace.created",
        "workspace",
        workspace.id,
    )
    .await?;
    transaction.commit().await?;
    Ok((StatusCode::CREATED, Json(workspace)))
}

#[utoipa::path(get, path = "/api/v1/workspaces/{workspace_id}", tag = "organization",
    params(("workspace_id" = Uuid, Path)), responses((status = 200, body = WorkspaceResponse))
)]
pub async fn get_workspace(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
) -> Result<(HeaderMap, Json<WorkspaceResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::ReadWorkspace)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let workspace = sqlx::query_as::<_, WorkspaceResponse>(
        "select id, organization_id, slug, name, status, revision,
                created_at, updated_at, archived_at
         from workspaces where id = $1 and organization_id = $2",
    )
    .bind(workspace_id)
    .bind(auth.organization_id)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    let mut headers = HeaderMap::new();
    headers.insert(header::ETAG, revision_etag(workspace.revision)?);
    Ok((headers, Json(workspace)))
}

#[utoipa::path(patch, path = "/api/v1/workspaces/{workspace_id}", tag = "organization",
    params(("workspace_id" = Uuid, Path), ("If-Match" = String, Header)), request_body = UpdateWorkspaceRequest,
    responses((status = 200, body = WorkspaceResponse), (status = 412, description = "Revision mismatch"))
)]
pub async fn update_workspace(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<UpdateWorkspaceRequest>,
) -> Result<(HeaderMap, Json<WorkspaceResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::ManageWorkspace)?;
    let revision = required_revision(&headers)?;
    if let Some(name) = request.name.as_deref() {
        validate_name(name)?;
    }
    if let Some(status) = request.status.as_deref()
        && !matches!(status, "active" | "archived")
    {
        return Err(ApiError::Validation("unknown workspace status".to_owned()));
    }
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let workspace = sqlx::query_as::<_, WorkspaceResponse>(
        "update workspaces
         set name = coalesce($1, name), status = coalesce($2, status),
             archived_at = case when $2 = 'archived' then coalesce(archived_at, now()) else archived_at end,
             revision = revision + 1, updated_at = now()
         where id = $3 and organization_id = $4 and revision = $5
         returning id, organization_id, slug, name, status, revision,
                   created_at, updated_at, archived_at",
    )
    .bind(request.name)
    .bind(request.status)
    .bind(workspace_id)
    .bind(auth.organization_id)
    .bind(revision)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(ApiError::PreconditionFailed)?;
    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace_id),
        "workspace.updated",
        "workspace",
        workspace_id,
    )
    .await?;
    transaction.commit().await?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(header::ETAG, revision_etag(workspace.revision)?);
    Ok((response_headers, Json(workspace)))
}

#[utoipa::path(post, path = "/api/v1/workspaces/{workspace_id}/select", tag = "organization",
    params(("workspace_id" = Uuid, Path)), responses((status = 204, description = "Selected workspace stored in web session"))
)]
pub async fn select_workspace(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
) -> Result<(HeaderMap, StatusCode), ApiError> {
    if auth.principal_kind != PrincipalKind::User {
        return Err(ApiError::Forbidden);
    }
    let session_id = auth.session_id.ok_or(ApiError::Forbidden)?;
    let session_token = random_token(32).map_err(|_| ApiError::Internal)?;
    let csrf_token = random_token(32).map_err(|_| ApiError::Internal)?;
    let selected: bool = sqlx::query_scalar(
        "select zeus_private.rotate_user_session_context($1, $2, $3, $4, $5, $6)",
    )
    .bind(session_id)
    .bind(auth.principal_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(sha256(session_token.expose_secret().as_bytes()))
    .bind(sha256(csrf_token.expose_secret().as_bytes()))
    .fetch_one(&state.platform.database)
    .await?;
    if !selected {
        return Err(ApiError::Forbidden);
    }
    let mut headers = HeaderMap::new();
    headers.append(
        header::SET_COOKIE,
        session_cookie(
            &state,
            session_token.expose_secret(),
            state.identity.session_absolute_ttl.as_secs(),
        )
        .parse()
        .map_err(|_| ApiError::Internal)?,
    );
    headers.append(
        header::SET_COOKIE,
        csrf_cookie(
            &state,
            csrf_token.expose_secret(),
            state.identity.session_absolute_ttl.as_secs(),
        )
        .parse()
        .map_err(|_| ApiError::Internal)?,
    );
    Ok((headers, StatusCode::NO_CONTENT))
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct OrganizationMemberResponse {
    pub user_id: Uuid,
    pub email: String,
    pub display_name: String,
    pub role: String,
    pub status: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetOrganizationMemberRequest {
    pub user_id: Uuid,
    pub role: String,
    #[serde(default = "active_status")]
    pub status: String,
}

pub async fn list_organization_members(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<OrganizationMemberResponse>>, ApiError> {
    auth.require_organization(organization_id, Permission::ManageOrganization)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let members = sqlx::query_as::<_, OrganizationMemberResponse>(
        "select m.user_id, u.email, u.display_name, m.role, m.status,
                m.created_at, m.updated_at
         from organization_memberships m join users u on u.id = m.user_id
         where m.organization_id = $1
         order by m.created_at, m.user_id limit 500",
    )
    .bind(organization_id)
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(members))
}

pub async fn set_organization_member(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(organization_id): Path<Uuid>,
    Json(request): Json<SetOrganizationMemberRequest>,
) -> Result<StatusCode, ApiError> {
    auth.require_organization(organization_id, Permission::ManageOrganization)?;
    validate_organization_role(&request.role)?;
    validate_membership_status(&request.status)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let target_is_owner: bool = sqlx::query_scalar(
        "select exists (
           select 1 from organization_memberships
           where organization_id = $1 and user_id = $2 and role = 'owner'
         )",
    )
    .bind(organization_id)
    .bind(request.user_id)
    .fetch_one(&mut *transaction)
    .await?;
    if (request.role == "owner" || target_is_owner)
        && auth.organization_role != Some(OrganizationRole::Owner)
    {
        return Err(ApiError::Forbidden);
    }
    sqlx::query(
        "insert into organization_memberships (organization_id, user_id, role, status)
         values ($1, $2, $3, $4)
         on conflict (organization_id, user_id) do update
         set role = excluded.role, status = excluded.status, updated_at = now()",
    )
    .bind(organization_id)
    .bind(request.user_id)
    .bind(request.role)
    .bind(request.status)
    .execute(&mut *transaction)
    .await?;
    insert_audit(
        &mut transaction,
        &auth,
        None,
        "organization_member.set",
        "user",
        request.user_id,
    )
    .await?;
    transaction.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct WorkspaceMemberResponse {
    pub user_id: Uuid,
    pub email: String,
    pub display_name: String,
    pub role: String,
    pub status: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetWorkspaceMemberRequest {
    pub user_id: Uuid,
    pub role: String,
    #[serde(default = "active_status")]
    pub status: String,
}

pub async fn list_workspace_members(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
) -> Result<Json<Vec<WorkspaceMemberResponse>>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ManageWorkspace)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let members = sqlx::query_as::<_, WorkspaceMemberResponse>(
        "select m.user_id, u.email, u.display_name, m.role, m.status,
                m.created_at, m.updated_at
         from workspace_memberships m join users u on u.id = m.user_id
         where m.workspace_id = $1 and m.organization_id = $2
         order by m.created_at, m.user_id limit 500",
    )
    .bind(workspace_id)
    .bind(auth.organization_id)
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(members))
}

pub async fn set_workspace_member(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    Json(request): Json<SetWorkspaceMemberRequest>,
) -> Result<StatusCode, ApiError> {
    auth.require_workspace(workspace_id, Permission::ManageWorkspace)?;
    validate_workspace_role(&request.role)?;
    validate_membership_status(&request.status)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    sqlx::query(
        "insert into workspace_memberships (organization_id, workspace_id, user_id, role, status)
         values ($1, $2, $3, $4, $5)
         on conflict (workspace_id, user_id) do update
         set role = excluded.role, status = excluded.status, updated_at = now()",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(request.user_id)
    .bind(request.role)
    .bind(request.status)
    .execute(&mut *transaction)
    .await?;
    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace_id),
        "workspace_member.set",
        "user",
        request.user_id,
    )
    .await?;
    transaction.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct FederatedIdentityProviderResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub slug: String,
    pub issuer_url: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub group_claim: Option<String>,
    pub jit_enabled: bool,
    pub trusted_acr: Vec<String>,
    pub trusted_amr: Vec<String>,
    pub enabled: bool,
    pub revision: i64,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateFederatedIdentityProviderRequest {
    pub slug: String,
    pub issuer_url: String,
    pub client_id: String,
    #[schema(value_type = String, write_only)]
    pub client_secret: String,
    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,
    pub group_claim: Option<String>,
    #[serde(default)]
    pub jit_enabled: bool,
    #[serde(default)]
    pub trusted_acr: Vec<String>,
    #[serde(default)]
    pub trusted_amr: Vec<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateFederatedIdentityProviderRequest {
    pub slug: Option<String>,
    pub issuer_url: Option<String>,
    pub client_id: Option<String>,
    #[schema(value_type = Option<String>, write_only)]
    pub client_secret: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub group_claim: Option<Option<String>>,
    pub enabled: Option<bool>,
    pub jit_enabled: Option<bool>,
    pub trusted_acr: Option<Vec<String>>,
    pub trusted_amr: Option<Vec<String>>,
}

pub async fn list_federated_identity_providers(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<FederatedIdentityProviderResponse>>, ApiError> {
    auth.require_organization(organization_id, Permission::ManageOrganization)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let providers = sqlx::query_as::<_, FederatedIdentityProviderResponse>(
        "select id, organization_id, slug, issuer_url, client_id, scopes, group_claim,
                jit_enabled, trusted_acr, trusted_amr, enabled, revision, created_at, updated_at
         from federated_identity_providers where organization_id = $1
         order by created_at desc, id desc",
    )
    .bind(organization_id)
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(providers))
}

pub async fn create_federated_identity_provider(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(organization_id): Path<Uuid>,
    Json(request): Json<CreateFederatedIdentityProviderRequest>,
) -> Result<(StatusCode, Json<FederatedIdentityProviderResponse>), ApiError> {
    auth.require_organization(organization_id, Permission::ManageOrganization)?;
    validate_slug(&request.slug)?;
    validate_federated_provider_request(
        &request.issuer_url,
        &request.client_id,
        &request.client_secret,
        &request.scopes,
        state.identity.allow_private_oidc_issuers,
    )?;
    validate_trusted_authentication_values(&request.trusted_acr, &request.trusted_amr)?;
    let provider_id = Uuid::now_v7();
    let aad = format!("oidc-provider/{provider_id}/client-secret");
    let sealed = state
        .platform
        .envelope
        .seal(request.client_secret.as_bytes(), aad.as_bytes())
        .map_err(|_| ApiError::Internal)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let provider = sqlx::query_as::<_, FederatedIdentityProviderResponse>(
        "insert into federated_identity_providers (
            id, organization_id, slug, issuer_url, client_id, encrypted_client_secret,
            secret_nonce, key_id, scopes, group_claim, jit_enabled, trusted_acr, trusted_amr
         ) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
         returning id, organization_id, slug, issuer_url, client_id, scopes, group_claim,
                   jit_enabled, trusted_acr, trusted_amr, enabled, revision, created_at, updated_at",
    )
    .bind(provider_id)
    .bind(organization_id)
    .bind(request.slug)
    .bind(request.issuer_url.trim_end_matches('/'))
    .bind(request.client_id)
    .bind(sealed.ciphertext)
    .bind(sealed.nonce)
    .bind(sealed.key_id)
    .bind(request.scopes)
    .bind(request.group_claim)
    .bind(request.jit_enabled)
    .bind(request.trusted_acr)
    .bind(request.trusted_amr)
    .fetch_one(&mut *transaction)
    .await?;
    insert_audit(
        &mut transaction,
        &auth,
        None,
        "federated_identity_provider.created",
        "federated_identity_provider",
        provider.id,
    )
    .await?;
    transaction.commit().await?;
    Ok((StatusCode::CREATED, Json(provider)))
}

pub async fn update_federated_identity_provider(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((organization_id, provider_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<UpdateFederatedIdentityProviderRequest>,
) -> Result<(HeaderMap, Json<FederatedIdentityProviderResponse>), ApiError> {
    auth.require_organization(organization_id, Permission::ManageOrganization)?;
    let revision = required_revision(&headers)?;
    if let Some(slug) = request.slug.as_deref() {
        validate_slug(slug)?;
    }
    if let Some(issuer) = request.issuer_url.as_deref() {
        let parsed = url::Url::parse(issuer)
            .map_err(|_| ApiError::Validation("issuer_url is invalid".to_owned()))?;
        validate_remote_url(&parsed, state.identity.allow_private_oidc_issuers)
            .map_err(|_| ApiError::Validation("issuer_url is not allowed".to_owned()))?;
    }
    if request.client_id.as_deref().is_some_and(str::is_empty)
        || request.client_secret.as_deref().is_some_and(str::is_empty)
        || request.scopes.as_ref().is_some_and(Vec::is_empty)
    {
        return Err(ApiError::Validation(
            "client_id, client_secret, and scopes cannot be empty".to_owned(),
        ));
    }
    if let Some(values) = request.trusted_acr.as_deref() {
        validate_trusted_authentication_values(values, &[])?;
    }
    if let Some(values) = request.trusted_amr.as_deref() {
        validate_trusted_authentication_values(&[], values)?;
    }
    let sealed = request
        .client_secret
        .as_deref()
        .map(|secret| {
            let aad = format!("oidc-provider/{provider_id}/client-secret");
            state
                .platform
                .envelope
                .seal(secret.as_bytes(), aad.as_bytes())
                .map_err(|_| ApiError::Internal)
        })
        .transpose()?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let provider = sqlx::query_as::<_, FederatedIdentityProviderResponse>(
        "update federated_identity_providers
         set slug = coalesce($1, slug),
             issuer_url = coalesce($2, issuer_url),
             client_id = coalesce($3, client_id),
             encrypted_client_secret = coalesce($4, encrypted_client_secret),
             secret_nonce = coalesce($5, secret_nonce),
             key_id = coalesce($6, key_id),
             scopes = coalesce($7, scopes),
             group_claim = case when $8 then $9 else group_claim end,
             enabled = coalesce($10, enabled),
             jit_enabled = coalesce($11, jit_enabled),
             trusted_acr = coalesce($12, trusted_acr),
             trusted_amr = coalesce($13, trusted_amr),
             revision = revision + 1, updated_at = now()
         where id = $14 and organization_id = $15 and revision = $16
         returning id, organization_id, slug, issuer_url, client_id, scopes, group_claim,
                   jit_enabled, trusted_acr, trusted_amr, enabled, revision, created_at, updated_at",
    )
    .bind(request.slug)
    .bind(
        request
            .issuer_url
            .map(|value| value.trim_end_matches('/').to_owned()),
    )
    .bind(request.client_id)
    .bind(sealed.as_ref().map(|value| value.ciphertext.clone()))
    .bind(sealed.as_ref().map(|value| value.nonce.clone()))
    .bind(sealed.as_ref().map(|value| value.key_id.clone()))
    .bind(request.scopes)
    .bind(request.group_claim.is_some())
    .bind(request.group_claim.flatten())
    .bind(request.enabled)
    .bind(request.jit_enabled)
    .bind(request.trusted_acr)
    .bind(request.trusted_amr)
    .bind(provider_id)
    .bind(organization_id)
    .bind(revision)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(ApiError::PreconditionFailed)?;
    insert_audit(
        &mut transaction,
        &auth,
        None,
        "federated_identity_provider.updated",
        "federated_identity_provider",
        provider_id,
    )
    .await?;
    transaction.commit().await?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(header::ETAG, revision_etag(provider.revision)?);
    Ok((response_headers, Json(provider)))
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct FederatedGroupMappingResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub provider_id: Uuid,
    pub group_value: String,
    pub organization_role: Option<String>,
    pub workspace_id: Option<Uuid>,
    pub workspace_role: Option<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateFederatedGroupMappingRequest {
    pub group_value: String,
    pub organization_role: Option<String>,
    pub workspace_id: Option<Uuid>,
    pub workspace_role: Option<String>,
}

pub async fn list_federated_group_mappings(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((organization_id, provider_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Vec<FederatedGroupMappingResponse>>, ApiError> {
    auth.require_organization(organization_id, Permission::ManageOrganization)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let mappings = sqlx::query_as::<_, FederatedGroupMappingResponse>(
        "select id, organization_id, provider_id, group_value, organization_role,
                workspace_id, workspace_role, created_at
         from federated_group_mappings
         where organization_id = $1 and provider_id = $2
         order by created_at, id",
    )
    .bind(organization_id)
    .bind(provider_id)
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(mappings))
}

pub async fn create_federated_group_mapping(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((organization_id, provider_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<CreateFederatedGroupMappingRequest>,
) -> Result<(StatusCode, Json<FederatedGroupMappingResponse>), ApiError> {
    auth.require_organization(organization_id, Permission::ManageOrganization)?;
    if request.group_value.trim().is_empty() {
        return Err(ApiError::Validation(
            "group_value cannot be empty".to_owned(),
        ));
    }
    match (
        request.organization_role.as_deref(),
        request.workspace_id,
        request.workspace_role.as_deref(),
    ) {
        (Some(role), None, None) => validate_organization_role(role)?,
        (None, Some(_), Some(role)) => validate_workspace_role(role)?,
        _ => {
            return Err(ApiError::Validation(
                "mapping must target one organization role or one workspace role".to_owned(),
            ));
        }
    }
    let mut transaction = begin_tenant(
        &state.platform.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let mapping = sqlx::query_as::<_, FederatedGroupMappingResponse>(
        "insert into federated_group_mappings (
            organization_id, provider_id, group_value, organization_role,
            workspace_id, workspace_role
         ) values ($1, $2, $3, $4, $5, $6)
         returning id, organization_id, provider_id, group_value, organization_role,
                   workspace_id, workspace_role, created_at",
    )
    .bind(organization_id)
    .bind(provider_id)
    .bind(request.group_value.trim())
    .bind(request.organization_role)
    .bind(request.workspace_id)
    .bind(request.workspace_role)
    .fetch_one(&mut *transaction)
    .await?;
    insert_audit(
        &mut transaction,
        &auth,
        request.workspace_id,
        "federated_group_mapping.created",
        "federated_group_mapping",
        mapping.id,
    )
    .await?;
    transaction.commit().await?;
    Ok((StatusCode::CREATED, Json(mapping)))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/organizations", post(create_organization))
        .route(
            "/api/v1/organizations/{organization_id}",
            get(get_organization).patch(update_organization),
        )
        .route(
            "/api/v1/organizations/{organization_id}/workspaces",
            get(list_workspaces).post(create_workspace),
        )
        .route(
            "/api/v1/organizations/{organization_id}/members",
            get(list_organization_members).put(set_organization_member),
        )
        .route(
            "/api/v1/organizations/{organization_id}/identity-providers",
            get(list_federated_identity_providers).post(create_federated_identity_provider),
        )
        .route(
            "/api/v1/organizations/{organization_id}/identity-providers/{provider_id}",
            patch(update_federated_identity_provider),
        )
        .route(
            "/api/v1/organizations/{organization_id}/identity-providers/{provider_id}/group-mappings",
            get(list_federated_group_mappings).post(create_federated_group_mapping),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}",
            get(get_workspace).patch(update_workspace),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/select",
            post(select_workspace),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/members",
            get(list_workspace_members).put(set_workspace_member),
        )
}

fn validate_slug(value: &str) -> Result<(), ApiError> {
    let bytes = value.as_bytes();
    if !(3..=63).contains(&bytes.len())
        || value != value.to_ascii_lowercase()
        || !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        || bytes
            .iter()
            .any(|byte| !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && *byte != b'-')
    {
        return Err(ApiError::Validation(
            "slug must use 3-63 lowercase letters, digits, or internal hyphens".to_owned(),
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

fn validate_organization_role(value: &str) -> Result<(), ApiError> {
    if matches!(value, "owner" | "admin" | "member" | "auditor") {
        Ok(())
    } else {
        Err(ApiError::Validation("unknown organization role".to_owned()))
    }
}

fn validate_workspace_role(value: &str) -> Result<(), ApiError> {
    if matches!(value, "admin" | "builder" | "operator" | "viewer") {
        Ok(())
    } else {
        Err(ApiError::Validation("unknown workspace role".to_owned()))
    }
}

fn validate_membership_status(value: &str) -> Result<(), ApiError> {
    if matches!(value, "active" | "suspended") {
        Ok(())
    } else {
        Err(ApiError::Validation("unknown membership status".to_owned()))
    }
}

fn validate_federated_provider_request(
    issuer_url: &str,
    client_id: &str,
    client_secret: &str,
    scopes: &[String],
    allow_private: bool,
) -> Result<(), ApiError> {
    let issuer = url::Url::parse(issuer_url)
        .map_err(|_| ApiError::Validation("issuer_url is invalid".to_owned()))?;
    validate_remote_url(&issuer, allow_private)
        .map_err(|_| ApiError::Validation("issuer_url is not allowed".to_owned()))?;
    if client_id.trim().is_empty() || client_secret.is_empty() || scopes.is_empty() {
        return Err(ApiError::Validation(
            "client_id, client_secret, and scopes cannot be empty".to_owned(),
        ));
    }
    Ok(())
}

#[allow(clippy::similar_names)] // ACR and AMR are distinct OIDC claim names.
fn validate_trusted_authentication_values(
    trusted_acr: &[String],
    trusted_amr: &[String],
) -> Result<(), ApiError> {
    if trusted_acr.len() > 32 || trusted_amr.len() > 32 {
        return Err(ApiError::Validation(
            "trusted_acr and trusted_amr may contain at most 32 values".to_owned(),
        ));
    }
    for values in [trusted_acr, trusted_amr] {
        let mut unique = std::collections::BTreeSet::new();
        for value in values {
            if value.is_empty()
                || value.len() > 256
                || value.chars().any(char::is_control)
                || !unique.insert(value)
            {
                return Err(ApiError::Validation(
                    "trusted authentication values must be unique, non-empty, and bounded"
                        .to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn default_oidc_scopes() -> Vec<String> {
    vec![
        "openid".to_owned(),
        "profile".to_owned(),
        "email".to_owned(),
    ]
}

fn active_status() -> String {
    "active".to_owned()
}

#[cfg(test)]
mod tests {
    use super::{validate_organization_role, validate_slug, validate_workspace_role};

    #[test]
    fn slug_validation_matches_database_shape() {
        assert!(validate_slug("platform-team").is_ok());
        assert!(validate_slug("Platform").is_err());
        assert!(validate_slug("-platform").is_err());
    }

    #[test]
    fn role_validation_rejects_cross_layer_names() {
        assert!(validate_organization_role("owner").is_ok());
        assert!(validate_organization_role("builder").is_err());
        assert!(validate_workspace_role("builder").is_ok());
        assert!(validate_workspace_role("owner").is_err());
    }
}
